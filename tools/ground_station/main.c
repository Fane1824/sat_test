main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <gcrypt.h>
#include <signal.h>

/* Configuration */
#define DEFAULT_HOSTNAME  "127.0.0.1"
#define DEFAULT_PORT      1234
#define ENCRYPTED_PORT    1236  /* Use dedicated port for encrypted data */
#define BUFFER_SIZE       2048
#define AES_KEY_SIZE      32

/* Command message IDs - match exactly with cFS app */
#define ENCRYPT_APP_CMD_MID        0x1882
#define ENCRYPT_APP_SEND_HK_MID    0x1883
#define ENCRYPT_APP_ENCRYPTED_MID  0x1884
#define ENCRYPT_APP_KEY_ROT_MID    0x1885

/* Command codes */
#define ENCRYPT_APP_NOOP_CC        0
#define ENCRYPT_APP_RESET_CC       1

/* Flag for program termination */
static volatile int keep_running = 1;

/* Ground station state data */
typedef struct {
    /* Network */
    int          SocketFD;         /* Main socket for CI_LAB commands */
    int          DataSocketFD;     /* Socket for encrypted data on dedicated port */
    struct sockaddr_in ServerAddr; /* Main cFS address */
    struct sockaddr_in DataAddr;   /* Data port address */
    
    /* Message scheduling */
    int          MessageInterval;  /* Time between messages (seconds) */
    int          KeyRotInterval;   /* Time between key rotations (seconds) */
    time_t       LastMsgTime;      /* Last message time */
    time_t       LastKeyRotTime;   /* Last key rotation time */
    
    /* Encryption */
    gcry_sexp_t  RSAPrivateKey;    /* RSA private key */
    gcry_sexp_t  RSAPublicKey;     /* RSA public key (derived from private) */
    unsigned char AESKey[AES_KEY_SIZE]; /* Current AES key */
    unsigned int KeyCounter;       /* Count key rotations */
} GroundStation_t;

/* Global ground station data */
GroundStation_t GroundStation;

/* Function prototypes */
void print_hex_dump(const char *title, const void *data, size_t len);
int GroundStation_Init(const char *hostname, int port, int msg_interval, int key_interval);
void GroundStation_Cleanup(void);
int GroundStation_InitCrypto(void);
int GroundStation_GenerateOrLoadKeys(void);
void GroundStation_SendCommand(uint16_t command_code);
void GroundStation_SendEncryptedMessage(const char *message);
void GroundStation_SendKeyRotation(void);
void GroundStation_Run(void);
void handle_signal(int signal);

/* Signal handler for clean shutdown */
void handle_signal(int signal) {
    printf("\nReceived signal %d, shutting down...\n", signal);
    keep_running = 0;
}

/* Main function */
int main(int argc, char *argv[]) {
    char *hostname = DEFAULT_HOSTNAME;
    int port = DEFAULT_PORT;
    int message_interval = 5;
    int key_rotation_interval = 30;
    int c;
    
    /* Parse command line options */
    while ((c = getopt(argc, argv, "h:p:m:k:?")) != -1) {
        switch (c) {
            case 'h':
                hostname = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'm':
                message_interval = atoi(optarg);
                break;
            case 'k':
                key_rotation_interval = atoi(optarg);
                break;
            case '?':
                printf("Usage: %s [-h hostname] [-p port] [-m msg_interval] [-k key_interval]\n", argv[0]);
                printf("Options:\n");
                printf("  -h  Hostname (default: %s)\n", DEFAULT_HOSTNAME);
                printf("  -p  Port (default: %d)\n", DEFAULT_PORT);
                printf("  -m  Message interval in seconds (default: 5)\n");
                printf("  -k  Key rotation interval in seconds (default: 30)\n");
                return 0;
            default:
                fprintf(stderr, "Unknown option: %c\n", c);
                return 1;
        }
    }
    
    printf("Ground Station Simulator for ENCRYPT_APP\n");
    printf("----------------------------------------\n");
    
    /* Install signal handler for clean shutdown */
    signal(SIGINT, handle_signal);
    
    /* Initialize the ground station */
    if (GroundStation_Init(hostname, port, message_interval, key_rotation_interval) != 0) {
        fprintf(stderr, "Failed to initialize ground station. Exiting.\n");
        return 1;
    }
    
    /* Initialize cryptographic operations */
    if (GroundStation_InitCrypto() != 0) {
        fprintf(stderr, "Failed to initialize crypto. Exiting.\n");
        GroundStation_Cleanup();
        return 1;
    }
    
    /* Send initial NOOP to verify connection */
    printf("GROUND STATION: Sending NO-OP command\n");
    GroundStation_SendCommand(ENCRYPT_APP_NOOP_CC);
    
    /* Run the ground station */
    GroundStation_Run();
    
    /* Clean up before exit */
    GroundStation_Cleanup();
    
    printf("Ground station terminated.\n");
    return 0;
}

/* Helper function to dump binary data */
void print_hex_dump(const char *title, const void *data, size_t len) {
    printf("%s (%zu bytes):\n", title, len);
    const unsigned char *p = data;
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", p[i]);
        if ((i + 1) % 16 == 0 || i == len - 1)
            printf("\n");
    }
}

/* Initialize the ground station */
int GroundStation_Init(const char *hostname, int port, int msg_interval, int key_interval) {
    /* Initialize ground station state */
    memset(&GroundStation, 0, sizeof(GroundStation));
    GroundStation.MessageInterval = msg_interval;
    GroundStation.KeyRotInterval = key_interval;
    GroundStation.LastMsgTime = time(NULL);
    GroundStation.LastKeyRotTime = time(NULL);
    GroundStation.KeyCounter = 0;
    
    /* Create socket for commands (to CI_LAB) */
    GroundStation.SocketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (GroundStation.SocketFD < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    /* Set up command address (CI_LAB) */
    memset(&GroundStation.ServerAddr, 0, sizeof(GroundStation.ServerAddr));
    GroundStation.ServerAddr.sin_family = AF_INET;
    GroundStation.ServerAddr.sin_port = htons(port);
    
    /* Create socket for encrypted data (direct to our app) */
    GroundStation.DataSocketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (GroundStation.DataSocketFD < 0) {
        perror("Data socket creation failed");
        close(GroundStation.SocketFD);
        return -1;
    }
    
    /* Set up data address (direct to ENCRYPT_APP) */
    memset(&GroundStation.DataAddr, 0, sizeof(GroundStation.DataAddr));
    GroundStation.DataAddr.sin_family = AF_INET;
    GroundStation.DataAddr.sin_port = htons(ENCRYPTED_PORT);
    
    /* Convert hostname to IP */
    if (inet_pton(AF_INET, hostname, &GroundStation.ServerAddr.sin_addr) <= 0) {
        perror("Invalid address");
        close(GroundStation.SocketFD);
        close(GroundStation.DataSocketFD);
        return -1;
    }
    
    /* Use same IP for data socket */
    memcpy(&GroundStation.DataAddr.sin_addr, &GroundStation.ServerAddr.sin_addr, 
           sizeof(GroundStation.ServerAddr.sin_addr));
    
    /* Initialize AES key */
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        GroundStation.AESKey[i] = i; /* Simple initial key pattern */
    }
    
    printf("Ground station initialized with:\n");
    printf("  Hostname: %s\n", hostname);
    printf("  Command port: %d\n", port);
    printf("  Data port: %d\n", ENCRYPTED_PORT);
    printf("  Message interval: %d seconds\n", msg_interval);
    printf("  Key rotation interval: %d seconds\n", key_interval);
    
    return 0;
}

/* Clean up resources */
void GroundStation_Cleanup(void) {
    /* Close sockets */
    if (GroundStation.SocketFD >= 0) {
        close(GroundStation.SocketFD);
    }
    
    if (GroundStation.DataSocketFD >= 0) {
        close(GroundStation.DataSocketFD);
    }
    
    /* Release cryptographic resources */
    if (GroundStation.RSAPrivateKey) {
        gcry_sexp_release(GroundStation.RSAPrivateKey);
    }
    
    if (GroundStation.RSAPublicKey) {
        gcry_sexp_release(GroundStation.RSAPublicKey);
    }
}

/* Initialize cryptographic operations */
int GroundStation_InitCrypto(void) {
    /* Initialize libgcrypt */
    if (!gcry_check_version("1.8.0")) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        return -1;
    }
    
    /* Disable secure memory */
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    
    /* Initialize the library */
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    
    /* Generate or load RSA keys */
    if (GroundStation_GenerateOrLoadKeys() != 0) {
        fprintf(stderr, "Failed to initialize RSA keys\n");
        return -1;
    }
    
    /* Initialize random number generator */
    gcry_randomize(NULL, 0, GCRY_STRONG_RANDOM);
    
    return 0;
}

/* Generate or load RSA key pair */
int GroundStation_GenerateOrLoadKeys(void) {
    const char *key_path = "encrypt_app_rsa.key";
    FILE *key_file;
    
    /* Check if key file exists */
    if ((key_file = fopen(key_path, "rb")) != NULL) {
        /* Key file exists, load it */
        printf("Loading RSA key from file: %s\n", key_path);
        
        /* Get file size */
        fseek(key_file, 0, SEEK_END);
        long file_size = ftell(key_file);
        rewind(key_file);
        
        /* Read key data */
        char *key_data = malloc(file_size + 1);
        if (!key_data) {
            fclose(key_file);
            fprintf(stderr, "Memory allocation failed\n");
            return -1;
        }
        
        size_t read_size = fread(key_data, 1, file_size, key_file);
        fclose(key_file);
        
        if (read_size != file_size) {
            free(key_data);
            fprintf(stderr, "Failed to read key file\n");
            return -1;
        }
        
        key_data[file_size] = '\0';
        
        /* Parse key S-expression */
        gcry_error_t err = gcry_sexp_sscan(&GroundStation.RSAPrivateKey, 
                                          NULL, key_data, file_size);
        free(key_data);
        
        if (err) {
            fprintf(stderr, "Failed to parse key file: %s/%s\n",
                   gcry_strsource(err), gcry_strerror(err));
            return -1;
        }
    } else {
        /* Key file doesn't exist, generate a new key pair */
        printf("Generating new RSA key pair...\n");
        
        /* Generate key parameters */
        const int key_bits = 2048;
        gcry_sexp_t key_params;
        gcry_error_t err = gcry_sexp_build(&key_params, NULL,
                                          "(genkey (rsa (nbits %d)))", key_bits);
        if (err) {
            fprintf(stderr, "Failed to create key generation parameters: %s/%s\n",
                   gcry_strsource(err), gcry_strerror(err));
            return -1;
        }
        
        /* Generate the key pair */
        err = gcry_pk_genkey(&GroundStation.RSAPrivateKey, key_params);
        gcry_sexp_release(key_params);
        
        if (err) {
            fprintf(stderr, "Failed to generate RSA key: %s/%s\n",
                   gcry_strsource(err), gcry_strerror(err));
            return -1;
        }
        
        /* Save the key to file */
        printf("Saving RSA key to file: %s\n", key_path);
        
        /* Serialize key */
        size_t key_len = gcry_sexp_sprint(GroundStation.RSAPrivateKey, 
                                         GCRYSEXP_FMT_ADVANCED, 
                                         NULL, 0);
        char *key_str = malloc(key_len);
        if (!key_str) {
            fprintf(stderr, "Memory allocation failed\n");
            return -1;
        }
        
        gcry_sexp_sprint(GroundStation.RSAPrivateKey, 
                        GCRYSEXP_FMT_ADVANCED, key_str, key_len);
        
        /* Write to file */
        key_file = fopen(key_path, "wb");
        if (!key_file) {
            free(key_str);
            fprintf(stderr, "Failed to create key file\n");
            return -1;
        }
        
        size_t write_size = fwrite(key_str, 1, key_len - 1, key_file); /* -1 to skip null terminator */
        fclose(key_file);
        free(key_str);
        
        if (write_size != key_len - 1) {
            fprintf(stderr, "Failed to write key file\n");
            return -1;
        }
        
        printf("RSA key saved successfully\n");
    }
    
    /* Extract public key components */
    printf("Extracting public key from private key...\n");
    
    /* Find the public key part */
    gcry_sexp_t public_key_part = gcry_sexp_find_token(GroundStation.RSAPrivateKey, "public-key", 0);
    if (public_key_part) {
        /* If there's a public-key token, use it directly */
        GroundStation.RSAPublicKey = gcry_sexp_copy(public_key_part);
        gcry_sexp_release(public_key_part);
    } else {
        /* Extract n and e components and build public key */
        gcry_sexp_t rsa = gcry_sexp_find_token(GroundStation.RSAPrivateKey, "rsa", 0);
        if (!rsa) {
            fprintf(stderr, "Failed to find RSA token in key\n");
            return -1;
        }
        
        gcry_sexp_t n = gcry_sexp_find_token(rsa, "n", 0);
        gcry_sexp_t e = gcry_sexp_find_token(rsa, "e", 0);
        gcry_sexp_release(rsa);
        
        if (!n || !e) {
            fprintf(stderr, "Failed to extract key components\n");
            if (n) gcry_sexp_release(n);
            if (e) gcry_sexp_release(e);
            return -1;
        }
        
        /* Get the actual MPI values */
        gcry_mpi_t n_mpi = gcry_sexp_nth_mpi(n, 1, GCRYMPI_FMT_USG);
        gcry_mpi_t e_mpi = gcry_sexp_nth_mpi(e, 1, GCRYMPI_FMT_USG);
        gcry_sexp_release(n);
        gcry_sexp_release(e);
        
        if (!n_mpi || !e_mpi) {
            fprintf(stderr, "Failed to extract MPI values\n");
            if (n_mpi) gcry_mpi_release(n_mpi);
            if (e_mpi) gcry_mpi_release(e_mpi);
            return -1;
        }
        
        /* Build the public key */
        gcry_error_t err = gcry_sexp_build(&GroundStation.RSAPublicKey, NULL,
                                          "(public-key (rsa (n %m) (e %m)))",
                                          n_mpi, e_mpi);
        gcry_mpi_release(n_mpi);
        gcry_mpi_release(e_mpi);
        
        if (err) {
            fprintf(stderr, "Failed to build public key: %s/%s\n",
                   gcry_strsource(err), gcry_strerror(err));
            return -1;
        }
    }
    
    /* Print public key */
    char *pubkey_str;
    size_t len = gcry_sexp_sprint(GroundStation.RSAPublicKey, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    pubkey_str = malloc(len);
    if (pubkey_str) {
        gcry_sexp_sprint(GroundStation.RSAPublicKey, GCRYSEXP_FMT_ADVANCED, pubkey_str, len);
        printf("RSA Public Key:\n%s\n", pubkey_str);
        free(pubkey_str);
    }
    
    return 0;
}

/* Send a command to cFS (via CI_LAB) */
void GroundStation_SendCommand(uint16_t command_code) {
    /* Create a properly formatted CCSDS command packet for CI_LAB */
    uint8_t cmd_packet[8] = {0};
    
    /* Primary header (6 bytes) */
    cmd_packet[0] = 0x18;  /* Version (3 bits), Type (1 bit), Secondary Header Flag (1 bit), App ID (3 bits MSB) */
    cmd_packet[1] = 0x82;  /* App ID (8 bits LSB) - ENCRYPT_APP_CMD_MID (0x1882) */
    cmd_packet[2] = 0xC0;  /* Sequence flags (2 bits), Sequence count (6 bits MSB) */
    cmd_packet[3] = 0x00;  /* Sequence count (8 bits LSB) */
    cmd_packet[4] = 0x00;  /* Packet length MSB (length of secondary header + data - 1) */
    cmd_packet[5] = 0x01;  /* Packet length LSB = 1 byte of data */
    
    /* Secondary header / command code (2 bytes) */
    cmd_packet[6] = command_code; /* Command code */
    cmd_packet[7] = 0x00;         /* Checksum or reserved */
    
    /* Send the command via the CI_LAB port */
    if (sendto(GroundStation.SocketFD, cmd_packet, sizeof(cmd_packet), 0,
              (struct sockaddr*)&GroundStation.ServerAddr, sizeof(GroundStation.ServerAddr)) < 0) {
        perror("Command sendto failed");
    } else {
        if (command_code == ENCRYPT_APP_NOOP_CC) {
            printf("Sent NOOP command to cFS\n");
        } else if (command_code == ENCRYPT_APP_RESET_CC) {
            printf("Sent RESET command to cFS\n");
        } else {
            printf("Sent command %d to cFS\n", command_code);
        }
    }
}

/* Send an encrypted message via the direct data port */
void GroundStation_SendEncryptedMessage(const char *message) {
    if (!message || strlen(message) == 0) {
        fprintf(stderr, "Empty message, not sending\n");
        return;
    }
    
    /* Generate a random IV for this message */
    unsigned char iv[16] = {0};
    gcry_randomize(iv, 16, GCRY_STRONG_RANDOM);
    
    /* Create a buffer for the ciphertext (IV + encrypted data) */
    unsigned char ciphertext[BUFFER_SIZE];
    memcpy(ciphertext, iv, 16); /* Copy the IV to the beginning of the ciphertext */
    
    /* Open a cipher handle */
    gcry_cipher_hd_t cipher;
    gcry_error_t err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if (err) {
        fprintf(stderr, "Failed to open cipher: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return;
    }
    
    /* Set the key */
    err = gcry_cipher_setkey(cipher, GroundStation.AESKey, AES_KEY_SIZE);
    if (err) {
        fprintf(stderr, "Failed to set key: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        gcry_cipher_close(cipher);
        return;
    }
    
    /* Set the IV */
    err = gcry_cipher_setiv(cipher, iv, 16);
    if (err) {
        fprintf(stderr, "Failed to set IV: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        gcry_cipher_close(cipher);
        return;
    }
    
    /* Calculate the padded message length */
    size_t msg_len = strlen(message);
    size_t padded_len = ((msg_len + 15) / 16) * 16; /* Round up to multiple of 16 */
    
    /* Create a buffer for the plaintext with padding */
    unsigned char *plaintext = (unsigned char *)calloc(padded_len, 1);
    if (!plaintext) {
        fprintf(stderr, "Memory allocation error\n");
        gcry_cipher_close(cipher);
        return;
    }
    
    /* Copy the message to the plaintext buffer and pad with zeros */
    memcpy(plaintext, message, msg_len);
    
    /* Encrypt the message */
    err = gcry_cipher_encrypt(cipher, ciphertext + 16, padded_len, plaintext, padded_len);
    if (err) {
        fprintf(stderr, "Encryption failed: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        free(plaintext);
        gcry_cipher_close(cipher);
        return;
    }
    
    /* Calculate the total size of the encrypted message (IV + encrypted data) */
    size_t encrypted_len = 16 + padded_len;
    
    /* Send directly to the ENCRYPT_APP UDP port */
    if (sendto(GroundStation.DataSocketFD, ciphertext, encrypted_len, 0,
              (struct sockaddr*)&GroundStation.DataAddr, 
              sizeof(GroundStation.DataAddr)) < 0) {
        perror("Direct encrypted sendto failed");
    } else {
        printf("Sent encrypted message directly to satellite: \"%s\"\n", message);
        print_hex_dump("Sent data", ciphertext, encrypted_len);
    }
    
    /* Clean up */
    free(plaintext);
    gcry_cipher_close(cipher);
}

/* Send a key rotation message */
void GroundStation_SendKeyRotation(void) {
    /* Generate a new AES key */
    unsigned char new_key[AES_KEY_SIZE];
    gcry_randomize(new_key, AES_KEY_SIZE, GCRY_STRONG_RANDOM);
    
    /* Create the MPI from the new key */
    gcry_mpi_t key_mpi;
    gcry_error_t err = gcry_mpi_scan(&key_mpi, GCRYMPI_FMT_USG, new_key, AES_KEY_SIZE, NULL);
    if (err) {
        fprintf(stderr, "Failed to create MPI: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return;
    }
    
    /* Create S-expression for the plaintext data */
    gcry_sexp_t plain_data;
    err = gcry_sexp_build(&plain_data, NULL, "(data (flags pkcs1) (value %m))", key_mpi);
    gcry_mpi_release(key_mpi);
    
    if (err) {
        fprintf(stderr, "Failed to create plaintext S-exp: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return;
    }
    
    /* Encrypt with the public key */
    gcry_sexp_t cipher_data;
    err = gcry_pk_encrypt(&cipher_data, plain_data, GroundStation.RSAPublicKey);
    gcry_sexp_release(plain_data);
    
    if (err) {
        fprintf(stderr, "RSA encryption failed: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return;
    }
    
    /* Extract the encrypted data */
    gcry_sexp_t a_part = gcry_sexp_find_token(cipher_data, "a", 0);
    if (!a_part) {
        fprintf(stderr, "Failed to extract encrypted data\n");
        gcry_sexp_release(cipher_data);
        return;
    }
    
    /* Get the MPI for the encrypted data */
    gcry_mpi_t cipher_mpi = gcry_sexp_nth_mpi(a_part, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(a_part);
    gcry_sexp_release(cipher_data);
    
    if (!cipher_mpi) {
        fprintf(stderr, "Failed to extract MPI from encrypted data\n");
        return;
    }
    
    /* Convert MPI to binary */
    unsigned char *key_data;
    size_t key_len;
    err = gcry_mpi_aprint(GCRYMPI_FMT_USG, &key_data, &key_len, cipher_mpi);
    gcry_mpi_release(cipher_mpi);
    
    if (err) {
        fprintf(stderr, "Failed to convert MPI to binary: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return;
    }
    
    /* Send the encrypted key directly to the ENCRYPT_APP UDP port */
    if (sendto(GroundStation.DataSocketFD, key_data, key_len, 0,
              (struct sockaddr*)&GroundStation.DataAddr, 
              sizeof(GroundStation.DataAddr)) < 0) {
        perror("Direct key rotation sendto failed");
    } else {
        printf("Sent key rotation #%u directly to satellite\n", ++GroundStation.KeyCounter);
        print_hex_dump("Sent key data", key_data, key_len);
        
        /* Store the new key for future messages */
        memcpy(GroundStation.AESKey, new_key, AES_KEY_SIZE);
    }
    
    /* Free the allocated memory */
    free(key_data);
}

/* Run the ground station until terminated */
void GroundStation_Run(void) {
    time_t current_time;
    
    printf("Ground station running. Press Ctrl+C to exit.\n");
    
    /* Main loop */
    while (keep_running) {
        current_time = time(NULL);
        
        /* Check if it's time to send a message */
        if (difftime(current_time, GroundStation.LastMsgTime) >= GroundStation.MessageInterval) {
            char message[256];
            sprintf(message, "Hello from Ground Station - Message %u", 
                   GroundStation.KeyCounter);
            
            GroundStation_SendEncryptedMessage(message);
            GroundStation.LastMsgTime = current_time;
        }
        
        /* Check if it's time to rotate the key */
        if (difftime(current_time, GroundStation.LastKeyRotTime) >= GroundStation.KeyRotInterval) {
            GroundStation_SendKeyRotation();
            GroundStation.LastKeyRotTime = current_time;
        }
        
        /* Sleep for a short time to avoid busy waiting */
        usleep(100000);  /* 100ms sleep */
    }
}