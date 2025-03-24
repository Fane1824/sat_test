/ground_station/main.c
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

/* Message IDs (must match those in the cFS app) */
#define ENCRYPT_APP_CMD_MID            0x1812
#define ENCRYPT_APP_SEND_HK_MID        0x1813
#define ENCRYPT_APP_ENCRYPTED_MID      0x1814
#define ENCRYPT_APP_KEY_ROT_MID        0x1815

/* Default connection settings */
#define DEFAULT_HOSTNAME  "127.0.0.1"
#define DEFAULT_PORT      1234
#define BUFFER_SIZE       2048

/* Command codes (must match those in encrypt_app_msg.h) */
#define ENCRYPT_APP_NOOP_CC 0
#define ENCRYPT_APP_RESET_CC 1

/* CCSDS Headers */
#define CCSDS_PRI_HDR_SIZE      6
#define CCSDS_CMD_SEC_HDR_SIZE  2
#define CCSDS_TLM_SEC_HDR_SIZE  6

/* cFS message structures (simplified for ground tool) */
typedef struct {
    uint8_t StreamId[2];   /* Stream ID / Message ID */
    uint8_t Sequence[2];   /* Sequence Count */
    uint8_t Length[2];     /* Length of packet in bytes (including header) */
    uint8_t FunctionCode;  /* Command function code */
    uint8_t Checksum;      /* Checksum for command verification */
    uint8_t Payload[1024]; /* Payload data (variable length) */
} CFE_SB_Msg_t;

/* Structure for holding ground station state */
typedef struct {
    unsigned char AESKey[32];
    size_t AESKeyLen;
    gcry_sexp_t RSAPublicKey;
    uint32_t MessageCounter;
    uint32_t KeyRotationCounter;
    int SocketFD;
    struct sockaddr_in ServerAddr;
} GroundStation_t;

GroundStation_t GroundStation;

/* RSA public key in S-expression format */
const char *RSA_PUBLIC_KEY = 
    "(public-key (rsa (n #00BA65A53C3A3C02A87679B5F86A9BE4E5AB38475709E8784B0F2C3C573219E609AACB0C6D5F550879AA1AA80961C48AB663930F6FAAD5F1860E39A7B1A58A543#)"
    "(e #010001#)))";

/* Function prototypes */
int GroundStation_InitCrypto(void);
int GroundStation_Connect(const char *hostname, int port);
void GroundStation_Shutdown(void);
int GroundStation_EncryptMessage(const char *plaintext, size_t plaintext_len, 
                                unsigned char *ciphertext, size_t *ciphertext_len);
int GroundStation_EncryptNewKey(unsigned char *new_key, size_t key_len, 
                               unsigned char **encrypted_key, size_t *encrypted_len);
void GroundStation_GenerateNewAESKey(void);
void GroundStation_SendEncryptedMessage(const char *message);
void GroundStation_SendKeyRotation(void);
void GroundStation_SendNoOpCommand(void);
void GroundStation_SendResetCommand(void);
void GroundStation_SendMessage(uint16_t msgId, uint8_t cmdCode, void *payload, size_t payloadLen);
void GroundStation_RunSimulation(int message_interval, int key_rotation_interval);
void GroundStation_PrintHelp(void);

/* Main function */
int main(int argc, char *argv[])
{
    char *hostname = DEFAULT_HOSTNAME;
    int port = DEFAULT_PORT;
    int message_interval = 5;    /* seconds between messages */
    int key_rotation_interval = 30; /* seconds between key rotations */
    int c;
    
    printf("Ground Station Simulator for ENCRYPT_APP\n");
    printf("----------------------------------------\n");
    
    /* Parse command line arguments */
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
                GroundStation_PrintHelp();
                return 0;
            default:
                fprintf(stderr, "Unknown option: %c\n", c);
                GroundStation_PrintHelp();
                return 1;
        }
    }
    
    /* Initialize crypto operations */
    if (GroundStation_InitCrypto() != 0) {
        fprintf(stderr, "Failed to initialize crypto. Exiting.\n");
        return 1;
    }
    
    /* Initialize AES key (same initial key as in encrypt_app.c) */
    unsigned char initialKey[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    
    memcpy(GroundStation.AESKey, initialKey, 32);
    GroundStation.AESKeyLen = 32;
    GroundStation.MessageCounter = 0;
    GroundStation.KeyRotationCounter = 0;
    
    /* Connect to cFS UDP server */
    if (GroundStation_Connect(hostname, port) != 0) {
        fprintf(stderr, "Failed to connect to cFS. Exiting.\n");
        return 1;
    }
    
    printf("Connected to cFS at %s:%d\n", hostname, port);
    printf("Message interval: %d seconds\n", message_interval);
    printf("Key rotation interval: %d seconds\n", key_rotation_interval);
    printf("Press Ctrl+C to exit\n\n");
    
    /* Run the simulation */
    GroundStation_RunSimulation(message_interval, key_rotation_interval);
    
    /* Clean up */
    GroundStation_Shutdown();
    
    return 0;
}

/* Print help information */
void GroundStation_PrintHelp(void)
{
    printf("Usage: ground_station [options]\n");
    printf("Options:\n");
    printf("  -h hostname    Set the cFS hostname (default: %s)\n", DEFAULT_HOSTNAME);
    printf("  -p port        Set the cFS port (default: %d)\n", DEFAULT_PORT);
    printf("  -m interval    Set message interval in seconds (default: 5)\n");
    printf("  -k interval    Set key rotation interval in seconds (default: 30)\n");
    printf("  -?             Show this help\n");
}

/* Initialize cryptographic operations */
int GroundStation_InitCrypto(void)
{
    /* Initialize libgcrypt */
    if (!gcry_check_version("1.8.0")) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        return -1;
    }
    
    /* Disable secure memory */
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    
    /* Initialize the library */
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    
    /* Convert RSA public key from string to S-expression */
    gcry_error_t err = gcry_sexp_sscan(&GroundStation.RSAPublicKey, 
                                      NULL, 
                                      RSA_PUBLIC_KEY, 
                                      strlen(RSA_PUBLIC_KEY));
    if (err) {
        fprintf(stderr, "Failed to load RSA public key: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Initialize random number generator */
    gcry_randomize(NULL, 0, GCRY_STRONG_RANDOM);
    
    return 0;
}

/* Connect to cFS via UDP socket */
int GroundStation_Connect(const char *hostname, int port)
{
    /* Create UDP socket */
    GroundStation.SocketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (GroundStation.SocketFD < 0) {
        perror("Cannot create socket");
        return -1;
    }
    
    /* Set up the server address structure */
    memset(&GroundStation.ServerAddr, 0, sizeof(GroundStation.ServerAddr));
    GroundStation.ServerAddr.sin_family = AF_INET;
    GroundStation.ServerAddr.sin_port = htons(port);
    if (inet_pton(AF_INET, hostname, &GroundStation.ServerAddr.sin_addr) <= 0) {
        perror("Invalid address");
        close(GroundStation.SocketFD);
        return -1;
    }
    
    return 0;
}

/* Shutdown and cleanup */
void GroundStation_Shutdown(void)
{
    if (GroundStation.SocketFD >= 0) {
        close(GroundStation.SocketFD);
    }
    
    /* Release RSA key */
    gcry_sexp_release(GroundStation.RSAPublicKey);
    
    printf("\nGround Station Simulator shutdown complete.\n");
}

/* Encrypt a message using AES-256 */
int GroundStation_EncryptMessage(const char *plaintext, size_t plaintext_len, 
                                unsigned char *ciphertext, size_t *ciphertext_len)
{
    gcry_cipher_hd_t cipher;
    gcry_error_t err;
    
    /* Create a cipher handle */
    err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if (err) {
        fprintf(stderr, "Failed to open cipher: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Set key */
    err = gcry_cipher_setkey(cipher, GroundStation.AESKey, GroundStation.AESKeyLen);
    if (err) {
        gcry_cipher_close(cipher);
        fprintf(stderr, "Failed to set key: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Generate a random IV (16 bytes for AES) */
    unsigned char iv[16];
    gcry_randomize(iv, sizeof(iv), GCRY_STRONG_RANDOM);
    
    /* Set IV */
    err = gcry_cipher_setiv(cipher, iv, sizeof(iv));
    if (err) {
        gcry_cipher_close(cipher);
        fprintf(stderr, "Failed to set IV: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Calculate padding size (AES block size is 16 bytes) */
    size_t padded_len = ((plaintext_len + 15) / 16) * 16; /* Ceiling to multiple of 16 */
    unsigned char *padded_text = malloc(padded_len);
    if (!padded_text) {
        gcry_cipher_close(cipher);
        return -1;
    }
    
    /* Prepare padded data (simple zero padding) */
    memset(padded_text, 0, padded_len);
    memcpy(padded_text, plaintext, plaintext_len);
    
    /* Copy IV to the beginning of ciphertext */
    memcpy(ciphertext, iv, sizeof(iv));
    
    /* Encrypt */
    err = gcry_cipher_encrypt(cipher, ciphertext + sizeof(iv), padded_len, 
                             padded_text, padded_len);
    
    free(padded_text);
    gcry_cipher_close(cipher);
    
    if (err) {
        fprintf(stderr, "Failed to encrypt: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Set total ciphertext length (IV + encrypted data) */
    *ciphertext_len = sizeof(iv) + padded_len;
    
    return 0;
}

/* Generate a new AES key */
void GroundStation_GenerateNewAESKey(void)
{
    /* Generate a new 256-bit (32-byte) AES key */
    gcry_randomize(GroundStation.AESKey, 32, GCRY_VERY_STRONG_RANDOM);
    GroundStation.AESKeyLen = 32;
    
    printf("GROUND STATION: Generated new AES key #%d\n", 
           GroundStation.KeyRotationCounter + 1);
}

/* Encrypt the new AES key using RSA */
int GroundStation_EncryptNewKey(unsigned char *new_key, size_t key_len, 
                               unsigned char **encrypted_key, size_t *encrypted_len)
{
    gcry_error_t err;
    gcry_sexp_t key_sexp, enc_sexp;
    gcry_mpi_t key_mpi;
    
    /* Convert key to MPI */
    err = gcry_mpi_scan(&key_mpi, GCRYMPI_FMT_USG, new_key, key_len, NULL);
    if (err) {
        fprintf(stderr, "Failed to create MPI: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Create S-expression for the key */
    err = gcry_sexp_build(&key_sexp, NULL, "(data (value %m))", key_mpi);
    gcry_mpi_release(key_mpi);
    
    if (err) {
        fprintf(stderr, "Failed to create key S-exp: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Encrypt with RSA public key */
    err = gcry_pk_encrypt(&enc_sexp, key_sexp, GroundStation.RSAPublicKey);
    gcry_sexp_release(key_sexp);
    
    if (err) {
        fprintf(stderr, "Failed to encrypt key: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Extract the encrypted data */
    gcry_sexp_t data = gcry_sexp_find_token(enc_sexp, "a", 0);
    gcry_mpi_t enc_mpi = gcry_sexp_nth_mpi(data, 1, GCRYMPI_FMT_USG);
    
    /* Convert to binary */
    err = gcry_mpi_aprint(GCRYMPI_FMT_USG, encrypted_key, encrypted_len, enc_mpi);
    
    /* Clean up */
    gcry_sexp_release(enc_sexp);
    gcry_sexp_release(data);
    gcry_mpi_release(enc_mpi);
    
    if (err) {
        fprintf(stderr, "Failed to convert encrypted key: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        if (*encrypted_key) free(*encrypted_key);
        return -1;
    }
    
    return 0;
}

/* Send a message to cFS */
void GroundStation_SendMessage(uint16_t msgId, uint8_t cmdCode, void *payload, size_t payloadLen)
{
    static uint16_t sequence = 0;
    CFE_SB_Msg_t msg;
    size_t totalLen;
    
    /* Clear the message structure */
    memset(&msg, 0, sizeof(msg));
    
    /* Set up CCSDS header */
    msg.StreamId[0] = (msgId >> 8) & 0xFF;  /* MSB of message ID */
    msg.StreamId[1] = msgId & 0xFF;         /* LSB of message ID */
    
    /* Set sequence number */
    msg.Sequence[0] = (sequence >> 8) & 0xFF;
    msg.Sequence[1] = sequence & 0xFF;
    sequence++;
    
    /* Set function code for commands */
    msg.FunctionCode = cmdCode;
    
    /* Copy payload data if provided */
    if (payload != NULL && payloadLen > 0) {
        if (payloadLen > sizeof(msg.Payload)) {
            fprintf(stderr, "Payload too large for message buffer\n");
            return;
        }
        memcpy(msg.Payload, payload, payloadLen);
    }
    
    /* Calculate total message length */
    totalLen = CCSDS_PRI_HDR_SIZE + CCSDS_CMD_SEC_HDR_SIZE + payloadLen;
    
    /* Set length in header */
    msg.Length[0] = (totalLen >> 8) & 0xFF;
    msg.Length[1] = totalLen & 0xFF;
    
    /* Send the message to cFS via UDP */
    if (sendto(GroundStation.SocketFD, &msg, totalLen, 0,
              (struct sockaddr *)&GroundStation.ServerAddr,
              sizeof(GroundStation.ServerAddr)) < 0) {
        perror("sendto failed");
    }
}

/* Send an encrypted message to the satellite */
void GroundStation_SendEncryptedMessage(const char *message)
{
    unsigned char ciphertext[512];
    size_t ciphertext_len;
    
    /* Encrypt the message */
    int status = GroundStation_EncryptMessage(message, strlen(message), 
                                             ciphertext, &ciphertext_len);
    if (status != 0) {
        fprintf(stderr, "Failed to encrypt message\n");
        return;
    }
    
    printf("GROUND STATION: Sending encrypted message: \"%s\"\n", message);
    
    /* Send encrypted message to cFS */
    GroundStation_SendMessage(ENCRYPT_APP_ENCRYPTED_MID, 0, ciphertext, ciphertext_len);
    
    GroundStation.MessageCounter++;
}

/* Send a key rotation message to the satellite */
void GroundStation_SendKeyRotation(void)
{
    /* Generate a new AES key */
    GroundStation_GenerateNewAESKey();
    
    /* Encrypt the new key with RSA */
    unsigned char *encrypted_key = NULL;
    size_t encrypted_len = 0;
    
    int status = GroundStation_EncryptNewKey(GroundStation.AESKey, GroundStation.AESKeyLen, 
                                            &encrypted_key, &encrypted_len);
    if (status != 0) {
        fprintf(stderr, "Failed to encrypt new AES key\n");
        return;
    }
    
    printf("GROUND STATION: Sending encrypted new AES key #%d\n", 
           GroundStation.KeyRotationCounter + 1);
    
    /* Send key rotation message to cFS */
    GroundStation_SendMessage(ENCRYPT_APP_KEY_ROT_MID, 0, encrypted_key, encrypted_len);
    
    /* Free the encrypted key buffer */
    free(encrypted_key);
    
    GroundStation.KeyRotationCounter++;
}

/* Send a NO-OP command to the satellite */
void GroundStation_SendNoOpCommand(void)
{
    printf("GROUND STATION: Sending NO-OP command\n");
    GroundStation_SendMessage(ENCRYPT_APP_CMD_MID, ENCRYPT_APP_NOOP_CC, NULL, 0);
}

/* Send a RESET command to the satellite */
void GroundStation_SendResetCommand(void)
{
    printf("GROUND STATION: Sending RESET command\n");
    GroundStation_SendMessage(ENCRYPT_APP_CMD_MID, ENCRYPT_APP_RESET_CC, NULL, 0);
}

/* Run the ground station simulation */
void GroundStation_RunSimulation(int message_interval, int key_rotation_interval)
{
    time_t start_time, current_time;
    uint32_t run_seconds = 0;
    char message[256];
    
    /* Send an initial NO-OP command */
    GroundStation_SendNoOpCommand();
    
    /* Start the simulation */
    time(&start_time);
    
    while (1) {
        time(&current_time);
        run_seconds = (uint32_t)difftime(current_time, start_time);
        
        /* Check if it's time for key rotation */
        if (run_seconds > 0 && (run_seconds % key_rotation_interval) == 0) {
            GroundStation_SendKeyRotation();
            sleep(1); /* Ensure we don't trigger rotation again in the same second */
            continue;
        }
        
        /* Check if it's time to send a message */
        if (run_seconds > 0 && (run_seconds % message_interval) == 0) {
            /* Prepare message */
            if (GroundStation.KeyRotationCounter == 0) {
                strcpy(message, "Hello from Ground Station");
            } else {
                snprintf(message, sizeof(message), "Hello from Ground Station (Key #%d)",
                         GroundStation.KeyRotationCounter);
            }
            
            /* Send the encrypted message */
            GroundStation_SendEncryptedMessage(message);
            sleep(1); /* Ensure we don't send multiple messages in the same second */
        }
        
        /* Small delay to prevent CPU spinning */
        usleep(100000); /* 100ms */
    }
}