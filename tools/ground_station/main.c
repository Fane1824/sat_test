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
#define ENCRYPT_APP_CMD_MID            0x1882
#define ENCRYPT_APP_SEND_HK_MID        0x1883
#define ENCRYPT_APP_ENCRYPTED_MID      0x1884
#define ENCRYPT_APP_KEY_ROT_MID        0x1885

/* Default connection settings */
#define DEFAULT_HOSTNAME  "127.0.0.1"
#define DEFAULT_CMD_PORT    1234  /* CI_LAB port for commands */
#define DEFAULT_TLM_PORT    1235  /* TO_LAB port for telemetry/data */
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
    int CmdSocketFD;         /* Socket for commands to CI_LAB */
    int TlmSocketFD;         /* Socket for telemetry to TO_LAB */
    struct sockaddr_in CmdAddr;  /* Address for CI_LAB */
    struct sockaddr_in TlmAddr;  /* Address for TO_LAB */
} GroundStation_t;

GroundStation_t GroundStation;


/* Function prototypes */
int GroundStation_InitCrypto(void);
int GroundStation_Connect(const char *hostname, int cmd_port, int tlm_port);
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
void GroundStation_SendMessage(uint16_t msgId, uint8_t cmdCode, void *payload, size_t payloadLen, int useCmd);
void GroundStation_RunSimulation(int message_interval, int key_rotation_interval);
void GroundStation_PrintHelp(void);
void GroundStation_SendTestTelemetry(void);

/* Main function */
int main(int argc, char *argv[])
{
    char *hostname = DEFAULT_HOSTNAME;
    int cmd_port = DEFAULT_CMD_PORT;
    int tlm_port = DEFAULT_TLM_PORT;
    int message_interval = 5;    /* seconds between messages */
    int key_rotation_interval = 30; /* seconds between key rotations */
    int c;
    
    printf("Ground Station Simulator for ENCRYPT_APP\n");
    printf("----------------------------------------\n");
    
    /* Parse command line arguments */
    while ((c = getopt(argc, argv, "h:p:t:m:k:?")) != -1) {
        switch (c) {
            case 'h':
                hostname = optarg;
                break;
            case 'p':
                cmd_port = atoi(optarg);
                break;
            case 't':
                tlm_port = atoi(optarg);
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
    if (GroundStation_Connect(hostname, cmd_port, tlm_port) != 0) {
        fprintf(stderr, "Failed to connect to cFS. Exiting.\n");
        return 1;
    }
    
    printf("Connected to cFS at %s (cmd port: %d, tlm port: %d)\n", 
           hostname, cmd_port, tlm_port);
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
    printf("  -p port        Set the CI_LAB command port (default: %d)\n", DEFAULT_CMD_PORT);
    printf("  -t port        Set the TO_LAB telemetry port (default: %d)\n", DEFAULT_TLM_PORT);
    printf("  -m interval    Set message interval in seconds (default: 5)\n");
    printf("  -k interval    Set key rotation interval in seconds (default: 30)\n");
    printf("  -?             Show this help\n");
}

/* Initialize cryptographic operations */
/* Remove the RSA_PUBLIC_KEY constant */
/* And modify the GroundStation_InitCrypto function: */

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
    
    /* Create RSA public key from components instead of string */
    gcry_mpi_t n, e;
    gcry_error_t err;
    
    /* Import the modulus (n) */
    err = gcry_mpi_scan(&n, GCRYMPI_FMT_HEX, 
        "00BA65A53C3A3C02A87679B5F86A9BE4E5AB38475709E8784B0F2C3C573219E609AACB0C6D5F550879AA1AA80961C48AB663930F6FAAD5F1860E39A7B1A58A543", 
        0, NULL);
    if (err) {
        fprintf(stderr, "Failed to create modulus MPI: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Import the public exponent (e) */
    err = gcry_mpi_scan(&e, GCRYMPI_FMT_HEX, "010001", 0, NULL);
    if (err) {
        gcry_mpi_release(n);
        fprintf(stderr, "Failed to create exponent MPI: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Create the S-expression */
    err = gcry_sexp_build(&GroundStation.RSAPublicKey, NULL,
                        "(public-key (rsa (n %m) (e %m)))", n, e);
    
    /* Free the MPIs */
    gcry_mpi_release(n);
    gcry_mpi_release(e);
    
    if (err) {
        fprintf(stderr, "Failed to build RSA public key: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Initialize random number generator */
    gcry_randomize(NULL, 0, GCRY_STRONG_RANDOM);
    
    return 0;
}

/* Connect to cFS via UDP socket */
int GroundStation_Connect(const char *hostname, int cmd_port, int tlm_port)
{
    /* Create command socket (CI_LAB) */
    GroundStation.CmdSocketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (GroundStation.CmdSocketFD < 0) {
        perror("Cannot create command socket");
        return -1;
    }
    
    /* Create telemetry socket (TO_LAB) */
    GroundStation.TlmSocketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (GroundStation.TlmSocketFD < 0) {
        perror("Cannot create telemetry socket");
        close(GroundStation.CmdSocketFD);
        return -1;
    }
    
    /* Set up the command address structure */
    memset(&GroundStation.CmdAddr, 0, sizeof(GroundStation.CmdAddr));
    GroundStation.CmdAddr.sin_family = AF_INET;
    GroundStation.CmdAddr.sin_port = htons(cmd_port);
    
    /* Set up the telemetry address structure */
    memset(&GroundStation.TlmAddr, 0, sizeof(GroundStation.TlmAddr));
    GroundStation.TlmAddr.sin_family = AF_INET;
    GroundStation.TlmAddr.sin_port = htons(tlm_port);
    
    /* Convert hostname to IP address */
    if (inet_pton(AF_INET, hostname, &GroundStation.CmdAddr.sin_addr) <= 0) {
        perror("Invalid address");
        close(GroundStation.CmdSocketFD);
        close(GroundStation.TlmSocketFD);
        return -1;
    }
    
    /* Use same IP for telemetry socket */
    memcpy(&GroundStation.TlmAddr.sin_addr, &GroundStation.CmdAddr.sin_addr, 
           sizeof(GroundStation.CmdAddr.sin_addr));
    
    return 0;
}

/* Shutdown and cleanup */
void GroundStation_Shutdown(void)
{
    if (GroundStation.CmdSocketFD >= 0) {
        close(GroundStation.CmdSocketFD);
    }
    
    if (GroundStation.TlmSocketFD >= 0) {
        close(GroundStation.TlmSocketFD);
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
void GroundStation_SendMessage(uint16_t msgId, uint8_t cmdCode, void *payload, 
                              size_t payloadLen, int useCmd)
{
    static uint16_t cmd_sequence = 0;
    static uint16_t tlm_sequence = 0;
    CFE_SB_Msg_t msg;
    size_t totalLen;
    uint16_t *sequence = useCmd ? &cmd_sequence : &tlm_sequence;
    struct sockaddr_in *addr = useCmd ? &GroundStation.CmdAddr : &GroundStation.TlmAddr;
    int socketFD = useCmd ? GroundStation.CmdSocketFD : GroundStation.TlmSocketFD;
    
    /* Clear the message structure */
    memset(&msg, 0, sizeof(msg));
    
    /* Set up CCSDS header */
    msg.StreamId[0] = (msgId >> 8) & 0xFF;  /* MSB of message ID */
    msg.StreamId[1] = msgId & 0xFF;         /* LSB of message ID */
    
    /* Set sequence number */
    msg.Sequence[0] = (*sequence >> 8) & 0xFF;
    msg.Sequence[1] = *sequence & 0xFF;
    (*sequence)++;
    
    /* Set function code for commands */
    if (useCmd) {
        msg.FunctionCode = cmdCode;
    }
    
    /* Copy payload data if provided */
    if (payload != NULL && payloadLen > 0) {
        if (payloadLen > sizeof(msg.Payload)) {
            fprintf(stderr, "Payload too large for message buffer\n");
            return;
        }
        memcpy(msg.Payload, payload, payloadLen);
    }
    
    /* Calculate total message length */
    if (useCmd) {
        totalLen = CCSDS_PRI_HDR_SIZE + CCSDS_CMD_SEC_HDR_SIZE + payloadLen;
    } else {
        totalLen = CCSDS_PRI_HDR_SIZE + payloadLen;  /* No secondary header for telemetry */
    }
    
    /* Set length in header */
    msg.Length[0] = ((totalLen - 1) >> 8) & 0xFF;  /* Length field is size-1 */
    msg.Length[1] = (totalLen - 1) & 0xFF;
    
    /* Send the message to cFS via UDP */
    if (sendto(socketFD, &msg, totalLen, 0,
              (struct sockaddr *)addr, sizeof(*addr)) < 0) {
        perror("sendto failed");
    }
}

void GroundStation_SendEncryptedMessage(const char *message) 
{
    /* Debugging helper function */
    void print_hex_dump(const char *title, const void *data, size_t len) {
        printf("%s (%zu bytes):\n", title, len);
        const unsigned char *p = data;
        for (size_t i = 0; i < len; i++) {
            printf("%02X ", p[i]);
            if ((i + 1) % 16 == 0 || i == len - 1)
                printf("\n");
        }
    }

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
    err = gcry_cipher_setkey(cipher, GroundStation.AESKey, sizeof(GroundStation.AESKey));
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
    
    /* Create telemetry packet for TO_LAB with encrypted data */
    /* CCSDS Telemetry Primary Header (6 bytes) */
    uint8_t tlm_header[6] = {0};
    tlm_header[0] = 0x08;  /* Version (3 bits = 0), Type (1 bit = 0 for tlm), Sec Hdr Flag (1 bit = 0), App ID (3 bits MSB) */
    tlm_header[1] = 0x84;  /* App ID (8 bits LSB) - ENCRYPT_APP_ENCRYPTED_MID (0x0884 for telemetry) */
    tlm_header[2] = 0xC0;  /* Sequence flags (2 bits), Sequence count (6 bits MSB) */
    tlm_header[3] = 0x00;  /* Sequence count (8 bits LSB) */
    
    uint16_t length = encrypted_len - 1;  /* CCSDS length is total bytes - 1 */
    tlm_header[4] = (length >> 8) & 0xFF;
    tlm_header[5] = length & 0xFF;
    
    uint8_t tlm_packet[BUFFER_SIZE];
    memcpy(tlm_packet, tlm_header, 6);
    memcpy(tlm_packet + 6, ciphertext, encrypted_len);
    
    print_hex_dump("Sending telemetry packet", tlm_packet, 6 + encrypted_len);
    
    /* Send the telemetry packet to TO_LAB */
    if (sendto(GroundStation.TlmSocketFD, tlm_packet, 6 + encrypted_len, 0,
              (struct sockaddr *)&GroundStation.TlmAddr, 
              sizeof(GroundStation.TlmAddr)) < 0) {
        perror("sendto failed for encrypted message");
    } else {
        printf("Sent encrypted message to TO_LAB (port %d): \"%s\"\n", 
            ntohs(GroundStation.TlmAddr.sin_port), message);
        printf("Packet size: %zu bytes\n", 6 + encrypted_len);
        GroundStation.MessageCounter++;
    }
    
    /* Clean up */
    free(plaintext);
    gcry_cipher_close(cipher);
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
    
    /* Create telemetry packet for TO_LAB with key rotation data */
    /* CCSDS Telemetry Primary Header (6 bytes) */
    uint8_t tlm_header[6] = {0};
    tlm_header[0] = 0x08;  /* Version (3 bits = 0), Type (1 bit = 0 for tlm), Sec Hdr Flag (1 bit = 0), App ID (3 bits MSB) */
    tlm_header[1] = 0x85;  /* App ID (8 bits LSB) - ENCRYPT_APP_KEY_ROT_MID (0x0885 for telemetry) */
    tlm_header[2] = 0xC0;  /* Sequence flags (2 bits), Sequence count (6 bits MSB) */
    tlm_header[3] = 0x00;  /* Sequence count (8 bits LSB) */
    
    uint16_t length = encrypted_len - 1;  /* CCSDS length is total bytes - 1 */
    tlm_header[4] = (length >> 8) & 0xFF;
    tlm_header[5] = length & 0xFF;
    
    uint8_t tlm_packet[BUFFER_SIZE];
    memcpy(tlm_packet, tlm_header, 6);
    memcpy(tlm_packet + 6, encrypted_key, encrypted_len);
    
    /* Send the telemetry packet to TO_LAB */
    if (sendto(GroundStation.TlmSocketFD, tlm_packet, 6 + encrypted_len, 0,
              (struct sockaddr *)&GroundStation.TlmAddr, 
              sizeof(GroundStation.TlmAddr)) < 0) {
        perror("sendto failed for key rotation");
    } else {
        printf("Sent key rotation to satellite\n");
        GroundStation.KeyRotationCounter++;
    }
    
    /* Free the encrypted key buffer */
    free(encrypted_key);
}

/* Send a NO-OP command to the satellite */
void GroundStation_SendNoOpCommand(void)
{
    printf("GROUND STATION: Sending NO-OP command\n");
    
    /* CCSDS Command Packet for CI_LAB */
    uint8_t cmd_packet[8] = {0};  /* CI_LAB expects 8-byte command */
    cmd_packet[0] = 0x18;  /* Version (3 bits = 1), Type (1 bit = 1 for cmd), Sec Hdr Flag (1 bit = 1), App ID (3 bits MSB) */
    cmd_packet[1] = 0x82;  /* App ID (8 bits LSB) - ENCRYPT_APP_CMD_MID (0x1882) */
    cmd_packet[2] = 0xC0;  /* Sequence flags (2 bits), Sequence count (6 bits MSB) */
    cmd_packet[3] = 0x00;  /* Sequence count (8 bits LSB) */
    cmd_packet[4] = 0x00;  /* Packet length MSB (length of secondary header + data - 1) */
    cmd_packet[5] = 0x01;  /* Packet length LSB = 1 byte of data */
    cmd_packet[6] = ENCRYPT_APP_NOOP_CC;  /* Command code */
    cmd_packet[7] = 0x00;  /* Checksum or reserved */
    
    /* Send command to CI_LAB */
    if (sendto(GroundStation.CmdSocketFD, cmd_packet, sizeof(cmd_packet), 0,
              (struct sockaddr *)&GroundStation.CmdAddr, 
              sizeof(GroundStation.CmdAddr)) < 0) {
        perror("sendto failed for NOOP command");
    }
}

/* Send a RESET command to the satellite */
void GroundStation_SendResetCommand(void)
{
    printf("GROUND STATION: Sending RESET command\n");
    
    /* CCSDS Command Packet for CI_LAB */
    uint8_t cmd_packet[8] = {0};  /* CI_LAB expects 8-byte command */
    cmd_packet[0] = 0x18;  /* Version (3 bits = 1), Type (1 bit = 1 for cmd), Sec Hdr Flag (1 bit = 1), App ID (3 bits MSB) */
    cmd_packet[1] = 0x82;  /* App ID (8 bits LSB) - ENCRYPT_APP_CMD_MID (0x1882) */
    cmd_packet[2] = 0xC0;  /* Sequence flags (2 bits), Sequence count (6 bits MSB) */
    cmd_packet[3] = 0x00;  /* Sequence count (8 bits LSB) */
    cmd_packet[4] = 0x00;  /* Packet length MSB (length of secondary header + data - 1) */
    cmd_packet[5] = 0x01;  /* Packet length LSB = 1 byte of data */
    cmd_packet[6] = ENCRYPT_APP_RESET_CC;  /* Command code */
    cmd_packet[7] = 0x00;  /* Checksum or reserved */
    
    /* Send command to CI_LAB */
    if (sendto(GroundStation.CmdSocketFD, cmd_packet, sizeof(cmd_packet), 0,
              (struct sockaddr *)&GroundStation.CmdAddr, 
              sizeof(GroundStation.CmdAddr)) < 0) {
        perror("sendto failed for RESET command");
    }
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
        GroundStation_SendTestTelemetry();
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

/* Add a function to send a very simple telemetry packet that any app should receive */
void GroundStation_SendTestTelemetry(void)
{
    /* Create a very simple telemetry packet */
    uint8_t test_packet[16] = {0};
    
    /* CCSDS Telemetry Header (standard telemetry) */
    test_packet[0] = 0x08;  /* Version=000, Type=0 (tlm), 2nd hdr flag=0, AppID=00 (3 MSB) */
    test_packet[1] = 0x01;  /* AppID (8 LSB) - Use 0x0801 which many apps subscribe to */
    test_packet[2] = 0xC0;  /* Sequence flags=11, Sequence count=000000 */
    test_packet[3] = 0x00;  /* Sequence count (8 LSB) */
    test_packet[4] = 0x00;  /* Length (MSB) - Total bytes following primary header minus 1 */
    test_packet[5] = 0x09;  /* Length (LSB) - 10 bytes - 1 = 9 */
    
    /* Simple payload */
    test_packet[6] = 0xDE;
    test_packet[7] = 0xAD;
    test_packet[8] = 0xBE;
    test_packet[9] = 0xEF;
    test_packet[10] = 0xCA;
    test_packet[11] = 0xFE;
    test_packet[12] = 0xBA;
    test_packet[13] = 0xBE;
    test_packet[14] = 0x12;
    test_packet[15] = 0x34;
    
    printf("\n*** SENDING TEST TELEMETRY PACKET ***\n");
    printf("Sending to TO_LAB on port %d\n", ntohs(GroundStation.TlmAddr.sin_port));
    print_hex_dump("Test packet", test_packet, sizeof(test_packet));
    
    /* Send the packet to TO_LAB */
    if (sendto(GroundStation.TlmSocketFD, test_packet, sizeof(test_packet), 0,
              (struct sockaddr *)&GroundStation.TlmAddr, 
              sizeof(GroundStation.TlmAddr)) < 0) {
        printf("Error sending test telemetry: %s\n", strerror(errno));
    } else {
        printf("Successfully sent test telemetry packet\n");
    }
    printf("*** END TEST TELEMETRY ***\n\n");
}

/* Call this function periodically in your main simulation loop */