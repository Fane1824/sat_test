#include "encrypt_app.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gcrypt.h>
#include <time.h>

/* RSA public key in S-expression format (matching the private key in encrypt_app.c) */
const char *RSA_PUBLIC_KEY = 
    "(public-key (rsa (n #00BA65A53C3A3C02A87679B5F86A9BE4E5AB38475709E8784B0F2C3C573219E609AACB0C6D5F550879AA1AA80961C48AB663930F6FAAD5F1860E39A7B1A58A543#)"
    "(e #010001#)))";

/* Structure for holding ground station state */
typedef struct {
    unsigned char AESKey[32];
    size_t AESKeyLen;
    gcry_sexp_t RSAPublicKey;
    uint32_t MessageCounter;
    uint32_t KeyRotationCounter;
} GroundStation_t;

GroundStation_t GroundStation;

/* Function prototypes */
int GroundStation_InitCrypto(void);
int GroundStation_EncryptMessage(const char *plaintext, size_t plaintext_len, 
                                unsigned char *ciphertext, size_t *ciphertext_len);
int GroundStation_EncryptNewKey(unsigned char *new_key, size_t key_len, 
                               unsigned char *encrypted_key, size_t *encrypted_len);
void GroundStation_GenerateNewAESKey(void);
void GroundStation_SendMessage(const char *message);
void GroundStation_PerformKeyRotation(void);

/* Initialize ground station crypto */
int GroundStation_InitCrypto(void) 
{
    /* Initialize libgcrypt */
    if (!gcry_check_version("1.8.0")) {
        printf("libgcrypt version mismatch\n");
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
        printf("Failed to load RSA public key: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Initialize random number generator */
    gcry_randomize(NULL, 0, GCRY_STRONG_RANDOM);
    
    return 0;
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
        printf("Failed to open cipher: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Set key */
    err = gcry_cipher_setkey(cipher, GroundStation.AESKey, GroundStation.AESKeyLen);
    if (err) {
        gcry_cipher_close(cipher);
        printf("Failed to set key: %s/%s\n",
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
        printf("Failed to set IV: %s/%s\n",
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
        printf("Failed to encrypt: %s/%s\n",
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
        printf("Failed to create MPI: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Create S-expression for the key */
    err = gcry_sexp_build(&key_sexp, NULL, "(data (value %m))", key_mpi);
    gcry_mpi_release(key_mpi);
    
    if (err) {
        printf("Failed to create key S-exp: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Encrypt with RSA public key */
    err = gcry_pk_encrypt(&enc_sexp, key_sexp, GroundStation.RSAPublicKey);
    gcry_sexp_release(key_sexp);
    
    if (err) {
        printf("Failed to encrypt key: %s/%s\n",
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
        printf("Failed to convert encrypted key: %s/%s\n",
               gcry_strsource(err), gcry_strerror(err));
        free(*encrypted_key);
        return -1;
    }
    
    return 0;
}

/* Send an encrypted message to the satellite via the Software Bus */
void GroundStation_SendMessage(const char *message) 
{
    /* Encrypt the message */
    unsigned char ciphertext[512];
    size_t ciphertext_len;
    
    int status = GroundStation_EncryptMessage(message, strlen(message), 
                                             ciphertext, &ciphertext_len);
    if (status != 0) {
        printf("Failed to encrypt message\n");
        return;
    }
    
    printf("GROUND STATION: Sending encrypted message: \"%s\"\n", message);
    
    /* Create a message buffer for sending via Software Bus */
    CFE_SB_Buffer_t MsgBuf;
    CFE_MSG_Init(&MsgBuf.Msg, ENCRYPT_APP_ENCRYPTED_MID, sizeof(CFE_SB_Buffer_t));
    
    /* Set the message size */
    CFE_MSG_SetSize(&MsgBuf.Msg, CFE_SB_GetMsgHdrSize() + ciphertext_len);
    
    /* Copy the encrypted data into the message */
    uint8 *msgData = CFE_SB_GetUserData(&MsgBuf.Msg);
    memcpy(msgData, ciphertext, ciphertext_len);
    
    /* Send the message */
    status = CFE_SB_TransmitMsg(&MsgBuf.Msg, true);
    if (status != CFE_SUCCESS) {
        printf("Failed to send encrypted message, status = %d\n", (int)status);
    } else {
        printf("Message sent to software bus\n");
    }
}

/* Perform a key rotation - send a new AES key encrypted with RSA */
void GroundStation_PerformKeyRotation(void) 
{
    /* Generate a new AES key */
    GroundStation_GenerateNewAESKey();
    
    /* Encrypt the new key with RSA */
    unsigned char *encrypted_key = NULL;
    size_t encrypted_len = 0;
    
    int status = GroundStation_EncryptNewKey(GroundStation.AESKey, GroundStation.AESKeyLen, 
                                            &encrypted_key, &encrypted_len);
    if (status != 0) {
        printf("Failed to encrypt new AES key\n");
        return;
    }
    
    printf("GROUND STATION: Sending encrypted new AES key #%d\n", 
           GroundStation.KeyRotationCounter + 1);
    
    /* Create a message buffer for sending via Software Bus */
    CFE_SB_Buffer_t MsgBuf;
    CFE_MSG_Init(&MsgBuf.Msg, ENCRYPT_APP_KEY_ROT_MID, sizeof(CFE_SB_Buffer_t));
    
    /* Set the message size */
    CFE_MSG_SetSize(&MsgBuf.Msg, CFE_SB_GetMsgHdrSize() + encrypted_len);
    
    /* Copy the encrypted key into the message */
    uint8 *msgData = CFE_SB_GetUserData(&MsgBuf.Msg);
    memcpy(msgData, encrypted_key, encrypted_len);
    
    /* Free the encrypted key buffer */
    free(encrypted_key);
    
    /* Send the message */
    status = CFE_SB_TransmitMsg(&MsgBuf.Msg, true);
    if (status != CFE_SUCCESS) {
        printf("Failed to send key rotation message, status = %d\n", (int)status);
    } else {
        printf("Key rotation message sent to software bus\n");
        GroundStation.KeyRotationCounter++;
    }
}

/* Entry point for ground station simulation */
void GroundStation_Main(void)
{
    int status;
    time_t start_time, current_time;
    uint32_t run_seconds = 0;
    char message[256];
    
    printf("Ground Station Simulation Starting...\n");
    
    /* Initialize crypto operations */
    status = GroundStation_InitCrypto();
    if (status != 0) {
        printf("Failed to initialize ground station crypto\n");
        return;
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
    
    time(&start_time);
    
    /* Main simulation loop */
    while (1) {
        time(&current_time);
        run_seconds = (uint32_t)difftime(current_time, start_time);
        
        /* Check if it's time for key rotation (every 10 seconds) */
        if (run_seconds > 0 && run_seconds % 10 == 0 && 
            GroundStation.MessageCounter % 10 == 0) {
            
            GroundStation_PerformKeyRotation();
            sleep(1); /* Ensure we don't trigger rotation again in the same second */
            continue;
        }
        
        /* Prepare message */
        if (GroundStation.KeyRotationCounter == 0) {
            strcpy(message, "Hello World");
        } else {
            snprintf(message, sizeof(message), "Hello World %d", GroundStation.KeyRotationCounter);
        }
        
        /* Send the encrypted message */
        GroundStation_SendMessage(message);
        GroundStation.MessageCounter++;
        
        /* Sleep for 1 second */
        sleep(1);
    }
}