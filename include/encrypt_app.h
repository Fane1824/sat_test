#ifndef ENCRYPT_APP_H
#define ENCRYPT_APP_H

#include "cfe.h"
#include <gcrypt.h>

/************************************************************************
 ** Macro Definitions
 *************************************************************************/
#define ENCRYPT_APP_PIPE_DEPTH     32
#define ENCRYPT_APP_PIPE_NAME      "ENCRYPT_PIPE"

/* Command and Message IDs */
#define ENCRYPT_APP_ENCRYPTED_MID  0x1882
#define ENCRYPT_APP_KEY_ROT_MID    0x1883

/************************************************************************
 ** Type Definitions
 *************************************************************************/
typedef struct
{
    CFE_SB_PipeId_t    CommandPipe;
    uint32             RunStatus;
    uint32             MsgCounter;
    uint32             KeyRotationCounter;
    
    /* RSA Keys */
    gcry_sexp_t        RSAPrivateKey;
    
    /* AES Key */
    unsigned char      AESKey[32]; /* AES-256 key (32 bytes) */
    size_t             AESKeyLen;
    
    /* Buffer for decrypted messages */
    char               DecryptedMsg[256];
} ENCRYPT_APP_Data_t;

/************************************************************************
 ** Exported Functions
 *************************************************************************/
/**
 * \brief ENCRYPT APP Main Function
 */
void ENCRYPT_APP_Main(void);

/**
 * \brief Initialize the Encrypt App
 */
int32 ENCRYPT_APP_Init(void);

/**
 * \brief Decrypt an AES encrypted message
 */
int ENCRYPT_APP_DecryptMessage(const unsigned char *ciphertext, size_t ciphertext_len, 
                               unsigned char *plaintext);

/**
 * \brief Process a key rotation message
 */
int ENCRYPT_APP_ProcessKeyRotation(const unsigned char *encrypted_key, size_t key_len);

/**
 * \brief Initialize cryptographic operations
 */
int ENCRYPT_APP_InitCrypto(void);

/**
 * \brief Receive and process commands
 */
int32 ENCRYPT_APP_RcvMsg(int32 iBlocking);

#endif /* ENCRYPT_APP_H */