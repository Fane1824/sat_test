#ifndef ENCRYPT_APP_H
#define ENCRYPT_APP_H

/*
** Required header files
*/
#include "common_types.h"
#include "cfe_error.h"
#include "cfe_evs.h"
#include "cfe_sb.h"
#include "cfe_es.h"
#include "cfe_msg.h"
#include "cfe_time.h"

/*
** ENCRYPT App Macro Definitions
*/
#define ENCRYPT_APP_PIPE_DEPTH     32
#define ENCRYPT_APP_PIPE_NAME      "ENCRYPT_APP_PIPE"

/* Default Message IDs - make sure these match your deployment */
#define ENCRYPT_APP_CMD_MID        0x1882
#define ENCRYPT_APP_SEND_HK_MID    0x1883 
#define ENCRYPT_APP_ENCRYPTED_MID  0x1884
#define ENCRYPT_APP_KEY_ROT_MID    0x1885
#define ENCRYPT_APP_HK_TLM_MID     0x0882

/* Command codes */
#define ENCRYPT_APP_NOOP_CC        0
#define ENCRYPT_APP_RESET_CC       1

/* Event IDs */
#define ENCRYPT_APP_RESERVED_EID              0
#define ENCRYPT_APP_STARTUP_INF_EID           1
#define ENCRYPT_APP_COMMAND_ERR_EID           2
#define ENCRYPT_APP_COMMANDNOP_INF_EID        3
#define ENCRYPT_APP_COMMANDRST_INF_EID        4
#define ENCRYPT_APP_DECRYPT_SUCCESS_EID       5
#define ENCRYPT_APP_DECRYPT_ERR_EID           6
#define ENCRYPT_APP_KEY_ROTATION_SUCCESS_EID  7
#define ENCRYPT_APP_KEY_ROTATION_ERR_EID      8
#define ENCRYPT_APP_CRYPTO_INIT_ERR_EID       9
#define ENCRYPT_APP_PIPE_ERR_EID             10
#define ENCRYPT_APP_SUB_ERR_EID              11
#define ENCRYPT_APP_PERF_ID                  40

/*
** Type definitions
*/
typedef struct
{
    /* CFE Event Table */
    CFE_EVS_BinFilter_t  EventFilters[8];
    
    /* CFE Software Bus interfaces */
    CFE_SB_PipeId_t  CommandPipe;
    
    /* Task runtime info */
    uint32  RunStatus;
    
    /* Counters */
    uint32  MsgCounter;
    uint32  KeyRotationCounter;
    uint32  CommandCounter;
    uint32  CommandErrorCounter;
    
    /* Housekeeping telemetry */
    CFE_MSG_Message_t HkTlm;
    
    /* RSA Keys */
    gcry_sexp_t  RSAPrivateKey;
    
    /* AES Key */
    unsigned char  AESKey[32]; /* AES-256 key (32 bytes) */
    size_t         AESKeyLen;
    
    /* Buffer for decrypted messages */
    char  DecryptedMsg[256];
    
} ENCRYPT_APP_Data_t;

/*
** Exported Functions
*/
/**
 * \brief ENCRYPT APP Main Function
 */
void ENCRYPT_APP_Main(void);

/**
 * \brief Initialize the Encrypt App
 */
CFE_Status_t ENCRYPT_APP_Init(void);

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
 * \brief Process incoming commands and messages
 */
void ENCRYPT_APP_ProcessCommandPacket(CFE_SB_Buffer_t *BufPtr);

/**
 * \brief Send housekeeping telemetry
 */
void ENCRYPT_APP_ReportHousekeeping(void);

/*
** The following is an internal structure used for the encrypted messages table.
*/
typedef struct
{
    uint8  Payload[1024];  /* Message payload (encrypted data) */
} ENCRYPT_Message_t;

/*
** The following is an internal structure used for the key rotation table.
*/
typedef struct
{
    uint8  EncryptedKey[512];  /* RSA-encrypted AES key */
} ENCRYPT_KeyRotation_t;

#endif /* ENCRYPT_APP_H */