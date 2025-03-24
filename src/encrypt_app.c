/*************************************************************************
**
** Include Files
*************************************************************************/
#include "encrypt_app.h"
#include <string.h>
#include <gcrypt.h>

/*************************************************************************
** Global Data
*************************************************************************/
ENCRYPT_APP_Data_t ENCRYPT_APP_Data;

/* RSA private key in S-expression format (hardcoded for this example) */
const char *RSA_PRIVATE_KEY = 
    "(private-key (rsa (n #00BA65A53C3A3C02A87679B5F86A9BE4E5AB38475709E8784B0F2C3C573219E609AACB0C6D5F550879AA1AA80961C48AB663930F6FAAD5F1860E39A7B1A58A543#)"
    "(e #010001#)"
    "(d #0471A07F8C41A538284D78094D5CA68B1860EB680F571BAB964FC9EBCA9894F15B2A49478956A04E464D0D2BA6BE6969B866F4D9BEE631A7055EC955F3315C73#)"
    "(p #00D2B037CB00F9B13FE4B4B3B571C95891BA2AE79F27E19F54D758B2F605F07B#)"
    "(q #00E13B2F0E41EB0079940C973D3D92F2AC0A64A9EF3507C73D5AF8D39C7F5557#)"
    "(u #7764D724705A5BB528446AB9C428CE693C1C77E8CFEF78C487CE0B9C96B17513#))";

/* Application entry point and main process loop */
void ENCRYPT_APP_Main(void)
{
    int32 status;
    
    /* Register the application with Executive Services */
    CFE_ES_RegisterApp();
    
    /* Initialize the application */
    status = ENCRYPT_APP_Init();
    if (status != CFE_SUCCESS)
    {
        ENCRYPT_APP_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Error initializing application, RC = %d\n", (int)status);
    }
    
    /* Application main loop */
    while (CFE_ES_RunLoop(&ENCRYPT_APP_Data.RunStatus) == true)
    {
        /* Wait for the next message */
        status = ENCRYPT_APP_RcvMsg(CFE_SB_PEND_FOREVER);
        
        if (status != CFE_SUCCESS)
        {
            CFE_ES_WriteToSysLog("ENCRYPT_APP: Error receiving message, RC = %d\n", (int)status);
        }
    }
    
    /* Release resources */
    CFE_ES_ExitApp(ENCRYPT_APP_Data.RunStatus);
}

/* Initialize application */
int32 ENCRYPT_APP_Init(void)
{
    int32 status;
    
    /* Initialize app data */
    ENCRYPT_APP_Data.RunStatus = CFE_ES_RunStatus_APP_RUN;
    ENCRYPT_APP_Data.MsgCounter = 0;
    ENCRYPT_APP_Data.KeyRotationCounter = 0;
    
    /* Initialize crypto operations */
    if (ENCRYPT_APP_InitCrypto() != 0) {
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Failed to initialize crypto\n");
        return CFE_ES_RunStatus_APP_ERROR;
    }
    
    /* Create message pipe */
    status = CFE_SB_CreatePipe(&ENCRYPT_APP_Data.CommandPipe, 
                              ENCRYPT_APP_PIPE_DEPTH, 
                              ENCRYPT_APP_PIPE_NAME);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Error creating pipe, RC = %d\n", (int)status);
        return status;
    }
    
    /* Subscribe to encrypted message */
    status = CFE_SB_Subscribe(ENCRYPT_APP_ENCRYPTED_MID, ENCRYPT_APP_Data.CommandPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Error subscribing to encrypted msgs, RC = %d\n", (int)status);
        return status;
    }
    
    /* Subscribe to key rotation message */
    status = CFE_SB_Subscribe(ENCRYPT_APP_KEY_ROT_MID, ENCRYPT_APP_Data.CommandPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Error subscribing to key rotation msgs, RC = %d\n", (int)status);
        return status;
    }
    
    /* Initialize AES key (example initial key) */
    unsigned char initialKey[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    
    memcpy(ENCRYPT_APP_Data.AESKey, initialKey, 32);
    ENCRYPT_APP_Data.AESKeyLen = 32;
    
    CFE_ES_WriteToSysLog("ENCRYPT_APP: Initialized successfully\n");
    
    return CFE_SUCCESS;
}

/* Initialize cryptographic operations */
int ENCRYPT_APP_InitCrypto(void)
{
    /* Initialize libgcrypt */
    if (!gcry_check_version("1.8.0")) {
        CFE_ES_WriteToSysLog("ENCRYPT_APP: libgcrypt version mismatch\n");
        return -1;
    }
    
    /* Disable secure memory */
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    
    /* Initialize the library */
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    
    /* Convert RSA private key from string to S-expression */
    gcry_error_t err = gcry_sexp_sscan(&ENCRYPT_APP_Data.RSAPrivateKey, 
                                      NULL, 
                                      RSA_PRIVATE_KEY, 
                                      strlen(RSA_PRIVATE_KEY));
    if (err) {
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Failed to load RSA private key: %s/%s\n",
                            gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    return 0;
}

/* Receive message */
int32 ENCRYPT_APP_RcvMsg(int32 iBlocking)
{
    CFE_SB_MsgPtr_t MsgPtr;
    int32 status;
    
    /* Wait for WakeUp messages from scheduler */
    status = CFE_SB_RcvMsg(&MsgPtr, ENCRYPT_APP_Data.CommandPipe, iBlocking);
    
    if (status == CFE_SUCCESS)
    {
        /* Process the received message */
        CFE_SB_MsgId_t MsgId = CFE_SB_GetMsgId(MsgPtr);
        
        if (CFE_SB_MsgId_Equal(MsgId, ENCRYPT_APP_ENCRYPTED_MID))
        {
            /* Process encrypted message */
            uint16 MsgSize = CFE_SB_GetTotalMsgLength(MsgPtr);
            uint8 *payload = CFE_SB_GetUserData(MsgPtr);
            uint16 payloadLen = MsgSize - CFE_SB_GetMsgHdrSize();
            
            unsigned char decrypted[256];
            memset(decrypted, 0, sizeof(decrypted));
            
            if (ENCRYPT_APP_DecryptMessage(payload, payloadLen, decrypted) == 0) {
                CFE_ES_WriteToSysLog("ENCRYPT_APP: Decrypted message: %s\n", decrypted);
                OS_printf("SATELLITE RECEIVED: %s\n", decrypted);
                ENCRYPT_APP_Data.MsgCounter++;
            } else {
                CFE_ES_WriteToSysLog("ENCRYPT_APP: Failed to decrypt message\n");
            }
        }
        else if (CFE_SB_MsgId_Equal(MsgId, ENCRYPT_APP_KEY_ROT_MID))
        {
            /* Process key rotation message */
            uint16 MsgSize = CFE_SB_GetTotalMsgLength(MsgPtr);
            uint8 *payload = CFE_SB_GetUserData(MsgPtr);
            uint16 payloadLen = MsgSize - CFE_SB_GetMsgHdrSize();
            
            if (ENCRYPT_APP_ProcessKeyRotation(payload, payloadLen) == 0) {
                CFE_ES_WriteToSysLog("ENCRYPT_APP: Key rotation successful\n");
                ENCRYPT_APP_Data.KeyRotationCounter++;
                OS_printf("SATELLITE: Received new AES key #%d\n", (int)ENCRYPT_APP_Data.KeyRotationCounter);
            } else {
                CFE_ES_WriteToSysLog("ENCRYPT_APP: Key rotation failed\n");
            }
        }
    }
    
    return status;
}

/* Decrypt an AES encrypted message */
int ENCRYPT_APP_DecryptMessage(const unsigned char *ciphertext, size_t ciphertext_len, 
                              unsigned char *plaintext)
{
    gcry_cipher_hd_t cipher;
    gcry_error_t err;
    
    /* Create a cipher handle */
    err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if (err) {
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Failed to open cipher: %s/%s\n",
                            gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Set key */
    err = gcry_cipher_setkey(cipher, ENCRYPT_APP_Data.AESKey, ENCRYPT_APP_Data.AESKeyLen);
    if (err) {
        gcry_cipher_close(cipher);
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Failed to set key: %s/%s\n",
                            gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Extract IV from beginning of ciphertext (first 16 bytes) */
    err = gcry_cipher_setiv(cipher, ciphertext, 16);
    if (err) {
        gcry_cipher_close(cipher);
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Failed to set IV: %s/%s\n",
                            gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Decrypt (ciphertext starts after IV) */
    err = gcry_cipher_decrypt(cipher, plaintext, ciphertext_len - 16, 
                              ciphertext + 16, ciphertext_len - 16);
    if (err) {
        gcry_cipher_close(cipher);
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Failed to decrypt: %s/%s\n",
                            gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    gcry_cipher_close(cipher);
    return 0;
}

/* Process a key rotation message (contains RSA-encrypted new AES key) */
int ENCRYPT_APP_ProcessKeyRotation(const unsigned char *encrypted_key, size_t key_len)
{
    gcry_error_t err;
    gcry_sexp_t enc_data, plain_data;
    
    /* Create S-expression from encrypted data */
    err = gcry_sexp_build(&enc_data, NULL, "(enc-val (rsa (a %b)))", 
                          (int)key_len, encrypted_key);
    if (err) {
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Failed to create encrypted S-exp: %s/%s\n",
                            gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Decrypt with private key */
    err = gcry_pk_decrypt(&plain_data, enc_data, ENCRYPT_APP_Data.RSAPrivateKey);
    gcry_sexp_release(enc_data);
    
    if (err) {
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Failed to decrypt key: %s/%s\n",
                            gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Extract the decrypted key */
    gcry_sexp_t value = gcry_sexp_find_token(plain_data, "value", 0);
    gcry_mpi_t mpi = gcry_sexp_nth_mpi(value, 1, GCRYMPI_FMT_USG);
    
    /* Convert MPI to binary */
    size_t aes_key_len;
    unsigned char *new_key;
    err = gcry_mpi_aprint(GCRYMPI_FMT_USG, &new_key, &aes_key_len, mpi);
    
    /* Clean up */
    gcry_sexp_release(plain_data);
    gcry_sexp_release(value);
    gcry_mpi_release(mpi);
    
    if (err || aes_key_len != 32) {
        free(new_key);
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Invalid AES key: %s/%s\n",
                            gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Update the AES key */
    memcpy(ENCRYPT_APP_Data.AESKey, new_key, 32);
    ENCRYPT_APP_Data.AESKeyLen = 32;
    
    /* Free allocated memory */
    free(new_key);
    
    return 0;
}