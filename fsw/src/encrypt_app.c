/*
** Required header files
*/
#include "encrypt_app.h"
#include "encrypt_app_events.h"
#include "encrypt_app_version.h"
#include <string.h>
#include <gcrypt.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>

/*
** Global Data
*/
ENCRYPT_APP_Data_t ENCRYPT_APP_Data;

/* RSA private key in S-expression format (hardcoded for this example) */
const char *RSA_PRIVATE_KEY = 
    "(private-key (rsa (n #00BA65A53C3A3C02A87679B5F86A9BE4E5AB38475709E8784B0F2C3C573219E609AACB0C6D5F550879AA1AA80961C48AB663930F6FAAD5F1860E39A7B1A58A543#)"
    "(e #010001#)"
    "(d #0471A07F8C41A538284D78094D5CA68B1860EB680F571BAB964FC9EBCA9894F15B2A49478956A04E464D0D2BA6BE6969B866F4D9BEE631A7055EC955F3315C73#)"
    "(p #00D2B037CB00F9B13FE4B4B3B571C95891BA2AE79F27E19F54D758B2F605F07B#)"
    "(q #00E13B2F0E41EB0079940C973D3D92F2AC0A64A9EF3507C73D5AF8D39C7F5557#)"
    "(u #7764D724705A5BB528446AB9C428CE693C1C77E8CFEF78C487CE0B9C96B17513#))";

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* ENCRYPT_APP_Main() -- Application entry point and main process loop      */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void ENCRYPT_APP_Main(void)
{
    int32 status;
    CFE_SB_Buffer_t *SBBufPtr;

    /* Initialize the application */
    status = ENCRYPT_APP_Init();
    
    if (status != CFE_SUCCESS)
    {
        ENCRYPT_APP_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Error initializing app: 0x%08X\n", (unsigned int)status);
    }
    else
    {
        /* Application main loop */
        while (CFE_ES_RunLoop(&ENCRYPT_APP_Data.RunStatus) == true)
        {
            /* Check for UDP messages */
            ENCRYPT_APP_CheckUdpMessages();
            
            /* Pend on receipt of command packet with timeout */
            status = CFE_SB_ReceiveBuffer(&SBBufPtr, ENCRYPT_APP_Data.CommandPipe, 100); /* 100ms timeout */
            
            if (status == CFE_SUCCESS)
            {
                /* Process received command packet */
                ENCRYPT_APP_ProcessCommandPacket(SBBufPtr);
            }
            else if (status != CFE_SB_TIME_OUT)
            {
                CFE_EVS_SendEvent(ENCRYPT_APP_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
                                 "ENCRYPT_APP: SB ReceiveBuffer error (0x%08X)", (unsigned int)status);
            }
        }
    }

    /* Close UDP socket before exiting */
    if (ENCRYPT_APP_Data.DirectSocketFD >= 0) {
        close(ENCRYPT_APP_Data.DirectSocketFD);
    }

    /* Exit the application */
    CFE_ES_ExitApp(ENCRYPT_APP_Data.RunStatus);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* ENCRYPT_APP_Init() -- App initialization                                  */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
CFE_Status_t ENCRYPT_APP_Init(void)
{
    int32 status;

    /* Initialize app command execution counters */
    ENCRYPT_APP_Data.CommandCounter = 0;
    ENCRYPT_APP_Data.CommandErrorCounter = 0;
    ENCRYPT_APP_Data.MsgCounter = 0;
    ENCRYPT_APP_Data.KeyRotationCounter = 0;

    /* Initialize app configuration data */
    ENCRYPT_APP_Data.RunStatus = CFE_ES_RunStatus_APP_RUN;

    /* Initialize event filter table */
    ENCRYPT_APP_Data.EventFilters[0].EventID = ENCRYPT_APP_STARTUP_INF_EID;
    ENCRYPT_APP_Data.EventFilters[0].Mask    = 0x0000;
    ENCRYPT_APP_Data.EventFilters[1].EventID = ENCRYPT_APP_COMMAND_ERR_EID;
    ENCRYPT_APP_Data.EventFilters[1].Mask    = 0x0000;
    ENCRYPT_APP_Data.EventFilters[2].EventID = ENCRYPT_APP_COMMANDNOP_INF_EID;
    ENCRYPT_APP_Data.EventFilters[2].Mask    = 0x0000;
    ENCRYPT_APP_Data.EventFilters[3].EventID = ENCRYPT_APP_COMMANDRST_INF_EID;
    ENCRYPT_APP_Data.EventFilters[3].Mask    = 0x0000;
    ENCRYPT_APP_Data.EventFilters[4].EventID = ENCRYPT_APP_DECRYPT_SUCCESS_EID;
    ENCRYPT_APP_Data.EventFilters[4].Mask    = 0x0000;
    ENCRYPT_APP_Data.EventFilters[5].EventID = ENCRYPT_APP_DECRYPT_ERR_EID;
    ENCRYPT_APP_Data.EventFilters[5].Mask    = 0x0000;
    ENCRYPT_APP_Data.EventFilters[6].EventID = ENCRYPT_APP_KEY_ROTATION_SUCCESS_EID;
    ENCRYPT_APP_Data.EventFilters[6].Mask    = 0x0000;
    ENCRYPT_APP_Data.EventFilters[7].EventID = ENCRYPT_APP_KEY_ROTATION_ERR_EID;
    ENCRYPT_APP_Data.EventFilters[7].Mask    = 0x0000;

    /* Register the events */
    status = CFE_EVS_Register(ENCRYPT_APP_Data.EventFilters, 8,
                             CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("ENCRYPT_APP: Error registering events: 0x%08X\n", (unsigned int)status);
        return status;
    }

    /* Initialize housekeeping packet */
    CFE_MSG_Init(&ENCRYPT_APP_Data.HkTlm, CFE_SB_ValueToMsgId(ENCRYPT_APP_HK_TLM_MID), sizeof(ENCRYPT_APP_Data.HkTlm));

    /* Initialize crypto operations */
    if (ENCRYPT_APP_InitCrypto() != 0)
    {
        CFE_EVS_SendEvent(ENCRYPT_APP_CRYPTO_INIT_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Error initializing crypto");
        return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
    }

    /* Create Software Bus message pipe */
    status = CFE_SB_CreatePipe(&ENCRYPT_APP_Data.CommandPipe, ENCRYPT_APP_PIPE_DEPTH,
                              ENCRYPT_APP_PIPE_NAME);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(ENCRYPT_APP_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Error creating pipe: 0x%08X", (unsigned int)status);
        return status;
    }

    /* Subscribe to command messages */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(ENCRYPT_APP_CMD_MID), ENCRYPT_APP_Data.CommandPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(ENCRYPT_APP_SUB_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Error subscribing to commands: 0x%08X", (unsigned int)status);
        return status;
    }

    /* Subscribe to housekeeping request commands */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(ENCRYPT_APP_SEND_HK_MID), ENCRYPT_APP_Data.CommandPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(ENCRYPT_APP_SUB_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Error subscribing to HK requests: 0x%08X", (unsigned int)status);
        return status;
    }

    /* Subscribe to encrypted message */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(ENCRYPT_APP_ENCRYPTED_MID), ENCRYPT_APP_Data.CommandPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(ENCRYPT_APP_SUB_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Error subscribing to encrypted msgs: 0x%08X", (unsigned int)status);
        return status;
    }

    /* Subscribe to key rotation message */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(ENCRYPT_APP_KEY_ROT_MID), ENCRYPT_APP_Data.CommandPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(ENCRYPT_APP_SUB_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Error subscribing to key rotation msgs: 0x%08X", (unsigned int)status);
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

    /* Set up UDP socket for direct communication */
    ENCRYPT_APP_Data.DirectSocketFD = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ENCRYPT_APP_Data.DirectSocketFD < 0) {
        OS_printf("ENCRYPT_APP: Failed to create UDP socket\n");
        CFE_EVS_SendEvent(ENCRYPT_APP_CRYPTO_INIT_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Failed to create UDP socket");
        return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
    }
    
    /* Set socket to non-blocking */
    int flags = fcntl(ENCRYPT_APP_Data.DirectSocketFD, F_GETFL, 0);
    fcntl(ENCRYPT_APP_Data.DirectSocketFD, F_SETFL, flags | O_NONBLOCK);
    
    /* Set up UDP address */
    memset(&ENCRYPT_APP_Data.DirectAddr, 0, sizeof(ENCRYPT_APP_Data.DirectAddr));
    ENCRYPT_APP_Data.DirectAddr.sin_family = AF_INET;
    ENCRYPT_APP_Data.DirectAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    ENCRYPT_APP_Data.DirectAddr.sin_port = htons(1236);  /* Listen on port 1236 */
    
    /* Bind socket to address */
    if (bind(ENCRYPT_APP_Data.DirectSocketFD, 
            (struct sockaddr*)&ENCRYPT_APP_Data.DirectAddr, 
            sizeof(ENCRYPT_APP_Data.DirectAddr)) < 0) {
        OS_printf("ENCRYPT_APP: Failed to bind UDP socket\n");
        CFE_EVS_SendEvent(ENCRYPT_APP_CRYPTO_INIT_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Failed to bind UDP socket");
        close(ENCRYPT_APP_Data.DirectSocketFD);
        return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
    }
    
    OS_printf("ENCRYPT_APP: UDP socket listening on port 1236\n");

    /* Application startup event message */
    CFE_EVS_SendEvent(ENCRYPT_APP_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
                     "ENCRYPT_APP Initialized. Version %d.%d.%d.%d",
                     ENCRYPT_APP_MAJOR_VERSION,
                     ENCRYPT_APP_MINOR_VERSION,
                     ENCRYPT_APP_REVISION,
                     ENCRYPT_APP_MISSION_REV);

    /* Debug: Print message IDs we're subscribing to */
    OS_printf("ENCRYPT_APP: Subscribing to message IDs:\n");
    OS_printf("  CMD MID:        0x%04X\n", (unsigned int)CFE_SB_MsgIdToValue(CFE_SB_ValueToMsgId(ENCRYPT_APP_CMD_MID)));
    OS_printf("  SEND_HK MID:    0x%04X\n", (unsigned int)CFE_SB_MsgIdToValue(CFE_SB_ValueToMsgId(ENCRYPT_APP_SEND_HK_MID)));
    OS_printf("  ENCRYPTED MID:  0x%04X\n", (unsigned int)CFE_SB_MsgIdToValue(CFE_SB_ValueToMsgId(ENCRYPT_APP_ENCRYPTED_MID)));
    OS_printf("  KEY_ROT MID:    0x%04X\n", (unsigned int)CFE_SB_MsgIdToValue(CFE_SB_ValueToMsgId(ENCRYPT_APP_KEY_ROT_MID)));

    return CFE_SUCCESS;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* ENCRYPT_APP_InitCrypto() -- Initialize cryptographic operations           */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int ENCRYPT_APP_InitCrypto(void)
{
    /* Initialize libgcrypt */
    if (!gcry_check_version("1.8.0")) {
        CFE_EVS_SendEvent(ENCRYPT_APP_CRYPTO_INIT_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: libgcrypt version mismatch");
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
        CFE_EVS_SendEvent(ENCRYPT_APP_CRYPTO_INIT_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Failed to load RSA private key: %s/%s",
                         gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* ENCRYPT_APP_ProcessCommandPacket -- Process command packets               */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void ENCRYPT_APP_ProcessCommandPacket(CFE_SB_Buffer_t *BufPtr)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    
    /* Get the message ID from the message */
    CFE_MSG_GetMsgId(&BufPtr->Msg, &MsgId);

    OS_printf("ENCRYPT_APP: Received message with ID 0x%04X\n", 
        (unsigned int)CFE_SB_MsgIdToValue(MsgId));
    
    /* Process based on message ID */
    if (CFE_SB_MsgId_Equal(MsgId, CFE_SB_ValueToMsgId(ENCRYPT_APP_CMD_MID)))
    {
        /* This is a command message - handle it */
        uint16 CommandCode = 0;
        CFE_MSG_GetFcnCode(&BufPtr->Msg, &CommandCode);
        
        switch (CommandCode)
        {
            /* Process "No-op" command */
            case ENCRYPT_APP_NOOP_CC:
                ENCRYPT_APP_Data.CommandCounter++;
                CFE_EVS_SendEvent(ENCRYPT_APP_COMMANDNOP_INF_EID, CFE_EVS_EventType_INFORMATION,
                                 "ENCRYPT_APP: NOOP command received");
                break;
                
            /* Process "Reset" command */
            case ENCRYPT_APP_RESET_CC:
                ENCRYPT_APP_Data.CommandCounter = 0;
                ENCRYPT_APP_Data.CommandErrorCounter = 0;
                CFE_EVS_SendEvent(ENCRYPT_APP_COMMANDRST_INF_EID, CFE_EVS_EventType_INFORMATION,
                                 "ENCRYPT_APP: RESET command received");
                break;
                
            /* Invalid command code */
            default:
                ENCRYPT_APP_Data.CommandErrorCounter++;
                CFE_EVS_SendEvent(ENCRYPT_APP_COMMAND_ERR_EID, CFE_EVS_EventType_ERROR,
                                 "ENCRYPT_APP: Invalid command code: %d", (int)CommandCode);
                break;
        }
    }
    else if (CFE_SB_MsgId_Equal(MsgId, CFE_SB_ValueToMsgId(ENCRYPT_APP_SEND_HK_MID)))
    {
        /* Send housekeeping telemetry */
        ENCRYPT_APP_ReportHousekeeping();
    }
    else if (CFE_SB_MsgId_Equal(MsgId, CFE_SB_ValueToMsgId(ENCRYPT_APP_ENCRYPTED_MID)))
    {
        /* Process encrypted message */
        CFE_MSG_Size_t MsgSize = 0;
        CFE_MSG_GetSize(&BufPtr->Msg, &MsgSize);
        
        /* Get the message payload */
        uint8_t *UserData = CFE_SB_GetUserData(&BufPtr->Msg);
        uint16_t UserDataSize = CFE_SB_GetUserDataLength(&BufPtr->Msg);
        
        /* Determine payload size */
        size_t PayloadSize = UserDataSize;
        
        /* Decrypt the message */
        unsigned char DecryptedMsg[256];
        memset(DecryptedMsg, 0, sizeof(DecryptedMsg));
        
        if (ENCRYPT_APP_DecryptMessage(UserData, PayloadSize, DecryptedMsg) == 0)
        {
            CFE_EVS_SendEvent(ENCRYPT_APP_DECRYPT_SUCCESS_EID, CFE_EVS_EventType_INFORMATION,
                             "ENCRYPT_APP: Successfully decrypted message: %s", DecryptedMsg);
            OS_printf("SATELLITE RECEIVED: %s\n", DecryptedMsg);
            ENCRYPT_APP_Data.MsgCounter++;
        }
        else
        {
            CFE_EVS_SendEvent(ENCRYPT_APP_DECRYPT_ERR_EID, CFE_EVS_EventType_ERROR,
                             "ENCRYPT_APP: Failed to decrypt message");
        }
    }
    else if (CFE_SB_MsgId_Equal(MsgId, CFE_SB_ValueToMsgId(ENCRYPT_APP_KEY_ROT_MID)))
    {
        /* Process key rotation message */
        CFE_MSG_Size_t MsgSize = 0;
        CFE_MSG_GetSize(&BufPtr->Msg, &MsgSize);
        
        /* Get the message payload */
        uint8_t *UserData = CFE_SB_GetUserData(&BufPtr->Msg);
        uint16_t UserDataSize = CFE_SB_GetUserDataLength(&BufPtr->Msg);
        
        /* Determine payload size */
        size_t PayloadSize = UserDataSize;
        
        if (ENCRYPT_APP_ProcessKeyRotation(UserData, PayloadSize) == 0)
        {
            CFE_EVS_SendEvent(ENCRYPT_APP_KEY_ROTATION_SUCCESS_EID, CFE_EVS_EventType_INFORMATION,
                             "ENCRYPT_APP: Key rotation successful");
            ENCRYPT_APP_Data.KeyRotationCounter++;
            OS_printf("SATELLITE: Received new AES key #%d\n", (int)ENCRYPT_APP_Data.KeyRotationCounter);
        }
        else
        {
            CFE_EVS_SendEvent(ENCRYPT_APP_KEY_ROTATION_ERR_EID, CFE_EVS_EventType_ERROR,
                             "ENCRYPT_APP: Key rotation failed");
        }
    }
    else
    {
        /* Unknown message ID */
        ENCRYPT_APP_Data.CommandErrorCounter++;
        CFE_EVS_SendEvent(ENCRYPT_APP_COMMAND_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Invalid message ID: 0x%X", (unsigned int)CFE_SB_MsgIdToValue(MsgId));
    }
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* ENCRYPT_APP_ReportHousekeeping -- Send housekeeping telemetry packet      */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void ENCRYPT_APP_ReportHousekeeping(void)
{
    /* Get current time */
    CFE_TIME_SysTime_t CurrentTime;
    CurrentTime = CFE_TIME_GetTime();
    
    /* Initialize housekeeping message */
    CFE_MSG_Init(&ENCRYPT_APP_Data.HkTlm, CFE_SB_ValueToMsgId(ENCRYPT_APP_HK_TLM_MID), sizeof(ENCRYPT_APP_Data.HkTlm));
    
    /* Set timestamp */
    CFE_MSG_SetMsgTime(&ENCRYPT_APP_Data.HkTlm, CurrentTime);
    
    /* Copy relevant HK data to the packet (assumes correct structure) */
    /* For now, we'll include these directly in the packet */
    uint8 *HkTlmPayload = CFE_SB_GetUserData(&ENCRYPT_APP_Data.HkTlm);
    if (HkTlmPayload != NULL)
    {
        /* Copy counters to HK packet */
        memcpy(HkTlmPayload, &ENCRYPT_APP_Data.CommandCounter, sizeof(uint32));
        memcpy(HkTlmPayload + 4, &ENCRYPT_APP_Data.CommandErrorCounter, sizeof(uint32));
        memcpy(HkTlmPayload + 8, &ENCRYPT_APP_Data.MsgCounter, sizeof(uint32));
        memcpy(HkTlmPayload + 12, &ENCRYPT_APP_Data.KeyRotationCounter, sizeof(uint32));
    }
    
    /* Send the housekeeping packet */
    CFE_SB_TransmitMsg(&ENCRYPT_APP_Data.HkTlm, true);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* ENCRYPT_APP_DecryptMessage -- Decrypt an AES encrypted message            */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int ENCRYPT_APP_DecryptMessage(const unsigned char *ciphertext, size_t ciphertext_len, 
                              unsigned char *plaintext)
{
    gcry_cipher_hd_t cipher;
    gcry_error_t err;
    
    /* Create a cipher handle */
    err = gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if (err) {
        CFE_EVS_SendEvent(ENCRYPT_APP_DECRYPT_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Failed to open cipher: %s/%s",
                         gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Set key */
    err = gcry_cipher_setkey(cipher, ENCRYPT_APP_Data.AESKey, ENCRYPT_APP_Data.AESKeyLen);
    if (err) {
        gcry_cipher_close(cipher);
        CFE_EVS_SendEvent(ENCRYPT_APP_DECRYPT_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Failed to set key: %s/%s",
                         gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Extract IV from beginning of ciphertext (first 16 bytes) */
    err = gcry_cipher_setiv(cipher, ciphertext, 16);
    if (err) {
        gcry_cipher_close(cipher);
        CFE_EVS_SendEvent(ENCRYPT_APP_DECRYPT_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Failed to set IV: %s/%s",
                         gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Decrypt (ciphertext starts after IV) */
    err = gcry_cipher_decrypt(cipher, plaintext, ciphertext_len - 16, 
                              ciphertext + 16, ciphertext_len - 16);
    if (err) {
        gcry_cipher_close(cipher);
        CFE_EVS_SendEvent(ENCRYPT_APP_DECRYPT_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Failed to decrypt: %s/%s",
                         gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    gcry_cipher_close(cipher);
    return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* ENCRYPT_APP_ProcessKeyRotation -- Process a key rotation message          */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
int ENCRYPT_APP_ProcessKeyRotation(const unsigned char *encrypted_key, size_t key_len)
{
    gcry_error_t err;
    gcry_sexp_t enc_data, plain_data;
    
    /* Create S-expression from encrypted data */
    err = gcry_sexp_build(&enc_data, NULL, "(enc-val (rsa (a %b)))", 
                          (int)key_len, encrypted_key);
    if (err) {
        CFE_EVS_SendEvent(ENCRYPT_APP_KEY_ROTATION_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Failed to create encrypted S-exp: %s/%s",
                         gcry_strsource(err), gcry_strerror(err));
        return -1;
    }
    
    /* Decrypt with private key */
    err = gcry_pk_decrypt(&plain_data, enc_data, ENCRYPT_APP_Data.RSAPrivateKey);
    gcry_sexp_release(enc_data);
    
    if (err) {
        CFE_EVS_SendEvent(ENCRYPT_APP_KEY_ROTATION_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Failed to decrypt key: %s/%s",
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
        if (new_key) free(new_key);
        CFE_EVS_SendEvent(ENCRYPT_APP_KEY_ROTATION_ERR_EID, CFE_EVS_EventType_ERROR,
                         "ENCRYPT_APP: Invalid AES key: %s/%s",
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

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* ENCRYPT_APP_CheckUdpMessages -- Check for UDP messages                    */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
void ENCRYPT_APP_CheckUdpMessages(void)
{
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);
    unsigned char buffer[2048];
    int nbytes;
    
    /* Check if there's data on the UDP socket */
    nbytes = recvfrom(ENCRYPT_APP_Data.DirectSocketFD, buffer, sizeof(buffer), 0,
                     (struct sockaddr*)&sender_addr, &sender_len);
    
    if (nbytes > 0) {
        OS_printf("\n****************************************\n");
        OS_printf("ENCRYPT_APP: Received %d bytes via UDP from %s:%d\n", 
                nbytes, 
                inet_ntoa(sender_addr.sin_addr),
                ntohs(sender_addr.sin_port));

            /* Print as hex */
        OS_printf("Data (hex):\n");
        for (int i = 0; i < nbytes && i < 48; i++) {
            OS_printf("%02X ", buffer[i]);
            if ((i + 1) % 16 == 0) OS_printf("\n");
        }
        OS_printf("\n");

        if (nbytes < 32) {
            char ascii_buf[33] = {0};
            memcpy(ascii_buf, buffer, nbytes < 32 ? nbytes : 32);
            OS_printf("Data (ASCII): \"%s\"\n", ascii_buf);
        }
        
        OS_printf("****************************************\n\n");
        
        /* Extract CCSDS header */
        if (nbytes >= 6) {
            uint16_t app_id = (buffer[0] & 0x07) << 8 | buffer[1];
            uint16_t length = (buffer[4] << 8) | buffer[5];
            
            OS_printf("ENCRYPT_APP: UDP packet with App ID: 0x%04X, Length: %d\n", app_id, length);
            
            if (app_id == 0x184) { /* ENCRYPT_APP_ENCRYPTED_MID */
                /* Encrypted message */
                unsigned char plaintext[2048] = {0};
                if (ENCRYPT_APP_DecryptMessage(buffer + 6, nbytes - 6, plaintext) == 0) {
                    OS_printf("ENCRYPT_APP (UDP): Decrypted message: %s\n", plaintext);
                    CFE_EVS_SendEvent(ENCRYPT_APP_DECRYPT_SUCCESS_EID, 
                                     CFE_EVS_EventType_INFORMATION,
                                     "ENCRYPT_APP: Successfully decrypted UDP message: %s", 
                                     plaintext);
                    ENCRYPT_APP_Data.MsgCounter++;
                } else {
                    CFE_EVS_SendEvent(ENCRYPT_APP_DECRYPT_ERR_EID, 
                                     CFE_EVS_EventType_ERROR,
                                     "ENCRYPT_APP: Failed to decrypt UDP message");
                }
            }
            else if (app_id == 0x185) { /* ENCRYPT_APP_KEY_ROT_MID */
                /* Key rotation */
                if (ENCRYPT_APP_ProcessKeyRotation(buffer + 6, nbytes - 6) == 0) {
                    OS_printf("ENCRYPT_APP (UDP): Key rotation successful\n");
                    CFE_EVS_SendEvent(ENCRYPT_APP_KEY_ROTATION_SUCCESS_EID, 
                                     CFE_EVS_EventType_INFORMATION,
                                     "ENCRYPT_APP: UDP Key rotation successful");
                    ENCRYPT_APP_Data.KeyRotationCounter++;
                } else {
                    CFE_EVS_SendEvent(ENCRYPT_APP_KEY_ROTATION_ERR_EID, 
                                     CFE_EVS_EventType_ERROR,
                                     "ENCRYPT_APP: UDP Key rotation failed");
                }
            }
        }
    }
}