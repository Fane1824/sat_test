#ifndef ENCRYPT_APP_EVENTS_H
#define ENCRYPT_APP_EVENTS_H

/**
 * \file
 * \brief ENCRYPT App event ID definitions
 */

#define ENCRYPT_APP_RESERVED_EID              0  /* Reserved EID, not used */
#define ENCRYPT_APP_STARTUP_INF_EID           1  /* Startup Event */
#define ENCRYPT_APP_COMMAND_ERR_EID           2  /* Command Error Event */
#define ENCRYPT_APP_COMMANDNOP_INF_EID        3  /* No-op Command Event */
#define ENCRYPT_APP_COMMANDRST_INF_EID        4  /* Reset Command Event */
#define ENCRYPT_APP_DECRYPT_SUCCESS_EID       5  /* Message Decryption Success */
#define ENCRYPT_APP_DECRYPT_ERR_EID           6  /* Message Decryption Error */
#define ENCRYPT_APP_KEY_ROTATION_SUCCESS_EID  7  /* Key Rotation Success */
#define ENCRYPT_APP_KEY_ROTATION_ERR_EID      8  /* Key Rotation Error */
#define ENCRYPT_APP_CRYPTO_INIT_ERR_EID       9  /* Crypto Initialization Error */
#define ENCRYPT_APP_PIPE_ERR_EID             10  /* Command Pipe Error */
#define ENCRYPT_APP_SUB_ERR_EID              11  /* Subscription Error */
#define ENCRYPT_APP_PERF_ID                  40  /* Performance ID */

#endif /* ENCRYPT_APP_EVENTS_H */