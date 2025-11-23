#ifndef _ENCLAVE_APP_H_
#define _ENCLAVE_APP_H_

#define WALLET_MAX_ITEMS 100
#define WALLET_MAX_ITEM_SIZE 100
#define AES_GCM_KEY_SIZE 16
#define AES_GCM_IV_SIZE 12
#define AES_GCM_MAC_SIZE 16

typedef struct {
	char  title[WALLET_MAX_ITEM_SIZE];
	char  username[WALLET_MAX_ITEM_SIZE];
	char  password[WALLET_MAX_ITEM_SIZE];
} item_t;

typedef struct {
	item_t items[WALLET_MAX_ITEMS];
	size_t size;
	char master_password[WALLET_MAX_ITEM_SIZE];
} wallet_t;


#endif // !_ENCLAVE_APP_H_
