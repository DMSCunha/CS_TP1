#ifndef _APP_H_
#define _APP_H_

#include "config.h"

#define RET_SUCCESS 0
#define ERR_PASSWORD_OUT_OF_RANGE 1
#define ERR_WALLET_ALREADY_EXISTS 2
#define ERR_CANNOT_SAVE_WALLET 3
#define ERR_CANNOT_LOAD_WALLET 4
#define ERR_WRONG_MASTER_PASSWORD 5
#define ERR_WALLET_FULL 6
#define ERR_ITEM_DOES_NOT_EXIST 7
#define ERR_ITEM_TOO_LONG 8

#define ALPHA_SIZE 26
#define NUM_SIZE 10
#define SYM_SIZE 21

static char numbers[] = "1234567890";
static char letter[]  = "abcdefghijklmnoqprstuvwyzx";
static char letterr[] = "ABCDEFGHIJKLMNOQPRSTUYWVZX";
static char symbols[] = "!@#$%^&*(){}[]:<>?,./";

// item
struct Item {
	char  title[WALLET_MAX_ITEM_SIZE];
	char  username[WALLET_MAX_ITEM_SIZE];
	char  password[WALLET_MAX_ITEM_SIZE];
};
typedef struct Item item_t;

// wallet
struct Wallet {
	item_t items[WALLET_MAX_ITEMS];
	size_t size;
	char master_password[WALLET_MAX_ITEM_SIZE];
};
typedef struct Wallet wallet_t;

int generate_password(char *p_value, int p_length);
char get_pwd_char(char *charlist, int len);
int change_master_password(const char* old_password, const char* new_password);
int add_item(const char* master_password, const item_t* item, const size_t item_size);
int remove_item(const char* master_password, const int index);
int save_wallet(const wallet_t* wallet, const size_t wallet_size);
int load_wallet(wallet_t* wallet, const size_t wallet_size);
int is_wallet(void);
int create_wallet(const char* master_password);
int show_wallet(const char* master_password, wallet_t* wallet, size_t wallet_size);
void print_wallet(const wallet_t* wallet);
int is_error(int error_code);
void show_help();
void show_version();

#endif // !_APP_H_
