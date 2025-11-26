#include <stdint.h>

#include "sgx_trts.h"
#include "enclave_t.h"
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "enclave.h"

static int local_printf( const char *fmt, ... )
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;

	va_start( ap, fmt );
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end( ap );

	ocall_print_string(buf );

    return ( (int) strnlen( buf, BUFSIZ - 1 ) + 1 );
}

/**
 * @brief Return the size (in bytes) required to hold sealed data
 * 
 * @param[in]  plaintext_len  lenght of the data to be sealed
 * 
 * @return 0 on failure, number of bytesthat can be sealed.
 */
static uint32_t local_get_sealed_data_size(uint32_t plaintext_len)
{
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, plaintext_len);
	return sealed_size; /* if 0, sealing not possible */
}

/**
 * @brief Return the size (in bytes) required to hold sealed data
 * 
 * @param[in]  plaintext_len  lenght of the data to be sealed
 * 
 * @return 0 on failure, number of bytesthat can be sealed.
 */
uint32_t ecall_get_sealed_data_size(uint32_t plaintext_len)
{
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, plaintext_len);
	return sealed_size; /* if 0, sealing not possible */
}

/**
 * @brief Seal data provided in `plaintext` into `sealed_data` buffer of size sealed_size
 *
 *
 * @param[in]  plaintext       Input buffer containing the data to seal.
 * @param[in]  plaintext_len   Length of the plaintext in bytes.
 * @param[out] sealed_data     Output buffer that will receive the sealed data.
 * @param[in]  sealed_size     Size of the output buffer.
 *
 * @return 0 on success, non-zero on failure.
 */
static int local_seal_data(const uint8_t* plaintext, uint32_t plaintext_len,
					uint8_t* sealed_data, uint32_t sealed_size)
{
	if (plaintext == NULL || plaintext_len == 0 || sealed_data == NULL || sealed_size == 0) {
		return -1;
	}

	// sealing already uses AES-GCM with 128-bits 
	sgx_status_t ret = sgx_seal_data(0, NULL, plaintext_len, plaintext,
									 sealed_size, (sgx_sealed_data_t*) sealed_data);
	if (ret != SGX_SUCCESS) {
		return -2;
	}
	return 0;
}

/**
 * @brief Unseal data in `sealed_data` (sealed_size bytes) into `plaintext` buffer.
 *.
 *
 * @param[in]  sealed_data         Input buffer containing sealed data.
 * @param[in]  sealed_size         Size of the sealed data buffer in bytes.
 * @param[out] plaintext           Output buffer that will receive the unsealed data.
 * @param[in]  plaintext_len       Size of the output buffer in bytes.
 * @param[out] plaintext_ret_len   Actual number of bytes written to @p plaintext.
 *
 * @return 0 on success, non-zero on failure.
 */
static int local_unseal_data(const uint8_t* sealed_data, uint32_t sealed_size,
					  uint8_t* plaintext, uint32_t plaintext_len,
					  uint32_t* plaintext_ret_len)
{
	if (sealed_data == NULL || sealed_size == 0 || plaintext == NULL || plaintext_len == 0 || plaintext_ret_len == NULL) {
		return -1;
	}

	uint32_t additional_mac_len = 0;
	uint32_t out_text_len = plaintext_len; /* max available */

	sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t*) sealed_data,
									   NULL, &additional_mac_len,
									   plaintext, &out_text_len);
	if (ret != SGX_SUCCESS) {
		ocall_print_string("I WAS HERE IN ENCLAVE 2.2\n");
		return -2;
	}

	*plaintext_ret_len = out_text_len;
	return 0;
}


/**
 * @brief Generate a secure random password.
 *
 * @param[out] password  Output buffer that will receive the password.
 * @param[in]  length    Length of the password to generate.
 *
 * @return 0 on success, non-zero on failure.
 */
int ecall_generate_password(uint32_t length)
{
	if (length < 8 || length > WALLET_MAX_ITEM_SIZE) {
		return -1;
	}

	const char charset[] = "abcdefghijklmnopqrstuvwxyz"
						   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
						   "0123456789"
						   "!@#$%^&*(){}[]:<>?,./";
	const size_t charset_size = sizeof(charset) - 1;

	char* password = (char*)malloc(length);
	uint8_t* rand_bytes = (uint8_t*)malloc(length);
	if (rand_bytes == NULL) {
		return -2;
	}

	sgx_status_t ret = sgx_read_rand(rand_bytes, length);
	if (ret != SGX_SUCCESS) {
		memset_s(rand_bytes, length, 0, length);
		free(rand_bytes);
		return -3;
	}

	//generate password
	for (uint32_t i = 0; i < length - 1; i++) {
		password[i] = charset[rand_bytes[i] % charset_size];
	}
	password[length - 1] = '\0';

	memset_s(rand_bytes, length, 0, length);
	free(rand_bytes);

	//call the ocall to print new password
	int len_print = local_printf(password);
	if(len_print == 0){
		memset_s(password, length, 0, length);
		free(password);
		return -4;
	}

	//clear memory allocated
	memset_s(password, length, 0, length);
	free(password);
	return 0;
}

int ecall_remove_item(const char* master_password, uint8_t* encrypted_data, size_t data_size, int index){

	int status;
	uint32_t plain_len;
	uint32_t seal_size;
	uint8_t* plain_data;
	wallet_t* wallet;
	uint8_t* encrypted_data_to_save;
	
	if(master_password == NULL || encrypted_data == NULL)
		return -1;

	plain_data = (uint8_t *)malloc(data_size);

    status = local_unseal_data(
        encrypted_data,
        (uint32_t) data_size,
        plain_data,
        (uint32_t) data_size,
        &plain_len
    );

    if (status != 0 || plain_len != sizeof(wallet_t)) {
		free(plain_data);
        return -2;
    }

    // Copy plaintext into caller buffer
	wallet = (wallet_t *)malloc(sizeof(wallet_t));
    memcpy(wallet, plain_data, sizeof(wallet_t));
	
	memset_s(plain_data, plain_len, 0, plain_len);
	free(plain_data);

	// verify master-password
	if (strcmp(wallet->master_password, master_password) != 0) {
		memset_s(wallet, sizeof(wallet_t), 0, sizeof(wallet_t));
		free(wallet);
		return -3;
	}

	//verify if item exists
	if ((size_t)index >= wallet->size) {
		memset_s(wallet, sizeof(wallet_t), 0, sizeof(wallet_t));
		free(wallet);
		return -4;
	}

	//remove item
	for (size_t i = (size_t)index; i < wallet->size-1; ++i) {
		wallet->items[i] = wallet->items[i+1];
	}
	--wallet->size;

	//seal data
	
	seal_size = local_get_sealed_data_size((uint32_t) sizeof(wallet_t));
	encrypted_data_to_save = (uint8_t *)malloc(seal_size);

	status = local_seal_data(
		(uint8_t*) wallet,
		sizeof(wallet_t),
		encrypted_data_to_save,
		seal_size
	);

	memset_s(wallet, sizeof(wallet_t), 0, sizeof(wallet_t));
	free(wallet);

	//call ocall to save persistent data
	status = ocall_write_to_wallet(&status, (uint8_t *) encrypted_data_to_save, seal_size);
	if(status != 0){
		memset_s(encrypted_data_to_save, seal_size, 0, seal_size);
		free(encrypted_data_to_save);
		return -4;
	}

	memset_s(encrypted_data_to_save, seal_size, 0, seal_size);
	free(encrypted_data_to_save);
	
	return 0;
}

int ecall_add_item(const char* master_password, uint8_t* encrypted_data, size_t data_size, uint8_t* item, size_t item_size){
	
	(void)item_size;
	int status;
	uint32_t plain_len;
	uint32_t seal_size;
	uint8_t* plain_data;
	wallet_t* wallet;
	uint8_t* encrypted_data_to_save;
	
	if(master_password == NULL || encrypted_data == NULL || item == NULL)
		return -1;

	plain_data = (uint8_t *)malloc(data_size);

    status = local_unseal_data(
        encrypted_data,
        (uint32_t) data_size,
        plain_data,
        (uint32_t) data_size,
        &plain_len
    );

    if (status != 0 || plain_len != sizeof(wallet_t)) {
		free(plain_data);
        return -2;
    }

    // Copy plaintext into caller buffer
	wallet = (wallet_t *)malloc(sizeof(wallet_t));
    memcpy(wallet, plain_data, sizeof(wallet_t));
	
	memset_s(plain_data, plain_len, 0, plain_len);
	free(plain_data);

	// verify master-password
	if (strcmp(wallet->master_password, master_password) != 0) {
		memset_s(wallet, sizeof(wallet_t), 0, sizeof(wallet_t));
		free(wallet);
		return -3;
	}

	// try to add item
	if (wallet->size >= WALLET_MAX_ITEMS) {
		memset_s(wallet, sizeof(wallet_t), 0, sizeof(wallet_t));
		free(wallet);
		return -4;
	}
	
	const item_t *it = (const item_t *)item;

	wallet->items[wallet->size] = *it;
	++wallet->size;

	//seal data
	seal_size = local_get_sealed_data_size((uint32_t) sizeof(wallet_t));
	encrypted_data_to_save = (uint8_t *)malloc(seal_size);

	status = local_seal_data(
		(uint8_t*) wallet,
		sizeof(wallet_t),
		encrypted_data_to_save,
		seal_size
	);

	memset_s(wallet, sizeof(wallet_t), 0, sizeof(wallet_t));
	free(wallet);

	//call ocall to save persistent data
	status = ocall_write_to_wallet(&status, (uint8_t *) encrypted_data_to_save, seal_size);
	if(status != 0){
		memset_s(encrypted_data_to_save, seal_size, 0, seal_size);
		free(encrypted_data_to_save);
		return -4;
	}

	memset_s(encrypted_data_to_save, seal_size, 0, seal_size);
	free(encrypted_data_to_save);
	
	return 0;
}

int ecall_create_wallet(const char* master_password){

	int status;
	wallet_t* wallet;
	uint8_t* encrypted_data_to_save;
	uint32_t seal_size;

	// check password policy
	if (strlen(master_password) < 8 || strlen(master_password)+1 > WALLET_MAX_ITEM_SIZE) {
		return -1;
	}

	// allocate memory
	wallet = (wallet_t*)malloc(sizeof(wallet_t));

	wallet->size = 0;
	strncpy(wallet->master_password, master_password, strlen(master_password)+1);

	//seal data
	seal_size = local_get_sealed_data_size((uint32_t) sizeof(wallet_t));
	encrypted_data_to_save = (uint8_t *)malloc(seal_size);

	status = local_seal_data(
		(uint8_t*) wallet,
		sizeof(wallet_t),
		encrypted_data_to_save,
		seal_size
	);

	memset_s(wallet, sizeof(wallet_t), 0, sizeof(wallet_t));
	free(wallet);

	//call ocall to save persistent data
	status = ocall_write_to_wallet(&status, (uint8_t *) encrypted_data_to_save, seal_size);
	if(status != 0){
		memset_s(encrypted_data_to_save, seal_size, 0, seal_size);
		free(encrypted_data_to_save);
		return -4;
	}

	memset_s(encrypted_data_to_save, seal_size, 0, seal_size);
	free(encrypted_data_to_save);

	return 0;
}

int ecall_change_master_password(const char* old_password, const char* new_password, uint8_t* encrypted_data, size_t data_size){

	int status;
	uint32_t plain_len;
	uint32_t seal_size;
	uint8_t* plain_data;
	wallet_t* wallet;
	uint8_t* encrypted_data_to_save;
	
	if(old_password == NULL || new_password == NULL || encrypted_data == NULL || strcmp(old_password, new_password) == 0)
		return -1;

	plain_data = (uint8_t *)malloc(data_size);

    status = local_unseal_data(
        encrypted_data,
        (uint32_t) data_size,
        plain_data,
        (uint32_t) data_size,
        &plain_len
    );

    if (status != 0 || plain_len != sizeof(wallet_t)) {
		free(plain_data);
        return -2;
    }

    // Copy plaintext into caller buffer
	wallet = (wallet_t *)malloc(sizeof(wallet_t));
    memcpy(wallet, plain_data, sizeof(wallet_t));
	
	memset_s(plain_data, plain_len, 0, plain_len);
	free(plain_data);

	//verify older master_password
	if (strcmp(wallet->master_password, old_password) != 0) {
		memset_s(wallet, sizeof(wallet_t), 0, sizeof(wallet_t));
		free(wallet);
		return -3;
	}

	// update password
	strncpy(wallet->master_password, new_password, strlen(new_password)+1);

	//seal data
	seal_size = local_get_sealed_data_size((uint32_t) sizeof(wallet_t));
	encrypted_data_to_save = (uint8_t *)malloc(seal_size);

	status = local_seal_data(
		(uint8_t*) wallet,
		sizeof(wallet_t),
		encrypted_data_to_save,
		seal_size
	);

	memset_s(wallet, sizeof(wallet_t), 0, sizeof(wallet_t));
	free(wallet);

	//call ocall to save persistent data
	status = ocall_write_to_wallet(&status, (uint8_t *) encrypted_data_to_save, seal_size);
	if(status != 0){
		memset_s(encrypted_data_to_save, seal_size, 0, seal_size);
		free(encrypted_data_to_save);
		return -4;
	}

	memset_s(encrypted_data_to_save, seal_size, 0, seal_size);
	free(encrypted_data_to_save);

	return 0;
}

int ecall_show_wallet(const char* master_password, uint8_t* encrypted_data, size_t data_size){

	int status;
	uint32_t plain_len;
	uint8_t* plain_data;
	wallet_t* wallet;

	if(master_password == NULL || encrypted_data == NULL)
		return -1;

	plain_data = (uint8_t *)malloc(data_size);

    status = local_unseal_data(
        encrypted_data,
        (uint32_t) data_size,
        plain_data,
        (uint32_t) data_size,
        &plain_len
    );
	
	if (status != 0) {
		free(plain_data);
        return -2;
    }

	// Copy plaintext into caller buffer
	wallet = (wallet_t *)malloc(sizeof(wallet_t));
    memcpy(wallet, plain_data, sizeof(wallet_t));

	//verify master_password
	if (strcmp(wallet->master_password, master_password) != 0) {
		memset_s(wallet, sizeof(wallet_t), 0, sizeof(wallet_t));
		free(wallet);
		return -3;
	}
	memset_s(wallet, sizeof(wallet_t), 0, sizeof(wallet_t));
	free(wallet);

    //call ocall to save persistent data
	ocall_print_wallet(plain_data, plain_len);
	
	memset_s(plain_data, plain_len, 0, plain_len);
	free(plain_data);

	return 0;
}
