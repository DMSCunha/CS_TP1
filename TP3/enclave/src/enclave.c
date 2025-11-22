#include <stdint.h>

#include "sgx_trts.h"
#include "enclave_t.h"
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

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

int ecall_get_random_bytes(uint8_t* buf, size_t len)
{
	if (buf == NULL || len == 0) {
		return -1; // Invalid parameters
	}

	sgx_status_t status = sgx_read_rand((unsigned char*) buf, len);

	if (status != SGX_SUCCESS) {
		return -2; // Random generation failed
	}

	return 0;
}

/* Return the size (in bytes) required to hold sealed data for a plaintext of length plaintext_len */
uint32_t ecall_get_sealed_data_size(uint32_t plaintext_len)
{
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, plaintext_len);
	return sealed_size; /* if 0, sealing not possible */
}

/* Seal data provided in `plaintext` into `sealed_data` buffer of size sealed_size */
int ecall_seal_data(uint8_t* plaintext, uint32_t plaintext_len,
					uint8_t* sealed_data, uint32_t sealed_size)
{
	if (plaintext == NULL || plaintext_len == 0 || sealed_data == NULL || sealed_size == 0) {
		return -1;
	}

	sgx_status_t ret = sgx_seal_data(0, NULL, plaintext_len, plaintext,
									 sealed_size, (sgx_sealed_data_t*) sealed_data);
	if (ret != SGX_SUCCESS) {
		return -2;
	}
	return 0;
}

/* Unseal data in `sealed_data` (sealed_size bytes) into `plaintext` buffer. `plaintext_len` is in/out. */
int ecall_unseal_data(uint8_t* sealed_data, uint32_t sealed_size,
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
		return -2;
	}

	*plaintext_ret_len = out_text_len;
	return 0;
}

/* Helper: derive AES key from master password using SHA256 */
static int derive_key_from_password(const char* password, uint8_t* key_out)
{
	sgx_sha256_hash_t hash;
	/* cast length to uint32_t to silence warnings on size_t -> uint32_t */
	sgx_status_t ret = sgx_sha256_msg((const uint8_t*)password, (uint32_t)strlen(password), &hash);
	if (ret != SGX_SUCCESS) {
		return -1;
	}
	/* Use first 16 bytes of hash as AES-128 key */
	memcpy(key_out, hash, AES_GCM_KEY_SIZE);
	return 0;
}

/* Encrypt wallet data using AES-GCM with master password */
int ecall_encrypt_wallet(uint8_t* plaintext, uint32_t plaintext_len,
						 const char* master_password,
						 uint8_t* ciphertext, uint32_t ciphertext_len,
						 uint8_t* iv, uint8_t* mac)
{
	if (plaintext == NULL || master_password == NULL || ciphertext == NULL || iv == NULL || mac == NULL) {
		return -1;
	}

	if (ciphertext_len < plaintext_len) {
		return -2;
	}

	/* Derive encryption key from master password */
	uint8_t key[AES_GCM_KEY_SIZE];
	if (derive_key_from_password(master_password, key) != 0) {
		return -3;
	}

	/* Generate random IV */
	sgx_status_t ret = sgx_read_rand(iv, AES_GCM_IV_SIZE);
	if (ret != SGX_SUCCESS) {
		return -4;
	}

	/* Encrypt using AES-GCM */
	ret = sgx_rijndael128GCM_encrypt(
		(const sgx_aes_gcm_128bit_key_t*)key,
		plaintext, plaintext_len,
		ciphertext,
		iv, AES_GCM_IV_SIZE,
		NULL, 0,  /* no additional authenticated data */
		(sgx_aes_gcm_128bit_tag_t*)mac
	);

	/* Clear key from memory */
	memset(key, 0, AES_GCM_KEY_SIZE);

	if (ret != SGX_SUCCESS) {
		return -5;
	}

	return 0;
}

/* Decrypt wallet data using AES-GCM with master password */
int ecall_decrypt_wallet(uint8_t* ciphertext, uint32_t ciphertext_len,
						 const char* master_password,
						 uint8_t* iv, uint8_t* mac,
						 uint8_t* plaintext, uint32_t plaintext_len)
{
	if (ciphertext == NULL || master_password == NULL || iv == NULL || mac == NULL || plaintext == NULL) {
		return -1;
	}

	if (plaintext_len < ciphertext_len) {
		return -2;
	}

	/* Derive decryption key from master password */
	uint8_t key[AES_GCM_KEY_SIZE];
	if (derive_key_from_password(master_password, key) != 0) {
		return -3;
	}

	/* Decrypt using AES-GCM */
	sgx_status_t ret = sgx_rijndael128GCM_decrypt(
		(const sgx_aes_gcm_128bit_key_t*)key,
		ciphertext, ciphertext_len,
		plaintext,
		iv, AES_GCM_IV_SIZE,
		NULL, 0,  /* no additional authenticated data */
		(const sgx_aes_gcm_128bit_tag_t*)mac
	);

	/* Clear key from memory */
	memset(key, 0, AES_GCM_KEY_SIZE);

	if (ret != SGX_SUCCESS) {
		return -4;  /* Decryption failed or MAC verification failed */
	}

	return 0;
}

/* Generate secure random password */
int ecall_generate_password(char* password, uint32_t length)
{
	if (password == NULL || length < 8 || length > WALLET_MAX_ITEM_SIZE) {
		return -1;
	}

	const char charset[] = "abcdefghijklmnopqrstuvwxyz"
						   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
						   "0123456789"
						   "!@#$%^&*(){}[]:<>?,./";
	const size_t charset_size = sizeof(charset) - 1;

	uint8_t* rand_bytes = (uint8_t*)malloc(length);
	if (rand_bytes == NULL) {
		return -2;
	}

	sgx_status_t ret = sgx_read_rand(rand_bytes, length);
	if (ret != SGX_SUCCESS) {
		free(rand_bytes);
		return -3;
	}

	for (uint32_t i = 0; i < length - 1; i++) {
		password[i] = charset[rand_bytes[i] % charset_size];
	}
	password[length - 1] = '\0';

	free(rand_bytes);
	return 0;
}

/* Verify master password by attempting to decrypt */
int ecall_verify_password(uint8_t* encrypted_wallet, uint32_t encrypted_len,
						  const char* master_password,
						  uint8_t* iv, uint8_t* mac)
{
	if (encrypted_wallet == NULL || master_password == NULL || iv == NULL || mac == NULL) {
		return -1;
	}

	uint8_t* temp_buffer = (uint8_t*)malloc(encrypted_len);
	if (temp_buffer == NULL) {
		return -2;
	}

	int result = ecall_decrypt_wallet(encrypted_wallet, encrypted_len,
									   master_password, iv, mac,
									   temp_buffer, encrypted_len);

	/* Clear temporary buffer */
	memset(temp_buffer, 0, encrypted_len);
	free(temp_buffer);

	return result;  /* 0 if password is correct, negative otherwise */
}

#ifdef __cplusplus
}
#endif

