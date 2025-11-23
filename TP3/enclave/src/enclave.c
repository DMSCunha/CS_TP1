#include <stdint.h>

#include "sgx_trts.h"
#include "enclave_t.h"
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include <stdlib.h>
#include <string.h>
#include "enclave.h"



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

/**
 * @brief Helper: derive AES key from master password using SHA256
 * 
 * @param[in]   password  master password used to derive new keys
 * @param[out]  key_out   new key created form the master
 * 
 * @return 0 on success, non-zero on failure.
 */
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

	//clear hash
	memset_s(hash, sizeof(sgx_sha256_hash_t), 0, sizeof(sgx_sha256_hash_t));
	return 0;
}

/**
 * @brief Encrypt wallet data using AES-GCM with master password.
 *
 *
 * @param[in]  plaintext         Input buffer containing wallet data to encrypt.
 * @param[in]  plaintext_len     Length of the plaintext in bytes.
 * @param[in]  master_password   Master password used encrypte the data.
 * @param[out] ciphertext        Output buffer that receives the encrypted data.
 * @param[in]  ciphertext_len    Size of the ciphertext output buffer.
 * @param[out] iv                Output buffer for the AES-GCM initialization vector.
 * @param[out] mac               Output buffer for the AES-GCM authentication tag.
 *
 * @return 0 on success, non-zero on failure.
 */
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
	memset_s(key, AES_GCM_KEY_SIZE, 0, AES_GCM_KEY_SIZE);

	if (ret != SGX_SUCCESS) {
		return -5;
	}

	return 0;
}

/**
 * @brief Decrypt wallet data using AES-GCM with master password.
 *
 * @param[in]  ciphertext       Encrypted data.
 * @param[in]  ciphertext_len   Length of the encrypted data in bytes.
 * @param[in]  master_password  Master password to decrypte the encrypted data.
 * @param[in]  iv               Initialization vector (nonce) used for AES-GCM.
 * @param[in]  mac              Authentication tag associated with the data.
 * @param[out] plaintext        Output buffer where decrypted wallet data is written.
 * @param[in]  plaintext_len    Size of the plaintext output buffer.
 *
 * @return 0 on success, non-zero on failure.
 */
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
	memset_s(key, AES_GCM_KEY_SIZE, 0, AES_GCM_KEY_SIZE);

	if (ret != SGX_SUCCESS) {
		return -4;  /* Decryption failed or MAC verification failed */
	}

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

	//generate password
	for (uint32_t i = 0; i < length - 1; i++) {
		password[i] = charset[rand_bytes[i] % charset_size];
	}
	password[length - 1] = '\0';

	//clear memory allocated
	memset_s(rand_bytes, length, 0, length);
	free(rand_bytes);
	return 0;
}


/**
 * @brief Verify master password by attempting to decrypt.
 *
 * @param[in] encrypted_wallet  Buffer containing the encrypted wallet.
 * @param[in] encrypted_len     Length of the encrypted wallet in bytes.
 * @param[in] master_password   Master password.
 * @param[in] iv                Initialization vector (nonce) used for AES-GCM.
 * @param[in] mac               Authentication tag for AES-GCM.
 *
 * @return 0 on success, non-zero on failure.
 */
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
	memset_s(temp_buffer,encrypted_len,0, encrypted_len);
	free(temp_buffer);

	return result;  /* 0 if password is correct, negative otherwise */
}

