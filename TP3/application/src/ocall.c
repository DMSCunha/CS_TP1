#include "ocall.h"


int ocall_write_to_wallet( uint8_t* encrypted_data,  size_t data_size){
    
    /* open file */
	FILE* fp = fopen(WALLET_FILE, "wb");
	if (fp == NULL) {
		return 1;
	}

    fwrite(encrypted_data, 1, data_size, fp);
    fclose(fp);

    return 0;
}

void ocall_print_wallet( uint8_t* encrypted_data,  size_t data_size){

    (void)data_size;

    const wallet_t *w = (const wallet_t *)encrypted_data;

    printf("\n-----------------------------------------\n");
    printf("Simple password eWallet.\n");
    printf("-----------------------------------------\n");
	printf("Number of items: %zu\n", w->size);
	for (size_t i = 0; i < w->size; ++i) {
		printf("\n#%zu -- %s\n", i, w->items[i].title);
        printf("Username: %s\n", w->items[i].username);
        printf("Password: %s\n", w->items[i].password);
    }
    printf("\n------------------------------------------\n\n");
}

int ocall_print_string(const char *str){
    printf( "%s\n", str );
    return 0;
}
