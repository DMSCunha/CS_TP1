#ifndef _OCALL_H_
#define _OCALL_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <ctype.h>
#include <string.h>

#include "app.h"

int ocall_write_to_wallet( uint8_t* encrypted_data,  size_t data_size);

void ocall_print_wallet( uint8_t* encrypted_data,  size_t data_size);

int ocall_print_string(const char *str);

#endif // !_OCALL_H_