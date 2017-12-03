#ifndef BASIC_AES_H
#define BASIC_AES_H

#define AP_INT_MAX_W 256
#include "ap_int.h"

void AES_Encrypt(const ap_uint<128> & in, ap_uint<128> & out,
                 const ap_uint<128> expanded_key[15]);

void AES_Decrypt(const ap_uint<128> & in, ap_uint<128> & out,
				const ap_uint<128> expanded_key[15]);

void key_expansion(const unsigned char inputKey[32], unsigned char expanded_key[240]);

#endif
/* BASIC_AES_H defined */
