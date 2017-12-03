#include "modes_aes.h"

void aes_ecb_256(const ap_uint<AES_W> in1[AES_N], const ap_uint<AES_W> in2[AES_N], const ap_uint<AES_W> in3[AES_N], const ap_uint<AES_W> in4[AES_N],
		ap_uint<AES_W> out1[AES_N], ap_uint<AES_W> out2[AES_N], ap_uint<AES_W> out3[AES_N], ap_uint<AES_W> out4[AES_N], const ap_uint<256> key)
{
	ap_uint<128> expanded_key[15];
#pragma HLS ARRAY_PARTITION variable=expanded_key complete dim=1
	unsigned char user_key[32], exp_keys[240];

	for (int i = 0; i < 32; i++) {
		user_key[i] = key((i + 1) * 8 - 1, i * 8);
	}
	key_expansion(user_key, exp_keys);
	for (int i = 0; i < 240; i++) {
		expanded_key[i / 16]((i % 16 + 1) * 8 - 1, (i % 16) * 8) = exp_keys[i];
	}

	aes_ecb_label1: for (int i = 0; i < AES_N; i += 2) {
#pragma HLS PIPELINE
		ap_uint<128> block_in_1;
		ap_uint<128> block_out_1;
		block_in_1(63, 0) = in1[i];
		block_in_1(127, 64) = in1[i + 1];
		AES_Encrypt(block_in_1, block_out_1, expanded_key);
		out1[i] = block_out_1(63, 0);
		out1[i + 1] = block_out_1(127, 64);

		ap_uint<128> block_in_2;
		ap_uint<128> block_out_2;
		block_in_2(63, 0) = in2[i];
		block_in_2(127, 64) = in2[i + 1];
		AES_Encrypt(block_in_2, block_out_2, expanded_key);
		out2[i] = block_out_2(63, 0);
		out2[i + 1] = block_out_2(127, 64);

		ap_uint<128> block_in_3;
		ap_uint<128> block_out_3;
		block_in_3(63, 0) = in3[i];
		block_in_3(127, 64) = in3[i + 1];
		AES_Encrypt(block_in_3, block_out_3, expanded_key);
		out3[i] = block_out_3(63, 0);
		out3[i + 1] = block_out_3(127, 64);

		ap_uint<128> block_in_4;
		ap_uint<128> block_out_4;
		block_in_4(63, 0) = in4[i];
		block_in_4(127, 64) = in4[i + 1];
		AES_Encrypt(block_in_4, block_out_4, expanded_key);
		out4[i] = block_out_4(63, 0);
		out4[i + 1] = block_out_4(127, 64);
	}
}

ap_uint<128> reverse_bytes(const ap_uint<128> w)
{
	ap_uint<128> temp = 0;
	for (int i = 0; i < 16; i++) {
		temp((i + 1) * 8 - 1, i * 8) = w(((15 - i) + 1) * 8 - 1, (15 - i) * 8);
	}
	return temp;
}

//note: implemented based on cryptopp counter mode, ie no nonce used
void aes_ctr_256(const ap_uint<AES_W> in[AES_N], ap_uint<AES_W> out[AES_N], const ap_uint<256> key, ap_uint<128> & ctr_init)
{
	ap_uint<128> expanded_key[15];
#pragma HLS ARRAY_PARTITION variable=expanded_key complete dim=1
	unsigned char user_key[32], exp_keys[240];

	for (int i = 0; i < 32; i++) {
		user_key[i] = key((i + 1) * 8 - 1, i * 8);
	}
	key_expansion(user_key, exp_keys);
	for (int i = 0; i < 240; i++) {
		expanded_key[i / 16]((i % 16 + 1) * 8 - 1, (i % 16) * 8) = exp_keys[i];
	}

	ap_uint<128> ctr1 = ctr_init;
	ctr_init = ctr_init + AES_N / 2;

	aes_ctr_label1: for (int i = 0; i < AES_N; i += 2, ctr1++) {
#pragma HLS PIPELINE
		ap_uint<128> ctr_out;
		AES_Encrypt(reverse_bytes(ctr1), ctr_out, expanded_key);
		out[i] = ctr_out(63, 0) ^ in[i];
		out[i + 1] = ctr_out(127, 64) ^ in[i + 1];
	}
}

//note: implemented based on cryptopp counter mode, ie no nonce used
void aes_ctr_256_hp(const ap_uint<AES_W> in1[AES_N], const ap_uint<AES_W> in2[AES_N], const ap_uint<AES_W> in3[AES_N], const ap_uint<AES_W> in4[AES_N],
		ap_uint<AES_W> out1[AES_N], ap_uint<AES_W> out2[AES_N], ap_uint<AES_W> out3[AES_N], ap_uint<AES_W> out4[AES_N], const ap_uint<256> key, ap_uint<128> & ctr_init)
{
	ap_uint<128> expanded_key[15];
#pragma HLS ARRAY_PARTITION variable=expanded_key complete dim=1
	unsigned char user_key[32], exp_keys[240];

	for (int i = 0; i < 32; i++) {
		user_key[i] = key((i + 1) * 8 - 1, i * 8);
	}
	key_expansion(user_key, exp_keys);
	for (int i = 0; i < 240; i++) {
		expanded_key[i / 16]((i % 16 + 1) * 8 - 1, (i % 16) * 8) = exp_keys[i];
	}

	ap_uint<128> ctr1 = ctr_init;
	ap_uint<128> ctr2 = ctr_init + AES_N / 2;
	ap_uint<128> ctr3 = ctr_init + AES_N;
	ap_uint<128> ctr4 = ctr_init + 3 * AES_N / 2;
	ctr_init = ctr_init + 2 * AES_N;

	aes_ctr_label1: for (int i = 0; i < AES_N; i += 2, ctr1++, ctr2++, ctr3++, ctr4++) {
#pragma HLS PIPELINE
		ap_uint<128> ctr_out_1;
		AES_Encrypt(reverse_bytes(ctr1), ctr_out_1, expanded_key);
		out1[i] = ctr_out_1(63, 0) ^ in1[i];
		out1[i + 1] = ctr_out_1(127, 64) ^ in1[i + 1];

		ap_uint<128> ctr_out_2;
		AES_Encrypt(reverse_bytes(ctr2), ctr_out_2, expanded_key);
		out2[i] = ctr_out_2(63, 0) ^ in2[i];
		out2[i + 1] = ctr_out_2(127, 64) ^ in2[i + 1];

		ap_uint<128> ctr_out_3;
		AES_Encrypt(reverse_bytes(ctr3), ctr_out_3, expanded_key);
		out3[i] = ctr_out_3(63, 0) ^ in3[i];
		out3[i + 1] = ctr_out_3(127, 64) ^ in3[i + 1];

		ap_uint<128> ctr_out_4;
		AES_Encrypt(reverse_bytes(ctr4), ctr_out_4, expanded_key);
		out4[i] = ctr_out_4(63, 0) ^ in4[i];
		out4[i + 1] = ctr_out_4(127, 64) ^ in4[i + 1];
	}
}

void aes_ofb_256(const ap_uint<AES_W> in[AES_N], ap_uint<AES_W> out[AES_N], const ap_uint<256> key, ap_uint<128> & iv)
{
	ap_uint<128> expanded_key[15];
#pragma HLS ARRAY_PARTITION variable=expanded_key complete dim=1
	unsigned char user_key[32], exp_keys[240];

	for (int i = 0; i < 32; i++) {
		user_key[i] = key((i + 1) * 8 - 1, i * 8);
	}
	key_expansion(user_key, exp_keys);
	for (int i = 0; i < 240; i++) {
		expanded_key[i / 16]((i % 16 + 1) * 8 - 1, (i % 16) * 8) = exp_keys[i];
	}

	ap_uint<128> current_iv = iv;

	aes_ofb_label1: for (int i = 0; i < AES_N; i += 2)
	{
#pragma HLS PIPELINE
		ap_uint<128> iv_new;
		AES_Encrypt(current_iv, iv_new, expanded_key);
		current_iv = iv_new;
		out[i] = in[i] ^ current_iv(63, 0);
		out[i + 1] = in[i + 1] ^ current_iv(127, 64);
	}

	iv = current_iv;
}
