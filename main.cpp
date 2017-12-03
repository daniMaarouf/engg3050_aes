/*
 * Authors: Dani Maarouf, Andrew Gunter
 * Note that main.cpp, modes_aes.cpp, modes_aes.h, basic_aes.cpp and basic_aes.h
 * are code that is written by us and that the remaining files are from the
 * Crypto++ library. Some minor changes needed to be made to the Crypto++ library
 * files to remove C library calls which can't be used on the bare-metal Zedboard,
 * like time() and clock(). This means that the functionality of things like the
 * random number generators will be effected, however the functionality of AES
 * encryption and decryption is not affected
 *
 * Note 2: AES code we have written is for demonstration purposes only, do not
 * assume that it is cryptographically secure.
 */

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#include <stdio.h>
#include <iostream>
#include <string.h>
#include <assert.h>

//XILINX INCLUDES
#include "sds_lib.h"

//CRYPTOPP INCLUDES
#include "modes.h"
#include "cryptlib.h"
#include "aes.h"
#include "rng.h"
using namespace CryptoPP;

//PROJECT INCLUDES
#include "modes_aes.h"

enum mode {
	AES_ECB,
	AES_OFB,
	AES_CTR,
};

ap_uint<128> bytes_to_128(const unsigned char * c)
{
	ap_uint<128> temp = 0;
	for (int i = 0; i < 16; i++) {
		temp((i + 1) * 8 - 1, i * 8) = c[i];
	}
	return temp;
}

ap_uint<256> bytes_to_256(const unsigned char * c)
{
	ap_uint<256> temp = 0;
	for (int i = 0; i < 32; i++) {
		temp((i + 1) * 8 - 1, i * 8) = c[i];
	}
	return temp;
}

void _256_to_bytes(unsigned char * c, const ap_uint<256> w)
{
	for (int i = 0; i < 32; i++) {
		c[i] = w((i + 1) * 8 - 1, i * 8);
	}
}

void _128_to_bytes(unsigned char * c, const ap_uint<128> w)
{
	for (int i = 0; i < 16; i++) {
		c[i] = w((i + 1) * 8 - 1, i * 8);
	}
}

void aes_print_settings(const unsigned char * key, const unsigned char * init, int mode, bool hardware)
{
	printf("\n****************************************************************\n");
	printf("AES encryption settings: \n");
	printf("Mode: ");
	switch(mode) {
	case AES_ECB:
		printf("ECB\n");
		break;

	case AES_OFB:
		printf("OFB\n");
		break;

	case AES_CTR:
		printf("CTR\n");
		break;

	default:
		assert(0);
	}

	printf("Key (hexstring): ");
	for (int i = 0; i < 32; i++) {
		printf("%x", key[i]);
	}
	printf("\n");
	printf("Key (ASCII): ");
	for (int i = 0; i < 32; i++) {
		printf("%c", key[i]);
	}
	printf("\n");
	switch(mode) {
	case AES_ECB:
		break;

	case AES_OFB:
		printf("IV (hexstring): ");
		for (int i = 0; i < 16; i++) {
			printf("%x", init[i]);
		}
		printf("\n");
		printf("IV (ASCII): ");
		for (int i = 0; i < 16; i++) {
			printf("%c", init[i]);
		}
		printf("\n");
		break;

	case AES_CTR:
		printf("CTR init (hexstring): ");
		for (int i = 0; i < 16; i++) {
			printf("%x", init[i]);
		}
		printf("\n");
		printf("CTR init (ASCII): ");
		for (int i = 0; i < 16; i++) {
			printf("%c", init[i]);
		}
		printf("\n");
		std::cout << "CTR init (integer): " << bytes_to_128(init) << std::endl;
		break;

	default:
		assert(0);
	}
	printf("****************************************************************\n");
}

void aes_hardware_settings(int bytes_per_chunk, int num_chunks, int bytes_in_last_chunk, int num_rounds)
{
	printf("\n****************************************************************\n");
	printf("Hardware settings: \n");
	std::cout << "AES_N: " << AES_N << std::endl;
	std::cout << "AES_W: " << AES_W << std::endl;
	std::cout << "Bytes per chunk: " << bytes_per_chunk << std::endl;
	std::cout << "Num chunks: " << num_chunks << std::endl;
	std::cout << "Bytes in last chunk: " << bytes_in_last_chunk << std::endl;
	std::cout << "Num rounds: " << num_rounds << std::endl;
	printf("****************************************************************\n");
}

void cycle_count(unsigned long long total_cycles, unsigned long long encryption_cycles,
	unsigned long long copy_in_cycles, unsigned long long copy_out_cycles, int total_bytes)
{
#define ZEDBOARD_ARM_FREQ 667000000
	assert(total_cycles > 0 && encryption_cycles > 0);
	printf("\n****************************************************************\n");
	double total_time = (double) total_cycles / (double) ZEDBOARD_ARM_FREQ;
	double encryption_time = (double) encryption_cycles / (double) ZEDBOARD_ARM_FREQ;
	printf("Total cycles: %llu (%fs, %fMB/s, %f cycles per byte)\n", total_cycles, total_time, ((double) total_bytes) / (1024 * 1024 * total_time), (double) total_cycles / (double) total_bytes);
	printf("Encryption cycles: %llu (%fs, %fMB/s)\n", encryption_cycles, encryption_time, ((double) total_bytes) / (1024 * 1024 * encryption_time));
	printf("Copy in: %llu (%fs)\n", copy_in_cycles, (double) copy_in_cycles / (double) ZEDBOARD_ARM_FREQ);
	printf("Copy out: %llu (%fs)\n", copy_out_cycles, (double) copy_out_cycles / (double) ZEDBOARD_ARM_FREQ);
	printf("****************************************************************\n");
}

void aes_encrypt(const unsigned char * in, unsigned char * out, int num_bytes,
		const unsigned char key[32], const unsigned char init[16], int mode, bool hardware)
{
	assert(in != NULL && out != NULL && num_bytes >= 1 && key != NULL && (init != NULL || (mode == AES_ECB)));

	unsigned long long total_cycles = 0;
	unsigned long long encryption_cycles = 0;
	unsigned long long copy_in_cycles = 0;
	unsigned long long copy_out_cycles = 0;

	unsigned long long t_start = sds_clock_counter();

	aes_print_settings(key, init, mode, hardware);

	if (hardware) {

		int bytes_per_chunk = AES_N * AES_W / 8;

		int num_chunks = num_bytes / bytes_per_chunk;
		if (num_bytes % bytes_per_chunk != 0) {
			num_chunks++;
		}
		assert(num_chunks > 0 && num_chunks % 4 == 0);

		int bytes_in_last_chunk = num_bytes % bytes_per_chunk;
		if (bytes_in_last_chunk == 0) {
			bytes_in_last_chunk = bytes_per_chunk;
		}
		assert(bytes_in_last_chunk > 0);

		int num_rounds = num_chunks / 4;
		if (num_chunks % 4 != 0) {
			num_rounds++;
		}
		assert(num_rounds > 0);

		aes_hardware_settings(bytes_per_chunk, num_chunks, bytes_in_last_chunk, num_rounds);

		ap_uint<128> mode_init = bytes_to_128(init);

		for (int i = 0; i < num_rounds; i++) {

			unsigned long long round_encryption_cycles = 0;

			switch(mode) {
				case AES_ECB: {
					round_encryption_cycles = sds_clock_counter();
					aes_ecb_256(
						(ap_uint<64> *) (in 							+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (in + bytes_per_chunk 			+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (in + bytes_per_chunk * 2 		+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (in + bytes_per_chunk * 3 		+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (out 							+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (out + bytes_per_chunk 			+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (out + bytes_per_chunk * 2 		+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (out + bytes_per_chunk * 3 		+ i * 4 * bytes_per_chunk),
						bytes_to_256(key));
					round_encryption_cycles = sds_clock_counter() - round_encryption_cycles;
					break;
				}

				case AES_OFB: {

					round_encryption_cycles = sds_clock_counter();
					aes_ofb_256((ap_uint<64> *) (in 							+ i * 4 * bytes_per_chunk), (ap_uint<64> *) (out 							+ i * 4 * bytes_per_chunk), bytes_to_256(key), mode_init);
					aes_ofb_256((ap_uint<64> *) (in + bytes_per_chunk 			+ i * 4 * bytes_per_chunk), (ap_uint<64> *) (out + bytes_per_chunk 		+ i * 4 * bytes_per_chunk), bytes_to_256(key), mode_init);
					aes_ofb_256((ap_uint<64> *) (in + bytes_per_chunk * 2 		+ i * 4 * bytes_per_chunk), (ap_uint<64> *) (out + bytes_per_chunk * 2 	+ i * 4 * bytes_per_chunk), bytes_to_256(key), mode_init);
					aes_ofb_256((ap_uint<64> *) (in + bytes_per_chunk * 3 		+ i * 4 * bytes_per_chunk), (ap_uint<64> *) (out + bytes_per_chunk * 3 	+ i * 4 * bytes_per_chunk), bytes_to_256(key), mode_init);
					round_encryption_cycles = sds_clock_counter() - round_encryption_cycles;
					break;
				}

				case AES_CTR: {
					round_encryption_cycles = sds_clock_counter();
					aes_ctr_256_hp(
						(ap_uint<64> *) (in 							+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (in + bytes_per_chunk 			+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (in + bytes_per_chunk * 2 		+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (in + bytes_per_chunk * 3 		+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (out 							+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (out + bytes_per_chunk 			+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (out + bytes_per_chunk * 2 		+ i * 4 * bytes_per_chunk),
						(ap_uint<64> *) (out + bytes_per_chunk * 3 		+ i * 4 * bytes_per_chunk),
						bytes_to_256(key), mode_init);
					/*
					aes_ctr_256((ap_uint<64> *) (in 							+ i * 4 * bytes_per_chunk), (ap_uint<64> *) (out 							+ i * 4 * bytes_per_chunk), bytes_to_256(key), mode_init);
					aes_ctr_256((ap_uint<64> *) (in + bytes_per_chunk 			+ i * 4 * bytes_per_chunk), (ap_uint<64> *) (out + bytes_per_chunk 		+ i * 4 * bytes_per_chunk), bytes_to_256(key), mode_init);
					aes_ctr_256((ap_uint<64> *) (in + bytes_per_chunk * 2 		+ i * 4 * bytes_per_chunk), (ap_uint<64> *) (out + bytes_per_chunk * 2 	+ i * 4 * bytes_per_chunk), bytes_to_256(key), mode_init);
					aes_ctr_256((ap_uint<64> *) (in + bytes_per_chunk * 3 		+ i * 4 * bytes_per_chunk), (ap_uint<64> *) (out + bytes_per_chunk * 3 	+ i * 4 * bytes_per_chunk), bytes_to_256(key), mode_init);
					*/
					round_encryption_cycles = sds_clock_counter() - round_encryption_cycles;
					break;
				}

				default: {
					assert(0);
					break;
				}
			}

			encryption_cycles += round_encryption_cycles;
		}


	} else {

		switch(mode) {
			case AES_ECB: {
				encryption_cycles = sds_clock_counter();
				ECB_Mode<AES>::Encryption ecbEncryption(key, 32);
				ecbEncryption.ProcessData((byte*) out, (byte*) in, num_bytes);
				encryption_cycles = sds_clock_counter() - encryption_cycles;
				break;
			}


			case AES_OFB: {
				encryption_cycles = sds_clock_counter();
				//in this case 'init' parameter is used as IV
				OFB_Mode<AES>::Encryption ofbEncryption(key, 32, init);
				ofbEncryption.ProcessData((byte*) out, (byte*) in, num_bytes);
				encryption_cycles = sds_clock_counter() - encryption_cycles;
				break;
			}


			case AES_CTR: {
				encryption_cycles = sds_clock_counter();
				CTR_Mode<AES>::Encryption e;
				//in this case 'init' parameter used as initial counter value
				e.SetKeyWithIV(key, 32, init, 16);
				e.ProcessData((byte*) out, (byte*) in, num_bytes);
				encryption_cycles = sds_clock_counter() - encryption_cycles;
				break;
			}

			default: {
				assert(0);
				break;
			}
		}
	}

	total_cycles = sds_clock_counter() - t_start;
	cycle_count(total_cycles, encryption_cycles, copy_in_cycles, copy_out_cycles, num_bytes);

}

bool data_matches(unsigned long long * d1, unsigned long long * d2, int num)
{
	assert(d1 != NULL && d2 != NULL && num > 0);
	for (int i = 0; i < num; i++) {
		if (d1[i] != d2[i]) {
			return false;
		}
	}
	return true;
}

int main()
{

	std::cout << "ENGG3050 Term Project" << std::endl;
	std::cout << "Group 9:" << std::endl;
	std::cout << "Dani Maarouf (dmaarouf@uoguelph.ca):" << std::endl;
	std::cout << "Andrew Gunter (agunter@uoguelph.ca):" << std::endl;
	printf("****************************************************************\n");

	const int data_size = 10000000;

	int bytes = sizeof(unsigned long long) * data_size;
	bytes = ((bytes / (AES_N * AES_W / 2)) + 1) * (AES_N * AES_W / 2);

	unsigned long long * data = (unsigned long long *) sds_alloc(bytes);
	unsigned long long * data_out = (unsigned long long *) sds_alloc(bytes);
	unsigned long long * data_back = (unsigned long long *) sds_alloc(bytes);
	assert(data != NULL && data_out != NULL && data_back != NULL);
	for (int i = 0; i < data_size; i++) {
		data[i] = rand();
		data_back[i] = data[i];
	}

	unsigned char key[] = "This is my key. This is my key. This is my key. This is my key.";
	//unsigned char iv[] = "InitVectorInitVectorInitVector";
	unsigned char ctr[16];
	_128_to_bytes(ctr, 0);



	//unsigned char plainText[] = "Hello! How are you. This is a message which is encrypted with CTR";
	//int messageLen = (int)strlen((char *) plainText) + 1;
	//std::cout << "Message before: " << plainText << std::endl;

	std::cout << "ENCRYPTION" << std::endl;
	aes_encrypt((unsigned char *) data, (unsigned char *) data_out, bytes, key, ctr, AES_CTR, 1);

	std::cout << "DECRYPTION" << std::endl;
	aes_encrypt((unsigned char *) data_out, (unsigned char *) data, bytes, key, ctr, AES_CTR, 0);
	//std::cout << "Message after: " << plainText << std::endl;

	if (data_matches(data, data_back, data_size)) {
		std::cout << "Results before and after match" << std::endl;
	} else {
		std::cout << "Results before and after don't match" << std::endl;
	}

	std::cout << std::endl;

	std::cout << "ENCRYPTION" << std::endl;
	aes_encrypt((unsigned char *) data, (unsigned char *) data_out, bytes, key, ctr, AES_CTR, 0);

	std::cout << "DECRYPTION" << std::endl;
	aes_encrypt((unsigned char *) data_out, (unsigned char *) data, bytes, key, ctr, AES_CTR, 1);

	if (data_matches(data, data_back, data_size)) {
		std::cout << "Results before and after match" << std::endl;
	} else {
		std::cout << "Results before and after don't match" << std::endl;
	}

	sds_free(data);
	sds_free(data_out);
	sds_free(data_back);
	return 0;
}
