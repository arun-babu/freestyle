#define MSG_LEN (64)
#include "freestyle.h"

int main ()
{
	int i, j;

	u8 iv [12];
	u8 key[32];

	freestyle_ctx encrypt;

	u8 plaintext [MSG_LEN];
	u8 ciphertext[MSG_LEN];

	u8 expected_hash;

	u32 min_rounds 	= 8;
	u32 max_rounds 	= 32;

	u8 pepper_bits = 16;
	u8 num_init_hashes = 7;

	u8 num_precomputed_rounds = 4;

	u16 total_tests = 30; 

	for (i = 0; i < 32; ++i) {
		key[i] = i; 
	}

	for (i = 0; i < 12; ++i) {
		iv[i] = i; 
	}

	for (i = 0; i < MSG_LEN; ++i) {
		ciphertext[i] = i; 
	}

	for (i = 0; i < total_tests; ++i)
	{
		memcpy(plaintext,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@",64);

		freestyle_init_encrypt (
			&encrypt,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
			num_precomputed_rounds,
			pepper_bits,
			num_init_hashes
		);
		freestyle_encrypt (&encrypt, plaintext, ciphertext, MSG_LEN, &expected_hash);
		printf("test_init_hash = {");
		for (j = 0; j < 7; ++j)
			printf("0x%.2x,",encrypt.init_hash[j]);
		printf("},\n");

		printf("test_ciphertext = {");
		for (j = 0; j < MSG_LEN; ++j)
			printf("0x%.2x,",ciphertext[j]);
		printf("},\n");

		printf("test_expected_hash = {");
			printf("0x%.2x",expected_hash);
		printf("},\n");
	}

	return 0;
}
