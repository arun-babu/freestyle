
#include "test-functionality.h"

#define MSG_LEN (64)

int main ()
{
	int i, j;

	u8 iv [12];
	u8 key[32];

	u8 message[MSG_LEN];

	freestyle_ctx encrypt;
	freestyle_ctx decrypt;

	u8 plaintext [MSG_LEN];
	u8 ciphertext[MSG_LEN];

	u8 expected_hash [MSG_LEN/64 + 1];

	u32 min_rounds 	= 8;
	u32 max_rounds 	= 32;

	u32 hash_interval = 1;

	u8 pepper_bits = 16;
	u32 pepper;
	u8 num_init_hashes = 7;

	u8 num_precomputed_rounds = 4;

	u16 total_tests = sizeof(test_init_hash)/sizeof(test_init_hash[0]);

	for (i = 0; i < 32; ++i) {
		key[i] = i; 
	}

	for (i = 0; i < 12; ++i) {
		iv[i] = i; 
	}

	for (i = 0; i < MSG_LEN; ++i) {
		ciphertext[i] = i; 
	}

	printf("--------------------------\n");
	printf("[ Functional tests ]\n");
	printf("--------------------------\n");

	for (i = 0; i < total_tests; ++i)
	{
		memset(plaintext,0,MSG_LEN);

		freestyle_init_decrypt (
			&decrypt,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
			num_precomputed_rounds,
			hash_interval,
			pepper_bits,
			num_init_hashes,
			test_init_hash[i]
		);
		freestyle_decrypt (&decrypt, test_ciphertext[i], plaintext, MSG_LEN, test_expected_hash[i]);

		fflush(stdout);
		assert(0 == memcmp(plaintext,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@",64));

		printf("Known ciphertext test %d OK\n",i);
	}

	printf("----------------------------------------------\n");

	for (i = 0; i < 15; ++i)
	{
		for (j = 0; j < 32; ++j) {
			key[j] = arc4random(); 
		}

		for (j = 0; j < 12; ++j) {
			iv[j] = arc4random(); 
		}

		for (j = 0; j < MSG_LEN; ++j) {
			message[j] = arc4random(); 
		}

		num_init_hashes = 7 + arc4random_uniform (56 - 7);

		freestyle_init_encrypt (
			&encrypt,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
			num_precomputed_rounds,
			hash_interval,
			pepper_bits,
			num_init_hashes	
		);
		freestyle_encrypt (&encrypt, message, ciphertext, MSG_LEN, expected_hash);

		freestyle_init_decrypt (
			&decrypt,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
			num_precomputed_rounds,
			hash_interval,
			pepper_bits,
			num_init_hashes,
			encrypt.init_hash	
		);
		freestyle_decrypt (&decrypt, ciphertext, plaintext, MSG_LEN, expected_hash);

		fflush(stdout);
		assert (0 == memcmp (plaintext, message, MSG_LEN));

		printf("Encrypt-Decrypt test %d OK\n",i);
	}

	printf("----------------------------------------------\n");

	for (i = 0; i < 15; ++i)
	{
		for (j = 0; j < 32; ++j) {
			key[j] = arc4random(); 
		}

		for (j = 0; j < 12; ++j) {
			iv[j] = arc4random(); 
		}

		for (j = 0; j < MSG_LEN; ++j) {
			message[j] = arc4random(); 
		}

		num_init_hashes = 7 + arc4random_uniform (56 - 7);

		pepper = arc4random_uniform(65536);

		freestyle_init_encrypt_with_pepper (
			&encrypt,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
			num_precomputed_rounds,
			hash_interval,
			pepper_bits,
			num_init_hashes,	
			pepper
		);
		freestyle_encrypt (&encrypt, message, ciphertext, MSG_LEN, expected_hash);

		freestyle_init_decrypt_with_pepper (
			&decrypt,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
			num_precomputed_rounds,
			hash_interval,
			pepper_bits,
			num_init_hashes,
			pepper,
			encrypt.init_hash	
		);
		freestyle_decrypt (&decrypt, ciphertext, plaintext, MSG_LEN, expected_hash);

		fflush(stdout);
		assert (0 == memcmp (plaintext, message, MSG_LEN));

		printf("Encrypt-Decrypt (with known pepper) test %d OK\n",i);
	}

	printf("\n");

	return 0;
}
