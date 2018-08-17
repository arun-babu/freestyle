
#include "test-functionality.h"

#define MSG_LEN (64)

int main (int argc, char **argv)
{
	int i, j;

	u8 iv [12];
	u8 key[32];

	u8 message[MSG_LEN];

	freestyle_ctx encrypt;
	freestyle_ctx decrypt;

	u8 plaintext [MSG_LEN+1];
	u8 ciphertext[MSG_LEN];

	u16 expected_hash [MSG_LEN/64 + 1];

	u32 min_rounds 	= 8;
	u32 max_rounds 	= 32;

	u32 hash_interval   = 1;

	u8 pepper_bits = 16;
	u8 num_init_hashes = 7;

	u16 total_tests = sizeof(test_init_hash)/sizeof(test_init_hash[0]);

	for (i = 0; i < 32; ++i) {
		key[i] = 0x0; 
	}

	for (i = 0; i < 12; ++i) {
		iv[i] = 0xF; 
	}

	for (i = 0; i < 64; ++i) {
		ciphertext[i] = i; 
	}

	printf("--------------------------\n");
	printf("[ Functional tests ]\n");
	printf("--------------------------\n");

	for (i = 0; i < total_tests; ++i)
	{
		memset(plaintext,0,65);

		freestyle_init_decrypt (
			&decrypt,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
			hash_interval,
			pepper_bits,
			num_init_hashes,	
			test_init_hash[i]
		);
		freestyle_decrypt (&decrypt, test_ciphertext[i], plaintext, MSG_LEN, test_expected_hash[i]);

		if (0 != strncmp(plaintext,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@",64))
		{
			printf("%d Failed '%s'\n",i,plaintext);
		}
		//assert(0 == strncmp(plaintext,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@",64));

		printf("Known ciphertext test %d OK\n",i);
	}

	printf("--------------------------\n");

	for (i = 0; i < 10; ++i)
	{
		for (j = 0; j < 32; ++j) {
			key[j] = arc4random(); 
		}

		for (j = 0; j < 12; ++j) {
			iv[j] = arc4random(); 
		}

		for (j = 0; j < 64; ++j) {
			message[j] = arc4random(); 
		}

		freestyle_init_encrypt (
			&encrypt,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
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
			hash_interval,
			pepper_bits,
			num_init_hashes,
			encrypt.init_hash	
		);
		freestyle_decrypt (&decrypt, ciphertext, plaintext, MSG_LEN, expected_hash);

		assert (0 == memcmp (plaintext, message, MSG_LEN));

		printf("Encrypt-Decrypt test %d OK\n",i);
	}

	printf("\n");

	return 0;
}
