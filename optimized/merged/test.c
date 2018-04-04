#include "freestyle.h"
#include <time.h>

#define MSG_LEN (1024)

int main (int argc, char **argv)
{
	int i;

	double t_kc;
	double t_kw;

	u8 iv [12];
	u8 key[32];

	u8 message[MSG_LEN];

	freestyle_ctx encrypt;
	freestyle_ctx decrypt_correct;
	freestyle_ctx decrypt_wrong;

        struct timespec ts_start;
        struct timespec ts_end;

	u8 plaintext [MSG_LEN];
	u8 ciphertext[MSG_LEN];

	u16 expected_hash [MSG_LEN/64 + 1];

	u16 min_rounds 	= 8;
	u16 max_rounds 	= 32;

	u8 hash_complexity = 3;
	u16 hash_interval   = 1;

	u8 initalization_complexity = 16;

	for (i = 0; i < 32; ++i) {
		key[i] = (u8)arc4random();
	}
	for (i = 0; i < 12; ++i) {
		iv[i] = (u8)arc4random();
	}

	for (i = 0; i < MSG_LEN; ++i) {
		message[i] = (u8)arc4random();
	}
	
	freestyle_init_encrypt (
			&encrypt,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
			hash_complexity,
			hash_interval,
			initalization_complexity	
	);

	freestyle_encrypt (&encrypt, message, ciphertext, MSG_LEN, expected_hash);

	clock_gettime(CLOCK_MONOTONIC, &ts_start);
	freestyle_init_decrypt (
			&decrypt_correct,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
			hash_complexity,
			hash_interval,
			initalization_complexity,
			encrypt.init_hash	
	);
	freestyle_decrypt (&decrypt_correct, ciphertext, plaintext, MSG_LEN, expected_hash);
	clock_gettime(CLOCK_MONOTONIC, &ts_end);

	assert (0 == memcmp (plaintext, message, MSG_LEN));

	t_kc = (double) (ts_end.tv_nsec - ts_start.tv_nsec) +
            (double) (ts_end.tv_sec - ts_start.tv_sec)*1000000000;

	printf ("Time taken to decrypt using the CORRECT key = %f nano seconds\n",t_kc);
	fflush(stdout);
                

	// Try with a wrong key !
	key[0] = ~key[0];

	clock_gettime(CLOCK_MONOTONIC, &ts_start);
	freestyle_init_decrypt (
			&decrypt_wrong,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
			hash_complexity,
			hash_interval,
			initalization_complexity,
			encrypt.init_hash	
	);
	freestyle_decrypt (&decrypt_wrong, ciphertext, plaintext, MSG_LEN, expected_hash);
	clock_gettime(CLOCK_MONOTONIC, &ts_end);

	t_kw = (double) (ts_end.tv_nsec - ts_start.tv_nsec) +
            (double) (ts_end.tv_sec - ts_start.tv_sec)*1000000000;

	printf ("Time taken to decrypt using the WRONG key = %f nano seconds\n",t_kw);

	printf("Key guessing penalty (using uniform random number generator) = %f\n",t_kw/t_kc);
}
