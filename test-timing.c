#include "freestyle.h"
#include <time.h>

#define MSG_LEN (1024)

int main (int argc, char **argv)
{
	int i;

	double t_kc;
	double t_kp;
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

	u32 min_rounds 	= 8;
	u32 max_rounds 	= 32;
	u8  num_precomputed_rounds = 4;

	u32 hash_interval   = 1;

	u8 pepper_bits = 16;
	u8 num_init_hashes = 28;

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
			num_precomputed_rounds,
			hash_interval,
			pepper_bits,
			num_init_hashes	
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
			num_precomputed_rounds,
			hash_interval,
			pepper_bits,
			num_init_hashes,
			encrypt.init_hash	
	);
	freestyle_decrypt (&decrypt_correct, ciphertext, plaintext, MSG_LEN, expected_hash);
	clock_gettime(CLOCK_MONOTONIC, &ts_end);

	fflush(stdout);
	assert (0 == memcmp (plaintext, message, MSG_LEN));

	t_kc = (double) (ts_end.tv_nsec - ts_start.tv_nsec) +
            (double) (ts_end.tv_sec - ts_start.tv_sec)*1000000000;

	printf("------------------------------------------------------------------------------------------------\n");
	printf("[ Timing tests ]\n");
	printf("------------------------------------------------------------------------------------------------\n");
	printf ("Time taken to decrypt using the CORRECT key                      = %f nano seconds\n",t_kc);

	clock_gettime(CLOCK_MONOTONIC, &ts_start);
	freestyle_init_decrypt_with_pepper (
			&decrypt_correct,
			key,
			256,
			iv,
			min_rounds,
			max_rounds,
			num_precomputed_rounds,
			hash_interval,
			pepper_bits,
			num_init_hashes,
			encrypt.pepper,
			encrypt.init_hash
	);
	freestyle_decrypt (&decrypt_correct, ciphertext, plaintext, MSG_LEN, expected_hash);
	clock_gettime(CLOCK_MONOTONIC, &ts_end);

	t_kp = (double) (ts_end.tv_nsec - ts_start.tv_nsec) +
            (double) (ts_end.tv_sec - ts_start.tv_sec)*1000000000;


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
			num_precomputed_rounds,
			hash_interval,
			pepper_bits,
			num_init_hashes,
			encrypt.init_hash	
	);
	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	freestyle_decrypt (&decrypt_wrong, ciphertext, plaintext, MSG_LEN, expected_hash);

	t_kw = (double) (ts_end.tv_nsec - ts_start.tv_nsec) +
            (double) (ts_end.tv_sec - ts_start.tv_sec)*1000000000;

	printf("Time taken to attempt decryption using the WRONG key             = %f nano seconds\n",t_kw);
	printf("Key guessing penalty (using uniform random number generator)     = %f\n",t_kw/t_kc);

	printf("------------------------------------------------------------------------------------------------\n");
	printf("Time taken to decrypt using the CORRECT key (using known pepper) = %f nano seconds\n",t_kp);
	printf("Key guessing penalty (when the pepper is known to the reciever)  = %f\n",t_kw/t_kp);
	printf("------------------------------------------------------------------------------------------------\n");

	return 0;
}
