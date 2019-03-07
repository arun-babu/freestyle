#define MSG_LEN (64)

#include "freestyle.h"
#include <time.h>

void freestyle_hash_password (
	const 	u8 		*password,
	const 	u8 		*salt,
		u8		*hash,
	const	size_t		hash_len,
	const 	u8 		min_rounds,
	const 	u8 		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8 		pepper_bits,
	const	u8 		num_init_hashes)
{
	int i,j;

	freestyle_ctx	x;

	const u8 *plaintext = salt;	// salt is 'hash_len' bytes long
	u8 ciphertext [MSG_LEN];

	u8 iv [12];
	u8 key[32];

	u8 expected_hash;

	int password_len = strlen (password);

	assert (hash_len 	<= 64);
	assert (password_len 	<= 32);

	// fill iv with password length
	for (i = 0; i < 12; ++i)
		iv [i] = password_len; 

	// fill the key with password
	for (i = 0; i < 32; )
	{
		for (j = 0; i < 32 && j < password_len; ++j)
			key [i++] = password[j];
	}

	freestyle_init_encrypt (
		&x,
		key,
		256,
		iv,
		min_rounds,
		max_rounds,
		num_precomputed_rounds,
		pepper_bits,
		num_init_hashes	
	);

	freestyle_encrypt (&x, plaintext, ciphertext, hash_len, &expected_hash);

	// 'hash' should be (hash_len + num_init_hashes + 1) long

	memcpy (hash, 				x.init_hash, 	num_init_hashes	);
	memcpy (hash + num_init_hashes, 	&expected_hash, 1		);
	memcpy (hash + num_init_hashes + 1, 	ciphertext, 	hash_len	);
}

bool freestyle_dehash_password (
	const 	u8 		*password,
	const 	u8 		*salt,
		u8		*hash,
	const	size_t		hash_len,
	const 	u8 		min_rounds,
	const 	u8 		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8 		pepper_bits,
	const	u8 		num_init_hashes)
{
	int i,j;

	freestyle_ctx	x;

	const u8 *ciphertext = hash + num_init_hashes + 1;
	u8 plaintext [MSG_LEN];

	u8 iv [12];
	u8 key[32];

	u8 expected_hash = hash [num_init_hashes];

	int password_len = strlen (password);

	assert (hash_len 	<= 64);
	assert (password_len 	<= 32);

	// fill iv with password length
	for (i = 0; i < 12; ++i)
		iv[i] = password_len;

	// fill the key with password
	for (i = 0; i < 32; )
	{
		for (j = 0; i < 32 && j < password_len; ++j)
			key [i++] = password[j];
	}

	freestyle_init_decrypt (
		&x,
		key,
		256,
		iv,
		min_rounds,
		max_rounds,
		num_precomputed_rounds,
		pepper_bits,
		num_init_hashes,
		hash		
	);

	freestyle_decrypt (&x, ciphertext, plaintext, hash_len, &expected_hash);

	int r = memcmp(plaintext,salt,hash_len);

	printf("Got pt = {%s} {%s} {%d} = %u\n",plaintext,salt, hash_len,
		memcmp(plaintext,salt,hash_len));

	printf("r == 0 %d\n",r);

	return r == 0;
}

int main ()
{
	double th;
	double td;

	u8 h[100];

	u8 min_rounds			= 8;
	u8 max_rounds			= 32;
	u8 pepper_bits			= 16;
	u8 num_init_hashes		= 7;
	u8 num_precomputed_rounds	= 4;

        struct timespec ts_start;
        struct timespec ts_end;

	clock_gettime(CLOCK_MONOTONIC, &ts_start);
	freestyle_hash_password (
		"hello",
		"world",
		h,
		5,
		min_rounds,
		max_rounds,
		num_precomputed_rounds,
		pepper_bits,
		num_init_hashes
	);
	clock_gettime(CLOCK_MONOTONIC, &ts_end);

	th = (double) (ts_end.tv_nsec - ts_start.tv_nsec) +
            (double) (ts_end.tv_sec - ts_start.tv_sec)*1000000000;

	printf ("Time taken to hash = %f nano seconds\n",th);

	clock_gettime(CLOCK_MONOTONIC, &ts_start);
	bool success = freestyle_dehash_password (
			"xhello",
			"world",
			h,
			5,
			min_rounds,
			max_rounds,
			num_precomputed_rounds,
			pepper_bits,
			num_init_hashes
	);
	clock_gettime(CLOCK_MONOTONIC, &ts_end);

	td = (double) (ts_end.tv_nsec - ts_start.tv_nsec) +
            (double) (ts_end.tv_sec - ts_start.tv_sec)*1000000000;

	printf ("Time taken to dehash = %f nano seconds\n",td);
	printf ("td/th = %f\n",td/th);

	if (success)
		printf("Passed\n");
	else
		printf("Failed\n");

	return 0;
}
