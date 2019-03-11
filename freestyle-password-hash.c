/*
 * Copyright (c) 2018  P. Arun Babu and Jithin Jose Thomas 
 * arun DOT hbni AT gmail DOT com, jithinjosethomas AT gmail DOT com
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "freestyle.h"
#include <time.h>

void freestyle_hash_password (
	const 	char 		*password,
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

	const u8 	*plaintext = salt;	// salt is 'hash_len' bytes long
	u8 		*ciphertext;

	u8 iv [12];
	u8 key[32];

	u8 expected_hash;

	int password_len = strlen (password);

	assert (password_len 	<= 32);
	assert (hash_len 	<= 64);

	ciphertext = malloc(hash_len);
	if (! ciphertext)
	{
		perror("malloc failed ");
		exit(-1);
	}

	// fill iv with password length
	for (i = 0; i < 12; ++i)
		iv [i] = password_len; 

	// fill the key with password
	for (i = 0; i < 32; )
	{
		for (j = 0; i < 32 && j < password_len; ++j)
			key [i++] = (u8) password[j];
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

bool freestyle_verify_password_hash (
	const 	char 		*password,
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

	const u8 	*ciphertext = hash + num_init_hashes + 1;
	u8 		*plaintext;

	u8 iv [12];
	u8 key[32];

	u8 expected_hash = hash [num_init_hashes];

	int password_len = strlen (password);

	assert (password_len 	<= 32);
	assert (hash_len 	<= 64);

	plaintext = malloc(hash_len);
	if (! plaintext)
	{
		perror("malloc failed ");
		exit(-1);
	}

	// fill iv with password length
	for (i = 0; i < 12; ++i)
		iv[i] = password_len;

	// fill the key with password
	for (i = 0; i < 32; )
	{
		for (j = 0; i < 32 && j < password_len; ++j)
			key [i++] = (u8) password[j];
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

	return (0 == memcmp(plaintext,salt,hash_len));
}

int main ()
{
	int i;

	double th;
	double tc;
	double tw;

	const char PASSWORD_CHARS [] = 
			"abcdefghijklmnopqrstuvwxyz"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"01234567890"
			"~!@#$%^&*-_+=,.:;?/ {}[]<>()"
			;

	u8 hash [128];

	u8 min_rounds			= 8;
	u8 max_rounds			= 32;
	u8 pepper_bits			= 16;
	u8 num_init_hashes		= 7;
	u8 num_precomputed_rounds	= 4;

        struct timespec ts_start;
        struct timespec ts_end;

	char 	password 	[32 + 1];
	char 	wrong_password 	[32 + 1];

	u8	salt	 [64];

	for (int t = 1; t <= 10; ++t)
	{
		int password_len 	= 1 + arc4random_uniform(32);
		int hash_len 		= 1 + arc4random_uniform(64);

		for (i = 0; i < password_len; ++i)
		{
			int r = arc4random_uniform(sizeof(PASSWORD_CHARS) - 1);
			password[i] = PASSWORD_CHARS [r];
		}

		password[i] = '\0';

		arc4random_buf (salt, hash_len); 

		clock_gettime(CLOCK_MONOTONIC, &ts_start);
		freestyle_hash_password (
			password,
			salt,
			hash,
			hash_len,
			min_rounds,
			max_rounds,
			num_precomputed_rounds,
			pepper_bits,
			num_init_hashes
		);
		clock_gettime(CLOCK_MONOTONIC, &ts_end);

		th = (double) (ts_end.tv_nsec - ts_start.tv_nsec) +
            		(double) (ts_end.tv_sec - ts_start.tv_sec)*1000000000;

		printf ("(th) Time taken to hash                               = %f nano seconds\n",th);

		clock_gettime(CLOCK_MONOTONIC, &ts_start);
		bool success = freestyle_verify_password_hash (
			password,
			salt,
			hash,
			hash_len,
			min_rounds,
			max_rounds,
			num_precomputed_rounds,
			pepper_bits,
			num_init_hashes
		);
		clock_gettime(CLOCK_MONOTONIC, &ts_end);

		assert (success);

		tc = (double) (ts_end.tv_nsec - ts_start.tv_nsec) +
       		     (double) (ts_end.tv_sec - ts_start.tv_sec)*1000000000;

		printf ("(tc) Time taken to verify hash using CORRECT password = %f nano seconds\n",tc);

		// wrong password !
		strcpy(wrong_password,password);
		wrong_password[0] = ~wrong_password[0];

		clock_gettime(CLOCK_MONOTONIC, &ts_start);
		success = freestyle_verify_password_hash (
			wrong_password,
			salt,
			hash,
			hash_len,
			min_rounds,
			max_rounds,
			num_precomputed_rounds,
			pepper_bits,
			num_init_hashes
		);
		clock_gettime(CLOCK_MONOTONIC, &ts_end);

		assert (! success);

		tw = (double) (ts_end.tv_nsec - ts_start.tv_nsec) +
            		(double) (ts_end.tv_sec - ts_start.tv_sec)*1000000000;

		printf ("(tw) Time taken to verify hash using   WRONG password = %f nano seconds\n",tw);

		printf ("\ntc/th = %f\n",tc/th);
		printf ("tw/th = %f\n",tw/th);

		printf("---> Password hash test %d OK\n\n",t);
	}

	return 0;
}
