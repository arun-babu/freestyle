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

#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>

#include "freestyle.h"

int main ()
{
	int i;

	double th;
	double tc;
	double tw;

	const char PASSWORD_CHARS [] = 
			"abcdefghijklmnopqrstuvwxyz"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"0123456789"
			"~!@#$%^&*-_+=,.:;?/ {}[]<>()'\""
			;

	u8 hash [128];

	u8 min_rounds			= 8;
	u8 max_rounds			= 32;
	u8 pepper_bits			= 16;
	u8 num_init_hashes		= 7;
	u8 num_precomputed_rounds	= 4;

        struct timespec ts_start;
        struct timespec ts_end;

	char 	password 	[43 + 1];
	char 	wrong_password 	[43 + 1];

	u8	salt	 [64];

	int t;

	for (t = 1; t <= 10; ++t)
	{
		int password_len 	= 1 + arc4random_uniform(43);
		int hash_len 		= 1 + arc4random_uniform(64);

		for (i = 0; i < password_len; ++i)
		{
			int r = arc4random_uniform(sizeof(PASSWORD_CHARS) - 1);
			password[i] = PASSWORD_CHARS [r];
		}

		password[i] = '\0';
		printf ("For password = '%s'\n",password);

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

		printf ("(th) Time taken to hash password                      = %f nano seconds\n",th);

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

		fflush(stdout);
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

		fflush(stdout);
		assert (! success);

		tw = (double) (ts_end.tv_nsec - ts_start.tv_nsec) +
            		(double) (ts_end.tv_sec - ts_start.tv_sec)*1000000000;

		printf ("(tw) Time taken to verify hash using   WRONG password = %f nano seconds\n",tw);

		printf ("\ntc/th = %f\n",tc/th);
		printf ("tw/th = %f (KGP)\n",tw/th);

		printf ("---> Password hash test %d OK\n\n",t);
	}

	return 0;
}
