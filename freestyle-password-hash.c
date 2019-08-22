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

#include "freestyle-password-hash.h"

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

	u8 key_and_iv [44];

	u8 expected_hash;

	int password_len = strlen (password);

	assert (password_len 	>= 1 );
	assert (password_len 	<= 43);
	assert (hash_len 	<= 64);

	ciphertext = malloc(hash_len);
	if (! ciphertext)
	{
		perror("malloc failed ");
		exit(-1);
	}

	// fill the key (32 bytes) and IV (first 11 bytes) with password
	for (i = 0; i < 43; )
	{
		for (j = 0; i < 43 && j < password_len; ++j)
		{
			key_and_iv [i++] = (u8) password[j];
		}
	}

	// last byte of IV is the password length 
	key_and_iv [43] = password_len;

	u8 *key	= key_and_iv;
	u8 *iv	= key_and_iv + 32; 

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

	u8 key_and_iv [44];

	u8 expected_hash = hash [num_init_hashes];

	int password_len = strlen (password);

	assert (password_len 	<= 43);
	assert (hash_len 	<= 64);

	plaintext = malloc(hash_len);
	if (! plaintext)
	{
		perror("malloc failed ");
		exit(-1);
	}

	// fill the key (32 bytes) and IV (first 11 bytes) with password
	for (i = 0; i < 43; )
	{
		for (j = 0; i < 43 && j < password_len; ++j)
		{
			key_and_iv [i++] = (u8) password[j];
		}
	}

	// last byte of IV is the password length 
	key_and_iv [43] = password_len;

	u8 *key	= key_and_iv;
	u8 *iv	= key_and_iv + 32; 

	if (! freestyle_init_decrypt (
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
	))
	{
		return false;
	}

	freestyle_decrypt (&x, ciphertext, plaintext, hash_len, &expected_hash);

	return (0 == memcmp(plaintext,salt,hash_len));
}
