/*
 * Copyright (c) 2019  P. Arun Babu and Jithin Jose Thomas
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

/*
 * Some code is taken from D. J. Bernstein's
 * chacha-merged.c version 20080118
 * Public domain.
 */

#include "freestyle.h"
#include "freestyle-opt.h"

static u8 gcd (u8 a, u8 b)
{
	u8 r;

	while (b != 0)
	{
		r = a % b;
		a = b;
		b = r;
	}

	return a;
}

void freestyle_set_counter (freestyle_ctx* const x, const u32 counter)
{
	x->input_COUNTER = PLUS(x->initial_counter, counter);
}

static void freestyle_keysetup (
		freestyle_ctx*	const x,
	const	u8*		key,
	const	u16		key_length_bits)
{
	const char *constants;

	x->input_KEY0 = U8TO32_LITTLE(key +  0);
	x->input_KEY1 = U8TO32_LITTLE(key +  4);
	x->input_KEY2 = U8TO32_LITTLE(key +  8);
	x->input_KEY3 = U8TO32_LITTLE(key + 12);

	if (key_length_bits == 128) /* 256 is recommended */
	{
		constants = tau;
	}
	else
	{
		key += 16;
		constants = sigma;
	}

	x->input_KEY4 = U8TO32_LITTLE(key +  0);
	x->input_KEY5 = U8TO32_LITTLE(key +  4);
	x->input_KEY6 = U8TO32_LITTLE(key +  8);
	x->input_KEY7 = U8TO32_LITTLE(key + 12);

	x->input_CONSTANT0 = U8TO32_LITTLE(constants +  0);
	x->input_CONSTANT1 = U8TO32_LITTLE(constants +  4);
	x->input_CONSTANT2 = U8TO32_LITTLE(constants +  8);
	x->input_CONSTANT3 = U8TO32_LITTLE(constants + 12);
}

static void freestyle_ivsetup (
		freestyle_ctx*	const x,
	const	u8*		const iv,
	const	u32		counter)
{
	x->input_COUNTER	= counter;

	x->input_IV0		= U8TO32_LITTLE(iv + 0);
	x->input_IV1		= U8TO32_LITTLE(iv + 4);
	x->input_IV2		= U8TO32_LITTLE(iv + 8);
}

static void freestyle_roundsetup (
		freestyle_ctx*	const x,
	const	u8		min_rounds,
	const	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8		pepper_bits,
	const	u8		num_init_hashes)
{
	u8 i;

	x->min_rounds			= min_rounds;
	x->max_rounds			= max_rounds;
	x->num_precomputed_rounds	= num_precomputed_rounds;
	x->pepper_bits			= pepper_bits;
	x->num_init_hashes		= num_init_hashes;

	x->hash_interval		= gcd(x->min_rounds,x->max_rounds);

	/* 8 + 8 + 6 + 6 + 4  bits */
	u32 cipher_parameter =	((x->min_rounds			& 0xFF) << 24)
				| ((x->max_rounds		& 0xFF) << 16)
				| ((x->pepper_bits		& 0x3F) << 10)
				| ((x->num_init_hashes		& 0x3F) <<  4)
				| ((x->num_precomputed_rounds	& 0x0F)      );

	for (i = 0; i < 8; ++i) {
		x->rand[i] = 0;
	}

	/* modify constant[0] */
	x->input_CONSTANT0 ^= cipher_parameter;
}

static u8 freestyle_encrypt_block_init (
		freestyle_ctx* const x,
	const	u8		rounds,
		u8*		const expected_hash)
{
	u8	hash = 0;

	u32	temp1, temp2;

	u8	r;

	u32 hash_collided [8];

	u32	output_00 = x->input_CONSTANT0,
		output_01 = x->input_CONSTANT1,
		output_02 = x->input_CONSTANT2,
		output_03 = x->input_CONSTANT3,

		output_04 = x->input_KEY0,
		output_05 = x->input_KEY1,
		output_06 = x->input_KEY2,
		output_07 = x->input_KEY3,
		output_08 = x->input_KEY4,
		output_09 = x->input_KEY5,
		output_10 = x->input_KEY6,
		output_11 = x->input_KEY7,

		output_12 = x->input_COUNTER ^ x->rand[0],

		output_13 = x->input_IV0,
		output_14 = x->input_IV1,
		output_15 = x->input_IV2;

	memset (hash_collided, 0, sizeof(hash_collided));

	for (r = x->num_precomputed_rounds + 1; r <= rounds; ++r)
	{
		if (r & 1)
		{
			FREESTYLE_COLUMN_ROUND()
		}
		else
		{
			FREESTYLE_DIAGONAL_ROUND()
		}

		if (r >= x->min_rounds && r % x->hash_interval == 0)
		{
			COMPUTE_HASH(x,hash,r)
		}
	}

	/* This function is only called at initalization
	no encryption is performed. */

	*expected_hash = hash;

	return rounds;
}

static u8 freestyle_decrypt_block_init (
		freestyle_ctx*	const x,
		u8*		const expected_hash)
{
	u8	hash = 0;

	u32	temp1, temp2;

	u8	r;

	u32 hash_collided [8];

	u32	output_00 = x->input_CONSTANT0,
		output_01 = x->input_CONSTANT1,
		output_02 = x->input_CONSTANT2,
		output_03 = x->input_CONSTANT3,

		output_04 = x->input_KEY0,
		output_05 = x->input_KEY1,
		output_06 = x->input_KEY2,
		output_07 = x->input_KEY3,
		output_08 = x->input_KEY4,
		output_09 = x->input_KEY5,
		output_10 = x->input_KEY6,
		output_11 = x->input_KEY7,

		output_12 = x->input_COUNTER ^ x->rand[0],

		output_13 = x->input_IV0,
		output_14 = x->input_IV1,
		output_15 = x->input_IV2;

	memset (hash_collided, 0, sizeof(hash_collided));

	for (r = x->num_precomputed_rounds + 1; r <= x->max_rounds; ++r)
	{
		if (r & 1)
		{
			FREESTYLE_COLUMN_ROUND()
		}
		else
		{
			FREESTYLE_DIAGONAL_ROUND()
		}

		if (r >= x->min_rounds && r % x->hash_interval == 0)
		{
			COMPUTE_HASH(x,hash,r)

			if (hash == *expected_hash) {
				break;
			}
		}
	}

	/* This function is only called at initalization
	no decryption is performed. */

	if (r > x->max_rounds)
		return 0;
	else
		return r;
}

static void freestyle_randomsetup_encrypt (freestyle_ctx* const x)
{
	u32	i;

	u8	r;
	u8	R [MAX_INIT_HASHES]; /* actual random rounds */
	u8	CR[MAX_INIT_HASHES]; /* collided random rounds */

	u32	temp1;
	u32	temp2;

	const u8 saved_min_rounds		= x->min_rounds;
	const u8 saved_max_rounds		= x->max_rounds;
	const u8 saved_hash_interval		= x->hash_interval;
	const u8 saved_num_precomputed_rounds	= x->num_precomputed_rounds;

	u32 p;

	/* init RNG */
	freestyle_init_RNG(x);

	if (! x->is_pepper_set)
	{
		if (x->pepper_bits == 32)
			x->pepper = arc4random_uniform (UINT32_MAX);
		else
			x->pepper = arc4random_uniform (
				1 << x->pepper_bits
			);
	}

	/* set sane values for initalization */
	x->min_rounds			= 8;
	x->max_rounds			= 32;
	x->hash_interval		= 1;
	x->num_precomputed_rounds	= 4;

	for (i = 0; i < MAX_INIT_HASHES; ++i) {

		R[i] = CR[i] = 0;

		// generate all init random round numbers
		if (i < x->num_init_hashes)
		{
			R[i] = x->min_rounds + arc4random_uniform(
				x->max_rounds - x->min_rounds + 1
			);
		}
	}

	/* initial pre-computed rounds */
	freestyle_precompute_rounds(x);

	/* add a random/user-set pepper to constant[0] */
	x->input_CONSTANT0 = PLUS(x->input_CONSTANT0,x->pepper);

	for (i = 0; i < x->num_init_hashes; ++i)
	{
		freestyle_encrypt_block_init (
			x,
			R[i],
			&x->init_hash [i]
		);

		freestyle_increment_counter(x);
	}

	if (! x->is_pepper_set)
	{
		/* set constant[0] back to its previous value */
		x->input_CONSTANT0 = MINUS(x->input_CONSTANT0,x->pepper);

		/* check for any collisions between 0 and pepper */
		for (p = 0; p < x->pepper; ++p)
		{
			x->input_COUNTER = x->initial_counter;

			for (i = 0; i < x->num_init_hashes; ++i)
			{
				CR[i] = freestyle_decrypt_block_init (
					x,
					&x->init_hash [i]
				);

				if (CR[i] == 0) {
					goto retry;
				}

				freestyle_increment_counter(x);
			}

			/* found a collision. use the collided rounds */
			memcpy (R, CR, sizeof(R));
			break;

retry:
			x->input_CONSTANT0 = PLUSONE(x->input_CONSTANT0);
		}
	}

	for (i = 0; i < 8; ++i)
	{
		temp1 = 0;
		temp2 = 0;

		AXR (temp1, R[7*i + 0], temp2, 16);
		AXR (temp2, R[7*i + 1], temp1, 12);
		AXR (temp1, R[7*i + 2], temp2,  8);
		AXR (temp2, R[7*i + 3], temp1,  7);

		AXR (temp1, R[7*i + 4], temp2, 16);
		AXR (temp2, R[7*i + 5], temp1, 12);
		AXR (temp1, R[7*i + 6], temp2,  8);
		AXR (temp2, R[7*i + 0], temp1,  7);

		x->rand[i] = temp1;
	}

	/* set user parameters back */
	x->min_rounds			= saved_min_rounds;
	x->max_rounds			= saved_max_rounds;
	x->hash_interval		= saved_hash_interval;
	x->num_precomputed_rounds	= saved_num_precomputed_rounds;

	/* set counter to the value that was after pre-computed rounds */
	x->input_COUNTER = x->initial_counter;

	/* modify constant[1], constant[2], and constant[3] */
	x->input_CONSTANT1 ^= x->rand[1];
	x->input_CONSTANT2 ^= x->rand[2];
	x->input_CONSTANT3 ^= x->rand[3];

	/* modify key[0], key[1], key[2], and key[3] */
	x->input_KEY0 ^= x->rand[4];
	x->input_KEY1 ^= x->rand[5];
	x->input_KEY2 ^= x->rand[6];
	x->input_KEY3 ^= x->rand[7];

	/* Do pre-computation as specified by the user */
	freestyle_precompute_rounds(x);
}

static bool freestyle_randomsetup_decrypt (freestyle_ctx* const x)
{
	u32	i;

	u8	r;
	u8	R [MAX_INIT_HASHES]; /* random rounds */

	u32	temp1;
	u32	temp2;

	const u8 saved_min_rounds		= x->min_rounds;
	const u8 saved_max_rounds		= x->max_rounds;
	const u8 saved_hash_interval		= x->hash_interval;
	const u8 saved_num_precomputed_rounds	= x->num_precomputed_rounds;

	const u32 max_pepper = (x->pepper_bits == 32) ?
				UINT32_MAX : (u32) ((1 << x->pepper_bits) - 1);

	bool found_pepper		= false;

	/* set sane values for initalization */
	x->min_rounds			= 8;
	x->max_rounds			= 32;
	x->hash_interval		= 1;
	x->num_precomputed_rounds	= 4;

	for (i = 0; i < MAX_INIT_HASHES; ++i) {
		R[i] = 0;
	}

	/* initial pre-computed rounds */
	freestyle_precompute_rounds(x);

	/* if initial pepper is set, then add it to constant[0] */
	x->input_CONSTANT0 = PLUS(x->input_CONSTANT0, x->pepper);

	const	u32 start_pepper	= x->pepper;
		u32 running_pepper	= x->pepper;

	while (true)
	{
		x->input_COUNTER = x->initial_counter;

		for (i = 0; i < x->num_init_hashes; ++i)
		{
			R[i] = freestyle_decrypt_block_init (
				x,
				&x->init_hash [i]
			);

			if (R[i] == 0) {
				goto retry;
			}

			freestyle_increment_counter(x);
		}

		/* found all valid R[i]s */
		found_pepper = true;
		break;

retry:
		x->input_CONSTANT0 = PLUSONE(x->input_CONSTANT0);

		++running_pepper;

		if (running_pepper > max_pepper)
			running_pepper = 0;

		if (running_pepper == start_pepper)
			return false;
	}

	if (! found_pepper)
		return false;

	for (i = 0; i < 8; ++i)
	{
		temp1 = 0;
		temp2 = 0;

		AXR (temp1, R[7*i + 0], temp2, 16);
		AXR (temp2, R[7*i + 1], temp1, 12);
		AXR (temp1, R[7*i + 2], temp2,  8);
		AXR (temp2, R[7*i + 3], temp1,  7);

		AXR (temp1, R[7*i + 4], temp2, 16);
		AXR (temp2, R[7*i + 5], temp1, 12);
		AXR (temp1, R[7*i + 6], temp2,  8);
		AXR (temp2, R[7*i + 0], temp1,  7);

		x->rand[i] = temp1;
	}

	/* set user parameters back */
	x->min_rounds			= saved_min_rounds;
	x->max_rounds			= saved_max_rounds;
	x->hash_interval		= saved_hash_interval;
	x->num_precomputed_rounds	= saved_num_precomputed_rounds;

	/* set counter to the value that was after pre-computed rounds */
	x->input_COUNTER = x->initial_counter;

	/* modify constant[1], constant[2], and constant[3] */
	x->input_CONSTANT1 ^= x->rand[1];
	x->input_CONSTANT2 ^= x->rand[2];
	x->input_CONSTANT3 ^= x->rand[3];

	/* modify key[0], key[1], key[2], and key[3] */
	x->input_KEY0 ^= x->rand[4];
	x->input_KEY1 ^= x->rand[5];
	x->input_KEY2 ^= x->rand[6];
	x->input_KEY3 ^= x->rand[7];

	/* Do pre-computation as specified by the user */
	freestyle_precompute_rounds(x);

	return true;
}

static void freestyle_init_common (
		freestyle_ctx*	const x,
	const	u8*		const key,
	const	u16		key_length_bits,
	const	u8*		const iv,
	const	u8		min_rounds,
	const	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8		pepper_bits,
	const	u8		num_init_hashes)
{
	assert (min_rounds >= 1);
	assert (min_rounds <= max_rounds);

	assert (num_precomputed_rounds <= 15);
	assert (num_precomputed_rounds <= (min_rounds - 4));

	assert (pepper_bits >= 8);
	assert (pepper_bits <= 32);

	assert (num_init_hashes >= 7);
	assert (num_init_hashes <= 56);

	freestyle_keysetup	(x, key, key_length_bits);
	freestyle_ivsetup	(x, iv, 0);
	freestyle_roundsetup	(
		x,
		min_rounds,
		max_rounds,
		num_precomputed_rounds,
		pepper_bits,
		num_init_hashes
	);
}

void freestyle_init_encrypt (
		freestyle_ctx*	const x,
	const	u8*		const key,
	const	u16		key_length_bits,
	const	u8*		const iv,
	const	u8		min_rounds,
	const	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8		pepper_bits,
	const	u8		num_init_hashes)
{
	freestyle_init_common (
		x,
		key,
		key_length_bits,
		iv,
		min_rounds,
		max_rounds,
		num_precomputed_rounds,
		pepper_bits,
		num_init_hashes
	);

	x->pepper		= 0;
	x->is_pepper_set	= false;

	freestyle_randomsetup_encrypt(x);
}

void freestyle_init_encrypt_with_pepper (
		freestyle_ctx*	const x,
	const	u8*		const key,
	const	u16		key_length_bits,
	const	u8*		const iv,
	const	u8		min_rounds,
	const	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8		pepper_bits,
	const	u8		num_init_hashes,
	const	u32		pepper)
{
	freestyle_init_common (
		x,
		key,
		key_length_bits,
		iv,
		min_rounds,
		max_rounds,
		num_precomputed_rounds,
		pepper_bits,
		num_init_hashes
	);

	x->pepper		= pepper;
	x->is_pepper_set	= true;

	freestyle_randomsetup_encrypt(x);
}

bool freestyle_init_decrypt (
		freestyle_ctx*	const x,
	const	u8*		const key,
	const	u16		key_length_bits,
	const	u8*		const iv,
	const	u8		min_rounds,
	const	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8		pepper_bits,
	const	u8		num_init_hashes,
	const	u8*		const init_hash)
{
	freestyle_init_common (
		x,
		key,
		key_length_bits,
		iv,
		min_rounds,
		max_rounds,
		num_precomputed_rounds,
		pepper_bits,
		num_init_hashes
	);

	x->pepper		= 0;
	x->is_pepper_set	= false;

	memcpy (
		x->init_hash,
		init_hash,
		sizeof(x->init_hash)
	);

	return freestyle_randomsetup_decrypt(x);
}

bool freestyle_init_decrypt_with_pepper (
		freestyle_ctx*	const x,
	const	u8*		const key,
	const	u16		key_length_bits,
	const	u8*		const iv,
	const	u8		min_rounds,
	const	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8		pepper_bits,
	const	u8		num_init_hashes,
	const	u32		pepper,
	const	u8*		const init_hash)
{
	freestyle_init_common (
		x,
		key,
		key_length_bits,
		iv,
		min_rounds,
		max_rounds,
		num_precomputed_rounds,
		pepper_bits,
		num_init_hashes
	);

	x->pepper		= pepper;
	x->is_pepper_set	= true;

	memcpy (
		x->init_hash,
		init_hash,
		sizeof(x->init_hash)
	);

	return freestyle_randomsetup_decrypt(x);
}

void freestyle_encrypt (
		freestyle_ctx*	const	restrict	x,
	const	u8*			restrict	plaintext,
		u8*			restrict	ciphertext,
		u32					bytes,
		u8*		const	restrict	expected_hash)
{
	u32	i;

	u32	block = 0;

	u8	hash;

	u16	r;
	u16	rounds;

	u32	temp1, temp2;

	u8	keystream[64];

	register u32
		output_00, output_01, output_02, output_03,
		output_04, output_05, output_06, output_07,
		output_08, output_09, output_10, output_11,
		output_12, output_13, output_14, output_15;

	u32 hash_collided [8];

	while (bytes > 0)
	{
		hash = 0;

		memset (hash_collided, 0, sizeof(hash_collided));

		output_00 = x->input_CONSTANT0;
		output_01 = x->input_CONSTANT1;
		output_02 = x->input_CONSTANT2;
		output_03 = x->input_CONSTANT3;

		output_04 = x->input_KEY0;
		output_05 = x->input_KEY1;
		output_06 = x->input_KEY2;
		output_07 = x->input_KEY3;
		output_08 = x->input_KEY4;
		output_09 = x->input_KEY5;
		output_10 = x->input_KEY6;
		output_11 = x->input_KEY7;

		output_12 = x->input_COUNTER ^ x->rand[0];

		output_13 = x->input_IV0;
		output_14 = x->input_IV1;
		output_15 = x->input_IV2;

		/* Generate a random round */
		freestyle_random_round_number_fast(x,rounds);

		assert (rounds >= x->min_rounds);
		assert (rounds <= x->max_rounds);

		for (r = x->num_precomputed_rounds + 1; r <= rounds; ++r)
		{
			if (r & 1)
			{
				FREESTYLE_COLUMN_ROUND()
			}
			else
			{
				FREESTYLE_DIAGONAL_ROUND()
			}

			if (r >= x->min_rounds && r % x->hash_interval == 0)
			{
				COMPUTE_HASH(x,hash,r)
			}
		}

		assert (r <= x->max_rounds + 1);

		expected_hash[block] = hash;

		output_00 = PLUS(output_00, x->input_CONSTANT0);
		output_01 = PLUS(output_01, x->input_CONSTANT1);
		output_02 = PLUS(output_02, x->input_CONSTANT2);
		output_03 = PLUS(output_03, x->input_CONSTANT3);

		output_04 = PLUS(output_04, x->input_KEY0);
		output_05 = PLUS(output_05, x->input_KEY1);
		output_06 = PLUS(output_06, x->input_KEY2);
		output_07 = PLUS(output_07, x->input_KEY3);
		output_08 = PLUS(output_08, x->input_KEY4);
		output_09 = PLUS(output_09, x->input_KEY5);
		output_10 = PLUS(output_10, x->input_KEY6);
		output_11 = PLUS(output_11, x->input_KEY7);

		output_12 = PLUS(output_12, x->input_COUNTER);

		output_13 = PLUS(output_13, x->input_IV0);
		output_14 = PLUS(output_14, x->input_IV1);
		output_15 = PLUS(output_15, x->input_IV2);

		U32TO8_LITTLE (keystream + 4 * 0,  output_00);
		U32TO8_LITTLE (keystream + 4 * 1,  output_01);
		U32TO8_LITTLE (keystream + 4 * 2,  output_02);
		U32TO8_LITTLE (keystream + 4 * 3,  output_03);
		U32TO8_LITTLE (keystream + 4 * 4,  output_04);
		U32TO8_LITTLE (keystream + 4 * 5,  output_05);
		U32TO8_LITTLE (keystream + 4 * 6,  output_06);
		U32TO8_LITTLE (keystream + 4 * 7,  output_07);
		U32TO8_LITTLE (keystream + 4 * 8,  output_08);
		U32TO8_LITTLE (keystream + 4 * 9,  output_09);
		U32TO8_LITTLE (keystream + 4 * 10, output_10);
		U32TO8_LITTLE (keystream + 4 * 11, output_11);
		U32TO8_LITTLE (keystream + 4 * 12, output_12);
		U32TO8_LITTLE (keystream + 4 * 13, output_13);
		U32TO8_LITTLE (keystream + 4 * 14, output_14);
		U32TO8_LITTLE (keystream + 4 * 15, output_15);

		if (bytes >= 64)
		{
			FREESTYLE_XOR_64(plaintext,ciphertext,keystream)
		}
		else
		{
			for (i = 0; i < bytes; ++i) {
				ciphertext [i] = plaintext[i] ^ keystream[i];
			}

			return;
		}

		plaintext  += 64;
		ciphertext += 64;

		bytes -= 64;

		++block;

		freestyle_increment_counter(x);
	}
}

void freestyle_decrypt (
		freestyle_ctx*	const	restrict	x,
	const	u8*			restrict	ciphertext,
		u8*			restrict	plaintext,
		u32					bytes,
		u8*		const	restrict	expected_hash)
{
	u32	i;

	u32	block = 0;

	u8	hash;

	u16	r;

	u32	temp1, temp2;

	u8	keystream[64];

	register u32
		output_00, output_01, output_02, output_03,
		output_04, output_05, output_06, output_07,
		output_08, output_09, output_10, output_11,
		output_12, output_13, output_14, output_15;

	u32 hash_collided [8];

	while (bytes > 0)
	{
		hash = 0;

		memset (hash_collided, 0, sizeof(hash_collided));

		output_00 = x->input_CONSTANT0;
		output_01 = x->input_CONSTANT1;
		output_02 = x->input_CONSTANT2;
		output_03 = x->input_CONSTANT3;

		output_04 = x->input_KEY0;
		output_05 = x->input_KEY1;
		output_06 = x->input_KEY2;
		output_07 = x->input_KEY3;
		output_08 = x->input_KEY4;
		output_09 = x->input_KEY5;
		output_10 = x->input_KEY6;
		output_11 = x->input_KEY7;

		output_12 = x->input_COUNTER ^ x->rand[0];

		output_13 = x->input_IV0;
		output_14 = x->input_IV1;
		output_15 = x->input_IV2;

		for(r = x->num_precomputed_rounds + 1; r <= x->max_rounds; ++r)
		{
			if (r & 1)
			{
				FREESTYLE_COLUMN_ROUND()
			}
			else
			{
				FREESTYLE_DIAGONAL_ROUND()
			}

			if (r >= x->min_rounds && r % x->hash_interval == 0)
			{
				COMPUTE_HASH(x,hash,r)

				if (hash == expected_hash[block]) {
					break;
				}
			}
		}

		output_00 = PLUS(output_00, x->input_CONSTANT0);
		output_01 = PLUS(output_01, x->input_CONSTANT1);
		output_02 = PLUS(output_02, x->input_CONSTANT2);
		output_03 = PLUS(output_03, x->input_CONSTANT3);

		output_04 = PLUS(output_04, x->input_KEY0);
		output_05 = PLUS(output_05, x->input_KEY1);
		output_06 = PLUS(output_06, x->input_KEY2);
		output_07 = PLUS(output_07, x->input_KEY3);
		output_08 = PLUS(output_08, x->input_KEY4);
		output_09 = PLUS(output_09, x->input_KEY5);
		output_10 = PLUS(output_10, x->input_KEY6);
		output_11 = PLUS(output_11, x->input_KEY7);

		output_12 = PLUS(output_12, x->input_COUNTER);

		output_13 = PLUS(output_13, x->input_IV0);
		output_14 = PLUS(output_14, x->input_IV1);
		output_15 = PLUS(output_15, x->input_IV2);

		U32TO8_LITTLE (keystream + 4 * 0,  output_00);
		U32TO8_LITTLE (keystream + 4 * 1,  output_01);
		U32TO8_LITTLE (keystream + 4 * 2,  output_02);
		U32TO8_LITTLE (keystream + 4 * 3,  output_03);
		U32TO8_LITTLE (keystream + 4 * 4,  output_04);
		U32TO8_LITTLE (keystream + 4 * 5,  output_05);
		U32TO8_LITTLE (keystream + 4 * 6,  output_06);
		U32TO8_LITTLE (keystream + 4 * 7,  output_07);
		U32TO8_LITTLE (keystream + 4 * 8,  output_08);
		U32TO8_LITTLE (keystream + 4 * 9,  output_09);
		U32TO8_LITTLE (keystream + 4 * 10, output_10);
		U32TO8_LITTLE (keystream + 4 * 11, output_11);
		U32TO8_LITTLE (keystream + 4 * 12, output_12);
		U32TO8_LITTLE (keystream + 4 * 13, output_13);
		U32TO8_LITTLE (keystream + 4 * 14, output_14);
		U32TO8_LITTLE (keystream + 4 * 15, output_15);

		if (bytes >= 64)
		{
			FREESTYLE_XOR_64(ciphertext,plaintext,keystream)
		}
		else
		{
			for (i = 0; i < bytes; ++i) {
				plaintext [i] = ciphertext[i] ^ keystream[i];
			}

			return;
		}

		plaintext  += 64;
		ciphertext += 64;

		bytes -= 64;

		++block;

		x->input_COUNTER = PLUSONE (x->input_COUNTER);
	}
}

void freestyle_hash_password (
	const	char*		const password,
	const	u8*		const salt,
		u8*		const hash,
	const	size_t		hash_len,
	const	u8		min_rounds,
	const	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8		pepper_bits,
	const	u8		num_init_hashes)
{
	int i,j;

	freestyle_ctx x;

	/* salt is 'hash_len' bytes long */
	const	u8*	const	plaintext	= salt;
		u8*		ciphertext	= NULL;

	u8 key_and_iv [44];

	u8 expected_hash;

	int password_len = strlen (password);

	assert (password_len	>=  1);
	assert (password_len	<= 43);
	assert (hash_len	<= 64);

	if (! (ciphertext = malloc(hash_len)))
	{
		perror("malloc failed ");
		exit(-1);
	}

	/* Fill the key (32 bytes)
		and IV (first 11 bytes) with password */
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

	freestyle_encrypt (
		&x,
		plaintext,
		ciphertext,
		hash_len,
		&expected_hash
	);

	// 'hash' is (num_init_hashes + 1 + hash_len) long

	memcpy (
		hash,
		x.init_hash,
		num_init_hashes
	);

	memcpy (
		hash + num_init_hashes,
		&expected_hash,
		1
	);

	memcpy (
		hash + num_init_hashes + 1,
		ciphertext,
		hash_len
	);
}

void freestyle_hash_password_with_pepper (
	const	char*		const password,
	const	u8*		const salt,
		u8*		const hash,
	const	size_t		hash_len,
	const	u8		min_rounds,
	const	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8		pepper_bits,
	const	u8		num_init_hashes,
	const	u32		pepper)
{
	int i,j;

	freestyle_ctx x;

	/* salt is 'hash_len' bytes long */
	const	u8*	const	plaintext	= salt;
		u8*		ciphertext	= NULL;

	u8 key_and_iv [44];

	u8 expected_hash;

	int password_len = strlen (password);

	assert (password_len	>=  1);
	assert (password_len	<= 43);
	assert (hash_len	<= 64);

	if (! (ciphertext = malloc(hash_len)))
	{
		perror("malloc failed ");
		exit(-1);
	}

	/* Fill the key (32 bytes)
		and IV (first 11 bytes) with password */
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

	freestyle_init_encrypt_with_pepper (
		&x,
		key,
		256,
		iv,
		min_rounds,
		max_rounds,
		num_precomputed_rounds,
		pepper_bits,
		num_init_hashes,
		pepper
	);

	freestyle_encrypt (
		&x,
		plaintext,
		ciphertext,
		hash_len,
		&expected_hash
	);

	// 'hash' is (num_init_hashes + 1 + hash_len) long

	memcpy (
		hash,
		x.init_hash,
		num_init_hashes
	);

	memcpy (
		hash + num_init_hashes,
		&expected_hash,
		1
	);

	memcpy (
		hash + num_init_hashes + 1,
		ciphertext,
		hash_len
	);
}

static u8 safe_bcmp (const u8* const a, const u8* const b, const size_t length)
{
	u8 diff = 0;

	for (size_t i = 0; i < length; ++i)
		diff |= (a[i] ^ b[i]);

	return diff;
}

bool freestyle_verify_password_hash (
	const	char*		const password,
	const	u8*		const salt,
	const	u8*		const hash,
	const	size_t		hash_len,
	const	u8		min_rounds,
	const	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8		pepper_bits,
	const	u8		num_init_hashes)
{
	int i,j;

	freestyle_ctx x;

	const	u8*	const	ciphertext	= hash + num_init_hashes + 1;
		u8*		plaintext	= NULL;

	u8 key_and_iv [44];

	u8 expected_hash = hash [num_init_hashes];

	int password_len = strlen (password);

	assert (password_len	>=  1);
	assert (password_len	<= 43);
	assert (hash_len	<= 64);

	if (! (plaintext = malloc(hash_len)))
	{
		perror("malloc failed ");
		exit(-1);
	}

	/* Fill the key (32 bytes)
		and IV (first 11 bytes) with password */
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

	freestyle_decrypt (
		&x,
		ciphertext,
		plaintext,
		hash_len,
		&expected_hash
	);

	return (0 == safe_bcmp(plaintext,salt,hash_len));
}
