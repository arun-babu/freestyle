/*
 * Copyright (c) 2017  P. Arun Babu and Jithin Jose Thomas 
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
Some code is taken from D. J. Bernstein's
chacha-merged.c version 20080118
Public domain.
*/

#include "freestyle.h"

void freestyle_init_common (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32		key_length_bits,
	const 	u8 		*iv,
	const 	u16 		min_rounds,
	const	u16		max_rounds,
	const	u16 		hash_interval,
	const	u8 		pepper_bits)
{	
	assert (min_rounds >= 1);
	assert (max_rounds <= 512);

	assert (min_rounds <= max_rounds);

	assert (min_rounds % hash_interval == 0);
	assert (max_rounds % hash_interval == 0);

	assert ((max_rounds - min_rounds)/hash_interval < 512);

	assert (pepper_bits >= 8);
	assert (pepper_bits <= 32);

	freestyle_keysetup 		(x, key, key_length_bits);
	freestyle_ivsetup 		(x, iv, 0);
	freestyle_hashsetup 		(x, hash_interval);
	freestyle_roundsetup 		(x, min_rounds, max_rounds, pepper_bits);
}

void freestyle_init_encrypt (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32		key_length_bits,
	const 	u8 		*iv,
	const 	u16 		min_rounds,
	const	u16		max_rounds,
	const	u16 		hash_interval,
	const	u8 		pepper_bits)
{	
	freestyle_init_common (x, key, key_length_bits, iv, min_rounds, max_rounds, hash_interval, pepper_bits);

	x->pepper		= 0;
	x->is_pepper_set 	= false;
	
	freestyle_randomsetup_encrypt(x);
}

void freestyle_init_encrypt_with_pepper (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32		key_length_bits,
	const 	u8 		*iv,
	const 	u16 		min_rounds,
	const	u16		max_rounds,
	const	u16 		hash_interval,
	const	u8 		pepper_bits,
	const	u32 		pepper)
{	
	freestyle_init_common (x, key, key_length_bits, iv, min_rounds, max_rounds, hash_interval, pepper_bits);

	x->pepper 		= pepper;
	x->is_pepper_set 	= true;

	freestyle_randomsetup_encrypt(x);
}

void freestyle_init_decrypt (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32		key_length_bits,
	const 	u8 		*iv,
	const 	u16 		min_rounds,
	const	u16		max_rounds,
	const	u16 		hash_interval,
	const	u8 		pepper_bits,
	const	u16 		*init_hash)
{	
	freestyle_init_common (x, key, key_length_bits, iv, min_rounds, max_rounds, hash_interval, pepper_bits);

	x->pepper		= 0;
	x->is_pepper_set 	= false;

	memcpy ( x->init_hash,
		 init_hash,
		 NUM_INIT_HASHES * sizeof(u16)
	);

	freestyle_randomsetup_decrypt(x);
}

void freestyle_init_decrypt_with_pepper (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32		key_length_bits,
	const 	u8 		*iv,
	const 	u16 		min_rounds,
	const	u16		max_rounds,
	const	u16 		hash_interval,
	const	u8 		pepper_bits,
	const	u32 		pepper,
	const	u16 		*init_hash)
{	
	freestyle_init_common (x, key, key_length_bits, iv, min_rounds, max_rounds, hash_interval, pepper_bits);

	x->pepper 		= pepper;
	x->is_pepper_set 	= true;
	
	memcpy ( x->init_hash,
		 init_hash,
		 NUM_INIT_HASHES * sizeof(u16)
	);

	freestyle_randomsetup_decrypt(x);
}
	
void freestyle_randomsetup_encrypt (freestyle_ctx *x)
{
	u32 	i, p;

	u32 	R [NUM_INIT_HASHES]; /* actual random rounds */
	u32 	CR[NUM_INIT_HASHES]; /* collided random rounds */

	u32	temp1;
	u32	temp2;

	u16 saved_min_rounds		= x->min_rounds;
	u16 saved_max_rounds		= x->max_rounds;
	u16 saved_hash_interval   	= x->hash_interval;

	if (! x->is_pepper_set)
	{
		x->pepper = arc4random_uniform (
			x->pepper_bits == 32 ?  -1 : (1 << x->pepper_bits)
		);
	}

	x->min_rounds 		= 12;
	x->max_rounds 		= 36;
	x->hash_interval 	= 1;

	/* add a random number (pepper) to constant[3] */
	x->input_03 = PLUS(x->input_03,x->pepper); 

	for (x->input_12 = 0; x->input_12 < NUM_INIT_HASHES; ++(x->input_12))
	{
		R[x->input_12] = freestyle_encrypt_block (
			x,
			NULL,
			NULL,
			0,
			&x->init_hash [x->input_12]
		);
	}

	if (! x->is_pepper_set)
	{
		/* set it back to its previous value */
		x->input_03 = MINUS(x->input_03,x->pepper); 

		/* check for any collisions between 0 and pepper */
		for (p = 0; p < x->pepper; ++p)
		{
			for (x->input_12 = 0; x->input_12 < NUM_INIT_HASHES; ++(x->input_12))
			{
				CR[x->input_12] = freestyle_decrypt_block (
					x,
					NULL,
					NULL,
					0,
					&x->init_hash [x->input_12]
				);

				if (CR[x->input_12] == 0) {
					goto continue_loop_encrypt;	
				}
			}

			/* found a collision. use the collided rounds */ 
			memcpy(R, CR, NUM_INIT_HASHES*sizeof(u32));
			break;

	continue_loop_encrypt:
			x->input_03 = PLUSONE(x->input_03);
		}
	}

	for (i = 0; i < 4; ++i)
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
	x->min_rounds 		= saved_min_rounds;
	x->max_rounds 		= saved_max_rounds;
	x->hash_interval 	= saved_hash_interval; 

	/* modify constant[0], constant[1], constant[2] */
	x->input_00 ^= x->rand[0]; 
	x->input_01 ^= x->rand[1]; 
	x->input_02 ^= x->rand[2]; 

	/* set counter back to 0 */
	x->input_12 = 0;
}

void freestyle_randomsetup_decrypt (freestyle_ctx *x)
{
	u32 	i;
	u32 	R [NUM_INIT_HASHES]; /* random rounds */

	u32	temp1;
	u32	temp2;

	u16 saved_min_rounds		= x->min_rounds;
	u16 saved_max_rounds		= x->max_rounds;
	u16 saved_hash_interval   	= x->hash_interval;

	u32 pepper;
	u32 max_pepper = (u32)(((u64)1 << x->pepper_bits) - 1); 

	x->min_rounds 		= 12;
	x->max_rounds 		= 36;
	x->hash_interval 	= 1;

	x->input_03 = PLUS(x->input_03, x->pepper);

	for (pepper = 0; pepper <= max_pepper; ++pepper)
	{
		for (x->input_12 = 0; x->input_12 < NUM_INIT_HASHES; ++(x->input_12))
		{
			R[x->input_12] = freestyle_decrypt_block (
				x,
				NULL,
				NULL,
				0,
				&x->init_hash [x->input_12]
			);

			if (R[x->input_12] == 0) {
				goto continue_loop_decrypt;
			}

		}

		/* found all valid R[i]s */
		break;

continue_loop_decrypt:
		x->input_03 = PLUSONE(x->input_03);
	}

	for (i = 0; i < 4; ++i)
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
	x->min_rounds 		= saved_min_rounds;
	x->max_rounds 		= saved_max_rounds;
	x->hash_interval 	= saved_hash_interval; 

	/* modify constant[0], constant[1], constant[2] */
	x->input_00 ^= x->rand[0]; 
	x->input_01 ^= x->rand[1]; 
	x->input_02 ^= x->rand[2]; 

	/* set counter back to 0 */
	x->input_12 = 0;
}

void freestyle_hashsetup (
	freestyle_ctx 	*x,
	u16 		hash_interval)
{
	x->hash_interval = hash_interval;
}

void freestyle_keysetup (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32 		key_length_bits)
{
	const char *constants;

	x->input_04 = U8TO32_LITTLE(key +  0);
	x->input_05 = U8TO32_LITTLE(key +  4);
	x->input_06 = U8TO32_LITTLE(key +  8);
	x->input_07 = U8TO32_LITTLE(key + 12);

	if (key_length_bits == 256) /* recommended */
	{ 
		key += 16;
		constants = sigma;
	}
	else {
		constants = tau;
	}

	x->input_08 = U8TO32_LITTLE(key +  0);
	x->input_09 = U8TO32_LITTLE(key +  4);
	x->input_10 = U8TO32_LITTLE(key +  8);
	x->input_11 = U8TO32_LITTLE(key + 12);

	x->input_00 = U8TO32_LITTLE(constants +  0);
	x->input_01 = U8TO32_LITTLE(constants +  4);
	x->input_02 = U8TO32_LITTLE(constants +  8);
	x->input_03 = U8TO32_LITTLE(constants + 12);
}

void freestyle_ivsetup (
		freestyle_ctx 	*x,
	const 	u8 		*iv,
	const	u32 		counter)
{
	x->input_12 = counter;

	x->input_13 = U8TO32_LITTLE(iv + 0);
	x->input_14 = U8TO32_LITTLE(iv + 4);
	x->input_15 = U8TO32_LITTLE(iv + 8);
}

void freestyle_roundsetup (
		freestyle_ctx 	*x,
	const 	u16 		min_rounds,
	const 	u16 		max_rounds,
	const	u8 		pepper_bits)
{
	x->min_rounds 		= min_rounds;
	x->max_rounds 		= max_rounds;
	x->pepper_bits 		= pepper_bits;

	x->min_rounds_by_2 	= x->min_rounds/2;
	x->min_rounds_is_odd 	= (x->min_rounds & 1) == 1;


	x->cipher_parameter = 	  ((x->min_rounds    & 0x1FF) << 23) // 9 bits 
				| ((x->max_rounds    & 0x1FF) << 14) // 9 bits
				| ((x->hash_interval & 0x1FF) <<  5) // 9 bits
				| (x->pepper_bits    & 0x01F);       // 5 bits

	x->rand[0] = 0; 
	x->rand[1] = 0; 
	x->rand[2] = 0; 
	x->rand[3] = 0; 

	/* modify constant[3] */
	x->input_03 ^= x->cipher_parameter;

	/* the number of ways a block of message can be encrypted */
	x->num_rounds_possible = 1 + (x->max_rounds - x->min_rounds)/x->hash_interval;
}

int freestyle_encrypt (
		freestyle_ctx 	*x,
	const 	u8 		*full_plaintext,
		u8 		*full_ciphertext,
		u32 		bytes,
		u16 		*expected_hash)
{
	u32 	i	= 0;
	u32 	block 	= 0;

	u8	*plaintext, *ciphertext;

	u8 	bytes_to_process;

	u16 	hash, rounds;

	u16 	j, r = 0;

	u32 	temp1, temp2;

	u8	output8[64];

	u32 	output32_00,
		output32_01,
		output32_02,
		output32_03,
		output32_04,
		output32_05,
		output32_06,
		output32_07,
		output32_08,
		output32_09,
		output32_10,
		output32_11,
		output32_12,
		output32_13,
		output32_14,
		output32_15;

	u64 hash_collided [128];

	while (bytes > 0)
	{
		hash = 0;
		bytes_to_process = bytes >= 64 ? 64 : bytes;
		
		RESET_HASH_COLLIDED();
	
		plaintext  = (u8*)(full_plaintext  + i);
		ciphertext = (u8*)(full_ciphertext + i);

		output32_00 = x->input_00;
		output32_01 = x->input_01;
		output32_02 = x->input_02;
		output32_03 = x->input_03;
		output32_04 = x->input_04;
		output32_05 = x->input_05;
		output32_06 = x->input_06;
		output32_07 = x->input_07;
		output32_08 = x->input_08;
		output32_09 = x->input_09;
		output32_10 = x->input_10;
		output32_11 = x->input_11;
		output32_12 = x->input_12 ^ x->rand[3];
		output32_13 = x->input_13;
		output32_14 = x->input_14;
		output32_15 = x->input_15;

		/* Generate a random no. of round */ 
		rounds = x->min_rounds + arc4random_uniform (x->max_rounds - x->min_rounds + x->hash_interval);

		/* make it a multiple of hash_interval */
		rounds = x->hash_interval * (u16)(rounds/x->hash_interval);

		assert (rounds >= x->min_rounds);
		assert (rounds <= x->max_rounds);

		for (r = 1; r <= x->min_rounds_by_2; ++r) {
			FREESTYLE_DOUBLE_ROUND();
		}

		if (x->min_rounds_is_odd) {
			FREESTYLE_COLUMN_ROUND();
		}

		COMPUTE_HASH(x,hash,x->min_rounds);

		hash_collided [hash >> 9] |= ((u64)1 << (hash & 0x3F));

		for (r = x->min_rounds + 1; r <= rounds; ++r)
		{
			if (r & 1)
				FREESTYLE_COLUMN_ROUND();
			else
				FREESTYLE_DIAGONAL_ROUND();

			if (r % x->hash_interval == 0)
			{
				COMPUTE_HASH(x,hash,r);

				while ((hash_collided [hash >> 9] & ((u64)1 << (hash & 0x3F))) > 0) {
					++hash;
				}

				hash_collided [hash >> 9] |= ((u64)1 << (hash & 0x3F));
			}
		}

		assert (r <= x->max_rounds + 1);

	    	expected_hash[block] = hash; 

		output32_00 = PLUS(output32_00, x->input_00);
		output32_01 = PLUS(output32_01, x->input_01);
		output32_02 = PLUS(output32_02, x->input_02);
		output32_03 = PLUS(output32_03, x->input_03);
		output32_04 = PLUS(output32_04, x->input_04);
		output32_05 = PLUS(output32_05, x->input_05);
		output32_06 = PLUS(output32_06, x->input_06);
		output32_07 = PLUS(output32_07, x->input_07);
		output32_08 = PLUS(output32_08, x->input_08);
		output32_09 = PLUS(output32_09, x->input_09);
		output32_10 = PLUS(output32_10, x->input_10);
		output32_11 = PLUS(output32_11, x->input_11);
		output32_12 = PLUS(output32_12, x->input_12);
		output32_13 = PLUS(output32_13, x->input_13);
		output32_14 = PLUS(output32_14, x->input_14);
		output32_15 = PLUS(output32_15, x->input_15);

	    	U32TO8_LITTLE (output8 + 4 * 0,  output32_00);
	   	U32TO8_LITTLE (output8 + 4 * 1,  output32_01);
	    	U32TO8_LITTLE (output8 + 4 * 2,  output32_02);
	    	U32TO8_LITTLE (output8 + 4 * 3,  output32_03);
	    	U32TO8_LITTLE (output8 + 4 * 4,  output32_04);
	    	U32TO8_LITTLE (output8 + 4 * 5,  output32_05);
	    	U32TO8_LITTLE (output8 + 4 * 6,  output32_06);
	    	U32TO8_LITTLE (output8 + 4 * 7,  output32_07);
	    	U32TO8_LITTLE (output8 + 4 * 8,  output32_08);
	    	U32TO8_LITTLE (output8 + 4 * 9,  output32_09);
	    	U32TO8_LITTLE (output8 + 4 * 10, output32_10);
	    	U32TO8_LITTLE (output8 + 4 * 11, output32_11);
	    	U32TO8_LITTLE (output8 + 4 * 12, output32_12);
	    	U32TO8_LITTLE (output8 + 4 * 13, output32_13);
	    	U32TO8_LITTLE (output8 + 4 * 14, output32_14);
	    	U32TO8_LITTLE (output8 + 4 * 15, output32_15);
                                         
		if (bytes_to_process == 64)                 
			FREESTYLE_XOR_64(plaintext,ciphertext,output8);
		else
		{
			for (j = 0; j < bytes; ++j) {
				ciphertext [j] = XOR (plaintext[j], output8[j]);
			}
		}

		i     += bytes_to_process;
		bytes -= bytes_to_process;
	
        	++block;

		x->input_12 = PLUSONE (x->input_12);
	}

	return 0;
}

int freestyle_decrypt (
		freestyle_ctx 	*x,
	const 	u8 		*full_ciphertext,
		u8 		*full_plaintext,
		u32 		bytes,
		u16 		*expected_hash)
{
	u32 	i	= 0;
	u32 	block 	= 0;

	u8	*plaintext, *ciphertext;

	u8 	bytes_to_process;

	u16 	hash;

	u16 	j, r;

	u32 	temp1, temp2;

	u8	output8[64];

	u32 	output32_00,
		output32_01,
		output32_02,
		output32_03,
		output32_04,
		output32_05,
		output32_06,
		output32_07,
		output32_08,
		output32_09,
		output32_10,
		output32_11,
		output32_12,
		output32_13,
		output32_14,
		output32_15;

	u64 hash_collided [128];

	while (bytes > 0)
	{
		hash = 0;
		bytes_to_process = bytes >= 64 ? 64 : bytes;

		RESET_HASH_COLLIDED();

		plaintext  = (u8*)(full_plaintext  + i);
		ciphertext = (u8*)(full_ciphertext + i);

		output32_00 = x->input_00;
		output32_01 = x->input_01;
		output32_02 = x->input_02;
		output32_03 = x->input_03;
		output32_04 = x->input_04;
		output32_05 = x->input_05;
		output32_06 = x->input_06;
		output32_07 = x->input_07;
		output32_08 = x->input_08;
		output32_09 = x->input_09;
		output32_10 = x->input_10;
		output32_11 = x->input_11;
		output32_12 = x->input_12 ^ x->rand[3];
		output32_13 = x->input_13;
		output32_14 = x->input_14;
		output32_15 = x->input_15;

		for (r = 1; r <= x->min_rounds_by_2; ++r) {
			FREESTYLE_DOUBLE_ROUND();
		}

		if (x->min_rounds_is_odd) {
			FREESTYLE_COLUMN_ROUND();
		}

		COMPUTE_HASH(x,hash,x->min_rounds);

		if (hash == expected_hash[block])
			goto decryption;

		hash_collided [hash >> 9] |= ((u64)1 << (hash & 0x3F));

		for (r = x->min_rounds + 1; r <= x->max_rounds; ++r)
		{
			if (r & 1)
				FREESTYLE_COLUMN_ROUND();
			else
				FREESTYLE_DIAGONAL_ROUND();

			if (r % x->hash_interval == 0)
			{
				COMPUTE_HASH(x,hash,r);

				while ((hash_collided [hash >> 9] & ((u64)1 << (hash & 0x3F))) > 0) {
					++hash;
				}

				hash_collided [hash >> 9] |= ((u64)1 << (hash & 0x3F));

				if (hash == expected_hash[block]) {
					break;
				}
			}
		}

decryption:
		output32_00 = PLUS(output32_00, x->input_00);
		output32_01 = PLUS(output32_01, x->input_01);
		output32_02 = PLUS(output32_02, x->input_02);
		output32_03 = PLUS(output32_03, x->input_03);
		output32_04 = PLUS(output32_04, x->input_04);
		output32_05 = PLUS(output32_05, x->input_05);
		output32_06 = PLUS(output32_06, x->input_06);
		output32_07 = PLUS(output32_07, x->input_07);
		output32_08 = PLUS(output32_08, x->input_08);
		output32_09 = PLUS(output32_09, x->input_09);
		output32_10 = PLUS(output32_10, x->input_10);
		output32_11 = PLUS(output32_11, x->input_11);
		output32_12 = PLUS(output32_12, x->input_12);
		output32_13 = PLUS(output32_13, x->input_13);
		output32_14 = PLUS(output32_14, x->input_14);
		output32_15 = PLUS(output32_15, x->input_15);

	    	U32TO8_LITTLE (output8 + 4 * 0,  output32_00);
	   	U32TO8_LITTLE (output8 + 4 * 1,  output32_01);
	    	U32TO8_LITTLE (output8 + 4 * 2,  output32_02);
	    	U32TO8_LITTLE (output8 + 4 * 3,  output32_03);
	    	U32TO8_LITTLE (output8 + 4 * 4,  output32_04);
	    	U32TO8_LITTLE (output8 + 4 * 5,  output32_05);
	    	U32TO8_LITTLE (output8 + 4 * 6,  output32_06);
	    	U32TO8_LITTLE (output8 + 4 * 7,  output32_07);
	    	U32TO8_LITTLE (output8 + 4 * 8,  output32_08);
	    	U32TO8_LITTLE (output8 + 4 * 9,  output32_09);
	    	U32TO8_LITTLE (output8 + 4 * 10, output32_10);
	    	U32TO8_LITTLE (output8 + 4 * 11, output32_11);
	    	U32TO8_LITTLE (output8 + 4 * 12, output32_12);
	    	U32TO8_LITTLE (output8 + 4 * 13, output32_13);
	    	U32TO8_LITTLE (output8 + 4 * 14, output32_14);
	    	U32TO8_LITTLE (output8 + 4 * 15, output32_15);

		if (bytes_to_process == 64)                 
			FREESTYLE_XOR_64(ciphertext,plaintext,output8);
		else
		{
			for (j = 0; j < bytes; ++j) {
				plaintext [j] = XOR (ciphertext[j], output8[j]);
			}
		}

	    i 	  += bytes_to_process;
	    bytes -= bytes_to_process;
	
            ++block;

	    x->input_12 = PLUSONE (x->input_12);
	}

	return 0;
}

u16 freestyle_encrypt_block (
		freestyle_ctx	*x,	
	const 	u8 		*plaintext,
		u8 		*ciphertext,
		u8 		bytes,
		u16 		*expected_hash)
{
	u16 	i, r;

	u16 	hash = 0;

	u32 	temp1, temp2;


	bool init = (plaintext == NULL) || (ciphertext == NULL) || (bytes == 0);

	u16 rounds = x->min_rounds + arc4random_uniform (x->max_rounds - x->min_rounds + x->hash_interval);

	rounds = x->hash_interval * (u16)(rounds/x->hash_interval);

	u8 output8 [64];

	u64 hash_collided [128] = {0};

	u32 	output32_00 = x->input_00,
		output32_01 = x->input_01,
		output32_02 = x->input_02,
		output32_03 = x->input_03,
		output32_04 = x->input_04,
		output32_05 = x->input_05,
		output32_06 = x->input_06,
		output32_07 = x->input_07,
		output32_08 = x->input_08,
		output32_09 = x->input_09,
		output32_10 = x->input_10,
		output32_11 = x->input_11,
		output32_12 = x->input_12 ^ x->rand[3],
		output32_13 = x->input_13,
		output32_14 = x->input_14,
		output32_15 = x->input_15;

	for (r = 1; r <= rounds; ++r)
	{
		if (r & 1)
			FREESTYLE_COLUMN_ROUND();
		else
			FREESTYLE_DIAGONAL_ROUND();

		if (r >= x->min_rounds && r % x->hash_interval == 0)
		{
			COMPUTE_HASH(x,hash,r);

			while ((hash_collided [hash >> 9] & ((u64)1 << (hash & 0x3F))) > 0) {
				++hash;
			}

			hash_collided [hash >> 9] |= ((u64)1 << (hash & 0x3F));
		}
	}

	*expected_hash = hash;

	if (! init)
	{
	     	U32TO8_LITTLE (output8 + 4 * 0,  PLUS(output32_00, x->input_00));
	     	U32TO8_LITTLE (output8 + 4 * 1,  PLUS(output32_01, x->input_01));
	     	U32TO8_LITTLE (output8 + 4 * 2,  PLUS(output32_02, x->input_02));
	     	U32TO8_LITTLE (output8 + 4 * 3,  PLUS(output32_03, x->input_03));
	     	U32TO8_LITTLE (output8 + 4 * 4,  PLUS(output32_04, x->input_04));
	     	U32TO8_LITTLE (output8 + 4 * 5,  PLUS(output32_05, x->input_05));
	     	U32TO8_LITTLE (output8 + 4 * 6,  PLUS(output32_06, x->input_06));
	     	U32TO8_LITTLE (output8 + 4 * 7,  PLUS(output32_07, x->input_07));
	     	U32TO8_LITTLE (output8 + 4 * 8,  PLUS(output32_08, x->input_08));
	     	U32TO8_LITTLE (output8 + 4 * 9,  PLUS(output32_09, x->input_09));
	     	U32TO8_LITTLE (output8 + 4 * 10, PLUS(output32_10, x->input_10));
	     	U32TO8_LITTLE (output8 + 4 * 11, PLUS(output32_11, x->input_11));
	     	U32TO8_LITTLE (output8 + 4 * 12, PLUS(output32_12, x->input_12));
	     	U32TO8_LITTLE (output8 + 4 * 13, PLUS(output32_13, x->input_13));
	     	U32TO8_LITTLE (output8 + 4 * 14, PLUS(output32_14, x->input_14));
	     	U32TO8_LITTLE (output8 + 4 * 15, PLUS(output32_15, x->input_15));
                                                 
		if (bytes == 64)                 
		{                                
			FREESTYLE_XOR_64(plaintext,ciphertext,output8);
		}
		else
		{
			for (i = 0; i < bytes; ++i) {
				ciphertext [i] = XOR (plaintext[i], output8[i]);
			}
		}
        }

	return rounds;
}

u16 freestyle_decrypt_block (
		freestyle_ctx	*x,	
		u8 		*plaintext,
	const	u8 		*ciphertext,
		u8 		bytes,
		u16 		*expected_hash)
{
	u16 	i, r;

	u16 	hash = 0;

	u32 	temp1, temp2;

	bool init = (plaintext == NULL) || (ciphertext == NULL) || (bytes == 0);

	u64 hash_collided [128] = {0};

	u8 output8 [64];

	u32 	output32_00 = x->input_00,
		output32_01 = x->input_01,
		output32_02 = x->input_02,
		output32_03 = x->input_03,
		output32_04 = x->input_04,
		output32_05 = x->input_05,
		output32_06 = x->input_06,
		output32_07 = x->input_07,
		output32_08 = x->input_08,
		output32_09 = x->input_09,
		output32_10 = x->input_10,
		output32_11 = x->input_11,
		output32_12 = x->input_12 ^ x->rand[3],
		output32_13 = x->input_13,
		output32_14 = x->input_14,
		output32_15 = x->input_15;

	for (r = 1; r <= x->max_rounds; ++r)
	{
		if (r & 1)
			FREESTYLE_COLUMN_ROUND();
		else
			FREESTYLE_DIAGONAL_ROUND();

		if (r >= x->min_rounds && r % x->hash_interval == 0)
		{
			COMPUTE_HASH(x,hash,r);

			while ((hash_collided [hash >> 9] & ((u64)1 << (hash & 0x3F))) > 0) {
				++hash;
			}

			hash_collided [hash >> 9 ] |= ((u64)1 << (hash & 0x3F));

			if (hash == *expected_hash) {
				break;
			}
		}
	}

	if (r > x->max_rounds)
		return 0;

	if (! init)
	{
	     	U32TO8_LITTLE (output8 + 4 * 0,  PLUS(output32_00, x->input_00));
	     	U32TO8_LITTLE (output8 + 4 * 1,  PLUS(output32_01, x->input_01));
	     	U32TO8_LITTLE (output8 + 4 * 2,  PLUS(output32_02, x->input_02));
	     	U32TO8_LITTLE (output8 + 4 * 3,  PLUS(output32_03, x->input_03));
	     	U32TO8_LITTLE (output8 + 4 * 4,  PLUS(output32_04, x->input_04));
	     	U32TO8_LITTLE (output8 + 4 * 5,  PLUS(output32_05, x->input_05));
	     	U32TO8_LITTLE (output8 + 4 * 6,  PLUS(output32_06, x->input_06));
	     	U32TO8_LITTLE (output8 + 4 * 7,  PLUS(output32_07, x->input_07));
	     	U32TO8_LITTLE (output8 + 4 * 8,  PLUS(output32_08, x->input_08));
	     	U32TO8_LITTLE (output8 + 4 * 9,  PLUS(output32_09, x->input_09));
	     	U32TO8_LITTLE (output8 + 4 * 10, PLUS(output32_10, x->input_10));
	     	U32TO8_LITTLE (output8 + 4 * 11, PLUS(output32_11, x->input_11));
	     	U32TO8_LITTLE (output8 + 4 * 12, PLUS(output32_12, x->input_12));
	     	U32TO8_LITTLE (output8 + 4 * 13, PLUS(output32_13, x->input_13));
	     	U32TO8_LITTLE (output8 + 4 * 14, PLUS(output32_14, x->input_14));
	     	U32TO8_LITTLE (output8 + 4 * 15, PLUS(output32_15, x->input_15));
         
		if (bytes == 64)
			FREESTYLE_XOR_64(ciphertext,plaintext,output8);
		else
		{
			for (i = 0; i < bytes; ++i) {
				plaintext[i] = XOR (ciphertext[i], output8[i]);
			}
		}
        }

	return r;
}
