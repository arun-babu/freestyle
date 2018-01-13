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

void freestyle_init_encrypt (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32		key_length_bits,
	const 	u8 		*iv,
	const 	u16 		min_rounds,
	const	u16		max_rounds,
	const	u8 		hash_complexity,
	const	u16 		hash_interval,
	const	u8 		init_complexity)
{	
	assert (min_rounds <= max_rounds);

	assert (min_rounds >= 1);
	assert (max_rounds <= 256 * hash_interval);

	assert (min_rounds % hash_interval == 0);
	assert (max_rounds % hash_interval == 0);

	assert (hash_complexity >= 1);
	assert (hash_complexity <= 3);

	assert (init_complexity >= 8);
	assert (init_complexity <= 32);

	freestyle_keysetup 		(x, key, key_length_bits);
	freestyle_ivsetup 		(x, iv,  NULL);
	freestyle_hashsetup 		(x, hash_complexity, hash_interval);
	freestyle_roundsetup 		(x, min_rounds, max_rounds, init_complexity);
	freestyle_randomsetup_encrypt 	(x);
}

void freestyle_init_decrypt (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32		key_length_bits,
	const 	u8 		*iv,
	const 	u16 		min_rounds,
	const	u16		max_rounds,
	const	u8 		hash_complexity,
	const	u16 		hash_interval,
	const	u8 		init_complexity,
	const	u16 		*init_stop_condition)
{	
	assert (min_rounds <= max_rounds);

	assert (min_rounds >= 1);
	assert (max_rounds <= 256 * hash_interval);

	assert (min_rounds % hash_interval == 0);
	assert (max_rounds % hash_interval == 0);

	assert (hash_complexity >= 1);
	assert (hash_complexity <= 3);

	assert (init_complexity >= 8);
	assert (init_complexity <= 32);

	freestyle_keysetup 		(x, key, key_length_bits);
	freestyle_ivsetup 		(x, iv,  NULL);
	freestyle_hashsetup 		(x, hash_complexity, hash_interval);
	freestyle_roundsetup 		(x, min_rounds, max_rounds, init_complexity);

	memcpy ( x->init_stop_condition,
		 init_stop_condition,
		 NUM_INIT_HASHES * sizeof(u16)
	);

	freestyle_randomsetup_decrypt 	(x);
}
	
void freestyle_randomsetup_encrypt (freestyle_ctx *x)
{
	u32 	i, t;

	u8 	index;

	u32 	R [NUM_INIT_HASHES]; /* actual random rounds */
	u32 	CR[NUM_INIT_HASHES]; /* collided random rounds */

	u32	temp1;
	u32	temp2;

	u16 saved_min_rounds		= x->min_rounds;
	u16 saved_max_rounds		= x->max_rounds;
	u16 saved_hash_interval   	= x->hash_interval;
	u8  saved_hash_complexity 	= x->hash_complexity;

	x->min_rounds 		= 12;
	x->max_rounds 		= 36;
	x->hash_interval 	= 1;
	x->hash_complexity 	= 3;

	x->random_word[0] = 0;
	x->random_word[1] = 0;
	x->random_word[2] = 0;
	x->random_word[3] = 0;

	u32 target = arc4random_uniform (
		x->init_complexity == 32 ?  -1 : (1 << x->init_complexity)
	);

#ifdef FREESTYLE_RANDOMIZE_ARRAY_INDICES
	u8	random_mask   = arc4random_uniform (32); 
#else
	u8 	random_mask = 0;
#endif

	/* add a random number (target) to key[0] */
	x->input[KEY0] = PLUS(x->input[KEY0],target); 

	for (i = 0; i < NUM_INIT_HASHES; ++i)
	{
		index = i ^ random_mask; 

		x->input[COUNTER] = index;

		R[index] = freestyle_encrypt_block (
			x,
			NULL,
			NULL,
			0,
			&x->init_stop_condition[index]
		);
	}

	/* set it back to its previous value */
	x->input[KEY0] = MINUS(x->input[KEY0],target); 

	/* check for any collisions between 0 and target */
	for (t = 0; t < target; ++t)
	{
		for (i = 0; i < NUM_INIT_HASHES; ++i)
		{
			index = i ^ random_mask;

			x->input[COUNTER] = index;

			CR[index] = freestyle_decrypt_block (
				x,
				NULL,
				NULL,
				0,
				&x->init_stop_condition[index]
			);

			if (CR[index] == 0) {
				goto continue_loop_encrypt;	
			}
		}

		/* found a collision. use the collided rounds */ 
		memcpy(R, CR, NUM_INIT_HASHES*sizeof(u32));
		break;

continue_loop_encrypt:
		x->input[KEY0] = PLUSONE(x->input[KEY0]);
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
		AXR (temp2, R[7*i + 7], temp1,  7);

		x->random_word[i] = temp1; 
	}

	/* set user parameters back */
	x->min_rounds 		= saved_min_rounds;
	x->max_rounds 		= saved_max_rounds;
	x->hash_interval 	= saved_hash_interval; 
	x->hash_complexity 	= saved_hash_complexity;

	/* modify constant[0], constant[1], constant[2] */
	x->input[CONSTANT0] ^= x->random_word[0]; 
	x->input[CONSTANT1] ^= x->random_word[1]; 
	x->input[CONSTANT2] ^= x->random_word[2]; 

	/* set counter back to 0 */
	x->input[COUNTER] = 0;
}

void freestyle_randomsetup_decrypt (freestyle_ctx *x)
{
	u32 	i, t;
	u32 	R [NUM_INIT_HASHES]; /* random rounds */

	u8 	index;

	u32	temp1;
	u32	temp2;

	u16 saved_min_rounds		= x->min_rounds;
	u16 saved_max_rounds		= x->max_rounds;
	u16 saved_hash_interval   	= x->hash_interval;
	u8  saved_hash_complexity 	= x->hash_complexity;

	x->min_rounds 		= 12;
	x->max_rounds 		= 36;
	x->hash_interval 	= 1;
	x->hash_complexity 	= 3;

	x->random_word[0] = 0;
	x->random_word[1] = 0;
	x->random_word[2] = 0;
	x->random_word[3] = 0;

	u32 target = (u32)(((u64)1 << x->init_complexity) - 1); 

#ifdef FREESTYLE_RANDOMIZE_ARRAY_INDICES
	u8	random_mask   = arc4random_uniform (32); 
#else
	u8 	random_mask = 0;
#endif
	for (t = 0; t <= target; ++t)
	{
		for (i = 0; i < NUM_INIT_HASHES; ++i)
		{
			index = i ^ random_mask;

			x->input[COUNTER] = index;
			
			R[index] = freestyle_decrypt_block (
				x,
				NULL,
				NULL,
				0,
				&x->init_stop_condition[index]
			);

			if (R[index] == 0) {
				goto continue_loop_decrypt;
			}

		}

		/* found all valid R[i]s */
		break;

continue_loop_decrypt:
		x->input[KEY0] = PLUSONE(x->input[KEY0]);
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
		AXR (temp2, R[7*i + 7], temp1,  7);

		x->random_word[i] = temp1; 
	}

	/* set user parameters back */
	x->min_rounds 		= saved_min_rounds;
	x->max_rounds 		= saved_max_rounds;
	x->hash_interval 	= saved_hash_interval; 
	x->hash_complexity 	= saved_hash_complexity;

	/* modify constant[0], constant[1], constant[2] */
	x->input[CONSTANT0] ^= x->random_word[0]; 
	x->input[CONSTANT1] ^= x->random_word[1]; 
	x->input[CONSTANT2] ^= x->random_word[2]; 

	/* set counter back to 0 */
	x->input[COUNTER] = 0;
}

void freestyle_hashsetup (
	freestyle_ctx 	*x,
	u8 		hash_complexity,
	u16 		hash_interval)
{
	x->hash_complexity 		= hash_complexity;
	x->num_output_elements_to_hash 	= 4 * (x->hash_complexity + 1);
	x->hash_interval 		= hash_interval;
}

void freestyle_keysetup (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32 		key_length_bits)
{
	const char *constants;

	x->input[KEY0] = U8TO32_LITTLE(key +  0);
	x->input[KEY1] = U8TO32_LITTLE(key +  4);
	x->input[KEY2] = U8TO32_LITTLE(key +  8);
	x->input[KEY3] = U8TO32_LITTLE(key + 12);

	if (key_length_bits == 256) /* recommended */
	{ 
		key += 16;
		constants = sigma;
	}
	else
	{
		constants = tau;
	}

	x->input[KEY4] = U8TO32_LITTLE(key +  0);
	x->input[KEY5] = U8TO32_LITTLE(key +  4);
	x->input[KEY6] = U8TO32_LITTLE(key +  8);
	x->input[KEY7] = U8TO32_LITTLE(key + 12);

	x->input[CONSTANT0] = U8TO32_LITTLE(constants +  0);
	x->input[CONSTANT1] = U8TO32_LITTLE(constants +  4);
	x->input[CONSTANT2] = U8TO32_LITTLE(constants +  8);
	x->input[CONSTANT3] = U8TO32_LITTLE(constants + 12);
}

void freestyle_ivsetup (
		freestyle_ctx 	*x,
	const 	u8 		*iv,
	const	u8 		*counter)
{
	x->input[COUNTER] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 0);

	x->input[IV0] = U8TO32_LITTLE(iv + 0);
	x->input[IV1] = U8TO32_LITTLE(iv + 4);
	x->input[IV2] = U8TO32_LITTLE(iv + 8);
}

void freestyle_roundsetup (
		freestyle_ctx 	*x,
	const 	u16 		min_rounds,
	const 	u16 		max_rounds,
	const	u8 		init_complexity)
{
	x->min_rounds 		= min_rounds;
	x->max_rounds 		= max_rounds;

	x->init_complexity 	= init_complexity;

	x->cipher_parameter [0] = (x->min_rounds    << 16) | (x->max_rounds);
	x->cipher_parameter [1] = (x->hash_interval << 16) | (x->hash_complexity << 8) | (x->init_complexity);

	x->random_word[0] = 0; 
	x->random_word[1] = 0; 
	x->random_word[2] = 0; 
	x->random_word[3] = 0; 

	/* modify key[0], key[1] */
	x->input[KEY0] ^= x->cipher_parameter[0];
	x->input[KEY1] ^= x->cipher_parameter[1];

	/* the number of ways a block of message can be encrypted */
	x->num_rounds_possible = 1 + (x->max_rounds - x->min_rounds)/x->hash_interval;
}

u16 freestyle_random_round_number (const freestyle_ctx *x)
{
	u16 R;

	/* Generate a random number */
	R = x->min_rounds + arc4random_uniform (x->max_rounds - x->min_rounds + x->hash_interval);

	/* Make it a multiple of hash_interval */
	R = x->hash_interval * (u16)(R/x->hash_interval);

	assert (R >= x->min_rounds);
	assert (R <= x->max_rounds);

	return R;
}

void freestyle_column_round (u32 x[16])
{
	QR (x[0], x[4], x[ 8], x[12])
	QR (x[1], x[5], x[ 9], x[13])
	QR (x[2], x[6], x[10], x[14])
	QR (x[3], x[7], x[11], x[15])
}

void freestyle_diagonal_round (u32 x[16])
{
	QR (x[0], x[5], x[10], x[15])
	QR (x[1], x[6], x[11], x[12])
	QR (x[2], x[7], x[ 8], x[13])
	QR (x[3], x[4], x[ 9], x[14])
}

void freestyle_increment_counter (freestyle_ctx *x)
{   
	x->input [COUNTER] = PLUSONE (x->input[COUNTER]);
}

u8 freestyle_hash (
		freestyle_ctx	*x,
	const	u32 		output[16],
	const 	u8 		previous_hash,
	const	u16 		rounds)
{
	u8 i;

	u8 	hash[4];

	u32	temp1 	= rounds;
	u32	temp2 	= previous_hash;

	AXR (temp1, x->random_word[0], temp2, 16);
	AXR (temp2, x->random_word[1], temp1, 12);
	AXR (temp1, x->random_word[2], temp2,  8);
	AXR (temp2, x->random_word[3], temp1,  7);

	for (i = 0; i < x->num_output_elements_to_hash; i+=4)
	{
		AXR (temp1, output[ i ], temp2, 16);
		AXR (temp2, output[i+1], temp1, 12);
		AXR (temp1, output[i+2], temp2,  8);
		AXR (temp2, output[i+3], temp1,  7);
	}

	U32TO8_LITTLE (hash, temp1);

	return  (u8)(hash[0] ^ hash[1] ^ hash[2] ^ hash[3]);
}

void freestyle_encrypt (
		freestyle_ctx 	*x,	
	const 	u8 	    	*plaintext,
		u8 	    	*ciphertext,
		u32 	    	bytes,
		u16 	    	*stop_condition)
{
	int 	i 	= 0;
	int 	block 	= 0;

	while (bytes > 0)
	{
	    u8 bytes_to_process = bytes >= 64 ? 64 : bytes;

	    (void) freestyle_encrypt_block (
		x,
		plaintext  + i,
		ciphertext + i,
		bytes_to_process,
		&stop_condition [block]
	    );
	
	    i 	  += bytes_to_process;
	    bytes -= bytes_to_process;

	    ++block;

	    freestyle_increment_counter(x);
	}
}

int freestyle_decrypt (
		freestyle_ctx 	*x,
	const 	u8 		*ciphertext,
		u8 		*plaintext,
		u32 		bytes,
	const	u16 		*stop_condition)
{
	int 	i	= 0;
	int 	block 	= 0;

	while (bytes > 0)
	{
	    u8 bytes_to_process = bytes >= 64 ? 64 : bytes;

	    u16 num_rounds = freestyle_decrypt_block (
		x,
		ciphertext + i,
		plaintext  + i,
		bytes_to_process,
		&stop_condition [block]
	    );

	    if (num_rounds < x->min_rounds) {
		return -1;
	    }

	    i 	  += bytes_to_process;
	    bytes -= bytes_to_process;
	
            ++block;

	    freestyle_increment_counter(x);
	}

	return 0;
}

u16 freestyle_encrypt_block (
		freestyle_ctx	*x,	
	const 	u8 		*plaintext,
		u8 		*ciphertext,
	const 	u8 		bytes,
		u16 		*stop_condition)
{
	u16 	i, r;

	u8 	hash = 0;

	u32 	output32[16];

	u16 	random_rounds = freestyle_random_round_number (x);

	bool init = (plaintext == NULL) || (ciphertext == NULL) || (bytes == 0);

#ifdef FREESTYLE_RANDOMIZE_ARRAY_INDICES
	u8	random_mask   = arc4random_uniform (256); 
#else
	u8 	random_mask = 0;
#endif

	u8 hash_count [256];

	memset (hash_count, -1, 256 * sizeof(u8));

	for (i = 0; i < 16; ++i) {
		output32 [i] = x->input [i];
	}

	/* modify counter[0] */
	output32[COUNTER] ^= x->random_word[3];

	u32 temp1 = 0;
	u32 temp2 = 0; 

	AXR (temp1, output32[COUNTER], temp2, 16);
	AXR (temp2, output32[KEY2], temp1, 12);
	AXR (temp1, output32[KEY3], temp2,  8);
	AXR (temp2, output32[KEY4], temp1,  7);

	u32 hash_count_mask = temp1;

	for (r = 1; r <= random_rounds; ++r)
	{
		if (r & 1)
			freestyle_column_round   (output32);
		else
			freestyle_diagonal_round (output32);

		if (r >= x->min_rounds && r % x->hash_interval == 0)
		{
			hash = freestyle_hash (x,output32,hash,r);
			++(hash_count [hash ^ random_mask]);
		}
	}

	if (!init && random_rounds == x->max_rounds)
	{
		hash = arc4random_uniform (256);
		++hash_count [hash ^ random_mask];
	}

	u8 masked_hash_count = PLUS(hash_count[hash^random_mask], hash_count_mask) % x->num_rounds_possible;

	*stop_condition = (hash << 8) | (masked_hash_count);

	if (! init)
	{
		u8 output8 [64];

		for (i = 0; i < 16; ++i)
		{
			output32 [i] = PLUS(output32[i], x->input[i]);
	     		U32TO8_LITTLE (output8 + 4 * i, output32[i]);
		}

		for (i = 0; i < bytes; ++i) {
			ciphertext [i] = plaintext[i] ^ output8[i];
		}
        }

	return random_rounds;
}

u16 freestyle_decrypt_block (
		freestyle_ctx	*x,
	const	u8 		*ciphertext,
		u8 		*plaintext,
		u8 		bytes,
	const 	u16 		*stop_condition)
{
	u16 i, r = 0;

	u8 hash = 0, hc;

	u32 	output32[16];

	bool init = (plaintext == NULL) || (ciphertext == NULL) || (bytes == 0);

	u8 expected_hash 	= (*stop_condition >> 8) & 0xFF;
	u8 masked_hash_count    = (*stop_condition & 0xFF); 

	for (i = 0; i < 16; ++i) {
		output32 [i] = x->input[i];
	}

	/* modify counter[0] */
	output32[COUNTER] ^= x->random_word[3];

	u32 temp1 = 0; 
	u32 temp2 = 0; 

	AXR (temp1, output32[COUNTER], 	temp2, 16);
	AXR (temp2, output32[KEY2], 	temp1, 12);
	AXR (temp1, output32[KEY3], 	temp2,  8);
	AXR (temp2, output32[KEY4], 	temp1,  7);

	u32 hash_count_mask = temp1;

	u8 hash_count = (((i64)masked_hash_count - hash_count_mask) % x->num_rounds_possible + x->num_rounds_possible) % x->num_rounds_possible;

	for (hc = 0; hc <= hash_count; ++hc)
	{
		while (1)	
		{
			++r;

			if (r > x->max_rounds) {
				if (init)
					return 0; // wrong key OR too many rounds
				else
					goto decrypt;
			}

			if (r & 1)
				freestyle_column_round   (output32);
			else
				freestyle_diagonal_round (output32);

			if (r >= x->min_rounds && r % x->hash_interval == 0)
		  	{
		   		hash = freestyle_hash (
					x,
					output32,
				 	hash,
					r
				);

				if (hash == expected_hash) {
					break;
				}
			}
		}
	}

decrypt:
	if (! init)	
	{
		u8 output8[64];

		for (i = 0; i < 16; ++i)
		{
			output32 [i] = PLUS(output32[i], x->input[i]);
	     		U32TO8_LITTLE (output8 + 4 * i, output32[i]);
		}

		for (i = 0; i < bytes; ++i) {
			plaintext[i] = ciphertext[i] ^ output8[i];
		}
	}

	return r;
}
