/*
 * Copyright (c) 2017 
 *
 * P. Arun Babu <arun.hbni@gmail.com> and 
 * Jithin Jose Thomas <jithinjosethomas@gmail.com>
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

void freestyle_init_encrypt (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32		key_length_bits,
	const 	u8 		*iv,
	const 	u16 		min_rounds,
	const	u16		max_rounds,
	const	u8 		hash_complexity,
	const	u16 		hash_interval)
{	
	freestyle_keysetup 	(x, key, key_length_bits);
	freestyle_ivsetup 	(x, iv,  NULL);
	freestyle_hashsetup 	(x, hash_complexity, hash_interval);
	freestyle_roundsetup 	(x, min_rounds, max_rounds);
	freestyle_randomsetup 	(x, true);
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
	const	u16 		*init_stop_condition)
{	
	freestyle_keysetup 	(x, key, key_length_bits);
	freestyle_ivsetup 	(x, iv,  NULL);
	freestyle_hashsetup 	(x, hash_complexity, hash_interval);
	freestyle_roundsetup 	(x, min_rounds, max_rounds);

	memcpy ( x->init_stop_condition,
		 init_stop_condition,
		 28 * sizeof(u16)
	);

	freestyle_randomsetup 	(x, false);
}
	
void freestyle_randomsetup (
		freestyle_ctx 	*x,
	const 	bool 		do_encryption_setup)
{
	int 	i;
	u32 	R[28]; /* 28 random rounds */

	u32	temp1;
	u32	temp2;

	u16 save_min_rounds		= x->min_rounds;
	u16 save_max_rounds		= x->max_rounds;
	u16 save_hash_interval   	= x->hash_interval;
	u8  save_hash_complexity 	= x->hash_complexity;

	x->min_rounds 		= 8;
	x->max_rounds 		= 32;
	x->hash_interval 	= 1;
	x->hash_complexity 	= 3;

	x->random_word[0] = 0;
	x->random_word[1] = 0;
	x->random_word[2] = 0;
	x->random_word[3] = 0;

	for (i = 0; i < 28; ++i)
	{
		if (do_encryption_setup)
		{
			R[i] = freestyle_encrypt_block (
				x,
				NULL,
				NULL,
				0,
				&x->init_stop_condition[i]
			);
		}
		else
		{
			R[i] = freestyle_decrypt_block (
				x,
				NULL,
				NULL,
				0,
				&x->init_stop_condition[i]
			);
		}
		freestyle_increment_counter(x);
	}

	for (i = 0; i < 4; ++i)
	{
		temp1 = 0;
		temp2 = 0;

		AXR (temp1,     i+1   , temp2, 16);

		AXR (temp2, R[7*i    ], temp1, 12);
		AXR (temp1, R[7*i + 1], temp2,  8);
		AXR (temp2, R[7*i + 2], temp1,  7);

		AXR (temp1, R[7*i + 3], temp2, 16);
		AXR (temp2, R[7*i + 4], temp1, 12);
		AXR (temp1, R[7*i + 5], temp2,  8);
		AXR (temp2, R[7*i + 6], temp1,  7);

		x->random_word[i] = temp1; 
	}

	/* set user parameters back */
	x->min_rounds 		= save_min_rounds;
	x->max_rounds 		= save_max_rounds;
	x->hash_interval 	= save_hash_interval; 
	x->hash_complexity 	= save_hash_complexity;

	/* change key[1], key[2], key[3] */
	x->input[5] = XOR(x->input[5], x->random_word[0]); 
	x->input[6] = XOR(x->input[6], x->random_word[1]); 
	x->input[7] = XOR(x->input[7], x->random_word[2]); 

	/* set counter back to 0 */
	x->input[12] = 0;
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

	x->input[4] = U8TO32_LITTLE(key +  0);
	x->input[5] = U8TO32_LITTLE(key +  4);
	x->input[6] = U8TO32_LITTLE(key +  8);
	x->input[7] = U8TO32_LITTLE(key + 12);

	if (key_length_bits == 256) /* recommended */
	{ 
		key += 16;
		constants = sigma;
	}
	else
	{
		constants = tau;
	}

	x->input[ 8] = U8TO32_LITTLE(key +  0);
	x->input[ 9] = U8TO32_LITTLE(key +  4);
	x->input[10] = U8TO32_LITTLE(key +  8);
	x->input[11] = U8TO32_LITTLE(key + 12);

	x->input[0] = U8TO32_LITTLE(constants +  0);
	x->input[1] = U8TO32_LITTLE(constants +  4);
	x->input[2] = U8TO32_LITTLE(constants +  8);
	x->input[3] = U8TO32_LITTLE(constants + 12);
}

void freestyle_ivsetup (
		freestyle_ctx 	*x,
	const 	u8 		*iv,
	const	u8 		*counter)
{
	x->input[12] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 0);
	x->input[13] = U8TO32_LITTLE(iv + 0);
	x->input[14] = U8TO32_LITTLE(iv + 4);
	x->input[15] = U8TO32_LITTLE(iv + 8);
}

void freestyle_roundsetup (
		freestyle_ctx 	*x,
	const 	u16 		min_rounds,
	const 	u16 		max_rounds)
{

	assert (min_rounds <= max_rounds);
	assert (min_rounds % x->hash_interval == 0);
	assert (max_rounds % x->hash_interval == 0);

	assert (min_rounds >= 1);
	assert (max_rounds <= 256);

	x->min_rounds = min_rounds;
	x->max_rounds = max_rounds;

	x->cipher_parameter = 
			((0xFF & x->min_rounds      ) << 24) |
			((0xFF & x->max_rounds      ) << 16) |
			((0xFF & x->hash_interval   ) <<  8) |
			((0xFF & x->hash_complexity )      ) ; 

	x->random_word[0] = 0; 
	x->random_word[1] = 0; 
	x->random_word[2] = 0; 
	x->random_word[3] = 0; 

	/* change key[0] */
	x->input[4] = XOR(x->input[4], x->cipher_parameter);
}

u16 freestyle_random_round_number (const freestyle_ctx *x)
{
	u16 r;

	/* Generate a random number */
	r = x->min_rounds + arc4random_uniform (x->max_rounds - x->min_rounds + x->hash_interval);

	/* Make it a multiple of hash_interval */
	r = x->hash_interval * (u16)(r/x->hash_interval);

	return r;
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
	x->input [12] = PLUSONE (x->input[12]);
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

	AXR (temp1, x->cipher_parameter, temp2, 16);
	AXR (temp2, x->random_word[0], 	 temp1, 12);
	AXR (temp1, x->random_word[1],   temp2,  8);
	AXR (temp2, x->random_word[2],   temp1,  7);

	for (i = 0; i < x->num_output_elements_to_hash; i+=4)
	{
		AXR (temp1, output[ i ], temp2, 16);
		AXR (temp2, output[i+1], temp1, 12);
		AXR (temp1, output[i+2], temp2,  8);
		AXR (temp2, output[i+3], temp1,  7);
	}

	temp1 = XOR (temp1, x->random_word[3]);

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
	int 	i 			= 0;
	int 	block 			= 0;
	u8	bytes_to_process 	= 0;
	u16 	num_rounds 		= 0;

	while (bytes > 0)
	{
	    bytes_to_process = bytes >= 64 ? 64 : bytes;

	    num_rounds = freestyle_encrypt_block (
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
	int 	i		 = 0;
	int 	block 		 = 0;
	int 	bytes_to_process = 0;
	u16 	num_rounds 	 = 0;

	while (bytes > 0)
	{
	    bytes_to_process = bytes >= 64 ? 64 : bytes;

	    num_rounds = freestyle_decrypt_block (
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

	u8 	output8	[64];
	u32 	output32[16];

	u16 	random_rounds = freestyle_random_round_number (x);

#ifdef FREESTYLE_RANDOMIZE_INDICES
	u8	random_mask   = arc4random_uniform (256); 
#else
	u8   	random_mask   = 0;
#endif

	u8 hash_count [256];

	memset (hash_count, -1, 256 * sizeof(u8));

	for (i = 0; i < 16; ++i) {
		output32 [i] = x->input [i];
	}

	/* change counter[0] */
	output32[12] = XOR (output32[12], x->random_word[3]);

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

	*stop_condition = (hash << 8) | hash_count [hash ^ random_mask];

	if (plaintext && ciphertext && bytes)
	{
		for (i = 0; i < 16; ++i)
		{
			output32 [i] = PLUS(output32[i], x->input[i]);
			U32TO8_LITTLE (output8 + 4 * i, output32[i]);
		}

		for (i = 0; i < bytes; ++i) {
			ciphertext [i] = XOR (plaintext[i], output8[i]);
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

	u8 expected_hash = (*stop_condition >> 8) & 0xFF;
	u8 hash_count    = (*stop_condition & 0xFF);

	u8 	output8	[64];
	u32 	output32[16];

	for (i = 0; i < 16; ++i) {
		output32 [i] = x->input[i];
	}

	/* change counter[0] */
	output32[12] = XOR (output32[12], x->random_word[3]);

	for (hc = 0; hc <= hash_count; ++hc)
	{
		while (1)	
		{
			++r;

			/* wrong key OR too many rounds */
			if (r > x->max_rounds) {
				return 0;
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

				if (hash == expected_hash)
				{
					break;
				}
			}
		}
	}

	if (plaintext && ciphertext && bytes)
	{
		for (i = 0; i < 16; ++i)
		{
			output32 [i] = PLUS(output32[i],x->input[i]);
			U32TO8_LITTLE (output8 + 4 * i, output32[i]);
		}

		for (i = 0; i < bytes; ++i) {
			plaintext[i] = XOR (ciphertext[i], output8[i]);
		}
	}

	return r;
}
