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

/*
 * Some code is taken from D. J. Bernstein's
 * chacha-merged.c version 20080118
 * Public domain.
 */

#ifndef FREESTYLE_H
#define FREESTYLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "./randen-rng/src/randen.h"

#define MAX_HASH_VALUES	(256)
#define MAX_INIT_HASHES (56)

#if 1
	#include <assert.h>
#else
	#define assert(x)
#endif

#ifdef __linux__
	#include <bsd/stdlib.h>
#endif

/*--- Elements of the cipher state --- */

#define CONSTANT0 	(0)
#define CONSTANT1 	(1)
#define CONSTANT2 	(2)
#define CONSTANT3 	(3)
#define KEY0 		(4)
#define KEY1 		(5)
#define KEY2 		(6)
#define KEY3 		(7)
#define KEY4 		(8)
#define KEY5 		(9)
#define KEY6 		(10)
#define KEY7 		(11)
#define COUNTER 	(12)
#define IV0 		(13)
#define IV1 		(14)	
#define IV2 		(15)

/*------*/

typedef unsigned char	u8;
typedef unsigned short	u16;
typedef unsigned int	u32;

#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((u8)(v) & U8C(0xFF))
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define MINUS(v,w) (U32V((v) - (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QR(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

#define AXR(a,b,c,r) {a = PLUS(a,b); c = ROTATE(XOR(c,a),r);}

typedef struct freestyle_ctx {

	u32 	input_CONSTANT0,
		input_CONSTANT1,
		input_CONSTANT2,
		input_CONSTANT3,
		input_KEY0,
		input_KEY1,
		input_KEY2,
		input_KEY3,
		input_KEY4,
		input_KEY5,
		input_KEY6,
		input_KEY7,
		input_COUNTER,
		input_IV0,
		input_IV1,
		input_IV2;

	u32 	initial_counter;

	u8	min_rounds;
	u8	max_rounds;
	u8	num_precomputed_rounds;

	u8 	hash_interval;

	u32 	cipher_parameter;
	u32 	rand[8];

	u8	num_init_hashes;
	u8	init_hash [MAX_INIT_HASHES];

	u8 	pepper_bits;
	u32 	pepper;

	bool 	is_pepper_set;


	RandenState	rng;
	uint8_t seed [RANDEN_SEED_BYTES];

} freestyle_ctx;

void freestyle_encrypt (
		freestyle_ctx 	*x,
	const 	u8 		*plaintext,
		u8 		*ciphertext,
		u32 		bytes,
		u8 		*hash
);

void freestyle_decrypt (
		freestyle_ctx 	*x,
	const 	u8 		*input,
		u8 		*output,
		u32 		bytes,
		u8 		*hash
);

void freestyle_set_counter (freestyle_ctx *x, u32 counter);

void freestyle_init_encrypt (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u16 		key_length_bits,
	const 	u8 		*iv,
	const 	u8 		min_rounds,
	const 	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const 	u8 		pepper_bits,
	const	u8 		num_init_hashes	
);

void freestyle_init_encrypt_with_pepper (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u16 		key_length_bits,
	const 	u8 		*iv,
	const 	u8 		min_rounds,
	const 	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const 	u8 		pepper_bits,
	const	u8 		num_init_hashes,
	const 	u32 		pepper_set	
);

void freestyle_init_decrypt (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u16 		key_length_bits,
	const 	u8 		*iv,
	const 	u8 		min_rounds,
	const 	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const 	u8 		pepper_bits,
	const	u8 		num_init_hashes,
	const	u8 		*init_hash
);

void freestyle_init_decrypt_with_pepper (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u16 		key_length_bits,
	const 	u8 		*iv,
	const 	u8 		min_rounds,
	const 	u8		max_rounds,
	const	u8		num_precomputed_rounds,
	const 	u8 		pepper_bits,
	const	u8 		num_init_hashes,
	const 	u32 		pepper_set,
	const	u8 		*init_hash
);

#endif	/* FREESTYLE_H */
