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

#ifndef FREESTYLE_H
#define FREESTYLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>

#define MAX_HASH_VALUE 	(65536)
#define MAX_INIT_HASHES (56)

#include <assert.h>

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

typedef unsigned char 	u8;
typedef unsigned short 	u16;
typedef unsigned int 	u32;
typedef uint64_t 	u64;

#define freestyle_encrypt(...) freestyle_process(__VA_ARGS__,true)
#define freestyle_decrypt(...) freestyle_process(__VA_ARGS__,false)

#define freestyle_encrypt_block(...) freestyle_process_block(__VA_ARGS__,true)
#define freestyle_decrypt_block(...) freestyle_process_block(__VA_ARGS__,false)

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
	u32 		input[16];

	u32		min_rounds;
	u32		max_rounds;

	u32 		cipher_parameter[2];
	u32 		rand[8];

	u32		num_rounds_possible;

	u8		num_init_hashes;
	u16 		init_hash [MAX_INIT_HASHES];

	u8 		pepper_bits;
	u32 		pepper;

	bool 		is_pepper_set;

	u32 		hash_interval;
	u8 		num_output_elements_to_hash;

} freestyle_ctx;

void freestyle_increment_counter (
	freestyle_ctx *x
);

u32 random_round_number (
	const freestyle_ctx *x
);

void freestyle_init_common (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u16		key_length_bits,
	const 	u8 		*iv,
	const 	u32 		min_rounds,
	const	u32		max_rounds,
	const	u32 		hash_interval,
	const	u8 		pepper_bits,
	const	u8 		num_init_hashes	
);

void freestyle_init_encrypt (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u16 		key_length_bits,
	const 	u8 		*iv,
	const 	u32 		min_rounds,
	const 	u32		max_rounds,
	const 	u32 		hash_interval,
	const 	u8 		pepper_bits,
	const	u8 		num_init_hashes	
);

void freestyle_init_encrypt_with_pepper (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u16 		key_length_bits,
	const 	u8 		*iv,
	const 	u32 		min_rounds,
	const 	u32		max_rounds,
	const 	u32 		hash_interval,
	const 	u8 		pepper_bits,
	const	u8 		num_init_hashes,
	const 	u32 		pepper_set	
);

void freestyle_init_decrypt (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u16 		key_length_bits,
	const 	u8 		*iv,
	const 	u32 		min_rounds,
	const 	u32		max_rounds,
	const 	u32 		hash_interval,
	const 	u8 		pepper_bits,
	const	u8 		num_init_hashes,
	const	u16 		*init_hash
);

void freestyle_init_decrypt_with_pepper (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u16 		key_length_bits,
	const 	u8 		*iv,
	const 	u32 		min_rounds,
	const 	u32		max_rounds,
	const 	u32 		hash_interval,
	const 	u8 		pepper_bits,
	const	u8 		num_init_hashes,
	const 	u32 		pepper_set,
	const	u16 		*init_hash
);

void freestyle_keysetup (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u16 		key_length_bits
);

void freestyle_ivsetup (
		freestyle_ctx 	*x,
	const 	u8 		*iv,
	const 	u32 		counter
); 

void freestyle_hashsetup (
		freestyle_ctx 	*x,
	const 	u32 		hash_interval
);

void freestyle_roundsetup (
		freestyle_ctx 	*x,
	const	u32 		min_rounds,
	const	u32 		max_rounds,
	const	u8 		pepper_bits,
	const	u8 		num_init_hashes	
);

void freestyle_randomsetup_encrypt (
		freestyle_ctx 	*x
);

void freestyle_randomsetup_decrypt (
		freestyle_ctx 	*x
);

u16 freestyle_hash (
		freestyle_ctx 	*x,
	const 	u32 		output [16],
	const 	u16 		previous_hash,
	const 	u32 		rounds
);

int freestyle_process (
		freestyle_ctx 	*x,
	const 	u8 		*input,
		u8 		*output,
		u32 		bytes,
		u16 		*hash,
	const 	bool 		do_encryption
);

u32 freestyle_process_block (
		freestyle_ctx	*x,	
	const 	u8 		*input,
		u8 		*output,
		u8 		bytes,
		u16		*expected_hash,	
	const	bool 		do_encryption
);

void freestyle_init_random_indices (
		freestyle_ctx 	*x,
		u8 		*random_indices
);

#endif	/* FREESTYLE_H */
