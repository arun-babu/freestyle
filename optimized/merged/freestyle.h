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

#define CONSTANT_0 	(0)
#define CONSTANT_1 	(1)
#define CONSTANT_2 	(2)
#define CONSTANT_3 	(3)
#define KEY_0 		(4)
#define KEY_1 		(5)
#define KEY_2 		(6)
#define KEY_3 		(7)
#define KEY_4 		(8)
#define KEY_5 		(9)
#define KEY_6 		(10)
#define KEY_7 		(11)
#define COUNTER 	(12)
#define IV_0 		(13)
#define IV_1 		(14)	
#define IV_2 		(15)

/*------*/

typedef unsigned char 	u8;
typedef unsigned short 	u16;
typedef unsigned int 	u32;
typedef uint64_t 	u64;

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

	u32 		input_CONSTANT_0,
			input_CONSTANT_1,
			input_CONSTANT_2,
			input_CONSTANT_3,
			input_KEY_0,
			input_KEY_1,
			input_KEY_2,
			input_KEY_3,
			input_KEY_4,
			input_KEY_5,
			input_KEY_6,
			input_KEY_7,
			input_COUNTER,
			input_IV_0,
			input_IV_1,
			input_IV_2;

	u32		min_rounds;
	u32		max_rounds;

	u32		min_rounds_by_2;

	bool		min_rounds_is_odd;

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

void freestyle_encrypt (
		freestyle_ctx 	*x,
	const 	u8 		*input,
		u8 		*output,
		u32 		bytes,
		u16 		*hash
);

void freestyle_decrypt (
		freestyle_ctx 	*x,
	const 	u8 		*input,
		u8 		*output,
		u32 		bytes,
		u16 		*hash
);

u32 freestyle_encrypt_block (
		freestyle_ctx	*x,	
	const 	u8 		*plaintext,
		u8 		*ciphertext,
		u8 		bytes,
		u16		*expected_hash
);

u32 freestyle_decrypt_block (
		freestyle_ctx	*x,	
		u8 		*plaintext,
	const	u8 		*ciphertext,
		u8 		bytes,
		u16		*expected_hash
);

#define COMPUTE_HASH(x,hash,rounds)  do {			\
								\
	temp1 	= rounds;					\
	temp2 	= hash;						\
								\
	AXR (temp1, output32_03, temp2, 16);			\
	AXR (temp2, output32_06, temp1, 12);			\
	AXR (temp1, output32_09, temp2,  8);			\
	AXR (temp2, output32_12, temp1,  7);			\
								\
	hash = (u16) XOR(temp1 & 0xFFFF, temp1 >> 16);		\
								\
} while(0)

#define FREESTYLE_DOUBLE_ROUND() do {				\
	QR (output32_00, output32_04, output32_08, output32_12)	\
	QR (output32_01, output32_05, output32_09, output32_13)	\
	QR (output32_02, output32_06, output32_10, output32_14)	\
	QR (output32_03, output32_07, output32_11, output32_15)	\
								\
	QR (output32_00, output32_05, output32_10, output32_15)	\
	QR (output32_01, output32_06, output32_11, output32_12)	\
	QR (output32_02, output32_07, output32_08, output32_13)	\
	QR (output32_03, output32_04, output32_09, output32_14)	\
} while(0)

#define FREESTYLE_COLUMN_ROUND() do {				\
	QR (output32_00, output32_04, output32_08, output32_12)	\
	QR (output32_01, output32_05, output32_09, output32_13)	\
	QR (output32_02, output32_06, output32_10, output32_14)	\
	QR (output32_03, output32_07, output32_11, output32_15)	\
} while(0)

#define FREESTYLE_DIAGONAL_ROUND() do {				\
	QR (output32_00, output32_05, output32_10, output32_15)	\
	QR (output32_01, output32_06, output32_11, output32_12)	\
	QR (output32_02, output32_07, output32_08, output32_13)	\
	QR (output32_03, output32_04, output32_09, output32_14)	\
} while(0)

#define FREESTYLE_XOR_64(input,output,keystream) do {	\
	output[ 0] = XOR (input[ 0], keystream[ 0]);	\
	output[ 1] = XOR (input[ 1], keystream[ 1]);	\
	output[ 2] = XOR (input[ 2], keystream[ 2]);	\
	output[ 3] = XOR (input[ 3], keystream[ 3]);	\
	output[ 4] = XOR (input[ 4], keystream[ 4]);	\
	output[ 5] = XOR (input[ 5], keystream[ 5]);	\
	output[ 6] = XOR (input[ 6], keystream[ 6]);	\
	output[ 7] = XOR (input[ 7], keystream[ 7]);	\
	output[ 8] = XOR (input[ 8], keystream[ 8]);	\
	output[ 9] = XOR (input[ 9], keystream[ 9]);	\
	output[10] = XOR (input[10], keystream[10]);	\
	output[11] = XOR (input[11], keystream[11]);	\
	output[12] = XOR (input[12], keystream[12]);	\
	output[13] = XOR (input[13], keystream[13]);	\
	output[14] = XOR (input[14], keystream[14]);	\
	output[15] = XOR (input[15], keystream[15]);	\
	output[16] = XOR (input[16], keystream[16]);	\
	output[17] = XOR (input[17], keystream[17]);	\
	output[18] = XOR (input[18], keystream[18]);	\
	output[19] = XOR (input[19], keystream[19]);	\
	output[20] = XOR (input[20], keystream[20]);	\
	output[21] = XOR (input[21], keystream[21]);	\
	output[22] = XOR (input[22], keystream[22]);	\
	output[23] = XOR (input[23], keystream[23]);	\
	output[24] = XOR (input[24], keystream[24]);	\
	output[25] = XOR (input[25], keystream[25]);	\
	output[26] = XOR (input[26], keystream[26]);	\
	output[27] = XOR (input[27], keystream[27]);	\
	output[28] = XOR (input[28], keystream[28]);	\
	output[29] = XOR (input[29], keystream[29]);	\
	output[30] = XOR (input[30], keystream[30]);	\
	output[31] = XOR (input[31], keystream[31]);	\
	output[32] = XOR (input[32], keystream[32]);	\
	output[33] = XOR (input[33], keystream[33]);	\
	output[34] = XOR (input[34], keystream[34]);	\
	output[35] = XOR (input[35], keystream[35]);	\
	output[36] = XOR (input[36], keystream[36]);	\
	output[37] = XOR (input[37], keystream[37]);	\
	output[38] = XOR (input[38], keystream[38]);	\
	output[39] = XOR (input[39], keystream[39]);	\
	output[40] = XOR (input[40], keystream[40]);	\
	output[41] = XOR (input[41], keystream[41]);	\
	output[42] = XOR (input[42], keystream[42]);	\
	output[43] = XOR (input[43], keystream[43]);	\
	output[44] = XOR (input[44], keystream[44]);	\
	output[45] = XOR (input[45], keystream[45]);	\
	output[46] = XOR (input[46], keystream[46]);	\
	output[47] = XOR (input[47], keystream[47]);	\
	output[48] = XOR (input[48], keystream[48]);	\
	output[49] = XOR (input[49], keystream[49]);	\
	output[50] = XOR (input[50], keystream[50]);	\
	output[51] = XOR (input[51], keystream[51]);	\
	output[52] = XOR (input[52], keystream[52]);	\
	output[53] = XOR (input[53], keystream[53]);	\
	output[54] = XOR (input[54], keystream[54]);	\
	output[55] = XOR (input[55], keystream[55]);	\
	output[56] = XOR (input[56], keystream[56]);	\
	output[57] = XOR (input[57], keystream[57]);	\
	output[58] = XOR (input[58], keystream[58]);	\
	output[59] = XOR (input[59], keystream[59]);	\
	output[60] = XOR (input[60], keystream[60]);	\
	output[61] = XOR (input[61], keystream[61]);	\
	output[62] = XOR (input[62], keystream[62]);	\
	output[63] = XOR (input[63], keystream[63]);	\
} while(0)

#endif	/* FREESTYLE_H */
