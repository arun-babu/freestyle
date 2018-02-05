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
#include <sys/tree.h>

#define NUM_INIT_HASHES (28)

#define MAX_HASH_VALUE (65536)

#include <assert.h>
//#define assert(x)

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

	u32 		input_00,
			input_01,
			input_02,
			input_03,
			input_04,
			input_05,
			input_06,
			input_07,
			input_08,
			input_09,
			input_10,
			input_11,
			input_12,
			input_13,
			input_14,
			input_15;

	u16		min_rounds;
	u16		max_rounds;

	u16		min_rounds_by_2;

	bool		min_rounds_is_odd;

	u32 		cipher_parameter[2];
	u32 		random_word[4];

	u16		num_rounds_possible;

	u16 		init_hash [NUM_INIT_HASHES];

	u8 		hash_complexity;
	u8 		init_complexity;

	u16 		hash_interval;
	u8 		num_output_elements_to_hash;

} freestyle_ctx;

void freestyle_increment_counter (
	freestyle_ctx *x
);

u16 random_round_number (
	const freestyle_ctx *x
);

void freestyle_init_common (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32		key_length_bits,
	const 	u8 		*iv,
	const 	u16 		min_rounds,
	const	u16		max_rounds,
	const	u8 		hash_complexity,
	const	u16 		hash_interval,
	const	u8 		init_complexity
);

void freestyle_init_encrypt (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32 		key_length_bits,
	const 	u8 		*iv,
	const 	u16 		min_rounds,
	const 	u16		max_rounds,
	const 	u8 		hash_complexity,
	const 	u16 		hash_interval,
	const 	u8 		init_complexity
);

void freestyle_init_decrypt (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32 		key_length_bits,
	const 	u8 		*iv,
	const 	u16 		min_rounds,
	const 	u16		max_rounds,
	const 	u8 		hash_complexity,
	const 	u16 		hash_interval,
	const 	u8 		init_complexity,
	const	u16 		*init_hash
);

void freestyle_keysetup (
		freestyle_ctx 	*x,
	const 	u8 		*key,
	const 	u32 		key_length_bits
);

void freestyle_ivsetup (
		freestyle_ctx 	*x,
	const 	u8 		*iv,
	const 	u8 		*counter
); 

void freestyle_hashsetup (
		freestyle_ctx 	*x,
	const 	u8 		hash_complexity,
	const 	u16 		hash_interval
);

void freestyle_roundsetup (
		freestyle_ctx 	*x,
	const	u16 		min_rounds,
	const	u16 		max_rounds,
	const	u8 		init_complexity
);

void freestyle_randomsetup_encrypt (
		freestyle_ctx 	*x
);

void freestyle_randomsetup_decrypt (
		freestyle_ctx 	*x
);

int freestyle_encrypt (
		freestyle_ctx 	*x,
	const 	u8 		*input,
		u8 		*output,
		u32 		bytes,
		u16 		*hash
);

int freestyle_decrypt (
		freestyle_ctx 	*x,
	const 	u8 		*input,
		u8 		*output,
		u32 		bytes,
		u16 		*hash
);

u16 freestyle_encrypt_block (
		freestyle_ctx	*x,	
	const 	u8 		*plaintext,
		u8 		*ciphertext,
		u8 		bytes,
		u16		*expected_hash
);

u16 freestyle_decrypt_block (
		freestyle_ctx	*x,	
		u8 		*plaintext,
	const	u8 		*ciphertext,
		u8 		bytes,
		u16		*expected_hash
);

#define HASH(x,output,hash,rounds)  do {			\
								\
	temp1 	= rounds;					\
	temp2 	= hash;						\
								\
	AXR (temp1, x->random_word[0], temp2, 16);		\
	AXR (temp2, x->random_word[1], temp1, 12);		\
	AXR (temp1, x->random_word[2], temp2,  8);		\
	AXR (temp2, x->random_word[3], temp1,  7);		\
								\
	AXR (temp1, *output[0], temp2, 16);			\
	AXR (temp2, *output[1], temp1, 12);			\
	AXR (temp1, *output[2], temp2,  8);			\
	AXR (temp2, *output[3], temp1,  7);			\
								\
	AXR (temp1, *output[4], temp2, 16);			\
	AXR (temp2, *output[5], temp1, 12);			\
	AXR (temp1, *output[6], temp2,  8);			\
	AXR (temp2, *output[7], temp1,  7);			\
								\
	if (x->hash_complexity >= 2)				\
	{							\
		AXR (temp1, *output[ 8], temp2, 16);		\
		AXR (temp2, *output[ 9], temp1, 12);		\
		AXR (temp1, *output[10], temp2,  8);		\
		AXR (temp2, *output[11], temp1,  7);		\
								\
		if (x->hash_complexity >= 3)			\
		{						\
			AXR (temp1, *output[12], temp2, 16);	\
			AXR (temp2, *output[13], temp1, 12);	\
			AXR (temp1, *output[14], temp2,  8);	\
			AXR (temp2, *output[15], temp1,  7);	\
		}						\
	}							\
								\
	U32TO8_LITTLE (hash_array, temp1);			\
								\
	hash = (u16)((hash_array[0] << 8 | hash_array[1])	\
		   ^ (hash_array[2] << 8 | hash_array[3]));	\
} while(0)

#define RESET_HASH_COLLIDED() 	do {  \
		hash_collided [  0] = \
		hash_collided [  1] = \
		hash_collided [  2] = \
		hash_collided [  3] = \
		hash_collided [  4] = \
		hash_collided [  5] = \
		hash_collided [  6] = \
		hash_collided [  7] = \
		hash_collided [  8] = \
		hash_collided [  9] = \
		hash_collided [ 10] = \
		hash_collided [ 11] = \
		hash_collided [ 12] = \
		hash_collided [ 13] = \
		hash_collided [ 14] = \
		hash_collided [ 15] = \
		hash_collided [ 16] = \
		hash_collided [ 17] = \
		hash_collided [ 18] = \
		hash_collided [ 19] = \
		hash_collided [ 20] = \
		hash_collided [ 21] = \
		hash_collided [ 22] = \
		hash_collided [ 23] = \
		hash_collided [ 24] = \
		hash_collided [ 25] = \
		hash_collided [ 26] = \
		hash_collided [ 27] = \
		hash_collided [ 28] = \
		hash_collided [ 29] = \
		hash_collided [ 30] = \
		hash_collided [ 31] = \
		hash_collided [ 32] = \
		hash_collided [ 33] = \
		hash_collided [ 34] = \
		hash_collided [ 35] = \
		hash_collided [ 36] = \
		hash_collided [ 37] = \
		hash_collided [ 38] = \
		hash_collided [ 39] = \
		hash_collided [ 40] = \
		hash_collided [ 41] = \
		hash_collided [ 42] = \
		hash_collided [ 43] = \
		hash_collided [ 44] = \
		hash_collided [ 45] = \
		hash_collided [ 46] = \
		hash_collided [ 47] = \
		hash_collided [ 48] = \
		hash_collided [ 49] = \
		hash_collided [ 50] = \
		hash_collided [ 51] = \
		hash_collided [ 52] = \
		hash_collided [ 53] = \
		hash_collided [ 54] = \
		hash_collided [ 55] = \
		hash_collided [ 56] = \
		hash_collided [ 57] = \
		hash_collided [ 58] = \
		hash_collided [ 59] = \
		hash_collided [ 60] = \
		hash_collided [ 61] = \
		hash_collided [ 62] = \
		hash_collided [ 63] = \
		hash_collided [ 64] = \
		hash_collided [ 65] = \
		hash_collided [ 66] = \
		hash_collided [ 67] = \
		hash_collided [ 68] = \
		hash_collided [ 69] = \
		hash_collided [ 70] = \
		hash_collided [ 71] = \
		hash_collided [ 72] = \
		hash_collided [ 73] = \
		hash_collided [ 74] = \
		hash_collided [ 75] = \
		hash_collided [ 76] = \
		hash_collided [ 77] = \
		hash_collided [ 78] = \
		hash_collided [ 79] = \
		hash_collided [ 80] = \
		hash_collided [ 81] = \
		hash_collided [ 82] = \
		hash_collided [ 83] = \
		hash_collided [ 84] = \
		hash_collided [ 85] = \
		hash_collided [ 86] = \
		hash_collided [ 87] = \
		hash_collided [ 88] = \
		hash_collided [ 89] = \
		hash_collided [ 90] = \
		hash_collided [ 91] = \
		hash_collided [ 92] = \
		hash_collided [ 93] = \
		hash_collided [ 94] = \
		hash_collided [ 95] = \
		hash_collided [ 96] = \
		hash_collided [ 97] = \
		hash_collided [ 98] = \
		hash_collided [ 99] = \
		hash_collided [100] = \
		hash_collided [101] = \
		hash_collided [102] = \
		hash_collided [103] = \
		hash_collided [104] = \
		hash_collided [105] = \
		hash_collided [106] = \
		hash_collided [107] = \
		hash_collided [108] = \
		hash_collided [109] = \
		hash_collided [110] = \
		hash_collided [111] = \
		hash_collided [112] = \
		hash_collided [113] = \
		hash_collided [114] = \
		hash_collided [115] = \
		hash_collided [116] = \
		hash_collided [117] = \
		hash_collided [118] = \
		hash_collided [119] = \
		hash_collided [120] = \
		hash_collided [121] = \
		hash_collided [122] = \
		hash_collided [123] = \
		hash_collided [124] = \
		hash_collided [125] = \
		hash_collided [126] = \
		hash_collided [127] = 0;\
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
