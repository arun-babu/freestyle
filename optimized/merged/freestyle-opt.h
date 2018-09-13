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

#ifndef FREESTYLE_OPT_H
#define FREESTYLE_OPT_H

#include "./randen-rng/src/randen.h"

#ifdef __OpenBSD__
	#define restrict __restrict
#endif

#define freestyle_init_RNG(x) \
	arc4random_buf (x->seed,RANDEN_SEED_BYTES);	\
	randen_init(&x->rng,(const uint8_t *)&x->seed);

#define freestyle_increment_counter(x) \
	x->input_COUNTER = PLUSONE(x->input_COUNTER);

#define HAS_COLLISION(hash,hash_collided) \
	(hash_collided[hash >> 5] & (1 << (hash & 0x1F)))

#define SET_COLLIDED(hash,hash_collided) \
	hash_collided[hash >> 5] |= (1 << (hash & 0x1F));

#define COMPUTE_HASH(x,hash,rounds) {				\
								\
	temp1 	= rounds;					\
	temp2 	= hash;						\
								\
	AXR (temp1, output_03, temp2, 16);			\
	AXR (temp2, output_06, temp1, 12);			\
	AXR (temp1, output_09, temp2,  8);			\
	AXR (temp2, output_12, temp1,  7);			\
								\
	hash = temp1 & 0xFF;					\
								\
	while (HAS_COLLISION(hash, hash_collided)) {		\
		++hash;						\
	}							\
								\
	SET_COLLIDED(hash,hash_collided)			\
} 

#define FREESTYLE_DOUBLE_ROUND() {			\
	QR (output_00, output_04, output_08, output_12)	\
	QR (output_01, output_05, output_09, output_13)	\
	QR (output_02, output_06, output_10, output_14)	\
	QR (output_03, output_07, output_11, output_15)	\
							\
	QR (output_00, output_05, output_10, output_15)	\
	QR (output_01, output_06, output_11, output_12)	\
	QR (output_02, output_07, output_08, output_13)	\
	QR (output_03, output_04, output_09, output_14)	\
}

#define FREESTYLE_COLUMN_ROUND() {			\
	QR (output_00, output_04, output_08, output_12)	\
	QR (output_01, output_05, output_09, output_13)	\
	QR (output_02, output_06, output_10, output_14)	\
	QR (output_03, output_07, output_11, output_15)	\
}

#define FREESTYLE_DIAGONAL_ROUND() {			\
	QR (output_00, output_05, output_10, output_15)	\
	QR (output_01, output_06, output_11, output_12)	\
	QR (output_02, output_07, output_08, output_13)	\
	QR (output_03, output_04, output_09, output_14)	\
}

#define FREESTYLE_XOR_64(input,output,keystream) {	\
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
}

#define freestyle_precompute_rounds(x) {				     \
									     \
 for (r = 1; r <= x->num_precomputed_rounds; ++r)			     \
 {									     \
   if (r & 1)								     \
   {									     \
      QR(x->input_CONSTANT0, x->input_KEY0, x->input_KEY4, x->input_COUNTER) \
      QR(x->input_CONSTANT1, x->input_KEY1, x->input_KEY5, x->input_IV0)     \
      QR(x->input_CONSTANT2, x->input_KEY2, x->input_KEY6, x->input_IV1)     \
      QR(x->input_CONSTANT3, x->input_KEY3, x->input_KEY7, x->input_IV2)     \
   }									     \
   else									     \
   {									     \
      QR(x->input_CONSTANT0, x->input_KEY1, x->input_KEY6, x->input_IV2)     \
      QR(x->input_CONSTANT1, x->input_KEY2, x->input_KEY7, x->input_COUNTER) \
      QR(x->input_CONSTANT2, x->input_KEY3, x->input_KEY4, x->input_IV0)     \
      QR(x->input_CONSTANT3, x->input_KEY0, x->input_KEY5, x->input_IV1)     \
   }									     \
   x->initial_counter = x->input_COUNTER;				     \
 }									     \
}

#define freestyle_random_round_number(x,r) {				\
	r = (								\
		(x->min_rounds						\
			+ arc4random_uniform (				\
		       	x->max_rounds - x->min_rounds + x->hash_interval\
		  )							\
		) / x->hash_interval					\
	) * x->hash_interval; 						\
}

#define freestyle_random_round_number_fast(x,r) {			\
	r = (								\
		(x->min_rounds						\
			+ randen_generate_byte(&x->rng) % (		\
		       	x->max_rounds - x->min_rounds + x->hash_interval\
		  )							\
		) / x->hash_interval					\
	) * x->hash_interval; 						\
}

#endif	/* FREESTYLE_OPT_H */
