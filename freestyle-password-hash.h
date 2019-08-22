#ifndef FREESTYLE_PASSWORD_HASH_H
#define FREESTYLE_PASSWORD_HASH_H

#include "freestyle.h"

void freestyle_hash_password (
	const 	char 		*password,
	const 	u8 		*salt,
		u8		*hash,
	const	size_t		hash_len,
	const 	u8 		min_rounds,
	const 	u8 		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8 		pepper_bits,
	const	u8 		num_init_hashes);

bool freestyle_verify_password_hash (
	const 	char 		*password,
	const 	u8 		*salt,
		u8		*hash,
	const	size_t		hash_len,
	const 	u8 		min_rounds,
	const 	u8 		max_rounds,
	const	u8		num_precomputed_rounds,
	const	u8 		pepper_bits,
	const	u8 		num_init_hashes);

#endif	/* FREESTYLE_PASSWORD_HASH_H */
