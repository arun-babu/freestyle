# Freestyle

Freestyle is a randomized and variable round version of the ChaCha cipher.

Freestyle uses the concept of hash based halting condition where a decryption attempt with an incorrect key is likely to take longer time to halt. This makes Freestyle resistant to key-guessing attacks i.e. brute-force and dictionary based attacks. Freestyle demonstrates a novel approach for ciphertext randomization by using random number of rounds for each block, where the exact number of rounds are unknown to the receiver in advance. 

Freestyle provides the possibility of generating 2^256 different ciphertexts for a given key, nonce, and message; thus resisting key and nonce reuse attacks. Due to its inherent random behavior, Freestyle makes cryptanalysis through known-plaintext, chosen-plaintext, and chosen-ciphertext attacks difficult in practice. 

On the other hand, Freestyle has costlier cipher initialization process, typically generates 1.56% larger ciphertext, and was found to be  1.13 to 1.60 times slower than ChaCha20. Freestyle is suitable for applications that favor ciphertext randomization and resistance to key-guessing and key reuse attacks over performance and ciphertext size. Freestyle is ideal for applications where ciphertext can be assumed to be in full control of an adversary, and an offline key-guessing attack can be carried out. 

The main aim of Freestyle is to improve the Key Guessing Penalty (KGP), which is defined as:

1. For encryption

```
	    Expected time to attempt decryption using an incorrect key
KGP =     -----------------------------------------------------------
	       Expected time to decrypt using the correct key
```

2. For password hashing 

```
	    Expected time to verify a password hash using an incorrect password 
KGP =     ----------------------------------------------------------------------
	    Expected time to verify a password hash using the correct password 
```
**To run:**

On Ubuntu, libbsd-dev package is needed for arc4random() and arc4random_uniform() functions.

```
	$ git clone https://github.com/arun-babu/freestyle
	$ cd freestyle
	$ ./test.sh
```

**License**

Freestyle is released in ISC License; and a paper on Freestyle is available [(here)](https://github.com/arun-babu/freestyle/blob/master/freestyle.pdf), and in [(Journal of Information Security and Applications)](http://www.sciencedirect.com/science/article/pii/S2214212618307634).

You may cite the Freestyle paper as:

```
Arun Babu Puthuparambil, Jithin Jose Thomas,
Freestyle, a randomized version of ChaCha for resisting offline brute-force and dictionary attacks,
Journal of Information Security and Applications,
Volume 49,
2019,
102396,
ISSN 2214-2126,
https://doi.org/10.1016/j.jisa.2019.102396.
```

Or as BibTex:

```
@article{PUTHUPARAMBIL2019102396,
title = "Freestyle, a randomized version of ChaCha for resisting offline brute-force and dictionary attacks",
journal = "Journal of Information Security and Applications",
volume = "49",
pages = "102396",
year = "2019",
issn = "2214-2126",
doi = "https://doi.org/10.1016/j.jisa.2019.102396",
url = "http://www.sciencedirect.com/science/article/pii/S2214212618307634",
author = "Arun Babu Puthuparambil and Jithin Jose Thomas",
}
```

**Other libraries used**

For one of the optimized versions we use `randen-rng` instead of `arc4random` functions.

The "randen-rng" (https://github.com/jedisct1/randen-rng) is released in Apache License Version 2.0, January 2004.
