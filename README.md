# Freestyle

Freestyle is a randomized and variable round version of the ChaCha cipher.

Freestyle uses the concept of hash based halting condition where a decryption attempt with an incorrect key is likely to take longer time to halt. This makes Freestyle resistant to key-guessing attacks i.e. brute-force and dictionary based attacks. Freestyle demonstrates a novel approach for ciphertext randomization by using random number of rounds for each block, where the exact number of rounds are unknown to the receiver in advance. 

Freestyle provides the possibility of generating 2^256 different ciphertexts for a given key, nonce, and message; thus resisting key and nonce reuse attacks. Due to its inherent random behavior, Freestyle makes cryptanalysis through known-plaintext, chosen-plaintext, and chosen-ciphertext attacks difficult in practice. 

On the other hand, Freestyle has costlier cipher initialization process, typically generates 1.56% larger ciphertext, and was found to be 1.6 to 3.2 times slower than ChaCha20. Freestyle is suitable for applications that favor ciphertext randomization and resistance to key-guessing and key reuse attacks over performance and ciphertext size. Freestyle is ideal for applications where ciphertext can be assumed to be in full control of an adversary, and an offline key-guessing attack can be carried out. 

The main aim of Freestyle is to improve the Key Guessing Penalty (KGP), which is defined as:

```
	    Time taken to attempt decryption using an incorrect key
KGP =     -----------------------------------------------------------
	       Time taken to decrypt using the correct key
```

**Optimized version of Freestyle is still work in progress.** 
An old version of paper on Freestyle can be found at [(arXiv.org)](https://arxiv.org/abs/1802.03201)

On Linux, you need to install libbsd-dev package for arc4random() and arc4random_uniform() functions.

Released in ISC License

**To run:**
```
	$ git clone https://github.com/arun-babu/freestyle
	$ cd freestyle
	$ ./test.sh
```
