# Freestyle

Freestyle is a randomized version of ChaCha cipher to resist brute-force and dictionary attacks.

Freestyle provides the possibility of generating 2^128 different ciphertexts for a given message
even though the key and nonce (a.k.a IV) are the same.

[A paper on Freestyle (arXiv.org)](https://arxiv.org/abs/1802.03201)

On Linux, you need to install libbsd-dev package for arc4random() and arc4random_uniform() functions.

Released in ISC License
