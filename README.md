[![Build Status](https://travis-ci.org/ffleming/crypto_toolchain.svg?branch=master)](https://travis-ci.org/ffleming/crypto_toolchain)

# CryptoToolchain

This is a suite of tools for ruining the blue team's day with respect to crypto.

It is mostly based on the Matasano/Cryptopals challenges, because they lead you
by the hand down the garden path to breaking a good number of common
cryptographic vulnerabilities.

NB: These will probably never be finished

Add `--tag ~slow` to your `.rspec` file if you don't want to run slow tests.

## Cryptopals progress

### Set 1: Basics
* [x] Convert hex to base64
* [x] Fixed XOR
* [x] Single-byte XOR cipher
* [x] Detect single-character XOR
* [x] Implement repeating-key XOR
* [x] Break repeating-key XOR
* [x] AES in ECB mode
* [x] Detect AES in ECB mode

### Set 2: Block crypto
* [x] Implement PKCS#7 padding
* [x] Implement CBC mode
* [x] An ECB/CBC detection oracle
* [x] Byte-at-a-time ECB decryption (Simple)
* [x] ECB cut-and-paste
* [x] Byte-at-a-time ECB decryption (Harder)
* [x] PKCS#7 padding validation
* [x] CBC bitflipping attacks

### Set 3: Block & stream crypto
* [x] The CBC padding oracle
* [x] Implement CTR, the stream cipher mode
* [x] Break fixed-nonce CTR mode using substitutions
* [x] Break fixed-nonce CTR statistically
* [x] Implement the MT19937 Mersenne Twister RNG
* [x] Crack an MT19937 seed
* [x] Clone an MT19937 RNG from its output
* [x] Create the MT19937 stream cipher and break it

### Set 4: Stream crypto & randomness
* [x] Break "random access read/write" AES CTR
* [x] CTR bitflipping
* [x] Recover the key from CBC with IV=Key
* [x] Implement a SHA-1 keyed MAC
* [x] Break a SHA-1 keyed MAC using length extension
* [x] Break an MD4 keyed MAC using length extension
* [x] Implement and break HMAC-SHA1 with an artificial timing leak
    * See [timing_attack](https://github.com/ffleming/timing_attack) for a timing attack tool
    * See [camelflage](https://github.com/ffleming/camelflage) for the vulnerable server
* [x] Break HMAC-SHA1 with a slightly less artificial timing leak
    * See [timing_attack](https://github.com/ffleming/timing_attack) for a timing attack tool
    * See [camelflage](https://github.com/ffleming/camelflage) for the vulnerable server

### Set 5: Diffie-Hellman & friends
* [x] Implement Diffie-Hellman
* [x] Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
* [x] Implement DH with negotiated groups, and break with malicious "g" parameters
* [x] Implement Secure Remote Password (SRP)
* [x] Break SRP with a zero key
* [x] Offline dictionary attack on simplified SRP
* [x] Implement RSA
* [x] Implement an E=3 RSA Broadcast attack

### Set 6: RSA & DSA
* [x] Implement unpadded message recovery oracle
* [x] Bleichenbacher's e=3 RSA Attack
* [x] DSA key recovery from nonce
* [x] DSA nonce recovery from repeated nonce
* [x] DSA parameter tampering
* [x] RSA parity oracle
* [x] Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
* [x] Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

### Set 7: Hashes
* [ ] CBC-MAC Message Forgery
* [ ] Hashing with CBC-MAC
* [ ] Compression Ratio Side-Channel Attacks
* [ ] Iterated Hash Function Multicollisions
* [ ] Kelsey and Schneier's Expandable Messages
* [ ] Kelsey and Kohno's Nostradamus Attack
* [ ] MD4 Collisions
* [ ] RC4 Single-Byte Biases

### Set 8: Abstract Algebra
* [ ] Diffie-Hellman Revisited: Small Subgroup Confinement
* [ ] Pollard's Method for Catching Kangaroos
* [ ] Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks
* [ ] Single-Coordinate Ladders and Insecure Twists
* [ ] Duplicate-Signature Key Selection in ECDSA (and RSA)
* [ ] Key-Recovery Attacks on ECDSA with Biased Nonces
* [ ] Key-Recovery Attacks on GCM with Repeated Nonces
* [ ] Key-Recovery Attacks on GCM with a Truncated MAC
