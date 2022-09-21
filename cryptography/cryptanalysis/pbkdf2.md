# PBKDF2

[In](https://www.wikiwand.com/en/Independent\_politician) [cryptography](https://www.wikiwand.com/en/Cryptography), **PBKDF1** and **PBKDF2** (**Password-Based Key Derivation Function 1** and **2**) are [key derivation functions](https://www.wikiwand.com/en/Key\_derivation\_function) with a sliding computational cost, used to reduce vulnerabilities of [brute-force attacks](https://www.wikiwand.com/en/Brute-force\_attack).[\[1\]](https://www.wikiwand.com/en/PBKDF2#citenoteRFC39621)

PBKDF2 is part of [RSA Laboratories](https://www.wikiwand.com/en/RSA\_Laboratories)' [Public-Key Cryptography Standards](https://www.wikiwand.com/en/Public-Key\_Cryptography\_Standards) (PKCS) series, specifically PKCS #5 v2.0, also published as [Internet Engineering Task Force](https://www.wikiwand.com/en/Internet\_Engineering\_Task\_Force)'s RFC 2898. It supersedes PBKDF1, which could only produce derived keys up to 160 bits long.[\[2\]](https://www.wikiwand.com/en/PBKDF2#citenote2) RFC 8018 (PKCS #5 v2.1), published in 2017, recommends PBKDF2 for password hashing.[\[3\]](https://www.wikiwand.com/en/PBKDF2#citenote3)

### Purpose and operation

PBKDF2 applies a [pseudorandom function](https://www.wikiwand.com/en/Pseudorandom\_function), such as [hash-based message authentication code](https://www.wikiwand.com/en/Hash-based\_message\_authentication\_code) (HMAC), to the input [password](https://www.wikiwand.com/en/Password) or [passphrase](https://www.wikiwand.com/en/Passphrase) along with a [salt](https://www.wikiwand.com/en/Salt\_\(cryptography\)) value and repeats the process many times to produce a _derived key_, which can then be used as a [cryptographic key](https://www.wikiwand.com/en/Key\_\(cryptography\)) in subsequent operations. The added computational work makes [password cracking](https://www.wikiwand.com/en/Password\_cracking) much more difficult, and is known as [key stretching](https://www.wikiwand.com/en/Key\_stretching).

When the standard was written in the year 2000 the recommended minimum number of iterations was 1,000, but the parameter is intended to be increased over time as CPU speeds increase. A Kerberos standard in 2005 recommended 4,096 iterations;[\[1\]](https://www.wikiwand.com/en/PBKDF2#citenoteRFC39621) Apple reportedly used 2,000 for iOS 3, and 10,000 for iOS 4;[\[4\]](https://www.wikiwand.com/en/PBKDF2#citenote4) while LastPass in 2011 used 5,000 iterations for JavaScript clients and 100,000 iterations for server-side hashing.[\[5\]](https://www.wikiwand.com/en/PBKDF2#citenote5) In 2021, OWASP recommended to use 310,000 iterations for PBKDF2-HMAC-SHA256 and 120,000 for PBKDF2-HMAC-SHA512.[\[6\]](https://www.wikiwand.com/en/PBKDF2#citenote6)

![Algorithmic representation of the iterative process of the Password-Based Key Derivation Function 2.](.gitbook/assets/1663772257.png)Algorithmic representation of the iterative process of the Password-Based Key Derivation Function 2.

Having a salt added to the password reduces the ability to use precomputed hashes ([rainbow tables](https://www.wikiwand.com/en/Rainbow\_tables)) for attacks, and means that multiple passwords have to be tested individually, not all at once. The standard recommends a salt length of at least 64 bits.[\[7\]](https://www.wikiwand.com/en/PBKDF2#citenoteRFC8018s47) The US National Institute of Standards and Technology recommends a salt length of 128 bits.[\[8\]](https://www.wikiwand.com/en/PBKDF2#citenote8)

### Key derivation process

The PBKDF2 key derivation function has five input parameters:[\[9\]](https://www.wikiwand.com/en/PBKDF2#citenoterfc28989)

DK = PBKDF2(PRF, Password, Salt, c, dkLen)

where:

* PRF is a pseudorandom function of two parameters with output length hLen (e.g., a keyed HMAC)
* Password is the master password from which a derived key is generated
* Salt is a sequence of bits, known as a [cryptographic salt](https://www.wikiwand.com/en/Salt\_\(cryptography\))
* c is the number of iterations desired
* dkLen is the desired bit-length of the derived key
* DK is the generated derived key

Each hLen-bit block Ti of derived key DK, is computed as follows (with + marking string concatenation):

DK = T1 + T2 + ⋯ + Tdklen/hlenTi = F(Password, Salt, c, i)

The function F is the [xor](https://www.wikiwand.com/en/Xor) (^) of _c_ iterations of chained PRFs. The first iteration of PRF uses _Password_ as the PRF key and _Salt_ concatenated with i encoded as a big-endian 32-bit integer as the input. (Note that _i_ is a 1-based index.) Subsequent iterations of PRF use _Password_ as the PRF key and the output of the previous PRF computation as the input:

F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc

where:

U1 = PRF(Password, Salt + INT\_32\_BE(i))U2 = PRF(Password, U1)⋮Uc = PRF(Password, Uc−1)

For example, [WPA2](https://www.wikiwand.com/en/WPA2) uses:

DK = PBKDF2(HMAC−SHA1, passphrase, ssid, 4096, 256)

PBKDF1 had a simpler process: the initial _U_ (called _T_ in this version) is created by PRF(Password + Salt), and the following ones are simply PRF(Uprevious). The key is extracted as the first _dkLen_ bits of the final hash, which is why there is a size limit.[\[9\]](https://www.wikiwand.com/en/PBKDF2#citenoterfc28989)
