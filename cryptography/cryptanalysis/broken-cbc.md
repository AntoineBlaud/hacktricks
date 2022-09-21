# Broken CBC

**CBC Mode**

In [CBC](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation#Cipher\_Block\_Chaining\_.28CBC.29) mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This way, each ciphertext block depends on all plaintext blocks processed up to that point. To make each message unique, an initialization vector (IV) must be used in the first block.

### **Predictable IV Attack**

In a CBC Encryption oracle, If you can predict the IV for the next message (or simply it’s a fixed IV) you can verify if a previous ciphertext comes from a guess plaintext.

You have a ciphertext block `C1` and it’s IV `IV1`, you want know if that is the encryption of the plaintext `P1`.\
If you can predict the next IV (`IV2`), you can made up your plaintext like: `P2 = P1 ⊕ IV1 ⊕ IV2`.\
So you can send this new message to the server that encrypt it this way:\
`C2 = Enc(k,IV2 ⊕ P2)` but with the forged `P2` this become\
`C2 = Enc(k,IV2 ⊕ P1 ⊕ IV1 ⊕ IV2) = Enc(k,P1 ⊕ IV1)`.

`C2 == C1` only if you have guessed `P1`.

### **IV Recovery**

(aka. key used as the IV)

IV is not meant to be secret, because you can easily recover it.

If you have a ciphertext block, you can recover the key by letting someone decrypt `C = C1 || Z || C1` (where `Z` is a block filled with null/`0` bytes)\
The decrypted blocks are the following

```
P1 = D(k, C1) ⊕ IV = D(k, C1) ⊕ k = P1
P2 = D(k, Z) ⊕ C1 = R
P3 = D(k, C1) ⊕ Z = D(k, C1) = P1 ⊕ IV
```

`R` is a random block that we can throw away. Finally we can recover the IV with `P1 ⊕ P2 = P1 ⊕ P1 ⊕ IV = IV`

### **Bit Flipping attack**

![CBC BitFlip](.gitbook/assets/1663772255.png)

Note that if we XOR a ciphertext block, the next plaintext block will be XORed as well (X propagates like in the image).

If you have control over the plaintext `P`, you can fill a block `P[i]` with filler data `Z` that will be encrypted.\
Once it’s encrypted you must find that ciphertext block `C[i]` and replace it with a XORed version of `C[i]`, `Z` and your desired value `G`, like `X = C[i] ⊕ Z ⊕ G`. When the server will decrypt the ciphertext, will get a different plaintext `P’` where `P’[i]` will be indecipherable nonsense, but `P’[i+1]` will be your desided value `G`.

```
P’[i+1] = P[i+1] ⊕ X
        = P[i+1] ⊕ Z ⊕ G
        = Z ⊕ Z ⊕ G
        = G
```

e.g. This scenario is common in website where cookies that are stored encrypted in the client and the server will decrypt them for every request.\
You can select a very long username or password that will act as `Z` and set `G` to something like `;admin=true;`. :wink:

**Padding oracle attack**

This vulnerability is possible because CBC is a malleable cipher (as seen in the bitflip attack).\
If we make a small change in the ciphertext, when decrypted the resulting plaintext will have that same change.

This is not a strictly crypto vulnerability, but an implementation flaw.

The target is vulnerable if:

* Uses a flawed padding method (like PKCS#5, PKCS#7, or everything else… _Developers, please use HMAC_)
* The implementation leaks information about valid/invalid padding

If the implementation is vulnerable, upon decryption we should have 3 cases:

**Case 1**\
Valid ciphertext - Implementation works correctly\
The ciphertext decrypts to the plaintext `tom` that is a valid user.

**Case 2**\
Invalid ciphertext - Error about invalid plaintext\
The ciphertext decrypts to the plaintext `aw89d` that is an invalid user. Error reported for invalid user.

**Case 3**\
Valid ciphertext with incorrect padding - Error about incorrect padding\
The ciphertext decrypts to the plaintext `sam` that is a valid user but decryption fail as padding is incorrect.\
The implementation leaks some information about this specific error.

We will assume PKCS#5 is used, so the final block of plaintext is padded with `N` bytes of value `N`.\
If the block is full, append another block full of padding (`N = blocksize`).

Keep in mind the CBC decryption scheme.

```
P1 = D(C1) ⊕ IV 
P2 = D(C2) ⊕ C1
```

The padding will be placed at the end of `P2`. If we bitflip the last byte in `C1`, the last byte in `P2` will be flipped as well.

For convenience it’s better to work with the last 2-block of ciphertext, you can strip the previous one since we are working on recovering the last block backwards.

The objective is to recover `D(C2)`, xoring it with `C1` will give us `P2`.

Let `Z` be a block filled with null/`0` bytes and `||` a byte concatenation function,\
We start by submitting to the decryption-oracle (the decryption function) the input `C`

```
C = Z || C2
P'1 = D(Z) ⊕ IV
P'2 = D(C2) ⊕ Z
P'2 = D(C2)
```

For example

```
Z = 0x00000000
C2 = 0x4525535F
C = Z || C2 = 0x000000004525535F
P'2 = 0x0A72CE92
```

The implementation will decrypt this input, check the last byte of `P'2` and report an invalid padding error.

We can try all the values from `0` to `255` as the last byte in `Z`.\
The only input accepted without the padding error will be the value that decrypt to `0x01` (a padding of 1 byte).

Now that we have recovered the last byte of `D(C2)` and we can xor it with the last byte of `C1` to get the last byte of `P2`.

We repeat this steps backwards for all the length of `Z` to retrive the full `D(C2)` and `P2` next,\
finally we can also repeat this process block-by-block to recover the full plaintext `P`.

I developed a [python program and library](https://github.com/dzonerzy/simsalapad) to automatically perform Padding Oracle attack.\
Alternatively you can use [PadBuster](https://github.com/GDSSecurity/PadBuster).

This attack can easily be prevented by checks that the ciphertexts are valid before decrypting them, by using encrypt-then-MAC or AE/AEAD.
