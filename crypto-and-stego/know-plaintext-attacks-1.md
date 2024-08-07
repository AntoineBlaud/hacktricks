# Know Plaintext Attacks

The first crypto challenge of UMassCTF 2021 was "malware", where we were given a zip archive containing `malware.py` and `files.zip`, which when decompressed yielded `malware.py.enc`, `CTF-favicon.png.enc`, `shopping_list.txt.enc`, and `flag.txt.enc`. The contents of `malware.py` were

```
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii
import os

key = os.urandom(16)
iv = int(binascii.hexlify(os.urandom(16)), 16)

for file_name in os.listdir():
    data = open(file_name, 'rb').read()

    cipher = AES.new(key, AES.MODE_CTR, counter = Counter.new(128, initial_value=iv))
    
    enc = open(file_name + '.enc', 'wb')
    enc.write(cipher.encrypt(data))

    iv += 1
```

where it can be seen that each of the `*.enc` files are AES encrypted with CTR mode. For the ciphertext `malware.py.enc`, we have the known plaintext `malware.py`, so the type of this attack will be a known-plaintext attack.

### AES encryption with CTR mode

A good place to start learning about the cipher is in the documentation of the cryptography library you're using. In this case, it's the `pycryptodome` Python package. [The documentation describes the operation of the CTR mode as the exclusive-or of the plaintext with a keystream to obtain the ciphertext. The keystream itself is an AES encrypted sequence of counter blocks in ECB mode.](https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ctr-mode)

![.gitbook/assets/1664530363\_1458.svg](https://upload.wikimedia.org/wikipedia/commons/4/4d/CTR\_encryption\_2.svg)

Since we have one known plaintext-ciphertext pair, we can recover the keystream used to encrypt that pair by taking the exclusive-or of the plaintext and the ciphertext

$$
P\oplus C=P\oplus(P\oplus K)=K
$$

and if the same keystream was used to encrypt the other files, then we can take the exclusive-or of the ciphertext and the keystream to recover the plaintext

$$
C\oplus K=(P \oplus K)\oplus K=P
$$

of those other files, thus completing our known-plaintext attack. However, we require keystream reuse across files, and that necessitates a closer inspection of how the keystream is constructed. The keystream is an AES encryption in [ECB mode](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation#Electronic\_codebook\_\(ECB\)) of the counter blocks, and requires the encryption key, an initial counter value, and any additional random nonces to be appended or prepended to the counter as parameters. The counter block sequence is in the form

![.gitbook/assets/1664530363\_397.png](https://pycryptodome.readthedocs.io/en/latest/\_images/counter\_be.png)

and the program initializes the sequence using

```
counter = Counter.new(128, initial_value=iv)
```

[The documentation reveals that this initialization results in no random prefix or suffix nonce value for the counter block. In this case each counter block in the sequence consists entirely of the counter value.](https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#crypto-util-counter-module)

```
key = os.urandom(16)
iv = int(binascii.hexlify(os.urandom(16)), 16)
for file_name in os.listdir():
    # Encrypt file
    iv += 1
```

Since the same encryption key is used for all files and the initial counter value is incremented by one for each file, this means the same keystream is used for all files, except it is left-shifted by one block (16 bytes) for each file. This makes our [known-plaintext keystream-reuse attack](https://crypto.stackexchange.com/a/35225) possible.

### Decryption

The Python Standard Library documentation notes that `os.listdir()` [returns the files in arbitrary order](https://docs.python.org/3/library/os.html#os.listdir) so we do not know in what order the files were encrypted. Therefore we must recover the shift of the keystream for each file relative to the `malware.py`-`malware.py.enc` plaintext-ciphertext pair. Through trial and error of different 16-byte block shifts and inspection of the results for expected data we end up with the keystream shifts in blocks

| Encrypted File         | Shift (+L/+IV) |
| ---------------------- | -------------- |
| CTF-favicon.png.enc    | -1             |
| malware.py.enc         | 0              |
| shopping\_list.txt.enc | 1              |
| flag.txt.enc           | 2              |

and thus are able to decode the flag `UMASS{m4lw4re_st1ll_n33ds_g00d_c4ypt0}` in `flag.txt.enc` using

$$
C\oplus (K\ll 32\text{B})=(P \oplus (K\ll 32\text{B}))\oplus (K\ll 32\text{B})=P
$$

as well as the other files using their respective keystream shifts. It also should be noted that the plaintext of `CTF-favicon.png.enc` which was not provided in the zip archive could be obtained from the favicon of the UMassCTF 2021 website, but it was not necessary to obtain more plaintext in this case.

### Detailed solution code and work

```
import os
import binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util import strxor


# Proof of concept:
# When initial value is incremented for ciphertext 2, shift keystream backward one block.
# That is, the second keystream is just the first one left shifted by one block (16 bytes).
key = os.urandom(16)
iv = int(binascii.hexlify(os.urandom(16)), 16)
plain1 = bytes('the quick brown fox jumped over the lazy dog', 'ascii')
plain2 = bytes('dog lazy the over jumped fox brown quick the', 'ascii')
aes1 = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))
aes2 = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv+1))
cipher1 = aes1.encrypt(plain1)
cipher2 = aes2.encrypt(plain2)[:]
keystream1 = strxor.strxor(cipher1, plain1)[16:]
keystream2 = strxor.strxor(cipher2, plain2)

# Keystream recovery:
# Recover the keystream from the malware.
malware_plain = open('malware.py', 'rb').read()
malware_cipher = open('files/malware.py.enc', 'rb').read()
malware_keystream = strxor.strxor(malware_cipher, malware_plain)

# Shift keystream on files:
icon_keystream = malware_keystream[:]
icon_cipher = open('files/CTF-favicon.png.enc', 'rb').read()[16:][:len(icon_keystream)]
icon_plain = strxor.strxor(icon_cipher, icon_keystream)
# I had to shift the keystream forwards by one block to decode the icon ciphertext.
# The decoding was confirmed by the sighting of the "iCCP" chunk of the PNG specification
# "iCCPICC Profile\x00\x00" which means there is a zlib-compressed embedded ICC profile.
# Since keystream was shifted forwards by one block, the iv is decremented from the malware.
# So, os.listdir() had returned "CTF-favicon.png" immediately before "malware.py".
# Now trying the shopping list:
shopping_cipher = open('files/shopping_list.txt.enc', 'rb').read()
shopping_keystream = malware_keystream[16:][:len(shopping_cipher)]
shopping_plain = strxor.strxor(shopping_cipher, shopping_keystream)
# I had to shift the keystream backwards by one block to decode the shopping ciphertext.
# The decoding was confirmed by seeing the list contents are "Soul's Shopping List".
# This means the iv is incremented from the malware.
# So, the flag must be either iv+2 or iv-2 from the malware.
flag_cipher = open('files/flag.txt.enc', 'rb').read()
flag_keystream = malware_keystream[32:][:len(flag_cipher)]
flag_plain = strxor.strxor(flag_cipher, flag_keystream)
# The flag is found (iv+2 from the malware).
print(flag_plain.decode('ascii'))
```
