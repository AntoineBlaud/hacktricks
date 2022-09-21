# AES

This was the first crypto task of SwampCTF called “We Three Keys”.

```
#!/usr/bin/env python2
from Crypto.Cipher import AES
from keys import key1, key2, key3

def pkcs7_pad(msg):
    val = 16 - (len(msg) % 16)
    if val == 0:
        val = 16
    pad_data = msg + (chr(val) * val)
    return pad_data

def encrypt_message(key, IV):
    print("What message woud you like to encrypt (in hex)?")
    ptxt = raw_input("<= ")
    ptxt = pkcs7_pad(ptxt.decode('hex'))
    cipher = AES.new(key, AES.MODE_CBC, IV)
    ctxt = cipher.encrypt(ptxt)
    print ctxt.encode('hex')

def decrypt_message(key, IV):
    print("What message would you like to decrypt (in hex)?")
    ctxt = raw_input("<= ")
    ctxt = ctxt.decode('hex')
    if (len(ctxt) % 16) != 0:
        print "What a fake message, I see through your lies"
        return
    cipher = AES.new(key, AES.MODE_CBC, IV)
    ptxt = cipher.decrypt(ctxt)
    print ptxt.encode('hex')

def new_key():
    print("Which key would you like to use now? All 3 are great")
    key_opt = str(raw_input("<= "))
    if key_opt == "1":
        key = key1
    elif key_opt == "2":
        key = key2
    elif key_opt == "3":
        key = key3
    else:
        print("Still no, pick a real key plz")
        exit()
    return key

def main():
    print("Hello! We present you with the future kings, we three keys!")
    print("Pick your key, and pick wisely!")
    key_opt = str(raw_input("<= "))
    if key_opt == "1":
        key = key1
    elif key_opt == "2":
        key = key2
    elif key_opt == "3":
        key = key3
    else:
        print("Come on, I said we have 3!")
        exit()
    while True:
        print("1) Encrypt a message")
        print("2) Decrypt a message")
        print("3) Choose a new key")
        print("4) Exit")
        choice = str(raw_input("<= "))
        if choice == "1":
            encrypt_message(key, key)
        elif choice == "2":
            decrypt_message(key, key)
        elif choice == "3":
            key = new_key()
        else:
            exit()


if __name__=='__main__':
    main()
```

So far so good, even the first challenge looks like some actual cryptography and not some “hurr durr caesar base64 vigenere” kind of bullshit (I swear I’m not such a hater in real life).

If you are a crypto beginner and have trouble following along this post, don’t worry. I have planned another article about cryptography basics, I have no idea when it will come out but it will at some point. Stay tuned !

I’m already digressing, great. The python code is pretty straightforward without any obfuscation, it uses the common package PyCrypto. We can already sense this challenge will be pure crypto, without much reverse engineering. I believe that the right mix of crypto and reverse makes for the best CTF challenges on earth, but is hard to achieve.

We can see the code uses AES, which is a famous cryptographic function. But the most important part here is the use of `AES.MODE_CBC`, which is where the vulnerability lies. I reckon I’ve probably lost half of the readers by talking about AES and CBC, so let’s backtrack a little and explain what these two words mean.

### AES - Advanced Encryption Standard

This is probably the only encryption algorithm that is used more than RSA (both are extremely useful but do not serve the same purposes). AES has two main defining properties :

* **Block cipher** : This algorithm takes a fixed size input (in this case, 16 bytes) called the plaintext, and spits an output of the same size called the ciphertext. If you’re familiar with RSA, that one isn’t a block cipher because it accepts ciphertexts of any size smaller than it modulus.
* **Symmetric** : It means that the same key is used for both encryption and decryption.

Here is a visualization of how AES encrypts one block of data.

![.gitbook/assets/1663786910.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786909/tbvsv1ewvzzfqwv3uxlr.png)

Note that the output data looks like random noise, and that’s the point of the encryption. If there were any information in the output that could lead to information about the input, the algorithm is broken. Luckily, AES isn’t broken (yet), so the output bytes seem completely random.

The inverse operation takes a ciphertext and the key, and outputs the original plaintext. It’s impossible (if used correctly) to guess the original plaintext without having the key.

![.gitbook/assets/1663786911.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786910/kv7qeqxhqoaiqoqiqfyz.png)

It’s safe to assume in CTFs that we are not breaking the AES algorithm itself, but rather its implementation (choice of keys, compression, padding, …). Actually, AES is only a building block of the challenge, but we should be focusing on entering through open doors instead of breaking through the concrete walls. Remember the `AES.MODE_CBC` ? It defines how the data is actually encrypted with the block cipher. Let’s have a deeper look into it.

### Block cipher modes of operation

When operating with a block cipher, we need to cut the data in individual pieces and encrypt them because AES can only encrypt 16 bytes at a time.

Well, that’s quite easy isn’t it ? We can simply break the text into smaller chunks of 16 bytes and encrypt them one by one ! Congratulations, we just invented something called ECB.

**ECB - Electronic Codebook**

ECB is the retarded cousin of CBC, and here’s why: let’s imagine we are encrypting the message `Today's code: 4975384264852. Bye` using AES-ECB and sharing it with an ally :

![.gitbook/assets/1663786913.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786912/rq96yngynhzwyfmh2ron.png)

In this case the encryption is done correctly, and there is no way for an enemy intercepting the encrypted message to recover the ciphertext. However, fast forward a few weeks, we’re sending a different code `Today's code: 4935412269921. Bye` encrypted with the same key.

![.gitbook/assets/1663786914.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786913/gkuceht6aiu7g8pnjvdg.png)

If you have a closer look at the ciphertext on the left, you will notice it’s exactly the same as the previous one because the block’s input is the same ! This might reveal some precious information on your code (in this case, the first 2 digits of the code) if someone intercepts the ciphertext and has enough information about older plaintexts. The supposedly perfect cryptosystem we invented has turned into a mediocre cryptosystem which can leak information. Using ECB is the easiest and fastest way to encrypt long plaintexts with block ciphers, but it’s recommended to use another way of chaining blocks, such as CBC.

**CBC - Cipher Block Chaining**

I’ve talked about CBC enough that you must be dying to know what it’s all about. It’s time for me to reveal the ingredients to the CBC secret sauce that holds all the blocks together !

It’s actually quite simple : a random value (called the initialization vector or IV) is mixed with the first plaintext before encryption. Then, we mix the first ciphertext with the second plaintext and encrypt the mix, then the second ciphertext with the third plaintext, and so on.

In practice, the mixing is done with XOR, which is a reversible transformation. If the IV is chosen randomly and never reused, the cascading property (aka butterfly effect in cryptography) of AES makes the cipher unbreakable.

![.gitbook/assets/1663786914.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786913/wwj9tp7ndelchsg9lusc.png)

The IV is transmitted along with the ciphertext, making each transmission 16 bytes longer.

**CBC decryption**

The decryption algorithm is more complicated than the straightforward block-per-block ECB decryption, but we can understand how to reverse the operations made in the encryption. The mixing operation has to be reversible, because we need to untangle the ciphertext and the plaintext from the AES decryption’s output.

XOR has several properties (for example, XOR is its own inverse, and 0 is its neutral element). This means that if we XOR the decrypted data (equal to `plaintext_block[i] xor ciphertext_block[i-1]`) with `ciphertext_block[i-1]`, we get

`(plaintext_block[i] xor ciphertext_block[i-1]) xor ciphertext_block[i-1]`

`= plaintext_block[i] xor (ciphertext_block[i-1] xor ciphertext_block[i-1])`

`= plaintext_block[i] xor 0`

`= plaintext_block[i]`

So we have successfully recovered the plaintext. The full operation is detailed here :

![.gitbook/assets/1663786915.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786914/hdbz5ddmawofr4d5mzof.png)

Now, we have all the knowledge needed to find an attack on the cryptosystem.

I won’t get into PKCS7 padding which is also implemented in the challenge. The only thing you need to know about PKCS7 is that it’s used to make the ciphertext length a multiple of 16 so the data can nicely be split into blocks without the last one being too short.

### Applied attack on bad AES-CBC

Now if you remember what I said, the IV has to be chosen perfectly at random and never reused. But have a look at the implementation :

```
def encrypt_message(key, IV):
    print("What message woud you like to encrypt (in hex)?")
    ptxt = raw_input("<= ")
    ptxt = pkcs7_pad(ptxt.decode('hex'))
    cipher = AES.new(key, AES.MODE_CBC, IV)
    ctxt = cipher.encrypt(ptxt)
    print ctxt.encode('hex')
    
# (later in the source)
encrypt_message(key, key)
```

Not only is the IV reused for all messages, it also contains a value that should be kept secret ! To attack this, we don’t even need to use the encrypt function - let’s look at what happens if we decrypt a made-up ciphertext full of null bytes :

![.gitbook/assets/1663786916.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786915/zp1fwziwzumnuqy7iypv.png)

Since the only thing that determines the output of AES encryption/decryption is the data and the key, all three AES decryption blocks output the same data.

However, outputs 1, 2 and 3 are different because they are not XORed with the same values, but the data which exits each block is exactly the same.

Output 1 corresponds to `decryptAES(0000000000000000, key) xor IV`, whereas outputs 2 and 3 are `decryptAES(0000000000000000, key) xor 0000000000000000`. Let’s verify in practice that output 2 and 3 are equal (I added spaces between blocks for clarity).

```
$ nc chal1.swampctf.com 1441

Hello! We present you with the future kings, we three keys!
Pick your key, and pick wisely!
<= 1
1) Encrypt a message
2) Decrypt a message
3) Choose a new key
4) Exit
<= 2
What message would you like to decrypt (in hex)?
<= 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000
9c53fc4f03020389898c77d7cdaa0f74 fa3f9d28787533fed6fb1fe3b9f56340 fa3f9d28787533fed6fb1fe3b9f56340
```

The value of `decryptAES(0000000000000000, key)` is not predictable, even with such a special input. However, we can use properties of XOR to recover the IV. If we XOR the first two output blocks, the result will be

`Output1 xor Output2 = (decryptAES(0000000000000000, key) xor IV) xor (decryptAES(0000000000000000, key) xor 0000000000000000)`

XORing with zeros does nothing (0 is the identity element of XOR), so we have

`Output1 xor Output2 = (decryptAES(0000000000000000, key) xor IV) xor decryptAES(0000000000000000, key)`

`Output1 xor Output2 = IV xor decryptAES(0000000000000000, key) xor decryptAES(0000000000000000, key)`

`Output1 xor Output2 = IV xor (decryptAES(0000000000000000, key) xor decryptAES(0000000000000000, key))`

`Output1 xor Output2 = IV xor 0000000000000000`

`Output1 xor Output2 = IV`

By XORing the first two output blocks, we can successfully recover the Initialization Vector which contains a secret value. The only thing left to do is convert it back to a printable string :

```
o1 = '9c53fc4f03020389898c77d7cdaa0f74'
o2 = 'fa3f9d28787533fed6fb1fe3b9f56340'

flag = ''
for i in range(0,32,2):
    flag += chr(int(o1[i:i+2],16)^int(o2[i:i+2],16))
print flag
```

Rinse and repeat for the two other keys, and we get the whole flag : `flag{w0w_wh4t_l4zy_k3yz_much_w34k_crypt0_f41ls!}`

``

In cryptography, a **block cipher mode of operation** is an algorithm that uses a [block cipher](https://www.wikiwand.com/en/Block\_cipher) to provide [information security](https://www.wikiwand.com/en/Information\_security) such as [confidentiality](https://www.wikiwand.com/en/Confidentiality) or [authenticity](https://www.wikiwand.com/en/Authentication).[\[1\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteNISTBLOCKCIPHERMODES1) A block cipher by itself is only suitable for the secure cryptographic transformation (encryption or decryption) of one fixed-length group of [bits](https://www.wikiwand.com/en/Bit) called a [block](https://www.wikiwand.com/en/Block\_\(data\_storage\)).[\[2\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteFERGUSON2) A mode of operation describes how to repeatedly apply a cipher's single-block operation to securely transform amounts of data larger than a block.[\[3\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteNISTPROPOSEDMODES3)[\[4\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteHAC4)[\[5\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteISO101165)

Most modes require a unique binary sequence, often called an [initialization vector](https://www.wikiwand.com/en/Initialization\_vector) (IV), for each encryption operation. The IV has to be non-repeating and, for some modes, random as well. The initialization vector is used to ensure distinct [ciphertexts](https://www.wikiwand.com/en/Ciphertext) are produced even when the same [plaintext](https://www.wikiwand.com/en/Plaintext) is encrypted multiple times independently with the same [key](https://www.wikiwand.com/en/Key\_\(cryptography\)).[\[6\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote6) Block ciphers may be capable of operating on more than one [block size](https://www.wikiwand.com/en/Block\_size\_\(cryptography\)), but during transformation the block size is always fixed. Block cipher modes operate on whole blocks and require that the last part of the data be [padded](https://www.wikiwand.com/en/Padding\_\(cryptography\)) to a full block if it is smaller than the current block size.[\[2\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteFERGUSON2) There are, however, modes that do not require padding because they effectively use a block cipher as a [stream cipher](https://www.wikiwand.com/en/Stream\_cipher).

Historically, encryption modes have been studied extensively in regard to their error propagation properties under various scenarios of data modification. Later development regarded [integrity protection](https://www.wikiwand.com/en/Integrity\_protection) as an entirely separate cryptographic goal. Some modern modes of operation combine [confidentiality](https://www.wikiwand.com/en/Confidentiality) and [authenticity](https://www.wikiwand.com/en/Authentication) in an efficient way, and are known as [authenticated encryption](https://www.wikiwand.com/en/Authenticated\_encryption) modes.[\[7\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteNISTCURRENTMODES7)

### History and standardization

The earliest modes of operation, ECB, CBC, OFB, and CFB (see below for all), date back to 1981 and were specified in [FIPS 81](http://csrc.nist.gov/publications/fips/fips81/fips81.htm), _DES Modes of Operation_. In 2001, the US [National Institute of Standards and Technology](https://www.wikiwand.com/en/National\_Institute\_of\_Standards\_and\_Technology) (NIST) revised its list of approved modes of operation by including [AES](https://www.wikiwand.com/en/Advanced\_Encryption\_Standard) as a block cipher and adding CTR mode in [SP800-38A](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf), _Recommendation for Block Cipher Modes of Operation_. Finally, in January, 2010, NIST added [XTS-AES](https://www.wikiwand.com/en/Disk\_encryption\_theory#XEX-based\_tweaked-codebook\_mode\_with\_ciphertext\_stealing\_\(XTS\)) in [SP800-38E](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38e.pdf), _Recommendation for Block Cipher Modes of Operation: The XTS-AES Mode for Confidentiality on Storage Devices_. Other confidentiality modes exist which have not been approved by NIST. For example, CTS is [ciphertext stealing](https://www.wikiwand.com/en/Ciphertext\_stealing) mode and available in many popular cryptographic libraries.

The block cipher modes ECB, CBC, OFB, CFB, CTR, and [XTS](https://www.wikiwand.com/en/XTS\_mode) provide confidentiality, but they do not protect against accidental modification or malicious tampering. Modification or tampering can be detected with a separate [message authentication code](https://www.wikiwand.com/en/Message\_authentication\_code) such as [CBC-MAC](https://www.wikiwand.com/en/CBC-MAC), or a [digital signature](https://www.wikiwand.com/en/Digital\_signature). The cryptographic community recognized the need for dedicated integrity assurances and NIST responded with HMAC, CMAC, and GMAC. [HMAC](https://www.wikiwand.com/en/HMAC) was approved in 2002 as [FIPS 198](http://csrc.nist.gov/publications/fips/fips198/fips-198a.pdf), _The Keyed-Hash Message Authentication Code (HMAC)_, [CMAC](https://www.wikiwand.com/en/CMAC) was released in 2005 under [SP800-38B](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf), _Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication_, and [GMAC](https://www.wikiwand.com/en/Galois/Counter\_Mode) was formalized in 2007 under [SP800-38D](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf), _Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC_.

The cryptographic community observed that compositing (combining) a confidentiality mode with an authenticity mode could be difficult and error prone. They therefore began to supply modes which combined confidentiality and data integrity into a single cryptographic primitive (an encryption algorithm). These combined modes are referred to as [authenticated encryption](https://www.wikiwand.com/en/Authenticated\_encryption), AE or "authenc". Examples of AE modes are [CCM](https://www.wikiwand.com/en/CCM\_mode) ([SP800-38C](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf)), [GCM](https://www.wikiwand.com/en/Galois/Counter\_Mode) ([SP800-38D](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)), [CWC](https://www.wikiwand.com/en/CWC\_mode), [EAX](https://www.wikiwand.com/en/EAX\_mode), [IAPM](https://www.wikiwand.com/en/IAPM\_\(mode\)), and [OCB](https://www.wikiwand.com/en/OCB\_mode).

Modes of operation are defined by a number of national and internationally recognized standards bodies. Notable standards organizations include [NIST](https://www.wikiwand.com/en/National\_Institute\_of\_Standards\_and\_Technology), [ISO](https://www.wikiwand.com/en/International\_Organization\_for\_Standardization) (with ISO/IEC 10116[\[5\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteISO101165)), the [IEC](https://www.wikiwand.com/en/International\_Electrotechnical\_Commission), the [IEEE](https://www.wikiwand.com/en/Institute\_of\_Electrical\_and\_Electronics\_Engineers), [ANSI](https://www.wikiwand.com/en/American\_National\_Standards\_Institute), and the [IETF](https://www.wikiwand.com/en/Internet\_Engineering\_Task\_Force).

### Initialization vector (IV)

An initialization vector (IV) or starting variable (SV)[\[5\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteISO101165) is a block of bits that is used by several modes to randomize the encryption and hence to produce distinct ciphertexts even if the same plaintext is encrypted multiple times, without the need for a slower re-keying process.\[[_citation needed_](https://www.wikiwand.com/en/Wikipedia:Citation\_needed)]

An initialization vector has different security requirements than a key, so the IV usually does not need to be secret. For most block cipher modes it is important that an initialization vector is never reused under the same key, i.e. it must be a [cryptographic nonce](https://www.wikiwand.com/en/Cryptographic\_nonce). Many block cipher modes have stronger requirements, such as the IV must be [random](https://www.wikiwand.com/en/Random) or [pseudorandom](https://www.wikiwand.com/en/Pseudorandom). Some block ciphers have particular problems with certain initialization vectors, such as all zero IV generating no encryption (for some keys).

It is recommended to review relevant IV requirements for the particular block cipher mode in relevant specification, for example [SP800-38A](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).

For CBC and CFB, reusing an IV leaks some information about the first block of plaintext, and about any common prefix shared by the two messages.

For OFB and CTR, reusing an IV causes key bitstream re-use, which breaks security.[\[8\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote8) This can be seen because both modes effectively create a bitstream that is XORed with the plaintext, and this bitstream is dependent on the key and IV only.

In CBC mode, the IV must be unpredictable ([random](https://www.wikiwand.com/en/Random) or [pseudorandom](https://www.wikiwand.com/en/Pseudorandom)) at encryption time; in particular, the (previously) common practice of re-using the last ciphertext block of a message as the IV for the next message is insecure (for example, this method was used by SSL 2.0). If an attacker knows the IV (or the previous block of ciphertext) before the next plaintext is specified, they can check their guess about plaintext of some block that was encrypted with the same key before (this is known as the TLS CBC IV attack).[\[9\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote9)

For some keys an all-zero initialization vector may generate some block cipher modes (CFB-8, OFB-8) to get internal state stuck at all-zero. For CFB-8, an all-zero IV and an all-zero plaintext, causes 1/256 of keys to generate no encryption, plaintext is returned as ciphertext.[\[10\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote10) For OFB-8, using all zero initialization vector will generate no encryption for 1/256 of keys.[\[11\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote11) OFB-8 encryption returns the plaintext unencrypted for affected keys.

Some modes (such as AES-SIV and AES-GCM-SIV) are built to be more nonce-misuse resistant, i.e. resilient to scenarios in which the randomness generation is faulty or under the control of the attacker.

* Synthetic Initialization Vector (SIV) synthesize an internal IV by running an Pseudo-Random Function (PRF) construction called S2V on the input (additional data and plaintext), preventing any external data from directly controlling the IV. External nonces / IV may be feed into S2V as an additional data field.
* AES-GCM-SIV synthesize an internal IV by running POLYVAL Galois mode of authentication on input (additional data and plaintext), followed by an AES operation.

### Padding

A [block cipher](https://www.wikiwand.com/en/Block\_cipher) works on units of a fixed [size](https://www.wikiwand.com/en/Block\_size\_\(cryptography\)) (known as a _block size_), but messages come in a variety of lengths. So some modes (namely [ECB](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#ECB) and [CBC](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#CBC)) require that the final block be padded before encryption. Several [padding](https://www.wikiwand.com/en/Padding\_\(cryptography\)) schemes exist. The simplest is to add [null bytes](https://www.wikiwand.com/en/Null\_character) to the [plaintext](https://www.wikiwand.com/en/Plaintext) to bring its length up to a multiple of the block size, but care must be taken that the original length of the plaintext can be recovered; this is trivial, for example, if the plaintext is a [C](https://www.wikiwand.com/en/C\_\(programming\_language\)) style [string](https://www.wikiwand.com/en/Literal\_string) which contains no null bytes except at the end. Slightly more complex is the original [DES](https://www.wikiwand.com/en/Data\_Encryption\_Standard) method, which is to add a single one [bit](https://www.wikiwand.com/en/Bit), followed by enough zero [bits](https://www.wikiwand.com/en/Bit) to fill out the block; if the message ends on a block boundary, a whole padding block will be added. Most sophisticated are CBC-specific schemes such as [ciphertext stealing](https://www.wikiwand.com/en/Ciphertext\_stealing) or [residual block termination](https://www.wikiwand.com/en/Residual\_block\_termination), which do not cause any extra ciphertext, at the expense of some additional complexity. [Schneier](https://www.wikiwand.com/en/Bruce\_Schneier) and [Ferguson](https://www.wikiwand.com/en/Niels\_Ferguson) suggest two possibilities, both simple: append a byte with value 128 (hex 80), followed by as many zero bytes as needed to fill the last block, or pad the last block with _n_ bytes all with value _n_.

CFB, OFB and CTR modes do not require any special measures to handle messages whose lengths are not multiples of the block size, since the modes work by [XORing](https://www.wikiwand.com/en/Exclusive\_or) the plaintext with the output of the block cipher. The last partial block of plaintext is XORed with the first few bytes of the last [keystream](https://www.wikiwand.com/en/Keystream) block, producing a final ciphertext block that is the same size as the final partial plaintext block. This characteristic of stream ciphers makes them suitable for applications that require the encrypted ciphertext data to be the same size as the original plaintext data, and for applications that transmit data in streaming form where it is inconvenient to add padding bytes.

### Common modes

#### Authenticated encryption with additional data (AEAD) modes

A number of modes of operation have been designed to combine [secrecy](https://www.wikiwand.com/en/Secrecy) and [authentication](https://www.wikiwand.com/en/Authentication) in a single cryptographic primitive. Examples of such modes are extended cipher block chaining (XCBC)\[[_clarification needed_](https://www.wikiwand.com/en/Wikipedia:Please\_clarify)],[\[12\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote12) integrity-aware cipher block chaining (IACBC)\[[_clarification needed_](https://www.wikiwand.com/en/Wikipedia:Please\_clarify)], [integrity-aware parallelizable mode](https://www.wikiwand.com/en/IAPM\_\(mode\)) (IAPM),[\[13\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote13) [OCB](https://www.wikiwand.com/en/OCB\_mode), [EAX](https://www.wikiwand.com/en/EAX\_mode), [CWC](https://www.wikiwand.com/en/CWC\_mode), [CCM](https://www.wikiwand.com/en/CCM\_mode), and [GCM](https://www.wikiwand.com/en/Galois/counter\_mode). [Authenticated encryption](https://www.wikiwand.com/en/Authenticated\_encryption) modes are classified as single-pass modes or double-pass modes. Some single-pass [authenticated encryption](https://www.wikiwand.com/en/Authenticated\_encryption) algorithms, such as [OCB mode](https://www.wikiwand.com/en/OCB\_mode), are encumbered by patents, while others were specifically designed and released in a way to avoid such encumberment.

In addition, some modes also allow for the authentication of unencrypted associated data, and these are called [AEAD](https://www.wikiwand.com/en/AEAD\_block\_cipher\_modes\_of\_operation) (authenticated encryption with associated data) schemes. For example, EAX mode is a double-pass AEAD scheme while OCB mode is single-pass.

**Galois/counter (GCM)**

| GCM                       |
| ------------------------- |
| Galois/counter            |
| Encryption parallelizable |
| Decryption parallelizable |
| Random read access        |

[Galois/counter mode](https://www.wikiwand.com/en/Galois/counter\_mode) (GCM) combines the well-known [counter mode](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#Counter\_\(CTR\)) of encryption with the new Galois mode of authentication. The key feature is the ease of parallel computation of the [Galois field](https://www.wikiwand.com/en/Galois\_field) multiplication used for authentication. This feature permits higher throughput than encryption algorithms.

GCM is defined for block ciphers with a block size of 128 bits. Galois message authentication code (GMAC) is an authentication-only variant of the GCM which can form an incremental message authentication code. Both GCM and GMAC can accept initialization vectors of arbitrary length. GCM can take full advantage of parallel processing and implementing GCM can make efficient use of an [instruction pipeline](https://www.wikiwand.com/en/Instruction\_pipeline) or a hardware pipeline. The CBC mode of operation incurs [pipeline stalls](https://www.wikiwand.com/en/Pipeline\_stall) that hamper its efficiency and performance.

Like in CTR, blocks are numbered sequentially, and then this block number is combined with an IV and encrypted with a block cipher E, usually AES. The result of this encryption is then XORed with the plaintext to produce the ciphertext. Like all counter modes, this is essentially a stream cipher, and so it is essential that a different IV is used for each stream that is encrypted.

![.gitbook/assets/1663786917.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786916/xuswt1xorubg1nu9nd2z.png)

The ciphertext blocks are considered coefficients of a [polynomial](https://www.wikiwand.com/en/Polynomial) which is then evaluated at a key-dependent point H, using [finite field arithmetic](https://www.wikiwand.com/en/Finite\_field\_arithmetic). The result is then encrypted, producing an authentication tag that can be used to verify the integrity of the data. The encrypted text then contains the IV, ciphertext, and authentication tag.

**Counter with cipher block chaining message authentication code (CCM)**

[_Counter with cipher block chaining message authentication code_](https://www.wikiwand.com/en/CCM\_mode) (counter with CBC-MAC; CCM) is an [authenticated encryption](https://www.wikiwand.com/en/Authenticated\_encryption) algorithm designed to provide both [authentication](https://www.wikiwand.com/en/Authentication) and [confidentiality](https://www.wikiwand.com/en/Confidentiality). CCM mode is only defined for block ciphers with a block length of 128 bits.[\[14\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteNISTSP80038C14)[\[15\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteRFC361015)

**Synthetic initialization vector (SIV)**

Synthetic initialization vector (SIV) is a nonce-misuse resistant block cipher mode.

SIV synthesizes an internal IV using the a pseudorandom function S2V. S2V is a keyed hash is based on CMAC, and the input to the function is:

* Additional authenticated data (zero, one or many AAD fields are supported)
* Plaintext
* Authentication key (K1).

SIV encrypts the S2V output and the plaintext using AES-CTR, keyed with the encryption key (K2).

SIV can support external nonce-based authenticated encryption, in which case one of the authenticated data fields is utilized for this purpose. RFC5297[\[16\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote16) specifies that for interoperability purposes the last authenticated data field should be used external nonce.

Owing to the use of two keys, the authentication key K1 and encryption key K2, naming schemes for SIV AEAD-variants may lead to some confusion; for example AEAD\_AES\_SIV\_CMAC\_256 refers to AES-SIV with two AES-128 keys and **not** AES-256.

**AES-GCM-SIV**

[AES-GCM-SIV](https://www.wikiwand.com/en/AES-GCM-SIV) is a mode of operation for the [Advanced Encryption Standard](https://www.wikiwand.com/en/Advanced\_Encryption\_Standard) which provides similar performance to [Galois/counter mode](https://www.wikiwand.com/en/Galois/counter\_mode) as well as misuse resistance in the event of the reuse of a [cryptographic nonce](https://www.wikiwand.com/en/Cryptographic\_nonce). The construction is defined in RFC 8452.[\[17\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote17)

AES-GCM-SIV synthesizes the internal IV. It derives a hash of the additional authenticated data and plaintext using the POLYVAL Galois hash function. The hash is then encrypted an AES-key, and used as authentication tag and AES-CTR initialization vector.

**AES-GCM-SIV** is an improvement over the very similarly named algorithm **GCM-SIV**, with a few very small changes (e.g. how AES-CTR is initialized), but which yields practical benefits to its security "This addition allows for encrypting up to 250 messages with the same key, compared to the significant limitation of only 232 messages that were allowed with GCM-SIV."[\[18\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote18)

#### Confidentiality only modes

Many modes of operation have been defined. Some of these are described below. The purpose of cipher modes is to mask patterns which exist in encrypted data, as illustrated in the description of the [weakness of ECB](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#ECB-weakness).

Different cipher modes mask patterns by cascading outputs from the cipher block or other globally deterministic variables into the subsequent cipher block. The inputs of the listed modes are summarized in the following table:

| Mode                  | Formulas | Ciphertext                                                   |                                           |
| --------------------- | -------- | ------------------------------------------------------------ | ----------------------------------------- |
| Electronic codebook   | (ECB)    | Y_i_ = F(PlainText_i_, Key)                                  | Yi                                        |
| Cipher block chaining | (CBC)    | Y_i_ = PlainText_i_ XOR Ciphertext_i_−1                      | F(Y, Key); Ciphertext0 = IV               |
| Propagating CBC       | (PCBC)   | Y_i_ = PlainText_i_ XOR (Ciphertext_i_−1 XOR PlainText_i_−1) | F(Y, Key); Ciphertext0 = IV               |
| Cipher feedback       | (CFB)    | Y_i_ = Ciphertext_i_−1                                       | Plaintext XOR F(Y, Key); Ciphertext0 = IV |
| Output feedback       | (OFB)    | Y_i_ = F(Y_i_−1, Key); Y0 = F(IV, Key)                       | Plaintext XOR Y_i_                        |
| Counter               | (CTR)    | Y_i_ = F(IV + _g_(_i_), Key); IV = token()                   | Plaintext XOR Y_i_                        |

Note: _g_(_i_) is any deterministic function, often the [identity function](https://www.wikiwand.com/en/Identity\_function).

**Electronic codebook (ECB)**

| ECB                       |
| ------------------------- |
| Electronic codebook       |
| Encryption parallelizable |
| Decryption parallelizable |
| Random read access        |

The simplest (and not to be used anymore) of the encryption modes is the **electronic codebook** (ECB) mode (named after conventional physical [codebooks](https://www.wikiwand.com/en/Codebook)[\[19\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote19)). The message is divided into blocks, and each block is encrypted separately.

![.gitbook/assets/1663786917.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786916/zogqcxhtnrn0psnlh4gc.png)

![.gitbook/assets/1663786918.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786917/cx5lpkck7znjgqxh3y1l.png)

The disadvantage of this method is a lack of [diffusion](https://www.wikiwand.com/en/Confusion\_and\_diffusion). Because ECB encrypts identical [plaintext](https://www.wikiwand.com/en/Plaintext) blocks into identical [ciphertext](https://www.wikiwand.com/en/Ciphertext) blocks, it does not hide data patterns well. ECB is not recommended for use in cryptographic protocols.[\[20\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote20)[\[21\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote21)[\[22\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote22)

A striking example of the degree to which ECB can leave plaintext data patterns in the ciphertext can be seen when ECB mode is used to encrypt a [bitmap image](https://www.wikiwand.com/en/Bitmap\_image) which uses large areas of uniform color. While the color of each individual [pixel](https://www.wikiwand.com/en/Pixel) is encrypted, the overall image may still be discerned, as the pattern of identically colored pixels in the original remains in the encrypted version.

![.gitbook/assets/1663786919.jpg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786918/hkfp93yydo4spsktrdy1.jpg)

Original image

![.gitbook/assets/1663786919.jpg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786918/hpji4e4nphkxwtkber3w.jpg)

Encrypted using ECB mode

![.gitbook/assets/1663786919.jpg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786919/zuvpliicmqtoupj6zit7.jpg)

Modes other than ECB result in pseudo-randomness

The third image is how the image might appear encrypted with CBC, CTR or any of the other more secure modes—indistinguishable from random noise. Note that the random appearance of the third image does not ensure that the image has been securely encrypted; many kinds of insecure encryption have been developed which would produce output just as "random-looking".\[[_citation needed_](https://www.wikiwand.com/en/Wikipedia:Citation\_needed)]

ECB mode can also make protocols without integrity protection even more susceptible to [replay attacks](https://www.wikiwand.com/en/Replay\_attack), since each block gets decrypted in exactly the same way.\[[_citation needed_](https://www.wikiwand.com/en/Wikipedia:Citation\_needed)]

**Cipher block chaining (CBC)**

| CBC                       |
| ------------------------- |
| Cipher block chaining     |
| Encryption parallelizable |
| Decryption parallelizable |
| Random read access        |

Ehrsam, Meyer, Smith and Tuchman invented the cipher block chaining (CBC) mode of operation in 1976.[\[23\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote23) In CBC mode, each block of plaintext is [XORed](https://www.wikiwand.com/en/XOR) with the previous ciphertext block before being encrypted. This way, each ciphertext block depends on all plaintext blocks processed up to that point. To make each message unique, an [initialization vector](https://www.wikiwand.com/en/Initialization\_vector) must be used in the first block.

![.gitbook/assets/1663786921.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786920/dubgayilmqxq4fwaablj.png)

![.gitbook/assets/1663786921.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786920/fp6xg1w67cvwki0239xq.png)

If the first block has index 1, the mathematical formula for CBC encryption is

![.gitbook/assets/1663786922.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786921/f9dhaasueps7lfgw9xxj.svg)

![.gitbook/assets/1663786924.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786923/i4tsyrpsfl5t2vrzqsx3.svg)

while the mathematical formula for CBC decryption is

![.gitbook/assets/1663786926.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786925/zlmda6nk7jwfconjgmuw.svg)

![.gitbook/assets/1663786928.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786927/yesgdd7bdfbnqxmmytyq.svg)

**Example**

![.gitbook/assets/1663786930.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786929/avsq1fzp8amjlv6lk8kp.png)

![.gitbook/assets/1663786930.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786930/myng5lxliui3bborasge.png)

CBC has been the most commonly used mode of operation. Its main drawbacks are that encryption is sequential (i.e., it cannot be parallelized), and that the message must be padded to a multiple of the cipher block size. One way to handle this last issue is through the method known as [ciphertext stealing](https://www.wikiwand.com/en/Ciphertext\_stealing). Note that a one-bit change in a plaintext or initialization vector (IV) affects all following ciphertext blocks.

Decrypting with the incorrect IV causes the first block of plaintext to be corrupt but subsequent plaintext blocks will be correct. This is because each block is XORed with the ciphertext of the previous block, not the plaintext, so one does not need to decrypt the previous block before using it as the IV for the decryption of the current one. This means that a plaintext block can be recovered from two adjacent blocks of ciphertext. As a consequence, decryption _can_ be parallelized. Note that a one-bit change to the ciphertext causes complete corruption of the corresponding block of plaintext, and inverts the corresponding bit in the following block of plaintext, but the rest of the blocks remain intact. This peculiarity is exploited in different [padding oracle attacks](https://www.wikiwand.com/en/Padding\_oracle\_attack), such as [POODLE](https://www.wikiwand.com/en/POODLE).

_Explicit initialization vectors_[\[24\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote24) takes advantage of this property by prepending a single random block to the plaintext. Encryption is done as normal, except the IV does not need to be communicated to the decryption routine. Whatever IV decryption uses, only the random block is "corrupted". It can be safely discarded and the rest of the decryption is the original plaintext.

**Propagating cipher block chaining (PCBC)**

| PCBC                              |
| --------------------------------- |
| Propagating cipher block chaining |
| Encryption parallelizable         |
| Decryption parallelizable         |
| Random read access                |

The _propagating cipher block chaining_[\[25\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote25) or _plaintext cipher-block chaining_[\[26\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote26) mode was designed to cause small changes in the ciphertext to propagate indefinitely when decrypting, as well as when encrypting. In PCBC mode, each block of plaintext is XORed with both the previous plaintext block and the previous ciphertext block before being encrypted. Like with CBC mode, an initialization vector is used in the first block.

![.gitbook/assets/1663786932.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786931/lkoe8x7smpnlsgdgbcab.png)

![.gitbook/assets/1663786932.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786931/irelpvm44jpmk2tt9wqd.png)

Encryption and decryption algorithms are as follows:

![.gitbook/assets/1663786933.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786932/fbppafr8khwq1hb8pogg.svg)

![.gitbook/assets/1663786935.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786934/uumlgeal15sazhtpbyx0.svg)

PCBC is used in [Kerberos v4](https://www.wikiwand.com/en/Kerberos\_\(protocol\)) and [WASTE](https://www.wikiwand.com/en/WASTE), most notably, but otherwise is not common. On a message encrypted in PCBC mode, if two adjacent ciphertext blocks are exchanged, this does not affect the decryption of subsequent blocks.[\[27\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote27) For this reason, PCBC is not used in Kerberos v5.

**Cipher feedback (CFB)**

**Full-block CFB**

| CFB                       |
| ------------------------- |
| Cipher feedback           |
| Encryption parallelizable |
| Decryption parallelizable |
| Random read access        |

The _cipher feedback_ (CFB) mode, in its simplest form uses the entire output of the block cipher. In this variation, it is very similar to CBC, makes a block cipher into a self-synchronizing [stream cipher](https://www.wikiwand.com/en/Stream\_cipher). CFB decryption in this variation is almost identical to CBC encryption performed in reverse:

![.gitbook/assets/1663786937.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786936/l2gwtio0yp2ny8lymce5.svg)

![.gitbook/assets/1663786939.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786938/nuqohdnesmqe0clx3lvm.png)

![.gitbook/assets/1663786940.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786939/pomydggysveyrc15pzb5.png)

**CFB-1, CFB-8, CFB-64, CFB-128, etc.**

NIST SP800-38A defines CFB with a bit-width.[\[28\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenoteAESBlockDocumentation28) _The CFB mode also requires an integer parameter, denoted s, such that 1 ≤ s ≤ b. In the specification of the CFB mode below, each plaintext segment (Pj) and ciphertext segment (Cj) consists of s bits. The value of s is sometimes incorporated into the name of the mode, e.g., the 1-bit CFB mode, the 8-bit CFB mode, the 64-bit CFB mode, or the 128-bit CFB mode._

These modes will truncate the output of the underlying block cipher.

![.gitbook/assets/1663786940.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786939/wb2sydccz9osuu1fcgke.svg)

![.gitbook/assets/1663786942.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786941/ahfeugp3azzivfjapadj.svg)

![.gitbook/assets/1663786944.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786943/jtjvjphmrrr5chppx7xy.svg)

![.gitbook/assets/1663786946.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786945/dibeeud1xm4h072cs33o.svg)

CFB-1 is considered self synchronizing and resilient to loss of ciphertext; "When the 1-bit CFB mode is used, then the synchronization is automatically restored b+1 positions after the inserted or deleted bit. For other values of s in the CFB mode, and for the other confidentiality modes in this recommendation, the synchronization must be restored externally." (NIST SP800-38A). I.e. 1-bit loss in a 128-bit-wide block cipher like AES will render 129 invalid bits before emitting valid bits.

CFB may also self synchronize in some special cases other than those specified. For example, a one bit change in CFB-128 with an underlying 128 bit block cipher, will re-synchronize after two blocks. (However, CFB-128 etc. will not handle bit loss gracefully; a one-bit loss will cause the decryptor to lose alignment with the encryptor)

**CFB compared to other modes**

Like CBC mode, changes in the plaintext propagate forever in the ciphertext, and encryption cannot be parallelized. Also like CBC, decryption can be parallelized.

CFB, OFB and CTR share two advantages over CBC mode: the block cipher is only ever used in the encrypting direction, and the message does not need to be padded to a multiple of the cipher block size (though [ciphertext stealing](https://www.wikiwand.com/en/Ciphertext\_stealing) can also be used for CBC mode to make padding unnecessary).

**Output feedback (OFB)**

| OFB                       |
| ------------------------- |
| Output feedback           |
| Encryption parallelizable |
| Decryption parallelizable |
| Random read access        |

The _output feedback_ (OFB) mode makes a block cipher into a synchronous [stream cipher](https://www.wikiwand.com/en/Stream\_cipher). It generates [keystream](https://www.wikiwand.com/en/Keystream) blocks, which are then [XORed](https://www.wikiwand.com/en/XOR) with the plaintext blocks to get the ciphertext. Just as with other stream ciphers, flipping a bit in the ciphertext produces a flipped bit in the plaintext at the same location. This property allows many [error-correcting codes](https://www.wikiwand.com/en/Error-correcting\_code) to function normally even when applied before encryption.

Because of the symmetry of the XOR operation, encryption and decryption are exactly the same:

![.gitbook/assets/1663786949.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786948/sity4trht7cp61z29xtq.svg)

![.gitbook/assets/1663786951.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786950/ige2eybs75t0l2s5ux4b.svg)

![.gitbook/assets/1663786952.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786951/ovmiosfh7nzf9gxm8vzi.svg)

![.gitbook/assets/1663786955.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786954/ho2iakdwhrvsfd3w3djh.svg)

![.gitbook/assets/1663786940.svg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786939/wb2sydccz9osuu1fcgke.svg)

![.gitbook/assets/1663786958.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786957/ddndor4jw4bdegowbdqc.png)

![.gitbook/assets/1663786959.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786958/x5hlamnaxrtj94q0u7ku.png)

Each output feedback block cipher operation depends on all previous ones, and so cannot be performed in parallel. However, because the plaintext or ciphertext is only used for the final XOR, the block cipher operations may be performed in advance, allowing the final step to be performed in parallel once the plaintext or ciphertext is available.

It is possible to obtain an OFB mode keystream by using CBC mode with a constant string of zeroes as input. This can be useful, because it allows the usage of fast hardware implementations of CBC mode for OFB mode encryption.

Using OFB mode with a partial block as feedback like CFB mode reduces the average cycle length by a factor of 232 or more. A mathematical model proposed by Davies and Parkin and substantiated by experimental results showed that only with full feedback an average cycle length near to the obtainable maximum can be achieved. For this reason, support for truncated feedback was removed from the specification of OFB.[\[29\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote29)

**Counter (CTR)**

| CTR                       |
| ------------------------- |
| Counter                   |
| Encryption parallelizable |
| Decryption parallelizable |
| Random read access        |

Note: CTR mode (CM) is also known as _integer counter mode_ (ICM) and _segmented integer counter_ (SIC) mode.

Like OFB, counter mode turns a [block cipher](https://www.wikiwand.com/en/Block\_cipher) into a [stream cipher](https://www.wikiwand.com/en/Stream\_cipher). It generates the next [keystream](https://www.wikiwand.com/en/Keystream) block by encrypting successive values of a "counter". The counter can be any function which produces a sequence which is guaranteed not to repeat for a long time, although an actual increment-by-one counter is the simplest and most popular. The usage of a simple deterministic input function used to be controversial; critics argued that "deliberately exposing a cryptosystem to a known systematic input represents an unnecessary risk".[\[30\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote30) However, today CTR mode is widely accepted, and any problems are considered a weakness of the underlying block cipher, which is expected to be secure regardless of systemic bias in its input. Along with CBC, CTR mode is one of two block cipher modes recommended by Niels Ferguson and Bruce Schneier.[\[32\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote32)

CTR mode was introduced by [Whitfield Diffie](https://www.wikiwand.com/en/Whitfield\_Diffie) and [Martin Hellman](https://www.wikiwand.com/en/Martin\_Hellman) in 1979.

CTR mode has similar characteristics to OFB, but also allows a random-access property during decryption. CTR mode is well suited to operate on a multi-processor machine, where blocks can be encrypted in parallel. Furthermore, it does not suffer from the short-cycle problem that can affect OFB.[\[33\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote33)

If the IV/nonce is random, then they can be combined with the counter using any invertible operation (concatenation, addition, or XOR) to produce the actual unique counter block for encryption. In case of a non-random nonce (such as a packet counter), the nonce and counter should be concatenated (e.g., storing the nonce in the upper 64 bits and the counter in the lower 64 bits of a 128-bit counter block). Simply adding or XORing the nonce and counter into a single value would break the security under a [chosen-plaintext attack](https://www.wikiwand.com/en/Chosen-plaintext\_attack) in many cases, since the attacker may be able to manipulate the entire IV–counter pair to cause a collision. Once an attacker controls the IV–counter pair and plaintext, XOR of the ciphertext with the known plaintext would yield a value that, when XORed with the ciphertext of the other block sharing the same IV–counter pair, would decrypt that block.[\[34\]](https://www.wikiwand.com/en/Block\_cipher\_modes\_of\_operation#citenote34)

Note that the [nonce](https://www.wikiwand.com/en/Cryptographic\_nonce) in this diagram is equivalent to the [initialization vector](https://www.wikiwand.com/en/Initialization\_vector) (IV) in the other diagrams. However, if the offset/location information is corrupt, it will be impossible to partially recover such data due to the dependence on byte offset.

![.gitbook/assets/1663786960.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786959/mvhpgu4mafjgihqmcesb.png)

![.gitbook/assets/1663786961.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663786960/qj8jzallyga5dpslim9c.png)

### Error propagation

"Error propagation" properties describe how a decryption behaves during bit errors, i.e. how error in one bit cascades to different decrypted bits.

Bit errors may occur intentionally in attacks or randomly due to transmission errors.

* Random bit errors occur independently in any bit position with an expected probability of ½.
* Specific bit errors occur in the same bit position(s) as the original bit error(s).
* Specific bit errors in stream cipher modes (OFB, CTR, etc.) are trivial. They affect only the specific bit intended.
* Specific bit errors in more complex modes such (e.g. CBC): [adaptive chosen-ciphertext attack](https://www.wikiwand.com/en/Adaptive\_chosen-ciphertext\_attack) may intelligently combine many different specific bit errors to break the cipher mode. In [Padding oracle attack](https://www.wikiwand.com/en/Padding\_oracle\_attack), CBC can be decrypted in the attack by guessing encryption secrets based on error responses. The Padding Oracle attack variant "CBC-R" (CBC Reverse) lets the attacker construct any valid message.

For modern [authenticated encryption](https://www.wikiwand.com/en/Authenticated\_encryption) (AEAD) or protocols with [message authentication codes](https://www.wikiwand.com/en/Message\_authentication\_codes) chained in MAC-Then-Encrypt order, any bit error should completely abort decryption and must not generate any specific bit errors to decryptor. I.e. if decryption succeeded, there should not be any bit error. As such error propagation is less important subject in modern cipher modes than in traditional confidentiality-only modes.

| Mode                                                            | Effect of bit errors in Ci                                    | Effect of bit errors in the IV or nonce                   |
| --------------------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------- |
| ECB                                                             | Random bit errors in Pi                                       | N/A                                                       |
| CBC                                                             | Random bit errors in Pi                                       |                                                           |
| Specific bit errors in Pi+1                                     | Specific bit errors in P1                                     |                                                           |
| CFB                                                             | Specific bit errors in Pi                                     |                                                           |
| Random bit errors in Pi+1, …, until synchronization is restored | Random bit errors in P1, …, until synchronization is restored |                                                           |
| OFB                                                             | Specific bit errors in Pi                                     | Random bit errors in P1, P2, …, Pn                        |
| CTR                                                             | Specific bit errors in Pi                                     | Random bit errors in Pi for bit error in counter block Ti |

(Source: SP800-38A Table D.2: Summary of Effect of Bit Errors on Decryption)

It might be observed, for example, that a one-block error in the transmitted ciphertext would result in a one-block error in the reconstructed plaintext for ECB mode encryption, while in CBC mode such an error would affect two blocks. Some felt that such resilience was desirable in the face of random errors (e.g., line noise), while others argued that error correcting increased the scope for attackers to maliciously tamper with a message.

However, when proper integrity protection is used, such an error will result (with high probability) in the entire message being rejected. If resistance to random error is desirable, [error-correcting codes](https://www.wikiwand.com/en/Error-correcting\_code) should be applied to the ciphertext before transmission.

### Other modes and other cryptographic primitives

Many more modes of operation for block ciphers have been suggested. Some have been accepted, fully described (even standardized), and are in use. Others have been found insecure, and should never be used. Still others don't categorize as confidentiality, authenticity, or authenticated encryption – for example [key feedback mode](https://www.wikiwand.com/en/Key\_feedback\_mode) and [Davies–Meyer](https://www.wikiwand.com/en/One-way\_compression\_function#Davies.E2.80.93Meyer) hashing.
