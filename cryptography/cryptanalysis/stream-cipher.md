# Stream cipher

The operation of the [keystream](https://en.wikipedia.org/wiki/Keystream) generator in [A5/1](https://en.wikipedia.org/wiki/A5/1), an LFSR-based stream cipher used to encrypt mobile phone conversations.

A **stream cipher** is a [symmetric key](https://en.wikipedia.org/wiki/Symmetric\_key\_algorithm) [cipher](https://en.wikipedia.org/wiki/Cipher) where plaintext digits are combined with a [pseudorandom](https://en.wikipedia.org/wiki/Pseudorandom) cipher digit stream ([keystream](https://en.wikipedia.org/wiki/Keystream)). In a stream cipher, each [plaintext](https://en.wikipedia.org/wiki/Plaintext) [digit](https://en.wikipedia.org/wiki/Numerical\_digit) is encrypted one at a time with the corresponding digit of the keystream, to give a digit of the [ciphertext](https://en.wikipedia.org/wiki/Ciphertext) stream. Since encryption of each digit is dependent on the current state of the cipher, it is also known as _**state cipher**_. In practice, a digit is typically a [bit](https://en.wikipedia.org/wiki/Bit) and the combining operation is an [exclusive-or](https://en.wikipedia.org/wiki/Exclusive-or) (XOR).

The pseudorandom keystream is typically generated serially from a random seed value using digital [shift registers](https://en.wikipedia.org/wiki/Shift\_register). The [seed value](https://en.wikipedia.org/wiki/Seed\_value) serves as the [cryptographic key](https://en.wikipedia.org/wiki/Cryptographic\_key) for decrypting the ciphertext stream. Stream ciphers represent a different approach to symmetric encryption from [block ciphers](https://en.wikipedia.org/wiki/Block\_cipher). Block ciphers operate on large blocks of digits with a fixed, unvarying transformation. This distinction is not always clear-cut: in some [modes of operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation), a block cipher primitive is used in such a way that it acts effectively as a stream cipher. Stream ciphers typically execute at a higher speed than block ciphers and have lower hardware complexity. However, stream ciphers can be susceptible to security breaches (see [stream cipher attacks](https://en.wikipedia.org/wiki/Stream\_cipher\_attack)); for example, when the same starting state (seed) is used twice.

### Loose inspiration from the one-time pad\[[edit](https://en.wikipedia.org/w/index.php?title=Stream\_cipher\&action=edit\&section=1)]

Stream ciphers can be viewed as approximating the action of a proven unbreakable cipher, the [one-time pad](https://en.wikipedia.org/wiki/One-time\_pad) (OTP). A one-time pad uses a [keystream](https://en.wikipedia.org/wiki/Keystream) of completely [random](https://en.wikipedia.org/wiki/Random) digits. The keystream is combined with the plaintext digits one at a time to form the ciphertext. This system was proved to be secure by [Claude E. Shannon](https://en.wikipedia.org/wiki/Claude\_E.\_Shannon) in 1949.\[[_citation needed_](https://en.wikipedia.org/wiki/Wikipedia:Citation\_needed)] However, the keystream must be generated completely at random with at least the same length as the plaintext and cannot be used more than once. This makes the system cumbersome to implement in many practical applications, and as a result the one-time pad has not been widely used, except for the most critical applications. Key generation, distribution and management are critical for those applications.

A stream cipher makes use of a much smaller and more convenient key such as 128 bits. Based on this key, it generates a pseudorandom keystream which can be combined with the plaintext digits in a similar fashion to the one-time pad. However, this comes at a cost. The keystream is now pseudorandom and so is not truly random. The proof of security associated with the one-time pad no longer holds. It is quite possible for a stream cipher to be completely insecure.\[[_citation needed_](https://en.wikipedia.org/wiki/Wikipedia:Citation\_needed)]

### Types\[[edit](https://en.wikipedia.org/w/index.php?title=Stream\_cipher\&action=edit\&section=2)]

A stream cipher generates successive elements of the keystream based on an internal state. This state is updated in essentially two ways: if the state changes independently of the plaintext or [ciphertext](https://en.wikipedia.org/wiki/Ciphertext) messages, the cipher is classified as a _synchronous_ stream cipher. By contrast, _self-synchronising_ stream ciphers update their state based on previous ciphertext digits.

#### Synchronous stream ciphers\[[edit](https://en.wikipedia.org/w/index.php?title=Stream\_cipher\&action=edit\&section=3)]

[![.gitbook/assets/1664528940_4592.jpg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1664528940/monyjifwtcs92o7s4ote.jpg)](https://en.wikipedia.org/wiki/File:Lorenz\_Cipher\_Machine.jpg)

In a **synchronous stream cipher** a stream of pseudorandom digits is generated independently of the plaintext and ciphertext messages, and then combined with the plaintext (to encrypt) or the ciphertext (to decrypt). In the most common form, binary digits are used ([bits](https://en.wikipedia.org/wiki/Bit)), and the keystream is combined with the plaintext using the [exclusive or](https://en.wikipedia.org/wiki/Exclusive\_or) operation (XOR). This is termed a **binary additive stream cipher**.

In a synchronous stream cipher, the sender and receiver must be exactly in step for decryption to be successful. If digits are added or removed from the message during transmission, synchronisation is lost. To restore synchronisation, various offsets can be tried systematically to obtain the correct decryption. Another approach is to tag the ciphertext with markers at regular points in the output.

If, however, a digit is corrupted in transmission, rather than added or lost, only a single digit in the plaintext is affected and the error does not propagate to other parts of the message. This property is useful when the transmission error rate is high; however, it makes it less likely the error would be detected without further mechanisms. Moreover, because of this property, synchronous stream ciphers are very susceptible to [active attacks](https://en.wikipedia.org/wiki/Attack\_\(computing\)#Phenomenology): if an attacker can change a digit in the ciphertext, they might be able to make predictable changes to the corresponding plaintext bit; for example, flipping a bit in the ciphertext causes the same bit to be flipped in the plaintext.

#### Self-synchronizing stream ciphers\[[edit](https://en.wikipedia.org/w/index.php?title=Stream\_cipher\&action=edit\&section=4)]

Another approach uses several of the previous _N_ ciphertext digits to compute the keystream. Such schemes are known as **self-synchronizing stream ciphers**, **asynchronous stream ciphers** or **ciphertext autokey** (**CTAK**). The idea of self-synchronization was patented in 1946 and has the advantage that the receiver will automatically synchronise with the keystream generator after receiving _N_ ciphertext digits, making it easier to recover if digits are dropped or added to the message stream. Single-digit errors are limited in their effect, affecting only up to _N_ plaintext digits.

An example of a self-synchronising stream cipher is a block cipher in [cipher feedback](https://en.wikipedia.org/wiki/Cipher\_feedback) (CFB) [mode](https://en.wikipedia.org/wiki/Block\_cipher\_modes\_of\_operation).

### Based on linear-feedback shift registers

Binary stream ciphers are often constructed using [linear-feedback shift registers](https://en.wikipedia.org/wiki/Linear-feedback\_shift\_register) (LFSRs) because they can be easily implemented in hardware and can be readily analysed mathematically. The use of LFSRs on their own, however, is insufficient to provide good security. Various schemes have been proposed to increase the security of LFSRs.

#### Non-linear combining functions\[[edit](https://en.wikipedia.org/w/index.php?title=Stream\_cipher\&action=edit\&section=6)]

[![.gitbook/assets/1664528940_4592.jpg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1664528940/m564mawfqcrcqbyp3dm2.png)](https://en.wikipedia.org/wiki/File:Nonlinear-combo-generator.png)

One approach is to use _n_ LFSRs in parallel, their outputs combined using an _n_-input binary Boolean function (_F_).

Because LFSRs are inherently linear, one technique for removing the linearity is to feed the outputs of several parallel LFSRs into a non-linear [Boolean function](https://en.wikipedia.org/wiki/Boolean\_function) to form a _combination generator_. Various properties of such a _combining function_ are critical for ensuring the security of the resultant scheme, for example, in order to avoid [correlation attacks](https://en.wikipedia.org/wiki/Correlation\_attack).

| [![\[icon\]](https://upload.wikimedia.org/wikipedia/commons/thumb/1/1c/Wiki\_letter\_w\_cropped.svg/20px-Wiki\_letter\_w\_cropped.svg.png)](https://en.wikipedia.org/wiki/File:Wiki\_letter\_w\_cropped.svg) | This section **needs expansion**. You can help by [adding to it](https://en.wikipedia.org/w/index.php?title=Stream\_cipher\&action=edit\&section=). _(June 2008)_ |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |

#### Clock-controlled generators\[[edit](https://en.wikipedia.org/w/index.php?title=Stream\_cipher\&action=edit\&section=7)]

Normally LFSRs are stepped regularly. One approach to introducing non-linearity is to have the LFSR clocked irregularly, controlled by the output of a second LFSR. Such generators include the [stop-and-go generator](https://en.wikipedia.org/w/index.php?title=Stop-and-go\_generator\&action=edit\&redlink=1), the [alternating step generator](https://en.wikipedia.org/wiki/Alternating\_step\_generator) and the [shrinking generator](https://en.wikipedia.org/wiki/Shrinking\_generator).

An [alternating step generator](https://en.wikipedia.org/wiki/Alternating\_step\_generator) comprises three LFSRs, which we will call LFSR0, LFSR1 and LFSR2 for convenience. The output of one of the registers decides which of the other two is to be used; for instance, if LFSR2 outputs a 0, LFSR0 is clocked, and if it outputs a 1, LFSR1 is clocked instead. The output is the exclusive OR of the last bit produced by LFSR0 and LFSR1. The initial state of the three LFSRs is the key.

The stop-and-go generator (Beth and Piper, 1984) consists of two LFSRs. One LFSR is clocked if the output of a second is a 1, otherwise it repeats its previous output. This output is then (in some versions) combined with the output of a third LFSR clocked at a regular rate.

The [shrinking generator](https://en.wikipedia.org/wiki/Shrinking\_generator) takes a different approach. Two LFSRs are used, both clocked regularly. If the output of the first LFSR is 1, the output of the second LFSR becomes the output of the generator. If the first LFSR outputs 0, however, the output of the second is discarded, and no bit is output by the generator. This mechanism suffers from timing attacks on the second generator, since the speed of the output is variable in a manner that depends on the second generator's state. This can be alleviated by buffering the output.

#### Filter generator\[[edit](https://en.wikipedia.org/w/index.php?title=Stream\_cipher\&action=edit\&section=8)]

Another approach to improving the security of an LFSR is to pass the entire state of a single LFSR into a non-linear _filtering function_.

| [![\[icon\]](https://upload.wikimedia.org/wikipedia/commons/thumb/1/1c/Wiki\_letter\_w\_cropped.svg/20px-Wiki\_letter\_w\_cropped.svg.png)](https://en.wikipedia.org/wiki/File:Wiki\_letter\_w\_cropped.svg) | This section **needs expansion**. You can help by [adding to it](https://en.wikipedia.org/w/index.php?title=Stream\_cipher\&action=edit\&section=). _(June 2008)_ |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |

### Other designs

[![.gitbook/assets/1664528940_4592.jpg](http://res.cloudinary.com/dr4gsg09f/image/upload/v1664528941/bnrnjl2qh3lfqaiylr6p.png)](https://en.wikipedia.org/wiki/File:RC4.svg)

[RC4](https://en.wikipedia.org/wiki/RC4) is one of the most widely used stream cipher designs.

Instead of a linear driving device, one may use a nonlinear update function. For example, Klimov and Shamir proposed triangular functions ([T-functions](https://en.wikipedia.org/wiki/T-function)) with a single cycle on n-bit words.

| [![\[icon\]](https://upload.wikimedia.org/wikipedia/commons/thumb/1/1c/Wiki\_letter\_w\_cropped.svg/20px-Wiki\_letter\_w\_cropped.svg.png)](https://en.wikipedia.org/wiki/File:Wiki\_letter\_w\_cropped.svg) | This section **needs expansion**. You can help by [adding to it](https://en.wikipedia.org/w/index.php?title=Stream\_cipher\&action=edit\&section=). _(June 2008)_ |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |

### Security

For a stream cipher to be secure, its keystream must have a large [period](https://en.wikipedia.org/wiki/Periodic\_function), and it must be impossible to _recover the cipher's key_ or internal state from the keystream. Cryptographers also demand that the keystream be free of even subtle biases that would let attackers _distinguish_ a stream from random noise, and free of detectable relationships between keystreams that correspond to _related keys_ or related [cryptographic nonces](https://en.wikipedia.org/wiki/Cryptographic\_nonce). That should be true for all keys (there should be no [_weak keys_](https://en.wikipedia.org/wiki/Weak\_key)), even if the attacker can _know_ or _choose_ some _plaintext_ or _ciphertext_.

As with other attacks in cryptography, stream cipher attacks can be _certificational_ so they are not necessarily practical ways to break the cipher but indicate that the cipher might have other weaknesses.

Securely using a secure synchronous stream cipher requires that one never reuse the same keystream twice. That generally means a different [nonce](https://en.wikipedia.org/wiki/Cryptographic\_nonce) or key must be supplied to each invocation of the cipher. Application designers must also recognize that most stream ciphers provide not _authenticity_ but _privacy_: encrypted messages may still have been modified in transit.

Short periods for stream ciphers have been a practical concern. For example, 64-bit block ciphers like [DES](https://en.wikipedia.org/wiki/Data\_Encryption\_Standard) can be used to generate a keystream in [output feedback](https://en.wikipedia.org/wiki/Output\_feedback) (OFB) mode. However, when not using full feedback, the resulting stream has a period of around 232 blocks on average; for many applications, the period is far too low. For example, if encryption is being performed at a rate of 8 [megabytes](https://en.wikipedia.org/wiki/Megabyte) per second, a stream of period 232 blocks will repeat after about a half an hour.\[[_dubious_](https://en.wikipedia.org/wiki/Wikipedia:Accuracy\_dispute#Disputed\_statement) _–_ [_discuss_](https://en.wikipedia.org/wiki/Talk:Stream\_cipher#Dubious)]

Some applications using the stream cipher [RC4](https://en.wikipedia.org/wiki/RC4) are attackable because of weaknesses in RC4's key setup routine; new applications should either avoid RC4 or make sure all keys are unique and ideally [unrelated](https://en.wikipedia.org/wiki/Related\_key) (such as generated by a well-seeded [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically\_secure\_pseudorandom\_number\_generator) or a [cryptographic hash function](https://en.wikipedia.org/wiki/Cryptographic\_hash\_function)) and that the first bytes of the keystream are discarded.

The elements of stream ciphers are often much simpler to understand than block ciphers and are thus less likely to hide any accidental or malicious weaknesses.

### Usage

Stream ciphers are often used for their speed and simplicity of implementation in hardware, and in applications where plaintext comes in quantities of unknowable length like a secure [wireless](https://en.wikipedia.org/wiki/Wireless\_network) connection. If a [block cipher](https://en.wikipedia.org/wiki/Block\_cipher) (not operating in a stream cipher mode) were to be used in this type of application, the designer would need to choose either transmission efficiency or implementation complexity, since block ciphers cannot directly work on blocks shorter than their block size. For example, if a 128-bit block cipher received separate 32-bit bursts of plaintext, three quarters of the data transmitted would be [padding](https://en.wikipedia.org/wiki/Padding\_\(cryptography\)). Block ciphers must be used in [ciphertext stealing](https://en.wikipedia.org/wiki/Ciphertext\_stealing) or [residual block termination](https://en.wikipedia.org/wiki/Residual\_block\_termination) mode to avoid padding, while stream ciphers eliminate this issue by naturally operating on the smallest unit that can be transmitted (usually bytes).

Another advantage of stream ciphers in military cryptography is that the cipher stream can be generated in a separate box that is subject to strict security measures and fed to other devices such as a radio set, which will perform the XOR operation as part of their function. The latter device can then be designed and used in less stringent environments.

[ChaCha](https://en.wikipedia.org/wiki/ChaCha20) is becoming the most widely used stream cipher in software;[\[1\]](https://en.wikipedia.org/wiki/Stream\_cipher#cite\_note-1) others include: [RC4](https://en.wikipedia.org/wiki/RC4), [A5/1](https://en.wikipedia.org/wiki/A5/1), [A5/2](https://en.wikipedia.org/wiki/A5/2), [Chameleon](https://en.wikipedia.org/w/index.php?title=Chameleon\_\(cipher\)\&action=edit\&redlink=1), [FISH](https://en.wikipedia.org/wiki/FISH\_\(cipher\)), [Helix](https://en.wikipedia.org/wiki/Helix\_\(cipher\)), [ISAAC](https://en.wikipedia.org/wiki/ISAAC\_\(cipher\)), [MUGI](https://en.wikipedia.org/wiki/MUGI), [Panama](https://en.wikipedia.org/wiki/Panama\_\(cipher\)), [Phelix](https://en.wikipedia.org/wiki/Phelix), [Pike](https://en.wikipedia.org/wiki/Pike\_\(cipher\)), [Salsa20](https://en.wikipedia.org/wiki/Salsa20), [SEAL](https://en.wikipedia.org/wiki/SEAL\_\(cipher\)), [SOBER](https://en.wikipedia.org/wiki/SOBER), [SOBER-128](https://en.wikipedia.org/wiki/SOBER-128), and [WAKE](https://en.wikipedia.org/wiki/WAKE\_\(cipher\)).

