# RC4

In [cryptography](https://en.wikipedia.org/wiki/Cryptography), **RC4** (Rivest Cipher 4 also known as **ARC4** or **ARCFOUR** meaning Alleged RC4, see below) is a [stream cipher](https://en.wikipedia.org/wiki/Stream\_cipher). While it is remarkable for its simplicity and speed in software, multiple vulnerabilities have been discovered in RC4, rendering it insecure.[\[3\]](https://en.wikipedia.org/wiki/RC4#cite\_note-rfc7465-3)[\[4\]](https://en.wikipedia.org/wiki/RC4#cite\_note-4) It is especially vulnerable when the beginning of the output [keystream](https://en.wikipedia.org/wiki/Keystream) is not discarded, or when nonrandom or related keys are used. Particularly problematic uses of RC4 have led to very insecure [protocols](https://en.wikipedia.org/wiki/Cryptographic\_protocol) such as [WEP](https://en.wikipedia.org/wiki/Wired\_Equivalent\_Privacy).[\[5\]](https://en.wikipedia.org/wiki/RC4#cite\_note-5)

As of 2015, there is speculation that some state cryptologic agencies may possess the capability to break RC4 when used in the [TLS protocol](https://en.wikipedia.org/wiki/Transport\_Layer\_Security).[\[6\]](https://en.wikipedia.org/wiki/RC4#cite\_note-Leyden20130906-6) [IETF](https://en.wikipedia.org/wiki/IETF) has published RFC 7465 to prohibit the use of RC4 in TLS;[\[3\]](https://en.wikipedia.org/wiki/RC4#cite\_note-rfc7465-3) [Mozilla](https://en.wikipedia.org/wiki/Mozilla) and [Microsoft](https://en.wikipedia.org/wiki/Microsoft) have issued similar recommendations.[\[7\]](https://en.wikipedia.org/wiki/RC4#cite\_note-7)[\[8\]](https://en.wikipedia.org/wiki/RC4#cite\_note-8)

A number of attempts have been made to strengthen RC4, notably Spritz, RC4A, [VMPC](https://en.wikipedia.org/wiki/Variably\_Modified\_Permutation\_Composition), and RC4+.

### History\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=1)]

RC4 was designed by [Ron Rivest](https://en.wikipedia.org/wiki/Ron\_Rivest) of [RSA Security](https://en.wikipedia.org/wiki/RSA\_Security) in 1987. While it is officially termed "Rivest Cipher 4", the RC acronym is alternatively understood to stand for "Ron's Code"[\[9\]](https://en.wikipedia.org/wiki/RC4#cite\_note-9) (see also [RC2](https://en.wikipedia.org/wiki/RC2), [RC5](https://en.wikipedia.org/wiki/RC5) and [RC6](https://en.wikipedia.org/wiki/RC6)).

RC4 was initially a [trade secret](https://en.wikipedia.org/wiki/Trade\_secret), but in September 1994, a description of it was anonymously posted to the [Cypherpunks](https://en.wikipedia.org/wiki/Cypherpunk) mailing list.[\[10\]](https://en.wikipedia.org/wiki/RC4#cite\_note-10) It was soon posted on the [sci.crypt](https://en.wikipedia.org/wiki/Sci.crypt) [newsgroup](https://en.wikipedia.org/wiki/Newsgroup), where it was analyzed within days by [Bob Jenkins](https://en.wikipedia.org/wiki/Robert\_John\_Jenkins\_Junior).[\[11\]](https://en.wikipedia.org/wiki/RC4#cite\_note-11) From there, it spread to many sites on the Internet. The leaked code was confirmed to be genuine, as its output was found to match that of proprietary software using licensed RC4. Because the algorithm is known, it is no longer a trade secret. The name _RC4_ is trademarked, so RC4 is often referred to as _ARCFOUR_ or _ARC4_ (meaning _alleged RC4_)[\[12\]](https://en.wikipedia.org/wiki/RC4#cite\_note-12) to avoid trademark problems. [RSA Security](https://en.wikipedia.org/wiki/RSA\_Security) has never officially released the algorithm; Rivest has, however, linked to the [English Wikipedia](https://en.wikipedia.org/wiki/English\_Wikipedia) article on RC4 in his own course notes in 2008[\[13\]](https://en.wikipedia.org/wiki/RC4#cite\_note-13) and confirmed the history of RC4 and its code in a 2014 paper by him.[\[14\]](https://en.wikipedia.org/wiki/RC4#cite\_note-Rivest2014-14)

RC4 became part of some commonly used encryption protocols and standards, such as [WEP](https://en.wikipedia.org/wiki/Wired\_Equivalent\_Privacy) in 1997 and [WPA](https://en.wikipedia.org/wiki/Wi-Fi\_Protected\_Access) in 2003/2004 for wireless cards; and [SSL](https://en.wikipedia.org/wiki/Secure\_Sockets\_Layer) in 1995 and its successor [TLS](https://en.wikipedia.org/wiki/Transport\_Layer\_Security) in 1999, until it was prohibited for all versions of TLS by RFC 7465 in 2015, due to the [RC4 attacks](https://en.wikipedia.org/wiki/Transport\_Layer\_Security#RC4\_attacks) weakening or breaking RC4 used in SSL/TLS. The main factors in RC4's success over such a wide range of applications have been its speed and simplicity: efficient implementations in both software and hardware were very easy to develop.

### Description\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=2)]

RC4 generates a [pseudorandom stream of bits](https://en.wikipedia.org/wiki/Pseudo-random\_number\_generator) (a [keystream](https://en.wikipedia.org/wiki/Keystream)). As with any stream cipher, these can be used for encryption by combining it with the plaintext using bit-wise [exclusive-or](https://en.wikipedia.org/wiki/Exclusive\_or); decryption is performed the same way (since exclusive-or with given data is an [involution](https://en.wikipedia.org/wiki/Involution\_\(mathematics\))). This is similar to the [one-time pad](https://en.wikipedia.org/wiki/One-time\_pad) except that generated _pseudorandom bits_, rather than a prepared stream, are used.

To generate the keystream, the cipher makes use of a secret internal state which consists of two parts:

1. A [permutation](https://en.wikipedia.org/wiki/Permutation) of all 256 possible [bytes](https://en.wikipedia.org/wiki/Bytes) (denoted "S" below).
2. Two 8-bit index-pointers (denoted "i" and "j").

The permutation is initialized with a variable length [key](https://en.wikipedia.org/wiki/Key\_\(cryptography\)), typically between 40 and 2048 bits, using the [_key-scheduling_](https://en.wikipedia.org/wiki/Key\_schedule) algorithm (KSA). Once this has been completed, the stream of bits is generated using the _pseudo-random generation algorithm_ (PRGA).

#### Key-scheduling algorithm (KSA)\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=3)]

The [key-scheduling](https://en.wikipedia.org/wiki/Key\_schedule) algorithm is used to initialize the permutation in the array "S". "keylength" is defined as the number of bytes in the key and can be in the range 1 ≤ keylength ≤ 256, typically between 5 and 16, corresponding to a [key length](https://en.wikipedia.org/wiki/Key\_length) of 40 – 128 bits. First, the array "S" is initialized to the [identity permutation](https://en.wikipedia.org/wiki/Identity\_permutation). S is then processed for 256 iterations in a similar way to the main PRGA, but also mixes in bytes of the key at the same time.

```
for i from 0 to 255
    S[i] := i
endfor
j := 0
for i from 0 to 255
    j := (j + S[i] + key[i mod keylength]) mod 256
    swap values of S[i] and S[j]
endfor
```

#### Pseudo-random generation algorithm (PRGA)\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=4)]

\[![.gitbook/assets/1664530364\_6919.svg](https://en.wikipedia.org/wiki/File:RC4.svg)

The lookup stage of RC4. The output byte is selected by looking up the values of S\[i] and

S\[j], adding them together modulo 256, and then using the sum as an index into

S;

S(S\[i] + S\[j]) is used as a byte of the key stream, K.

For as many iterations as are needed, the PRGA modifies the state and outputs a byte of the keystream. In each iteration, the PRGA:

* increments _i_
* looks up the \_i\_th element of S, S\[_i_], and adds that to _j_
* exchanges the values of S\[_i_] and S\[_j_] then uses the sum S\[_i_] + S\[_j_] (modulo 256) as an index to fetch a third element of S (the keystream value K below)
* then bitwise exclusive ORed ([XORed](https://en.wikipedia.org/wiki/Exclusive\_or)) with the next byte of the message to produce the next byte of either ciphertext or plaintext.

Each element of S is swapped with another element at least once every 256 iterations.

```
i := 0
j := 0
while GeneratingOutput:
    i := (i + 1) mod 256
    j := (j + S[i]) mod 256
    swap values of S[i] and S[j]
    K := S[(S[i] + S[j]) mod 256]
    output K
endwhile
```

Thus, this produces a stream of K\[0],K\[1],... which are [XOR](https://en.wikipedia.org/wiki/Exclusive\_or)'ed with the _plaintext_ to obtain the _ciphertext_. So ciphertext\[_l_] = plaintext\[_l_] ⊕ K\[_l_] .

#### RC4-based random number generators\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=5)]

Several [operating systems](https://en.wikipedia.org/wiki/Operating\_system) include `arc4random`, an API originating in [OpenBSD](https://en.wikipedia.org/wiki/OpenBSD\_security\_features) providing access to a random number generator originally based on RC4. In OpenBSD 5.5, released in May 2014, `arc4random` was modified to use [ChaCha20](https://en.wikipedia.org/wiki/ChaCha20).[\[15\]](https://en.wikipedia.org/wiki/RC4#cite\_note-15)[\[16\]](https://en.wikipedia.org/wiki/RC4#cite\_note-16) The implementations of arc4random in [FreeBSD](https://en.wikipedia.org/wiki/FreeBSD), [NetBSD](https://en.wikipedia.org/wiki/NetBSD)[\[17\]](https://en.wikipedia.org/wiki/RC4#cite\_note-17)[\[18\]](https://en.wikipedia.org/wiki/RC4#cite\_note-18) and [Linux](https://en.wikipedia.org/wiki/Linux)'s libbsd[\[19\]](https://en.wikipedia.org/wiki/RC4#cite\_note-19) also use ChaCha20. According to manual pages shipped with the operating system, in the 2017 release of its [desktop](https://en.wikipedia.org/wiki/MacOS) and [mobile](https://en.wikipedia.org/wiki/IOS) operating systems, Apple replaced RC4 with AES in its implementation of arc4random. [Man pages](https://en.wikipedia.org/wiki/Man\_page) for the new arc4random include the [backronym](https://en.wikipedia.org/wiki/Backronym) "A Replacement Call for Random" for ARC4 as a mnemonic,[\[20\]](https://en.wikipedia.org/wiki/RC4#cite\_note-arc4random-obsd-20) as it provides better random data than [rand()](https://en.wikipedia.org/wiki/Rand\(\)) does.

Proposed new random number generators are often compared to the RC4 random number generator.[\[21\]](https://en.wikipedia.org/wiki/RC4#cite\_note-21)[\[22\]](https://en.wikipedia.org/wiki/RC4#cite\_note-22)

Several attacks on RC4 are able to [distinguish its output from a random sequence](https://en.wikipedia.org/wiki/Ciphertext\_indistinguishability#Indistinguishable\_from\_random\_noise).[\[23\]](https://en.wikipedia.org/wiki/RC4#cite\_note-mantin-23)

#### Implementation\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=6)]

Many stream ciphers are based on [linear-feedback shift registers](https://en.wikipedia.org/wiki/Linear-feedback\_shift\_register) (LFSRs), which, while efficient in hardware, are less so in software. The design of RC4 avoids the use of LFSRs and is ideal for software implementation, as it requires only byte manipulations. It uses 256 bytes of memory for the state array, S\[0] through S\[255], k bytes of memory for the key, key\[0] through key\[k-1], and integer variables, i, j, and K. Performing a modular reduction of some value modulo 256 can be done with a [bitwise AND](https://en.wikipedia.org/wiki/Bitwise\_AND) with 255 (which is equivalent to taking the low-order byte of the value in question).

#### Test vectors\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=7)]

These test vectors are not official, but convenient for anyone testing their own RC4 program. The keys and plaintext are [ASCII](https://en.wikipedia.org/wiki/ASCII), the keystream and ciphertext are in [hexadecimal](https://en.wikipedia.org/wiki/Hexadecimal).

| Key    | Keystream             | Plaintext      | Ciphertext                   |
| ------ | --------------------- | -------------- | ---------------------------- |
| Key    | EB9F7781B734CA72A719… | Plaintext      | BBF316E8D940AF0AD3           |
| Wiki   | 6044DB6D41B7…         | pedia          | 1021BF0420                   |
| Secret | 04D46B053CA87B59…     | Attack at dawn | 45A01F645FC35B383552544B9BF5 |

### Security\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=8)]

Unlike a modern stream cipher (such as those in [eSTREAM](https://en.wikipedia.org/wiki/ESTREAM)), RC4 does not take a separate [nonce](https://en.wikipedia.org/wiki/Cryptographic\_nonce) alongside the key. This means that if a single long-term key is to be used to securely encrypt multiple streams, the protocol must specify how to combine the nonce and the long-term key to generate the stream key for RC4. One approach to addressing this is to generate a "fresh" RC4 key by [hashing](https://en.wikipedia.org/wiki/Cryptographic\_hash\_function) a long-term key with a [nonce](https://en.wikipedia.org/wiki/Cryptographic\_nonce). However, many applications that use RC4 simply concatenate key and nonce; RC4's weak [key schedule](https://en.wikipedia.org/wiki/Key\_schedule) then gives rise to [related key attacks](https://en.wikipedia.org/wiki/Related\_key\_attack), like the [Fluhrer, Mantin and Shamir attack](https://en.wikipedia.org/wiki/Fluhrer,\_Mantin\_and\_Shamir\_attack) (which is famous for breaking the [WEP](https://en.wikipedia.org/wiki/Wired\_Equivalent\_Privacy) standard).[\[24\]](https://en.wikipedia.org/wiki/RC4#cite\_note-24)

Because RC4 is a [stream cipher](https://en.wikipedia.org/wiki/Stream\_cipher), it is more [malleable](https://en.wikipedia.org/wiki/Malleability\_\(cryptography\)) than common [block ciphers](https://en.wikipedia.org/wiki/Block\_cipher). If not used together with a strong [message authentication code](https://en.wikipedia.org/wiki/Message\_authentication\_code) (MAC), then encryption is vulnerable to a [bit-flipping attack](https://en.wikipedia.org/wiki/Bit-flipping\_attack). The cipher is also vulnerable to a [stream cipher attack](https://en.wikipedia.org/wiki/Stream\_cipher\_attack) if not implemented correctly.[\[25\]](https://en.wikipedia.org/wiki/RC4#cite\_note-25)

It is noteworthy, however, that RC4, being a stream cipher, was for a period of time the only common cipher that was immune[\[26\]](https://en.wikipedia.org/wiki/RC4#cite\_note-26) to the 2011 [BEAST attack](https://en.wikipedia.org/wiki/BEAST\_attack) on [TLS 1.0](https://en.wikipedia.org/wiki/Transport\_Layer\_Security#TLS\_1.0). The attack exploits a known weakness in the way [cipher block chaining mode](https://en.wikipedia.org/wiki/Block\_cipher\_modes\_of\_operation#Cipher-block\_chaining\_.28CBC.29) is used with all of the other ciphers supported by TLS 1.0, which are all block ciphers.

In March 2013, there were new attack scenarios proposed by Isobe, Ohigashi, Watanabe and Morii,[\[27\]](https://en.wikipedia.org/wiki/RC4#cite\_note-27) as well as AlFardan, Bernstein, Paterson, Poettering and Schuldt that use new statistical biases in RC4 key table[\[28\]](https://en.wikipedia.org/wiki/RC4#cite\_note-28) to recover plaintext with large number of TLS encryptions.[\[29\]](https://en.wikipedia.org/wiki/RC4#cite\_note-29)[\[30\]](https://en.wikipedia.org/wiki/RC4#cite\_note-30)

The use of RC4 in TLS is prohibited by RFC 7465 published in February 2015.

#### Roos' biases and key reconstruction from permutation\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=9)]

In 1995, Andrew Roos experimentally observed that the first byte of the keystream is correlated to the first three bytes of the key and the first few bytes of the permutation after the KSA are correlated to some linear combination of the key bytes.[\[31\]](https://en.wikipedia.org/wiki/RC4#cite\_note-31) These biases remained unexplained until 2007, when Goutam Paul, Siddheshwar Rathi and Subhamoy Maitra[\[32\]](https://en.wikipedia.org/wiki/RC4#cite\_note-32) proved the keystream–key correlation and, in another work, Goutam Paul and Subhamoy Maitra[\[33\]](https://en.wikipedia.org/wiki/RC4#cite\_note-33) proved the permutation–key correlations. The latter work also used the permutation–key correlations to design the first algorithm for complete key reconstruction from the final permutation after the KSA, without any assumption on the key or [initialization vector](https://en.wikipedia.org/wiki/Initialization\_vector). This algorithm has a constant probability of success in a time which is the square root of the exhaustive key search complexity. Subsequently, many other works have been performed on key reconstruction from RC4 internal states.[\[34\]](https://en.wikipedia.org/wiki/RC4#cite\_note-34)[\[35\]](https://en.wikipedia.org/wiki/RC4#cite\_note-35)[\[36\]](https://en.wikipedia.org/wiki/RC4#cite\_note-36) Subhamoy Maitra and Goutam Paul[\[37\]](https://en.wikipedia.org/wiki/RC4#cite\_note-37) also showed that the Roos-type biases still persist even when one considers nested permutation indices, like S\[S\[i]] or S\[S\[S\[i]]]. These types of biases are used in some of the later key reconstruction methods for increasing the success probability.

#### Biased outputs of the RC4\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=10)]

The keystream generated by the RC4 is biased to varying degrees towards certain sequences making it vulnerable to [distinguishing attacks](https://en.wikipedia.org/wiki/Distinguishing\_attack). The best such attack is due to Itsik Mantin and [Adi Shamir](https://en.wikipedia.org/wiki/Adi\_Shamir) who showed that the second output byte of the cipher was biased toward zero with probability 1/128 (instead of 1/256). This is due to the fact that if the third byte of the original state is zero, and the second byte is not equal to 2, then the second output byte is always zero. Such bias can be detected by observing only 256 bytes.[\[23\]](https://en.wikipedia.org/wiki/RC4#cite\_note-mantin-23)

[Souradyuti Paul](https://en.wikipedia.org/wiki/Souradyuti\_Paul) and [Bart Preneel](https://en.wikipedia.org/wiki/Bart\_Preneel) of [COSIC](https://en.wikipedia.org/wiki/COSIC) showed that the first and the second bytes of the RC4 were also biased. The number of required samples to detect this bias is 225 bytes.[\[38\]](https://en.wikipedia.org/wiki/RC4#cite\_note-38)

[Scott Fluhrer](https://en.wikipedia.org/w/index.php?title=Scott\_Fluhrer\&action=edit\&redlink=1) and David McGrew also showed such attacks which distinguished the keystream of the RC4 from a random stream given a gigabyte of output.[\[39\]](https://en.wikipedia.org/wiki/RC4#cite\_note-39)

The complete characterization of a single step of RC4 PRGA was performed by Riddhipratim Basu, Shirshendu Ganguly, Subhamoy Maitra, and Goutam Paul.[\[40\]](https://en.wikipedia.org/wiki/RC4#cite\_note-40) Considering all the permutations, they proved that the distribution of the output is not uniform given i and j, and as a consequence, information about j is always leaked into the output.

#### Fluhrer, Mantin and Shamir attack\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=11)]

In 2001, a new and surprising discovery was made by [Fluhrer](https://en.wikipedia.org/w/index.php?title=Scott\_Fluhrer\&action=edit\&redlink=1), [Mantin](https://en.wikipedia.org/w/index.php?title=Itsik\_Mantin\&action=edit\&redlink=1) and [Shamir](https://en.wikipedia.org/wiki/Adi\_Shamir): over all the possible RC4 keys, the statistics for the first few bytes of output keystream are strongly non-random, leaking information about the key. If the nonce and long-term key are simply concatenated to generate the RC4 key, this long-term key can be discovered by analysing a large number of messages encrypted with this key.[\[41\]](https://en.wikipedia.org/wiki/RC4#cite\_note-41) This and related effects were then used to break the [WEP](https://en.wikipedia.org/wiki/Wired\_Equivalent\_Privacy) ("wired equivalent privacy") encryption used with [802.11](https://en.wikipedia.org/wiki/802.11) [wireless networks](https://en.wikipedia.org/wiki/Wireless\_network). This caused a scramble for a standards-based replacement for WEP in the 802.11 market, and led to the [IEEE 802.11i](https://en.wikipedia.org/wiki/IEEE\_802.11i) effort and [WPA](https://en.wikipedia.org/wiki/Wi-Fi\_Protected\_Access).[\[42\]](https://en.wikipedia.org/wiki/RC4#cite\_note-42)

Protocols can defend against this attack by discarding the initial portion of the keystream. Such a modified algorithm is traditionally called "RC4-drop\[n]", where n is the number of initial keystream bytes that are dropped. The SCAN default is n = 768 bytes, but a conservative value would be n = 3072 bytes.[\[43\]](https://en.wikipedia.org/wiki/RC4#cite\_note-43)

The Fluhrer, Mantin and Shamir attack does not apply to RC4-based SSL, since SSL generates the encryption keys it uses for RC4 by hashing, meaning that different SSL sessions have unrelated keys.[\[44\]](https://en.wikipedia.org/wiki/RC4#cite\_note-44)

#### Klein's attack\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=12)]

In 2005, Andreas Klein presented an analysis of the RC4 stream cipher, showing more correlations between the RC4 keystream and the key.[\[45\]](https://en.wikipedia.org/wiki/RC4#cite\_note-45) [Erik Tews](https://en.wikipedia.org/w/index.php?title=Erik\_Tews\&action=edit\&redlink=1), [Ralf-Philipp Weinmann](https://en.wikipedia.org/w/index.php?title=Ralf-Philipp\_Weinmann\&action=edit\&redlink=1), and [Andrei Pychkine](https://en.wikipedia.org/w/index.php?title=Andrei\_Pychkine\&action=edit\&redlink=1) used this analysis to create aircrack-ptw, a tool which cracks 104-bit RC4 used in 128-bit WEP in under a minute.[\[46\]](https://en.wikipedia.org/wiki/RC4#cite\_note-46) Whereas the Fluhrer, Mantin, and Shamir attack used around 10 million messages, aircrack-ptw can break 104-bit keys in 40,000 frames with 50% probability, or in 85,000 frames with 95% probability.

#### Combinatorial problem\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=13)]

A combinatorial problem related to the number of inputs and outputs of the RC4 cipher was first posed by [Itsik Mantin](https://en.wikipedia.org/w/index.php?title=Itsik\_Mantin\&action=edit\&redlink=1) and [Adi Shamir](https://en.wikipedia.org/wiki/Adi\_Shamir) in 2001, whereby, of the total 256 elements in the typical state of RC4, if _x_ number of elements (_x_ ≤ 256) are _only_ known (all other elements can be assumed empty), then the maximum number of elements that can be produced deterministically is also x in the next 256 rounds. This conjecture was put to rest in 2004 with a formal proof given by [Souradyuti Paul](https://en.wikipedia.org/wiki/Souradyuti\_Paul) and [Bart Preneel](https://en.wikipedia.org/wiki/Bart\_Preneel).[\[47\]](https://en.wikipedia.org/wiki/RC4#cite\_note-47)

#### Royal Holloway attack\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=14)]

In 2013, a group of security researchers at the Information Security Group at Royal Holloway, University of London reported an attack that can become effective using only 234 encrypted messages.[\[48\]](https://en.wikipedia.org/wiki/RC4#cite\_note-48)[\[49\]](https://en.wikipedia.org/wiki/RC4#cite\_note-49)[\[50\]](https://en.wikipedia.org/wiki/RC4#cite\_note-50) While yet not a practical attack for most purposes, this result is sufficiently close to one that it has led to speculation that it is plausible that some state cryptologic agencies may already have better attacks that render RC4 insecure.[\[6\]](https://en.wikipedia.org/wiki/RC4#cite\_note-Leyden20130906-6) Given that, as of 2013, a large amount of [TLS](https://en.wikipedia.org/wiki/Transport\_Layer\_Security) traffic uses RC4 to avoid attacks on block ciphers that use [cipher block chaining](https://en.wikipedia.org/wiki/Cipher\_block\_chaining), if these hypothetical better attacks exist, then this would make the TLS-with-RC4 combination insecure against such attackers in a large number of practical scenarios.[\[6\]](https://en.wikipedia.org/wiki/RC4#cite\_note-Leyden20130906-6)

In March 2015, researcher to Royal Holloway announced improvements to their attack, providing a 226 attack against passwords encrypted with RC4, as used in TLS.[\[51\]](https://en.wikipedia.org/wiki/RC4#cite\_note-51)

#### Bar mitzvah attack\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=15)]

At the Black Hat Asia 2015 Conference, Itsik Mantin presented another attack against SSL using RC4 cipher.[\[52\]](https://en.wikipedia.org/wiki/RC4#cite\_note-52)[\[53\]](https://en.wikipedia.org/wiki/RC4#cite\_note-53)

#### NOMORE attack\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=16)]

In 2015, security researchers from [KU Leuven](https://en.wikipedia.org/wiki/Katholieke\_Universiteit\_Leuven) presented new attacks against RC4 in both [TLS](https://en.wikipedia.org/wiki/Transport\_Layer\_Security) and [WPA-TKIP](https://en.wikipedia.org/wiki/Temporal\_Key\_Integrity\_Protocol).[\[54\]](https://en.wikipedia.org/wiki/RC4#cite\_note-rc4nomore-54) Dubbed the Numerous Occurrence MOnitoring & Recovery Exploit (NOMORE) attack, it is the first attack of its kind that was demonstrated in practice. Their attack against [TLS](https://en.wikipedia.org/wiki/Transport\_Layer\_Security) can decrypt a secure [HTTP cookie](https://en.wikipedia.org/wiki/HTTP\_cookie) within 75 hours. The attack against WPA-TKIP can be completed within an hour, and allows an attacker to decrypt and inject arbitrary packets.

### RC4 variants\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=17)]

As mentioned above, the most important weakness of RC4 comes from the insufficient key schedule; the first bytes of output reveal information about the key. This can be corrected by simply discarding some initial portion of the output stream.[\[55\]](https://en.wikipedia.org/wiki/RC4#cite\_note-55) This is known as RC4-drop\_N\_, where _N_ is typically a multiple of 256, such as 768 or 1024.

A number of attempts have been made to strengthen RC4, notably Spritz, RC4A, [VMPC](https://en.wikipedia.org/wiki/Variably\_Modified\_Permutation\_Composition), and RC4+.

#### RC4A\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=18)]

[Souradyuti Paul](https://en.wikipedia.org/wiki/Souradyuti\_Paul) and [Bart Preneel](https://en.wikipedia.org/wiki/Bart\_Preneel) have proposed an RC4 variant, which they call RC4A.[\[56\]](https://en.wikipedia.org/wiki/RC4#cite\_note-56)

RC4A uses two state arrays S1 and S2, and two indexes j1 and j2. Each time i is incremented, two bytes are generated:

1. First, the basic RC4 algorithm is performed using S1 and j1, but in the last step, S1\[i]+S1\[j1] is looked up in S2.
2. Second, the operation is repeated (without incrementing i again) on S2 and j2, and S1\[S2\[i]+S2\[j2]] is output.

Thus, the algorithm is:

```
All arithmetic is performed modulo 256
i := 0
j1 := 0
j2 := 0
while GeneratingOutput:
    i := i + 1
    j1 := j1 + S1[i]
    swap values of S1[i] and S1[j1]
    output S2[S1[i] + S1[j1]]
    j2 := j2 + S2[i]
    swap values of S2[i] and S2[j2]
    output S1[S2[i] + S2[j2]]
endwhile
```

Although the algorithm required the same number of operations per output byte, there is greater parallelism than RC4, providing a possible speed improvement.

Although stronger than RC4, this algorithm has also been attacked, with Alexander Maximov[\[57\]](https://en.wikipedia.org/wiki/RC4#cite\_note-57) and a team from NEC[\[58\]](https://en.wikipedia.org/wiki/RC4#cite\_note-nec-58) developing ways to distinguish its output from a truly random sequence.

#### VMPC\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=19)]

Variably Modified Permutation Composition (VMPC) is another RC4 variant.[\[59\]](https://en.wikipedia.org/wiki/RC4#cite\_note-59) It uses similar key schedule as RC4, with j := S\[(j + S\[i] + key\[i mod keylength]) mod 256] iterating 3 × 256 = 768 times rather than 256, and with an optional additional 768 iterations to incorporate an initial vector. The output generation function operates as follows:

```
All arithmetic is performed modulo 256.
i := 0
while GeneratingOutput:
    a := S[i]
    j := S[j + a]
    
    output S[S[S[j] + 1]]
    Swap S[i] and S[j]          (b := S[j]; S[i] := b; S[j] := a))
    
    i := i + 1
endwhile
```

This was attacked in the same papers as RC4A, and can be distinguished within 238 output bytes.[\[60\]](https://en.wikipedia.org/wiki/RC4#cite\_note-maximov-60)[\[58\]](https://en.wikipedia.org/wiki/RC4#cite\_note-nec-58)

#### RC4+\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=20)]

RC4+ is a modified version of RC4 with a more complex three-phase key schedule (taking about three times as long as RC4, or the same as RC4-drop512), and a more complex output function which performs four additional lookups in the S array for each byte output, taking approximately 1.7 times as long as basic RC4.[\[61\]](https://en.wikipedia.org/wiki/RC4#cite\_note-rc4+-61)

```
All arithmetic modulo 256.  << and >> are left and right shift, ⊕ is exclusive OR
while GeneratingOutput:
    i := i + 1
    a := S[i]
    j := j + a
    
    Swap S[i] and S[j]               (b := S[j]; S[j] := S[i]; S[i] := b;)
    
    c := S[i<<5 ⊕ j>>3] + S[j<<5 ⊕ i>>3]
    output (S[a+b] + S[c⊕0xAA]) ⊕ S[j+b]
endwhile
```

This algorithm has not been analyzed significantly.

#### Spritz\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=21)]

In 2014, Ronald Rivest gave a talk and co-wrote a paper[\[14\]](https://en.wikipedia.org/wiki/RC4#cite\_note-Rivest2014-14) on an updated redesign called [Spritz](https://en.wikipedia.org/wiki/RC4#Spritz). A hardware accelerator of Spritz was published in Secrypt, 2016[\[62\]](https://en.wikipedia.org/wiki/RC4#cite\_note-62) and shows that due to multiple nested calls required to produce output bytes, Spritz performs rather slowly compared to other hash functions such as SHA-3 and the best known hardware implementation of RC4.

The algorithm is:[\[14\]](https://en.wikipedia.org/wiki/RC4#cite\_note-Rivest2014-14)

```
All arithmetic is performed modulo 256
while GeneratingOutput:
    i := i + w
    j := k + S[j + S[i]]
    k := k + i + S[j]
    swap values of S[i] and S[j]
    output z := S[j + S[i + S[z + k]]]
endwhile
```

The value w, is [relatively prime](https://en.wikipedia.org/wiki/Relatively\_prime) to the size of the S array. So after 256 iterations of this inner loop, the value i (incremented by w every iteration) has taken on all possible values 0...255, and every byte in the S array has been swapped at least once.

Like other [sponge functions](https://en.wikipedia.org/wiki/Sponge\_function), Spritz can be used to build a cryptographic hash function, a deterministic random bit generator ([DRBG](https://en.wikipedia.org/wiki/DRBG)), an encryption algorithm that supports [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated\_encryption) with associated data (AEAD), etc.[\[14\]](https://en.wikipedia.org/wiki/RC4#cite\_note-Rivest2014-14)

In 2016, Banik and Isobe proposed an attack that can distinguish Spritz from random noise.[\[63\]](https://en.wikipedia.org/wiki/RC4#cite\_note-63)

### RC4-based protocols\[[edit](https://en.wikipedia.org/w/index.php?title=RC4\&action=edit\&section=22)]

* [WEP](https://en.wikipedia.org/wiki/Wired\_Equivalent\_Privacy)
* [TKIP](https://en.wikipedia.org/wiki/Temporal\_Key\_Integrity\_Protocol) (default algorithm for [WPA](https://en.wikipedia.org/wiki/Wi-Fi\_Protected\_Access), but can be configured to use [AES-CCMP](https://en.wikipedia.org/wiki/AES-CCMP) instead of RC4)
* [BitTorrent protocol encryption](https://en.wikipedia.org/wiki/BitTorrent\_protocol\_encryption)
* [Microsoft Office XP](https://en.wikipedia.org/wiki/Microsoft\_Office\_XP) (insecure implementation since nonce remains unchanged when documents get modified[\[64\]](https://en.wikipedia.org/wiki/RC4#cite\_note-64))
* [Microsoft Point-to-Point Encryption](https://en.wikipedia.org/wiki/Microsoft\_Point-to-Point\_Encryption)
* [Transport Layer Security](https://en.wikipedia.org/wiki/Transport\_Layer\_Security) / [Secure Sockets Layer](https://en.wikipedia.org/wiki/Secure\_Sockets\_Layer) (was optional and then the use of RC4 was prohibited in RFC 7465)
* [Secure Shell](https://en.wikipedia.org/wiki/Secure\_Shell) (optionally)
* [Remote Desktop Protocol](https://en.wikipedia.org/wiki/Remote\_Desktop\_Protocol) (optionally)
* [Kerberos](https://en.wikipedia.org/wiki/Kerberos\_\(protocol\)) (optionally)
* [SASL](https://en.wikipedia.org/wiki/Simple\_Authentication\_and\_Security\_Layer) Mechanism Digest-MD5 (optionally, _historic_, obsoleted in RFC 6331)
* [Gpcode.AK](https://en.wikipedia.org/w/index.php?title=Gpcode.AK\&action=edit\&redlink=1), an early June 2008 computer virus for Microsoft Windows, which takes documents hostage for [ransom](https://en.wikipedia.org/wiki/Ransom) by obscuring them with RC4 and RSA-1024 encryption
* [PDF](https://en.wikipedia.org/wiki/Portable\_Document\_Format)
* [Skype](https://en.wikipedia.org/wiki/Skype) (in modified form)[\[65\]](https://en.wikipedia.org/wiki/RC4#cite\_note-65)

Where a protocol is marked with "(optionally)", RC4 is one of multiple ciphers the system can be configured to use.
