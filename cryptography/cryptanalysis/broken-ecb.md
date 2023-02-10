# Broken ECB

hey give us a telnet server that prompts us to send whatever string we want, and then it sends back an encrypted version of that string. Also they give us this source code for the server:

```
#!/usr/bin/python -u
from Crypto.Cipher import AES

flag = open("flag", "r").read().strip()
key = open('enc_key', 'r').read().strip().decode('hex')

welcome = """
************ MI6 Secure Encryption Service ************
                  [We're super secure]
       ________   ________    _________  ____________;_
      - ______ \ - ______ \ / _____   //.  .  ._______/ 
     / /     / // /     / //_/     / // ___   /
    / /     / // /     / /       .-'//_/|_/,-'
   / /     / // /     / /     .-'.-'
  / /     / // /     / /     / /
 / /     / // /     / /     / /
/ /_____/ // /_____/ /     / /
\________- \________-     /_/

"""

def pad(m):
  m = m + '1'
  while len(m) % 16 != 0:
    m = m + '0'
  return m

def encrypt():
  cipher = AES.new(key,AES.MODE_ECB)

  m = raw_input("Agent number: ")
  m = "agent " + m + " wants to see " + flag

  return cipher.encrypt(pad(m)).encode("hex")

print welcome
print encrypt()
```

We also get a web shell on hackcenter.com: literally an in-browser terminal emulator connected to the remote server (we do not have read access to the directory with “flag”), but for this problem we will just open our local Terminal app and poke around.

### Anything ECB is Bad Mmmkay

Look at the source: basically, `"agent " + yourinput + " wants to see " + flag` is padded out to the next nearest AES block length (128 bits == 16 bytes) and then encrypted with AES-ECB using whatever the key is. Now, basically the first thing you learn about block ciphers is to never use the Electronic Code Book (ECB) mode. You’ll see a photo of Tux the Linux mascot encrypted with AES-ECB and how you can still see the edges of the image in the encrypted version. But that’s about it. It’s rare to see an explanation of why this is relevant or how to break it. Just, “everyone knows it’s bad.”

The reason why ECB mode of any block cipher is bad is that the same input always encrypts to the same output. The input is broken into fixed-length blocks and encrypted, and all of the blocks of identical input will create similarly equal output blocks. The data is all encrypted, but we know where their plaintexts were the same. There is _no key recovery attack against this issue_, at least not that I am aware of, but the problem is that the plaintext can be guessed. There are two basic attacks against ECB:

1. Given enough encrypted blocks and some partial knowledge of the plaintext (known offsets of fixed data, like as defined by filetype formats or communication protocols), statistical and frequency analysis (and some guessing, then confirming) can reveal partial plaintext.
2. Given the ability to prefix or circumfix (that means insert in the middle somewhere) arbitrary plaintext, and then have it encrypted and view the resulting ciphertext, an attacker can stage what cryptographers call a Chosen Plaintext Attack (CPA). The scenario of passing arbitrary plaintext to a remote encryptor and receiving the ciphertext back is also called an [Oracle](https://en.wikipedia.org/wiki/Oracle\_machine#Applications\_to\_cryptography). This is the attack we will discuss in this post.

The reason why this is _relevant_ is that to the average programmer who can’t be bothered, ECB looks like a valid mode choice for AES, a cipher that people generally recommend: “military grade crypto,” right? They might use it to encrypt the cookie their web site stores in your browser. Or if they’re especially ignorant in security like the people who work at Adobe, [they might use it to encrypt their users’ passwords on the server](https://arstechnica.com/security/2013/11/how-an-epic-blunder-by-adobe-could-strengthen-hand-of-password-crackers/).

### Breaking ECB with the Chosen Plaintext Attack

Being able to circumfix our arbitrary input into the plaintext (at a known location in that string) means that we can choose an input such that we can fully align _our_ _known_ _substring_ on an AES block boundary. Thus allowing us to test what the ciphertext is for any arbitrary block that we choose.

```
"agent " + yourinput + " wants to see " + flag + padding
(6 chars)  (n chars)    (14 chars)   <—- if you want to test-encrypt a single block of arbitrary input, put your test input on a 16-byte block boundary, like so: yourinput = "01234567891000000000000000". "1000000000000000" is at bytes 16 through 31 of the input, aka the second AES (128-bit, 16-byte) block.
```

We don’t know how long the flag is, but we know how the padding is applied: if the plaintext message does not end on a 16-byte boundary, then it is extended by a single “1” and up to 14 “0” characters. If the plaintext message _does_ end on a 16-byte boundary, then it is extended by a full block of padding: `1000000000000000`. This may seem counter-intuitive, but there always has to be padding in a block cipher, even when the message length already is a multiple of the block length: otherwise how would you know if the last block is padding or if `1000000000000000` was part of the message?

See where we’re going with this? We will give the above plaintext, and observe the output’s 2nd block. That is the exact same output we would expect to see as the last block of ciphertext if the flag ends at a block boundary and the final block were AES padding.

```
Agent number: 01234567891000000000000000
ceaa6fa24a71971f21413c1ea39f4e7c53b1c1d36d11a2c20dfc3913bb299f11c9777890922460e74fefb1a94f5c95df0ebb6d7bc5a7922f0857283feb2b068dc5148be36b7670e2ca4fe52c3f65c37612b88acbe4bbd5a9f2588bbc4e0ea92453b1c1d36d11a2c20dfc3913bb299f11
```

Note the second block (32 hex characters = 16 bytes) of ciphertext is `53b1c1d36d11a2c20dfc3913bb299f11c` and, through a stroke of luck, we’ve already aligned the overall message on a block boundary too, as we see `53b1c1d36d11a2c20dfc3913bb299f11c` is also the last block of ciphertext!

The game now is to insert one _additional_ byte of arbitray text in order to push a single byte of the “flag” portion of the string rightward into the padding block. The final padding block will be `n100000000000000` where `n` is the unknown byte of flag.

What will we do then to guess that byte? We’ll brute-force it: send new plaintext messages for all 255 possibilities of `n` in our block-aligned arbitrary input (which is the 2nd block). When the ciphertext’s 2nd block matches the ciphertext’s 7th block, then we know we guessed correctly. Then we’ll insert one additional byte again at the same location, and repeat this process. In other words, we expect to send a series of messages like the following:

```
0123456789a100000000000000
0123456789b100000000000000
0123456789c100000000000000
0123456789d100000000000000
0123456789e100000000000000 ... let's say that ciphertext blocks 2 and 7 match at this point!
0123456789ae10000000000000
0123456789be10000000000000
0123456789ce10000000000000
0123456789de10000000000000
0123456789ee10000000000000
0123456789fe10000000000000 ... they match again. We so far know last block = fe10000000000000
0123456789afe1000000000000
0123456789bfe1000000000000
and so on, and so on... up to 255 guesses per byte and as many bytes as we need to discover
```

In practical terms, we can try guessing only in the ASCII range of 0x20-0x7E or so, since we expect the secret in this case to be plaintext (the “flag”). This will speed things up by more than double.

### Putting it All Togther: A Solution in Python

Knowing what to do is half the battle. The other half is coding it up and tearing your hair out over data alignment issues and dynamic typing issues.

```
#!/usr/bin/python

# Enigma2017 CTF, "Broken Encryption"

import sys
import time       # for using a delay in network connections
import telnetlib  # don't try using raw sockets, you'll tear your hair out trying to send the right line feed character

__author__ = 'michael-myers'

# TODO: I'm interested in any more elegant way to block-slice a Python string like this.
# Split out every 16-byte (32-hex char) block of returned ciphertext:
def parse_challenge(challenge):
    ciphertext_blocks = [challenge[0:32], challenge[32:64], challenge[64:96],
                         challenge[96:128], challenge[128:160], challenge[160:192],
                         challenge[192:224], challenge[224:]]
    return ciphertext_blocks


# To attack AES-ECB, we will be exploiting the following facts:
#   * we do not know all of the plaintext but we control a substring of it.
#* the controlled portion is at a known offset within the string.
#   * by varying our input length we can force the secret part onto a block boundary.
#   * we can choose our substring to be a full block of padding & align it at a boundary.
#   * if the message ends at a block boundary, the last 16-byte block will be all padding.
#   * thus we know when the secret part is block aligned; we'll see the same ciphertext.
#   * there is no nonce or IV or counter, so ciphertext is deterministic.
#   * by varying length of plaintext we can align the secret part such that there 
#is only one unknown byte at a time being encrypted in the final block of output. 
#* by varying one byte at a time, we can brute-force guess input blocks until we
#       match what we see in the final block, thus giving us one byte of the secret.
#   * we will limit our guesses to the ASCII range 0x20-0x7E for this particular challenge.
#
# Begin by changing the 2nd block of plaintext to n100000000000000, where n is a guess. 
# If the ciphertext[2nd block] == ciphertext[7th block] then the guess is correct,
# otherwise increment n.
def main():
    # If the Engima2017 servers are still up: enigma2017.hackcenter.com 7945
    if len(sys.argv) < 3:   # lol Python doesn't have an argc
        print 'Usage : python CTF-Challenge-Response.py hostname port'
        sys.exit()
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    guessed_secret = ""

    # Our input pads to the end of the 1st block, then aligns a guess at block 2.
    # Because we need to constantly alter this value, we are making it a bytearray. 
    # Strings in Python are immutable and inappropriate to use for holding data.
    chosen_plaintext = bytearray("0123456789" + "1000000000000000")

    # Guess each byte of the secret, in succession, by manipulating the 2nd plaintext
    # block (bytes 10 through 26) and looking for a matched ciphertext in the final block:
    for secret_bytes_to_guess in range(0, 64):
        # Add in a new guessing byte at the appropriate position:
        chosen_plaintext.insert(10, "?")

        # Guess over and over different values until we get this byte:
        for guessed_byte in range(0x20, 0x7E):  # this is the printable ASCII range.
            chosen_plaintext[10] = chr(guessed_byte)

            tn = telnetlib.Telnet("enigma2017.hackcenter.com", 7945)
            tn.read_until("Agent number: ")

            # Telnet input MUST BE DELIVERED with a \r\n line ending. If you send
            # only the \n the remote end will silently error on your input and send back
            # partially incorrect ciphertext! Untold hours debugging that bullshit.
            # Here we carefully convert the bytearray to ASCII and then to a string type, 
            # or else telnetlib barfs because of the hell that is dynamic typing.
            send_string = str(chosen_plaintext.decode('ascii') + "\r\n")
            tn.write(send_string)

            challenge = tn.read_all()
            tn.close()
            # time.sleep(0.5)   # (optional) rate-limit if you're worried about getting banned.

            ciphertext_blocks = parse_challenge(challenge)
            print "Currently guessing: " + chosen_plaintext[10:26]  # 2nd block holds the guess
            print "Chosen vs. final ciphertext blocks: " + ciphertext_blocks[1] + " <- ? -> " + ciphertext_blocks[6]

            # We're always guessing in the 2nd block and comparing result vs the 7th block:
            if ciphertext_blocks[1] == ciphertext_blocks[6]:
                print "Guessed a byte of the secret: " + chr(guessed_byte)
                guessed_secret = chr(guessed_byte) + guessed_secret
                break   # Finish the inner loop immediately, back up to the outer loop.

    print "All guessed bytes: " + guessed_secret

    print("Done")


if __name__ == "__main__":
    main()
```

And, after all of this, we uncover the flag: `54368eae12f64b2451cc234b0f327c7e_ECB_is_the_w0rst`

## `TUCTF 2018`

hought I'd give you an essential lesson to how you shouldn't get input for AES in ECB mode.

nc 18.218.238.95 12345

The server run the python file `redacted.py`

```
#!/usr/bin/env python2

from Crypto.Cipher import AES

from select import select

import sys

INTRO = """
Lol. You think you can steal my flag?
I\'ll even encrypt your input for you,
but you can\'t get my secrets!

"""

flag = "REDACTED" # TODO Redact this

key = "REDACTED" # TODO Redact this


if __name__ == '__main__':

    padc = 'REDACTED' #TODO Redact this

    assert (len(flag) == 32) and (len(key) == 32)

    cipher = AES.new(key, AES.MODE_ECB)

    sys.stdout.write(INTRO)
    sys.stdout.flush()

    while True:
        try:
            sys.stdout.write('Enter your text here: ')
            sys.stdout.flush()

            rlist, _, _ = select([sys.stdin], [], [])

            inp = ''
            if rlist:
                inp = sys.stdin.readline().rstrip('\n')

            plaintext = inp + flag
            l = len(plaintext)

            padl = (l // 32 + 1)*32 if l % 32 != 0 else 0

            plaintext = plaintext.ljust(padl, padc)

            sys.stdout.write('Here\'s your encrypted text:\n{}\n\n'.format((cipher.encrypt(plaintext)).encode('hex')))
        except KeyboardInterrupt:
            exit(0)
```

### Solution

#### Analysis of the code

* First of all we see that the challenge is based on AES in ECB mode. It is highly insecure when encrypting over multiple blocks. One of the reason is that we can differentiate text based of their ciphertext. This means that if we encrypt:

block 1, block 2, block 3 `aaaa....aaaa, bbbb....bbbb, aaaa....aaaa`

the ciphertext of the block 1 will be equals to the one in the block 3.

* In the code the flag size is constant to 32 characters, the exact size of a block.
* We can concatenate text on the left side of the flag before encryption.
* There is padding, and it is handled by adding the characted `padc` to the right size of the text until the text is a multiple of 32 characters (a block size).

#### The attack

The attack is a chosen plaintext attack. There is two steps needed to retreive the flag:

* Find the value of `padc`
* Char by char padding attack on the flag

**Find the value of `padc`**

In the next descriptions we renamed `padc` as `c`.

When sending one single character "a" to the server, there will be 2 blocks of the form: `"a" + flag [0:31]` and `"}" + ccccccc..cccccc`

So if we send `"}" + ccccc...cccccc + "a"`, there will be a 3rd block on the left with the exact same value as the rightmost block.

Then it's trivial to determine the value of `c`, we send all the possible ascii character that could be `c` (max 256 requests). If the ciphertext of the leftmost block is the same as the one on the rightmost block, it means that it is the correct padding character!

The code below achieved this results

```
#find the padding char
for i in range(64,256):
    char = chr(i)
    text = "}"+char * 31
    send_text = text+"a"
    conn.sendline(send_text)
    conn.recvline()
    code = conn.recvline()
    c1, c2, c3 = code[:64], code[64:128], code[128:192]
    if(c1 == c3):
        paddingChar = char
        break
    conn.recvline()
print("padding char is: "+paddingChar)
```

The padding character was `_`

**Char by char padding attack on the flag**

Now that we know `padc`, we will try to retreive a character of the flag.

This is the same idea as before, by trying to leak one unknown character at a time in the rightmost block. We put the same text on the leftmost block, and compare if the 2 ciphertexts are equals. (need max 256 requests / tries per unknown character).

Let's show one example to find the character before the "}" of the flag.

If we send `t+"}"+cccc....cccc+"aa"`, (`c` is the padding character) we will have these blocks:

block 1, block 2, block 3 `t+"}"+cccc....cccc, "aa" + flag[0:30], flag[31]+"}"+ccccccccccccc`

Then we will just have to test all possible ascii characters for `t` and compare the ciphertexts of the block 1 and the block 3 if they are equals.

Afterward we iterate to the next unknown character.

The code below implement this attack

```
#find the flag char by char
flag = ""
for i in range(31):
    for j in range(32,127):
        char = chr(j)
        text = char + flag + paddingChar * (31-i)
        send_text = text+"a"+"a"*i
        conn.recvuntil(":")
        conn.sendline(send_text)
        conn.recvline()
        code = conn.recvline()
        c1, c2, c3 = code[:64], code[64:128], code[128:192]
        if(c1 == c3):
            flag = char + flag
            print(flag)
            break
        conn.recvline()

print("The flag is: " + flag)
```

#### Full Code

The full code is available [here](https://github.com/ctf-epfl/writeups/blob/master/tuctf18/AESential%20Lesson/flag.py).

#### Flag

The flag is: `TUCTF{A3S_3CB_1S_VULN3R4BL3!!!!}`
