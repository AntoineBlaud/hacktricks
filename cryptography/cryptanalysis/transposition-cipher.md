# Transposition cipher

In [cryptography](https://www.wikiwand.com/en/Cryptography), a **transposition cipher** is a method of encryption by which the positions held by units of [plaintext](https://www.wikiwand.com/en/Plaintext) (which are commonly characters or groups of characters) are shifted according to a regular system, so that the [ciphertext](https://www.wikiwand.com/en/Ciphertext) constitutes a [permutation](https://www.wikiwand.com/en/Permutation) of the plaintext. That is, the order of the units is changed (the plaintext is reordered). Mathematically a [bijective](https://www.wikiwand.com/en/Bijective) function is used on the characters' positions to encrypt and an [inverse function](https://www.wikiwand.com/en/Inverse\_function) to decrypt.

Following are some implementations.

### Rail Fence cipher

The Rail Fence cipher is a form of transposition cipher that gets its name from the way in which it is encoded. In the rail fence cipher, the plaintext is written downwards and diagonally on successive "rails" of an imaginary fence, then moving up when we get to the bottom. The message is then read off in rows. For example, using three "rails" and a message of 'WE ARE DISCOVERED FLEE AT ONCE', the cipherer writes out:

```
W . . . E . . . C . . . R . . . L . . . T . . . E
. E . R . D . S . O . E . E . F . E . A . O . C .
. . A . . . I . . . V . . . D . . . E . . . N . .
```

Then reads off:

```
WECRL TEERD SOEEF EAOCA IVDEN
```

(The cipher has broken this ciphertext up into blocks of five to help avoid errors. This is a common technique used to make the cipher more easily readable. The spacing is not related to spaces in the plaintext and so does not carry any information about the plaintext.)

### Scytale

The rail fence cipher follows a pattern similar to that of the [scytale](https://www.wikiwand.com/en/Scytale), (pronounced "SKIT-uhl-ee") a mechanical system of producing a transposition cipher used by the [ancient Greeks](https://www.wikiwand.com/en/Ancient\_Greeks). The system consisted of a cylinder and a ribbon that was wrapped around the cylinder. The message to be encrypted was written on the coiled ribbon. The letters of the original message would be rearranged when the ribbon was uncoiled from the cylinder. However, the message was easily decrypted when the ribbon recoiled on a cylinder of the same diameter as the encrypting cylinder.[\[1\]](https://www.wikiwand.com/en/Transposition\_cipher#citenote1) Using the same example as before, if the cylinder has a radius such that only three letters can fit around its circumference, the cipherer writes out:

```
W . . E . . A . . R . . E . . D . . I . . S . . C
. O . . V . . E . . R . . E . . D . . F . . L . .
. . E . . E . . A . . T . . O . . N . . C . . E .
```

In this example, the cylinder is running horizontally and the ribbon is wrapped around vertically. Hence, the cipherer then reads off:

```
WOEEV EAEAR RTEEO DDNIF CSLEC
```

### Route cipher

In a route cipher, the plaintext is first written out in a grid of given dimensions, then read off in a pattern given in the key. For example, using the same plaintext that we used for [rail fence](https://www.wikiwand.com/en/Rail\_fence):

```
W R I O R F E O E 
E E S V E L A N J 
A D C E D E T C X 
```

The key might specify "spiral inwards, clockwise, starting from the top right". That would give a cipher text of:

```
EJXCTEDEC DAEWRIORF EONALEVSE
```

Route ciphers have many more keys than a rail fence. In fact, for messages of reasonable length, the number of possible keys is potentially too great to be enumerated even by modern machinery. However, not all keys are equally good. Badly chosen routes will leave excessive chunks of plaintext, or text simply reversed, and this will give cryptanalysts a clue as to the routes.

A variation of the route cipher was the Union Route Cipher, used by Union forces during the [American Civil War](https://www.wikiwand.com/en/American\_Civil\_War). This worked much like an ordinary route cipher, but transposed whole words instead of individual letters. Because this would leave certain highly sensitive words exposed, such words would first be concealed by [code](https://www.wikiwand.com/en/Code\_\(cryptography\)). The cipher clerk may also add entire null words, which were often chosen to make the ciphertext humorous.\[[_citation needed_](https://www.wikiwand.com/en/Wikipedia:Citation\_needed)]

### Columnar transposition

In a columnar transposition, the message is written out in rows of a fixed length, and then read out again column by column, and the columns are chosen in some scrambled order. Both the width of the rows and the permutation of the columns are usually defined by a keyword. For example, the keyword ZEBRAS is of length 6 (so the rows are of length 6), and the permutation is defined by the alphabetical order of the letters in the keyword. In this case, the order would be "6 3 2 4 1 5".

In a regular columnar transposition cipher, any spare spaces are filled with nulls; in an irregular columnar transposition cipher, the spaces are left blank. Finally, the message is read off in columns, in the order specified by the keyword. For example, suppose we use the keyword ZEBRAS and the message WE ARE DISCOVERED. FLEE AT ONCE. In a regular columnar transposition, we write this into the grid as follows:

```
6 3 2 4 1 5
W E A R E D
I S C O V E 
R E D F L E 
E A T O N C 
E Q K J E U 
```

providing five nulls (QKJEU), these letters can be randomly selected as they just fill out the incomplete columns and are not part of the message. The ciphertext is then read off as:

```
EVLNE ACDTK ESEAQ ROFOJ DEECU WIREE
```

In the irregular case, the columns are not completed by nulls:

```
6 3 2 4 1 5
W E A R E D 
I S C O V E 
R E D F L E 
E A T O N C 
E 
```

This results in the following ciphertext:

```
EVLNA CDTES EAROF ODEEC WIREE
```

To decipher it, the recipient has to work out the column lengths by dividing the message length by the key length. Then they can write the message out in columns again, then re-order the columns by reforming the key word.

In a variation, the message is blocked into segments that are the key length long and to each segment the same permutation (given by the key) is applied. This is equivalent to a columnar transposition where the read-out is by rows instead of columns.

Columnar transposition continued to be used for serious purposes as a component of more complex ciphers at least into the 1950s.

### Double transposition

A single columnar transposition could be attacked by guessing possible column lengths, writing the message out in its columns (but in the wrong order, as the key is not yet known), and then looking for possible [anagrams](https://www.wikiwand.com/en/Anagram). Thus to make it stronger, a double transposition was often used. This is simply a columnar transposition applied twice. The same key can be used for both transpositions, or two different keys can be used.

As an example, we can take the result of the irregular columnar transposition in the previous section, and perform a second encryption with a different keyword, STRIPE, which gives the permutation "564231":

```
5 6 4 2 3 1 
E V L N A C
D T E S E A
R O F O D E
E C W I R E
E
```

As before, this is read off columnwise to give the ciphertext:

```
CAEEN SOIAE DRLEF WEDRE EVTOC
```

If multiple messages of exactly the same length are encrypted using the same keys, they can be anagrammed simultaneously. This can lead to both recovery of the messages, and to recovery of the keys (so that every other message sent with those keys can be read).

During [World War I](https://www.wikiwand.com/en/World\_War\_I), the German military used a double columnar transposition cipher, changing the keys infrequently. The system was regularly solved by the French, naming it Übchi, who were typically able to quickly find the keys once they'd intercepted a number of messages of the same length, which generally took only a few days. However, the French success became widely known and, after a publication in [_Le Matin_](https://www.wikiwand.com/en/Le\_Matin\_\(France\)), the Germans changed to a new system on 18 November 1914.[\[2\]](https://www.wikiwand.com/en/Transposition\_cipher#citenote2)

During World War II, the double transposition cipher was used by [Dutch Resistance](https://www.wikiwand.com/en/Netherlands\_in\_World\_War\_II#Oppression\_and\_resistance) groups, the French [Maquis](https://www.wikiwand.com/en/Maquis\_\(World\_War\_II\)) and the British [Special Operations Executive](https://www.wikiwand.com/en/Special\_Operations\_Executive) (SOE), which was in charge of managing underground activities in Europe.[\[3\]](https://www.wikiwand.com/en/Transposition\_cipher#citenote3) It was also used by agents of the American [Office of Strategic Services](https://www.wikiwand.com/en/Office\_of\_Strategic\_Services)[\[4\]](https://www.wikiwand.com/en/Transposition\_cipher#citenote4) and as an emergency cipher for the German Army and Navy.

Until the invention of the [VIC cipher](https://www.wikiwand.com/en/VIC\_cipher), double transposition was generally regarded as the most complicated cipher that an agent could operate reliably under difficult field conditions.

#### Cryptanalysis

The double transposition cipher can be treated as a single transposition with a key as long as the product of the lengths of the two keys.[\[5\]](https://www.wikiwand.com/en/Transposition\_cipher#citenote5)

In late 2013, a double transposition challenge, regarded by its author as undecipherable, was solved by George Lasry using a divide-and-conquer approach where each transposition was attacked individually.[\[6\]](https://www.wikiwand.com/en/Transposition\_cipher#citenote6)

### Myszkowski transposition

A variant form of columnar transposition, proposed by Émile Victor Théodore Myszkowski in 1902, requires a keyword with recurrent letters. In usual practice, subsequent occurrences of a keyword letter are treated as if the next letter in alphabetical order, _e.g.,_ the keyword TOMATO yields a numeric keystring of "532164."

In Myszkowski transposition, recurrent keyword letters are numbered identically, TOMATO yielding a keystring of "432143."

```
4 3 2 1 4 3
W E A R E D
I S C O V E
R E D F L E
E A T O N C
E
```

Plaintext columns with unique numbers are transcribed downward; those with recurring numbers are transcribed left to right:

```
ROFOA CDTED SEEEA CWEIV RLENE
```

### Disrupted transposition

A disrupted transposition cipher[\[7\]](https://www.wikiwand.com/en/Transposition\_cipher#citenotemahalakshmi7) further complicates the transposition pattern with irregular filling of the rows of the matrix, i.e. with some spaces intentionally left blank (or blackened out like in the [Rasterschlüssel 44](https://www.wikiwand.com/en/Rasterschl%C3%BCssel\_44)), or filled later with either another part of the plaintext or random letters. One possible algorithm[\[7\]](https://www.wikiwand.com/en/Transposition\_cipher#citenotemahalakshmi7) is to start a new row whenever the plaintext reaches a password character. Another simple option[\[8\]](https://www.wikiwand.com/en/Transposition\_cipher#citenote8) would be to use a password that places blanks according to its number sequence. E.g. "SECRET" would be decoded to a sequence of "5,2,1,4,3,6" and cross out the 5th field of the matrix, then count again and cross out the second field, etc. The following example would be a matrix set up for columnar transposition with the columnar key "CRYPTO" and filled with crossed out fields according to the disruption key "SECRET" (marked with an asterisk), whereafter the message "we are discovered, flee at once" is placed in the leftover spaces. The resulting ciphertext (the columns read according to the transposition key) is "WCEEO ERET RIVFC EODN SELE ADA".

```
C R Y P T O
1 4 6 3 5 2
W E A R * E
* * D I S *
C O * V E R
E D * F L E
E * A * * T
O N * C E *
```

### Grilles

Another form of transposition cipher uses _grilles_, or physical masks with cut-outs. This can produce a highly irregular transposition over the period specified by the size of the grille, but requires the correspondents to keep a physical key secret. Grilles were first proposed in 1550, and were still in military use for the first few months of World War One.

### Detection and cryptanalysis

Since transposition does not affect the frequency of individual symbols, simple transposition can be easily detected by the [cryptanalyst](https://www.wikiwand.com/en/Cryptanalysis) by doing a frequency count. If the ciphertext exhibits a [frequency distribution](https://www.wikiwand.com/en/Frequency\_distribution) very similar to plaintext, it is most likely a transposition. This can then often be attacked by [anagramming](https://www.wikiwand.com/en/Anagram)—sliding pieces of ciphertext around, then looking for sections that look like anagrams of English words, and solving the anagrams. Once such anagrams have been found, they reveal information about the transposition pattern, and can consequently be extended.

Simpler transpositions also often suffer from the property that keys very close to the correct key will reveal long sections of legible plaintext interspersed by gibberish. Consequently, such ciphers may be vulnerable to optimum seeking algorithms such as [genetic algorithms](https://www.wikiwand.com/en/Genetic\_algorithm).[\[9\]](https://www.wikiwand.com/en/Transposition\_cipher#citenote9)

A detailed description of the cryptanalysis of a German transposition cipher can be found in chapter 7 of Herbert Yardley's "The American Black Chamber."

A cipher used by the [Zodiac Killer](https://www.wikiwand.com/en/Zodiac\_Killer), called "Z-340", organized into triangular sections with substitution of 63 different symbols for the letters and diagonal "knight move" transposition, remained unsolved for over 51 years, until an international team of private citizens cracked it on December 5, 2020, using specialized software.[\[10\]](https://www.wikiwand.com/en/Transposition\_cipher#citenote010)

### Combinations

Transposition is often combined with other techniques such as evaluation methods. For example, a simple [substitution cipher](https://www.wikiwand.com/en/Substitution\_cipher) combined with a columnar transposition avoids the weakness of both. Replacing high frequency ciphertext symbols with high frequency plaintext letters does not reveal chunks of plaintext because of the transposition. Anagramming the transposition does not work because of the substitution. The technique is particularly powerful if combined with fractionation (see below). A disadvantage is that such ciphers are considerably more laborious and error prone than simpler ciphers.

### Fractionation

Transposition is particularly effective when employed with fractionation – that is, a preliminary stage that divides each plaintext symbol into two or more ciphertext symbols. For example, the plaintext alphabet could be written out in a grid, and every letter in the message replaced by its co-ordinates (see [Polybius square](https://www.wikiwand.com/en/Polybius\_square) and [Straddling checkerboard](https://www.wikiwand.com/en/Straddling\_checkerboard)).[\[11\]](https://www.wikiwand.com/en/Transposition\_cipher#citenote11) Another method of fractionation is to simply convert the message to [Morse code](https://www.wikiwand.com/en/Morse\_code), with a symbol for spaces as well as dots and dashes.[\[12\]](https://www.wikiwand.com/en/Transposition\_cipher#citenote12)

When such a fractionated message is transposed, the components of individual letters become widely separated in the message, thus achieving [Claude E. Shannon](https://www.wikiwand.com/en/Claude\_E.\_Shannon)'s [diffusion](https://www.wikiwand.com/en/Confusion\_and\_diffusion). Examples of ciphers that combine fractionation and transposition include the [bifid cipher](https://www.wikiwand.com/en/Bifid\_cipher), the [trifid cipher](https://www.wikiwand.com/en/Trifid\_cipher), the [ADFGVX cipher](https://www.wikiwand.com/en/ADFGVX\_cipher) and the [VIC cipher](https://www.wikiwand.com/en/VIC\_cipher).

Another choice would be to replace each letter with its binary representation, transpose that, and then convert the new binary string into the corresponding ASCII characters. Looping the scrambling process on the binary string multiple times before changing it into ASCII characters would likely make it harder to break. Many modern [block ciphers](https://www.wikiwand.com/en/Block\_cipher) use more complex forms of transposition related to this simple idea.
