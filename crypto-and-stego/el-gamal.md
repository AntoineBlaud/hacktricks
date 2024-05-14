# El Gamal

$$
generation : d : = {1 …, q-1} ; e : = g^d
$$

$$
Encryption(m,e) r: = {1 …, q-1} ; c1 : = g^r ; c2 :=m*e^r
$$

$$
Decryption(c1,c2,d) m:= c2/c1^d
$$

### Breaking the ElGamal Scheme using a QR generator
