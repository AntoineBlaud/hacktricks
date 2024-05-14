# Cheat sheet maths

```
Si n est divisible par (a-b) alors   : a  mod(n) == b mod(n)
Si a et b premiers entre eux alors   : pgcd(a, b) = 1
Si a et b sont premiers entre eux    : xa + yb = 1
Si c|ab et pgcd(b, c) = 1  alors     : c|a
Si pgcd(a,n) = 1 alors il existe b   : ab=1
Si pgcd(a,n) = 1 alors	             : a ^ phi(n) mod(n) == 1 mod(n)
Si p est premier alors               : a^p mod(p) == a mod(p)
Si pgcd(a, b) = 1 alors              : phi(pq) = phi(p)phi(q)

phi(p) = p - 1
phi(pq) = (p-1)(q-1)


```

####

**ElGamal Signature Algorithm**

1. **Key Generation:**
   * Choose a large prime number $$pp$$ and a primitive root $$gg$$ modulo $$pp$$.
   * Select a private key $$x$$ randomly from the range $$1<x<p−1$$.
   * Compute the public key $$y=g^xmod  p$$.
2. **Signing:**
   * Choose a random integer $$kk$$ such that $$1<k<p−1$$ and $$gcd(k,p−1)=1$$.
   * Compute $$r=(g^kmod  p)mod  (p−1)$$.
   * Compute $$s=(k−1⋅(H(m)−x⋅r))mod  (p−1)$$, where $$H(m)$$ is the hash of the message $$m$$.
3. **Verification:**
   * Obtain the sender's public key $$(p,g,y)$$.
   * Verify that $$0<r<p−1$$ and $$0<s<p−1$$.
   * Compute $$v1=(y^r⋅r^smod  p)mod  (p−1)$$.
   * Compute $$v2=(g^H(m)mod  p)mod  (p−1)$$.
   * The signature is valid if $$v1=v2$$.

#### RSA (Rivest-Shamir-Adleman) Signature Algorithm:

1. **Génération des clés :**
   * Choisissez deux grands nombres premiers distincts, $$p$$ et $$q$$.
   * Calculez $$n=p×q$$, $$ϕ(n)=(p−1)×(q−1)$$.
   * Choisissez un exposant public $$ee$$ tel que $$1<e<ϕ(n)$$ et $$gcd(e,ϕ(n))=1$$.
   * Calculez l'exposant privé $$d$$ tel que $$d≡e^-1 mod  ϕ(n)$$.
2. **Signature :**
   * Calculez la valeur de hachage du message, $$H(m)$$.
   * Calculez la signature $$s$$ telle que $$s≡H(m)^dmod  n$$.
3. **Vérification :**
   * Obtenez la clé publique $$(n,e)$$ du signataire.
   * Calculez $$m′≡s^emod  n$$.
   * La signature est valide si $$m′≡H(m)mod  n$$.

#### ECDSA (Elliptic Curve Digital Signature Algorithm):

1. **Génération des clés :**
   * Choisissez une courbe elliptique définie sur un corps fini $$Fp$$.
   * Choisissez un point de base $$G$$ sur la courbe et un ordre $$n$$.
   * Choisissez une clé privée $$d$$ dans l'intervalle $$[1,n−1]$$.
   * Calculez la clé publique $$Q=d×G$$.
2. **Signature :**
   * Choisissez un entier aléatoire $$k$$ dans l'intervalle $$[1,n−1]$$.
   * Calculez le point $$(x1,y1)=k×G$$ sur la courbe.
   * Calculez $$r≡x1mod  n$$
   * Calculez $$s≡k−1×(H(m)+r×d)mod  n$$.
3. **Vérification :**
   * Obtenez la clé publique $$QQ$$ du signataire.
   * Calculez $$w≡s−1(mod  n)$$ et $$u1≡H(m)×w(mod  n)$$.
   * Calculez $$u2≡r×w(mod  n)$$.
   * Calculez le point $$(x1,y1)=u1×G+u2×Q$$.
   * La signature est valide si $$r≡x1 (mod  n)$$

#### Schnorr Signature Algorithm:

**Key Generation:**

* Select a prime number $$p$$ and a generator $$g$$ of the subgroup $$G$$ of order $$q$$ in the finite field $$Fp$$.
* Choose a private key $$x$$ randomly from the interval $$[1,q−1]$$.
* Compute the public key $$y=gxmod  p$$.

**Signature:**

* Choose a random nonce $$kk$$ from the interval $$[1,q−1][$$.
* Compute the commitment $$R=g^kmod  p$$.
* Compute the challenge $$e=H(R∥M)$$, where $$∥$$ denotes concatenation and $$M$$ is the message.
* Compute the response $$s=(k+x⋅e)mod  q$$.

**Verification:**

* Obtain the public key $$y$$ of the signer.
* Compute the commitment $$R′=g^s⋅y^(−e)mod  p$$.
* Compute the challenge $$e′=H(R′∥M)$$.
* The signature is valid if $$e′=e$$.

.

####
