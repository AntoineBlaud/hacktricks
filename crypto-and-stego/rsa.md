# RSA

Le **chiffrement RSA** (nommé par les initiales de ses trois inventeurs) est un [algorithme](https://fr.wikipedia.org/wiki/Algorithmique) de [cryptographie asymétrique](https://fr.wikipedia.org/wiki/Cryptographie\_asym%C3%A9trique), très utilisé dans le [commerce électronique](https://fr.wikipedia.org/wiki/Commerce\_%C3%A9lectronique), et plus généralement pour échanger des données confidentielles sur [Internet](https://fr.wikipedia.org/wiki/Internet). Cet algorithme a été décrit en 1977 par [Ronald Rivest](https://fr.wikipedia.org/wiki/Ronald\_Rivest), [Adi Shamir](https://fr.wikipedia.org/wiki/Adi\_Shamir) et [Leonard Adleman](https://fr.wikipedia.org/wiki/Leonard\_Adleman). RSA a été breveté[\[1\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-brevet-1) par le [Massachusetts Institute of Technology](https://fr.wikipedia.org/wiki/Massachusetts\_Institute\_of\_Technology) (MIT) en 1983 aux [États-Unis](https://fr.wikipedia.org/wiki/%C3%89tats-Unis). Le brevet a expiré le 21 septembre 2000.

### Fonctionnement général

Le [chiffrement](https://fr.wikipedia.org/wiki/Chiffrement) RSA est _asymétrique_ : il utilise une paire de clés (des nombres entiers) composée d'une _clé publique_ pour [chiffrer](https://fr.wikipedia.org/wiki/Chiffrement) et d'une _clé privée_ pour [déchiffrer](https://fr.wikipedia.org/wiki/Chiffrement) des données confidentielles. Les deux clés sont créées par une personne, souvent nommée [par convention](https://fr.wikipedia.org/wiki/Langage\_de\_la\_cryptologie) _Alice_, qui souhaite que lui soient envoyées des données confidentielles. Alice rend la clé publique accessible. Cette clé est utilisée par ses correspondants (_Bob_, etc.) pour chiffrer les données qui lui sont envoyées. La clé privée est quant à elle réservée à Alice, et lui permet de déchiffrer ces données. La clé privée peut aussi être utilisée par Alice pour [signer](https://fr.wikipedia.org/wiki/Signature) une donnée qu'elle envoie, la clé publique permettant à n'importe lequel de ses correspondants de vérifier la signature.

Une condition indispensable est qu'il soit « calculatoirement impossible » de déchiffrer à l'aide de la seule clé publique, en particulier de reconstituer la clé privée à partir de la clé publique, c'est-à-dire que les moyens de calcul disponibles et les méthodes connues au moment de l'échange (et le temps que le secret doit être conservé) ne le permettent pas.

Le chiffrement RSA est souvent utilisé pour communiquer une clé de [chiffrement symétrique](https://fr.wikipedia.org/wiki/Chiffrement\_sym%C3%A9trique), qui permet alors de poursuivre l'échange de façon confidentielle : Bob envoie à Alice une clé de chiffrement symétrique qui peut ensuite être utilisée par Alice et Bob pour échanger des données.

### Fonctionnement détaillé

Ronald Rivest, Adi Shamir et Leonard Adleman ont publié leur chiffrement en 1978 dans _A Method for Obtaining Digital Signatures and Public-key Cryptosystems_. Ils utilisent les [congruences sur les entiers](https://fr.wikipedia.org/wiki/Congruence\_sur\_les\_entiers) et le [petit théorème de Fermat](https://fr.wikipedia.org/wiki/Petit\_th%C3%A9or%C3%A8me\_de\_Fermat), pour obtenir des [fonctions à sens unique](https://fr.wikipedia.org/wiki/Fonction\_%C3%A0\_sens\_unique), avec brèche secrète (ou porte dérobée).

Tous les calculs se font modulo un nombre entier _n_ qui est le produit de deux [nombres premiers](https://fr.wikipedia.org/wiki/Nombre\_premier). Le [petit théorème de Fermat](https://fr.wikipedia.org/wiki/Petit\_th%C3%A9or%C3%A8me\_de\_Fermat) joue un rôle important dans la conception du chiffrement.

Les messages clairs et chiffrés sont des entiers inférieurs à l'entier _n_[\[2\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-2). Les opérations de chiffrement et de déchiffrement consistent à élever le message à une certaine puissance modulo _n_ (c'est l'opération d'[exponentiation modulaire](https://fr.wikipedia.org/wiki/Exponentiation\_modulaire)).

La seule description des principes [mathématiques](https://fr.wikipedia.org/wiki/Math%C3%A9matiques) sur lesquels repose l'algorithme RSA n'est pas suffisante. Sa mise en œuvre concrète demande de tenir compte d'autres questions qui sont essentielles pour la sécurité. Par exemple le couple (clé privée, clé publique) doit être engendré par un procédé vraiment aléatoire qui, même s'il est connu, ne permet pas de reconstituer la clé privée. Les données chiffrées ne doivent pas être trop courtes, pour que le déchiffrement demande vraiment un calcul modulaire, et complétées de façon convenable (par exemple par l'[Optimal Asymmetric Encryption Padding](https://fr.wikipedia.org/wiki/Optimal\_Asymmetric\_Encryption\_Padding)).

#### Création des clés

L'étape de création des clés est à la charge d'Alice. Elle n'intervient pas à chaque chiffrement car les clés peuvent être réutilisées. La difficulté première, que ne règle pas le chiffrement, est que Bob soit bien certain que la clé publique qu'il détient est celle d'Alice. Le renouvellement des clés n'intervient que si la clé privée est compromise, ou par précaution au bout d'un certain temps (qui peut se compter en années).

1. Choisir _p_ et _q_, deux [nombres premiers](https://fr.wikipedia.org/wiki/Nombre\_premier) distincts ;
2. calculer leur produit _n_ = _pq_, appelé _module de chiffrement_ ;
3. calculer φ(_n_) = (_p_ - 1)(_q_ - 1) (c'est la valeur de l'[indicatrice d'Euler](https://fr.wikipedia.org/wiki/Indicatrice\_d'Euler) en _n_) ;
4. choisir un entier naturel _e_ [premier avec](https://fr.wikipedia.org/wiki/Nombres\_premiers\_entre\_eux) φ(_n_) et strictement inférieur à φ(_n_), appelé _exposant de chiffrement_ ;
5. calculer l'entier naturel _d_, [inverse](https://fr.wikipedia.org/wiki/Inverse\_modulaire) de _e_ modulo φ(_n_), et strictement inférieur à φ(_n_), appelé _exposant de déchiffrement_ ; _d_ peut se calculer efficacement par l'[algorithme d'Euclide étendu](https://fr.wikipedia.org/wiki/Algorithme\_d'Euclide\_%C3%A9tendu).

Comme _e_ est premier avec φ(_n_), d'après le [théorème de Bachet-Bézout](https://fr.wikipedia.org/wiki/Th%C3%A9or%C3%A8me\_de\_Bachet-B%C3%A9zout) il existe deux entiers _d_ et _k_ tels que _ed_ = 1 + \_k\_φ(_n_), c'est-à-dire que _ed_ ≡ 1 (mod φ(_n_)) : _e_ est bien inversible modulo φ(_n_).

Dans tout le paragraphe précédent, on peut utiliser l’[indicatrice de Carmichael](https://fr.wikipedia.org/wiki/Indicatrice\_de\_Carmichael), ![{\displaystyle \lambda (n)}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/8f06b26d7cb84392c1891a14c32c4dbe7e3f5e92), qui divise φ(_n_)[\[réf. souhaitée\]](https://fr.wikipedia.org/wiki/Aide:R%C3%A9f%C3%A9rence\_n%C3%A9cessaire).

Le couple (_n_, _e_) — ou (_e_, _n_)[\[3\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-RSAp122-3) — est la _clé publique_ du chiffrement, alors que sa _clé privée_ est[\[4\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-4) le nombre _d_, sachant que l'opération de déchiffrement ne demande que la clef privée _d_ et l'entier _n_, connu par la clé publique (la clé privée est parfois aussi définie comme le couple (_d_, _n_)[\[3\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-RSAp122-3) ou le triplet (_p, q_, _d_)[\[5\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-5)).

#### Chiffrement du message

Si _M_ est un entier naturel strictement inférieur à _n_ représentant un message, alors le message chiffré sera représenté par

![{\displaystyle C\equiv M^{e}{\pmod {n\}},}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/c0f8acb6662bf4e913410838aacff91b035e2c7a)

l'entier naturel _C_ étant choisi strictement inférieur à _n_.

#### Déchiffrement du message

Pour déchiffrer _C_, on utilise _d_, l'inverse de _e_ modulo (_p_ – 1)(_q_ – 1), et l'on retrouve le message clair _M_ par

![{\displaystyle M\equiv C^{d}{\pmod {n\}}.}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/1221183ab1f0b1cae65f0dd666edd7fb490adeec)

#### Exemple

Un exemple avec de petits nombres premiers (en pratique il faut de très grands nombres premiers) :

1. on choisit deux nombres premiers _p_ = 3, _q_ = 11 ;
2. leur produit _n_ = 3 × 11 = 33 est le module de chiffrement ;
3. φ(_n_) = (3 – 1) × (11 – 1) = 2 × 10 = 20 ;
4. on choisit _e_= 3 (premier avec 20) comme exposant de chiffrement ;
5. l'exposant de déchiffrement est _d_ = 7, l'inverse de 3 modulo 20 (en effet _ed_ = 3 × 7 ≡ 1 mod 20).

La clé publique d'Alice est (_n_, _e_) = (33, 3), et sa clé privée est (_n_, _d_) = (33, 7). Bob transmet un message à Alice.

* Chiffrement de _M_ = 4 par Bob avec la _clé publique_ d'Alice : 43 ≡ 31 mod 33, le chiffré est _C_ = 31 que Bob transmet à Alice ;
* Déchiffrement de _C_ = 31 par Alice avec sa _clé privée_ : 317 ≡ 4 mod 33, Alice retrouve le message initial _M_ = 4.

Le mécanisme de signature par Alice, à l'aide de sa clé privée, est analogue, en échangeant les clés.

#### Justification

La démonstration repose sur le [petit théorème de Fermat](https://fr.wikipedia.org/wiki/Petit\_th%C3%A9or%C3%A8me\_de\_Fermat), à savoir que comme _p_ et _q_ sont deux nombres premiers, si _M_ n'est pas un multiple de _p_ on a la première égalité, et la seconde s'il n'est pas un multiple de _q_ :

![{\displaystyle M^{p-1}\equiv 1{\pmod {p\}}\ ,\ \ M^{q-1}\equiv 1{\pmod {q\}}.}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/b1c2321a24eb9a55d03ca240f8b2b51c5f860d0c)

En effet

![{\displaystyle C^{d}\equiv (M^{e})^{d}\equiv M^{ed}{\pmod {n\}}.}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/8eb4eeb60c891ce7c2e73d70342ee1d91487bcec)

Or

![ed\equiv 1{\pmod {(p-1)(q-1)\}}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/2e65b9bacf7a59054fa2ae1c693102ba015b9524)

ce qui signifie qu'il existe un entier _k tel que_

![{\displaystyle ed=1+k(p-1)(q-1)}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/0a0a645caa162834c7b69f6161fe61f07a09b1c8)

donc, si _M_ n'est pas multiple de _p_ d'après le petit théorème de Fermat

![M^{ed}\equiv M^{1+k(p-1)(q-1)}\equiv M\cdot \left(M^{p-1}\right)^{k(q-1)}\equiv M{\pmod {p\}}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/3919f97fa0a4ed054262a9b4c731281f1a0e7c36)

et de même, si _M_ n'est pas multiple de _q_

![{\displaystyle M^{ed}\equiv M{\pmod {q\}}.}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/e900c285bd155943941ba28ee67844fddd59286a)

Les deux égalités sont en fait réalisées pour n'importe quel entier _M_, car si _M_ est un multiple de _p_, _M_ et toutes ses puissances non nulles sont congrues à 0 modulo _p_. De même pour _q_.

L'entier ![M^{ed}-M](https://wikimedia.org/api/rest\_v1/media/math/render/svg/57915051431bc63b43bf448eeb25f6f006b35bd5) est donc un multiple de _p_ et de _q_, qui sont premiers distincts, donc de leur produit _pq_ = _n_ (on peut le voir comme une conséquence de l'unicité de la [décomposition en facteurs premiers](https://fr.wikipedia.org/wiki/D%C3%A9composition\_en\_facteurs\_premiers), ou plus directement du [lemme de Gauss](https://fr.wikipedia.org/wiki/Lemme\_d'Euclide#Lien\_entre\_PGCD\_et\_PPCM), sachant que _p_ et _q_ sont premiers entre eux, étant premiers et distincts).

#### Asymétrie

On constate que pour chiffrer un message, il suffit de connaître _e_ et _n_. En revanche pour déchiffrer, il faut _d_ et _n_.

Pour calculer _d_ à l'aide de _e_ et _n_, il faut trouver l'[inverse modulaire](https://fr.wikipedia.org/wiki/Inverse\_modulaire) de _e_ modulo (_p_ – 1)(_q_ – 1), ce que l'on ne sait pas faire sans connaître les entiers _p_ et _q_, c'est-à-dire la décomposition de _n_ en facteurs premiers.

Le chiffrement demande donc de pouvoir vérifier que de « très grands » nombres sont des nombres premiers, pour pouvoir trouver _p_ et _q_, mais aussi que le produit de ces deux très grands nombres, ne soit pas factorisable pratiquement. En effet les algorithmes efficaces connus qui permettent de vérifier qu'un nombre n'est pas premier ne fournissent pas de factorisation.

#### Théorème d'Euler

La valeur φ(_n_) de l'[indicatrice d'Euler](https://fr.wikipedia.org/wiki/Indicatrice\_d'Euler) en _n_ est l'[ordre du groupe](https://fr.wikipedia.org/wiki/Ordre\_\(th%C3%A9orie\_des\_groupes\)) des éléments inversibles de l’[anneau ℤ/nℤ](https://fr.wikipedia.org/wiki/Anneau\_%E2%84%A4/n%E2%84%A4). Ceci permet de voir immédiatement, par le [théorème d'Euler](https://fr.wikipedia.org/wiki/Th%C3%A9or%C3%A8me\_d'Euler\_\(arithm%C3%A9tique\)) (conséquence du [théorème de Lagrange](https://fr.wikipedia.org/wiki/Th%C3%A9or%C3%A8me\_de\_Lagrange)), que si _M_ est premier avec _n_, donc inversible (ce qui est le cas de « la plupart » des entiers naturels _M_ strictement inférieurs à _n_)

![M^{ed}\equiv M^{1+k\varphi (n)}\equiv M{\pmod {n\}}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/03f657f5c0e024f0cae845e7e6b291b4b3560cab)

soit de justifier le chiffrement RSA (pour de tels _M_).

Il s'avère que quand _n_ est un produit de nombres premiers distincts, l'égalité est vérifiée pour tout _M_[\[6\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-Demazure200863proposition\_2.19-6) (la démonstration est essentiellement celle faite ci-dessus pour RSA, dans le cas particulier où _n_ est un produit de deux nombres premiers).

### Implémentation

#### Engendrer les clefs

Le couple de clefs demande de choisir deux nombres premiers de grande taille, de façon qu'il soit calculatoirement impossible de factoriser leur produit.

Pour déterminer un nombre premier de grande taille, on utilise un procédé qui fournit à la demande un entier impair aléatoire d'une taille suffisante, un [test de primalité](https://fr.wikipedia.org/wiki/Test\_de\_primalit%C3%A9) permet de déterminer s'il est ou non premier, et on s'arrête dès qu'un nombre premier est obtenu. Le [théorème des nombres premiers](https://fr.wikipedia.org/wiki/Th%C3%A9or%C3%A8me\_des\_nombres\_premiers) assure que l'on trouve un nombre premier au bout d'un nombre raisonnable d'essais.

La méthode demande cependant un test de primalité très rapide. En pratique on utilise un test probabiliste, le [test de primalité de Miller-Rabin](https://fr.wikipedia.org/wiki/Test\_de\_primalit%C3%A9\_de\_Miller-Rabin)[\[7\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-7) ou une variante[\[8\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-8). Un tel test ne garantit pas exactement que le nombre soit premier, mais seulement une (très) forte probabilité qu'il le soit.

**Propriétés requises**

Pour éviter les failles de sécurité, les deux nombres premiers ![p](https://wikimedia.org/api/rest\_v1/media/math/render/svg/81eac1e205430d1f40810df36a0edffdc367af36) et ![q](https://wikimedia.org/api/rest\_v1/media/math/render/svg/06809d64fa7c817ffc7e323f85997f783dbdf71d) choisis pour construire le couple de clefs doivent satisfaire les propriétés suivantes[\[9\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-boyer-9):

L'exposant ![e](https://wikimedia.org/api/rest\_v1/media/math/render/svg/cd253103f0876afc68ebead27a5aa9867d927467) choisi doit quant à lui vérifier les propriétés suivantes[\[9\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-boyer-9):

#### Chiffrer et déchiffrer

Le calcul de ![\scriptstyle M=c^{d}\mod {n}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/0ed86df60240dd9e20b80b62886dd29633eaf0ae) ne peut se faire en calculant d'abord _cd_, puis le reste modulo _n_, car cela demanderait de manipuler des entiers beaucoup trop grands. Il existe des méthodes efficaces pour le calcul de l'[exponentiation modulaire](https://fr.wikipedia.org/wiki/Exponentiation\_modulaire).

On peut conserver une forme différente de la clé privée pour permettre un déchiffrement plus rapide à l'aide du [théorème des restes chinois](https://fr.wikipedia.org/wiki/Th%C3%A9or%C3%A8me\_des\_restes\_chinois).

### Sécurité

\[!\[.gitbook/assets/1683032450\_3842.svg]\(<.gitbook/assets/1683032450\_3842.svg>?uselang=fr)

Il faut distinguer les [attaques par la force brute](https://fr.wikipedia.org/wiki/Attaque\_par\_force\_brute), qui consistent à retrouver _p_ et _q_ sur base de la connaissance de _n_ uniquement, et les attaques sur base de la connaissance de _n_ mais aussi de la manière dont _p_ et _q_ ont été générés, du logiciel de cryptographie utilisé, d'un ou plusieurs messages éventuellement interceptés etc.

La sécurité de l'algorithme RSA contre les attaques par la force brute repose sur deux conjectures[\[9\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-boyer-9):

1. « casser » RSA de cette manière nécessite la [factorisation](https://fr.wikipedia.org/wiki/D%C3%A9composition\_en\_produit\_de\_facteurs\_premiers) du nombre _n_ en le produit initial des nombres _p_ et _q_,
2. avec les algorithmes classiques, le temps que prend cette factorisation croît exponentiellement avec la longueur de la clé.

Il est possible que l'une des deux conjectures soit fausse, voire les deux. Jusqu'à présent, ce qui fait le succès du RSA est qu'il n'existe pas d'[algorithme](https://fr.wikipedia.org/wiki/Algorithme) connu de la communauté scientifique pour réaliser une attaque force brute avec des ordinateurs classiques.

Le 2 décembre 2019, le plus grand nombre factorisé par ce moyen, en utilisant une méthode de calculs distribués, était long de 795 [bits](https://fr.wikipedia.org/wiki/Bit\_\(informatique\)). Les clés RSA sont habituellement de longueur comprise entre 1 024 et 2 048 bits. Quelques experts croient possible que des clés de 1 024 bits seront cassées dans un proche avenir (bien que ce soit controversé[\[réf. nécessaire\]](https://fr.wikipedia.org/wiki/Aide:R%C3%A9f%C3%A9rence\_n%C3%A9cessaire)), mais peu voient un moyen de casser de cette manière des clés de 4 096 bits dans un avenir prévisible[\[réf. nécessaire\]](https://fr.wikipedia.org/wiki/Aide:R%C3%A9f%C3%A9rence\_n%C3%A9cessaire). On peut néanmoins présumer que RSA reste sûr si la taille de la clé est suffisamment grande. On peut trouver la factorisation d'une clé de taille inférieure à 256 bits en quelques minutes sur un ordinateur individuel, en utilisant des logiciels librement disponibles[\[10\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-10). Pour une taille allant jusqu'à 512 bits, et depuis 1999, il faut faire travailler conjointement plusieurs centaines d'ordinateurs. Par sûreté, il est couramment recommandé que la taille des clés RSA soit au moins de 2 048 bits.

Si une personne possède un moyen « rapide » de factoriser le nombre _n_, tous les algorithmes de chiffrement fondés sur ce principe seraient remis en cause ainsi que toutes les données chiffrées dans le passé à l'aide de ces algorithmes.

En 1994, un algorithme permettant de factoriser les nombres en un temps non exponentiel a été écrit pour les [ordinateurs quantiques](https://fr.wikipedia.org/wiki/Calculateur\_quantique). Il s'agit de l'[algorithme de Shor](https://fr.wikipedia.org/wiki/Algorithme\_de\_Shor). Les applications des ordinateurs quantiques permettent théoriquement de casser le RSA par la force brute, ce qui a activé la recherche sur ce sujet ; mais actuellement ces ordinateurs génèrent des erreurs aléatoires qui les rendent inefficaces.

Les autres types d'attaques (voir [Attaques](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#Attaques) ci-dessous), beaucoup plus efficaces, visent la manière dont les [nombres premiers](https://fr.wikipedia.org/wiki/Nombres\_premiers) _p_ et _q_ ont été générés, comment _e_ a été choisi, si l'on dispose de messages codés ou de toute autre information qui peut être utilisée. Une partie de la recherche sur ce sujet est publiée mais les techniques les plus récentes développées par les entreprises de [cryptanalyse](https://fr.wikipedia.org/wiki/Cryptanalyse) et les organismes de renseignement comme la [NSA](https://fr.wikipedia.org/wiki/NSA) restent secrètes.

Il faut enfin noter que casser une clé par factorisation du nombre _n_ ne nécessite pas d'attendre d'avoir un message chiffré à disposition. Cette opération peut débuter sur base de la connaissance de la [clé publique](https://fr.wikipedia.org/wiki/Cl%C3%A9\_publique) seulement, qui est généralement libre d'accès. Dans ces conditions, si _n_ est factorisé, la [clé privée](https://fr.wikipedia.org/wiki/Cl%C3%A9\_priv%C3%A9e) s'en déduit immédiatement. Les conséquences de cette observation sont également qu'un code peut être cassé avant même son utilisation.

### Applications

Lorsque deux personnes souhaitent s'échanger des informations numériques de façon confidentielle, sur [Internet](https://fr.wikipedia.org/wiki/Internet) par exemple avec le [commerce électronique](https://fr.wikipedia.org/wiki/Commerce\_%C3%A9lectronique), celles-ci doivent recourir à un mécanisme de [chiffrement](https://fr.wikipedia.org/wiki/Cryptographie) de ces données numériques. RSA étant un algorithme de [chiffrement asymétrique](https://fr.wikipedia.org/wiki/Cryptographie\_asym%C3%A9trique), celui-ci hérite du domaine d'application de ces mécanismes de chiffrement. On citera :

* l'[authentification](https://fr.wikipedia.org/wiki/Authentification) des parties entrant en jeu dans l'échange d'informations chiffrées avec la notion de [signature numérique](https://fr.wikipedia.org/wiki/Signature\_num%C3%A9rique) ;
* le chiffrement des [clés symétriques](https://fr.wikipedia.org/wiki/Cryptographie\_sym%C3%A9trique) (nettement moins coûteuse en temps de calcul) utilisées lors du reste du processus d'échange d'informations numériques chiffrées.

Ce dernier est en fait intégré dans un mécanisme RSA. En effet, le problème des algorithmes symétriques est qu'il faut être sûr que la clé de chiffrement ne soit divulguée qu'aux personnes qui veulent partager un secret. RSA permet de communiquer cette clé symétrique de manière sûre. Pour ce faire, Alice va tout d'abord choisir une clé symétrique. Voulant échanger un secret avec Bob elle va lui transmettre cette clé symétrique en utilisant RSA. Elle va, pour cela, chiffrer la clé symétrique avec la clé publique (RSA) de Bob, ainsi elle sera sûre que seul Bob pourra déchiffrer cette clé symétrique. Une fois que Bob reçoit le message, il le déchiffre et peut alors utiliser la clé symétrique définie par Alice pour lui envoyer des messages chiffrés que seuls lui et Alice pourront alors déchiffrer.

### Attaques

Plusieurs attaques ont été proposées pour casser le chiffrement RSA[\[11\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-11).

#### Attaque de Wiener

L'[attaque de Wiener](https://fr.wikipedia.org/wiki/Attaque\_de\_Wiener) (1989) est exploitable si l'exposant secret _d_ est inférieur à ![{\displaystyle {\frac {1}{3\}}N^{\frac {1}{4\}}}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/31f4ed927296743c5934d2c34fb51284a430e0f3)[\[12\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-12). On peut retrouver dans ce cas l'exposant secret à l'aide du développement en fractions continues de ![{\frac {e}{N\}}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/e61bceedd1a63fbc0c421a051903584c1491fa3b)[\[13\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-wiener-13),[\[9\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-boyer-9).

#### Attaque de Håstad

L'attaque de [Håstad](https://fr.wikipedia.org/wiki/Johan\_H%C3%A5stad), l'une des premières attaques découvertes (en 1985), repose sur la possibilité que l'exposant public _e_ soit suffisamment petit. En interceptant le même message envoyé à au moins ![e](https://wikimedia.org/api/rest\_v1/media/math/render/svg/cd253103f0876afc68ebead27a5aa9867d927467) destinataires différents, il est possible de retrouver le message originel à l'aide du [théorème des restes chinois](https://fr.wikipedia.org/wiki/Th%C3%A9or%C3%A8me\_des\_restes\_chinois)[\[14\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-14),[\[9\]](https://fr.wikipedia.org/wiki/Chiffrement\_RSA#cite\_note-boyer-9).

#### Attaque par chronométrage (_timing attacks_)

[Paul Kocher](https://fr.wikipedia.org/wiki/Paul\_Kocher) a décrit en 1995 une nouvelle attaque contre RSA : en supposant que l’attaquante Ève en connaisse suffisamment sur les documents d'Alice et soit capable de mesurer les temps de déchiffrement de plusieurs documents chiffrés, elle serait en mesure d’en déduire rapidement la clef de déchiffrement. Il en irait de même pour la signature.

En 2003, Boneh et Brumley ont montré une attaque plus pratique permettant de retrouver la factorisation RSA sur une connexion réseau ([SSL](https://fr.wikipedia.org/wiki/Transport\_Layer\_Security)) en s’appuyant sur les informations que laissent filtrer certaines optimisations appliquées au théorème des restes chinois. Une façon de contrecarrer ces attaques est d'assurer que l'opération de déchiffrement prend un temps constant. Cependant, cette approche peut en réduire significativement la performance. C'est pourquoi la plupart des implémentations (mises en œuvre) RSA utilisent plutôt une technique différente connue sous le nom d'« aveuglement cryptographique » (_blinding_).

L'aveuglement se sert des propriétés multiplicatives de RSA en insérant dans le calcul une valeur secrète aléatoire dont l'effet peut être annulé. Cette valeur étant différente à chaque chiffrement, le temps de déchiffrement n'est plus directement corrélé aux données à chiffrer, ce qui met en échec l'attaque par chronométrage : au lieu de calculer ![\scriptstyle c^{d}{\pmod {n\}}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/90005e390fce4d91ae05b2e48c134b2661e2ae41), Alice choisit d'abord une valeur aléatoire secrète _r_ et calcule ![\scriptstyle (r^{e}c)^{d}{\pmod {n\}}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/887c4f329d3f129c4e78c87b48b4018c7df9468a). Le résultat de ce calcul est ![\scriptstyle rm{\pmod {n\}}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/e436fbeb5f7aa438a0ca754bb4094f293fb0daba) et donc l'effet de _r_ peut être annulé en multipliant par son inverse.

#### Attaque à chiffrés choisis (_Adaptive chosen ciphertext attacks_)

Tel que décrit dans cet article, RSA est un chiffrement déterministe, et ne peut donc pas être [sémantiquement sûr](https://fr.wikipedia.org/wiki/S%C3%A9curit%C3%A9\_s%C3%A9mantique). Une contremesure est l’utilisation d’un [schéma de remplissage](https://fr.wikipedia.org/wiki/Remplissage\_\(cryptographie\)) probabiliste de manière telle qu'aucune valeur de message, une fois chiffré, ne donne un résultat peu sûr, par exemple si _C = Me ≤ N_, une attaque simple est le calcul direct de la racine e-ième de C, qui n’aura pas été réduite modulo N.

## RSA Encryption

#### Resources

```
https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/

# Think about factordb.com to retrieve p and q from n
```

#### Theory

```
# Used
# c  → cyphertext
# m → Plaintext message converted as a number
# e  → public exponent
# d  → private exponent
# n  → modulo => p * q

# Encrypt
c = (m^e)[n] => pow(m,e,n)

# Decrypt
m = (c^d)[n] => pow(c,d,n)


# 5 times encryption
c = m^(e1 * e2 * e3 * e4 * e5)
m = c^(d1 * d2 * d3 * d4 * d5)

# Can get n and e from openssl like this
cat alice_pubkey.pem | openssl rsa -pubin -inform PEM -text -noout
```

#### Tips & Tricks

```
# Getting clear when you have c, d, n
text = pow(c, d, n)   # équivaut à text = (c^d)[n]
result = hex(text)
result = result.replace("0x", "").replace("L", "")
print(result.decode('hex'))

# Convert ASCII message to INT
int(binascii.hexlify(m),16)


# Convert INT message to ASCII
binascii.unhexlify(hex(m).split('x')[1])


# Get n and e from a public key in Python
from Crypto.PublicKey import RSA

key = RSA.importKey(open("public_key_path.pem").read())
n = key.n
e = key.e
```

#### Attacks : Public Key + Message

```
# Chovid99's Blog

# Factorization Attack:
→ When n is small, go for factordb.com

# When we can encrypt any messages:
-> n=GCD(c1​−m1e​,c2​−m2e​)
If the result is wrong, maybe what we got from the GCDGCDGCD is n∗GCD(k1,k2)n*GCD(k_{1}, k_{2})n∗GCD(k1​,k2​), and we just need to repeat the above equation and GCDGCDGCD it again.
https://chovid99.github.io/posts/csaw-ctf-2019/

# Fermat Attack
→ When n is quite small
https://github.com/Ganapati/RsaCtfTool


# E is unknow:
Use z3 

# p + q is bruteforce-able (sum not big)
try all from 0 to large number

# Weak prime generation
https://ctftime.org/writeup/23033

# When n is too big modulo is useless
https://chovid99.github.io/posts/cyber-apocalypse-ctf-2022/


# Low Exponent Attack: 
→ Usefull when e=3 and n is quite big because pow(m,e,n) == pow(m,e)


#Low Private Exponent Attack
if n is the modulus and d is the private exponent, with d < 1/3(n)¼, then given the
public key (e, n), an attacker can efficiently recover d (Boneh and Durfee have
recently improved the bound to d < n0.292).

# ROCA: 
→ Usable when RSA key has 512 bits long n


# Twin Primes: 
→ q = p + 2
→ Usefull is most cases when n is too bid and others attacks doesn\'t work
https://github.com/Ganapati/RsaCtfTool


# Boneh Durfee Attack:
→ Allows to go slightly faster then Wiener Attack because d < n^0.292
https://github.com/Ganapati/RsaCtfTool


# Partial Key Exposure Attack
If the modulus n is k bits long, given the (k/4) least
significant bits of d, an attacker can reconstruct all of d in time linear to (e log(e)),
where e is the public exponent. This means that if e is small, the exposure of a
quarter of bits of d can lead to the recovery of the whole private key d.
https://github.com/victini-lover/CSAW-Quals-2021-Writeups/tree/main/RSA-Pop-Quiz
https://github.com/Ganapati/RsaCtfTool


# Short RSA Secret Exponents
Short public exponents can be exploited when the same message is broadcast to many
parties [1]. To illustrate this attack, suppose that a message m is broadcast to three parties
whose public exponents are e1 = e2 = e3 = 3 and whose moduli are n1, n2, and n3. The
encrypted messages are
m3 mod n1, m3 mod n2, and m3 mod n3.

#Coron
n = pq
if we are given the high order 1/4 log2 n bits of p.

# Hint 
https://ctftime.org/writeup/29741


# Coppersmith attack 
For example if you know the most significant bits of the message. 
You can find the rest of the message with this method.
The usual RSA model is this one: you have a ciphertext c a modulus N and a public exponent e. Find m such that m^e = c mod N.
Now, this is the relaxed model we can solve: you have c = (m + x)^e, you know a part of the message, m, but you don't know x. For example the message is always something like "the password today is: [password]". Coppersmith says that if you are looking for N^1/e of the message it is then a small root and you should be able to find it pretty quickly.

Another case is factoring N knowing high bits of q.
The Factorization problem normally is: give N = pq, find q.
 In our relaxed model we know an approximation q' of q.
Here's how to do it with my implementation:
let f(x) = x - q' which has a root modulo q.
This is because x - q' = x - ( q + diff ) = x - diff mod q with the difference being diff = | q - q' |.
What is important here if you want to find a solution:
    we should have q >= N^0,5
    as usual XX is the upper bound of the root, so the difference should be: |diff| < XX
    https://github.com/pcw109550/write-up/tree/master/2020/DEFCON/coooppersmith
 
# weak q   
q = OpenSSL::BN.new(e).mod_inverse(p)
q = mod_inverse(p)
q = e ^ (-1) mod p
q * e = 1 mod p
q * e = k * p + 1                            # k is multiplier
q * q * e = q * (k * p + 1)
(q ^ 2) * e = (k * p * q) + q
(q ^ 2) * e = (k * N) + q                          # N = p * q
((q ^ 2) * e) - q = k * N
q = ((k * N) / e) ^ 2
```

\
Attacks : Several public keys

```bash
# Chinese Remainder Attack
→ Usable when 3 messages have the same exponent (c= m^3 mod (n^b * n^c * n^d))
→ chinese_reminder.py

# Common Modulus Attack:
→ Usable when you have 2 messages, 2 public keys and n1 == n2
https://github.com/Ganapati/RsaCtfTool

# Common Factor Attack:
→ Usable when you have 2 messages, and p1 = p2
https://github.com/Ganapati/RsaCtfTool

# Wiener Attack:
→ Usable when private exponen d is quite small compared to N (d < n^(1/4)) 
→ https://github.com/rk700/attackrsa
→ attackrsa -t wiener -n N_VALUE -e E_VALUE
https://github.com/Ganapati/RsaCtfTool
```

#### Remote Service allowing to decrypt

```
# Decipher Oracle in Python
from pwn import *
from Crypto.Util.number import *

n = <>
e = <>

c1 = <>
c2 = pow(2, e, n)

c = c1*c2

# If it's a process that is the Oracle
r = process("./oracle")

# If it's a socket that is the Oracle
# r = remote("ip",port)

r.recvuntil("where_firs_message_stop")
r.sendline(str(c))
res = r.recvline()
res = r.recvline()
dec = long_to_bytes(long(res.split(" ")[-1]) / 2)
print(dec)
```

### Pollard ‘s rho Method

This method is based on a fact known as the birthday paradox. If you have 23\
people in a room, the probability that at least 2 of them share the same birthday\
is greater than 50%. This fact might seem surprising to many people, thus the\
name. More generally, if you have a set with N elements and you draw elements\
at random (with replacement) from this set, then after around 1.2(N)½ draws you\
would expect to have drawn an element twice.

Pollard’s rho method works by successively picking at random numbers less than\
n. If p is an unknown prime divisor of n, then it follows from the above fact that\
after around 1.2p½ draws we would expect to have drawn xi, xj such that xi ≡ xj\
mod p. Thus we have p = gcd(xi – xj, n).

For this method to be effective, one has to choose a function from Zn into Zn\
which behaves “randomly” in Zn ( f(x) = x^2 +1 will do it), and starting with any x 0 in\
Zn, repeatedly calculate xj = f(xi- 1 ). One does not have to calculate gcd(xj – xi, n)\
for all previous numbers xj (which would require very large memory and would\
make the method nearly as expensive as exhaustive search). It has been shown\
that one needs only to compare xi with x2i. This decreases the requirement for\
storage and the number of operations, but it can happen that we might miss an\
early collision, which would only be caught later. The spatial description of the\
sequence of elements xi is of the Greek letter ρ (rho), starting at the tail, iterating\
until it meets the tail again, and then it cycles on from there until the prime p is\
found.

The runtime of this algorithm is therefore proportional to the size of the smallest\
prime dividing n. For the size of today’s RSA moduli this method is impractical.\
But Pollard’s rho method was used on the factorization of the eighth Fermat\
number 2256 + 1, which unexpectedly had a small prime factor.

### Elliptic Curve Method

The Elliptic Curve Factorization method was introduced by H. W. Lenstra in\
1985, and can be seen as a generalization of Pollard’s p – 1 method. The\
success of Pollard’s method depends on n having a divisor p such that p – 1 is\
smooth; if no such p exists, the method fails. The Elliptic Curve method\
randomizes the choice, replacing the group Zp (used in Pollard’s method) by a\
random elliptic curve over Zp. Because the order of the elliptic curve group\
behaves roughly as a random integer close to p + 1, by repeatedly choosing\
different curves, one will find with high probability a group with B-smooth order\
(for a previously selected B), and computation in the group will provide a non-\
trivial factor of n.

The Elliptic Curve method has a (heuristic) subexponential runtime depending on\
the size of the prime factors of n, with small factors tending to be found first. The\
worst case is when p is roughly (n)½, which applies for RSA moduli. So although the method cannot be considered a threat against the standard (two-prime) RSA, it must nevertheless be taken into account when implementing the so-called “multi-prime” RSA, where the modulus may have more than two prime factors

### Quadratic Sieve and Number Field Sieve Methods

The Quadratic Sieve and the Number Field Sieve methods are the most widely\
used general-purpose factoring methods. Both are based on a method known as\
“Fermat Factorization”: one tries to find integers x, y, such that x^2 ≡ y^2 mod n but x\
≠ ± y mod n. In this case we have that n divides x^2 – y^2 = (x - y)(x + y), but it does\
not divide either term. It then follows that gcd(x - y, n) is a non-trivial factor of n. If\
n = pq, a random solution (x, y) of the congruence x^2 ≡ y^2 mod n would give us a\
factor of n with probability of 50%.

The general approach for finding solutions (x, y) of the congruence above is to\
choose a set of relatively small primes S = { p 1 , p 2 , ..., pt } (called factor base) and\
enough integers ai such that bi ≡ ai^2 mod n is the product of powers of primes in\
S. In this case every bi can be represented as a vector in the t-dimensional vector\
space over Z 2. If we collect enough bi’s (e. g., t+1 of them), then a solution of x^2 ≡\
y^2 mod n can be found by performing the Gaussian elimination on the matrix B =\
\[bi], with chance of at least 50% of finding a factor of n.

The first step above is called the “relation collection stage” and is highly\
parallelizable. The second step is called the “matrix step”, in which we work with\
a huge (sparse) matrix, and will eventually produce a non-trivial factor of n.

It should be clear that the choice of the number of primes of S is very important\
to the performance of the method: if this number is too small, the relation stage\
will take very long time, as a very small proportion of numbers will factor over a\
small set of primes. If we pick too many primes, the matrix will be too large to be\
efficiently reduced. Also crucial are the methods for choosing the integers ai’s\
and testing division by primes in S.

The Quadratic Sieve (QS) Method was invented by Carl Pomerance in 1981, and\
was until recently the fastest general-purpose factoring method. It follows the\
approach above, introducing an efficient way to determine the integers ai’s, by\
performing a “sieving process” (recall the “Sieve of Eratosthenes”). It has a\
subexponential runtime and was used in the factorization of the RSA- 129\
challenge number in 1994. The effort took around 8 months, with the factor base\
in this case containing 524,339 primes \[11].

The Number Field Sieve (NFS) Method is currently the fastest general-purpose\
factoring method. The technique is similar to the Quadratic Sieve, but it uses a\
factor base in the ring of integer of a suitably chosen algebraic number field \[10].\
From the sieving step on, the QS and NFS methods coincide. For NFS, the\
matrix is usually larger, but the initial step is more efficient. NFS has also a\
(heuristic) subexponential runtime, which is (asymptotically) better than the QS.\
Experiments show that NFS outperforms QS for numbers from 110-120 digits
