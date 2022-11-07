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



> Pierre de Fermat est très connu pour son grand théorème concernant la non-existence de solutions entières positives de l’équation pour chaque entier Toutefois, une de ses plus importantes contributions aux mathématiques modernes est sa méthode tout à fait originale pour factoriser des grands nombres.

Plusieurs considèrent Fermat comme le fondateur (avec Blaise Pascal) de la théorie des probabilités et comme un précurseur du calcul différentiel par sa méthode de recherche des maximums et des minimums d’une fonction. Toutefois, sa méthode tout à fait originale pour factoriser des grands nombres est une de ses plus grandes contributions aux mathématiques modernes, et c’est souvent un fait dont l’importance est négligée.

#### ![Fermat](https://accromath.uqam.ca/wp-content/uploads/2019/10/Fermat.png)Pierre de Fermat (1601-1665)

Le mathématicien français Pierre de Fermat était d’abord et avant tout un avocat et un officiel du gouvernement dans la ville de Toulouse. Dans ses temps libres, il exerçait sa passion pour les mathématiques et la physique. Même si on peut le qualifier de « mathématicien amateur », il est néanmoins passé à l’histoire comme fondateur de la théorie moderne des nombres.

#### Comment fait-on pour « factoriser » un nombre?

D’entrée de jeu, il est bien d’expliquer ce qu’on veut-on dire par « factoriser » un nombre. D’abord, rappelons que, selon le théorème fondamental de l’arithmétique, tout entier supérieur à 1 peut s’écrire comme un produit de nombres premiers et cette représentation est unique si on écrit ses facteurs premiers en ordre croissant. Ainsi, le nombre 60 peut s’écrire comme et cette factorisation est unique.

#### Nombre premier et nombre composé

Un entier n > 1 est appelé _nombre premier_ s’il n’est divisible que par 1 et par lui-même. Ainsi 7 est un nombre premier car ses seuls diviseurs entiers sont 1 et 7, alors que 6 n’est pas premier puisqu’il est non seulement divisible par 1 et 6, mais il l’est aussi par 2 et 3. Un entier n > 1 qui n’est pas premier est appelé _nombre composé_.

#### Est-il important de connaître la factorisation d’un nombre?

La réponse est OUI, à tout le moins depuis quelques décennies, plus précisément depuis 1978, année de la création de la méthode de chiffrement RSA largement utilisée de nos jours pour sécuriser les transactions bancaires. Cette méthode tient au fait que bien qu’il soit facile de multiplier des nombres, il est en contrepartie très difficile de faire le chemin inverse, c’est-à-dire de prendre un grand nombre composé et de trouver ses facteurs premiers. D’où la course sur la planète pour trouver des algorithmes de factorisation de plus en plus performants qui pourraient « casser » le code RSA. C’est ainsi qu’en 1976, à l’aide des algorithmes connus et des ordinateurs de l’époque, on estimait qu’il faudrait plus de 1020 années pour arriver à factoriser 2251 – 1, un nombre de 76 chiffres. Aujourd’hui, en utilisant un logiciel de calcul installé sur un ordinateur de bureau, il est possible d’obtenir cette factorisation en moins d’une minute.

Cependant, le véritable défi est d’être en mesure de factoriser des nombres arbitraires de 300 chiffres et plus, ce qui est présentement impossible, même à l’aide d’ordinateurs très puissants. D’où l’intérêt pour la recherche de nouveaux algorithmes de factorisation.

#### Comment s’y prendre pour factoriser un nombre?

Comment pourrions-nous procéder pour factoriser un nombre composé dont on ne connaît à priori aucun facteur? De toute évidence, on s’intéresse ici seulement à la factorisation des nombres impairs, car autrement, il suffit de diviser par 2 le nombre à factoriser jusqu’à ce qu’il « devienne » impair. À titre d’exemple, pour trouver la factorisation du nombre _n_ = 11 009, on peut utiliser l’approche tout à fait naturelle qui consiste à examiner successivement la divisibilité de _n_ par chacun des nombres premiers 3, 5, 7, 11 et ainsi de suite. En procédant ainsi, on constate éventuellement que ce nombre n est divisible par 101 et que _n_ = 101 × 109, menant du coup à la factorisation 11 009 = 101 × 109. Bravo! Mais avouez que cela a été un peu laborieux, car on a dû vérifier la divisibilité de n par chacun des nombres premiers inférieurs à 101. D’ailleurs, on se convainc aisément que pour un nombre arbitraire n, il aurait fallu vérifier la divisibilité par chacun des nombres premiers plus petits que Cela veut dire que pour un nombre de 200 chiffres, il faudrait vérifier sa divisibilité par tous les nombres premiers de moins de 100 chiffres, un travail colossal ! C’est pourquoi il est légitime de se demander s’il existe des méthodes plus efficaces pour factoriser des nombres. Or, justement, Pierre de Fermat en a trouvé une, qui s’avère d’une simplicité déconcertante (Voir encadré).

#### La méthode de factorisation de Fermat

D’entrée de jeu, on peut supposer que le nombre _n_ à factoriser n’est pas un carré parfait, car sinon, on s’attardera tout simplement à la factorisation du nombre Débutons avec un exemple. Si on vous demande de factoriser le nombre 899, peut-être allez-vous écrire

et le tour est joué ! Quelle chance que 899 soit une différence de deux carrés, n’est-ce pas? Non, pas du tout, car en réalité c’est le cas de tout entier positif impair composé, et c’est l’idée de base de la méthode de factorisation de Fermat. En effet, pour un tel entier _n_, il existe nécessairement deux entiers tels que auquel cas

Pourquoi? Supposons que n=rs avec On peut facilement vérifier que les nombre et sont tels que Mais comment fait-on pour trouver ces deux entiers _a_ et _b_? Certes on a et donc auquel cas Ici, désigne le plus grand entier Commençons donc par poser Si est un carré parfait, disons alors nous avons trouvé _a_ et _b_, comme requis. Autrement (c’est-à-dire si n’est pas un carré parfait), on choisit et ainsi de suite jusqu’à ce que l’on trouve un entier positif _k_ tel que le nombre soit tel que est un carré parfait, que l’on écrit alors comme Ce processus a une fin, en ce sens qu’on va éventuellement trouver un nombre _b_ tel que et cela parce que l’on sait déjà que fait l’affaire.

Pour illustrer sa méthode, Fermat a choisi le nombre

Il obtient d’abord que et commence ainsi avec

comme 45 0302 – 2 027 651 281 = 49 619

n’est pas un carré parfait, il pose ensuite _a_ = 45 031, qui ne produit pas non plus de carré parfait, et ainsi de suite jusqu’à ce qu’il pose _a_ = 45 041, qui donne

Fermat conclut alors que

Si on choisit de programmer cette méthode avec le logiciel de calcul Python[1](https://accromath.uqam.ca/2019/10/lheritage-de-fermat-pour-la-factorisation-des-grands-nombres/#fn-14139-1), on peut écrire ceci (dans le cas particulier _n_ = 2 027 651 281):

import math\
n = 2 027 651 281\
a=math.floor(math.sqrt(n))+1\
b=math.sqrt(a\*\*2-n)\
while b !=int(b) :\
a+=1\
b=sqrt(a\*\*2 – n)\
print (« a=% d et b=% d —>\
n= %d x % d » %(int(a),int(b),int(a- b),int(a+b)))

ce qui donnera

_a_ = 45 041 et _b_ = 1 020 et\
_n_ = 44 021 × 46 061.

#### La méthode de Fermat est-elle réellement efficace?

<figure><img src="https://accromath.uqam.ca/wp-content/uploads/2019/10/Fermat-1.png" alt=""><figcaption></figcaption></figure>

La réponse courte est: « Cela dépend de la nature du nombre à factoriser »[2](https://accromath.uqam.ca/2019/10/lheritage-de-fermat-pour-la-factorisation-des-grands-nombres/#fn-14139-2). Afin de donner une réponse précise à cette question, évaluons le nombre d’opérations élémentaires nécessaires pour exécuter la méthode de Fermat. Par « opération élémentaire », on entend l’addition, la soustraction, la multiplication, la division, l’élévation à une puissance et l’extraction de la racine carrée. Une opération élémentaire est aussi parfois appelée une « étape ». On dira d’un algorithme qu’il est « rapide » s’il s’exécute en peu d’étapes.

Étant donné un entier positif _n_ qui n’est pas un carré parfait, on dit que les nombres et sont les _diviseurs milieux_ de _n_ si est le plus grand diviseur de _n_ inférieur à et On peut alors démontrer que le nombre _k_ d’étapes requises pour factoriser _n_ via la méthode de Fermat est exactement

soit essentiellement la différence entre la moyenne arithmétique et la moyenne géométrique des diviseurs et En effet, comme on l’a vu ci-dessus (encadré), on a

Exécuter l’algorithme de Fermat consiste donc à chercher le plus petit entier tel que

est un entier.

Or, implique que et cela entraîne

#### Pour quels entiers l’algorithme de Fermat est-il rapide?

Le temps d’exécution pour factoriser un entier n en utilisant l’algorithme de Fermat sera court si ses diviseurs milieux sont près l’un de l’autre, c’est-à-dire près de (voir l’encadré ci-dessous). En contrepartie, si les diviseurs milieux sont éloignés l’un de l’autre, alors exécuter la méthode de Fermat peut prendre davantage de temps que la simple vérification de la divisibilité de _n_ par les petits nombres premiers (voir le deuxième encadré ci-dessous).

![Fermat-3](https://accromath.uqam.ca/wp-content/uploads/2019/10/Fermat-3.png)

#### ![fermat-encadré](https://accromath.uqam.ca/wp-content/uploads/2019/10/fermat-encadre%CC%81.png)Tirer le maximum de la méthode de Fermat

Comme on vient de le voir, si la distance qui sépare les diviseurs milieux d’un entier n est grande, la méthode de Fermat est peu efficace. On peut contourner ce problème en vérifiant au préalable la divisibilité de _n_ par les petits nombres premiers. Par exemple, supposons qu’on ose s’attaquer à la factorisation du nombre de 16 chiffres _n_ = 489 + 3 = 1 352 605 460 594 691. Appliquer naïvement la méthode de Fermat nous amènera sans doute à abandonner notre approche une fois rendu à quelques millions d’étapes. Une approche plus sensée consiste à d’abord identifier les possibles petits facteurs premiers de _n_, soit en vérifiant la divisibilité de _n_ par les nombres premiers inférieurs à 10 000 ou 100 000, disons, ce qu’on sera en mesure de réaliser très rapidement à l’aide d’un logiciel de calcul. C’est ainsi qu’on découvre que notre nombre _n_ est divisible par 3 et 1 249. Le problème se ramène alors à factoriser le nombre

Appliquer la méthode de Fermat à ce nouveau nombre donne

et cela après seulement 157 étapes. En rassemblant nos calculs, on obtient finalement que

Dans cet exemple, nous avons été chanceux car les deux plus grands facteurs premiers de n étaient proches l’un de l’autre. Il va de soi que ce n’est pas toujours le cas. C’est pourquoi, si après avoir éliminé les petits facteurs premiers de _n_, la méthode de Fermat prend trop de temps à dévoiler ses grands facteurs premiers, il est rassurant de savoir qu’il existe d’autres avenues.

#### Compliquer le problème pour mieux le simplifier

Une autre approche pour factoriser un nombre n est d’appliquer la méthode de Fermat à un nombre plus grand que _n_ lui-même, en fait à un multiple de _n_. Prenons par exemple le nombre _n_ = 54 641. Comme ce nombre est relativement petit, la méthode de Fermat trouvera sa factorisation, à savoir _n_ = 101 × 541, en 87 étapes, un nombre néanmoins plutôt grand compte tenu de la petite taille de n. Toutefois, si on avait su que l’un des facteurs premiers de n était approximativement 5 fois son autre facteur premier, on aurait pu préalablement multiplier _n_ par 5, permettant ainsi au nouveau nombre 5\_n\_ d’avoir ses diviseurs milieux essentiellement du même ordre de grandeur, de sorte que la méthode de Fermat appliquée au nombre 5\_n\_ aurait révélé ses facteurs 505 et 541 en une seule étape. Il aurait ensuite suffi de vérifier lequel de 505 et de 541 avait « hérité » du facteur artificiel 5, ce qui est bien sûr très facile à faire. Voila qui est bien facile lorsqu’on sait qu’un des facteurs est proche d’un multiple d’un autre facteur, une information dont on ne dispose malheureusement pas à l’avance!

Peut-on néanmoins explorer cette approche pour un nombre composé arbitraire? L’idée serait de considérer le nombre _n_ × _r_ pour un choix approprié de _r_. Par exemple, si _n = pq_ et _r = uv_, nous aurons _nr = pu × qv_, et si nous sommes chanceux, les deux nouveaux diviseurs _pu_ et _qv_ (de _nr_) seront suffisamment proches l’un de l’autre pour nous permettre d’appliquer l’algorithme de Fermat avec succès. En 1974, utilisant un raffinement de cette idée, R. Sherman Lehman est parvenu à montrer que l’on peut en effet accélérer la méthode de Fermat et de fait factoriser un entier impair _n_ en seulement \_n\_1/3 étapes.

#### Maurice Kraitchik 1882-1957

Mathématicien et vulgarisateur scientifique belge, Kraitchik s’est surtout intéressé à la théorie des nombres et aux mathématiques récréatives.

Il est l’auteur de plusieurs ouvrages sur la théorie des nombres rédigés entre 1922 et 1930. De 1931 à 1939, il a édité la revue _Sphinx_, un mensuel consacré aux mathématiques récréatives. Émigré aux Etats-Unis lors de la Seconde Guerre mondiale, il a enseigné à la New School for Social Research à New York. Il s’est particulièrement intéressé au thème général des _récréations mathématiques_.

#### Les nombreuses améliorations de l’idée originale de Fermat

Est-il possible de faire encore mieux ? Dans les années 1920, Maurice Kraitchik améliorait la méthode de Fermat et on sait aujourd’hui que son approche a constitué la base des principales méthodes modernes de factorisation des grands nombres. L’idée de Kraitchik est la suivante: plutôt que de chercher des entiers _a_ et _b_ tels que il suffit de trouver des entiers _u_ et _v_ tels que est un multiple de _n_. Par exemple, sachant que est un multiple du nombre on peut encore une fois profiter de l’identité

Dans notre cas, on peut écrire que

Comme tout facteur premier de _n_ doit obligatoirement être un facteur de 47 ou de 207, et comme 207 = 9 × 23, on peut rapidement conclure que _n_ = 23 × 47. Bien sûr, pour que cette approche soit efficace, il faut élaborer des astuces permettant de trouver des multiples du nombre à factoriser qui puissent s’écrire comme une différence de deux carrés. Or, c’est précisément ce que plusieurs mathématiciens ont réussi à faire au cours du vingtième siècle.

#### Où en est-on aujourd’hui?

On a vu qu’en optimisant la méthode originale de Fermat, R. Sherman Lehman pouvait factoriser un entier _n_ en environ étapes. Or, dans les années 1980, en faisant intervenir des outils mathématiques plus avancés, dont des notions d’algèbre linéaire, Carl Pomerance a davantage peaufiné la méthode originale de Fermat et créé une nouvelle méthode de factorisation connue sous le nom de crible quadratique. On sait montrer que dans la pratique, avec le crible quadratique, il suffit d’au plus étapes pour factoriser un nombre arbitraire _n_, ce qui peut faire une énorme différence lorsqu’il s’agit de factoriser de très grands nombres. C’est ainsi que le crible quadratique permet de factoriser un nombre _n_ de 75 chiffres en moins de

alors que la méthode de Lehman en requiert environ

Et dire que toute cette panoplie de méthodes de factorisation ont leur origine dans une idée de Fermat datant de plus de trois siècles et demi!

<figure><img src="https://accromath.uqam.ca/wp-content/uploads/2019/10/Fermat-5.png" alt=""><figcaption></figcaption></figure>

