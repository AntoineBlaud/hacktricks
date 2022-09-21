# CrewCTF

### **Corrupted (data img)**

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787028/yykrprxc0ppbkcgnynnt.png)

Après avoir télécharger le fichier, j’ai trouvé que c’est du « data », pourtant c’est une image de disque corrompu normalement.

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787029/qldinogfl6zh2nsr1m3y.png)

Alors, j’ai utiliser un éditeur hexadécimal (bless) pour vérifier son signature hexa.

J’ai trouvé beaucoup de A avant d’arriver à la vrai signature d’une partition NTFS. Alors, j’ai supprimé les A est j’ai enregistré.

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787030/hcedzprfiyivgloang7v.png)

Alors, maintenant il est détecter comme une normale partition, j’ai essayé de le monter:

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787031/ukghfodq1jwnzau6s0tz.png)

J’ai cherché un peu sur les fichiers et j’ai trouvé cette image avec le flag.

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787032/zrogighn5snxwlqa9of9.png)

_2 ème méthode:_

On peut utiliser Foremost

> Foremost est un logiciel Linux de récupération de données pour l’informatique légale, qui exploite les en-têtes, pieds de page et structures de données de fichiers endommagés via un processus nommé file carving, consistant en la récupération à partir de fragments privés de métadonnées de fichiers informatiques.
>
> Wikipédia

Une utilisation simple de Foremost va extraire la photo qui contient le flag .

## **Policy Violation Pt.1 (image E01)**

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787033/skkaj0hzx22tmqxmn3sb.png)

J’ai télécharger l’image, après j’ai trouvé un bon [article](https://andreafortuna.org/2018/04/11/how-to-mount-an-ewf-image-file-e01-on-linux/) sur comment comment ce type d’image. J’ai suivi les étapes pour le monter:

J’ai monter l’image image.E01, après j’ai trouvé le fichier ewf1.

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787034/r14eloitustaqtjf5mha.png)

J’ai monter le fichier ewf1 avec une commande qui me permet de récupérer les fichiers supprimés

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787036/pyxkce8ysgfqglmhzxcl.png)

Après j’ai utilisé l’outil [peepdf](https://github.com/jesparza/peepdf) qui m’a permet de détecter le CVE immédiatement.

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787037/wamnbjffzscy8dydxooo.png)

Après il suffit de chercher sur la base donnée de NVD pour trouver la date du vulnérabilité.

_2 eme méthode:_

J’ai utiliser Windows avec le logiciel ‘autospy’, c’est automatique hhhh

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787039/mljpkwlnkfmznl5npm2g.png)

J’ai trouvé trois fichiers, les deux fichier .txt sont clean (pas de malware), pourtant le fichier Invoice.pdf a un petit problème. Je l’ai récupérer

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787040/lv6r0aeayzp0ci3mcomv.png)

Après je l’ai mis sur [Virustotale](https://www.virustotal.com/gui/file/a1427cea9075350a8f60839c9244c8470c4c5ee996257f34d6195243b91e8c3d), après j’ai trouvé le numéro de CVE et pour la date de même, il suffit de chercher sur la base nvd.

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787041/ibishrcl8y39iujjfe7a.png)

## **Policy Violation Pt.2 (PDF)**

Ce challenge (**Policy Violation Pt.2**) je l’ai pu terminer après le ctf mdr ..

Ici il faut trouver l’adresse ip de l’attaquant.

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787042/ylpp513hzw0v54f0cnd0.png)

Après avoir essayer plain de chose, j’ai trouvé [un article](https://www.adlice.com/fr/infected-pdf-extract-payload/) assez intéressant qui m’a aidé à résoudre ce challenge. En utilisant le logiciel [PDF Stream Dumper](http://sandsprite.com/blogs/index.php?pid=57\&uid=7). Alors j’ai récupérer le fichier malveillant et je l’ai ouvert avec PDF Stream Dumper

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787044/kxzfpvo2z9hbrlllwhti.png)

Ici après avoir analyser le code on a compris que la payload qui est passé à la première fonction unescape contient le shell code utilisé pour avoir un shell à distance, alors forcement il contient l’adresse ip de l’attaquant pour avoir un reverse shell.

Après j’ai utilisé l’éditeur Javascript UI pour analyser le shell code, j’ai copié le payload ici et j’ai lancé ScDbg

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787046/kusic9po0v5o2x5pl3aw.png)

Ce qui me permet d’émuler le fonctionnement du shell code:

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787048/z2415giz373pwoz6todx.png)

il suffit de cliquer sur ‘Launch’ et après boom on va trouver l’adresse ip de l’attaquant:

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787049/me9yyyhgfbjr74nnrwof.png)

il reste seulement à calculer le hash du cette ip et on a trouvé le flag.

En fait, après j’ai vu qu’il y a d’autre méthode, c’est d’extraire le code malveillant via un script après l’analyser en utilisant la librairie  [libemu](https://github.com/buffer/libemu) qui permet d’émuler un shell code. Sinon, on peut utiliser l’outil [SCDBG](https://github.com/dzzie/SCDBG), c’est un shell code debugger.

## **Screenshot Pt.1 (No Extension)**

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787050/txpr20cracjxg0cnktas.png)

J’ai téléchargé le fichier et j’ai utilisé le logiciel Access Data FTK manager pour monter l’image du disque. La description du challenge montre qu’on doit trouvé une image.

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787051/atmovweshmxsoqwyfhjn.png)

J’ai exporté un fichier .CSV qui contient les hash et les nom de tout le fichier dans le disque et j’ai filtrer sur png, jpg après j’ai trouvé 5 image sur un dossier qui s’appel **ScreenSketch**

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787053/hymhq5dthmywpd9bxy0r.png)

Après j’ai trouvé 5 image dans le fichier AppData\Local\Packages\Microsoft.ScreenSketch\_8wekyb3d8bbwe\TempState. Après j’ai trouvé une image qui peut être celle recherchée.

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787056/uowt6n9pudmbuswfgjos.png)

Ce qui m’a attiré sur cette image c’est le texte en base64 en bas, alors j’ai essayé cette image est boom c’est la bonne.

## **Screenshot Pt.2 (No Extension)**

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787057/p7f609nhiw9kto0djgsm.png)

Ici on chercher un fichier lnk, après avoir cherché un peu j’ai trouvé[(dans cette article)](https://thinkdfir.com/category/uncategorized/) que après avoir pris un screen shot un fichier lnk est créer automatiquement (ancien version du logiciel). Et ce qui est interéssant c’est que ces fichiers sont stockés sur ScreenShot\Users\0xSh3rl0ck\AppData\Roaming\Microsoft\Windows\Recent.

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787058/syghv91cyscbwumvekzz.png)

Alors je me suis déplacé et j’ai trouvé 5 fichiers(qui correspondent au 5 images), alors j’ai pas pu déduire lequel et le bon donc j’ai testé les cinq hhhh, ce qui était bénef c’est que le fichier Excel que j’ai généré dans le challenges précédent contient aussi le md5 des fichiers. Après 2 tentatives la troisième était la bonne.

**Screenshot Pt.3**

Ici, il fallait chercher un texte secret alors j’ai immédiatement pensé au texte qui était chiffré en base64 sur l’image que j’ai déjà trouvé dans la première partie de ce challenge. Alors je l’ai décodé et j’ai trouvé enfin le flag

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787059/i74aawvaiu29bmmfpmk6.png)

Certes, j’ai perdu du temps dans l’histoire de I (I majuscule) et l (L minuscule). Mais enfin je l’ai trouvé.

![.gitbook/assets/1663787028.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787060/e1vgswpmblyo1jxropoy.png)

un simple cat du fichier permet de voir tous ces informations. Après j’ai remarqué que le fichier est envoyé depuis un compte google, alors j’ai fait de même et j’ai trouvé en fin de compte qu’il y a un attribut qui était supprimé au niveau du Header (X-Gm-Message-State:), donc le flag est :
