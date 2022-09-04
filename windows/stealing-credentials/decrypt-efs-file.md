# Decrypt EFS file



> A "raw" howto, for friends\
> Of course it's always better to use a backup of the user certificate, or a recovery certificate...

### Prerequistes

1. Encrypted file(s) access on a Windows system
   * Here I use a mapped partition on `d:\`
2. `SystemCertificates`, `Crypto` and `Protect` folders of the user (see [https://1drv.ms/x/s!AlQCT5PF61KjmCAhhYO0flOcZE4e](https://1drv.ms/x/s!AlQCT5PF61KjmCAhhYO0flOcZE4e))
   * Here it's in `d:\Users\Gentil Kiwi\AppData\Roaming\Microsoft`
3. One way to decrypt the good masterkey (usually the user password), or the masterkey itself
   * depending of the situation, it can be SHA1, NTLM, Domain backup Key, memory dump, etc... Here, I only describe password (`waza1234/`)

### Get informations and datas

#### About the certificate

```
> cipher /c "d:\Users\Gentil Kiwi\Documents\encrypted.txt"

 Liste de d:\Users\Gentil Kiwi\Documents\
 Les nouveaux fichiers ajoutés à ce répertoire seront chiffrés.

E encrypted.txt
  Niveau de compatibilité :
    Windows XP/Server 2003

  Utilisateurs pouvant déchiffrer :
    Gentil Kiwi(Gentil Kiwi@DESKTOP-HF8ESMF)
    Empreinte numérique du certificat : B53C 6DE2 83C0 0203 587A 03DD 3D0B F66E 1696 9A55

  Aucun certificat de récupération trouvé.

  Impossible de récupérer les informations sur la clé.

Le fichier spécifié n’a pas pu être déchiffré.
```

We know here that the only certificate & private key that can decrypt the `encrypted.txt` file has this digest **`B53C6DE283C00203587A03DD3D0BF66E16969A55`**

Of course, we don't have them.

```
> type "d:\Users\Gentil Kiwi\Documents\encrypted.txt"
Accès refusé.
```

#### Getting the certificate

```
mimikatz # crypto::system /file:"D:\Users\Gentil Kiwi\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\B53C6DE283C00203587A03DD3D0BF66E16969A55" /export

* File: 'D:\Users\Gentil Kiwi\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\B53C6DE283C00203587A03DD3D0BF66E16969A55'
[0045/1] BACKED_UP_PROP_ID
  00
[0019/1] SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID
  3915df0b8542999968d666acb050b95f
[000f/1] SIGNATURE_HASH_PROP_ID
  af0ea0cb980bc85c276ba9ea5e70b1824b723316
[0003/1] SHA1_HASH_PROP_ID
  b53c6de283c00203587a03dd3d0bf66e16969a55
[0002/1] KEY_PROV_INFO_PROP_ID
  Provider info:
        Key Container  : ffb75517-bc6c-4a40-8f8b-e2c555e30e34
        Provider       : Microsoft Enhanced Cryptographic Provider v1.0
        Provider type  : RSA_FULL (1)
        Type           : AT_KEYEXCHANGE (0x00000001)
        Flags          : 00000000
        Param (todo)   : 00000000 / 00000000

[0004/1] MD5_HASH_PROP_ID
  082428ded429d585b68588fd02acfeed
[0014/1] KEY_IDENTIFIER_PROP_ID
  b96699f3d9dc422d9a56d59c0711b31375d87ec8
[005c/1] SUBJECT_PUB_KEY_BIT_LENGTH_PROP_ID
  00080000
[0020/1] cert_file_element
  Data: 30820315308201fda00302010202106842ff10fbd7c79b46eefdb9035fe894300d06092a864886f70d01010505003016311430120603550403130b47656e74696c204b6977693020170d3136303631363231353733385a180f32313136303532333231353733385a3016311430120603550403130b47656e74696c204b69776930820122300d06092a864886f70d01010105000382010f003082010a0282010100cea66533c41baf75e40e4fb0943f8804f95623178e798cbc41269f08c21ef18f9d6c3172dc9ec8a6f6ba3eb209689faff74ca4a1937b0faca742210b52fa20347be60855b21dba8987c6e110c51ba33651cc9142314fce57fd4be8698704105a3bc48f404f70c77d04e3f3365142f6ed4c51fe02a751050fd1b71063be783f55c685d996b354bde35eca60026f288d52234abd531663cf7699e692c417141f224251d6606f5feb541c2c69ef7d1dcc591e419c74f2ee3a4a293a7b0204b12bd67639597d28f1e250cc9a84e276c71ae570c8247cfaec0f192594e702cbe16aaff3b3e8d702bbab16ea45af6f68805f3564bab247e3de29a52f8ba5eef429abbf0203010001a35d305b30150603551d25040e300c060a2b0601040182370a030430370603551d110430302ea02c060a2b060104018237140203a01e0c1c47656e74696c204b697769404445534b544f502d48463845534d460030090603551d1304023000300d06092a864886f70d01010505000382010100b6d295aa09c5523159eb48038b34fa542f8dfb10885ca582435ae61a3af1092e67125f9e8a7a1c4e6fd413c1c5b6ddf81835c714439ae6d70fa282c02f9283a7a1c8631ae6abccc3d671d0b3411bca4882385814876a3102f9bd6d7716decdeed5ca7ae0f95c503be99d14cd448a05e087a7e8d041515635b8c0ba0f16dc52c18b9df4ee79063496b1219961e2422ee662413a60abc22a04a24b8744cb95c0760be1911aae25e655df127b339fb798171597eab4054081e7f67dd4a77ceb7d37c0bf85fb526f08e0eb3e91094175b5b1d6a4f675de8aaa91608abe603f23be36b9b4fd167bf8b85cdf3dc22ee9e994bd90a4ecb0e3ec89a8e2a69c337a414d56
  Saved to file: B53C6DE283C00203587A03DD3D0BF66E16969A55.der
```

We now have the certificate and its **public** key in the `B53C6DE283C00203587A03DD3D0BF66E16969A55.der` file, and we know that the private key is in a container named **`ffb75517-bc6c-4a40-8f8b-e2c555e30e34`** from the `Microsoft Enhanced Cryptographic Provider v1.0` crypto provider.

#### About the private key

Unfortunately, private key filenames are not always linked to container names. You must test them, and compare `pUniqueName` field with the container name.

```
mimikatz # dpapi::capi /in:"D:\Users\Gentil Kiwi\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-494464150-3436831043-1864828003-1001\79e1ac78150e8bea8ad238e14d63145b_4f8e7ec6-a506-4d31-9d5a-1e4cbed4997b"
**KEY (capi)**
  dwVersion          : 00000002 - 2
  dwUniqueNameLen    : 00000025 - 37
  dwSiPublicKeyLen   : 00000000 - 0
  dwSiPrivateKeyLen  : 00000000 - 0
  dwExPublicKeyLen   : 0000011c - 284
  dwExPrivateKeyLen  : 0000064e - 1614
  dwHashLen          : 00000014 - 20
  dwSiExportFlagLen  : 00000000 - 0
  dwExExportFlagLen  : 000000fc - 252
  pUniqueName        : ffb75517-bc6c-4a40-8f8b-e2c555e30e34
  pHash              : 0000000000000000000000000000000000000000
  pSiPublicKey       :
  pSiPrivateKey      :
  pSiExportFlag      :
  pExPublicKey       : 525341310801000000080000ff00000001000100bfab29f4eea58b2fa529dee347b2ba64355f80686faf45ea16abbb02d7e8b3f3af6ae1cb02e79425190fecfa7c24c870e51ac776e2849acc50e2f1287d593976d62bb104027b3a294a3aeef2749c411e59cc1d7def692c1c54eb5f6f60d65142221f1417c492e69976cf631653bd4a23528d286f0260ca5ee3bd54b396d985c6553f78be6310b7d10f0551a702fe514cedf6425136f3e3047dc7704f408fc43b5a10048769e84bfd57ce4f314291cc5136a31bc510e1c68789ba1db25508e67b3420fa520b2142a7ac0f7b93a1a44cf7af9f6809b23ebaf6a6c89edc72316c9d8ff11ec2089f2641bc8c798e172356f904883f94b04f0ee475af1bc43365a6ce0000000000000000
  pExPrivateKey      :
  **BLOB**
    dwVersion          : 00000001 - 1
    guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
    dwMasterKeyVersion : 00000001 - 1
    guidMasterKey      : {1eccdbd2-4771-4360-8b19-9d6060a061dc}
    dwFlags            : 00000000 - 0 ()
    dwDescriptionLen   : 0000002a - 42
    szDescription      : Clé privée CryptoAPI
    algCrypt           : 00006610 - 26128 (CALG_AES_256)
    dwAlgCryptLen      : 00000100 - 256
    dwSaltLen          : 00000020 - 32
    pbSalt             : 27e9175d0d9bbaa8987782036b5ae2e8174bf1817f5d962196a94b4621f028a5
    dwHmacKeyLen       : 00000000 - 0
    pbHmackKey         :
    algHash            : 0000800e - 32782 (CALG_SHA_512)
    dwAlgHashLen       : 00000200 - 512
    dwHmac2KeyLen      : 00000020 - 32
    pbHmack2Key        : 898f558b700ccffc1d2fe16ca62bce66dfe0b78e6d8e4c593e774a342decb2f8
    dwDataLen          : 00000550 - 1360
    pbData             : 1bfa381970e93ec34b71d3b5cd104671b28d14c841d921823cad030755cb16078e38ecc4a0deddb09c97439b162a5efaecd21c50851a3489f0ad804263bd4164d14bdff85936840568cf25369df824965367dd05ff3bb40d35be52fe8425029ee4b154bc3da2bdc65be0029490024047f9b573a74dc6d624f385acbbfcf754585a0267d5397e91005d3bf4fe98bc4c23b82dc06947d42f30066bc4505e968e6b4e953fecde6dc22ac0ec7da82f0c3f6fc4462f3ac1ab8c8211ae76d44a239c2eab91282c60d90e47bed61d893f6551579383ca3f01cc234d276a64e8b13e80f2b4667a31b2d8252654139434489addccdd033db72874b6ecb5d3fa6d4cae0446c3aca78cb4d018ff8b7155df00d35412bb105613cdb4972302e90f3f5c88a766047743c0b2c77619abef8832752ed2798e0a0cd8ac6ec090185f0ec71f2f6069e8d3e1967c033659e4debe474c2faec7d9db9cfca9abca3a2266407269a3ef895bb82495038da5e64fd0051c354a26db29c9ea6d9d9969535683845fe1cd50767e210e8c2d9a5cf56f37c8a34411901bc7d09c7c2188beb84014958580b2f00a634f35fac920759f4655ca3645020d85c8abfcc1323ca8d8d799d4fc9dd20f6e18c7c0735bd57f064da02e676f80bfbec52a32f0dbc0d2f28f7d0009c07ae52ebad0ce0607888d89379d487ed93c4f4e175284f5e9ef73b511f71b37bbe6fb5485122ada686c747207912a0287130f29e3e24b5f51c6def3e7cea71314fabc99db7755e50bb464d75eef100dd89d1e6807029bb8b183b077955d3c8cfb0ba9bd9af6c8855589abdad4704d6d4bd86e93a4dca914ebc44fd54231bc91e56e6f80e22152d20412cd94adc3c979b8c580f55536926c3842df388bcbf9cdf9c51983a6a8e6cb66f9baf09d520ffd6fcbacfa30ba53de0dab1c1bba2955bfa9a97b36866da8e743b1f6fc1cdce22e094fa196c0ab80ed2a5c8406d1cdf0ed87a882905416d96a64fc2c66eaae645d939da9fa32b9b54eec5b11bc3085adb261e4bc6f7a0ea23b18c176e8518aa5df0ffb630359a55fdc702e7c12f363eb6029c9b0b281be5e0494a198a821b47f3a19dea41c5cbf7d2e0b0df045718b3b9167176b9765c82217ebde800a574c488b3a957a352f9e3ba6c15117539a4a31863fff6e7495517779fbf68c8cb0f8bcae14fcfd57a6dacfcf18eab8a80ef6edf16b4fc14eb98eb40a09349983ae5953971ad105732e3a89f1a9b3968b988aa1be111b76264a725086017bdedfc1be76a50864759d13b3be4ce6cf14d52c8a007c04e1581de43ad926516a8bed90056246f0c45b9d285047035f35493ac7be08add32205aafa45c2aa811bcf1f528511f6d9cde8c6b001379e87b78bf124f98122a627381c3ad445788999c448375e4324c11f984aade3a124ada9f403488a5c5f4f0d255481e4d1fcd0250562fa3f2e89215cf6600d49cab22433a303e74e95fa913e50616b1b85097ad68c73015109b89d6cea9e374aa842d2f405f6966719cc8310df5861f6625cab1b56140832654e46563525349a893d8d6ac8476e0d1c2626e866395472d2019467b7027cc4d219895e255a168b8382f98eb025afbc4417fb9ed05c77f8267af47f2be04e8296909b1d713079002129b3b81c0474ffa01011e1d517bf3a88e858d231525a5b8493d9f197cbc765971d8d3baba6a2c37fe889e108f200d70061f2c7e32f506761167a35ca91fca4bf0f927b88465304822a72350f276c275ff0b1cd31e6403abe6b1bdc0864dd27b4fc7d9fffacce30bb52448362202a0fc7d3493259ae299af0c42845290833438d25e5b35f75d082a66751ef3ea6e00b40a9533d610cdf4376feeb296486de8f144af4bc8cff4b53cbd7626d0d917505b4f542024af5bc6aa353b5b1e781
    dwSignLen          : 00000040 - 64
    pbSign             : 0733e4242e0aee05a87aee456ade99ccedce27548f93b96d9d1a2c029ab6ef2afa8d1027680a9f92a380e82752dab06409f74d15d978a72920d99fabbf1f4377

  pExExportFlag      :
  **BLOB**
    dwVersion          : 00000001 - 1
    guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
    dwMasterKeyVersion : 00000001 - 1
    guidMasterKey      : {1eccdbd2-4771-4360-8b19-9d6060a061dc}
    dwFlags            : 00000000 - 0 ()
    dwDescriptionLen   : 00000018 - 24
    szDescription      : Export Flag
    algCrypt           : 00006610 - 26128 (CALG_AES_256)
    dwAlgCryptLen      : 00000100 - 256
    dwSaltLen          : 00000020 - 32
    pbSalt             : c23d0a88fe308d2f0172a4ebaad46f4485f4638739bc7488e3ad0f858f415b5a
    dwHmacKeyLen       : 00000000 - 0
    pbHmackKey         :
    algHash            : 0000800e - 32782 (CALG_SHA_512)
    dwAlgHashLen       : 00000200 - 512
    dwHmac2KeyLen      : 00000020 - 32
    pbHmack2Key        : 05a72a929f5a7f5518887a7d082a2c7c25b444798c255d592e77b7b979e0360d
    dwDataLen          : 00000010 - 16
    pbData             : 2097aff03cd998c4fd1faf2bca7fe6c4
    dwSignLen          : 00000040 - 64
    pbSign             : bfddd1ab8552bff9b642cb695d351635d302019238c77e0495eb1a558b4eabada2802d1e33a63e9829700eaa7913abb83c9598f9b97c87fed793f3bd4fb90be3
```

We know that the private key is encrypted with the masterkey **`{1eccdbd2-4771-4360-8b19-9d6060a061dc}`**

#### Decrypting the masterkey

Here you must have the password of the user, but:

* You can use a hash instead of password (`/hash:xx`), NTLM for domain accounts, SHA1 for local accounts (so, not in the `SAM` database) ;
* You can use domain backup key to recover masterkeys ;
* In some cases, you can use a previous password with `CREDHIST` ;
* If you have a `LSASS`/`Kernel` full memory dump, you can find NTLM, SHA1 and some masterkeys in memory.

Here, we will use the cleartext password `waza1234/` and the SID: `S-1-5-21-494464150-3436831043-1864828003-1001` (`mimikatz` can get it from the masterkey path)

```
mimikatz # dpapi::masterkey /in:"D:\Users\Gentil Kiwi\AppData\Roaming\Microsoft\Protect\S-1-5-21-494464150-3436831043-1864828003-1001\1eccdbd2-4771-4360-8b19-9d6060a061dc" /password:waza1234/
**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {1eccdbd2-4771-4360-8b19-9d6060a061dc}
  dwFlags            : 00000005 - 5
  dwMasterKeyLen     : 000000b0 - 176
  dwBackupKeyLen     : 00000090 - 144
  dwCredHistLen      : 00000014 - 20
  dwDomainKeyLen     : 00000000 - 0
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : 477e4b37a7a3a0992c01cff93bb0af66
    rounds           : 00000ce4 - 3300
    algHash          : 0000800e - 32782 (CALG_SHA_512)
    algCrypt         : 00006610 - 26128 (CALG_AES_256)
    pbKey            : 7e86f2b7999a110b2d790774a74654448d662744e6376364e0119da902408f2755982f39501818c77192298576db414ffba65465dc070eb0c33cddd43ba646320e87f5d3ede1f7486ed581defc289e954704d18f1c8c25d0bc40803f48722a32bcc4514b3ce01461c7f540ec3b4463d4993522b4a91d47f9973933097b15850d32fa41151e59e596fa8cbda3afeefa61

[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : 3bd70f65d2bbb26b561f6a5fdd607710
    rounds           : 00000ce4 - 3300
    algHash          : 0000800e - 32782 (CALG_SHA_512)
    algCrypt         : 00006610 - 26128 (CALG_AES_256)
    pbKey            : e5eb7ff936303cf9d7f7639eb29a0fc5631990eed00d9451225942dace54ca257073fd2215a4f812fdbd8a4f39939d06159fb97b2421fda64e1451366b2f557c5b2630cf94d215143a6332f0ad27444991a69066390881f3a970a02b36a196f941238a6f1822c562196f8e44ffe8379d

[credhist]
  **CREDHIST INFO**
    dwVersion        : 00000003 - 3
    guid             : {d87e22e8-a2ac-42ba-af15-2edca2eb6547}


Auto SID from path seems to be: S-1-5-21-494464150-3436831043-1864828003-1001

[masterkey] with password: waza1234/ (normal user)
  key : d3fb9169447509d9a2d3d4f6fc0e84b4733a676add274094f91452b8fe4984ab8fe02326c8be8931122514b90f8d850205bb1a84db54fc72d1cffb521377bafc
  sha1: f2c9ea33a990c865e985c496fb8915445895d80b
```

We know that the masterkey is `d3fb9169447509d9a2d3d4f6fc0e84b4733a676add274094f91452b8fe4984ab8fe02326c8be8931122514b90f8d850205bb1a84db54fc72d1cffb521377bafc`. If you're lazy, you can use its SHA1: **`f2c9ea33a990c865e985c496fb8915445895d80b`**

#### Decrypting the private key

```
mimikatz # dpapi::capi /in:"D:\Users\Gentil Kiwi\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-494464150-3436831043-1864828003-1001\79e1ac78150e8bea8ad238e14d63145b_4f8e7ec6-a506-4d31-9d5a-1e4cbed4997b" /masterkey:f2c9ea33a990c865e985c496fb8915445895d80b
**KEY (capi)**
  dwVersion          : 00000002 - 2
  dwUniqueNameLen    : 00000025 - 37
  dwSiPublicKeyLen   : 00000000 - 0
  dwSiPrivateKeyLen  : 00000000 - 0
  dwExPublicKeyLen   : 0000011c - 284
  dwExPrivateKeyLen  : 0000064e - 1614
  dwHashLen          : 00000014 - 20
  dwSiExportFlagLen  : 00000000 - 0
  dwExExportFlagLen  : 000000fc - 252
  pUniqueName        : ffb75517-bc6c-4a40-8f8b-e2c555e30e34
  pHash              : 0000000000000000000000000000000000000000
  pSiPublicKey       :
  pSiPrivateKey      :
  pSiExportFlag      :
  pExPublicKey       : 525341310801000000080000ff00000001000100bfab29f4eea58b2fa529dee347b2ba64355f80686faf45ea16abbb02d7e8b3f3af6ae1cb02e79425190fecfa7c24c870e51ac776e2849acc50e2f1287d593976d62bb104027b3a294a3aeef2749c411e59cc1d7def692c1c54eb5f6f60d65142221f1417c492e69976cf631653bd4a23528d286f0260ca5ee3bd54b396d985c6553f78be6310b7d10f0551a702fe514cedf6425136f3e3047dc7704f408fc43b5a10048769e84bfd57ce4f314291cc5136a31bc510e1c68789ba1db25508e67b3420fa520b2142a7ac0f7b93a1a44cf7af9f6809b23ebaf6a6c89edc72316c9d8ff11ec2089f2641bc8c798e172356f904883f94b04f0ee475af1bc43365a6ce0000000000000000
  pExPrivateKey      :
  **BLOB**
    dwVersion          : 00000001 - 1
    guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
    dwMasterKeyVersion : 00000001 - 1
    guidMasterKey      : {1eccdbd2-4771-4360-8b19-9d6060a061dc}
    dwFlags            : 00000000 - 0 ()
    dwDescriptionLen   : 0000002a - 42
    szDescription      : Clé privée CryptoAPI
    algCrypt           : 00006610 - 26128 (CALG_AES_256)
    dwAlgCryptLen      : 00000100 - 256
    dwSaltLen          : 00000020 - 32
    pbSalt             : 27e9175d0d9bbaa8987782036b5ae2e8174bf1817f5d962196a94b4621f028a5
    dwHmacKeyLen       : 00000000 - 0
    pbHmackKey         :
    algHash            : 0000800e - 32782 (CALG_SHA_512)
    dwAlgHashLen       : 00000200 - 512
    dwHmac2KeyLen      : 00000020 - 32
    pbHmack2Key        : 898f558b700ccffc1d2fe16ca62bce66dfe0b78e6d8e4c593e774a342decb2f8
    dwDataLen          : 00000550 - 1360
    pbData             : 1bfa381970e93ec34b71d3b5cd104671b28d14c841d921823cad030755cb16078e38ecc4a0deddb09c97439b162a5efaecd21c50851a3489f0ad804263bd4164d14bdff85936840568cf25369df824965367dd05ff3bb40d35be52fe8425029ee4b154bc3da2bdc65be0029490024047f9b573a74dc6d624f385acbbfcf754585a0267d5397e91005d3bf4fe98bc4c23b82dc06947d42f30066bc4505e968e6b4e953fecde6dc22ac0ec7da82f0c3f6fc4462f3ac1ab8c8211ae76d44a239c2eab91282c60d90e47bed61d893f6551579383ca3f01cc234d276a64e8b13e80f2b4667a31b2d8252654139434489addccdd033db72874b6ecb5d3fa6d4cae0446c3aca78cb4d018ff8b7155df00d35412bb105613cdb4972302e90f3f5c88a766047743c0b2c77619abef8832752ed2798e0a0cd8ac6ec090185f0ec71f2f6069e8d3e1967c033659e4debe474c2faec7d9db9cfca9abca3a2266407269a3ef895bb82495038da5e64fd0051c354a26db29c9ea6d9d9969535683845fe1cd50767e210e8c2d9a5cf56f37c8a34411901bc7d09c7c2188beb84014958580b2f00a634f35fac920759f4655ca3645020d85c8abfcc1323ca8d8d799d4fc9dd20f6e18c7c0735bd57f064da02e676f80bfbec52a32f0dbc0d2f28f7d0009c07ae52ebad0ce0607888d89379d487ed93c4f4e175284f5e9ef73b511f71b37bbe6fb5485122ada686c747207912a0287130f29e3e24b5f51c6def3e7cea71314fabc99db7755e50bb464d75eef100dd89d1e6807029bb8b183b077955d3c8cfb0ba9bd9af6c8855589abdad4704d6d4bd86e93a4dca914ebc44fd54231bc91e56e6f80e22152d20412cd94adc3c979b8c580f55536926c3842df388bcbf9cdf9c51983a6a8e6cb66f9baf09d520ffd6fcbacfa30ba53de0dab1c1bba2955bfa9a97b36866da8e743b1f6fc1cdce22e094fa196c0ab80ed2a5c8406d1cdf0ed87a882905416d96a64fc2c66eaae645d939da9fa32b9b54eec5b11bc3085adb261e4bc6f7a0ea23b18c176e8518aa5df0ffb630359a55fdc702e7c12f363eb6029c9b0b281be5e0494a198a821b47f3a19dea41c5cbf7d2e0b0df045718b3b9167176b9765c82217ebde800a574c488b3a957a352f9e3ba6c15117539a4a31863fff6e7495517779fbf68c8cb0f8bcae14fcfd57a6dacfcf18eab8a80ef6edf16b4fc14eb98eb40a09349983ae5953971ad105732e3a89f1a9b3968b988aa1be111b76264a725086017bdedfc1be76a50864759d13b3be4ce6cf14d52c8a007c04e1581de43ad926516a8bed90056246f0c45b9d285047035f35493ac7be08add32205aafa45c2aa811bcf1f528511f6d9cde8c6b001379e87b78bf124f98122a627381c3ad445788999c448375e4324c11f984aade3a124ada9f403488a5c5f4f0d255481e4d1fcd0250562fa3f2e89215cf6600d49cab22433a303e74e95fa913e50616b1b85097ad68c73015109b89d6cea9e374aa842d2f405f6966719cc8310df5861f6625cab1b56140832654e46563525349a893d8d6ac8476e0d1c2626e866395472d2019467b7027cc4d219895e255a168b8382f98eb025afbc4417fb9ed05c77f8267af47f2be04e8296909b1d713079002129b3b81c0474ffa01011e1d517bf3a88e858d231525a5b8493d9f197cbc765971d8d3baba6a2c37fe889e108f200d70061f2c7e32f506761167a35ca91fca4bf0f927b88465304822a72350f276c275ff0b1cd31e6403abe6b1bdc0864dd27b4fc7d9fffacce30bb52448362202a0fc7d3493259ae299af0c42845290833438d25e5b35f75d082a66751ef3ea6e00b40a9533d610cdf4376feeb296486de8f144af4bc8cff4b53cbd7626d0d917505b4f542024af5bc6aa353b5b1e781
    dwSignLen          : 00000040 - 64
    pbSign             : 0733e4242e0aee05a87aee456ade99ccedce27548f93b96d9d1a2c029ab6ef2afa8d1027680a9f92a380e82752dab06409f74d15d978a72920d99fabbf1f4377

  pExExportFlag      :
  **BLOB**
    dwVersion          : 00000001 - 1
    guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
    dwMasterKeyVersion : 00000001 - 1
    guidMasterKey      : {1eccdbd2-4771-4360-8b19-9d6060a061dc}
    dwFlags            : 00000000 - 0 ()
    dwDescriptionLen   : 00000018 - 24
    szDescription      : Export Flag
    algCrypt           : 00006610 - 26128 (CALG_AES_256)
    dwAlgCryptLen      : 00000100 - 256
    dwSaltLen          : 00000020 - 32
    pbSalt             : c23d0a88fe308d2f0172a4ebaad46f4485f4638739bc7488e3ad0f858f415b5a
    dwHmacKeyLen       : 00000000 - 0
    pbHmackKey         :
    algHash            : 0000800e - 32782 (CALG_SHA_512)
    dwAlgHashLen       : 00000200 - 512
    dwHmac2KeyLen      : 00000020 - 32
    pbHmack2Key        : 05a72a929f5a7f5518887a7d082a2c7c25b444798c255d592e77b7b979e0360d
    dwDataLen          : 00000010 - 16
    pbData             : 2097aff03cd998c4fd1faf2bca7fe6c4
    dwSignLen          : 00000040 - 64
    pbSign             : bfddd1ab8552bff9b642cb695d351635d302019238c77e0495eb1a558b4eabada2802d1e33a63e9829700eaa7913abb83c9598f9b97c87fed793f3bd4fb90be3

Decrypting AT_EXCHANGE Export flags:
 * masterkey     : f2c9ea33a990c865e985c496fb8915445895d80b

01000000
Decrypting AT_EXCHANGE Private Key:
 * masterkey     : f2c9ea33a990c865e985c496fb8915445895d80b

525341320801000000080000ff00000001000100bfab29f4eea58b2fa529dee347b2ba64355f80686faf45ea16abbb02d7e8b3f3af6ae1cb02e79425190fecfa7c24c870e51ac776e2849acc50e2f1287d593976d62bb104027b3a294a3aeef2749c411e59cc1d7def692c1c54eb5f6f60d65142221f1417c492e69976cf631653bd4a23528d286f0260ca5ee3bd54b396d985c6553f78be6310b7d10f0551a702fe514cedf6425136f3e3047dc7704f408fc43b5a10048769e84bfd57ce4f314291cc5136a31bc510e1c68789ba1db25508e67b3420fa520b2142a7ac0f7b93a1a44cf7af9f6809b23ebaf6a6c89edc72316c9d8ff11ec2089f2641bc8c798e172356f904883f94b04f0ee475af1bc43365a6ce000000000000000027fc60e13eca2e1299234c00916c6a864ca3c834da67c49c7cf181279d845c45b95640301157afc3380ed77911235caab0b6d0c02d2ea3b38a00b2c9771d2995423b33554d865f7b56e7965fcf070445f86316e35487350782343d9b39bc912eefc298b1bfa2a8c0beb9360bbf711df7502439558c4dedbd5e24b8a0498760da00000000a9da86a8ee9474160ac17038b65061c6e2babf5c830753b2eb03e754dff61d79732c440d0318050bc76eeb7c15c8f5401b91602cca636c358c8306b165f966812d0e099a7c46c03c0852898c5404905aba8de44d62c3e7c5e066e1a16bbe5ee8ab70611da9f981a27449b1868ed20acb3a160ae4b8ab40521e26b61981a540f2000000004741d7a3cd5111047fb9eb70190c63e17fd4fabf00527d6098504b7c207a358f4cc59704dc05964753388f79c6de3a28fad764c3d700b3598ad3030256c9e48a475c89c67a1bf1f4f8aed9995965686bd9ccdcb18524c81e8e3e2138c35681f0ee53ae50e04ffc69ddc5c353d5568d4cff136d59ab061f9ae81bdf5ffd6181c300000000e180076963015447b6853b2420831696489b2bb7c7ddc8dd7b72440d655680135ffc8a717a719c8e107a13e514ed987f54967c5d641c7a96ee4f2581ead14f0a078cd91ddcaceda36ce8db6cc2c6e805045b6e36e7c31d557b9cca8a9884e2184bb9d7f04a665011b087b5f09622ad0c0af0cb6032d534c9622f64738c3d3adb00000000dc93548eccf25667a764f15768798d05c64f9a551bf84269f4f09e28180769f43d7bb9c3abc7be149467034438e20ed0e5324a926f972916d6855641cf564a9a2ccd0ec4bde399e1243674fa8030fdf16bdb8434668e2725084ac740c484d4d8155bf814dd8720644f1a1259291f2cf9c24805d992fa18ecac1f4135c4baf39c00000000b95ec0bf840fe8cb4e7aa64139f753e0a8430ff0491a763e52871085a0b555bb96b2025685264b4631f36e75567fb460487a583c3aa3772daf402707e1b6f6a8e93d4f853a1f9f32cf147974a6c6fa225ac2a8f13fade5dd4bf6e5ddf0fc94e03a6c37e0c70f9de1d80be7f0407fc660f24ccf98e45201678a82b457be3431f180b6a719f1e350e8feb870317f1e2b2549f8d29ca9e5d805f82d6b59bc1977b2b8c57ad114d7d8d9a8476a1e7a81d4d9b6c070050134f44d406be1d69440ab43ecee1d4da4f6805a9afa6539bce166f8c13f775c1ce813ba24773d936396f1e100be85edb556586b1461e03a1b52fc05bb2683a57fbbdd2f0514f3b668f62f1600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
        Exportable key : YES
        Key size       : 2048
        Private export : OK - 'raw_exchange_capi_0_ffb75517-bc6c-4a40-8f8b-e2c555e30e34.pvk'
```

How nice, this time we have the private key in the file **`raw_exchange_capi_0_ffb75517-bc6c-4a40-8f8b-e2c555e30e34.pvk`**

### Building the correct PFX

This time with `OpenSSL` version 1.x (it's not in `mimikatz`...yet?)

```
> openssl x509 -inform DER -outform PEM -in B53C6DE283C00203587A03DD3D0BF66E16969A55.der -out public.pem
> openssl rsa -inform PVK -outform PEM -in raw_exchange_capi_0_ffb75517-bc6c-4a40-8f8b-e2c555e30e34.pvk -out private.pem
> openssl pkcs12 -in public.pem -inkey private.pem -password pass:mimikatz -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

### Installing the PFX

```
> certutil -user -p mimikatz -importpfx cert.pfx NoChain,NoRoot
```

(or by the GUI of course)

### Data access

```
> type "d:\Users\Gentil Kiwi\Documents\encrypted.txt"
clear!
```

(or by the GUI of course)
