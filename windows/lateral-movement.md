# Lateral Movement

Penetration into the target network is just the first stage of a hacking attack. At the next stage, you have to establish a foothold there, steal users’ credentials, and gain the ability to run arbitrary code in the system. This article discusses techniques used to achieve the above goals and explains how to perform lateral movement in compromised networks.

After penetrating the external perimeter and getting into the internal corporate network, you have to expand your presence there. Surprisingly, but the larger is the internal corporate network, the easier can it be hacked. And vice versa, if the company is very small, its network may be extremely difficult to hack. Why is it so? The reason is simple: the larger is the network, the more vulnerable or misconfigured components it contains. In most cases, the compromise of a single node enables you to compromise multiple nodes adjacent to it at once.

Internal networks mostly consist of Windows servers and workstations. For attackers, this OS is of utmost interest because by default, it includes numerous interfaces for remote code execution. Furthermore, the attacker can extract user’s credentials from the system in multiple ways. Lateral movement between Linux servers is beyond the scope of this article: they are rarely included in domains and don’t offer such a broad range of default interfaces for remote administration. From the lateral movement perspective, a Linux PC is of interest only as a handy foothold.

Important: lateral movement involves 100% legitimate remote code execution. Accordingly, all techniques addressed in this article are based on the assumption that you have a valid account for a given PC. Furthermore, in many situation, an admin account is required.

When you perform lateral movement, your main priority is to attract as little attention from users and the security service as possible and avoid being detected by antivirus programs. The best way is to use the standard OS tools that are perfectly legitimate and indistinguishable from actions performed by network admins.

This article is not about numerous vulnerabilities plaguing Windows, or attacks on local networks, or privilege escalation in the Active Directory environment. It’s dedicated exclusively to legitimate aspects of a hacking attack: where to look for account credentials in Windows and what to do with them. The techniques addressed in it are not vulnerability exploits _per se_, but just tricks by design: if implemented properly, these procedures are perfectly legal.

The examples below are based on real situations you may encounter while exploring real-life internal networks. First, I am going to explain how to make your movement as quiet as possible and bypass antiviruses, and then I will separately address network ports required for that.

### Lateral movement strategy <a href="#h2-1" id="h2-1"></a>

Lateral movement combines two techniques:

* authenticated remote code execution; and&#x20;
* extraction of confidential information after gaining access.

Cyclical and sequential repetition of these steps sometimes allows to advance from a single compromised PC to the entire network infrastructure. Normally, lateral movement is performed to achieve one of the following goals:

* seize control over the domain controllers;
* reach to isolated critical network segments (e.g. the automatic process control system, SWIFT, etc.); or&#x20;
* search for critical information stored on a certain PC (confidential documents, billing data, etc.).

However, to achieve any of these goals, more and more credentials are required so that you can navigate through the network and gain access to more and more PCs. In most situations, to move freely through the internal network, you have to take over the domain controller: after doing so, you automatically gain access to nearly all nodes on the network. Speaking of [admins hunting](http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/), after reaching to the domain controller, it might seem that the search for privileged accounts is limited to blind guessing. But in fact, the Active Directory infrastructure and Windows itself disclose enough information to an ordinary domain user, so that you can identify the right movement direction and plan a sophisticated chain of hacks in the very beginning of lateral movement.

Sometimes, after taking over the domain controllers, you have to continue the movement to reach to a certain heavily guarded segment containing so-called ‘business risk’ objects. This might be a segment of the automatic process control system, interference into a technological process, access to a SWIFT segment (if you deal with a bank), access to the principal general’s computer, etc. In each case, you may encounter various lateral movement-related issues discussed below.

### Remote code execution in Windows <a href="#h2-2" id="h2-2"></a>

Below is an overview of tools that allow you to remotely execute arbitrary code on Windows systems using an existing account. Some of these programs support a handy interactive mode, while other just blindly run commands without displaying the result. This overview covers both handy and commonly used tools and less popular – but still capable to execute your code – ones.

Some of these utilities upload an executable service file to the target system to provide you with a handy interactive mode. But the problem is that such services are often blocked by antiviruses. The attacker’s IP can be blocked as well, which significantly slows down your movement. Furthermore, SOC becomes aware that somebody has penetrated into the network.

The lateral movement will mostly be performed using an amazing Python collection called [impacket](https://www.secureauth.com/labs/impacket/). To install it, run the command `pipinstallimpacket`. After the installation, the required executable files will be stored in the folder `impacket/examples`; to find it, type: `pipshow-fimpacket`.

#### MSRPC <a href="#h3-1" id="h3-1"></a>

This is a DCERPC implementation by Microsoft. It expands open-source DCERPC by adding to it access over the SMB protocol via named pipes and primarily uses TCP port 445. The [auxiliary/scanner/smb/pipe\_auditor](https://www.offensive-security.com/metasploit-unleashed/scanner-smb-auxiliary-modules/) module will determine what named pipes are available over SMB.

**psexec.exe**

* **Source**: [sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
* **AV risk**: no&#x20;
* **Used ports**: 135, 445, 4915x/TCP

Speaking of remote code execution on Windows, I cannot omit the well-known `psexec` utility created by Mark Russinovich. The program is equally popular among administrators and pentesters. It copies the executable file via the network resource `ADMIN$ (445/TCP)` and then remotely creates and launches a service for this executable file via `DCERPC (135,4915x/TCP)`. When the service is launched, you get a regular networking interaction with a remote command line:

The main advantage of the program is that the server component, `psexecsvc.exe`, is signed by the Sysinternals certificate belonging to Microsoft (i.e. the software is 100% legitimate). Another advantage of the classical `psexec.exe` is the ability to execute code in specified user sessions:

**psexec.py**

* **Source**: impacket Python collection
* **AV risk**: yes
* **Used ports**: 445/TCP

A great alternative for Linux users. However, this tool will most probably alert the antiviruses. As said above, this is because of the service copied to the remote host. The problem can be fixed by specifying an arbitrary command in the implementation of the `createService()` method in `/usr/local/lib/python3.7/dist-packages/impacket/examples/serviceinstall.py`; this command will be executed instead of the launched remote admin service.

<figure><img src=".gitbook/assets/1663772460.png" alt="Arbitrary command conceals the launch of the remote admin service"><figcaption><p>Arbitrary command conceals the launch of the remote admin service</p></figcaption></figure>

To prevent `psexec.py` from copying the suspicious component, you forcefully specify the file that must be used as a service. Because you have already written the command manually, this file can be anything.

As you can see, the `mkdirc:\pwn` command has been executed, which won’t ring the alarm bells for antiviruses. However, this `psexec` modification lacks the usability present in its initial version.

**winexe**

* **Source**: [winexe](https://sourceforge.net/projects/winexe/)
* **AV risk**: yes
* **Used ports**: 445/TCP

An older native analogue of `psexec` for Linux. Similar to `psexec`, opens a remote interactive command line:

The utility is similar to other such tools, but it’s more rarely detected by antiviruses. Of course, `winexe` isn’t 100% secure, but it can be used if, for some reason, `psexec.py` doesn’t work.

**smbexec.py**

* **Source**: impacket Python collection / built-in Windows component
* **AV risk**: yes
* **Used ports**: 445/TCP

A simplified version of `psexec`; it also creates a service, but uses for this purpose only MSRPC, and the service is controlled via the `svcctl` SMB pipe:

As a result, you gain access to an interactive command line.

**services.py**

* **Source**: impacket Python collection
* **AV risk**: no&#x20;
* **Used ports**: 445/TCP

An even simpler version of `psexec`. You have to manually perform operations that `psexec` performs automatically. To view the list of services, type:

Then create a new service and specify an arbitrary command:

Next, run the newly-created service:

And finally, cover-up the traces and delete the service.

This remote command execution technique is noninteractive – you cannot see results of your actions. But it’s 100% secure and I used it many times in situations when antiviruses installed on the remote host have killed all my hacking tools.

**atexec.py/at.exe**

* **Source**: impacket Python collection / built-in Windows component
* **AV risk**: no&#x20;
* **Used ports**: 445/TCP

This a Windows Task Scheduler service available via the `atsvc` SMB pipe. It allows you to remotely add to the scheduler a task that will be executed at the specified time.

`At.exe` is another noninteractive RCE technique. When you use it, the following commands are executed blindly:

By contrast, `atexec.py`, allows you to see the output of the executed command:

The only difference is that the command output is sent to a file and read using `ADMIN$`. To use this tool, you must ensure that the clocks on the attacking PC and on the target PC are synchronized to the exact minute.

**reg.exe**

* **Source**: Windows component
* **AV risk**: no&#x20;
* **Used ports**: 445/TCP

Remote access to the registry with writing permissions effectively grants you the RCE capacity. The utility uses the `winreg` SMB pipe. By default, the remote registry service is running only on server operating systems (Windows 2003-2019). Below is a popular trick involving the startup (delayed RCE):

The trick uses the program launch handler. If this program is frequently run on the target PC, you will get RCE almost instantly:

My favorite trick involving a backdoor in RDP:

#### DCERPC <a href="#h3-2" id="h3-2"></a>

DCERPC uses ports 135/TCP and 4915x/TCP (4915x are dynamically assigned ports). In some cases, ports from other ranges can be used as well.

In many companies, network admins and security specialists – who are aware of the most common attack vectors – simply block port 445/TCP as a mitigation, thus, making `psexec` and many other techniques unusable. However, as said above, Windows offers multiple ways for remote code execution, and DCERPC provides an alternative (in some situations, it even opens access to the same RPC interfaces). In fact, you use not DCERPC itself, but other tools based on its technology (e.g. WMI).

**wmiexec.py**

* **Source**: impacket Python collection
* **AV risk:** yes
* **Used ports:** 135, (445), 4915x/TCP

The `wmiexec.py` script allows you to execute code in the interactive mode:

Even though `wmiexec.py` doesn’t run any third-party executable files on the remote host, antiviruses sometimes detect it. In addition, `wmiexec.py` retrieves results from the `ADMIN$` share (i.e. uses port 445/TCP). Therefore, blind RCE is a more secure variant:

**dcomexec.py**

* **Source**: impacket Python collection
* **AV risk:** no&#x20;
* **Used ports:** 135, (445), 4915x/TCP

This tool is similar to `wmiexec.py`. By default, it’s interactive and retrieves results from `ADMIN$` via port 445/TCP:

To avoid the need to use port 445/TCP, you may execute your code blindly:

**wmis**

* **Origin:** wmi-client and wmis packages
* **AV risk:** yes
* **Used ports:** 135, 4915x/TCP

The `wmis` utility is present in two packages of the same name. To run it, use the following command:

There are no principal differences between the two versions with one exception: one of them may fail to work in your case.

**wmic.exe**

* **Origin:** Windows component
* **AV risk:** no&#x20;
* **Used ports:** 135, 4915x/TCP

A funny out-of-the box way to blindly execute code on all Windows versions:

This is the only Windows command that noninteractively receives the username and password via options, which means that you can run it from anywhere. Later, I will show how to use this command to attack admin’s sessions.

**sc.exe**

* **Origin:** Windows component
* **AV risk:** no&#x20;
* **Used ports:** 135, 4915x/TCP

The purpose of this tool is remote administration of services and drivers. Similar to the `services.py` utility, you can run an arbitrary command when you create a service:

But unlike `services.py`, `sc.exe` uses different ports because DCERPC is involved here.

#### WinRM <a href="#h3-3" id="h3-3"></a>

Windows Remote Management is a relatively new tool introduced in Windows 7/2008. It uses HTTP and runs by default only on Windows Server 2012-2019; on client versions (i.e. Windows 7-10), it has to be enabled manually. The technique is pretty efficient if your primary goal is a domain controller running on Windows Server.

**Evil-WinRM**

* **Origin:** [evil-winrm](https://github.com/Hackplayers/evil-winrm) Ruby package
* **AV risk:** no&#x20;
* **Used ports:** 5985/TCP (5986/TCP)

Provides an interactive shell:

**WinRS.exe/PowerShell**

* **Origin:** Windows component
* **AV risk:** no&#x20;
* **Used ports:** 5985/TCP (5986/TCP)

Using this built-in Windows component, you can gain interactive remote access:

In addition, PowerShell can be used to execute command and commandlets:

**RDP**

* **Origin:** freerdp2-x11 and rdesktop packages, `mstsc.exe` Windows component, etc.
* **AV risk:** no&#x20;
* **Used ports:** 3389/TCP

This remote code execution technique is neither handy nor very promising from the Pass-the-Hash/Pass-the-Ticket perspective; but it works out-of-the box on nearly all Windows versions:

#### GP <a href="#h3-4" id="h3-4"></a>

Group policies can help in remote code execution on heavily guarded computers completely hidden behind a firewall or located in isolated networks. Group policies are used when the domain has already been taken over, and you need to move on.

An advantage of group policies in comparison with the described above methods is that they use a sort of the reverse-connect scheme. To use the above techniques, you have to initiate the communication and need open ports on the target host (e.g. 135, 445, 3389, 5985, and 4915x), but all you need to use group policies is access to the DC. The DC normally isn’t hidden behind firewalls; so, you shouldn’t have any problems with its administration.

Using `gpmc.msc` you create a group policy for the required container. `Dsa.msc` will help to identify the container storing your target. After creating the policy, you attach a VBS script with arbitrary code to the `logon` event. Then you have to wait until the user logs into the target system again – and _voila_! You have got RCE.

Critical components of the internal infrastructure (e.g. the domain controller) are often protected by SIEM. Any changes in its configuration, including creation of new group policy objects, can be monitored and would likely ring the alarm bells for the security team. Therefore, instead of creating a new group policy, it is preferable to find an existing one and inject the required code into the script located in the `SYSVOL` share.

The table below summarizes the strengths and weaknesses of different authenticated code execution techniques in their default variants (i.e. without modifications).

<figure><img src=".gitbook/assets/1663772461.png" alt=""><figcaption></figcaption></figure>

Every hacker has a set of favorite tools. But in some situations, you preferred technique may fail, and you must be able to execute arbitrary code using alternative methods. The above table can be used for reference purposes.

As can be seen, the most ‘stealthy’ RCE techniques are Windows components (`winrs.exe`, `sc.exe`, `reg.exe`, `at.exe`, `wmic.exe`, and `psexec.exe`), but not of them are handy. The `sc.exe`, `reg.exe`, and `at.exe` utilities don’t support the username transmission via options; therefore, to use them, you have to run `cmd` on behalf of the target user, while in case of a local account, you must create it first.

Done with authenticated code execution (i.e. legitimate RCE on behalf of an existing account). Now it is time to discuss where to look for these accounts and what are their formats.

#### Local accounts <a href="#h3-5" id="h3-5"></a>

Windows authenticates users without distinguishing the letter case in usernames: `ADMIN` and `admin` look the same for it. This applies both to local and domain accounts.

The main idea behind the use of local accounts is that the same password can be used on several PCs and servers. Sometimes, such local accounts bring you directly to the admin’s PC or to the domain controller.

Local users’ credentials, as well as NTLM hashes, are stored in the registry; the path to them is `HKLM\sam`. SAM (Security Account Manager) is a separate registry hive located, together with other hives, at `\windows\system32\config\`. Interestingly, even admins (except for the system) cannot access `HKLM\sam` using `regedit.exe` or by directly copying a file from the system directory. However, the `reg.exe` command enables you to do this. The point is that system files are extracted using built-in OS components and subsequently analyzed on your PC. This ensures that your actions won’t alert the antiviruses.

To extract local accounts’ credentials, you will need two registry hives:

To extract hashes of local accounts on your computer, use [creddump7\pwdump.py](https://github.com/Neohapsis/creddump7):

Alternatively, you can use the above-mentioned `impacket` collection.

A fully automated approach involving access via remote registry looks as follows:

As a result, you get hashes in the format `Username:RID:LM-hash:NTLM-hash:::`. In newer versions (starting from Windows 7/2008R2), the LM hash may be empty (i.e. may have the value `aad3b435b51404eeaad3b435b51404ee`) because LM hashes aren’t used anymore for security reasons. The NTLM hash of a blank password is `31d6cfe0d16ae931b73c59d7e0c089c0`. When you perform lateral movement and locate plenty of hashes, such hashes should be immediately discarded because the blank password restriction won’t allow you to log on remotely.

**Pass-the-Hash**

Windows has a well-known (and pretty funny) feature enabling you to use an NTLM hash for authentication (i.e. you don’t have to brute-force it and retrieve the password).

All the extracted NTLM hashes (except for `31d6cfe0d16ae931b73c59d7e0c089c0`) can be used for authentication to the following services:

* MSRPC (SMB);
* DCERPC (WMI);
* WINRM;
* MS SQL;
* RDP (Windows 2012 R2 and Windows 8.1 only);
* LDAP;
* IMAP;
* HTTP.

Normally, RCE is possible only for the first five services from the above list; while for the three remaining ones, [NTLM relay](https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/) attacks are more suitable. All the above-mentioned tools from the `impacket` collection support the transmission of hashes: both as LM:NTLM and as an NTLM hash:

Kali distributions include nine popular Pass-the-Hash tools; all of them start with `pth-`:

Starting with the version xfreerdp v2.0.0 (and only on Windows 2012 R2 and Windows 8.1), it’s possible to authenticate with an NTLM hash over RDP:

Fortunately, the modern WinRM works fine as well:

The above examples involve Pass-the-Hash for Linux. But it’s also possible to use RCE tools written for Windows (`psexec.exe`, `at.exe`, `reg.exe`, `wmic.exe`, `sc.exe`, and `winrs.exe`) in Pass-the-Hash attacks; you just have to create a temporary session using `mimikatz`:

A `cmd` window pops-up, and the required NTLM hash will be automatically inserted for any called program:

By the way, you can compute the NTLM hash for a passphrase by yourself:

**Brute force**

If you have to authenticate to a service that doesn’t support Pass-the-Hash (e.g. RDP), you may try to brute-force the password at a high enough speed. LM hashes have a limited number of input values, are encrypted in halves 7 bytes each, and are case insensitive. In other words, any LM hash can be cracked. The situation with NTLM hashes is more complicated.

**LM**

The best way to brute-force LM hashes is to use [ophcrack](https://ophcrack.sourceforge.io/download.php) rainbow tables:

Alternatively, you can use a classical brute-forcing technique with a wordlist:

In the past, there used to be an excellent [Chinese resource](https://www.objectif-securite.ch/en/ophcrack.php) that could convert any LM hash into plain text.

**NTLM**

Hashcat and John require NTLM hashes to be inputted in different ways. For Hashcat, the command is as follows:

For John, it is:

The LM and NTLM hashes for domain users can be found by analyzing the memory of the `lsass.exe` process or in the `ntds.dit` database. Such hashes are never transmitted over the network ‘as is’; instead, they are sent as NetNTLM/NetNTLMv2 hashes unsuitable for Pass-the-Hash attacks. These hash types are single-use and can be used only at the time of transmission (the NTLM relay technique). Alternatively, they can be brute-forced at a high enough speed.

### Kerberos tickets <a href="#h2-3" id="h2-3"></a>

To use Kerberos tickets for authentication, you will need access to port 88/TCP on the domain controller.

#### Kerberoasting <a href="#h3-6" id="h3-6"></a>

The [kerberoasting](https://www.qomplx.com/qomplx-knowledge-kerberoasting-attacks-explained/) technique is very useful because it allows to compromise accounts of domain admins, as well as other service accounts. To perform this attack, you need to control any domain account.

The main idea of the attack is that you impersonate a valid domain user and legitimately extract from the domain controller a Kerberos service ticket (TGS ticket) for a certain service. Such tickets are encrypted using the password (i.e. NTLM hash) of the user you impersonate and hence can be brute-forced offline using a wordlist. Accordingly, your goal is to extract such a ticket by all means.

To identify all users whose TGS tickets can be extracted, use a LDAP search filter:

A classical kerberoasting attack can be performed in many ways, for instance, with `impacket` (if you use a Linux machine):

If you work on Windows, use [Rubeus.exe](https://github.com/GhostPack/Rubeus) for this attack:

Antiviruses rarely detect Rubeus. But when it comes to post-exploitation, be prepared for all kinds of problems. It might happen that you penetrate into the internal network through a Windows PC, and your actions will be limited to the scarce arsenal provided by this OS.

A kerberoasting attack can also be performed using such a basic Windows component as PowerShell:

But the problem is that it’s Windows, not you, who gets the tickets in this case. They will be saved in the memory, and it’s impossible to dump them in the form suitable for brute-forcing using standard OS means.

#### Extracting Kerberos tickets by dumping virtual memory <a href="#h3-7" id="h3-7"></a>

If the antivirus software doesn’t allow you to use the above tools, you can dump the memory of the `lsass.exe` process. This can be done in three ways:

* `taskmgr.exe` → right-click on `lsass.exe` → memory dump;
* `rundll32.exeC:\windows\System32\comsvcs.dll,MiniDump624C:\temp\lsass.dmpfull`; or&#x20;
* `procdump.exe-malsass.exe /accepteula`.

After dumping the memory, you can securely extract the tickets from it on your PC:

However, in some cases, antiviruses prevented me from reaching to `lsass.exe` (which is perfectly understandable).

#### Extracting Kerberos tickets by dumping physical memory <a href="#h3-8" id="h3-8"></a>

If you cannot reach to a process, you may dump the entire physical memory using a utility from the open-source [rekall](https://github.com/google/rekall) forensic framework:

The resultant dump will be several gigabytes in size. To extract the tickets from it, you will need WinDbg and the [mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) plugin:

#### Extracting Kerberos tickets from network traffic <a href="#h3-9" id="h3-9"></a>

This elegant solution involves the extraction of tickets from the network traffic at the time of their download:

#### Brute-forcing TGS <a href="#h3-10" id="h3-10"></a>

Brute-force attacks can be used only against Kerberos TGS (Ticket Granting Service) tickets because these tickets are encrypted with the user’s password:

The brute-forcing speed is high enough: over 1 million passwords per second (`<span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>kmi><mi>rmi><mi>bmi><mn>5mn><mi>tmi><mi>gmi><mi>smi>mrow><annotation encoding="application/x-tex">krb5tgsannotation>semantics>math>krb5tgs23RC4`).

#### Pass-the-Ticket <a href="#h3-11" id="h3-11"></a>

If you have a Kerberos TGT (Ticket Granting Ticket), you can use it for authentication. Note that Linux and Windows use different ticket formats: `ccache` and `kirbi`, respectively. Initially, the tickets can be presented in any of these formats: this depends on the OS you have extracted them from. The techniques described below allow to use tickets on any OS regardless of their initial format.

To import tickets in the `kirbi` format to a Windows system, use the following approach:

To import tickets in the `ccache` format:

After the import, use any program you need without specifying any keys:

On Linux systems, Pass-the-Ticket is performed for tickets in the `ccache` format as follows:

Linux doesn’t understand the `kirbi` format; therefore, the ticket must be first converted into `ccache` using [kekeo.exe](https://github.com/gentilkiwi/kekeo):

After importing the tickets, use them as follows:

Tools from the `impacket` collection can use tickets without their prior import.

To use a Kerberos ticket for authentication, you must address the target by name, not by its IP address.

### Domain accounts <a href="#h2-4" id="h2-4"></a>

Domain accounts are your top-priority targets in the domain infrastructure of companies that use Active Directory. Furthermore, domain accounts ultimately bring you to the domain controller.

### Domain Credential Cache <a href="#h2-5" id="h2-5"></a>

Domain Credential Cache is a registry hive where all successful logons into the system on behalf of domain accounts are recorded – in case the domain controller becomes inaccessible in the future. This cache can be dumped using one of the above-mentioned commands:

The cache stores hashes of domain accounts. To extract them, use the following command:

On old Windows versions, `creddump7` sometimes fails to dump the hashes; in such situations, use its old variant, [creddump](https://github.com/moyix/creddumpcachedump.py):

In a similar way, you can use a tool from the `impacket` collection:

There is also a chance to extract saved service passwords in the plain text format from this cache:

When you perform lateral movement, chances are high that you encounter domain admin account credentials in the cache. Note however that since this is a cache, no one can guarantee that the password wasn’t changed after the caching.

There are two versions of the Domain Credential Cache: dcc1 (mscash1) and dcc2 (mscash2). These hash functions have the same length, and if you don’t know the OS version, you may spend plenty of time on unsuccessful password guessing. On Windows XP/2003, it’s dcc1:

On Windows Vista/2008-10/2019, it’s dcc2:

Overall, Windows XP/2003 are more suitable for lateral movement because the dcc1 hash function used by these systems is 3000 times weaker and hence more vulnerable to brute-forcing attacks. Therefore, if a domain admin has once logged into an obsolete Windows version a long time ago, this operation has significantly compromised the security of the entire infrastructure. Consider this yet another reason to get rid of old Windows versions.

**Credentials in active sessions**

Domain account credentials are also stored in the memory of the `lsass.exe` process. This applies only to sessions that are currently active. To check the list of users and their processes, use the built-in `qprocess*` command.

Such tools as `mimikatz.exe` and `wce.exe` can extract from active sessions hashes and passwords in the plain text format:

But, for some reason, antiviruses don’t like these programs. Therefore, the best way is to use memory dump techniques.

**Dumping virtual memory**

Dump the memory using one of the above-described techniques. Then use `mimikatz`:

**Dumping physical memory**

As said above, antivirus programs can protect `lsass.exe` from your incursions and prevent you from dumping the process. In such situations, use the `winpmem.exe` utility to dump the entire physical memory. Antiviruses rarely detect the physical memory dump procedure because it doesn’t involve WinAPI calls: the memory is directly read in the kernel mode.

Then the dumped memory is analyzed on your PC using WinDbg and a special module created for it by the author of `mimikatz`:

In addition, the popular [Volatility](https://github.com/volatilityfoundation/volatility) forensic framework has a [module](https://github.com/volatilityfoundation/community/tree/master/FrancescoPicasso) specially designed for this purpose:

**Hardware isolation of lsalso.exe**

On modern versions of Windows, you may encounter `lsalso.exe`, a process protected by the virtualization technology. Of course, there are some techniques involving the registration of the LSASS provider:

Then you’ll have to wait until the admin logs into the system again. The credentials entered by the admin will be recorded in `c:\windows\system32\mimilsa.log`.

But the question is: do you really need this domain admin’s password? Just think: you have authenticated to the server under one account and want to get a password to another account. But on this particular PC, your account and the admin account are at the same level: both of you are local admins of this PC. In other words, you can interact both with the home directory of the target account and with the memory of its processes.

To be specific, you can inject code into the memory of processes running on behalf of the domain admin and run arbitrary threads in them. To do so, you have to generate a shellcode with an arbitrary command, inject it into any process running on behalf of the target user, and execute the command on behalf of the domain admin. You don’t even need the admin’s password for this operation:

As you can see, I generated a shellcode that will use WMI to execute a command activating [sticky keys](https://hackmag.com/security/windows-pivoting) on the domain controller. The shellcode must look as innocent as possible: in this particular case, it’s coded in ASCII commands and impersonates a text file. Normally, antiviruses don’t attack such stuff.

Now all you have to do is select a process running on behalf of the domain admin using the `qprocess*`. command. The processes of the domain admin are running in a parallel RDP session (sometimes, such sessions can be even left forgotten). You can use, for instance, `explorer.exe` as the target. Then you allocate some memory in it, write your shellcode there, and run a flow with [shellcode\_inject.exe](https://github.com/s0i37/shellcode\_inject):

Congrats! You have just injected code into the domain admin’s context, and this code remotely executed a command opening a backdoor. Now you can connect to this domain:

And a familiar picture appears.

<figure><img src=".gitbook/assets/1663772461.png" alt="Shellcode injected into an admin"><figcaption><p>Shellcode injected into an admin’s process activates a backdoor on the domain controller</p></figcaption></figure>

You gained access to the domain controller and can now replicate domain accounts, including the `krbtgt` system account. Using it, you can generate a Kerberos TGT ticket belonging to that same admin and authenticate on behalf of this admin without knowledge of their password (this technique is called [golden ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)).

The table below summarizes the properties of various types of Windows hashes and their application areas.

<figure><img src=".gitbook/assets/1663772462.png" alt=""><figcaption></figcaption></figure>

### Lateral movement <a href="#h2-6" id="h2-6"></a>

To perform lateral movement, you need account credentials in one of the following forms:

* passwords in plain text;
* NTLM hashes; or&#x20;
* Kerberos tickets.

Below I will show how to use these credentials against numerous targets at once.

#### Credentials spraying <a href="#h3-12" id="h3-12"></a>

Lateral movement normally involves massive code execution (i.e. execution of the same command on a group of targets). This operation is often performed blindly, especially at the initial stage when you have no idea how to obtain admin’s credentials.

Therefore, you must be able to execute the code in different ways not on a single PC, but on a group of targets. In my opinion, the best tool for this is [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec). The program supports a broad range of functions, including brute-forcing and many other features that are beyond the scope of this article.

The syntax for local accounts is as follows:

For domain accounts, it is:

Note that any argument can be either a value or a file containing a list of values. Prior to starting massive code execution, you have to find out what accounts have access to what PCs.

For a specific account, you can check its permissions for a group of targets at once:

But when you perform lateral movement, you normally deal with dozens and even hundreds of accounts. Fortunately, new versions of `cme` allow you to check combos:

All account credentials that match something are saved in the database and can be accessed using the `cmedb` command. It can also be used to access the SMB protocol database:

List of saved account credentials:

List of hosts the program has attempted to authenticate to:

The saved credentials can be subsequently used for authentication in `cme` by specifying their IDs:

#### Massive code execution <a href="#h3-13" id="h3-13"></a>

At some point, you may need to run a program on a group of targets. To execute a command on a single host, you use `psexec` and other similar utilities, but the best tool for massive execution is `cme`. To execute a simple command, use the following directive:

To execute PowerShell commandlets:

To execute commands in different ways:

Using the Pass-the-Hash technique on a group of targets:

Using the Pass-the-Ticket technique on a group of targets:

In addition, `cme` makes it possible to automate the retrieval of local account credentials and the Domain Credential Cache:

This command can automate nearly all described-above operations: it effectively retrieves whatever is possible using each and every account. Furthermore, `crackmapexec` has additional modules that extend its functionality. For instance, the `mimikatz` module can be used for mass extraction of domain account credentials from active sessions:

But I don’t recommend using this module in real-life situations because antiviruses often detect it.

### Conclusions <a href="#h2-7" id="h2-7"></a>

Windows has many features enabling you to ‘jump’ from one host to another one. Many of these tricks (e.g. PTH) technically can be considered vulnerabilities, but Microsoft doesn’t want to fix them. As a result, these features became valuable additions to the pentester’s arsenal.

It sounds paradoxical, but security of many internal networks can be improved by getting rid of Active Directory. There was an illustrative case in my experience when a huge internal network consisting of 140,000 PCs was taken over in 1.5 days. By contrast, a tiny company of ten people that wasn’t using Active Directory couldn’t be hacked in five days.

It’s hard to imagine a company able to withstand the combination of all described-above techniques. Too many things are not obvious for admins and can be inadvertently omitted, while a single error can result in the collapse of the entire infrastructure.

A network with Active Directory is an ecosystem with a single center: the domain controller. To compromise it, you don’t have to deliver a frontal attack on the network. Domains are normally compromised not because of software vulnerabilities, but due to primitive flaws: either there are too many admin accounts, or they are used excessively, or same passwords are used for local accounts, or the passwords are just weak…

The above techniques represent some 10% of factors threatening the internal infrastructure and constitute only one-tenth of a standard hacker’s arsenal. Aside from them, it is necessary to mention software vulnerabilities and attacks targeting local area networks. Tons of subtle flows make the combination of Active Directory and Windows extremely vulnerable. From the attacker’s perspective, this environment provides favorable conditions for advancement because each of the hosts has trusting relationships with its neighbors. When one of such hosts is hacked, a hacking chain reaction begins, which ultimately brings the attacker to admin’s computers and servers and then to the automatic process control system or SWIFT. And the larger is the network, the more difficult it is to maintain it in good order, the higher is the chance to find a misconfiguration, and the higher is the cost of such an error.
