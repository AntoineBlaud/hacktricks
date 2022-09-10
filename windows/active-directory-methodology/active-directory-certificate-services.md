# Active Directory Certificate Services



### Active Directory Certificate Services

This cheatsheet is built from numerous papers, GitHub repos and GitBook, blogs, HTB boxes and other resources found on the web or through my experience. I will try to put as many links as possible at the end of the page to direct to more complete resources.

**If you see a missing resource, a reference, or a copy right, please immediatly contact me on Twitter :** [**@BlWasp\_**](https://twitter.com/BlWasp\_)

A cheatsheet about the different AD-CS's ESC presented by SpecterOps. All the references and resources for the commands and techniques will be listed at the end of the page, for acknowledgments and explains.

Many commands come from [here](https://www.thehacker.recipes/ad/movement/ad-cs) where I have participate for AD-CS - **Don't hesitate to read all his blog and support him !**

### Is there a CA ?

Find the **Cert Publishers** group :

* From UNIX-like systems: `rpc net group members "Cert Publishers" -U "DOMAIN"/"User"%"Password" -S "DomainController"`
* From Windows systems: `net group "Cert Publishers" /domain`

Find the PKI : `crackmapexec ldap 'domaincontroller' -d 'domain' -u 'user' -p 'password' -M adcs`

Find the CA from Windows : `certutil –config – -ping`

Enumerate the HTTP ports on the servers, enumerate the shares to find **CertEnroll**, etc

### Template Attacks - ESC1, 2, 3, 9 & 10

[![image-1640805125672.png](https://hideandsec.sh/uploads/images/gallery/2021-12/scaled-1680-/mlK5E1SH1D1CzLOG-image-1640805125672.png)](https://hideandsec.sh/uploads/images/gallery/2021-12/mlK5E1SH1D1CzLOG-image-1640805125672.png)

* **ESC1** : SAN authorized & Low Privileged Users can enroll & Authentication EKU
* **ESC2** : Low Privileged Users can enroll & Any or No EKU
* **ESC3** : Certificate Request Agent EKU & Enrollment agent restrictions are not implemented on the CA
  * A template allows a low-privileged user to use an enrollment agent certificate.
  * Another template allows a low privileged user to use the enrollment agent certificate to request a certificate on behalf of another user, and the template defines an EKU that allows for domain authentication.

#### ESC1, 2 & 3

**Windows**

**ESC1 & 2**

If **ANY EKU** but no Client Authentication, it can be used as en **ESC3**.

**ESC2 & 3**

**Linux**

**ESC1 & 2**

If **ANY EKU** but no Client Authentication, it can be used as en **ESC3**.

**ESC2 & 3**

#### ESC9 & 10

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

**Windows**

**ESC9**

Here, **user1** has `GenericWrite` against **user2** and want to compromise **user3**. **user2** is allowed to enroll in a vulnerable template that specifies the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value.

**ESC10 - Case 1**

Here, **user1** has `GenericWrite` against **user2** and want to compromise **user3**.

**ESC10 - Case 2**

Here, **user1** has `GenericWrite` against **user2** and want to compromise the domain controller **DC$@contoso.local**.

Now, authentication with the obtained certificate will be performed through Schannel. It can be used to perform, for example, an RBCD.

**Linux**

**ESC9**

Here, **user1** has `GenericWrite` against **user2** and want to compromise **user3**. **user2** is allowed to enroll in a vulnerable template that specifies the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value.

**ESC10 - Case 1**

Here, **user1** has `GenericWrite` against **user2** and want to compromise **user3**.

**ESC10 - Case 2**

Here, **user1** has `GenericWrite` against **user2** and want to compromise the domain controller **DC$@contoso.local**.

### Access Controls Attacks - ESC4, 5, 7

#### ESC4 : Sufficient rights against a template

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

**Windows**

**Linux**

* Quick override and restore
* Precise modification

#### ESC5 : Sufficient rights against several objects

#### ESC7 : Sufficient rights against the CA

* [https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/ad-cs-abuse#vulnerable-ca-aces-esc7](https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/ad-cs-abuse#vulnerable-ca-aces-esc7)

**Windows**

* _If an attacker gains control over a principal that has the **ManageCA** right over the CA, he can remotely flip the `EDITF_ATTRIBUTESUBJECTALTNAME2` bit to allow SAN specification in any template_
* _If an attacker gains control over a principal that has the **ManageCertificates** right over the CA, he can remotely approve pending certificate requests, subvertnig the "CA certificate manager approval" protection_

**Linux**

When it is not possible to restart the `CertSvc` service to enable the `EDITF_ATTRIBUTESUBJECTALTNAME2 attribute`,the built-in template **SubCA** can be usefull.

It is vulnerable to the **ESC1** attack, but only **Domain Admins** and **Enterprise Admins** can enroll in it. If a standard user try to enroll in it with [Certipy](https://github.com/ly4k/Certipy), he will encounter a `CERTSRV_E_TEMPLATE_DENIED` errror and will obtain a request ID with a corresponding private key.

This ID can be used by a user with the **ManageCA** _and_ **ManageCertificates** rights to validate the failed request. Then, the user can retrieve the issued certificate by specifying the same ID.

* With **ManageCA** right it is possible to promote new officier and enable templates
* With **ManageCertificates** AND **ManageCA** it is possible to issue certificate from failed request

### CA Configuration - ESC6

If the CA flag **EDITF\_ATTRIBUTESUBJECTALTNAME2** is set, it is possible to specify a SAN in any certificate request

#### Windows

#### Linux

### HTTP Endpoint - ESC8

If the HTTP endpoint is up on the CA and it accept NTLM authentication, it is vulnerable to NTLM or Kerberos relay.

#### NTLM Relay

#### Kerberos Relay

It is possible with the last versions of **mitm6** and **krbrelayx**.

### Pass-The-Certificate

#### PKINIT

With a certificate valid for authentication, it is possible to request a TGT via the **PKINIT** protocol

**Windows**

**Linux**

#### Schannel

If PKINIT is not working on the domain, LDAPS can be used to pass the certificate with `PassTheCert`.

**Windows**

* Grant DCSync rights to an user
* Add computer account
* RBCD
* Reset password

**Linux**

For RBCD attack

#### UnPAC the Hash

When a TGT is requested with PKINIT, the **LM:NT hash** in added in the structure `PAC_CREDENTIAL_INFO` for futur use if Kerberos is not supported, and the PAC is ciphered with the krbtgt key. When a TGS is requested from the TGT, the same structure is added, but ciphered with the session key.

The structure can be unciphered if a TGS-REQ U2U is realised.

**Windows**

**Linux**

### References

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
