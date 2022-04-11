# Meterpreter

## Post Scripts

* arp\_scanner.rb Script for performing an ARP's Scan Discovery. ​&#x20;
* autoroute.rbMeterpreter session without having to background the current session. ​&#x20;
* checkvm.rb Script for detecting if target host is a virtual machine. ​&#x20;
* credcollect.rb Script to harvest credentials found on the host and store them in the database. ​&#x20;
* domain\_list\_gen.rb Script for extracting domain admin account list for use. ​&#x20;
* dumplinks.rb Dumplinks parses .lnk files from a user's recent documents folder and Microsoft Office's Recent documents folder, if present. The .lnk files contain time stamps, file locations, including share names, volume serial #s and more. This info may help you target additional systems. ​&#x20;
* duplicate.rb Uses a meterpreter session to spawn a new meterpreter session in a different process. A new process allows the session to take "risky" actions that might get the process killed by A/V, giving a meterpreter session to another controller, or start a keylogger on another process. ​
* &#x20;enum\_chrome.rb Script to extract data from a chrome installation. ​&#x20;
* enum\_firefox.rb Script for extracting data from Firefox.
* enum\_logged\_on\_users.rb - Script for enumerating current logged users and users that have logged in to the system. ​
* &#x20;enum\_powershell\_env.rb - Enumerates PowerShell and WSH configurations. ​&#x20;
* enum\_putty.rb Enumerates Putty connections. ​&#x20;
* enum\_shares.rb Script for Enumerating shares offered and history of mounted shares. ​&#x20;
* enum\_vmware.rb Enumerates VMware configurations for VMware products. ​&#x20;
* event\_manager.rb Show information about Event Logs on the target system and their configuration. ​ file\_collector.rb Script for searching and downloading files that match a specific pattern. ​&#x20;
* get\_application\_list.rb - Script for extracting a list of installed applications and their version. ​&#x20;
* getcountermeasure.rb - Script for detecting AV, HIPS, Third Party Firewalls, DEP Configuration and Windows Firewallconfiguration. Provides also the option to kill the processes of detected products and disable the built-in firewall. ​&#x20;
* get\_env.rb Script for extracting a list of all System and User environment variables. ​&#x20;
* getfilezillacreds.rb Script for extracting servers and credentials from Filezilla. ​&#x20;
* getgui.rbScript to enable Windows RDP. ​&#x20;
* get\_local\_subnets.rb - Get a list of local subnets based on the host's routes. ​&#x20;
* get\_pidgen\_creds.rb - Script for extracting configured services with username and passwords. ​&#x20;
* gettelnet.rb Checks to see whether telnet is installed. ​&#x20;
* get\_valid\_community.rb - Gets a valid community string from SNMP. ​&#x20;
* getvncpw.rb Gets the VNC password. ​&#x20;
* hashdump.rb Grabs password hashes from the SAM. ​ hostedit.rb Script for adding entries in to the Windows Hosts file. ​&#x20;
* keylogrecorder.rb Script for running keylogger and saving all the keystrokes. ​&#x20;
* killav.rb Terminates nearly every antivirus software on victim. ​&#x20;
* metsvc.rb Delete one meterpreter service and start another. ​ migrate Moves the meterpreter service to another process. ​&#x20;
* multicommand.rb Script for running multiple commands on Windows 2003, Windows Vista and Windows XP and Windows 2008 targets. ​&#x20;
* multi\_console\_command.rb - Script for running multiple console commands on a meterpreter session. ​&#x20;
* multi\_meter\_inject.rb - Script for injecting a reverce tcp Meterpreter Payload into memory of multiple PIDs, if none is provided a notepad process will be created and a Meterpreter Payload will be injected in to each. ​&#x20;
* multiscript.rb Script for running multiple scripts on a Meterpreter session. ​&#x20;
* netenum.rb Script for ping sweeps on Windows 2003, Windows Vista, Windows 2008 and Windows XP targets using native Windows commands. ​&#x20;
* packetrecorder.rb Script for capturing packets in to a PCAP file. ​&#x20;
* panda2007pavsrv51.rb - This module exploits a privilege escalation vulnerability in Panda Antivirus 2007. Due to insecure permission issues, a local attacker can gain elevated privileges. ​&#x20;
* persistence.rb Script for creating a persistent backdoor on a target host. ​&#x20;
* pml\_driver\_config.rb - Exploits a privilege escalation vulnerability in Hewlett-Packard's PML Driver HPZ12. Due to an insecure SERVICE\_CHANGE\_CONFIG DACL permissions, a local attacker can gain elevated privileges. ​&#x20;
* powerdump.rb Meterpreter script for utilizing purely PowerShell to extract username and password hashes through registry keys.This script requires you to be running as system in order to work properly. This hascurrently been tested on Server 2008 and Windows 7, which install PowerShell by default. ​&#x20;
* prefetchtool.rb Script for extracting information from windows prefetch folder. ​&#x20;
* process\_memdump.rb - Script is based on the paper Neurosurgery With Meterpreter. ​&#x20;
* remotewinenum.rb This script will enumerate windows hosts in the target environment given a username and  password or using the credential under which Meterpeter is running using WMI wmic windows native tool. ​&#x20;
* scheduleme.rb Script for automating the most common scheduling tasks during a pentest. This script works withWindows XP, Windows 2003, Windows Vista and Windows 2008. ​&#x20;
* schelevator.rb Exploit for Windows Vista/7/2008 Task Scheduler 2.0 Privilege Escalation.This script exploits the Task Scheduler 2.0 XML0day exploited by Stuxnet. ​&#x20;
* schtasksabuse.rb Meterpreter script for abusing the scheduler service in Windows by scheduling and running a list of command again one or more targets. Using schtasks command to run them as system. This script works with Windows XP, Windows 2003, Windows Vista and Windows 2008. ​&#x20;
* scraper.rb The goal of this script is to obtain system information from a victim through an existingMeterpreter session. ​&#x20;
* screenspy.rb This script will open an interactive view of remote hosts. You will need Firefox installed on your machine. ​&#x20;
* screen\_unlock.rb Script to unlock a windows screen. Needs system privileges to run and known signatures for the target system. ​&#x20;
* screen\_dwld.rb Script that recursively search and download files matching a given pattern. ​ service\_manager.rbScript for managing Windows services. ​ ​&#x20;
* service\_permissions\_escalate.rb This script attempts to create a service, then searches through a list of existing services to find insecure file or configuration permissions that will let it replace the executable with a payload. It will then attempt to restart the replaced service to run the payload. If that fails, the next time the service is started (such as on reboot) the attacker will gain elevated privileges. ​&#x20;
* sound\_recorder.rb Script for recording in intervals the sound capture by a target host microphone. ​&#x20;
* srt\_webdrive\_priv.rb - Exploits a privilege escalation vulnerability in South River Technologies WebDrive. ​&#x20;
* uploadexec.rb Script to upload executable file to host. ​ virtualbox\_sysenter\_dos - Script to DoS Virtual Box. ​&#x20;
* virusscan\_bypass.rb -Script that kills Mcafee VirusScan Enterprise v8.7.0i+ processes. ​&#x20;
* vnc.rb Meterpreter script for obtaining a quick VNC session. ​&#x20;
* webcam.rb Script to enable and capture images from the host webcam. ​&#x20;
* win32-sshclient.rb Script to deploy & run the "plink" commandline ssh-client. Supports only MS-Windows-2k/XP/Vista Hosts. ​&#x20;
* win32-sshserver.rbScript to deploy and run OpenSSH on the target machine. ​&#x20;
* winbf.rb Function for checking the password policy of current system. This policy may resemble the policy of other servers in the target environment. ​&#x20;
* winenum.rb Enumerates Windows system including environment variables, network interfaces, routing, user accounts, etc.
* wmic.rb Script for running WMIC commands on Windows 2003, Windows Vista and Windows XP and Windows 2008 targets. ​

