```bash
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN "/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/_quick_tcp_nmap.txt" -oX "/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/xml/_quick_tcp_nmap.xml" 10.10.10.192
```

[/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/_quick_tcp_nmap.txt](file:///home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/_quick_tcp_nmap.txt):

```
# Nmap 7.92 scan initiated Mon Aug 29 17:18:47 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN /home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/_quick_tcp_nmap.txt -oX /home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/xml/_quick_tcp_nmap.xml 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up, received user-set (0.074s latency).
Scanned at 2022-08-29 17:18:49 PDT for 548s
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain?       syn-ack ttl 127
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-08-30 07:19:02Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=8/29%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=630D598D%P=x86_64-pc-linux-gnu)
SEQ(SP=107%GCD=1%ISR=10C%TI=I%II=I%SS=S%TS=U)
OPS(O1=M539NW8NNS%O2=M539NW8NNS%O3=M539NW8%O4=M539NW8NNS%O5=M539NW8NNS%O6=M539NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M539NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-08-30T07:27:20
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48702/tcp): CLEAN (Timeout)
|   Check 2 (port 39309/tcp): CLEAN (Timeout)
|   Check 3 (port 61652/udp): CLEAN (Timeout)
|   Check 4 (port 53637/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 6h59m59s

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   78.74 ms 10.10.14.1
2   79.10 ms 10.10.10.192

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 29 17:27:57 2022 -- 1 IP address (1 host up) scanned in 549.55 seconds

```
