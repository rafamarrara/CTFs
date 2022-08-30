```bash
nmap -vv --reason -Pn -T4 -sV -p 88 --script="banner,krb5-enum-users" -oN "/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp88/tcp_88_kerberos_nmap.txt" -oX "/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp88/xml/tcp_88_kerberos_nmap.xml" 10.10.10.192
```

[/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp88/tcp_88_kerberos_nmap.txt](file:///home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp88/tcp_88_kerberos_nmap.txt):

```
# Nmap 7.92 scan initiated Mon Aug 29 17:27:57 2022 as: nmap -vv --reason -Pn -T4 -sV -p 88 --script=banner,krb5-enum-users -oN /home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp88/tcp_88_kerberos_nmap.txt -oX /home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp88/xml/tcp_88_kerberos_nmap.xml 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up, received user-set (0.072s latency).
Scanned at 2022-08-29 17:27:59 PDT for 17s

PORT   STATE SERVICE      REASON          VERSION
88/tcp open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-08-30 07:28:07Z)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 29 17:28:16 2022 -- 1 IP address (1 host up) scanned in 19.45 seconds

```
