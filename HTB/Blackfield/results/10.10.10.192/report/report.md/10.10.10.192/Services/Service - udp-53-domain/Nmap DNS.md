```bash
nmap -vv --reason -Pn -T4 -sU -sV -p 53 --script="banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/udp53/udp_53_dns_nmap.txt" -oX "/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/udp53/xml/udp_53_dns_nmap.xml" 10.10.10.192
```

[/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/udp53/udp_53_dns_nmap.txt](file:///home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/udp53/udp_53_dns_nmap.txt):

```
# Nmap 7.92 scan initiated Mon Aug 29 17:49:44 2022 as: nmap -vv --reason -Pn -T4 -sU -sV -p 53 "--script=banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN /home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/udp53/udp_53_dns_nmap.txt -oX /home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/udp53/xml/udp_53_dns_nmap.xml 10.10.10.192
Nmap scan report for DC01 (10.10.10.192)
Host is up, received user-set (0.073s latency).
Scanned at 2022-08-29 17:49:44 PDT for 37s

PORT   STATE SERVICE REASON               VERSION
53/udp open  domain  udp-response ttl 127 (generic dns response: SERVFAIL)
| fingerprint-strings: 
|   NBTStat: 
|_    CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
| dns-nsec-enum: 
|_  No NSEC records found
| dns-nsec3-enum: 
|_  DNSSEC NSEC3 not supported
|_dns-cache-snoop: 0 of 100 tested domains are cached.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-UDP:V=7.92%I=7%D=8/29%Time=630D5EBD%P=x86_64-pc-linux-gnu%r(NBTS
SF:tat,32,"\x80\xf0\x80\x82\0\x01\0\0\0\0\0\0\x20CKAAAAAAAAAAAAAAAAAAAAAAA
SF:AAAAAAA\0\0!\0\x01");

Host script results:
|_dns-brute: Can't guess domain of "DC01"; use dns-brute.domain script argument.

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 29 17:50:21 2022 -- 1 IP address (1 host up) scanned in 37.02 seconds

```
