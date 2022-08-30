```bash
nmap -vv --reason -Pn -T4 -sV -p 445 --script="banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp445/tcp_445_smb_nmap.txt" -oX "/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp445/xml/tcp_445_smb_nmap.xml" 10.10.10.192
```

[/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp445/tcp_445_smb_nmap.txt](file:///home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp445/tcp_445_smb_nmap.txt):

```
# Nmap 7.92 scan initiated Mon Aug 29 17:27:57 2022 as: nmap -vv --reason -Pn -T4 -sV -p 445 "--script=banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN /home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp445/tcp_445_smb_nmap.txt -oX /home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp445/xml/tcp_445_smb_nmap.xml 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up, received user-set (0.078s latency).
Scanned at 2022-08-29 17:28:00 PDT for 54s

PORT    STATE SERVICE       REASON          VERSION
445/tcp open  microsoft-ds? syn-ack ttl 127
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)

Host script results:
|_smb-print-text: false
| smb-mbenum: 
|_  ERROR: Failed to connect to browser service: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
| smb2-time: 
|   date: 2022-08-30T07:28:21
|_  start_date: N/A
| smb-protocols: 
|   dialects: 
|     2.0.2
|     2.1
|     3.0
|     3.0.2
|_    3.1.1
| smb2-capabilities: 
|   2.0.2: 
|     Distributed File System
|   2.1: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3.0: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3.0.2: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3.1.1: 
|     Distributed File System
|     Leasing
|_    Multi-credit operations

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 29 17:28:54 2022 -- 1 IP address (1 host up) scanned in 56.87 seconds

```
