# CTF cheat sheet

## Nmap - quick

```bash
sudo nmap -p <port, port> <TARGET_IP>
```

## Nmap - ippsec

```bash
cd <traget_folder>
mkdir nmap
sudo nmap -v -sC -sV -oA nmap/<target_name> <TARGET_IP>
```

## Autorecon

```bash
sudo $(which autorecon) <TARGET_IP> --dirbuster.wordlist /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt 
```

## Netcat (nc)

```bash
nc -zvv <TARGET_IP> <PORT>
```

## Listening open ports (netstat)

### Linux

```bash
sudo netstat -lunpt
```

### Windows

```bash
netstat -nao
```

## ICMP

Set `tcpdump` to listen for ICMP (ping) requests on interface tun0.

```bash
sudo tcpdump -n -i tun0 icmp
```

Use `fping` to sent ICMP requests to all IPs on the network and get a list of the ones that respond.

```bash
fping -asgq 172.16.7.0/23
```

Or use `for` + `ping` to run a loop that is going to return reached IPs.

```bash
for i in $(seq 254); do ping 172.16.8.$i -c1 -W1 & done | grep from
```

## DNS

NS record

```bash
dig ns <domain> @<DNS_SERVER_IP>
```

DNS server's version using a class CHAOS query and type TXT

```bash
dig CH TXT version.bind @<DNS_SERVER_IP>
```

ANY Query

```bash
dig any <domain> @<DNS_SERVER_IP>
```

AXFR Zone Transfer

```bash
dig axfr <domain> @<DNS_SERVER_IP>
```

Enum subdomain

```bash
dnsenum --dnsserver <DNS_SERVER_IP> --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt <domain>
```

Other lists

```bash
locate seclist | grep subdomain
```

```bash
```

## SMB

```bash
smbmap -H <TARGET_IP> -u anonymous
```

```bash
smbmap -H <TARGET_IP> -u '<USER>' -p '<PWD>' -d '<HOSTNAME or DOMAIN>'
```

```bash
crackmapexec smb <TARGET_IP> -u '' -p '' --shares
```

```bash
crackmapexec smb <TARGET_IP> -u '<USER>' -p '<PWD>' -d '<HOSTNAME or DOMAIN>' --shares
```

```bash
smbclient //<TARGET_IP>/<SHARE> -N
```

```bash
smbclient //<TARGET_IP>/<SHARE> -U '<USER>' --password='<PWD>'
```

- recurse download

```bash
smbclient '\\server\share'
mask ""
recurse ON
prompt OFF
cd 'path\to\remote\dir'
lcd '~/path/to/download/to/'
mget *
```

### Extra links

- [0xBEN Notes -  Blog](https://notes.benheater.com/)
- [HTB Academy - DNS](https://academy.hackthebox.com/module/144/section/1251)
- [HTB Academy - FOOTPRINTING- DNS](https://academy.hackthebox.com/module/112/section/1069)
- [HTB Academy - Email](https://academy.hackthebox.com/module/116/section/1173)
