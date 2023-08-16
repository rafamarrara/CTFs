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

## ICMP

Set `tcpdump` to listen for ICMP (ping) requests on interface tun0.

```bash
sudo tcpdump -n -i tun0 icmp
```

Use `fping` to sent ICMP requests to all IPs on the network and get a list of the ones that respond.

```bash
fping -asgq 172.16.7.0/23
```

### Extra links
https://notes.benheater.com/
