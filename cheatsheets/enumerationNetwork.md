# CTF cheat sheet


## Nmap - quick

```
sudo nmap -p <port, port> <TARGET_IP>
```

## Nmap - ippsec

```
cd <traget_folder>
mkdir nmap
sudo nmap -v -sC -sV -oA nmap/<target_name> <TARGET_IP>
```

## Autorecon
```
sudo $(which autorecon) <TARGET_IP> --dirbuster.wordlist /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt 
```

## Netcat (nc)
```
nc -zvv <TARGET_IP> <PORT>
```


## SMB

```
smbmap -H <TARGET_IP> -u anonymous
```

```
smbmap -H <TARGET_IP> -u '<USER>' -p '<PWD>' -d '<HOSTNAME or DOMAIN>'
```

```
crackmapexec smb <TARGET_IP> -u '' -p '' --shares
```

```
crackmapexec smb <TARGET_IP> -u '<USER>' -p '<PWD>' -d '<HOSTNAME or DOMAIN>' --shares
```

```
smbclient //<TARGET_IP>/<SHARE> -N
```

```
smbclient //<TARGET_IP>/<SHARE> -U '<USER>' --password='<PWD>'
```

- recurse download
```
smbclient '\\server\share'
mask ""
recurse ON
prompt OFF
cd 'path\to\remote\dir'
lcd '~/path/to/download/to/'
mget *
```

### Extra links
https://notes.benheater.com/
