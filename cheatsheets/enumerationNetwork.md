# CTF cheat sheet


## Nmap - quick

```
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



### Extra links
https://notes.benheater.com/
