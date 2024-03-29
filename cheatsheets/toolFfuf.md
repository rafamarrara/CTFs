# ffuf

## Fuzzing

### Directory Fuzzing

```bash
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```

### Extension Fuzzing

```bash
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ
```

### Page Fuzzing

```bash
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```

### Recursive Fuzzing

```bash
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```

### Sub-domain Fuzzing

```bash
ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/
```

### VHost Fuzzing

Use the following to get an not valid vHost response Content-Length to use on the `-fs` parameter

```bash
curl -s -I http://academy.htb:PORT/ -H "HOST: defnotvalid.academy.htb" | grep "Content-Length:"
```

```bash
ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx
```

### Parameter Fuzzing - GET

```bash
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```

### Parameter Fuzzing - POST

```bash
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

### Value Fuzzing

```bash
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

## Wordlists

### Directory/Page Wordlist

```bash
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

### Extensions Wordlist

```bash
/usr/share/seclists/Discovery/Web-Content/web-extensions.txt
```

### Domain Wordlist

```bash
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Parameters Wordlist

```bash
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

### Username Wordlist

```bash
/usr/share/seclists/Usernames/Names/names.txt
```

## Misc

### Add DNS entry

```bash
sudo sh -c 'echo "SERVER_IP domain.com" >> /etc/hosts'
```

### Create Sequence Wordlist

```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

### curl w/ POST

```bash
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```
