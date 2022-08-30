# CTF cheat sheet


## Autorecon
```
sudo $(which autorecon) <TARGET_IP> --dirbuster.wordlist /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt 
```

## AD Enum

### LDAP search
https://devconnected.com/how-to-search-ldap-using-ldapsearch-examples/
```
ldapsearch -H ldap://10.10.10.192 -x -b "DC=BLACKFIELD,DC=local"
```