# AD Enum

## LDAP search
https://devconnected.com/how-to-search-ldap-using-ldapsearch-examples/

Identifying LDAP BASE
```
ldapsearch -H ldap://10.10.10.192 -x -s base rootDomainNamingContext ldapServiceName dnsHostName defaultNamingContext
```

```
ldapsearch -H ldap://<TARGET IP> -x -b "<DOMAIN_NAME_CONTEXT>"
```




## RPC search
```

```


## BloodHound

### From Kali attacker machine (using [bloodhound-python](https://github.com/fox-it/BloodHound.py))

With password
```
bloodhound-python -ns 10.10.10.192 -d blackfield.local -u support -p '#00^BlackKnight' -c all 
```

With hash
```
bloodhound-python -ns 10.10.10.192 -d blackfield.local -u svc_backup --hashes 9658d1d1dcd9250115e2205d9f48400d:9658d1d1dcd9250115e2205d9f48400d -c all
```

### From Windows on the target domain (using [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors))


```
/SharpHound
```
or
```
./SharpHound --collectionmethods All --domain <DOMAIN>
```


## SMB

### Crackmapexec
```
crackmapexec smb -u '<USER>' -p '<PWD>' -d '<DOMAIN>' <Target_IP> --shares
```


# Links

- [bloodhound-python](https://github.com/fox-it/BloodHound.py)
- [crackmapexec cheatsheet](https://lisandre.com/archives/14589)
