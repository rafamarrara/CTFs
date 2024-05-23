# AD Enum

## Orange Cyberdefense Mindmap

[AD Mindmaps](https://github.com/Orange-Cyberdefense/ocd-mindmaps)

## LDAP search

[ldapsearch-examples](https://devconnected.com/how-to-search-ldap-using-ldapsearch-examples/)

Identifying LDAP BASE

```bash
ldapsearch -H ldap://10.10.10.192 -x -s base rootDomainNamingContext ldapServiceName dnsHostName defaultNamingContext
```

```bash
ldapsearch -H ldap://<TARGET IP> -x -b "<DOMAIN_NAME_CONTEXT>"
```

## RPC search

```bash
net rpc group members 'Domain Users' -U '%' --ipaddress $TARGET -W '<DOMAIN>' --long --verbose
```

## BloodHound

### From Kali attacker machine (using [bloodhound-python](https://github.com/fox-it/BloodHound.py))

With password

```bash
bloodhound-python -ns 10.10.10.192 -d blackfield.local -u support -p '#00^BlackKnight' -c all 
```

With hash

```bash
bloodhound-python -ns 10.10.10.192 -d blackfield.local -u svc_backup --hashes 9658d1d1dcd9250115e2205d9f48400d:9658d1d1dcd9250115e2205d9f48400d -c all
```

### From Windows on the target domain (using [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors))

```bash
/SharpHound
```

or

```bash
./SharpHound --collectionmethods All --domain <DOMAIN>
```

## SMB

### Crackmapexec

```bash
crackmapexec smb -u '<USER>' -p '<PWD>' -d '<DOMAIN>' <Target_IP> --shares
```

## LLMNR/NBT-NS Poisoning

### Responder

```bash
sudo responder -I ens224
```

Logs are located at `/usr/share/responder/logs/` folder.

### Inveigh

```powershell
C:\Tools\Inveigh.exe -nbns y -mDNS y
```

## Links

- [bloodhound-python](https://github.com/fox-it/BloodHound.py)
- [crackmapexec cheatsheet](https://lisandre.com/archives/14589)
- [OSCP-Cheatsheets](https://github.com/blackc03r/OSCP-Cheatsheets)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
