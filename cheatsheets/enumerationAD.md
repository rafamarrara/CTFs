## AD Enum

### LDAP search
https://devconnected.com/how-to-search-ldap-using-ldapsearch-examples/

Identifying LDAP BASE
```
ldapsearch -H ldap://10.10.10.192 -x -s base rootDomainNamingContext ldapServiceName dnsHostName defaultNamingContext
```

```
ldapsearch -H ldap://<TARGET IP> -x -b "<DOMAIN_NAME_CONTEXT>"
```




### RPC search
```

```