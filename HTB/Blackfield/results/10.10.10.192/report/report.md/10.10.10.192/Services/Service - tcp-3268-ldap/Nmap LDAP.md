```bash
nmap -vv --reason -Pn -T4 -sV -p 3268 --script="banner,(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp3268/tcp_3268_ldap_nmap.txt" -oX "/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp3268/xml/tcp_3268_ldap_nmap.xml" 10.10.10.192
```

[/home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp3268/tcp_3268_ldap_nmap.txt](file:///home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp3268/tcp_3268_ldap_nmap.txt):

```
# Nmap 7.92 scan initiated Mon Aug 29 17:27:57 2022 as: nmap -vv --reason -Pn -T4 -sV -p 3268 "--script=banner,(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN /home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp3268/tcp_3268_ldap_nmap.txt -oX /home/kali/Projects/CTFs/HTB/Blackfield/results/10.10.10.192/scans/tcp3268/xml/tcp_3268_ldap_nmap.xml 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up, received user-set (0.076s latency).
Scanned at 2022-08-29 17:28:00 PDT for 18s

PORT     STATE SERVICE REASON          VERSION
3268/tcp open  ldap    syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local, Site: Default-First-Site-Name)
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=BLACKFIELD,DC=local
|       ldapServiceName: BLACKFIELD.local:dc01$@BLACKFIELD.LOCAL
|       isGlobalCatalogReady: TRUE
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxPercentDirSyncRequests
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxBatchReturnMessages
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxDirSyncDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: MaxValRangeTransitive
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.840.113556.1.4.801
|       supportedControl: 1.2.840.113556.1.4.473
|       supportedControl: 1.2.840.113556.1.4.528
|       supportedControl: 1.2.840.113556.1.4.417
|       supportedControl: 1.2.840.113556.1.4.619
|       supportedControl: 1.2.840.113556.1.4.841
|       supportedControl: 1.2.840.113556.1.4.529
|       supportedControl: 1.2.840.113556.1.4.805
|       supportedControl: 1.2.840.113556.1.4.521
|       supportedControl: 1.2.840.113556.1.4.970
|       supportedControl: 1.2.840.113556.1.4.1338
|       supportedControl: 1.2.840.113556.1.4.474
|       supportedControl: 1.2.840.113556.1.4.1339
|       supportedControl: 1.2.840.113556.1.4.1340
|       supportedControl: 1.2.840.113556.1.4.1413
|       supportedControl: 2.16.840.1.113730.3.4.9
|       supportedControl: 2.16.840.1.113730.3.4.10
|       supportedControl: 1.2.840.113556.1.4.1504
|       supportedControl: 1.2.840.113556.1.4.1852
|       supportedControl: 1.2.840.113556.1.4.802
|       supportedControl: 1.2.840.113556.1.4.1907
|       supportedControl: 1.2.840.113556.1.4.1948
|       supportedControl: 1.2.840.113556.1.4.1974
|       supportedControl: 1.2.840.113556.1.4.1341
|       supportedControl: 1.2.840.113556.1.4.2026
|       supportedControl: 1.2.840.113556.1.4.2064
|       supportedControl: 1.2.840.113556.1.4.2065
|       supportedControl: 1.2.840.113556.1.4.2066
|       supportedControl: 1.2.840.113556.1.4.2090
|       supportedControl: 1.2.840.113556.1.4.2205
|       supportedControl: 1.2.840.113556.1.4.2204
|       supportedControl: 1.2.840.113556.1.4.2206
|       supportedControl: 1.2.840.113556.1.4.2211
|       supportedControl: 1.2.840.113556.1.4.2239
|       supportedControl: 1.2.840.113556.1.4.2255
|       supportedControl: 1.2.840.113556.1.4.2256
|       supportedControl: 1.2.840.113556.1.4.2309
|       supportedControl: 1.2.840.113556.1.4.2330
|       supportedControl: 1.2.840.113556.1.4.2354
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
|       serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=BLACKFIELD,DC=local
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
|       namingContexts: DC=BLACKFIELD,DC=local
|       namingContexts: CN=Configuration,DC=BLACKFIELD,DC=local
|       namingContexts: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
|       namingContexts: DC=DomainDnsZones,DC=BLACKFIELD,DC=local
|       namingContexts: DC=ForestDnsZones,DC=BLACKFIELD,DC=local
|       isSynchronized: TRUE
|       highestCommittedUSN: 221274
|       dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=BLACKFIELD,DC=local
|       dnsHostName: DC01.BLACKFIELD.local
|       defaultNamingContext: DC=BLACKFIELD,DC=local
|       currentTime: 20220830072808.0Z
|_      configurationNamingContext: CN=Configuration,DC=BLACKFIELD,DC=local
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 29 17:28:18 2022 -- 1 IP address (1 host up) scanned in 20.45 seconds

```
