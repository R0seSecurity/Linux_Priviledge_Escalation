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

[Exploring Automated Tools](https://www.notion.so/Exploring-Automated-Tools-a12e98e4a7ea4fb08379da35d45d666c)

[Escalation Path: Kernel Exploits](https://www.notion.so/Escalation-Path-Kernel-Exploits-946236bec8734fa5a5d86bad7f6b9ec3)

[Escalation  Path: Password & File Permissions](https://www.notion.so/Escalation-Path-Password-File-Permissions-f396a9907a0b470987f940bf1f11522a)

[Escalation Path: Sudo](https://www.notion.so/Escalation-Path-Sudo-d71d46b20d5d49e282d06c30e0481df2)

[Escalation Path: SUID](https://www.notion.so/Escalation-Path-SUID-367a34f6fb504c5f87cc81a4a81e9f75)

[Escalation Path: Other SUID Escalation](https://www.notion.so/Escalation-Path-Other-SUID-Escalation-3499fe12053b4311a10829e18235c5f5)

[Escalation Path: Capabilities](https://www.notion.so/Escalation-Path-Capabilities-1d5f76d82b4e4f129ebaa6a6682a72e7)

[Escalation Path: Scheduled Tasks](https://www.notion.so/Escalation-Path-Scheduled-Tasks-e50e325782ce411e93226fc365cdfc0f)

[Escalation Path: NFS Root Squashing](https://www.notion.so/Escalation-Path-NFS-Root-Squashing-f307d8d8b80b491ab9011aebde96b4de)

[Escalation Path: Docker](https://www.notion.so/Escalation-Path-Docker-60cf38067b0d4cf9ab761975efd4f24a)

[Capstone Challenge](https://www.notion.so/Capstone-Challenge-5473fd2ee60a465f9a093ee8eac1e14f)
