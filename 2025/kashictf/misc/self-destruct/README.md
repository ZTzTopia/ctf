---
title: "Self Destruct"
categories: Miscellaneous
tags: 
draft: true
completedDuringEvent: true
submitted: true
flags: KashiCTF{Love_Hurts_5734b5f}
---
> Explore the virtual machine and you might just find the flag. Or a surprise. Maybe....
>
> **NOTE**: The attachment is a VirtualBox image. Do not run it outside VirtualBox. It is recommended to backup the .vdi file before launching the VM.
>
> VM Parameters: (VirtualBox)
> Type: Linux
> Version: Debian (32 bits)
> RAM: 1024MB
> Storage: attached .vdi file
>
> Username: kashictf
> Password: kashictf
>
> Attachments: [Self Destruct Debian.vdi](https://drive.google.com/file/d/1DFJn8cXhMBxq_NIixJo_J73Dkz9H2iSc/view?usp=drive_link)

by `Argus817`

---

## Exploring the User's Home Directory

After booting the VM, I logged in with the provided credentials. I started by checking the user's home directory.

```sh
$ ls -la ./home/kashictf/
total 8
drwxrwxrwx 1 ztz ztz 4096 Feb 20 22:57 .
drwxrwxrwx 1 ztz ztz 4096 Feb 20 20:29 ..
-rwxrwxrwx 1 ztz ztz   41 Feb 20 21:52 .bash_history
-rwxrwxrwx 1 ztz ztz  220 Feb 20 20:29 .bash_logout
-rwxrwxrwx 1 ztz ztz 3526 Feb 20 20:29 .bashrc
-rwxrwxrwx 1 ztz ztz  807 Feb 20 20:29 .profile
-rwxrwxrwx 1 ztz ztz   41 Feb 20 22:56 .sush_history
```

We find several hidden files, including `.bash_history` and `.sush_history`. Checking their contents reveals parts of the flag:

```sh
$ cat ./home/kashictf/.bash_history
ls
echo "fLaG Part 5: 'ht??_No_Er'"
exit
$ cat ./home/kashictf/.sush_history
ls
echo "fLaG Part 3: 'eserve_roo'"
exit
```

## Searching for More Flag Parts

Next, I searched for the flag parts in the entire filesystem. We use `grep` to search for the string `"fLaG Part"` in all files.

```sh
$ grep -r "fLaG Part" . 2>/dev/null
./etc/hosts.allow:# fLaG Part 1: 'KashiCTF{r'
./etc/kernel-img.conf:# Kernel image management overrides fLaG Part 4: 't_Am_1_Rig'
./etc/sudo.conf:# fLaG Part 6: 'r0rs_4ll0w'
./home/kashictf/.bash_history:echo "fLaG Part 5: 'ht??_No_Er'"
./home/kashictf/.sush_history:echo "fLaG Part 3: 'eserve_roo'"
```

## Interesting /etc/passwd Entry

Because i dont find the part with `grep` instead just check some important files in `/etc/` directory. And also check the `/etc/passwd` file.

```sh
$ cat ./etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
tcpdump:x:102:103::/nonexistent:/usr/sbin/nologin
sshd:x:103:65534::/run/sshd:/usr/sbin/nologin
ztz:x:1000:1000:,,,:/home/ztz:/bin/zsh
tss:x:104:106:TPM software stack,,,:/var/lib/tpm:/bin/false
strongswan:x:105:65534::/var/lib/strongswan:/usr/sbin/nologin
xrdp:x:106:108::/run/xrdp:/usr/sbin/nologin
dnsmasq:x:999:65534:dnsmasq:/var/lib/misc:/usr/sbin/nologin
avahi:x:107:110:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
nm-openvpn:x:108:111:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
speech-dispatcher:x:109:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
nm-openconnect:x:111:112:NetworkManager OpenConnect plugin,,,:/var/lib/NetworkManager:/usr/sbin/nologin
pulse:x:112:113:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
lightdm:x:113:116:Light Display Manager:/var/lib/lightdm:/bin/false
saned:x:114:118::/var/lib/saned:/usr/sbin/nologin
polkitd:x:992:992:User for polkitd:/:/usr/sbin/nologin
rtkit:x:115:119:RealtimeKit,,,:/proc:/usr/sbin/nologin
colord:x:116:120:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
(.venv)ztz@DESKTOP-U09SAP1:/mnt/c/Users/zenta/Downloads/halnnaecntk/Self Destruct Debian/0$ cat ./etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:109:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
kashictf:x:1000:1000:KashiCTF,,,:/home/kashictf:/bin/sush
```

The interesting part is the `/bin/sush` binary. Let's check it out.

```sh
$ strings ./bin/sush | grep "fLaG Part"              
fLaG Part 7: 'ed_Th0}'
fLaG Part 2: 'm_rf_no_pr'
```

```
1: 'KashiCTF{r'  
2: 'm_rf_no_pr'  
3: 'eserve_roo'  
4: 't_Am_1_Rig'  
5: 'ht??_No_Er'  
6: 'r0rs_4ll0w'  
7: 'ed_Th0}'  
```
