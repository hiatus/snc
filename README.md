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
	-h            this
	-v            verbosity
	-n            disable DNS
	-f            fork before connecting
	-r            set terminal to raw mode
	-l            listen until a client authenticates

	-e [args]     execute [args]
	-E [args]     execute [args] in a TTY
	-d [delim]    delimiter for [args]
	-k [pass]     use [pass] as AES key
	-K [file]     use [file] as AES key
	-i [file]     read input from [file]
	-o [file]     write output to [file]
	-w [secs]     idle connection timeout

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
