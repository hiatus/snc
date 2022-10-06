#include "snc.h"
#include "init.h"
#include "io.h"
#include "net.h"
#include "aes.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/wait.h>

struct SNCOptions {

	bool raw;
	bool tty;
	bool fork;
	bool verbose;
	bool use_dns;

	size_t argc;
	size_t port;

	char delim[2];
	char *argv [SNC_MAX_ARGV + 1];

	uint8_t key[AES_SIZE_KEY];
};


static struct SNCOptions opts = {
	.raw = false,
	.tty = false,
	.fork = false,
	.verbose = false,
	.use_dns = true,

	.argc = 0,
	.port = 0
};

static struct ServerInfo srv = {
	.fd = 0,
	.port = 0
};

static struct ConnectionInfo conn = {
	.fd = -1,
	.fdin = STDIN_FILENO,
	.fdout = STDOUT_FILENO,
	.timeout = 0,

	.port = 0
};

static const char banner[] =
"snc [options] [host]? [port]\n"
"	-h           this\n"
"	-v           display connection information\n"
"	-n           disable DNS resolution\n"
"	-r           set terminal to raw mode during the connection\n"
"	-f           fork before connecting\n"
"	-e [argv]    execute [argv] and pipe it's IO to the connection socket\n"
"	-E [argv]    execute [argv] in a TTY and pipe it's IO to the connection socket\n"
"	-d [char]    use [char] as string delimiter for [argv]\n"
"	-k [pass]    use the string [pass] as AES key\n"
"	-K [file]    use the file [file] as AES key\n"
"	-i [file]    read input from [file] instead of stdin\n"
"	-o [file]    write output to [file] instead of stdout\n"
"	-w [secs]    set a timeout of [secs] seconds for idle connections\n\n"

"	Notes:\n"
"		- When [host] is not provided, snc acts as server listening on port [port].\n"
"		- Option -d is useful when [argv] has arguments containing spaces.\n";

// Bionic does not provide pthread_cancel
#if defined(__ANDROID__)
static int pthread_cancel(pthread_t t)
{
	return pthread_kill(t, 0);
}
#endif

int main(int argc, char **argv)
{
	int opt;
	int ret = 0;

	pid_t pid;

	bool key_parsed = false;

	FILE *in = stdin;
	FILE *out = stdout;

	struct IOHandlerInfo iohi = {
		.ret = 0,
		.exited = false,

		.proc_pid = 0,
		.proc_in  = {0, 0},
		.proc_out = {0, 0},

		.conn = &conn
	};

	if (argc < 2) {
		fputs(banner, stderr);
		return SNC_EARGS;
	}

	strcpy(opts.delim, " ");

	memset(opts.key, 0x00, sizeof(opts.key));
	memset(conn.addr, 0x00, NET_MAX_IPV4 + 1);

	// Parse arguments
	while ((opt = getopt(argc, argv, ":hvnref:E:d:k:K:i:o:w:")) != -1) {
		switch (opt) {
			case 'h':
				ret = 0;
				fputs(banner, stderr);

				goto finish;

			case 'v':
				opts.verbose = true;
				break;

			case 'n':
				opts.use_dns = false;
				break;

			case 'r':
				opts.raw = true;
				break;

			case 'f':
				opts.fork = true;
				break;

			case 'e':
				opts.argc = init_argv(opts.argv, optarg, opts.delim);

				if (! opts.argc) {
					ret = SNC_EARGS;
					snc_err_fmt("Failed to parse [argv]: '%s'\n", optarg);

					goto finish;
				}

				if (access(opts.argv[0], F_OK | X_OK)) {
					ret = SNC_EARGS;
					snc_err_fmt("'%s' is not executable\n", opts.argv[0]);

					goto finish;
				}

				break;

			case 'E':
				opts.tty = true;
				opts.argc = init_argv(opts.argv, optarg, opts.delim);

				if (! opts.argc) {
					ret = SNC_EARGS;
					snc_err_fmt("Failed to parse [argv]: '%s'\n", optarg);

					goto finish;
				}

				if (access(opts.argv[0], F_OK | X_OK)) {
					ret = SNC_EARGS;
					snc_err_fmt("'%s' is not executable\n", opts.argv[0]);

					goto finish;
				}

				break;

			case 'd':
				if (strlen(optarg) != 1) {
					ret = SNC_EARGS;
					snc_err("The delimiter must be a single character\n");

					goto finish;
				}

				opts.delim[1] = 0x00;
				opts.delim[0] = optarg[0];

				break;

			case 'k':
				init_key(opts.key, optarg, strlen(optarg));
				memset(optarg, SNC_KEY_MASK, strlen(optarg));

				key_parsed = true;
				break;

			case 'K':
				if (init_key_file(opts.key, optarg)) {
					ret = SNC_EARGS;
					snc_perr("Failed to read key file");

					goto finish;
				}

				memset(optarg, SNC_KEY_MASK, strlen(optarg));

				key_parsed = true;
				break;

			case 'i':
				if (! (in = fopen(optarg, "rb"))) {
					ret = SNC_EARGS;
					snc_perr("Failed to open input file");

					goto finish;
				}

				conn.fdin = fileno(in);
				break;

			case 'o':
				if (! (out = fopen(optarg, "wb"))) {
					ret = SNC_EARGS;
					snc_perr("Failed to open output file");

					goto finish;
				}

				conn.fdout = fileno(out);
				break;

			case 'w':
				if (! (conn.timeout = strtoul(optarg, NULL, 10))) {
					ret = SNC_EARGS;
					snc_err_fmt("Invalid timeout: '%s'\n", optarg);

					goto finish;
				}

				break;

			case ':':
				ret = SNC_EARGS;
				snc_err_fmt("Option '%c' requires an argument\n", optopt);

				goto finish;

			case '?':
				ret = SNC_EARGS;
				snc_err_fmt("Invalid option: '%c'\n", optopt);

				goto finish;
		}
	}

	if (optind == argc) {
		ret = SNC_EARGS;
		snc_err("No remote host or port provided\n");

		goto finish;
	}

	if (optind < argc - 1) {
		if (opts.use_dns) {
			if (! host_to_ipv4(conn.addr, argv[optind])) {
				ret = SNC_EARGS;
				snc_err_fmt("Failed to resolve '%s'\n", argv[optind]);

				goto finish;
			}
		}
		else {
			if (! is_ipv4(argv[optind])) {
				ret = SNC_EARGS;
				snc_err_fmt("Bad IPv4 address: '%s'\n", argv[optind]);

				goto finish;
			}

			strncpy(conn.addr, argv[optind], NET_MAX_IPV4);
		}

		if (! (opts.port = strtoul(argv[++optind], NULL, 10)) || opts.port > 65535) {
			ret = SNC_EARGS;
			snc_err_fmt("Invalid port: '%s'\n", argv[optind]);

			goto finish;
		}

		conn.port = (uint16_t)opts.port;
	}
	else {
		if (! (opts.port = strtoul(argv[optind], NULL, 10)) || opts.port > 65535) {
			ret = SNC_EARGS;
			snc_err_fmt("Invalid port: '%s'\n", argv[optind]);

			goto finish;
		}

		srv.port = (uint16_t)opts.port;
	}

	if (! key_parsed) {
		ret = SNC_EARGS;
		snc_err("No key specified\n");

		goto finish;
	}

	// Initialize server socket
	if (srv.port && (ret = srv_init(&srv))) {
		snc_perr("srv_init");
		goto finish;
	}

	// Fork
	if (opts.fork) {
		if ((pid = fork()) < 0) {
			snc_perr("fork");
			goto finish;
		}
		else
		if (pid)
			_exit(0);

		if ((pid = setsid()) < 0) {
			snc_perr("setsid");
			goto finish;
		}
	}

	// Initialize connection
	if (opts.verbose) {
		if (srv.fd)
			snc_msg_fmt("Listening on port %i\n", srv.port);
		else
			snc_msg_fmt("Connecting to %s:%i\n", conn.addr, conn.port);
	}

	if (srv.fd) {
		if ((ret = srv_conn(&srv, &conn))) {
			snc_perr("srv_conn");
			goto finish;
		}
	}
	else {
		if ((ret = cli_conn(&conn))) {
			snc_perr("cli_conn");
			goto finish;
		}
	}

	if (opts.verbose) {
		if (! srv.fd)
			snc_msg("Connected\n");
		else
			snc_msg_fmt("Connection from %s:%i\n", conn.addr, conn.port);
	}

	// Authenticate
	if (srv.fd) {
		if ((ret = srv_auth(&conn, opts.key))) {
			if (ret == SNC_EAUTH)
				snc_err("srv_auth: key mismatch\n");
			else
			if (ret == SNC_ESYNC)
				snc_err("srv_auth: data asynchrony\n");

			goto finish;
		}
	}
	else {
		if ((ret = cli_auth(&conn, opts.key))) {
			if (ret == SNC_EAUTH)
				snc_err("cli_auth: key mismatch\n");
			else
			if (ret == SNC_ESYNC)
				snc_err("cli_auth: data asynchrony\n");

			goto finish;
		}
	}

	if (opts.argc) {
		// Setup process IO
		if (! opts.tty) {
			if (exec_child(&iohi, opts.argv) == SNC_EEXEC)
				goto finish;
		}
		else {
			if (exec_child_tty(&iohi, opts.argv) == SNC_EEXEC)
				goto finish;
		}
	}

	if (opts.raw) {
		// Set terminal to raw mode
		if (! tty_raw(conn.fdin))
			atexit(tty_reset);
		else
			snc_wrn("Failed to set terminal to raw mode\n");
	}

	// Thread execution to handle IO
	if ((ret = pthread_create(&iohi.thread, NULL, &io_handler, &iohi))) {
		iohi.ret = net_async(&conn);

		if (iohi.proc_pid)
			kill(iohi.proc_pid, SIGTERM);
	}

	if (iohi.proc_pid) {
		wait(NULL);

		if (! ret && ! iohi.exited)
			pthread_cancel(iohi.thread);
	}

	if (! ret)
		pthread_join(iohi.thread, NULL);

	if ((ret = iohi.ret) != 0) {
		if (opts.verbose)
			fputc('\n', stderr);

		if (ret == SNC_ESYNC)
			snc_err("async_io: data asynchrony\n");
		else
		if (ret == SNC_ETIME)
			snc_err("async_io: connection timeout\n");
		else
		if (ret == SNC_ECRPT)
			snc_err("async_io: data corruption\n");
		else
			snc_perr("async_io");
	}

finish:
	if (iohi.proc_pid) {
		if (iohi.proc_in[0] > 0)
			close(iohi.proc_in[0]);
		
		if (iohi.proc_out[1])
			close(iohi.proc_out[1]);
	}

	if (in && in != stdin) {
		fclose(in);
		in = NULL;
	}

	if (out && out != stdout) {
		fclose(out);
		out = NULL;
	}

	if (conn.fd > 0)
		close(conn.fd);

	if (srv.fd > 0)
		close(srv.fd);

	if (opts.raw)
		putchar('\r');

	return ret;
}
