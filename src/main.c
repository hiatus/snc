#include "snc.h"
#include "init.h"
#include "io.h"
#include "net.h"
#include "aes.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/wait.h>

struct snc_opts {
	bool raw;
	bool tty;
	bool fork;
	bool verbose;
	bool use_dns;
	bool persist;

	size_t argc;

	char delim[2];
	char *argv [SNC_ARG_MAX + 1];

	uint8_t key[AES_KEY_SIZE];
};

const char banner[] =
"snc [options] [host]? [port]\n"
"    -h           this\n"
"    -v           verbosity\n"
"    -n           disable DNS\n"
"    -f           fork before connecting\n"
"    -r           set terminal to raw mode\n"
"    -l           listen until a client authenticates\n\n"

"    -e [args]    execute [args]\n"
"    -E [args]    execute [args] in a TTY\n"
"    -d [char]    delimiter for [args]\n"
"    -k [pass]    use [pass] as AES key\n"
"    -K [file]    use [file] as AES key\n"
"    -i [file]    read input from [file]\n"
"    -o [file]    write output to [file]\n"
"    -w [secs]    idle connection timeout\n\n"

"    If [host] is not provided, listen on [port]\n";

// Bionic does not provide pthread_cancel
#if defined(__ANDROID__)
static int pthread_cancel(pthread_t t)
{
	return pthread_kill(t, 0);
}
#endif


// Count occurrences of c in len bytes of mem
static size_t _memeq(void *mem, int c, size_t len)
{
	size_t eq = 0;

	while (len--) {
		if (((uint8_t *)mem)[len] == (uint8_t)c)
			++eq;
	}

	return eq;
}

// Parse arguments for -e and -E
static int _parse_argv(char **argv, char *cmd, const char *delim)
{
	size_t argc;
	char *token = strtok(cmd, delim);

	for (argc = 0; token && argc < SNC_ARG_MAX; ++argc) {
		argv[argc] = token;
		token = strtok(NULL, delim);
	}

	argv[argc] = NULL;

	return argc;
}

int main(int argc, char **argv)
{
	int opt;
	int ret = 0;

	pid_t pid;

	FILE *in = stdin;
	FILE *out = stdout;

	struct snc_opts opts = {
		.argc = 0,

		.tty = false,
		.raw = false,
		.fork = false,
		.use_dns = true,
		.verbose = false,
		.persist = false
	};

	struct srv_info srv = {
		.sock = 0,
		.port = 0,

		.conn = {
			.sock = 0,
			.port = 0,

			.timeout = 0,
			.recv_bytes = 0,
			.send_bytes = 0,

			.fdin  = fileno(in),
			.fdout = fileno(out)
		}
	};

	struct conn_info *conn = &srv.conn;

	struct io_handler_info iohi = {
		.ret = 0,
		.exited = false,

		.proc_pid = 0,
		.proc_in  = {0, 0},
		.proc_out = {0, 0},

		.conn = conn
	};

	if (argc < 2) {
		fputs(banner, stderr);
		return -SNC_EARGV;
	}

	strcpy(opts.delim, " ");

	memset(opts.key,   0x00, sizeof(opts.key));
	memset(conn->addr, 0x00, NET_IPV4_MAX + 1);

	// Parse arguments
	while ((opt = getopt(argc, argv, ":hvnfrle:E:d:k:K:i:o:w:")) != -1) {
		switch (opt) {
			case 'h':
				ret = 0;
				fputs(banner, stderr);

				goto close_io;

			case 'v':
				opts.verbose = true;
				break;

			case 'n':
				opts.use_dns = false;
				break;

			case 'f':
				opts.fork = true;
				break;

			case 'r':
				opts.raw = true;
				break;

			case 'l':
				opts.persist = true;
				break;

			case 'e':
				opts.argc = _parse_argv(opts.argv, optarg, opts.delim);

				if (! opts.argc) {
					ret = SNC_EARGV;
					snc_err_fmt("Failed to parse [args]: '%s'\n", optarg);

					goto close_io;
				}

				if (access(opts.argv[0], F_OK | X_OK)) {
					ret = SNC_EARGV;
					snc_err_fmt("'%s' is not executable\n", opts.argv[0]);

					goto close_io;
				}

				break;

			case 'E':
				opts.tty = true;
				opts.argc = _parse_argv(opts.argv, optarg, opts.delim);

				if (! opts.argc) {
					ret = SNC_EARGV;
					snc_err_fmt("Failed to parse [args]: '%s'\n", optarg);

					goto close_io;
				}

				if (access(opts.argv[0], F_OK | X_OK)) {
					ret = SNC_EARGV;
					snc_err_fmt("'%s' is not executable\n", opts.argv[0]);

					goto close_io;
				}

				break;

			case 'd':
				if (strlen(optarg) != 1) {
					ret = SNC_EARGV;
					snc_err("The delimiter must be a single character\n");

					goto close_io;
				}

				opts.delim[1] = 0x00;
				opts.delim[0] = optarg[0];

				break;

			case 'k':
				init_aes_key(opts.key, optarg, strlen(optarg));
				memset(optarg, SNC_KEY_MASK, strlen(optarg));

				break;

			case 'K':
				if (init_aes_key_file(opts.key, optarg)) {
					ret = SNC_EARGV;
					snc_perr("Failed to read key file");

					goto close_io;
				}

				memset(optarg, SNC_KEY_MASK, strlen(optarg));
				break;

			case 'i':
				if (! (in = fopen(optarg, "rb"))) {
					ret = SNC_EARGV;
					snc_perr("Failed to open input file");

					goto close_io;
				}

				conn->fdin = fileno(in);
				break;

			case 'o':
				if (! (out = fopen(optarg, "wb"))) {
					ret = SNC_EARGV;
					snc_perr("Failed to open output file");

					goto close_io;
				}

				conn->fdout = fileno(out);
				break;

			case 'w':
				if (! (conn->timeout = (size_t)strtoul(optarg, NULL, 10))) {
					ret = SNC_EARGV;
					snc_err_fmt("Invalid timeout: '%s'\n", optarg);

					goto close_io;
				}

				break;

			case ':':
				ret = SNC_EARGV;
				snc_err_fmt("Option '%c' requires an argument\n", optopt);

				goto close_io;

			case '?':
				ret = SNC_EARGV;
				snc_err_fmt("Invalid option: '%c'\n", optopt);

				goto close_io;
		}
	}

	if (optind == argc) {
		ret = SNC_EARGV;
		snc_err("No remote host or port provided\n");

		goto close_io;
	}

	if (optind < argc - 1) {
		if (opts.use_dns) {
			if (! hostname_to_ipv4(conn->addr, argv[optind])) {
				ret = SNC_EARGV;
				snc_err_fmt("Failed to resolve '%s'\n", argv[optind]);

				goto close_io;
			}
		}
		else {
			if (! is_ipv4(argv[optind])) {
				ret = SNC_EARGV;
				snc_err_fmt("Bad IPv4 address: '%s'\n", argv[optind]);

				goto close_io;
			}

			strncpy(conn->addr, argv[optind], NET_IPV4_MAX);
		}


		if (! (conn->port = (uint16_t)strtoul(argv[++optind], NULL, 10))) {
			ret = SNC_EARGV;
			snc_err_fmt("Invalid port: '%s'\n", argv[optind]);

			goto close_io;
		}
	}
	else {
		if (! (srv.port = (uint16_t)strtoul(argv[optind], NULL, 10))) {
			ret = SNC_EARGV;
			snc_err_fmt("Invalid port: '%s'\n", argv[optind]);

			goto close_io;
		}
	}

	if (_memeq(opts.key, 0x00, sizeof(opts.key)) == sizeof(opts.key)) {
		ret = SNC_EARGV;
		snc_err("No AES key\n");

		goto close_io;
	}

	if (! srv.port && opts.persist) {
		ret = SNC_EARGV;
		snc_err("Option 'l' makes no sense in client mode\n");

		goto close_io;
	}

	if (opts.fork) {
		if ((pid = fork()) < 0) {
			snc_perr("fork");
			goto close_io;
		}
		else
		if (pid)
			exit(0);

		if ((pid = setsid()) < 0) {
			snc_perr("setsid");
			goto close_io;
		}
	}

	// Initialize server socket
	if (srv.port && (ret = srv_init(&srv)) != 0) {
		snc_perr("srv_init");
		goto close_io;
	}

conn:
	// Initialize connection
	if (opts.verbose) {
		if (srv.sock)
			snc_log_fmt("Listening on port %i\n", srv.port);
		else
			snc_log_fmt("Connecting to %s:%i\n", conn->addr, conn->port);
	}

	if ((ret = srv.sock ? srv_conn(&srv) : cli_conn(conn)) != 0) {
		(srv.sock) ? snc_perr("srv_conn") : snc_perr("cli_conn");
		goto close_io;
	}

	if (opts.verbose) {
		if (! srv.sock)
			snc_log("Connected\n");
		else
			snc_log_fmt("Connection from %s:%i\n", conn->addr, conn->port);
	}

	ret = srv.sock ? srv_auth(conn, opts.key) : cli_auth(conn, opts.key);

	if (ret != 0) {
		if (ret == SNC_EAUTH) {
			(srv.sock) ?
				snc_err("srv_auth: key mismatch\n") :
				snc_err("cli_auth: key mismatch\n") ;
		}
		else
		if (ret == SNC_ESYNC) {
			(srv.sock) ?
				snc_err("srv_auth: data asynchrony\n") :
				snc_err("cli_auth: data asynchrony\n") ;
		}
		else
			(srv.sock) ? snc_perr("srv_auth") : snc_perr("cli_auth");

		usleep(SNC_TRY_INT);

		if (srv.sock && opts.persist) {
			close(conn->sock);

			if (opts.verbose)
				fputc('\n', stderr);

			goto conn;
		}

		goto print_io;
	}

	if (opts.verbose)
		snc_log("Authenticated\n");

	if (opts.argc) {
		// Setup process IO
		if (! opts.tty) {
			if (init_proc_io(&iohi, opts.argv) == SNC_EPROC)
				goto print_io;
		}
		else {
			if (init_proc_io_tty(&iohi, opts.argv) == SNC_EPROC)
				goto print_io;
		}
	}

	if (opts.raw) {
		// Set terminal to raw mode
		if (! set_tty_raw(conn->fdin))
			atexit(unset_tty_raw);
		else
			snc_wrn("Failed to set terminal to raw mode\n");
	}

	// Thread execution to handle IO
	if ((ret = pthread_create(&iohi.thread, NULL, &io_handler, &iohi))) {
		iohi.ret = async_io(conn);

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

print_io:
	if (opts.verbose) {
		snc_log_fmt(
			"%zu bytes sent, %zu received\n",
			conn->send_bytes, conn->recv_bytes
		);
	}

close_io:
	if (iohi.proc_pid) {
		close_fd(&iohi.proc_in [0]);
		close_fd(&iohi.proc_out[1]);
	}

	if (in && in != stdin) {
		fclose(in);
		in = NULL;
	}

	if (out && out != stdout) {
		fclose(out);
		out = NULL;
	}

	if (conn->sock)
		close_fd(&conn->sock);

	if (srv.sock)
		close_fd(&srv.sock);

	if (opts.raw)
		putchar('\r');

	return -ret;
}
