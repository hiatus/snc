#include "io.h"
#include "net.h"
#include "snc.h"

#include <pty.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>

static int _term_fd;
static struct termios _term_info;

void close_fd(int *fd) {
	if (*fd) {
		close(*fd);
		*fd = 0;
	}
}

void unset_tty_raw(void)
{
	tcsetattr(_term_fd, TCSAFLUSH, &_term_info);
}

void *io_handler(void *arg)
{
	struct io_handler_info *iohi = (struct io_handler_info *)arg;

	iohi->ret = async_io(iohi->conn);

	if (iohi->proc_pid)
		kill(iohi->proc_pid, SIGTERM);

	iohi->exited = true;

	return NULL;
}

int set_tty_raw(int fd)
{
	struct termios raw;

	_term_fd = fd;

	if (! isatty(_term_fd)) {
		snc_pwrn("isatty");
		return SNC_ETERM;
	}

	if (tcgetattr(_term_fd, &_term_info) < 0) {
		snc_pwrn("tcgetattr");
		return SNC_ETERM;
	}

	memcpy(&raw, &_term_info, sizeof(struct termios));

	raw.c_cc[VMIN] = 0;

	raw.c_cflag |=  (CS8);
	raw.c_oflag &= ~(OPOST);
	raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
	raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

	if (tcsetattr(_term_fd, TCSAFLUSH, &raw) < 0) {
		snc_pwrn("tcsetattr");
		return SNC_ETERM;
	}

	return 0;
}

int init_proc_io(struct io_handler_info *iohi, char **argv)
{
	// Create pipes
	if (pipe(iohi->proc_in) < 0) {
		snc_perr("pipe");
		return SNC_EPROC;
	}

	if (pipe(iohi->proc_out) < 0) {
		snc_perr("pipe");
		return SNC_EPROC;
	}

	// Fork to execute process
	if ((iohi->proc_pid = fork()) < 0) {
		iohi->proc_pid = 0;
		snc_perr("fork");

		return SNC_EPROC;
	}

	if (! iohi->proc_pid) {
		fflush(stdout);
		fflush(stderr);

		dup2(iohi->proc_in [0], 0);
		dup2(iohi->proc_out[1], 1);
		dup2(iohi->proc_out[1], 2);

		execv(argv[0], argv);

		// Unreached
		iohi->proc_pid = 0;
		snc_perr("execv");

		_exit(SNC_EPROC);
	}

	iohi->conn->fdin  = iohi->proc_out[0];
	iohi->conn->fdout = iohi->proc_in [1];

	return 0;
}

int init_proc_io_tty(struct io_handler_info *iohi, char **argv)
{
	int pty, tty;
	struct winsize ws;

	if (openpty(&pty, &tty, NULL, NULL, NULL) < 0) {
		snc_perr("openpty");
		return SNC_EPROC;
	}

	if (! ttyname(tty)) {
		snc_perr("ttyname");
		return SNC_EPROC;
	}

	// Try to set terminal dimensions to the caller's
	if (ioctl(iohi->conn->fdout, TIOCGWINSZ, &ws) >= 0)
		ioctl(pty, TIOCSWINSZ, &ws);

	// Fork to execute process
	if ((iohi->proc_pid = fork()) < 0) {
		snc_perr("fork");
		return SNC_EPROC;
	}

	if (! iohi->proc_pid) {
		close_fd(&pty);

		// Start a new session
		if (setsid() < 0) {
			snc_perr("setsid");
			_exit(SNC_EPROC);
		}

		// Try to set TTY to have job control
		if (ioctl(tty, TIOCSCTTY, NULL) < 0)
			snc_pwrn("ioctl: no job control for TTY");

		dup2(tty, 0);
		dup2(tty, 1);
		dup2(tty, 2);

		execv(argv[0], argv);

		// Unreached
		iohi->proc_pid = 0;
		snc_perr("execv");

		_exit(SNC_EPROC);
	}

	close_fd(&tty);
	iohi->conn->fdin = iohi->conn->fdout = pty;

	return 0;
}
