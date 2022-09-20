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


void *io_handler(void *arg)
{
	struct IOHandlerInfo *iohi = (struct IOHandlerInfo *)arg;

	iohi->ret = net_async(iohi->conn);

	if (iohi->proc_pid)
		kill(iohi->proc_pid, SIGTERM);

	iohi->exited = true;

	return NULL;
}

// Set terminal to raw mode
int tty_raw(int fd)
{
	struct termios raw;

	_term_fd = fd;

	if (! isatty(_term_fd)) {
		snc_pwrn("isatty");
		return 1;
	}

	if (tcgetattr(_term_fd, &_term_info) < 0) {
		snc_pwrn("tcgetattr");
		return 1;
	}

	memcpy(&raw, &_term_info, sizeof(struct termios));

	raw.c_cc[VMIN] = 0;

	raw.c_cflag |=  (CS8);
	raw.c_oflag &= ~(OPOST);
	raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
	raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

	if (tcsetattr(_term_fd, TCSAFLUSH, &raw) < 0) {
		snc_pwrn("tcsetattr");
		return 1;
	}

	return 0;
}

// Set terminal back to normal
void tty_reset(void)
{
	tcsetattr(_term_fd, TCSAFLUSH, &_term_info);
}

int exec_child(struct IOHandlerInfo *iohi, char **argv)
{
	// Create pipes
	if (pipe(iohi->proc_in) < 0) {
		snc_perr("pipe");
		return 1;
	}

	if (pipe(iohi->proc_out) < 0) {
		snc_perr("pipe");
		return 1;
	}

	// Fork to execute process
	if ((iohi->proc_pid = fork()) < 0) {
		iohi->proc_pid = 0;
		snc_perr("fork");

		return 1;
	}

	if (! iohi->proc_pid) {
		fflush(stdout);
		fflush(stderr);

		// Duplicate file descriptors to pipes
		dup2(iohi->proc_in [0], 0);
		dup2(iohi->proc_out[1], 1);
		dup2(iohi->proc_out[1], 2);

		// Execute arguments
		execv(argv[0], argv);

		// Unreached
		iohi->proc_pid = 0;
		snc_perr("execv");

		_exit(1);
	}

	// Set connection file descriptors to those of the spawned process
	iohi->conn->fdin  = iohi->proc_out[0];
	iohi->conn->fdout = iohi->proc_in [1];

	return 0;
}

int exec_child_tty(struct IOHandlerInfo *iohi, char **argv)
{
	int pty, tty;
	struct winsize ws;

	// Allocate a TTY
	if (openpty(&pty, &tty, NULL, NULL, NULL) < 0) {
		snc_perr("openpty");
		return 1;
	}

	if (! ttyname(tty)) {
		snc_perr("ttyname");
		return 1;
	}

	// Try to set terminal dimensions to the parent's
	if (ioctl(iohi->conn->fdout, TIOCGWINSZ, &ws) >= 0)
		ioctl(pty, TIOCSWINSZ, &ws);

	// Fork to execute process
	if ((iohi->proc_pid = fork()) < 0) {
		snc_perr("fork");
		return 1;
	}

	if (! iohi->proc_pid) {
		close(pty);

		// Start a new session
		if (setsid() < 0) {
			snc_perr("setsid");
			_exit(1);
		}

		// Try to setup job control for the TTY
		if (ioctl(tty, TIOCSCTTY, NULL) < 0)
			snc_pwrn("ioctl: no job control for this TTY");

		// Set file descriptors to the TTY
		dup2(tty, 0);
		dup2(tty, 1);
		dup2(tty, 2);

		execv(argv[0], argv);

		// Unreached
		iohi->proc_pid = 0;
		snc_perr("execv");

		_exit(1);
	}

	close(tty);

	// Set connection input descriptor to the PTY
	iohi->conn->fdin = iohi->conn->fdout = pty;

	return 0;
}
