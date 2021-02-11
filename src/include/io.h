#ifndef IO_H
#define IO_H

#include "net.h"

#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>

struct io_handler_info {
	int ret;
	bool exited;

	pid_t proc_pid;

	pthread_t thread;

	int proc_in [2];
	int proc_out[2];

	struct conn_info *conn;
};

void close_fd(int *fd);
void unset_tty_raw(void);

void *io_handler(void *arg);

int set_tty_raw(int fd);
int init_proc_io(struct io_handler_info *iohi, char **argv);
int init_proc_io_tty(struct io_handler_info *iohi, char **argv);
#endif
