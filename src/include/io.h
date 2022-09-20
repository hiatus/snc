#ifndef IO_H
#define IO_H

#include "net.h"

#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>


struct IOHandlerInfo {
	int ret;
	bool exited;

	pid_t proc_pid;

	pthread_t thread;

	int proc_in[2];
	int proc_out[2];

	struct ConnectionInfo *conn;
};

void *io_handler(void *arg);

int tty_raw(int fd);
void tty_reset(void);

int exec_child(struct IOHandlerInfo *iohi, char **argv);
int exec_child_tty(struct IOHandlerInfo *iohi, char **argv);
#endif
