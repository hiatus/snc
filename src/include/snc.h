#ifndef SNC_H
#define SNC_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define SNC_EARGV -1
#define SNC_ECONN -2
#define SNC_EAUTH -3
#define SNC_ESYNC -4
#define SNC_ECRPT -5
#define SNC_ETIME -6
#define SNC_ETERM -7
#define SNC_EPROC -8

#define SNC_ARG_MAX 16
#define SNC_KEY_MAX 4096
#define SNC_TRY_DEF 1
#define SNC_TRY_INT 1000000

#define SNC_KEY_MASK '*'

#define snc_perr(s) perror("\r[err] " s)
#define snc_pwrn(s) perror("\r[err] " s)

#define snc_log(s) fputs("\r[snc] " s, stderr)
#define snc_wrn(s) fputs("\r[wrn] " s, stderr)
#define snc_err(s) fputs("\r[err] " s, stderr)

#define snc_err_fmt(fmt, ...) fprintf(stderr, "\r[err] " fmt, __VA_ARGS__)
#define snc_wrn_fmt(fmt, ...) fprintf(stderr, "\r[wrn] " fmt, __VA_ARGS__)
#define snc_log_fmt(fmt, ...) fprintf(stderr, "\r[snc] " fmt, __VA_ARGS__)
#endif
