#ifndef SNC_H
#define SNC_H

#define SNC_EARGS 1
#define SNC_ESYNC 2
#define SNC_EAUTH 3
#define SNC_EEXEC 4
#define SNC_ETIME 5
#define SNC_ECRPT 6

#define SNC_MAX_ARGV 32

#define SNC_KEY_MASK '*'

#define snc_msg(s) fputs("\r[snc] " s, stderr)
#define snc_wrn(s) fputs("\r[wrn] " s, stderr)
#define snc_err(s) fputs("\r[err] " s, stderr)

#define snc_msg_fmt(fmt, ...) fprintf(stderr, "\r[snc] " fmt, __VA_ARGS__)
#define snc_err_fmt(fmt, ...) fprintf(stderr, "\r[err] " fmt, __VA_ARGS__)
#define snc_wrn_fmt(fmt, ...) fprintf(stderr, "\r[wrn] " fmt, __VA_ARGS__)

#define snc_pmsg(s) perror("\r[snc] " s)
#define snc_pwrn(s) perror("\r[wrn] " s)
#define snc_perr(s) perror("\r[err] " s)
#endif