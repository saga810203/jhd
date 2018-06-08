/*
 * jhd_process.h
 *
 *  Created on: Jun 1, 2018
 *      Author: root
 */

#ifndef JHD_PROCESS_H_
#define JHD_PROCESS_H_


typedef void (*jhd_spawn_proc_pt) (void *data);

typedef struct {
	int signo;
	char *signame;
	char *name;
	void (*handler)(int signo, siginfo_t *siginfo, void *ucontext);
} jhd_signal_t;


extern pid_t jhd_pid;
extern pid_t jhd_parent;

jhd_bool jhd_init_signals();
int jhd_signal_process(char *sig);
jhd_bool jhd_daemon();
jhd_bool jhd_create_pidfile();
void jhd_single_process();
void jhd_master_process();

#endif /* JHD_PROCESS_H_ */
