/*
 * jhd_process.c
 *
 *  Created on: Jun 1, 2018
 *      Author: root
 */

#include <jhd_config.h>
#include <jhd_process.h>
#include <jhd_core.h>

static void jhd_signal_handler(int signo, siginfo_t *siginfo, void *ucontext);

jhd_signal_t signals[] = { { SIGHUP, "SIGHUP", "restart", jhd_signal_handler },

{ SIGUSR1, "SIGUSR1", "", jhd_signal_handler },

{ SIGWINCH, "SIGWINCH", "", jhd_signal_handler },

{ SIGTERM, "SIGTERM", "", jhd_signal_handler },

{ SIGQUIT, "SIGQUIT", "quit", jhd_signal_handler },

{ SIGUSR2, "SIGUSR2", "", jhd_signal_handler },

{ SIGALRM, "SIGALRM", "", jhd_signal_handler },

{ SIGINT, "SIGINT", "", jhd_signal_handler },

{ SIGIO, "SIGIO", "", jhd_signal_handler },

{ SIGCHLD, "SIGCHLD", "", jhd_signal_handler },

{ SIGSYS, "SIGSYS, SIG_IGN", "", NULL },

{ SIGPIPE, "SIGPIPE, SIG_IGN", "", NULL },

{ 0, NULL, "", NULL } };

static void jhd_signal_handler(int signo, siginfo_t *siginfo, void *ucontext) {
	jhd_signal_t *sig;

	for (sig = signals; sig->signo != 0; sig++) {
		if (sig->signo == signo) {
			break;
		}
	}

	switch (jhd_process) {

		case JHD_PROCESS_MASTER:
		case JHD_PROCESS_SINGLE:
			switch (signo) {

				case SIGQUIT:
				case SIGTERM:
				case SIGINT:
					jhd_quit = 1;
//            action = "shutting down";
					break;

				case SIGWINCH:
					break;

				case SIGHUP:
					jhd_restart = 1;
//            action = "restart jhttpd";
					break;

				case SIGUSR1:
				case SIGUSR2:
					break;
				case SIGALRM:
					//  ngx_sigalrm = 1;
					break;

				case SIGIO:
					//  ngx_sigio = 1;
					break;

				case SIGCHLD:
					//  ngx_reap = 1;
					break;
			}

			break;

		case JHD_PROCESS_WORKER:
		case JHD_PROCESS_HELPER:
			if (signo == SIGQUIT || signo == SIGTERM || signo == SIGINT) {
				jhd_quit = 1;
//    		 action = "shutting down";
			}
			break;
	}
}

jhd_bool jhd_init_signals() {
	jhd_signal_t *sig;
	struct sigaction sa;

	for (sig = signals; sig->signo != 0; sig++) {
		ngx_memzero(&sa, sizeof(struct sigaction));

		if (sig->handler) {
			sa.sa_sigaction = sig->handler;
			sa.sa_flags = SA_SIGINFO;

		} else {
			sa.sa_handler = SIG_IGN;
		}

		sigemptyset(&sa.sa_mask);
		if (sigaction(sig->signo, &sa, NULL) == -1) {
			return jhd_false;
		}
	}

	return jhd_true;
}
