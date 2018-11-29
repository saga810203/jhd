/*
 * jhd_process.c
 *
 *  Created on: Jun 1, 2018
 *      Author: root
 */

#include <jhd_config.h>
#include <jhd_process.h>
#include <jhd_core.h>
#include <jhd_string.h>
#include <sys/sysinfo.h>

pid_t jhd_pid;
pid_t jhd_parent;

jhd_listener_t jhd_pid_file_listener;
size_t process_count;
volatile uint32_t jhd_process_slot;

static int jhd_process_last;

pid_t *jhd_processes;

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

static void jhd_process_get_status(void) {
	int status;
	pid_t pid;
	uint32_t i;
	uint32_t one;

	one = 0;

	for (;;) {
		pid = waitpid(-1, &status, WNOHANG);

		if (pid == 0) {
			return;
		}

		if (pid == -1) {
			if (errno == EINTR) {
				continue;
			}

			if (errno == ECHILD && one) {
				return;
			}
			if (errno == ECHILD) {
//                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, err,"waitpid() failed");
				return;
			}

//            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,   "waitpid() failed");
			return;
		}

		one = 1;

		for (i = 0; i < process_count; ++i) {
			if (jhd_processes[i] == pid) {
				jhd_processes[i] = (-1);
				break;
			}
		}
	}
}

static void jhd_signal_handler(int signo, siginfo_t *siginfo, void *ucontext) {
	jhd_signal_t *sig;

	for (sig = signals; sig->signo != 0; sig++) {
		if (sig->signo == signo) {
			break;
		}
	}
	if (jhd_process == JHD_PROCESS_MASTER) {
		switch (signo) {
			case SIGQUIT:
			case SIGTERM:
			case SIGINT:
				jhd_quit = 1;
				break;
			case SIGWINCH:
				break;
			case SIGHUP:
				jhd_restart = 1;
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
				jhd_reap = 1;
				break;
		}
	} else {
		if (signo == SIGQUIT || signo == SIGTERM || signo == SIGINT) {
			jhd_quit = 1;
			//    		 action = "shutting down";
		}
	}

}

jhd_bool jhd_init_signals() {
	jhd_signal_t *sig;
	struct sigaction sa;

	for (sig = signals; sig->signo != 0; sig++) {
		memset(&sa,0,sizeof(struct sigaction));
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
int jhd_signal_process(char *sig_name) {
	ssize_t n;
	pid_t pid;
	int pid_file_fd;
	u_char buf[64];
	uint64_t read_pid;
	jhd_signal_t *sig;

	log_assert_helper();

	pid_file_fd = open(jhd_pid_file, O_RDONLY, 0);

	if (pid_file_fd < 0) {
		printf("open pid file[%s] error:%d", jhd_pid_file, errno);
		return 1;
	}

	n = read(pid_file_fd, buf, 64);

	if (n == -1) {
		printf("read pid file[%s] error:%d", jhd_pid_file, errno);
		jhd_close(pid_file_fd);
		return 1;
	}
	jhd_close(pid_file_fd);

	while (n-- && (buf[n] == '\r' || buf[n] == '\n')) { /* void */
	}

	if(JHD_OK != jhd_chars_to_u64(buf, ++n,&read_pid)){
		printf("invalid PID number in file[%s]", jhd_pid_file);
		return 1;
	}
	pid = (int)read_pid;

	for (sig = signals; sig->signo != 0; sig++) {
		if (strcmp(sig_name, sig->name) == 0) {
			if (kill(pid, sig->signo) != -1) {
				return 0;
			}
			printf("kill(%d, %d) failed", pid, sig->signo);
		}
	}
	return 1;

}

jhd_bool jhd_daemon() {
	int fd;
	switch (fork()) {
		case -1:
			log_stderr("systemcall fork() ==  -1");
			return jhd_false;
		case 0:
			break;
		default:
			exit(0);
	}
	jhd_pid = getpid();
	if (setsid() == -1) {
		log_stderr("systemcall setsid() ==-1");
		return jhd_false;
	}
	umask(0);
	fd = open("/dev/null", O_RDWR);
	if (fd == -1) {
		log_stderr("systemcall open(\"/dev/null\",...)  error");
		return jhd_false;
	}
	if (dup2(fd, STDIN_FILENO) == -1) {
		log_stderr("systemcall  dup2(,STDIN_FILENO) == -1");
		return jhd_false;;
	}

	if (dup2(fd, STDOUT_FILENO) == -1) {
		log_stderr("systemcall  dup2(,STDOUT_FILENO) == -1");
		return jhd_false;;
	}
	if (dup2(fd, STDERR_FILENO) == -1) {
		log_stderr("systemcall  dup2(,STDERR_FILENO) == -1");
		return jhd_false;;
	}
	return jhd_true;
}

static int jhd_delete_pidfile(jhd_listener_t *lis) {
	unlink((const char *) jhd_pid_file);
	return JHD_OK;
}

jhd_bool jhd_create_pidfile() {
	size_t len;
	int fd;
	char pid[64];

	fd = open(jhd_pid_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		//TODO:log
		return jhd_false;
	}

	sprintf(pid,"%d",jhd_pid);
	len = strlen(pid);
	if (pwrite(fd, pid, len, 0) == -1) {
		//TODO:log
		jhd_close(fd);
		return jhd_false;
	}
	jhd_close(fd);
	jhd_pid_file_listener.data = NULL;
	jhd_pid_file_listener.handler = jhd_delete_pidfile;
	jhd_add_master_shutdown_listener(&jhd_pid_file_listener);
	return jhd_true;
}
void jhd_single_process() {
	if (jhd_run_worker_startup_listener() != JHD_OK) {
		jhd_err = 1;
		return;
	}
	while (!jhd_quit) {
		jhd_process_events_and_timers();
	}
	jhd_run_worker_shutdown_listener();
}

jhd_bool jhd_worker_init(){
	if(jhd_run_worker_startup_listener()!=JHD_OK){
		return jhd_false;
	}
	return jhd_true;
}

static void jhd_worker_process() {
	jhd_process = JHD_PROCESS_WORKER;
	jhd_log_swtich_file();
	jhd_pool_init();
	if(!jhd_worker_init()){
		jhd_run_worker_shutdown_listener();
		return;

	}

	for(;;){
		jhd_process_events_and_timers();
		if(jhd_quit){
			break;
		}
	}
	jhd_run_worker_shutdown_listener();
}

jhd_bool jhd_spawn_process(uint32_t idx) {
	pid_t pid;
	jhd_process_slot = idx;
	pid = fork();
	switch (pid) {
		case -1:
			return jhd_false;
		case 0:
			jhd_parent = jhd_pid;
			jhd_pid = getpid();
			jhd_worker_process();
			break;
		default:
			jhd_processes[idx] = pid;
			break;
	}
	return jhd_true;
}

jhd_bool jhd_start_worker_processes() {
	uint32_t i;

	jhd_process_last = -1;

	for (i = 0; i < process_count; i++) {
		if (!jhd_spawn_process(i)) {
			jhd_err = 1;
			jhd_quit = 1;
			return jhd_false;
		}
		++jhd_process_last;
	}
	return jhd_true;
}

void jhd_master_wait(sigset_t *set) {
	uint32_t i;
	uint32_t pc;
	if (jhd_process_last < 0) {
		return;
	}
	for (;;) {
		pc = 0;
		for (i = 0; i < process_count; ++i) {
			if (jhd_processes[i] != (-1)) {
				sigsuspend(set);
				if (jhd_reap) {
					jhd_reap = 0;
					jhd_process_get_status();
				}
				break;
			}
			++pc;
		}
		if (pc == process_count) {
			break;
		}
	}
}

void jhd_master_process() {
//	uint64_t sigio;
	sigset_t set;
//	struct itimerval itv;
	uint32_t i;

	jhd_process = JHD_PROCESS_MASTER;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigaddset(&set, SIGALRM);
	sigaddset(&set, SIGIO);
//	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGWINCH);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGUSR2);

	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
		//TODO:LOG
	}

	sigemptyset(&set);

	process_count = get_nprocs();

	jhd_processes = malloc(sizeof(pid_t) * process_count);
	if (jhd_processes == NULL) {
		//TODO: LOG;
		jhd_err = 1;
		return;
	}
	for (i = 0; i < process_count; ++i) {
		jhd_processes[i] = (-1);
	}

//TODO LOG
	if (!jhd_start_worker_processes()) {
		jhd_master_wait(&set);
		return;
	}


	if(jhd_process == JHD_PROCESS_MASTER){
		for(;;){
			sigsuspend(&set);

			if(jhd_reap){
				jhd_reap = 0;


				jhd_process_get_status();

				for(i = 0 ;i < process_count ; ++i){
					if(jhd_processes[i] == (-1)){
						if(!jhd_spawn_process(i)){
							jhd_reap = 1;
							alarm(1);
							break;
						}
						if(jhd_process != JHD_PROCESS_MASTER){
							return;
						}
					}
				}
			}
			if(jhd_quit){
				for(i = 0 ;i < process_count;++i){
					if(jhd_processes[i] != (-1)){
						kill(jhd_processes[i],SIGINT);
					}
				}
				jhd_master_wait(&set);
				return;
			}
			if(jhd_restart){
				for(i = 0 ;i < process_count;++i){
						if(jhd_processes[i] != (-1)){
							kill(jhd_processes[i],SIGINT);
						}
				}
				jhd_master_wait(&set);
//TODO:



			}









		}



	}



}

