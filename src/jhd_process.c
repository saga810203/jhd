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

pid_t jhd_pid;
pid_t jhd_parent;

jhd_listener_t jhd_pid_file_listener;
int process_count;
uint32_t jhd_process_slot;

jhd_process_t    jhd_processes[512];

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
	case JHD_PROCESS_SINGLE:
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
int jhd_signal_process(char *sig_name) {
	ssize_t n;
	pid_t pid;
	int pid_file_fd;
	u_char buf[64];
	int64_t ret;
	jhd_signal_t *sig;

	pid_file_fd = open(jhd_pid_file, O_RDONLY, 0);

	if (pid_file_fd < 0) {
		printf("open pid file[%s] error:%d", jhd_pid_file, errno);
		return 1;
	}

	n = read(pid_file_fd, buf, 64, 0);

	if (n == -1) {
		printf("read pid file[%s] error:%d", jhd_pid_file, errno);
		close(pid_file_fd);
		return 1;
	}
	close(pid_file_fd);

	while (n-- && (buf[n] == '\r' || buf[n] == '\n')) { /* void */
	}

	ret = jhd_chars_to_uint64(buf, ++n);
	if (ret < 0) {
		printf("invalid PID number in file[%s]", jhd_pid_file);
		return 1;
	}
	pid = ret;

	for (sig = signals; sig->signo != 0; sig++) {
		if (strcmp(sig_name, sig->name) == 0) {
			if (kill(pid, sig->signo) != -1) {
				return 0;
			}
			printf("kill(%P, %d) failed", pid, sig->signo);
		}
	}
	return 1;

}

jhd_bool jhd_daemon() {
	int fd;

	switch (fork()) {
	case -1:
		printf("fork() failed");
		return jhd_false;
	case 0:
		break;

	default:
		exit(0);
	}

	jhd_pid = getpid();

	if (setsid() == -1) {
		//TODO:log
		return jhd_false;
	}

	umask(0);

	fd = open("/dev/null", O_RDWR);
	if (fd == -1) {
		//TODO:log
		return jhd_false;
	}

	if (dup2(fd, STDIN_FILENO) == -1) {

		//  ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDIN) failed");

		//TODO:log
		return jhd_false;;
	}

	if (dup2(fd, STDOUT_FILENO) == -1) {

		//ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDOUT) failed");
		//TODO:log
		return jhd_false;
	}
	if (dup2(fd, STDERR_FILENO) == -1) {

		//ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDOUT) failed");
		//TODO:log
		return jhd_false;
	}

	return jhd_true;
}

static void jhd_delete_pidfile(jhd_listener_t *lis){
	 unlink((const char *) jhd_pid_file);
}

jhd_bool jhd_create_pidfile() {
	size_t len;
	int fd;
	u_char pid[64];

	fd = ngx_open_file(jhd_pid_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		//TODO:log
		return jhd_false;
	}

	sprintf(&pid[0], "%d", jhd_pid);
	len = strlen(&pid[0]);
	if (pwrite(fd, pid, len, 0) == -1) {
		//TODO:log
		close(fd);
		return jhd_false;
	}
	close(fd);
	jhd_pid_file_listener.data = NULL;
	jhd_pid_file_listener.handler = jhd_delete_pidfile;
	jhd_add_master_shutdown_listener(&jhd_pid_file_listener);
	return jhd_true;
}

void jhd_delete_pidfile(){
	 unlink((const char *) jhd_pid_file);
}
void jhd_single_process(){
	if(jhd_run_worker_startup_listener()!=JHD_OK){
		jhd_err = 1;
		return;
	}

	while(!jhd_quit){
		jhd_process_events_and_timers();

	}

	jhd_run_worker_shutdown_listener();


}

static void jhd_worker_process(void *data){

}


static void jhd_process_listener_handler(jhd_listener_t *lis){
	jhd_process_t *p = lis->data;
	if(p->channel[0]!=-1){
		close(p->channel[0]);
	}
	if(p->channel[1]!=-1){
		close(p->channel[1]);
	}

}

jhd_bool jhd_spawn_process(jhd_spawn_proc_pt proc, void *data)
{

    pid_t  pid;
    uint32_t  p_slot;
    jhd_listener_t  *lis;
    int nb;
    nb =1;
    p_slot =(uint32_t)data;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, jhd_processes[p_slot].channel) == -1)
        {
          //TODO:LOG
        	return jhd_false;
        }
        lis = &&jhd_processes[p_slot].listener;
        lis->data = &jhd_processes[p_slot];
        lis->handler = jhd_process_listener_handler;
        jhd_add_master_startup_listener(lis);


        if (ioctl(jhd_processes[p_slot].channel[0], FIONBIO, &nb)== -1) {
        	//TODO:LOG
            return jhd_false;
        }
        if (ioctl(jhd_processes[p_slot].channel[1], FIONBIO, &nb)== -1) {
        	//TODO:LOG
            return jhd_false;
        }
        if (ioctl(jhd_processes[p_slot].channel[0], FIOASYNC, &nb)== -1) {
            return jhd_false;
        }

        if (fcntl(jhd_processes[p_slot].channel[0], F_SETOWN, jhd_pid) == -1) {
           return jhd_false;
        }

        if (fcntl(jhd_processes[p_slot].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
           return jhd_false;
        }

        if (fcntl(jhd_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            return jhd_false;
        }


    jhd_process_slot = p_slot;


    pid = fork();

    switch (pid) {

    case -1:
        return jhd_false;

    case 0:
        jhd_parent = jhd_pid;
        jhd_pid = ngx_getpid();
        proc(data);
        break;

    default:
        break;
    }



    jhd_processes[p_slot].pid = pid;
    jhd_processes[p_slot].exited = 0;



    jhd_processes[p_slot].proc = proc;
    jhd_processes[p_slot].data = data;


  return jhd_true;
}

jhd_bool jhd_start_worker_processes(){
	uint32_t i;
		jhd_channel_t ch;
		memset(&ch, 0,sizeof(jhd_channel_t));

		ch.command = JHD_CMD_OPEN_CHANNEL;

		for (i = 0; i < process_count; i++) {

			if(!jhd_spawn_process(jhd_worker_process,(void *) (intptr_t) i)){
				return jhd_false;
			}

			ch.pid = jhd_processes[jhd_process_slot].pid;
			ch.slot = jhd_process_slot;
			ch.fd = jhd_processes[jhd_process_slot].channel[0];

			jhd_pass_open_channel( &ch);
		}

		return jhd_true;

}

void jhd_master_process(){
	uint64_t n, sigio;
	sigset_t set;
	struct itimerval itv;
		sigemptyset(&set);
		sigaddset(&set, SIGCHLD);
		sigaddset(&set, SIGALRM);
		sigaddset(&set, SIGIO);
		sigaddset(&set, SIGINT);
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

		process_count = getnprocs();
		//TODO LOG
		if(!jhd_start_worker_processes(){
			return;
		}

		//TODO next



}

