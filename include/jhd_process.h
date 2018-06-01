/*
 * jhd_process.h
 *
 *  Created on: Jun 1, 2018
 *      Author: root
 */

#ifndef JHD_PROCESS_H_
#define JHD_PROCESS_H_

#define jhd_signal_value(n)     SIG##n


typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo, siginfo_t *siginfo, void *ucontext);
} jhd_signal_t;







#endif /* JHD_PROCESS_H_ */
