/*
 * jhd_core.h
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#ifndef JHD_CORE_H_
#define JHD_CORE_H_

#include <jhd_config.h>
#include <jhd_queue.h>
#include <jhd_pool.h>
#include <jhd_string.h>

#define JHD_CMD_OPEN_CHANNEL   1
#define JHD_CMD_CLOSE_CHANNEL  2
#define JHD_CMD_QUIT           3


#define JHD_PROCESS_MASTER     0
#define JHD_PROCESS_SINGLE     1
#define JHD_PROCESS_WORKER     2
#define JHD_PROCESS_HELPER     3

struct jhd_core_s {
	size_t max_connections;
	jhd_bool daemon;
	jhd_bool use_worker;

};

extern int jhd_core_master_startup_time;
extern int jhd_core_worker_startup_time;

extern int jhd_single;
extern int jhd_process;
extern sig_atomic_t jhd_quit;
extern sig_atomic_t jhd_restart;
extern sig_atomic_t jhd_daemonized;
extern sig_atomic_t jhd_reap;
extern u_char *jhd_pid_file;

void jhd_inline jhd_add_master_startup_listener(jhd_listener_t *lis) {
	jhd_queue_insert_tail(&jhd_master_startup_queue, &lis->queue);
}
void jhd_inline jhd_add_worker_startup_listener(jhd_listener_t *lis) {
	jhd_queue_insert_tail(&jhd_worker_startup_queue, &lis->queue);
}
void jhd_inline jhd_add_master_shutdown_listener(jhd_listener_t *lis) {
	jhd_queue_insert_tail(&jhd_master_shutdown_queue, &lis->queue);
}
void jhd_inline jhd_add_worker_shutdown_listener(jhd_listener_t *lis) {
	jhd_queue_insert_tail(&jhd_worker_shutdown_queue, &lis->queue);
}

int jhd_run_master_startup_listener();
int jhd_run_worker_startup_listener();
void jhd_run_master_shutdown_listener();
void jhd_run_worker_shutdown_listener();
void jhd_core_init();

#endif /* JHD_CORE_H_ */
