/*
 * jhd_core.c
 *
 *  Created on: May 22, 2018
 *      Author: root
 */

#include <jhd_config.h>
#include <jhd_core.h>
#include <jhd_event.h>
#include <jhd_queue.h>
#include <jhd_time.h>
#include <jhd_connection.h>

uint32_t jhd_core_master_startup_time;


 sig_atomic_t jhd_process;
 sig_atomic_t jhd_quit;
 sig_atomic_t jhd_reap;
 sig_atomic_t jhd_restart;
 sig_atomic_t jhd_daemonized;

u_char jhd_pid_file[1024];

 jhd_queue_t jhd_master_startup_queue;
 jhd_queue_t jhd_master_shutdown_queue;

 jhd_queue_t jhd_worker_startup_queue;
 jhd_queue_t jhd_worker_shutdown_queue;

void jhd_core_init() {
	jhd_quit = 0;
	jhd_restart = 0;
	jhd_reap = 0;
	jhd_daemonized = 0;
	jhd_queue_init(&jhd_master_startup_queue);
	jhd_queue_init(&jhd_master_shutdown_queue);

	jhd_queue_init(&jhd_worker_startup_queue);
	jhd_queue_init(&jhd_worker_shutdown_queue);
	jhd_core_master_startup_time = 1000 * 60;
	strcpy((char*)jhd_pid_file , "/run/jhttpd.pid");
}


int jhd_run_master_startup_listener() {
	uint64_t begin_time;

	jhd_listener_t *lis;
	jhd_queue_t *q;
	int ret;

	jhd_update_time();

	jhd_connection_init();
	jhd_event_init();

	begin_time = jhd_current_msec;
	while (jhd_queue_head(&jhd_master_startup_queue)) {
		q = jhd_queue_head(&jhd_master_startup_queue);
		jhd_queue_only_remove(q);
		lis = jhd_queue_data(q, jhd_listener_t, queue);
		ret = lis->handler(lis);
		if (ret == JHD_AGAIN) {
			jhd_queue_insert_tail(&jhd_master_startup_queue, q);
		} else if (ret == JHD_ERROR) {
			return JHD_ERROR;
		}
		if ((jhd_core_master_startup_time > 0)) {
			jhd_update_time();
			if ((jhd_current_msec - begin_time) > jhd_core_master_startup_time) {
				return JHD_ERROR;
			}
		}
	}
	return JHD_OK;
}
int jhd_run_worker_startup_listener() {
	jhd_listener_t *lis;
	jhd_queue_t *q;
	int ret;
	while (jhd_queue_head(&jhd_worker_startup_queue)) {
		q = jhd_queue_head(&jhd_worker_startup_queue);
		jhd_queue_only_remove(q);
		lis = jhd_queue_data(q, jhd_listener_t, queue);
		ret = lis->handler(lis);
		if (ret == JHD_AGAIN) {
			jhd_queue_insert_tail(&jhd_master_startup_queue, q);
		} else if (ret == JHD_ERROR) {
			return JHD_ERROR;
		}
	}
	return JHD_OK;

}
void jhd_run_master_shutdown_listener() {
	jhd_listener_t *lis;
	jhd_queue_t *q;
	int ret;
	while (jhd_queue_head(&jhd_master_shutdown_queue)) {
		q = jhd_queue_head(&jhd_master_shutdown_queue);
		jhd_queue_only_remove(q);
		lis = jhd_queue_data(q, jhd_listener_t, queue);
		ret = lis->handler(lis);
		if (ret == JHD_AGAIN) {
			jhd_queue_insert_tail(&jhd_master_startup_queue, q);
		}
	}
}
void jhd_run_worker_shutdown_listener() {
	jhd_listener_t *lis;
	jhd_queue_t *q;
	int ret;
	while (jhd_queue_head(&jhd_worker_shutdown_queue)) {
		q = jhd_queue_head(&jhd_worker_shutdown_queue);
		jhd_queue_only_remove(q);
		lis = jhd_queue_data(q, jhd_listener_t, queue);
		ret = lis->handler(lis);
		if (ret == JHD_AGAIN) {
			jhd_queue_insert_tail(&jhd_master_startup_queue, q);
		}
	}
}
