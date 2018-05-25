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

static jhd_queue_t jhd_master_startup_queue;
static jhd_queue_t jhd_master_shutdown_queue;

static jhd_queue_t jhd_worker_startup_queue;
static jhd_queue_t jhd_worker_shutdown_queue;

void jhd_init_core() {
	jhd_queue_init(&jhd_master_startup_queue);
	jhd_queue_init(&jhd_master_shutdown_queue);

	jhd_queue_init(&jhd_worker_startup_queue);
	jhd_queue_init(&jhd_worker_shutdown_queue);

}
void jhd_add_master_startup_listener(jhd_listener_t *lis) {
	jhd_queue_insert_tail(&jhd_master_startup_queue, &lis->queue);
}
void jhd_add_worker_startup_listener(jhd_listener_t *lis) {
	jhd_queue_insert_tail(&jhd_worker_startup_queue, &lis->queue);
}
void jhd_add_master_shutdown_listener(jhd_listener_t *lis) {
	jhd_queue_insert_tail(&jhd_master_shutdown_queue, &lis->queue);
}
void jhd_add_worker_shutdown_listener(jhd_listener_t *lis) {
	jhd_queue_insert_tail(&jhd_worker_shutdown_queue, &lis->queue);
}

int jhd_run_master_startup_listener() {
	jhd_listener_t *lis;
	jhd_queue_t *q;
	int ret;
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
		lis =jhd_queue_data(q, jhd_listener_t, queue);
		ret = lis->handler(lis);
		if (ret == JHD_AGAIN) {
			jhd_queue_insert_tail(&jhd_master_startup_queue, q);
		} else if (ret == JHD_ERROR) {
			return JHD_ERROR;
		}
	}
	return JHD_OK;

}
void jhd_run_master_shutdown_listener(){
	jhd_listener_t *lis;
	jhd_queue_t *q;
	int ret;
	while (jhd_queue_head(&jhd_master_shutdown_queue)) {
		q = jhd_queue_head(&jhd_master_shutdown_queue);
		jhd_queue_only_remove(q);
		lis =jhd_queue_data(q, jhd_listener_t, queue);
		ret = lis->handler(lis);
		if (ret == JHD_AGAIN) {
			jhd_queue_insert_tail(&jhd_master_startup_queue, q);
		}
	}
}
void jhd_run_worker_shutdown_listener(){
	jhd_listener_t *lis;
	jhd_queue_t *q;
	int ret;
	while (jhd_queue_head(&jhd_worker_shutdown_queue)) {
		q = jhd_queue_head(&jhd_worker_shutdown_queue);
		jhd_queue_only_remove(q);
		lis =jhd_queue_data(q, jhd_listener_t, queue);
		ret = lis->handler(lis);
		if (ret == JHD_AGAIN) {
			jhd_queue_insert_tail(&jhd_master_startup_queue, q);
		}
	}
}
