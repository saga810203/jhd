/*
 * jhd_aio.h
 *
 *  Created on: Nov 23, 2018
 *      Author: root
 */

#ifndef JHD_AIO_H_
#define JHD_AIO_H_
#include <jhd_config.h>
#include <jhd_log.h>
#include <jhd_event.h>
#include <linux/aio_abi.h>
#include <bits/syscall.h>




typedef struct {
	struct iocb  aio;
	int64_t      result;
}jhd_aio_cb;

extern jhd_aio_cb *jhd_free_iocbs;
extern jhd_queue_t waitting_iocb_queue;




int jhd_aio_setup();



static jhd_inline void* jhd_aio_get() {
	jhd_aio_cb *ret,**ppiocb;
	ret = jhd_free_iocbs;
	if(ret) {
		ppiocb = (jhd_aio_cb **)(ret);
		jhd_free_iocbs = *ppiocb;
	}
	return ret;
}
static jhd_inline void jhd_aio_free(void* ic){
	jhd_event_t *ev;
	jhd_queue_t *q;
	*((jhd_aio_cb **)ic) = jhd_free_iocbs;
	jhd_free_iocbs = ((jhd_aio_cb *)ic);
	q = waitting_iocb_queue.next;

	if(q != &waitting_iocb_queue){
		jhd_queue_remove(q);
		ev = jhd_queue_data(q,jhd_event_t,queue);
		ev->handler(ev);
	}
}

static jhd_inline void jhd_aio_wait(jhd_event_t *ev) {
	jhd_queue_insert_tail(&waitting_iocb_queue,&ev->queue);
}

void jhd_aio_read(jhd_event_t *ev,void*ic,int fd,u_char *buf, size_t size, off_t offset);
void jhd_aio_write(jhd_event_t *ev,void*ic,int fd,u_char *buf, size_t size, off_t offset);


void jhd_aio_destroy();

#endif /* JHD_AIO_H_ */
