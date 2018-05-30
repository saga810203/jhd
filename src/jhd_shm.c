/*
 * jhd_shm.c
 *
 *  Created on: May 30, 2018
 *      Author: root
 */


#include <jhd_config.h>
#include <jhd_event.h>
#include <jhd_core.h>
#include <jhd_shm.h>




static jhd_queue_t g_shm_queue ={NULL,NULL};

void jhd_request_shm(jhd_shm_t* shm){
	jhd_queue_t * queue;

	queue= &g_shm_queue;

	if(queue->next == NULL){
		jhd_queue_init(queue);
	}

    shm->addr = (u_char *) mmap(NULL, shm->size,PROT_READ|PROT_WRITE,
	                                MAP_ANON|MAP_SHARED, -1, 0);

	    if (shm->addr == MAP_FAILED) {
	       //TODO:LOG;
	    	shm->addr = NULL;
	    }else{
	    	jhd_queue_insert_tail(queue,&shm->queue);
	    }
	}




void jhd_free_shm(){
	jhd_queue_t * queue;

		queue= &g_shm_queue;

		if(queue->next == NULL){
			jhd_queue_init(queue);
		}

		while(!(jhd_queue_empty(queue))){
			jhd_shm_t* shm = jhd_queue_data(jhd_queue_head(queue),jhd_shm_t,queue);
			jhd_queue_remove(&shm->queue);
			munmap((void *) shm->addr, shm->size);
		}

}

