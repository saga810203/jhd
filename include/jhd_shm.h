/*
 * jhd_shm.h
 *
 *  Created on: May 30, 2018
 *      Author: root
 */

#ifndef JHD_SHM_H_
#define JHD_SHM_H_


#include <jhd_config.h>
#include <jhd_event.h>
#include <jhd_core.h>

typedef struct jhd_shm_s   jhd_shm_t;



struct jhd_shm_s {
    u_char      *addr;
    size_t       size;
    jhd_queue_t queue;
} ;



void jhd_request_shm(jhd_shm_t* shm);

void jhd_free_shm();

#endif /* JHD_SHM_H_ */
