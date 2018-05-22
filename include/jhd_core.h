/*
 * jhd_core.h
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#ifndef JHD_CORE_H_
#define JHD_CORE_H_








typedef void* jhd_string;





#include <jhd_config.h>
#include <jhd_queue.h>
#include <jhd_pool.h>
#include <jhd_string.h>
#include <jhd_log.h>
#include <jhd_time.h>
#include <jhd_rbtree.h>








void jhd_add_master_startup_listener(jhd_listener_t   *lis);
void jhd_add_worker_startup_listener(jhd_listener_t   *lis);
void jhd_add_master_shutdown_listener(jhd_listener_t   *lis);
void jhd_add_worker_shutdown_listener(jhd_listener_t   *lis);








#endif /* JHD_CORE_H_ */
