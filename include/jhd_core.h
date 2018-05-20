/*
 * jhd_core.h
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#ifndef JHD_CORE_H_
#define JHD_CORE_H_

#define NULL ((void*)0)

#define JHD_OK 0
#define JHD_ERROR (-1)

//#define  JHD_BUSY       (-3)
//#define  JHD_DONE       -4
//#define  NGX_DECLINED   -5
//#define  NGX_ABORT      -6

#define jhd_bool int
#define jhd_true 1
#define jhd_false 0

typedef void* jhd_string;





#include <jhd_config.h>
#include <jhd_queue.h>
#include <jhd_pool.h>
#include <jhd_string.h>
#include <jhd_log.h>
#include <jhd_time.h>
#include <jhd_rbtree.h>





#define JHD_OK			0
#define JHD_ERROR		-1
#define JHD_AGAIN		-2

#endif /* JHD_CORE_H_ */
