/*
 * jhd_time.h
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#ifndef JHD_TIME_H_
#define JHD_TIME_H_

#include <jhd_config.h>

#define JHD_CACHE_LOG_TIME_LEN 		19
#define JHD_CACHE_HTTP_DATE_LEN 	29

typedef struct tm             jht_tm_t;


void jhd_update_time();



extern u_char* 			jhd_cache_log_time;
extern u_char* 			jhd_cache_http_date;
extern uint64_t      	jhd_current_msec;






#endif /* JHD_TIME_H_ */
