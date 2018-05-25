/*
 * jhd_http.h
 *
 *  Created on: May 25, 2018
 *      Author: root
 */

#ifndef JHD_HTTP_H_
#define JHD_HTTP_H_

#include <jhd_config.h>
#include <jhd_queue.h>
#include <jhd_string.h>


typedef struct jhd_http_request_s  jhd_http_request_t;
typedef struct jhd_http_service_s  jhd_http_service_t;
typedef struct jhd_http_server_s	jhd_http_server_t;

typedef jhd_bool (*jhd_http_service_match_pt)(jhd_http_request_t *r,void* service_config_data);
typedef jhd_bool (*jhd_http_service_handler_pt)(jhd_http_request_t *r,void* service_config_data);


struct jhd_http_service_s{
		void							*config_data;
		jhd_http_service_match_pt		match;
		jhd_http_service_handler_pt		handler;
		jhd_queue_t						in_server;

};


struct jhd_http_server_s{
		u_char			*name;
		size_t			name_len;
		jhd_queue_t		services;
		jhd_queue_t		in_listening;
};


struct jhd_http_listening_s{



}




#endif /* JHD_HTTP_H_ */
