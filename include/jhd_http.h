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
//#include <jhd_string.h>
#include <jhd_connection.h>



typedef struct jhd_http_request_s  jhd_http_request_t;
typedef struct jhd_http_service_s  jhd_http_service_t;
typedef struct jhd_http_server_s	jhd_http_server_t;

typedef struct jhd_http1_connection_s jhd_h1c_t;
typedef struct jhd_http2_connection_s jhd_h2c_t;

typedef jhd_bool (*jhd_http_service_match_pt)(jhd_http_request_t *r,void* service_config_data);
typedef jhd_bool (*jhd_http_service_handler_pt)(jhd_http_request_t *r,void* service_config_data);


struct jhd_http_service_s{
		void							*config_data;
		jhd_http_service_match_pt		match;
		jhd_http_service_handler_pt		handler;
		jhd_queue_t						in_server;
};


struct jhd_http_server_s{
		jhd_queue_t			queue;
		jhd_queue_t			services;
		uint32_t			servername_count;
		u_char				**servernames;
		uint32_t			listening_count;
		jhd_listening_t		**listenings;


};

struct jhd_http1_connection_s{
		jhd_connection_t 						*c;
		jhd_connection_close_pt					c_close_pt;


};
struct jhd_http2_connection_s{
		jhd_connection_t 						*c;
		jhd_connection_close_pt					c_close_pt;



};



jhd_http_server_t*   jhd_http_find_server_by_host_name(jhd_connection_t *c,u_char* servername,size_t servername_len);
jhd_bool jhd_http_server_servername_add(jhd_http_server_t *srv,u_char *name,size_t len);
jhd_bool jhd_http_server_listening_add(jhd_http_server_t *srv,u_char *addr_text,size_t len);

void  jhd_http_server_free(jhd_http_server_t *s);
jhd_bool jhd_http_server_add(jhd_http_server_t *);



void jhd_http_init_connection(jhd_connection_t *c);



void jhd_http_empty_handler(jhd_event_t *ev);
void jhd_http_h1_wait_request_handler(jhd_event_t *rev);


void jhd_http_h1_close_connection(jhd_connection_t *c);




void jhd_http_init();

void jhd_http_free();



#endif /* JHD_HTTP_H_ */
