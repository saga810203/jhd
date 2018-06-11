/*
 * jhd_ssl.h
 *
 *  Created on: May 25, 2018
 *      Author: root
 */

#ifndef JHD_SSL_H_
#define JHD_SSL_H_

#include <jhd_config.h>

typedef struct jhd_ssl_srv_s  jhd_ssl_srv_t;


struct jhd_ssl_srv_s{
		    jhd_queue_t 	queue;
		   	SSL_CTX         *ctx;
		    size_t          buffer_size;
		    u_char			*name;
		    u_char			*certificates;
		    u_char			*certificate_keys;
		    ssize_t			timeout;
		    u_char			*ciphers;
};





	jhd_bool jhd_ssl_init();

	void jhd_ssl_free();


	jhd_ssl_srv_t*  jhd_ssl_srv_get(u_char* name);
	jhd_bool		jhd_ssl_srv_add(jhd_ssl_srv_t *srv_ssl);










extern	int  jhd_ssl_connection_index;
extern	int  jhd_ssl_server_conf_index;
extern	int  jhd_ssl_session_cache_index;
extern	int  jhd_ssl_session_ticket_keys_index;
extern	int  jhd_ssl_certificate_index;
extern	int  jhd_ssl_next_certificate_index;
extern	int  jhd_ssl_certificate_name_index;
extern	int  jhd_ssl_stapling_index;

#endif /* JHD_SSL_H_ */
