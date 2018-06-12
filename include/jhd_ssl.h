/*
 * jhd_ssl.h
 *
 *  Created on: May 25, 2018
 *      Author: root
 */

#ifndef JHD_SSL_H_
#define JHD_SSL_H_

#include <jhd_config.h>


#define JHD_SSL_SSLv2    0x0002
#define JHD_SSL_SSLv3    0x0004
#define JHD_SSL_TLSv1    0x0008
#define JHD_SSL_TLSv1_1  0x0010
#define JHD_SSL_TLSv1_2  0x0020
#define JHD_SSL_TLSv1_3  0x0040



#define jhd_ssl_get_connection(ssl_conn)  SSL_get_ex_data(ssl_conn, jhd_ssl_connection_index)


typedef struct jhd_ssl_srv_s  jhd_ssl_srv_t;
typedef struct jhd_ssl_srv_session_s jhd_ssl_srv_session_t;


struct jhd_ssl_srv_s{
		    jhd_queue_t 	queue;
		   	SSL_CTX         *ctx;
		    size_t          buffer_size;
		    u_char			*name;
		    u_char			*certificate;
		    u_char			*certificate_key;
		    ssize_t			timeout;
		    u_char			*ciphers;
		    uint64_t		protocols;
};
struct jhd_ssl_srv_session_s{
	SSL_CTX					*session_ctx;
	SSL						*session;



    unsigned                    handshaked:1;
    unsigned                    renegotiation:1;
    unsigned                    buffer:1;
    unsigned                    no_wait_shutdown:1;
    unsigned                    no_send_shutdown:1;
    unsigned                    handshake_buffer_set:1;

};




	jhd_bool jhd_ssl_init();

	void jhd_ssl_free();


	jhd_ssl_srv_t*  jhd_ssl_srv_get(u_char* name);
	u_char*		jhd_ssl_srv_add(jhd_ssl_srv_t *srv_ssl);










extern	int  jhd_ssl_connection_index;
extern	int  jhd_ssl_server_conf_index;
extern	int  jhd_ssl_session_cache_index;
extern	int  jhd_ssl_session_ticket_keys_index;
extern	int  jhd_ssl_certificate_index;
extern	int  jhd_ssl_next_certificate_index;
extern	int  jhd_ssl_certificate_name_index;
extern	int  jhd_ssl_stapling_index;

#endif /* JHD_SSL_H_ */
