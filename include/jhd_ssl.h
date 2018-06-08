/*
 * jhd_ssl.h
 *
 *  Created on: May 25, 2018
 *      Author: root
 */

#ifndef JHD_SSL_H_
#define JHD_SSL_H_


	jhd_bool jhd_ssl_init();

	void jhd_ssl_free();



extern	int  jhd_ssl_connection_index;
extern	int  jhd_ssl_server_conf_index;
extern	int  jhd_ssl_session_cache_index;
extern	int  jhd_ssl_session_ticket_keys_index;
extern	int  jhd_ssl_certificate_index;
extern	int  jhd_ssl_next_certificate_index;
extern	int  jhd_ssl_certificate_name_index;
extern	int  jhd_ssl_stapling_index;

#endif /* JHD_SSL_H_ */
