/*
 * jhd_connection.h
 *
 *  Created on: May 25, 2018
 *      Author: root
 */

#ifndef JHD_CONNECTION_H_
#define JHD_CONNECTION_H_


#include<jhd_config.h>
#include<jhd_queue.h>
#include<jhd_event.h>
#include<jhd_ssl.h>

typedef struct jhd_connection_s jhd_connection_t;

typedef struct jhd_listening_s  jhd_listening_t;

typedef union {
    struct sockaddr           sockaddr;
    struct sockaddr_in        sockaddr_in;

    struct sockaddr_in6       sockaddr_in6;
    struct sockaddr_un        sockaddr_un;
} jhd_sockaddr_t;


typedef ssize_t (*jhd_connection_recv_pt)(jhd_connection_t *c, u_char *buf, size_t size);

typedef ssize_t (*jhd_connection_send_pt)(jhd_connection_t *c, u_char *buf, size_t size);
typedef void (*jhd_connection_close_pt)(jhd_connection_t *c);


struct jhd_listening_s{
		int					fd;

		jhd_sockaddr_t		sockaddr;
		socklen_t           socklen;

		u_char* 			addr_text;
		size_t  			addr_text_len;
	    int                 backlog;
	    int                 rcvbuf;
	    int                 sndbuf;


	    jhd_connection_t	*connection;

	    jhd_ssl_srv_t		*ssl;
	    jhd_bool			ipv6only;
	    jhd_bool			bind;

	    jhd_queue_t			queue;

	    uint32_t			http_server_count;
	    void				**http_servers;


};



struct jhd_connection_s {
    void               *data;
    jhd_event_t        read;
    jhd_event_t        write;
    int        fd;

    jhd_connection_recv_pt         recv;
    jhd_connection_send_pt         send;
    jhd_connection_close_pt		   close;

    jhd_listening_t    *listening;

	jhd_sockaddr_t		sockaddr;
	socklen_t           socklen;

    void				*ssl;



    size_t   			idx;
};





void  jhd_connection_init();

jhd_connection_t*  getconnection();
void  free_connection(jhd_connection_t *c);


//jhd_bool  jhd_open_listening_sockets();

jhd_listening_t* jhd_listening_get(u_char *addr_text,size_t len);
jhd_bool jhd_listening_add_server(jhd_listening_t *lis,void *http_server);


void jhd_connection_accept(jhd_event_t *ev);

ssize_t jhd_connection_recv(jhd_connection_t *c, u_char *buf, size_t size);

ssize_t jhd_connection_ssl_recv(jhd_connection_t *c, u_char *buf, size_t size);

ssize_t jhd_connection_send(jhd_connection_t *c, u_char *buf, size_t size);

ssize_t jhd_connection_ssl_send(jhd_connection_t *c, u_char *buf, size_t size);

void jhd_connection_close(jhd_connection_t *c);


extern jhd_connection_t *g_connections;
extern uint32_t connection_count;
extern uint32_t free_connection_count;

#endif /* JHD_CONNECTION_H_ */
