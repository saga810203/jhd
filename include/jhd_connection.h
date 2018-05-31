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

typedef struct jhd_connection_s jhd_connection_t;

typedef struct jhd_listening_s  jhd_listening_t;


typedef ssize_t (*jhd_connection_recv_pt)(jhd_connection_t *c, u_char *buf, size_t size);

typedef ssize_t (*jhd_connection_send_pt)(jhd_connection_t *c, u_char *buf, size_t size);
typedef ssize_t (*jhd_connection_close_pt)(jhd_connection_t *c);


struct jhd_listening_s{
		int					fd;

		void   				*sockaddr;
		socklen_t           socklen;

		u_char* 			addr_text;
		size_t  			addr_text_len;
	    int                 backlog;
	    int                 rcvbuf;
	    int                 sndbuf;


	    jhd_connection_t	*connection;

	    jhd_bool			ssl;
	    jhd_bool			ipv6only;
	    jhd_bool			bind;

	    jhd_queue_t			*queue;


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

    void    			*sockaddr;
    socklen_t           socklen;

    jhd_queue_t         queue;

    size_t   			idx;
};




void  jhd_connection_init();

jhd_connection_t*  getconnection();
void  free_connection(jhd_connection_t *c);


jhd_bool  jhd_open_listening_sockets();






extern jhd_connection_t *g_connections;
extern uint32_t connection_count;
extern uint32_t free_connection_count;

#endif /* JHD_CONNECTION_H_ */
