/*
 * jhd_connection.h
 *
 *  Created on: May 25, 2018
 *      Author: root
 */

#ifndef JHD_CONNECTION_H_
#define JHD_CONNECTION_H_

#include <jhd_config.h>
#include <jhd_queue.h>
#include <jhd_event.h>


typedef struct jhd_connection_s jhd_connection_t;

typedef struct jhd_listening_s jhd_listening_t;

typedef union {
	struct sockaddr sockaddr;
	struct sockaddr_in sockaddr_in;
	struct sockaddr_in6 sockaddr_in6;
} jhd_sockaddr_t;

typedef ssize_t (*jhd_connection_recv_pt)(jhd_connection_t *c, u_char *buf, size_t size);
typedef ssize_t (*jhd_connection_send_pt)(jhd_connection_t *c, u_char *buf, size_t size);
typedef void (*jhd_connection_close_pt)(jhd_connection_t *c);
typedef void (*jhd_connection_start_pt)(jhd_connection_t *c);

struct jhd_listening_s {
	int fd;
	jhd_sockaddr_t sockaddr;
	socklen_t socklen;
	char* addr_text;
	uint8_t addr_text_len;
	uint16_t backlog;
	uint16_t rcvbuf;
	uint16_t sndbuf;
	jhd_connection_t *connection;
	void *ssl;
	unsigned ipv6only:1;
	unsigned bind:1;
	jhd_queue_t queue;
	uint8_t http_server_count;
	void **http_servers;
	size_t accept_timeout;
	jhd_connection_start_pt connection_start;
};

struct jhd_connection_s {
    void *data;
	jhd_event_t read;
	jhd_event_t write;
	int fd;
	jhd_connection_recv_pt recv;
	jhd_connection_send_pt send;
	jhd_connection_close_pt close;
	jhd_listening_t *listening;
	jhd_sockaddr_t sockaddr;
	socklen_t socklen;
	void *ssl;
	int idx;
	unsigned shutdown_remote:1;
};

void jhd_connection_init();




void jhd_connection_empty_read(jhd_event_t *rv);
void jhd_connection_empty_write(jhd_event_t *wv);
void jhd_connection_empty_ssl_write(jhd_event_t *wv);

ssize_t jhd_connection_error_recv(jhd_connection_t *c,u_char *buf,size_t size);
ssize_t jhd_connection_error_send(jhd_connection_t *c,u_char *buf,size_t size);





//jhd_bool  jhd_open_listening_sockets();

jhd_listening_t* jhd_listening_get(char *addr_text, size_t len);
jhd_bool jhd_listening_add_server(jhd_listening_t *lis, void *http_server);

void jhd_connection_accept(jhd_event_t *ev);

ssize_t jhd_connection_recv(jhd_connection_t *c, u_char *buf, size_t size);

ssize_t jhd_connection_ssl_recv(jhd_connection_t *c, u_char *buf, size_t size);

ssize_t jhd_connection_send(jhd_connection_t *c, u_char *buf, size_t size);

ssize_t jhd_connection_ssl_send(jhd_connection_t *c, u_char *buf, size_t size);

void jhd_connection_close(jhd_connection_t *c);


extern int free_connection_count;
extern int listening_count;
extern jhd_connection_t *g_connections;

#endif /* JHD_CONNECTION_H_ */
