/*
 * jhd_connection.h
 *
 *  Created on: May 25, 2018
 *      Author: root
 */

#ifndef JHD_CONNECTION_H_
#define JHD_CONNECTION_H_

#include <jhd_config.h>
#include <jhd_log.h>
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
	void *lis_ctx;
	void (*lis_ctx_close)(void *lis_ctx);
	void *lis_handler;
	uint32_t accept_timeout;
	uint32_t read_timeout;
	uint32_t write_timeout;
	uint32_t wait_mem_timeout;

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
	union{
	jhd_listening_t *listening;
	void *client_config;
	};
	jhd_sockaddr_t sockaddr;
	socklen_t socklen;
	void *ssl;
	int idx;
	unsigned shutdown_remote:1;

#ifdef JHD_LOG_ASSERT_ENABLE
	unsigned closed;
#endif

};

#define jhd_connection_free() ++free_connection_count;c->data = free_connections;free_connections = c



int jhd_connection_parse_sockaddr(jhd_sockaddr_t* addr,socklen_t *socklen,u_char *addr_text,size_t addr_text_len,uint16_t default_port);

void jhd_connection_init();




void jhd_connection_empty_read(jhd_event_t *rv);
void jhd_connection_empty_write(jhd_event_t *wv);

ssize_t jhd_connection_error_recv(jhd_connection_t *c,u_char *buf,size_t size);
ssize_t jhd_connection_error_send(jhd_connection_t *c,u_char *buf,size_t size);





//jhd_bool  jhd_open_listening_sockets();

jhd_listening_t* jhd_listening_get(char *addr_text, size_t len);

int jhd_listening_set_addr_text(jhd_listening_t *lis,u_char *addr_text,size_t addr_text_len,uint16_t default_port);

int jhd_listening_set_tls_cert_and_key(jhd_listening_t *lis,u_char *cert_text,size_t cert_text_len,u_char *key_text,size_t key_text_len);





int jhd_listening_config(jhd_listening_t *lis,void *lis_ctx,void (*lis_ctx_close)(void*),const char **alpn_list,jhd_connection_start_pt start_func);

void jhd_connection_accept(jhd_event_t *ev);



ssize_t jhd_connection_recv(jhd_connection_t *c, u_char *buf, size_t size);

ssize_t jhd_connection_tls_recv(jhd_connection_t *c, u_char *buf, size_t size);

ssize_t jhd_connection_send(jhd_connection_t *c, u_char *buf, size_t size);

ssize_t jhd_connection_tls_send(jhd_connection_t *c, u_char *buf, size_t size);
int jhd_connection_tls_handshark(jhd_connection_t *c);
void jhd_connection_tls_close(jhd_connection_t *c);
void jhd_connection_tls_empty_write(jhd_event_t * ev);

void jhd_connection_close(jhd_connection_t *c);

#define jhd_connection_close_by_only_read(CON) \
	log_assert((CON->write.handler == jhd_connection_empty_write) ||(CON->write.handler == jhd_connection_tls_empty_write) );\
    log_assert(CON->write.next == NULL);\
    log_assert(CON->read.next == NULL);\
    log_assert_code(CON->read.handler = NULL);\
	log_assert_code(CON->write.handler = NULL);\
	CON->close(CON);



extern int free_connection_count;
extern int listening_count;
extern jhd_connection_t *g_connections;

extern jhd_connection_t * event_c;

#endif /* JHD_CONNECTION_H_ */
