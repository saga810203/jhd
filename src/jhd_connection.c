/*
 * jhd_connection.c
 *
 *  Created on: May 25, 2018
 *      Author: root
 */
#include <jhd_config.h>
#include <jhd_log.h>
#include <jhd_queue.h>
#include <jhd_event.h>
#include <jhd_core.h>
#include <jhd_connection.h>
#include <jhd_log.h>
#include <jhd_string.h>
#include <tls/jhd_tls_ssl_internal.h>

jhd_connection_t *g_connections;
jhd_connection_t * event_c;

static jhd_queue_t g_listening_queue;

static jhd_queue_t inherited_listening_queue = { &inherited_listening_queue, &inherited_listening_queue };

static jhd_listener_t m_connection_listener;
static jhd_listener_t w_connection_listener;

static jhd_connection_t *free_connections;

int listening_count;
int connection_count;
int free_connection_count;

static void connection_accept_timeout(jhd_event_t *ev){
	event_c = ev->data;
	event_c->close(event_c);
}

in_addr_t jhd_inet_addr(u_char *text, size_t len)
{
    u_char      *p, c;
    in_addr_t    addr;
    uint64_t   octet, n;

    addr = 0;
    octet = 0;
    n = 0;
    for (p = text; p < text + len; ++p) {
        c = *p;
        if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
            if (octet > 255) {
                return INADDR_NONE;
            }
            continue;
        }
        if (c == '.') {
            addr = (addr << 8) + octet;
            octet = 0;
            n++;
            continue;
        }
        return INADDR_NONE;
    }
    if (n == 3) {
        addr = (addr << 8) + octet;
        return htonl(addr);
    }
    return INADDR_NONE;
}
int jhd_inet6_addr(u_char *text, size_t len, u_char *addr)
{
    u_char      c, *zero, *digit, *s, *d;
    size_t      len4;
    uint64_t  	n, nibbles, word;
    if (len == 0) {
        return JHD_ERROR;
    }
    zero = NULL;
    digit = NULL;
    len4 = 0;
    nibbles = 0;
    word = 0;
    n = 8;

    if (text[0] == ':') {
        text++;
        len--;
    }

    for (/* void */; len; len--) {
        c = *text++;
        if (c == ':') {
            if (nibbles) {
                digit = text;
                len4 = len;
                *addr++ = (u_char) (word >> 8);
                *addr++ = (u_char) (word & 0xff);
                if (--n) {
                    nibbles = 0;
                    word = 0;
                    continue;
                }
            } else {
                if (zero == NULL) {
                    digit = text;
                    len4 = len;
                    zero = addr;
                    continue;
                }
            }
            return JHD_ERROR;
        }
        if (c == '.' && nibbles) {
            if (n < 2 || digit == NULL) {
                return JHD_ERROR;
            }

            word = jhd_inet_addr(digit, len4 - 1);
            if (word == INADDR_NONE) {
                return JHD_ERROR;
            }
            word = ntohl(word);
            *addr++ = (u_char) ((word >> 24) & 0xff);
            *addr++ = (u_char) ((word >> 16) & 0xff);
            n--;
            break;
        }
        if (++nibbles > 4) {
            return JHD_ERROR;
        }
        if (c >= '0' && c <= '9') {
            word = word * 16 + (c - '0');
            continue;
        }
        c |= 0x20;
        if (c >= 'a' && c <= 'f') {
            word = word * 16 + (c - 'a') + 10;
            continue;
        }
        return JHD_ERROR;
    }

    if (nibbles == 0 && zero == NULL) {
        return JHD_ERROR;
    }
    *addr++ = (u_char) (word >> 8);
    *addr++ = (u_char) (word & 0xff);
    if (--n) {
        if (zero) {
            n *= 2;
            s = addr - 1;
            d = s + n;
            while (s >= zero) {
                *d-- = *s--;
            }
            memset(zero,0, n);
            return JHD_OK;
        }

    } else {
        if (zero == NULL) {
            return JHD_OK;
        }
    }
    return JHD_ERROR;
}

int jhd_connection_parse_sockaddr(jhd_sockaddr_t* addr,socklen_t *socklen,u_char *addr_text,size_t addr_text_len,uint16_t default_port){
    in_addr_t             inaddr;
    struct in6_addr       inaddr6;
    struct sockaddr_in6  *sin6;
    u_char *p,*last;
    size_t plen ;
    last = addr_text  + addr_text_len;
    p = NULL;
    plen = 0;
	if (addr_text_len && addr_text[0] == '[') {
		p = jhd_strlchr(addr_text, last, ']');
		if(p == NULL ){
			return JHD_ERROR;
		}
		++p;
		if(*p != ':'){
			return JHD_ERROR;
		}
		++p;
		plen = last - p;
		if(plen == 0){
			return JHD_ERROR;
		}
		++addr_text;
		addr_text_len -= plen;
		addr_text_len -=3;
	} else {
		p = jhd_strlchr(addr_text, last, ':');
		if (p != NULL) {
			++p;
			plen  = last - p;
			if(plen == 0){
				return JHD_ERROR;
			}
			--addr_text_len;
			addr_text -= plen;
		}
	}
    if(plen){
        if(JHD_OK != jhd_chars_to_u16(p,plen,&default_port)){
        	return JHD_ERROR;
        }
    }
    memset(&inaddr6,0, sizeof(struct in6_addr));
    inaddr = jhd_inet_addr(addr_text, addr_text_len);
    if (inaddr != INADDR_NONE) {
    	addr->sockaddr.sa_family = AF_INET;
        *socklen = sizeof(struct sockaddr_in);
        addr->sockaddr_in.sin_addr.s_addr = inaddr;
        addr->sockaddr_in.sin_port = htons(default_port);
    } else if (jhd_inet6_addr(addr_text, addr_text_len, inaddr6.s6_addr) == JHD_OK) {
    	addr->sockaddr.sa_family = AF_INET6;
        *socklen = sizeof(struct sockaddr_in6);
        sin6 =&addr->sockaddr_in6;
        memcpy(sin6->sin6_addr.s6_addr, inaddr6.s6_addr, 16);
        sin6->sin6_port = htons(default_port);
    } else {
        return JHD_ERROR;
    }
    return JHD_OK;
}


int jhd_connection_resolve_host(jhd_sockaddr_t* addr,socklen_t *socklen,u_char *addr_text,size_t addr_text_len,uint16_t default_port)
{
    u_char *p,*last;
    size_t plen;
    char host[256];
    struct addrinfo       hints, *res, *rp;
    log_assert(addr_text_len >255);
    plen = 0;
    last = addr_text + addr_text_len;
    p = jhd_strlchr(addr_text, last, ':');
	if (p != NULL) {
		++p;
		plen  = last - p;
		if(plen == 0){
			return JHD_ERROR;
		}
		--addr_text_len;
		addr_text -= plen;


	}
	memcpy(host,addr_text,addr_text_len);
	host[addr_text_len] = 0 ;
	if(plen){
		if(JHD_OK != jhd_chars_to_u16(p,plen,&default_port)){
			return JHD_ERROR;
		}
	}
    memset(&hints,0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
#ifdef AI_ADDRCONFIG
    hints.ai_flags = AI_ADDRCONFIG;
#endif

    if (getaddrinfo(host,NULL, &hints, &res) != 0) {
       return JHD_ERROR;
    }
    /* AF_INET addresses first */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family != AF_INET) {
            continue;
        }
        memcpy(&addr->sockaddr_in,rp->ai_addr, rp->ai_addrlen);
        addr->sockaddr_in.sin_port = htons(default_port);
        *socklen = rp->ai_addrlen;
        freeaddrinfo(res);
        return JHD_OK;
    }
    for (rp = res; rp != NULL; rp = rp->ai_next) {

        if (rp->ai_family != AF_INET6) {
            continue;
        }
        memcpy(&addr->sockaddr_in6, rp->ai_addr, rp->ai_addrlen);
        addr->sockaddr_in6.sin6_port =  htons(default_port);
        *socklen = rp->ai_addrlen;
        freeaddrinfo(res);
        return JHD_OK;
    }
    freeaddrinfo(res);
    return JHD_ERROR;
}


size_t jhd_connection_to_ip_str(jhd_sockaddr_t* addr,socklen_t socklen,u_char *text, size_t len)
{
    u_char               *p,c;

    size_t                n;
    struct sockaddr_in   *sin;
    struct sockaddr_in6  *sin6;

    log_assert(AF_INET ==addr->sockaddr.sa_family || AF_INET6 == addr->sockaddr.sa_family);
    log_assert(len >=45);

    if(AF_INET ==addr->sockaddr.sa_family) {
        sin = &addr->sockaddr_in;
        p = (u_char *) &sin->sin_addr;
        return (size_t)snprintf((char*)text, len, "%d.%d.%d.%d:%u",(int)(p[0]),(int)(p[1]),(int)(p[2]), (int)(p[3]), ntohs(sin->sin_port));
    }
    sin6 =&addr->sockaddr_in6;
    n = 0;
    c = sin6->sin6_addr.s6_addr[0];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] =jhd_g_hex_char[c & 0xF];
    c = sin6->sin6_addr.s6_addr[1];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] = jhd_g_hex_char[c & 0xF];
    text[n++] =':';
    c = sin6->sin6_addr.s6_addr[2];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] =jhd_g_hex_char[c & 0xF];
    c = sin6->sin6_addr.s6_addr[3];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] = jhd_g_hex_char[c & 0xF];
    text[n++] =':';
    c = sin6->sin6_addr.s6_addr[4];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] =jhd_g_hex_char[c & 0xF];
    c = sin6->sin6_addr.s6_addr[5];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] = jhd_g_hex_char[c & 0xF];
    text[n++] =':';
    c = sin6->sin6_addr.s6_addr[6];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] =jhd_g_hex_char[c & 0xF];
    c = sin6->sin6_addr.s6_addr[7];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] = jhd_g_hex_char[c & 0xF];
    text[n++] =':';
    c = sin6->sin6_addr.s6_addr[8];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] =jhd_g_hex_char[c & 0xF];
    c = sin6->sin6_addr.s6_addr[9];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] = jhd_g_hex_char[c & 0xF];
    text[n++] =':';
    c = sin6->sin6_addr.s6_addr[10];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] =jhd_g_hex_char[c & 0xF];
    c = sin6->sin6_addr.s6_addr[11];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] = jhd_g_hex_char[c & 0xF];
    text[n++] =':';
    c = sin6->sin6_addr.s6_addr[12];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] =jhd_g_hex_char[c & 0xF];
    c = sin6->sin6_addr.s6_addr[13];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] = jhd_g_hex_char[c & 0xF];
    text[n++] =':';
    c = sin6->sin6_addr.s6_addr[14];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] =jhd_g_hex_char[c & 0xF];
    c = sin6->sin6_addr.s6_addr[15];
    text[n++] = jhd_g_hex_char[c >> 4];
    text[n++] = jhd_g_hex_char[c & 0xF];
    text[n++] =':';
    return 45 + ((size_t)snprintf(((char*)(&text[n])),(size_t)(len-n),"%d",(int)ntohs(sin6->sin6_port)));
}


static void jhd_listening_free_ssl(jhd_listening_t *lis){
	jhd_tls_ssl_config *cfg ;
	log_assert_master();
	cfg = lis->ssl;
	lis->ssl = NULL;
	if(cfg!=NULL){
		if(cfg->key_cert){
			if(cfg->key_cert->cert){
				jhd_tls_x509_crt_free_by_master(cfg->key_cert->cert);
				free(cfg->key_cert->cert);
			}
			if(cfg->key_cert->key){
				if(cfg->key_cert->key->pk_ctx){
					free(cfg->key_cert->key->pk_ctx);
				}
				free(cfg->key_cert->key);
			}
			free(cfg->key_cert);
		}
		free(cfg);
	}
}

void jhd_listening_free(jhd_listening_t* lis, jhd_bool close_socket) {
	jhd_listening_free_ssl(lis);
	if(lis->lis_ctx_close){
		lis->lis_ctx_close(lis->lis_ctx);
		lis->lis_ctx_close = NULL;
	}
	if(close_socket){
		if(lis->addr_text){
			free(lis->addr_text);
			lis->addr_text = NULL;
		}
		/*
		 * in linux fd =(0 1,2 )  with stdin    stdout     stderr
		 *
		 *
		 * */
		if(lis->fd > 2){
			close(lis->fd);
			lis->fd = -1;
		}
	}
}

static void jhd_listening_free_all(){
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;

	log_assert_master();

	head = &g_listening_queue;
	while (jhd_queue_has_item(head)) {
		q = jhd_queue_head(head);
		jhd_queue_only_remove(q);
		lis = jhd_queue_data(q,jhd_listening_t,queue);
		jhd_listening_free(lis,jhd_true);
		free(lis);
	}
}
static void jhd_listening_to_inherited(){
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;
	log_assert_master();
	head = &g_listening_queue;
	while (jhd_queue_has_item(head)) {
		q = jhd_queue_head(head);
		jhd_queue_remove(q);
		lis = jhd_queue_data(q,jhd_listening_t,queue);
		jhd_listening_free(lis,jhd_false);
		jhd_queue_insert_tail(&g_listening_queue,q);
	}
}



jhd_listening_t* jhd_listening_get(char *addr_text, size_t len) {
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;

	head = &g_listening_queue;
	for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
		lis = jhd_queue_data(q, jhd_listening_t, queue);
		if ((lis->addr_text_len == len) && (0 == memcmp(addr_text,lis->addr_text,len))) {
			return lis;
		}
	}
	return NULL;
}

static int jhd_listening_create_tls_config(jhd_listening_t *lis){
	jhd_tls_ssl_config *cfg;
	log_assert_master();
	log_assert(lis->ssl == NULL);
	cfg = malloc(sizeof(jhd_tls_ssl_config));
	if(cfg == NULL){
		log_stderr("systemcall malloc error");
		return JHD_ERROR;
	}
	lis->ssl = cfg;
	memset(cfg,0,sizeof(jhd_tls_ssl_config));
	cfg->server_side = JHD_TLS_SSL_IS_SERVER;
	return JHD_OK;
}

int jhd_listening_set_addr_text(jhd_listening_t *lis,u_char *addr_text,size_t addr_text_len,uint16_t default_port){
	log_assert_master();
	log_assert(lis->addr_text == NULL);
	if(jhd_connection_parse_sockaddr(&lis->sockaddr,&lis->socklen,addr_text,addr_text_len,default_port)!=JHD_OK){
		log_stderr("parse listening addr[%s] error",addr_text);
		return JHD_ERROR;
	}
	lis->addr_text = malloc(addr_text_len+1);
	if(lis->addr_text == NULL){
		log_stderr("systemcall malloc error");
		return JHD_ERROR;
	}
	memcpy(lis->addr_text,addr_text,addr_text_len);
	lis->addr_text[addr_text_len] = 0;
	return JHD_OK;
}

int jhd_listening_set_tls_cert_and_key(jhd_listening_t *lis,u_char *cert_text,size_t cert_text_len,u_char *key_text,size_t key_text_len){
	jhd_tls_ssl_config *cfg;
	jhd_tls_ssl_key_cert *key_cert,*tmp;

	log_assert_master();
	key_cert = NULL;
	if(lis->ssl == NULL){
		if(JHD_OK != jhd_listening_create_tls_config(lis)){
			return JHD_ERROR;
		}
	}
	cfg = lis->ssl;

	key_cert = malloc(sizeof(jhd_tls_ssl_key_cert));
	if(key_cert == NULL){
		return JHD_ERROR;
	}
	key_cert->cert = NULL;
	key_cert->key = NULL;
	key_cert->next = NULL;

	key_cert->cert = jhd_tls_x509_crt_parse(cert_text,cert_text_len);
	if(key_cert->cert == NULL){
		free(key_cert);
		return JHD_ERROR;
	}
	key_cert->key = malloc(sizeof(jhd_tls_pk_context));
	if(key_cert->key == NULL){
		jhd_tls_x509_crt_free_by_master(key_cert->cert);
		free(key_cert->cert);
		free(key_cert);
		return JHD_ERROR;
	}
	key_cert->key->pk_ctx = NULL;
	key_cert->key->pk_info = NULL;
	if(JHD_OK != jhd_tls_pk_parse_key(key_cert->key,key_text,key_text_len)){
		free(key_cert->key);
		jhd_tls_x509_crt_free_by_master(key_cert->cert);
		free(key_cert->cert);
		free(key_cert);
		return JHD_ERROR;
	}


	if(cfg->key_cert == NULL){
		cfg->key_cert = key_cert;
	}else{
		tmp = cfg->key_cert;
		for(;;){
			if(tmp->next ==NULL){
				tmp->next = key_cert;
				break;
			}
			tmp = tmp->next;
		}
	}
	return JHD_OK;
}




int jhd_listening_config(jhd_listening_t *lis, void *lis_ctx, void (*lis_ctx_close)(void*), const char **alpn_list, jhd_connection_start_pt start_func) {
	log_assert_master();
	if (alpn_list != NULL) {
		if (lis->ssl == NULL) {
			if (JHD_OK != jhd_listening_create_tls_config(lis)) {
				return JHD_ERROR;
			}
		}
		((jhd_tls_ssl_config *) lis->ssl)->alpn_list = alpn_list;
	}
	lis->lis_ctx = lis_ctx;
	lis->lis_ctx_close = lis_ctx_close;
	lis->connection_start = start_func;
	return JHD_OK;
}


int jhd_open_listening_sockets(jhd_listening_t *lis) {
	int reuseaddr, reuseport;
	jhd_queue_t *q;
//	struct sockaddr *saddr;
	int fd;
	reuseaddr = 1;
	reuseport = 1;
	jhd_listening_t *o_lis;

	log_assert_master();
	log_assert(lis->fd == -1);
	for (q = jhd_queue_head(&inherited_listening_queue); q != &inherited_listening_queue; q = jhd_queue_next(q)) {
		o_lis = jhd_queue_data(q, jhd_listening_t, queue);
		if ((lis->addr_text_len == o_lis->addr_text_len) && (memcmp(lis->addr_text, o_lis->addr_text, lis->addr_text_len) == 0)) {
			lis->fd = o_lis->fd;
			lis->bind = jhd_true;
			jhd_queue_only_remove(q);
			o_lis->fd = -1;
			jhd_listening_free(o_lis, jhd_true);
			free(o_lis);
			return JHD_OK;
		}
	}
	fd = socket(lis->sockaddr.sockaddr.sa_family, SOCK_STREAM, 0);
	if (fd == -1) {
		log_stderr("systemcall socket(,SOCK_STREAM,0) failed  with %s",lis->addr_text);
		return JHD_ERROR;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuseaddr, sizeof(int)) == -1) {
		log_stderr("systemcall setsockopt(SO_REUSEADDR) failed with %s", lis->addr_text);
		close(fd);
		return JHD_ERROR;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *) &reuseport, sizeof(int)) == -1) {
		log_stderr("systemcall setsockopt(SO_REUSEPORT) failed with %s", lis->addr_text);
		close(fd);
		return JHD_ERROR;
	}

#if (JHD_HAVE_INET6 && defined IPV6_V6ONLY)
	if (lis->sockaddr.sockaddr.sa_family == AF_INET6) {
		int ipv6only;
		ipv6only = lis->ipv6only ? 1 : 0;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *) &ipv6only, sizeof(int)) == -1) {
			log_stderr("systemcall setsockopt(IPPROTO_IPV6) failed with %s, ignored", lis->addr_text);
		}
	}
#endif
	reuseport = 1;
	if (ioctl(fd, FIONBIO, &reuseport) == -1) {
		log_stderr("systemcall ioctl(FIONBIO) failed with %s", lis->addr_text);
		close(fd);
		return JHD_ERROR;
	}
	lis->fd = fd;
	return JHD_OK;
}
int32_t jhd_bind_listening_sockets() {
	int fd;
	uint32_t tries, failed;
	int err;
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;

	log_assert_master();

	head = &g_listening_queue;
	for (tries = 5; tries; tries--) {
		failed = 0;
		for (q = jhd_queue_head(head); q != jhd_queue_sentinel(head); q = jhd_queue_next(q)) {
			lis = jhd_queue_data(q, jhd_listening_t, queue);
			fd = lis->fd;
			if (lis->bind) {
				continue;
			}
			if (bind(fd, &lis->sockaddr.sockaddr, lis->socklen) == -1) {
				err = errno;
				if (err == EADDRINUSE) {
					log_stderr("exec socket bind() failed  to exit  with %s", lis->addr_text);
					return JHD_ERROR;
				} else {
					log_err("exec socket bind() failed  to retry  with %s", lis->addr_text);
					failed = 1;
					continue;
				}
			}
			if (listen(fd, lis->backlog) == -1) {
				err = errno;
				if (err == EADDRINUSE) {
					log_stderr("exec socket listen(%d) failed  to exit  with %s", lis->backlog, lis->addr_text);
					return JHD_ERROR;
				}
				log_err("exec socket listen(%d) failed  to retry  with %s", lis->backlog, lis->addr_text);
				failed = 1;
				continue;

			}

			lis->bind = jhd_true;
		}
		if (!failed) {
			break;
		}
		usleep(500 * 1000);
	}

	if (failed) {
		log_stderr("listen socket failed to exit  with %s", lis->addr_text);
		return JHD_ERROR;
	}
	return JHD_OK;
}

static int jhd_connection_master_close_listening(jhd_listener_t* listener) {
	log_assert_master();

	if(jhd_quit){
		jhd_listening_free_all();
	}else{
		jhd_listening_to_inherited();
	}
	if(event_accept_fds != NULL){
		free(event_accept_fds);
	}
	return JHD_OK;
}

static int jhd_listening_check_before_open(){
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;

	head =&g_listening_queue;

	//TODO impl
	for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
			lis = jhd_queue_data(q, jhd_listening_t, queue);
			log_assert(lis->connection_start != NULL);
	}
	return JHD_OK;
}

static int jhd_connection_master_startup_listening(jhd_listener_t* listener) {
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;



	event_accept_fds =NULL;
	head = &g_listening_queue;
	listening_count= 0 ;
	event_accept_fds = NULL;
	if(jhd_listening_check_before_open()!= JHD_OK){
		return JHD_ERROR;
	}
	for (q = jhd_queue_head(head); q != jhd_queue_sentinel(head); q = jhd_queue_next(q)) {
		++listening_count;
		lis = jhd_queue_data(q, jhd_listening_t, queue);

		if(lis->accept_timeout==0){
			lis->accept_timeout = 5000;
		}
		if(lis->read_timeout==0){
			lis->read_timeout = 5000;
		}
		if(lis->write_timeout==0){
			lis->write_timeout = 5000;
		}
		if(lis->wait_mem_timeout==0){
			lis->wait_mem_timeout = 5000;
		}
		if (JHD_OK != jhd_open_listening_sockets(lis)) {
			goto failed;
		}
	}

	if (listening_count == 0) {
		log_stderr("listening count is %d", (int )0);
		goto failed;
	}
	event_accept_fds = malloc(sizeof(int)*listening_count);
	if(event_accept_fds== NULL){
		log_stderr("malloc   event_accept_fds error");

	}

	if (jhd_bind_listening_sockets() != JHD_OK) {
		goto failed;
	}

	for (q = jhd_queue_head(&inherited_listening_queue); q != &inherited_listening_queue; q = jhd_queue_next(q)) {
		lis = jhd_queue_data(q, jhd_listening_t, queue);
		jhd_queue_only_remove(q);
		jhd_listening_free(lis, jhd_true);
	}

	listener->handler = jhd_connection_master_close_listening;
	jhd_add_master_shutdown_listener(listener);
	return JHD_OK;

	failed:
	jhd_listening_free_all();
	if(event_accept_fds != NULL){
		free(event_accept_fds);
	}
	return JHD_ERROR;

}

static int jhd_connection_worker_close_listening(jhd_listener_t* listener) {
	jhd_connection_t * c;
	jhd_event_t *ev;

	log_assert_worker();
	int i;
	for (i = listening_count; i < connection_count; ++i) {
		c = &g_connections[i];
		if (c->fd != -1) {
			c->recv = jhd_connection_error_recv;
			ev = &c->read;
			if (ev->timer.key) {
				jhd_rbtree_delete(&jhd_event_timer_rbtree, &ev->timer);
				ev->timer.key = 0;
				ev->timeout = NULL;
			}
			if (ev->queue.next) {
				jhd_queue_only_remove(&ev->queue);
			}
			jhd_queue_insert_tail(&jhd_posted_events, &(ev)->queue);

			c->send = jhd_connection_error_send;
			ev = &c->write;
			if (ev->timer.key) {
				jhd_rbtree_delete(&jhd_event_timer_rbtree, &ev->timer);
				ev->timer.key = 0;
				ev->timeout = NULL;
			}
			if (ev->queue.next) {
				jhd_queue_only_remove(&ev->queue);
			}
			jhd_queue_insert_tail(&jhd_posted_events, &(ev)->queue);
		}
	}
	jhd_event_process_posted(&jhd_posted_events);
	jhd_event_expire_all();
	free(g_connections);
	g_connections = NULL;
	free(event_list);
	event_list = NULL;
	close(epoll_fd);
	epoll_fd = -1;
	return JHD_OK;
}







static int jhd_connection_worker_startup_listening(jhd_listener_t* listener) {
	int i;
	jhd_queue_t *head, *q;
	jhd_listening_t *lis;
	jhd_connection_t *connection;
	log_assert_worker();
	if (connection_count < 100) {
		connection_count = 100;
	}
	if (event_count < 100) {
		event_count = 100;
	}
	epoll_fd = epoll_create(event_count);
	if (epoll_fd == -1) {
		log_stderr("systemcall epoll_create(%d) failed to exit", (int ) connection_count);
		goto failed;
	}
	event_list = malloc(sizeof(struct epoll_event) * event_count);
	if (event_list == NULL) {
		log_stderr("malloc event_list(count = %u) failed with ", event_count);
		goto failed;
	}
	memset(event_list,0,sizeof(struct epoll_event) * event_count);
	i = 0;
	g_connections = malloc(sizeof(jhd_connection_t) * connection_count);
	if (g_connections) {
		memset(event_list,0,sizeof(jhd_connection_t) * connection_count);
		head = &g_listening_queue;
		i = 0;
		for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
			lis = jhd_queue_data(q, jhd_listening_t, queue);
			lis->connection = &g_connections[i];
			lis->connection->idx = i;
			lis->connection->listening = lis;
			++i;
			lis->connection->read.data = lis->connection;
			lis->connection->read.handler = jhd_connection_accept;
			lis->connection->write.data = lis->connection;
			lis->connection->write.handler = jhd_event_noop;
		}
		for (; i < connection_count;) {
			connection = &g_connections[i];
			connection->idx = i;
			connection->read.data = connection;
			connection->write.data = connection;
			connection->fd = -1;
			++i;
			connection->data = free_connections;
			free_connections = connection;
		}

		free_connection_count = connection_count - listening_count;
		listener->handler = jhd_connection_worker_close_listening;
		jhd_add_worker_shutdown_listener(listener);
	} else {
		goto failed;
	}
	return JHD_OK;

	failed:

	if (epoll_fd != (-1)) {
		close(epoll_fd);
		epoll_fd = (-1);
	}
	if (event_list) {
		free(event_list);
		event_list = NULL;
	}
	return JHD_ERROR;

}

void jhd_connection_init() {
	epoll_fd = -1;

	listening_count = 0;
	connection_count = 0;
	g_connections = NULL;
	free_connections = NULL;
	event_count = 0;
	event_list = NULL;

	jhd_queue_init(&g_listening_queue);

	memset(&m_connection_listener, 0, sizeof(jhd_listener_t));

	m_connection_listener.handler = jhd_connection_master_startup_listening;

	jhd_add_master_startup_listener(&m_connection_listener);

	memset(&w_connection_listener, 0, sizeof(jhd_listener_t));

	w_connection_listener.handler = jhd_connection_worker_startup_listening;

	jhd_add_worker_startup_listener(&w_connection_listener);
}
ssize_t jhd_connection_error_recv(jhd_connection_t *c,u_char *buf,size_t size){
	log_notice("==>jhd_connection_error_recv<==  ");
	return JHD_ERROR;
}
ssize_t jhd_connection_error_send(jhd_connection_t *c,u_char *buf,size_t size){
	log_notice("==>jhd_connection_error_send<==  ");
	return JHD_ERROR;
}

void jhd_connection_empty_read(jhd_event_t *rv){}
void jhd_connection_empty_write(jhd_event_t *wv){}
void jhd_connection_empty_ssl_write(jhd_event_t *wv){
	//FIXME: impl
}

jhd_connection_t*  jhd_connection_get(){
	jhd_connection_t *c = free_connections;
	if (c) {
		--free_connection_count;
		free_connections = c->data;
	}
	return c;
}
void jhd_connection_destroy(jhd_connection_t *c){
	++free_connection_count;
	c->data = free_connections;
	free_connections = c;
}
ssize_t jhd_connection_recv(jhd_connection_t *c, u_char *buf, size_t size) {
	ssize_t n,ret;
	int err;
	log_notice("==>jhd_connection_recv(,buf:%lu,size:%lu)",(uint64_t)buf,size);
	n = 0;
	for (;;) {
		ret = recv(c->fd, buf, size, 0);
		if (ret == 0) {
			log_debug("syscall(recv(%d,%lu,%lu,0)==0", c->fd, (uint64_t )buf, size);
			c->shutdown_remote = 1;
			if(n == 0){
				c->recv = jhd_connection_error_recv;
				n = JHD_ERROR;
			}
			break;
		} else if (ret > 0) {
			log_debug("syscall(recv(%d,%lu,%lu,0)==%ld", c->fd, (uint64_t )buf, size,ret);
			n+=ret;
			size -=ret;
			if(size ==0){
				break;
			}
			buf +=ret;
		} else {
			err = errno;
			if (err == EAGAIN) {
				log_debug("syscall(recv(fd:%d,buf:%lu,size:%lu,0)==%ld,errno=%s", c->fd, (u_int64_t )buf, size, ret, "EAGAIN");
				if(n ==0){
					n = JHD_AGAIN;
				}
				break;
			} else if (err != EINTR) {
				log_warn("syscall(recv(fd:%d,buf:%lu,size:%lu,0)==%ld,errno=%d", c->fd, (u_int64_t )buf, size,ret, err);
				if(n == 0){
					c->recv = jhd_connection_error_recv;
					n = JHD_ERROR;
				}
				break;
			}
			log_debug("syscall recv(fd:%d,buf:%lu,size:%lu,0)==%ld,errno=%s", c->fd, (u_int64_t )buf, size, ret, "EINTR");
		}
	}
	log_notice("<= jhd_connection_recv(...) = %ld",n);
	return n;
}

ssize_t jhd_connection_send(jhd_connection_t *c, u_char *buf, size_t size) {
	ssize_t ret;
	int err;
	log_notice("==>jhd_connection_send(,buf:%lu,size:%lu)",(uint64_t)buf,size);
	for (;;) {
		ret = send(c->fd, buf, size, 0);
		if (ret >= 0) {
			log_debug("syscal send(fd:%d,buf:lu,size:%lu,0)==%ld",c->fd, (u_int64_t )buf, size, ret);
			break;
		} else {
			err = errno;
			if (err == EAGAIN) {
				log_debug("syscal send(fd:%d,buf:lu,size:%lu,0)==%ld,errno==EAGAIN", c->fd, (u_int64_t )buf, size,ret);
				ret= JHD_AGAIN;
				break;
			} else if (err != EINTR) {
				log_warn("syscal send(fd:%d,buf:lu,size:%lu,0)==%ld,errno==%d", c->fd, (u_int64_t )buf, size, ret, err);
				ret = JHD_ERROR;
				break;
			}
			log_debug("syscal send(fd:%d,buf:lu,size:%lu,0)==%ld,errno==EINTR", c->fd, (u_int64_t )buf, size, ret);

		}
	}
	log_notice("<==jhd_connection_send(...) = %ld",ret);
	return ret;
}

void jhd_connection_close(jhd_connection_t *c) {
	int op;
	struct epoll_event ee;
	log_notice("==>jhd_connection_close");
	log_assert(c->closed == 0);
	log_assert_code(c->closed = 1);
	log_assert(c->fd >2);
	log_assert(&g_connections[c->idx] == c);
	log_assert(c == c->read.data);
	log_assert(c == c->write.data);
	if(c->read.queue.next){
		jhd_queue_remove(&c->read.queue);
	}
	if(c->write.queue.next){
		jhd_queue_remove(&c->write.queue);
	}
	c->read.handler = jhd_connection_empty_read;
	c->write.handler = jhd_connection_empty_write;
	if(c->read.timer.key != 0){
		jhd_event_del_timer(&c->read);
	}
	if(c->write.timer.key != 0){
			jhd_event_del_timer(&c->write);
	}
	c->read.timeout = NULL;
	c->write.timeout = NULL;
	op = EPOLL_CTL_DEL;
	ee.events = 0;
	ee.data.ptr = NULL;
	epoll_ctl(epoll_fd, op, c->fd, &ee);
	close(c->fd);
	c->fd = -1;
	++free_connection_count;
	c->data = free_connections;
	free_connections = c;
	log_notice("==>jhd_connection_close");
}

#define connection_get_with_accept()\
	c = free_connections;\
	if (c) {\
		log_assert(free_connection_count>0);\
		--free_connection_count;\
		free_connections = c->data;\
		log_assert(c->closed == 1);\
		log_assert_code(c->closed = 1);\
		log_assert(c == c->read.data);\
		log_assert(c == c->write.data);\
		log_assert(c->fd == -1);\
		log_assert(c->read.handler == jhd_connection_empty_read);\
		log_assert(c->write.handler == jhd_connection_empty_write);\
		log_assert(c->read.timer.key ==0);\
		log_assert(c->write.timer.key ==0);\
		log_assert(&g_connections[c->idx] == c);\
	}else


#define connection_config_socket_with_accept()\
		nb = 1;\
		err = ioctl(fd, FIONBIO, &nb);\
		log_debug("exec ioctl(,FIONBIO,)==%d", err);\
		if (err == (-1)) {\
			jhd_connection_free();\
			close(fd);\
			log_err("connection acccept[%s] error with:%s", lis->addr_text, "ioctl(,FIONBIO,)== -1");\
			log_notice("<== function with:%s", "ioctl(,FIONBIO,)== -1");\
			return;\
		}\
		if(lis->rcvbuf){\
			nb = lis->rcvbuf ;\
			if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,(const void *) &nb, sizeof(int)) == -1) {\
				jhd_connection_free();\
				close(fd);\
				log_err("connection acccept[%s] error with:setsockopt(SO_RCVBUF,%d) == -1 error=%d", lis->addr_text,(int)lis->rcvbuf,errno);\
				log_notice("<== function with:%s  error");\
				return;\
			}\
		}\
		if(lis->sndbuf){\
			nb = lis->sndbuf ;\
			if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF,(const void *) &nb, sizeof(int)) == -1) {\
				jhd_connection_free();\
				close(fd);\
				log_err("connection acccept[%s] error with:setsockopt(SO_SNDBUF,%d) == -1 error=%d", lis->addr_text,(int)lis->sndbuf,errno);\
				log_notice("<== function with:%s error");\
				return;\
			}\
		}

#define connection_check_socket_with_accept()\
		if (fd == (-1)) {\
			err = errno;\
			if ((err == EAGAIN)) {\
				jhd_connection_free();\
				log_notice("<== function (%s) accept(...) ==-1,errno != EAGAIN",lis->addr_text);\
				return;\
			}else if(err != EINTR){\
				jhd_connection_free();\
				log_err("connection acccept[%s] error with:%s", lis->addr_text, "accept(...) = -1,errno= %d",errno);\
				log_notice("<== function accept(...) ==-1,errno != EINTR");\
				return;\
			}else{\
				jhd_connection_free();\
				continue;\
			}\
		}

#define connection_add_to_event_list()  	c->listening = sc->listening;\
		c->fd = fd;\
		if(jhd_event_add_connection(c)){\
			c->close = jhd_connection_close;\
			c->listening = sc->listening;\
			jhd_event_add_timer(&c->read,lis->accept_timeout,connection_accept_timeout);\
			sc->listening->connection_start(c);\
		}else{\
			close(fd);\
			c->fd = -1;\
			jhd_connection_free();\
			log_notice("<== function with: error");\
			return;\
		}

void jhd_connection_accept_use_accept(jhd_event_t *ev) {
	jhd_listening_t* lis;
	jhd_connection_t *c, *sc;
	int fd;
	int err;
	int nb;

	sc = ev->data;
	lis = sc->listening;
	log_notice("==>jhd_connection_accept_use_accept(%s)",lis->addr_text);
	for (;;) {
		connection_get_with_accept(){
			log_assert(free_connection_count==0);
			log_notice("<==jhd_connection_accept_use_accept(%s)",lis->addr_text);
			return;
		}
		c->socklen = sizeof(jhd_sockaddr_t);
		fd = accept(lis->fd,(struct sockaddr *) &c->sockaddr, &c->socklen);
		log_debug("exec accept(...)==%d", fd);

		connection_check_socket_with_accept()

		connection_config_socket_with_accept()

		connection_add_to_event_list()
	}
}

void jhd_connection_accept_use_accept4(jhd_event_t *ev) {
	jhd_listening_t *lis;
	jhd_connection_t *c, *sc;
	int fd;
	int err;
	int nb;
	log_notice("==>jhd_connection_accept_use_accept4");
	sc = ev->data;
	lis = sc->listening;
	log_info("begin connection acccept[%s]", lis->addr_text);
	for (;;) {
		connection_get_with_accept(){
			log_assert(free_connection_count==0);
			log_notice("<==jhd_connection_accept_use_accept4 : free_connections_count ==%d", free_connection_count);
			return;
		}
		c->socklen = sizeof(jhd_sockaddr_t);
		fd = accept4(lis->fd,(struct sockaddr *) &c->sockaddr, &c->socklen, SOCK_NONBLOCK);
		log_debug("exec accept4(...)==%d", fd);

		connection_check_socket_with_accept()

		connection_config_socket_with_accept()

		connection_add_to_event_list()
	}
}
void jhd_connection_accept(jhd_event_t *ev) {
	jhd_listening_t *lis;
	jhd_connection_t *c, *sc;
	int fd;
	int err;
	int nb;
	jhd_queue_t *head,*q;
	log_notice("==>jhd_connection_accept_use_accept4");

	sc = ev->data;
	lis = sc->listening;
	log_info("begin connection acccept[%s]", lis->addr_text);
	connection_get_with_accept(){
		log_assert(free_connection_count==0);
		log_notice("<==jhd_connection_accept: free_connections_count ==%d", free_connection_count);
		return;
	}
	fd = accept4(lis->fd, (struct sockaddr *)&c->sockaddr, &c->socklen, SOCK_NONBLOCK);
	log_debug("exec accept4(...)==%d", fd);
	if (fd == (-1)) {
		err = errno;
		if ((err == EAGAIN)) {
			jhd_connection_free();
			head = &g_listening_queue;
			nb = 0;
			for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
				(jhd_queue_data(q, jhd_listening_t, queue))->connection->read.handler = jhd_connection_accept_use_accept4;
			}
			log_notice("<== jhd_connection_accept accept4(...) ==-1,errno = EAGAIN");
			return;
		}else if (err == ENOSYS) {
			jhd_connection_free();
			log_err("connection acccept[%s] error with:%s", lis->addr_text, "accept4(...)==-1,errno = ENOSYS");
			head = &g_listening_queue;
			nb = 0;
			for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
				(jhd_queue_data(q, jhd_listening_t, queue))->connection->read.handler = jhd_connection_accept_use_accept;
			}
			jhd_post_event(ev,&jhd_posted_accept_events);
			log_notice("<== jhd_connection_accept accept4(...) ==-1,errno = ENOSYS");
			return;
		}else if(err == EINTR){
			jhd_connection_free();
			jhd_post_event(ev,&jhd_posted_accept_events);
			return;
		}else{
			jhd_connection_free();
			log_err("connection acccept[%s] error with: accept4(...)==-1,errno =%d", lis->addr_text, err);
			return;
		}
	}
	head = &g_listening_queue;
	for (q = jhd_queue_head(head); q != head; q = jhd_queue_next(q)) {
		(jhd_queue_data(q, jhd_listening_t, queue))->connection->read.handler = jhd_connection_accept_use_accept4;
	}

	connection_config_socket_with_accept()

	connection_add_to_event_list()

	jhd_post_event(ev,&jhd_posted_accept_events);
	log_notice("<== jhd_connection_accept OK ");
}





