#ifndef JHD_TLS_PLATFORM_H
#define JHD_TLS_PLATFORM_H


#include <tls/jhd_tls_config.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define jhd_tls_free       free
#define jhd_tls_free_with_size(p,s) free(p)
#define jhd_tls_malloc     malloc
#define jhd_tls_alloc     malloc
#define jhd_tls_wait_mem(event,s)
#endif /* platform.h */
