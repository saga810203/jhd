#ifndef JHD_CONFIG_H_
#define JHD_CONFIG_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE             /* pread(), pwrite(), gethostname() */
#endif

#define _FILE_OFFSET_BITS  64

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>             /* offsetof() */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <glob.h>
#include <sys/vfs.h>            /* statfs() */

#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sched.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>        /* TCP_NODELAY, TCP_CORK */
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/un.h>

#include <time.h>               /* tzset() */
#include <malloc.h>             /* memalign() */
#include <limits.h>             /* IOV_MAX */
#include <sys/ioctl.h>
#include <crypt.h>
#include <sys/utsname.h>        /* uname() */
#include <dlfcn.h>
#include <semaphore.h>
#include <sys/prctl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <linux/capability.h>
#include <inttypes.h>


#include <jhd_error.h>



#define JHD_PROCESS_MASTER     0
#define JHD_PROCESS_WORKER     1
#define JHD_PROCESS_HELPER     2


#define JHD_CONFIG_INCLUDE_TEST_CERTS
#define JHD_CONFIG_DEV_MODE

#define JHD_HAVE_INET6 1


#define JHD_LISTEN_BACKLOG  511

#define JHD_TLS_CONFIG_MAX  64


#ifndef JHD_ALIGNMENT
#define JHD_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#endif

#define jhd_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define jhd_align_ptr(p, a)  (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))

#define jhd_abort       abort



#ifndef JHD_INLINE
#ifndef jhd_inline
#define jhd_inline inline
#endif
#endif

#ifdef MAXHOSTNAMELEN
#define JHD_MAXHOSTNAMELEN  MAXHOSTNAMELEN
#else
#define JHD_MAXHOSTNAMELEN  256
#endif

#ifndef NULL
#define NULL ((void*)0)
#endif

#define INT64_MAX_STRING "9223372036854775807"


#define JHD_OK			0
#define JHD_ERROR		(-1)
#define JHD_AGAIN		(-2)
#define JHD_UNSUPPORTED    (-3)
#define JHD_UNEXPECTED	(-4)

#define JHD_RETURN_STR(X) ((X)==JHD_OK?"JHD_OK":((X)==JHD_AGAIN?"JHD_AGAIN":((X)==JHD_ERROR?"JHD_ERROR":"OTHER_RETURN_VALUE")))




#define jhd_bool int
#define jhd_true 1
#define jhd_false 0

extern  int jhd_err;
extern  u_char jhd_g_hex_char[];
extern sig_atomic_t jhd_process;

extern u_char jhd_calc_buffer[16384];
extern u_char jhd_empty_string[];


typedef void (*jhd_obj_free_pt)(void*);



static jhd_inline u_char * jhd_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {
        if (*p == c) {
            return p;
        }
        p++;
    }
    return NULL;
}


void jhd_config_check();


#endif

