#include <tls/jhd_tls_config.h>
#include <string.h>
#include <tls/jhd_tls_entropy.h>
#include <tls/jhd_tls_entropy_poll.h>


#if !defined(unix) && !defined(__unix__) && !defined(__unix) && \
    !defined(__APPLE__) && !defined(_WIN32) && !defined(__QNXNTO__)
#error "Platform entropy sources only work on Unix and Windows, see JHD_TLS_NO_PLATFORM_ENTROPY in config.h"
#endif

/*
 * Test for Linux getrandom() support.
 * Since there is no wrapper in the libc yet, use the generic syscall wrapper
 * available in GNU libc and compatible libc's (eg uClibc).
 */
#if defined(__linux__) && defined(__GLIBC__)
#include <unistd.h>
#include <sys/syscall.h>
#if defined(SYS_getrandom)
#define HAVE_GETRANDOM

static int getrandom_wrapper( void *buf, size_t buflen, unsigned int flags )
{
	/* MemSan cannot understand that the syscall writes to the buffer */
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
	memset( buf, 0, buflen );
#endif
#endif

	return( syscall( SYS_getrandom, buf, buflen, flags ) );
}

#include <sys/utsname.h>
/* Check if version is at least 3.17.0 */
static int check_version_3_17_plus( void )
{
	int minor;
	struct utsname un;
	const char *ver;

	/* Get version information */
	uname(&un);
	ver = un.release;

	/* Check major version; assume a single digit */
	if( ver[0] < '3' || ver[0] > '9' || ver [1] != '.' )
	return( -1 );

	if( ver[0] - '0' > 3 )
	return( 0 );

	/* Ok, so now we know major == 3, check minor.
	 * Assume 1 or 2 digits. */
	if( ver[2] < '0' || ver[2] > '9' )
	return( -1 );

	minor = ver[2] - '0';

	if( ver[3] >= '0' && ver[3] <= '9' )
	minor = 10 * minor + ver[3] - '0';
	else if( ver [3] != '.' )
	return( -1 );

	if( minor < 17 )
	return( -1 );

	return( 0 );
}
static int has_getrandom = 0;
#endif /* SYS_getrandom */
#endif /* __linux__ */

#include <stdio.h>

void jhd_tls_entropy_poll_init(){
#if defined(HAVE_GETRANDOM)
	has_getrandom = ( check_version_3_17_plus() == 0 );
#endif /* HAVE_GETRANDOM */
}

void jhd_tls_platform_entropy_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
	FILE *file;
	((void) data);
	uint64_t ct;
	struct timespec  nt;
	char *p;
	*olen = len;
#if defined(HAVE_GETRANDOM)
	if( has_getrandom )
	{
		 if(0 ==getrandom_wrapper( output, len, 0 )){
			 return;
		 }else{
			 goto internal_build;
		 }
	}
#endif /* HAVE_GETRANDOM */



	file = fopen("/dev/urandom", "rb");
	if (file != NULL) {
		if(len == fread(output, 1, len, file)){
		fclose(file);
		return;
		}
		fclose(file);
	}
#if defined(HAVE_GETRANDOM)
	internal_build:
#endif /* HAVE_GETRANDOM */
		ct = (uint64_t)(time(NULL));
		clock_gettime(CLOCK_MONOTONIC,&nt);
		ct = ct * nt.tv_nsec * nt.tv_sec;
		*((unsigned char*)(&ct)) |= 0x80;
		p = (char*)&ct;
		do{
		  if(len >= 8){
			  memcpy_8(output,p);
			  output+=8;
			  len -=8;
		  }else{
			memcpy(output,p,len);
			len = 0;
		  }

		}while(len >0 );
}





void jhd_tls_hardclock_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    unsigned long timer, hi;
    asm volatile( "rdtsc" : "=a" (timer), "=d" (hi) );
    timer |= ( hi << 32 ) ;
	((void) data);
	memcpy_8(output,&timer);
	*olen = 8;//sizeof(unsigned long);
}




