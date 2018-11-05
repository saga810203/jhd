#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_ssl_ciphersuites.h>
#include <tls/jhd_tls_ctr_drbg.h>
#include <tls/jhd_tls_aesni.h>
#include <tls/jhd_tls_cipher_internal.h>
#include <tls/jhd_tls_entropy_poll.h>
#include <tls/jhd_tls_gcm.h>
#if defined(JHD_TLS_HAVE_ASM) && defined(__GNUC__) &&  \
    ( defined(__amd64__) || defined(__x86_64__) )   &&  \
    ! defined(JHD_TLS_HAVE_X86_64)
#define JHD_TLS_HAVE_X86_64
#endif

int jhd_tls_config_init(){
	int ret= 0;
	int n= 0x12345678;
	size_t nn= 0x123456789ABCDEF0;
	unsigned char b[4];
	unsigned char c[8];
	if((sizeof(int) != 4) || (sizeof(size_t)!=8) || (sizeof(unsigned long)!=8)){
		log_stderr("unsupported  SYSTEM!!!!!!!!!!!!!!!!!!!!!\n");
		exit(1);
	}
    b[0] = (unsigned char) ( ( (n)       ) & 0xFF );
    b[1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );
    b[2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );
    b[3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );
    if( *((int*)b) != n){
    	log_stderr("unsupported  SYSTEM!!!!!!!!!!!!!!!!!!!!!\n");
    	exit(1);
    }
    c[0] = (unsigned char) ( ( (nn)       ) & 0xFF );
    c[1] = (unsigned char) ( ( (nn) >>  8 ) & 0xFF );
    c[2] = (unsigned char) ( ( (nn) >> 16 ) & 0xFF );
    c[3] = (unsigned char) ( ( (nn) >> 24 ) & 0xFF );
    c[4] = (unsigned char) ( ( (nn) >> 32 ) & 0xFF );
    c[5] = (unsigned char) ( ( (nn) >> 40 ) & 0xFF );
    c[6] = (unsigned char) ( ( (nn) >> 48 ) & 0xFF );
    c[7] = (unsigned char) ( ( (nn) >> 56 ) & 0xFF );
    if( *((size_t*)c) != nn){
    	log_stderr("unsupported  SYSTEM!!!!!!!!!!!!!!!!!!!!!\n");
    	exit(1);
    }
	jhd_tls_aes_init();
	jhd_tls_gcm_init_with_aesni();
	jhd_tls_entropy_poll_init();
	jhd_tls_ecp_init();
	jhd_tls_ciphers_init();
	jhd_tls_random_init();

	return ret;
}
