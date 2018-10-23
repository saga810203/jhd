#ifndef JHD_TLS_ENTROPY_POLL_H
#define JHD_TLS_ENTROPY_POLL_H

#include <tls/jhd_tls_config.h>

#include <stddef.h>

/*
 * Default thresholds for built-in sources, in bytes
 */
#define JHD_TLS_ENTROPY_MIN_PLATFORM     32     /**< Minimum for platform source    */
#define JHD_TLS_ENTROPY_MIN_HAVEGE       32     /**< Minimum for HAVEGE             */
#define JHD_TLS_ENTROPY_MIN_HARDCLOCK     4     /**< Minimum for jhd_tls_timing_hardclock()        */
#if !defined(JHD_TLS_ENTROPY_MIN_HARDWARE)
#define JHD_TLS_ENTROPY_MIN_HARDWARE     32     /**< Minimum for the hardware source */
#endif



void jhd_tls_entropy_poll_init();

#if !defined(JHD_TLS_NO_PLATFORM_ENTROPY)
/**
 * \brief           Platform-specific entropy poll callback
 */
void jhd_tls_platform_entropy_poll(void *data, unsigned char *output, size_t len, size_t *olen);
#endif


/**
 * \brief           jhd_tls_timing_hardclock-based entropy poll callback
 */
void jhd_tls_hardclock_poll(void *data, unsigned char *output, size_t len, size_t *olen);

#if defined(JHD_TLS_ENTROPY_HARDWARE_ALT)
/**
 * \brief           Entropy poll callback for a hardware source
 *
 * \warning         This is not provided by mbed TLS!
 *                  See \c JHD_TLS_ENTROPY_HARDWARE_ALT in config.h.
 *
 * \note            This must accept NULL as its first argument.
 */
void jhd_tls_hardware_poll( void *data,
		unsigned char *output, size_t len, size_t *olen );
#endif

#endif /* entropy_poll.h */
