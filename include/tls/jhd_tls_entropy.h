#ifndef JHD_TLS_ENTROPY_H
#define JHD_TLS_ENTROPY_H

#include <tls/jhd_tls_config.h>

#include <stddef.h>
#include <tls/jhd_tls_sha512.h>

#define JHD_TLS_ENTROPY_SHA512_ACCUMULATOR


#define JHD_TLS_ERR_ENTROPY_SOURCE_FAILED                 -0x003C  /**< Critical entropy source failure. */
#define JHD_TLS_ERR_ENTROPY_MAX_SOURCES                   -0x003E  /**< No more sources can be added. */
#define JHD_TLS_ERR_ENTROPY_NO_SOURCES_DEFINED            -0x0040  /**< No sources have been added to poll. */
#define JHD_TLS_ERR_ENTROPY_NO_STRONG_SOURCE              -0x003D  /**< No strong sources have been added to poll. */
#define JHD_TLS_ERR_ENTROPY_FILE_IO_ERROR                 -0x003F  /**< Read/write error in file. */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(JHD_TLS_ENTROPY_MAX_SOURCES)
#define JHD_TLS_ENTROPY_MAX_SOURCES     4      /**< Maximum number of sources supported */
#endif

#if !defined(JHD_TLS_ENTROPY_MAX_GATHER)
#define JHD_TLS_ENTROPY_MAX_GATHER      128     /**< Maximum amount requested from entropy sources */
#endif

/* \} name SECTION: Module settings */


#define JHD_TLS_ENTROPY_BLOCK_SIZE      64      /**< Block size of entropy accumulator (SHA-512) */

#define JHD_TLS_ENTROPY_MAX_SEED_SIZE   1024    /**< Maximum size of seed we read from seed file */
#define JHD_TLS_ENTROPY_SOURCE_MANUAL   JHD_TLS_ENTROPY_MAX_SOURCES

#define JHD_TLS_ENTROPY_SOURCE_STRONG   1       /**< Entropy source is strong   */
#define JHD_TLS_ENTROPY_SOURCE_WEAK     0       /**< Entropy source is weak     */

/**
 * \brief           Entropy poll callback pointer
 *
 * \param data      Callback-specific data pointer
 * \param output    Data to fill
 * \param len       Maximum size to provide
 * \param olen      The actual amount of bytes put into the buffer (Can be 0)
 *
 */
typedef void (*jhd_tls_entropy_f_source_ptr)(void *data, unsigned char *output, size_t len, size_t *olen);

/**
 * \brief           Entropy source state
 */
typedef struct {
	jhd_tls_entropy_f_source_ptr f_source; /**< The entropy source callback */
	void * p_source; /**< The callback data pointer */
	size_t size; /**< Amount received in bytes */
	size_t threshold; /**< Minimum bytes required before release */
	int strong; /**< Is the source strong? */
} jhd_tls_entropy_source_state;

/**
 * \brief           Entropy context structure
 */
typedef struct {
#if defined(JHD_TLS_ENTROPY_SHA512_ACCUMULATOR)
	jhd_tls_sha512_context accumulator;
#else
	jhd_tls_sha256_context accumulator;
#endif
	int source_count;
	jhd_tls_entropy_source_state source[JHD_TLS_ENTROPY_MAX_SOURCES];

} jhd_tls_entropy_context;

/**
 * \brief           Initialize the context
 *
 * \param ctx       Entropy context to initialize
 */
void jhd_tls_entropy_init(jhd_tls_entropy_context *ctx);



/**
 * \brief           Retrieve entropy from the accumulator
 *                  (Maximum length: JHD_TLS_ENTROPY_BLOCK_SIZE)
 *
 * \param data      Entropy context
 * \param output    Buffer to fill
 * \param len       Number of bytes desired, must be at most JHD_TLS_ENTROPY_BLOCK_SIZE(64)
 *
 */
void jhd_tls_entropy_func(void *data, unsigned char *output, size_t len);


#endif /* entropy.h */
