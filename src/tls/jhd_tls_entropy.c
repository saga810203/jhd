#include <tls/jhd_tls_config.h>

#if defined(JHD_TLS_TEST_NULL_ENTROPY)
#warning "**** WARNING!  JHD_TLS_TEST_NULL_ENTROPY defined! "
#warning "**** THIS BUILD HAS NO DEFINED ENTROPY SOURCES "
#warning "**** THIS BUILD IS *NOT* SUITABLE FOR PRODUCTION USE "
#endif

#include <tls/jhd_tls_entropy.h>
#include <tls/jhd_tls_entropy_poll.h>

#include <string.h>

#if defined(JHD_TLS_FS_IO)
#include <stdio.h>
#endif

#if defined(JHD_TLS_SELF_TEST)
#include <tls/jhd_tls_platform.h>
#endif /* JHD_TLS_SELF_TEST */

#define ENTROPY_MAX_LOOP    256     /**< Maximum amount to loop before error */

/**
 * \brief           Adds an entropy source to poll
 *
 * \param ctx       Entropy context
 * \param f_source  Entropy function
 * \param p_source  Function data
 * \param threshold Minimum required from source before entropy is released
 *                  ( with jhd_tls_entropy_func() ) (in bytes)
 * \param strong    JHD_TLS_ENTROPY_SOURCE_STRONG or
 *                  JHD_TLS_ENTROPY_SOURCE_WEAK.
 *                  At least one strong source needs to be added.
 *                  Weaker sources (such as the cycle counter) can be used as
 *                  a complement.
 *
 * \return          0 if successful or JHD_TLS_ERR_ENTROPY_MAX_SOURCES
 */
static inline void jhd_tls_entropy_add_source(jhd_tls_entropy_context *ctx, jhd_tls_entropy_f_source_ptr f_source, void *p_source, size_t threshold, int strong) {
	int idx = ctx->source_count;
	ctx->source[idx].f_source = f_source;
	ctx->source[idx].p_source = p_source;
	ctx->source[idx].threshold = threshold;
	ctx->source[idx].strong = strong;
	ctx->source_count++;
}

void jhd_tls_entropy_init(jhd_tls_entropy_context *ctx) {

	jhd_tls_platform_zeroize(ctx, sizeof(jhd_tls_entropy_context));
#if defined(JHD_TLS_ENTROPY_SHA512_ACCUMULATOR)
	jhd_tls_sha512_starts_ret(&ctx->accumulator);
#else
	jhd_tls_sha256_starts_ret_with_256(&ctx->accumulator);
#endif

	/* Reminder: Update ENTROPY_HAVE_STRONG in the test files
	 *           when adding more strong entropy sources here. */

#if defined(JHD_TLS_TEST_NULL_ENTROPY)
	jhd_tls_entropy_add_source( ctx, jhd_tls_null_entropy_poll, NULL,
			1, JHD_TLS_ENTROPY_SOURCE_STRONG );
#endif

	jhd_tls_entropy_add_source(ctx, jhd_tls_platform_entropy_poll, NULL,
	JHD_TLS_ENTROPY_MIN_PLATFORM,
	JHD_TLS_ENTROPY_SOURCE_STRONG);


	jhd_tls_entropy_add_source(ctx, jhd_tls_hardclock_poll, NULL,
	JHD_TLS_ENTROPY_MIN_HARDCLOCK,
	JHD_TLS_ENTROPY_SOURCE_WEAK);

#if defined(JHD_TLS_ENTROPY_HARDWARE_ALT)
	jhd_tls_entropy_add_source( ctx, jhd_tls_hardware_poll, NULL,
			JHD_TLS_ENTROPY_MIN_HARDWARE,
			JHD_TLS_ENTROPY_SOURCE_STRONG );
#endif

}

/*
 * Entropy accumulator update
 */
static void entropy_update(jhd_tls_entropy_context *ctx, unsigned char source_id, const unsigned char *data, size_t len) {
	unsigned char header[2];
	unsigned char tmp[JHD_TLS_ENTROPY_BLOCK_SIZE];
	size_t use_len = len;
	const unsigned char *p = data;

	if (use_len > JHD_TLS_ENTROPY_BLOCK_SIZE) {
#if defined(JHD_TLS_ENTROPY_SHA512_ACCUMULATOR)
		jhd_tls_sha512_ret(data, len, tmp);
#else
		jhd_tls_sha256_ret( data, len, tmp );
#endif
		p = tmp;
		use_len = JHD_TLS_ENTROPY_BLOCK_SIZE;
	}

	header[0] = source_id;
	header[1] = use_len & 0xFF;

	/*
	 * Start the accumulator if this has not already happened. Note that
	 * it is sufficient to start the accumulator here only because all calls to
	 * gather entropy eventually execute this code.
	 */
#if defined(JHD_TLS_ENTROPY_SHA512_ACCUMULATOR)

	jhd_tls_sha512_update_ret(&ctx->accumulator, header, 2);

	jhd_tls_sha512_update_ret(&ctx->accumulator, p, use_len);
#else
	jhd_tls_sha256_update_ret( &ctx->accumulator, header, 2 );

	ret = jhd_tls_sha256_update_ret( &ctx->accumulator, p, use_len );
#endif

}



/*
 * Run through the different sources to add entropy to our accumulator
 */
static void entropy_gather_internal(jhd_tls_entropy_context *ctx) {
	int i;
	unsigned char buf[JHD_TLS_ENTROPY_MAX_GATHER];
	size_t olen;

	/*
	 * Run through our entropy sources
	 */
	for (i = 0; i < ctx->source_count; i++) {
		olen = 0;
		ctx->source[i].f_source(ctx->source[i].p_source, buf, JHD_TLS_ENTROPY_MAX_GATHER, &olen);
		if (olen > 0) {
			entropy_update(ctx, (unsigned char) i, buf, olen);
			ctx->source[i].size += olen;
		}
	}

}

void jhd_tls_entropy_func(void *data, unsigned char *output, size_t len) {
	int  count = 0, i, done;
	jhd_tls_entropy_context *ctx = (jhd_tls_entropy_context *) data;
	unsigned char buf[JHD_TLS_ENTROPY_BLOCK_SIZE];

	if (len > JHD_TLS_ENTROPY_BLOCK_SIZE)
		len = JHD_TLS_ENTROPY_BLOCK_SIZE;
	/*
	 * Always gather extra entropy before a call
	 */
	do {
		if (count++ > ENTROPY_MAX_LOOP) {
			break;
		}
		entropy_gather_internal(ctx);
		done = 1;
		for (i = 0; i < ctx->source_count; i++)
			if (ctx->source[i].size < ctx->source[i].threshold)
				done = 0;
	} while (!done);

	memset(buf, 0, JHD_TLS_ENTROPY_BLOCK_SIZE);

#if defined(JHD_TLS_ENTROPY_SHA512_ACCUMULATOR)
	/*
	 * Note that at this stage it is assumed that the accumulator was started
	 * in a previous call to entropy_update(). If this is not guaranteed, the
	 * code below will fail.
	 */
	jhd_tls_sha512_finish_ret(&ctx->accumulator, buf);

	/*
	 * Reset accumulator and counters and recycle existing entropy
	 */
	jhd_tls_sha512_init(&ctx->accumulator);
	jhd_tls_sha512_starts_ret(&ctx->accumulator);
	jhd_tls_sha512_update_ret(&ctx->accumulator, buf, JHD_TLS_ENTROPY_BLOCK_SIZE);

	/*
	 * Perform second SHA-512 on entropy
	 */
	jhd_tls_sha512_ret(buf, JHD_TLS_ENTROPY_BLOCK_SIZE, buf);
#else /* JHD_TLS_ENTROPY_SHA512_ACCUMULATOR */
	jhd_tls_sha256_finish_ret( &ctx->accumulator, buf );

	/*
	 * Reset accumulator and counters and recycle existing entropy
	 */
	jhd_tls_sha256_init( &ctx->accumulator );
	jhd_tls_sha256_starts_ret_with_256( &ctx->accumulator);
	jhd_tls_sha256_update_ret( &ctx->accumulator, buf,JHD_TLS_ENTROPY_BLOCK_SIZE );

	/*
	 * Perform second SHA-256 on entropy
	 */
	jhd_tls_sha256_ret( buf, JHD_TLS_ENTROPY_BLOCK_SIZE, buf, 0 );
#endif /* JHD_TLS_ENTROPY_SHA512_ACCUMULATOR */

	for (i = 0; i < ctx->source_count; i++)
		ctx->source[i].size = 0;

	memcpy(output, buf, len);

}



