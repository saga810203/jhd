#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_hmac_drbg.h>
#include <string.h>

/*
 * HMAC_DRBG update, using optional additional data (10.1.2.2)
 */
void jhd_tls_hmac_drbg_update(jhd_tls_hmac_drbg_context *ctx, const unsigned char *additional, size_t add_len) {
	size_t md_len = ctx->md_info->size;
	unsigned char rounds = (additional != NULL && add_len != 0) ? 2 : 1;
	unsigned char sep[1];
	unsigned char K[JHD_TLS_MD_MAX_SIZE];

	for (sep[0] = 0; sep[0] < rounds; sep[0]++) {
		/* Step 1 or 4 */
		jhd_tls_md_hmac_starts(ctx->md_info,ctx->md_ctx,ctx->hmac_ctx);
		jhd_tls_md_hmac_update(ctx->md_info,ctx->md_ctx, ctx->V, md_len);
		jhd_tls_md_hmac_update(ctx->md_info,ctx->md_ctx, sep, 1);
		if (rounds == 2){
			jhd_tls_md_hmac_update(ctx->md_info,ctx->md_ctx, additional, add_len);
		}
		jhd_tls_md_hmac_finish(ctx->md_info,ctx->md_ctx,ctx->hmac_ctx, K,K);

		/* Step 2 or 5 */

		jhd_tls_md_hmac_init(ctx->md_info,K,md_len,ctx->hmac_ctx);
		jhd_tls_md_hmac_starts(ctx->md_info,ctx->md_ctx,ctx->hmac_ctx);
		jhd_tls_md_hmac_update(ctx->md_info,ctx->md_ctx,ctx->V, md_len);
		jhd_tls_md_hmac_finish(ctx->md_info,ctx->md_ctx,ctx->hmac_ctx,ctx->V,K);
	}
}

/*
 * Simplified HMAC_DRBG initialisation (for use with deterministic ECDSA)
 */
void jhd_tls_hmac_drbg_seed_buf(jhd_tls_hmac_drbg_context *ctx,const jhd_tls_md_info_t *md_info, const unsigned char *data, size_t data_len) {
	ctx->md_info = md_info;
	memset(ctx->V,0,md_info->size);
	jhd_tls_md_hmac_init(md_info,ctx->V,md_info->size,ctx->hmac_ctx);
	jhd_tls_md_hmac_starts(md_info,ctx->md_ctx,ctx->hmac_ctx);
	memset(ctx->V, 0x01, md_info->size);
	jhd_tls_hmac_drbg_update(ctx, data, data_len);
}

/*
 * HMAC_DRBG random function with optional additional data:
 * 10.1.2.5 (arabic) + 9.3 (Roman)
 */
void jhd_tls_hmac_drbg_random(void *p_rng, unsigned char *output, size_t out_len) {

	jhd_tls_hmac_drbg_context *ctx = (jhd_tls_hmac_drbg_context *) p_rng;
	size_t md_len = ctx->md_info->size;
	size_t left;
	unsigned char *out = output;
	/* II. Check request length */
	if (out_len > JHD_TLS_HMAC_DRBG_MAX_REQUEST) {
		out_len = JHD_TLS_HMAC_DRBG_MAX_REQUEST;
	}
	left = out_len;
	while (left != 0) {
		size_t use_len = left > md_len ? md_len : left;

		jhd_tls_md_hmac_starts(ctx->md_info,ctx->md_ctx,ctx->hmac_ctx);
		jhd_tls_md_hmac_update(ctx->md_info,ctx->md_ctx, ctx->V, md_len);
		jhd_tls_md_hmac_finish(ctx->md_info,ctx->md_ctx,ctx->hmac_ctx,ctx->V,ctx->V);

		memcpy(out, ctx->V, use_len);
		out += use_len;
		left -= use_len;
	}

	jhd_tls_hmac_drbg_update(ctx, NULL, 0);

}


