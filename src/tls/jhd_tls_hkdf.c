#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_sha512.h>

#include <string.h>
#include <tls/jhd_tls_hkdf.h>

void jhd_tls_hkdf(const jhd_tls_md_info_t *md, const unsigned char *salt, size_t salt_len, const unsigned char *ikm, size_t ikm_len, const unsigned char *info,
        size_t info_len, unsigned char *okm, size_t okm_len) {
	unsigned char prk[JHD_TLS_MD_MAX_SIZE];
	jhd_tls_hkdf_extract(md, salt, salt_len, ikm, ikm_len, prk);
	jhd_tls_hkdf_expand(md, prk, md->size, info, info_len, okm, okm_len);
}

void jhd_tls_hkdf_extract(const jhd_tls_md_info_t *md, const unsigned char *salt, size_t salt_len, const unsigned char *ikm, size_t ikm_len, unsigned char *prk) {
	unsigned char null_salt[JHD_TLS_MD_MAX_SIZE] = { '\0' };

	if (salt == NULL) {
		size_t hash_len;

		hash_len = jhd_tls_md_get_size(md);
		salt = null_salt;
		salt_len = hash_len;
	}
	jhd_tls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk);
}

void jhd_tls_hkdf_expand(const jhd_tls_md_info_t *md, const unsigned char *prk, uint8_t prk_len, const unsigned char *info, size_t info_len, unsigned char *okm,
        size_t okm_len) {
	size_t hash_len;
	size_t where = 0;
	size_t n;
	size_t t_len = 0;
	size_t i;
	unsigned char md_ctx[sizeof(jhd_tls_sha512_context)];
	unsigned char md_hmac_ctx[256];
	unsigned char t[JHD_TLS_MD_MAX_SIZE];
	log_assert(NULL != okm/*,"okm is NULL"*/);

	hash_len = md->size;

	log_assert(prk_len >= hash_len/*,"invalid param prk_len"*/);

	if (info == NULL) {
		info = (const unsigned char *) "";
		info_len = 0;
	}

	n = okm_len / hash_len;

	if ((okm_len % hash_len) != 0) {
		n++;
	}
	log_assert(n<=255/*,"invalid param okm_len"*/);


	/* RFC 5869 Section 2.3. */
	for (i = 1; i <= n; i++) {
		size_t num_to_copy;
		unsigned char c = i & 0xff;

		jhd_tls_md_hmac_init(md,prk, prk_len,md_hmac_ctx);
		jhd_tls_md_hmac_starts(md,md_ctx,md_hmac_ctx);
		jhd_tls_md_hmac_update(md,md_ctx,t,t_len);
		jhd_tls_md_hmac_update(md,md_ctx,info, info_len);

		jhd_tls_md_hmac_update(md,md_ctx,&c,1);

		/* The constant concatenated to the end of each t(n) is a single octet.
		 * */
		jhd_tls_md_hmac_finish(md,md_ctx,md_hmac_ctx,t,t);
		num_to_copy = i != n ? hash_len : okm_len - where;
		memcpy(okm + where, t, num_to_copy);
		where += hash_len;
		t_len = hash_len;
	}
}


