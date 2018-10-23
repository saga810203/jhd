#include <tls/jhd_tls_config.h>

#include <tls/jhd_tls_pk_internal.h>
#include <tls/jhd_tls_rsa.h>

#include <string.h>


#include <tls/jhd_tls_ecp.h>


#include <tls/jhd_tls_ecdsa.h>
#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_platform.h>

#include <limits.h>
#include <stdint.h>


static void rsa_ctx_init(void *ctx){
	   memset( ctx, 0, sizeof( jhd_tls_serializa_rsa_context) );
}
static size_t rsa_get_bitlen(const void *ctx) {
	return (((jhd_tls_serializa_rsa_context*)ctx)->len)<<3;
}

static int rsa_verify_wrap(void *ctx, const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len) {
	jhd_tls_rsa_context rsa;


	const jhd_tls_serializa_rsa_context * rsa_s = (jhd_tls_serializa_rsa_context *) ctx;
	size_t rsa_len = rsa_s->len;

	if (sig_len < rsa_len){
		return JHD_ERROR;
	}
	jhd_tls_rsa_init(&rsa,0,NULL);


	if(JHD_OK !=jhd_tls_rsa_deserialize(&rsa,rsa_s)){
		goto func_error;
	}

#ifdef JHD_LOG_LEVEL_INFO
	if(JHD_OK !=jhd_tls_rsa_serialize_check(&rsa,rsa_s)){
		goto func_error;
	}
#endif



	if (JHD_OK != jhd_tls_rsa_pkcs1_verify(&rsa,JHD_TLS_RSA_PUBLIC, md_info, (unsigned int) hash_len, hash, sig)){
		goto func_error;
	}

	/* The buffer contains a valid signature followed by extra data.
	 * We have a special error code for that so that so that callers can
	 * use jhd_tls_pk_verify() to check "Does the buffer start with a
	 * valid signature?" and not just "Does the buffer contain a valid
	 * signature?". */
	if (sig_len > rsa_len){
		goto func_error;
	}
	jhd_tls_rsa_free(&rsa);
	return (0);
	func_error:
	jhd_tls_rsa_free(&rsa);
	return JHD_ERROR;
}

static int rsa_sign_wrap(void *ctx, const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t *sig_len) {
	jhd_tls_rsa_context rsa;
	int ret ;
	const jhd_tls_serializa_rsa_context * rsa_s = (jhd_tls_serializa_rsa_context *) ctx;

	*sig_len = rsa_s->len;
	jhd_tls_rsa_init(&rsa,0,NULL);
	ret =jhd_tls_rsa_deserialize(&rsa,rsa_s);
#ifdef JHD_LOG_LEVEL_INFO
	if(ret == JHD_OK){
		ret =jhd_tls_rsa_serialize_check(&rsa,rsa_s);
	}
#endif
	if(ret  == JHD_OK){
		ret = (jhd_tls_rsa_pkcs1_sign(&rsa, JHD_TLS_RSA_PRIVATE, md_info, (unsigned int) hash_len, hash, sig));
	}
	jhd_tls_rsa_free(&rsa);
	return ret;
}

static int rsa_decrypt_wrap(void *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize) {
	jhd_tls_rsa_context rsa;
	int ret ;
	const jhd_tls_serializa_rsa_context * rsa_s = (jhd_tls_serializa_rsa_context *) ctx;

	if (ilen != rsa_s->len){
		return JHD_ERROR;
	}
	jhd_tls_rsa_init(&rsa,0,NULL);
	ret = jhd_tls_rsa_deserialize(&rsa,rsa_s);
#ifdef JHD_LOG_LEVEL_INFO
	if(ret == JHD_OK){
		ret =jhd_tls_rsa_serialize_check(&rsa,rsa_s);
	}
#endif
	if(ret == JHD_OK){
		ret = jhd_tls_rsa_pkcs1_decrypt(&rsa,JHD_TLS_RSA_PRIVATE, olen, input, output, osize);
	}
	jhd_tls_rsa_free(&rsa);
	return ret;
}

static int rsa_encrypt_wrap(void *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize) {
	jhd_tls_rsa_context rsa;
	int ret ;
	const jhd_tls_serializa_rsa_context * rsa_s = (jhd_tls_serializa_rsa_context *) ctx;
	*olen = rsa_s->len;
	if (*olen > osize)
		return JHD_ERROR;
	jhd_tls_rsa_init(&rsa,0,NULL);
	ret = jhd_tls_rsa_deserialize(&rsa, rsa_s);
#ifdef JHD_LOG_LEVEL_INFO
	if(ret == JHD_OK){
		ret =jhd_tls_rsa_serialize_check(&rsa,rsa_s);
	}
#endif
	if (ret == JHD_OK) {
		ret = (jhd_tls_rsa_pkcs1_encrypt(&rsa, JHD_TLS_RSA_PUBLIC, ilen, input, output));
	}
	jhd_tls_rsa_free(&rsa);
	return ret;
}

static int rsa_check_pair_wrap(const void *pub, const void *prv) {
	jhd_tls_rsa_context rsa_pub,rsa_prv;
	int ret ;
	jhd_tls_rsa_init(&rsa_pub,0,NULL);
	jhd_tls_rsa_init(&rsa_prv,0,NULL);

	ret = jhd_tls_rsa_deserialize(&rsa_pub,(const jhd_tls_serializa_rsa_context *)pub);
#ifdef JHD_LOG_LEVEL_INFO
	if(ret == JHD_OK){
		ret =jhd_tls_rsa_serialize_check(&rsa_pub,(const jhd_tls_serializa_rsa_context *)pub);
	}
#endif
	if(ret == JHD_OK){
		ret = jhd_tls_rsa_deserialize(&rsa_prv,(const jhd_tls_serializa_rsa_context *)prv);
	}
#ifdef JHD_LOG_LEVEL_INFO
	if(ret == JHD_OK){
		ret =jhd_tls_rsa_serialize_check(&rsa_prv,(const jhd_tls_serializa_rsa_context *)prv);
	}
#endif
	if(ret == JHD_OK){
		ret = (jhd_tls_rsa_check_pub_priv((const jhd_tls_rsa_context *) &rsa_pub, (const jhd_tls_rsa_context *) &rsa_prv));
	}
	jhd_tls_rsa_free(&rsa_pub);
	jhd_tls_rsa_free(&rsa_prv);
	return ret;
}


static void ecdsa_ctx_init(void *ctx){
	jhd_tls_mpi d;
	char * p;
	 size_t len,olen;
	jhd_tls_ecdsa_context *ecdsa_ctx = ctx;
	ecdsa_ctx->grp = NULL;
	jhd_tls_mpi_init(&d);
	p = ecdsa_ctx->encode_ctx;
	len = JHD_TLS_ECDSA_ENCODE_CTX_LEN;
	jhd_tls_mpi_encode(p,len,&d,&olen);
	p+=olen;
	len-=olen;
	jhd_tls_mpi_encode(p,len,&d,&olen);
	p+=olen;
	len-=olen;
	jhd_tls_mpi_encode(p,len,&d,&olen);
	p+=olen;
	len-=olen;
	jhd_tls_mpi_encode(p,len,&d,&olen);
	jhd_tls_mpi_free(&d);
}
//
//static size_t eckey_get_bitlen(const void *ctx) {
//	return (((jhd_tls_ecp_keypair *) ctx)->grp->pbits);
//}
static size_t ecdsa_get_bitlen(const void *ctx) {
	return (((jhd_tls_ecdsa_context *) ctx)->grp->pbits);
}

/* Forward declarations */


/*
static int eckey_verify_wrap(void *ctx, jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len) {
	int ret;
	jhd_tls_ecdsa_context ecdsa;

	jhd_tls_ecdsa_init(&ecdsa);

	if ((ret = jhd_tls_ecdsa_from_keypair(&ecdsa, ctx)) == 0)
		ret = ecdsa_verify_wrap(&ecdsa, md_info, hash, hash_len, sig, sig_len);

	jhd_tls_ecdsa_free(&ecdsa);

	return (ret);
}*/

/*static int eckey_sign_wrap(void *ctx, jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t *sig_len) {
	int ret;
	jhd_tls_ecdsa_context ecdsa;

	jhd_tls_ecdsa_init(&ecdsa);

	if ((ret = jhd_tls_ecdsa_from_keypair(&ecdsa, ctx)) == 0)
		ret = ecdsa_sign_wrap(&ecdsa, md_info, hash, hash_len, sig, sig_len);

	jhd_tls_ecdsa_free(&ecdsa);

	return (ret);
}*/

static int eckey_check_pair(const void *pub, const void *prv) {
	jhd_tls_ecp_keypair key_pub;
	jhd_tls_ecp_keypair key_prv;
	const jhd_tls_ecdsa_context *ecdsa_pub= pub;
	const jhd_tls_ecdsa_context *ecdsa_prv= prv;
	int ret ;

	jhd_tls_ecp_keypair_init(&key_pub);
	jhd_tls_ecp_keypair_init(&key_prv);

	ret = jhd_tls_ecdsa_to_keypair(ecdsa_pub,&key_pub);
	if(ret == JHD_OK){
		ret = jhd_tls_ecdsa_to_keypair(ecdsa_prv,&key_prv);
	}
#ifdef JHD_LOG_LEVEL_INFO
	if(ret == JHD_OK){
		ret =jhd_tls_ecdsa_context_check(ecdsa_pub,&key_pub);
	}
	if(ret == JHD_OK){
		ret =jhd_tls_ecdsa_context_check(ecdsa_prv,&key_prv);
	}
#endif
	if(ret == JHD_OK){
		ret = jhd_tls_ecp_check_pub_priv(&key_pub, &key_prv);
	}
	jhd_tls_ecp_keypair_free(&key_pub);
	jhd_tls_ecp_keypair_free(&key_prv);
	return ret;
}



/*
static void *eckey_alloc_wrap(void) {
	void *ctx = jhd_tls_malloc(sizeof(jhd_tls_ecp_keypair));

	if (ctx != NULL)
		jhd_tls_ecp_keypair_init(ctx);

	return (ctx);
}

static void eckey_free_wrap(void *ctx) {
	jhd_tls_ecp_keypair_free((jhd_tls_ecp_keypair *) ctx);
	jhd_tls_free(ctx);
}
*/


const jhd_tls_pk_info_t jhd_tls_ecdsa_info = {
		JHD_TLS_SSL_SIG_ECDSA,
		sizeof(jhd_tls_ecdsa_context),
		"ECDSA",
		ecdsa_ctx_init,
		ecdsa_get_bitlen, /* Compatible key structures */
		jhd_tls_ecdsa_read_signature,//verify_func
		jhd_tls_ecdsa_write_signature,//sign_func
		NULL,//decrypt_func
		NULL,//encrypt_func
		eckey_check_pair, /* Compatible key structures *///check_pair_func
//		eckey_debug, /* Compatible key structures */
};
const jhd_tls_pk_info_t jhd_tls_rsa_info = {
		JHD_TLS_SSL_SIG_RSA,
		sizeof(jhd_tls_serializa_rsa_context),
		"RSA",
		rsa_ctx_init,
		rsa_get_bitlen,
		rsa_verify_wrap,
		rsa_sign_wrap,
		rsa_decrypt_wrap,
        rsa_encrypt_wrap,
        rsa_check_pair_wrap,
};

