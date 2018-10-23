#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>

#include <tls/jhd_tls_pk.h>
#include <tls/jhd_tls_pk_internal.h>


#include <tls/jhd_tls_rsa.h>


#include <tls/jhd_tls_ecp.h>


#include <tls/jhd_tls_ecdsa.h>
#include <tls/jhd_tls_md_internal.h>

#include <limits.h>
#include <stdint.h>

#if !defined(JHD_TLS_INLINE)
void jhd_tls_pk_init(jhd_tls_pk_context *ctx) {
	ctx->pk_info = NULL;
	ctx->pk_ctx = NULL;
}

/*
 * Tell if a PK can do the operations of the given type
 */
jhd_tls_bool jhd_tls_pk_can_do(const jhd_tls_pk_context *ctx,const jhd_tls_pk_info_t *info) {
	return (ctx->pk_info == info);
}
#endif



///*
// * Initialise context
// */
//int jhd_tls_pk_setup(jhd_tls_pk_context *ctx, const jhd_tls_pk_info_t *info) {
//	if ((ctx->pk_ctx = info->pk_ctx_alloc_func()) == NULL)
//		return ( JHD_TLS_ERR_PK_ALLOC_FAILED);
//	ctx->pk_info = info;
//	return (0);
//}



/*
 * Verify a signature
 */
int jhd_tls_pk_verify(jhd_tls_pk_context *ctx, const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len) {
	if(hash_len == 0){
		log_assert(md_info != NULL);
		hash_len =  jhd_tls_md_get_size(md_info);
	}
	return (ctx->pk_info->pk_verify_func(ctx->pk_ctx, md_info, hash, hash_len, sig, sig_len));
}

///*
// * Verify a signature with options
// */
//int jhd_tls_pk_verify_ext(const jhd_tls_pk_info_t *pk_info, const void *options, jhd_tls_pk_context *ctx,const jhd_tls_md_info_t *md_info, const unsigned char *hash,
//        size_t hash_len, const unsigned char *sig, size_t sig_len) {
//	if (jhd_tls_pk_can_do(ctx,pk_info)){
//	/* General case: no options */
//		if (options != NULL)
//			return JHD_ERROR;
//
//		return (jhd_tls_pk_verify(ctx, md_info, hash, hash_len, sig, sig_len));
//	}
//	return ( JHD_TLS_ERR_PK_TYPE_MISMATCH);
//}

/*
 * Make a signature
 */
int jhd_tls_pk_sign(jhd_tls_pk_context *ctx,const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t *sig_len) {
	if(hash_len == 0){
		log_assert(md_info != NULL/*,"bug???????????????????"*/);
		hash_len =  jhd_tls_md_get_size(md_info);
	}
	return (ctx->pk_info->pk_sign_func(ctx->pk_ctx, md_info, hash, hash_len, sig, sig_len));
}

/*
 * Decrypt message
 */
int jhd_tls_pk_decrypt(jhd_tls_pk_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize) {
	log_assert((ctx !=NULL) && (ctx->pk_info != NULL) &&(ctx->pk_info->pk_decrypt_func != NULL)/*,"(ctx !=NULL) && (ctx->pk_info != NULL) &&(ctx->pk_info->pk_decrypt_func != NULL)"*/);
	return (ctx->pk_info->pk_decrypt_func(ctx->pk_ctx, input, ilen, output, olen, osize));
}

/*
 * Encrypt message
 */
int jhd_tls_pk_encrypt(jhd_tls_pk_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t osize) {
	log_assert((ctx !=NULL) && (ctx->pk_info != NULL) &&(ctx->pk_info->pk_encrypt_func != NULL));
	return (ctx->pk_info->pk_encrypt_func(ctx->pk_ctx, input, ilen, output, olen, osize));
}

/*
 * Check public-private key pair
 */
int jhd_tls_pk_check_pair(const jhd_tls_pk_context *pub, const jhd_tls_pk_context *prv) {
	log_assert(pub != NULL && pub->pk_info != NULL && prv != NULL && prv->pk_info != NULL && prv->pk_info->pk_check_pair_func != NULL && pub->pk_info == prv->pk_info);
	return (prv->pk_info->pk_check_pair_func(pub->pk_ctx, prv->pk_ctx));
}

/*
 * Get key size in bits
 */
size_t jhd_tls_pk_get_bitlen(const jhd_tls_pk_context *ctx) {
	log_assert(ctx != NULL && ctx->pk_info != NULL);
	return (ctx->pk_info->pk_get_bitlen(ctx->pk_ctx));
}


/*
 * Access the PK type name
 */
const char *jhd_tls_pk_get_name(const jhd_tls_pk_context *ctx) {
	log_assert(ctx != NULL && ctx->pk_info != NULL/*,"ctx != NULL && ctx->pk_info != NULL"*/);
	return (ctx->pk_info->name);
}




