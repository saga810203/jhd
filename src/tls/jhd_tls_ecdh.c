#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>



#include <tls/jhd_tls_ecdh.h>
#include <tls/jhd_tls_platform.h>
#include <string.h>


#if !defined(JHD_TLS_INLINE)

/*
 * Generate public key: simple wrapper around jhd_tls_ecp_gen_keypair
 */
int jhd_tls_ecdh_gen_public(jhd_tls_ecp_group *grp, jhd_tls_mpi *private_key, jhd_tls_ecp_point *public_key) {
	return jhd_tls_ecp_gen_keypair(grp, private_key, public_key);
}
#endif


/*
 * Compute shared secret (SEC1 3.3.1)
 */
int jhd_tls_ecdh_compute_shared(jhd_tls_ecp_group *grp, jhd_tls_mpi *z, const jhd_tls_ecp_point *public_key, const jhd_tls_mpi *private_key) {
	int ret;
	jhd_tls_ecp_point P;

	jhd_tls_ecp_point_init(&P);

	/*
	 * Make sure Q is a valid pubkey before using it
	 */
	JHD_TLS_MPI_CHK(jhd_tls_ecp_check_pubkey(grp, public_key));

	JHD_TLS_MPI_CHK(jhd_tls_ecp_mul(grp, &P, private_key, public_key));

	if (jhd_tls_ecp_is_zero(&P)) {
		ret =JHD_ERROR;
		goto cleanup;
	}

	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(z, &P.X));

	cleanup:
	jhd_tls_ecp_point_free(&P);

	return (ret);
}








/*
 * Setup and write the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int jhd_tls_ecdh_make_params(jhd_tls_ecdh_context *ctx, size_t *olen, unsigned char *buf, size_t blen,void *event) {
	size_t pt_len;
	jhd_tls_mpi private_key;
	jhd_tls_ecp_point public_key;

	log_assert((ctx->grp->nbits + 7) / 8 <= JHD_TLS_ECDH_CONTEXT_PRIVATE_KEY_LEN/*,"invalid jhd_tls_ecp_group.nbits" */);

	jhd_tls_mpi_init(&private_key);
	jhd_tls_ecp_point_init(&public_key);
	if (jhd_tls_ecdh_gen_public(ctx->grp, &private_key, &public_key) != JHD_OK){
		log_err("call jhd_tls_ecdh_gen_public fail");
		goto func_error;
	}
	if(jhd_tls_mpi_encode(ctx->private_key,JHD_TLS_ECDH_CONTEXT_PRIVATE_KEY_LEN,&private_key,&pt_len)!= JHD_OK){
		log_err("call jhd_tls_mpi_encode fail");
		goto func_error;
	}
	log_assert(blen >=3/*,"invalid param blen"*/);

	jhd_tls_ecp_tls_write_group(ctx->grp,buf);
	buf += 3;
	blen -= 3;
	if (jhd_tls_ecp_tls_write_point(ctx->grp, &public_key, ctx->point_format, &pt_len, buf, blen)!= 0){
		log_err("call jhd_tls_ecp_tls_write_point fail");
		goto func_error;
	}
	*olen = 3 + pt_len;
	jhd_tls_mpi_free(&private_key);
	jhd_tls_ecp_point_free(&public_key);
	return JHD_OK;
	func_error:
	jhd_tls_mpi_free(&private_key);
	jhd_tls_ecp_point_free(&public_key);
	return JHD_ERROR;

}

/*
 * Read the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int jhd_tls_ecdh_read_params(jhd_tls_ecdh_context *ctx,const unsigned char **buf, const unsigned char *end) {
	size_t len ;
	jhd_tls_ecp_point public_key;

	if (JHD_OK != jhd_tls_ecp_tls_read_group(&ctx->grp, buf, end - *buf)){
		return JHD_ERROR;
	}
	len = end - *buf;
	log_assert(len <= JHD_TLS_ECDH_CONTEXT_REMOTE_PUBLIC_KEY_LEN/*,"ecp remote public key too large"*/);
	memcpy(ctx->remote_public_key_buf,*buf,len);
	jhd_tls_ecp_point_init(&public_key);
	if (JHD_OK != jhd_tls_ecp_tls_read_point(ctx->grp, &public_key, buf, len)){
		jhd_tls_ecp_point_free(&public_key);
		return JHD_ERROR;
	}
	jhd_tls_ecp_point_free(&public_key);
	return JHD_OK;
}

///*
// * Get parameters from a keypair
// */
//int jhd_tls_ecdh_get_params(jhd_tls_ecdh_context *ctx, const jhd_tls_ecp_keypair *key, jhd_tls_ecdh_side side) {
//	int ret;
//
//	if ((ret = jhd_tls_ecp_group_copy(&ctx->grp, &key->grp)) != 0)
//		return (ret);
//
//	/* If it's not our key, just import the public part as Qp */
//	if (side == JHD_TLS_ECDH_THEIRS)
//		return (jhd_tls_ecp_copy(&ctx->remote_public_key, &key->public_key));
//
//	/* Our key: import public (as Q) and private parts */
//	if (side != JHD_TLS_ECDH_OURS)
//		return ( JHD_TLS_ERR_ECP_BAD_INPUT_DATA);
//
//	if ((ret = jhd_tls_ecp_copy(&ctx->public_key, &key->public_key)) != 0 || (ret = jhd_tls_mpi_copy(&ctx->private_key, &key->private_key)) != 0)
//		return (ret);
//
//	return (0);
//}

/*
 * Setup and export the client public value
 */
int jhd_tls_ecdh_make_public(jhd_tls_ecdh_context *ctx, size_t *olen, unsigned char *buf, size_t blen) {
	jhd_tls_ecp_point public_key;
	jhd_tls_mpi private_key;

	jhd_tls_mpi_init(&private_key);
	jhd_tls_ecp_point_init(&public_key);
	if (jhd_tls_ecdh_gen_public(ctx->grp, &private_key,&public_key) != 0){
		goto func_error;
	}
	if(jhd_tls_ecp_tls_write_point(ctx->grp, &public_key, ctx->point_format, olen, buf, blen) != 0){
		goto func_error;
	}
	if(jhd_tls_mpi_encode(ctx->private_key,JHD_TLS_ECDH_CONTEXT_PRIVATE_KEY_LEN,&private_key,&blen)!= JHD_OK){
		goto func_error;
	}
	jhd_tls_mpi_free(&private_key);
	jhd_tls_ecp_point_free(&public_key);
	return JHD_OK;
	func_error:
	jhd_tls_mpi_free(&private_key);
	jhd_tls_ecp_point_free(&public_key);
	return JHD_ERROR;
}

/*
 * Parse and import the client's public value
 */
int jhd_tls_ecdh_read_public(jhd_tls_ecdh_context *ctx,jhd_tls_ecp_point *public_key, const unsigned char *buf, size_t blen) {
	const unsigned char *p = buf;
	if (JHD_OK != jhd_tls_ecp_tls_read_point(ctx->grp,/*&ctx->remote_public_key*/ public_key, &p, blen)){
		return JHD_ERROR;
	}
	if ((size_t) (p - buf) != blen){
		return JHD_ERROR;
	}
	return JHD_OK;
}

/*
 * Derive and export the shared secret
 */
int jhd_tls_ecdh_calc_secret(jhd_tls_ecdh_context *ctx,jhd_tls_ecp_point *public_key, size_t *olen, unsigned char *buf, size_t blen) {
	int ret;
	size_t slen;
	jhd_tls_mpi z;
	jhd_tls_mpi pkey;

	jhd_tls_mpi_init(&pkey);
	jhd_tls_mpi_init(&z);

	if(JHD_OK != jhd_tls_mpi_decode(ctx->private_key,JHD_TLS_ECDH_CONTEXT_PRIVATE_KEY_LEN,&pkey,&slen)){
		return JHD_ERROR;
	}

	if ((ret = jhd_tls_ecdh_compute_shared(ctx->grp, &z,/*&ctx->remote_public_key*/public_key, &pkey)) != 0) {
		goto cleanup;
	}

	if (jhd_tls_mpi_size(&z) > blen){
		ret = JHD_ERROR;
		goto cleanup;
	}

	*olen = ctx->grp->pbits / 8 + ((ctx->grp->pbits % 8) != 0);
	ret =jhd_tls_mpi_write_binary(&z, buf, *olen);
	cleanup:
	jhd_tls_mpi_free(&pkey);
	jhd_tls_mpi_free(&z);
	return ret;


}


