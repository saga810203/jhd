#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_ecdsa.h>
#include <string.h>
#include <tls/jhd_tls_asn1write.h>
#include <tls/jhd_tls_hmac_drbg.h>


/*
 * Derive a suitable integer for group grp from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
static int derive_mpi(const jhd_tls_ecp_group *grp, jhd_tls_mpi *x, const unsigned char *buf, size_t blen) {
	int ret;
	size_t n_size = (grp->nbits + 7) / 8;
	size_t use_size = blen > n_size ? n_size : blen;

	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_binary(x, buf, use_size));
	if (use_size * 8 > grp->nbits){
		JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(x, use_size * 8 - grp->nbits));
	}
	/* While at it, reduce modulo N */
	if (jhd_tls_mpi_cmp_mpi(x, &grp->N) >= 0){
		JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(x, x, &grp->N));
	}
	cleanup: return (ret);
}


/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
int jhd_tls_ecdsa_sign(jhd_tls_ecp_group *grp, jhd_tls_mpi *r, jhd_tls_mpi *s, const jhd_tls_mpi *private_key, const unsigned char *buf, size_t blen,
		const jhd_tls_md_info_t *md_info,unsigned char *data,size_t grp_len) {
	int ret, key_tries, sign_tries, blind_tries;
	jhd_tls_ecp_point R;
	jhd_tls_mpi k, e, t;
	jhd_tls_hmac_drbg_context rng_ctx;

	log_assert(grp->N.p!= NULL/*,"??????????????????"*/);
	log_assert(md_info != NULL/*,"invalid param md_info"*/);
	log_assert(!(jhd_tls_mpi_cmp_int(private_key, 1) < 0 || jhd_tls_mpi_cmp_mpi(private_key, &grp->N) >= 0)/*,"invalid param private_key"*/);



	jhd_tls_hmac_drbg_seed_buf(&rng_ctx, md_info, data, 2 * grp_len);

	jhd_tls_ecp_point_init(&R);
	jhd_tls_mpi_init(&k);
	jhd_tls_mpi_init(&e);
	jhd_tls_mpi_init(&t);

	sign_tries = 0;
	do {
		/*
		 * Steps 1-3: generate a suitable ephemeral keypair
		 * and set r = xR mod n
		 */
		key_tries = 0;
		do {
			JHD_TLS_MPI_CHK(jhd_tls_ecp_gen_keypair_specific(grp, &k, &R, jhd_tls_hmac_drbg_random, &rng_ctx));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_mod_mpi(r, &R.X, &grp->N));

			if (key_tries++ > 10) {
				log_err("generate a suitable ephemeral keypair error,time =%d",key_tries);
				ret = JHD_ERROR;
				goto cleanup;
			}
		} while (jhd_tls_mpi_cmp_int(r, 0) == 0);

		/*
		 * Step 5: derive MPI from hashed message
		 */
		JHD_TLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

		/*
		 * Generate a random value to blind inv_mod in next step,
		 * avoiding a potential timing leak.
		 */
		blind_tries = 0;
		do {
			size_t n_size = (grp->nbits + 7) / 8;
			JHD_TLS_MPI_CHK(jhd_tls_mpi_fill_random_specific(&t, n_size, jhd_tls_hmac_drbg_random, &rng_ctx));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&t, 8 * n_size - grp->nbits));

			/* See jhd_tls_ecp_gen_keypair() */
			if (++blind_tries > 30){
				log_err("Generate a random value to blind inv_mod  error,time =%d",blind_tries);
				ret = JHD_ERROR;
				goto cleanup;
			}
		} while (jhd_tls_mpi_cmp_int(&t, 1) < 0 || jhd_tls_mpi_cmp_mpi(&t, &grp->N) >= 0);

		/*
		 * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
		 */
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(s, r, private_key));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(&e, &e, s));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&e, &e, &t));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&k, &k, &t));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_inv_mod(s, &k, &grp->N));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(s, s, &e));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mod_mpi(s, s, &grp->N));

		if (sign_tries++ > 10) {
			log_err("sign  error,time =%d",sign_tries);
			ret = JHD_ERROR;
			goto cleanup;
		}
	} while (jhd_tls_mpi_cmp_int(s, 0) == 0);

	cleanup:
	jhd_tls_ecp_point_free(&R);
	jhd_tls_mpi_free(&k);
	jhd_tls_mpi_free(&e);
	jhd_tls_mpi_free(&t);
	return (ret);
}


/*
 * Deterministic signature wrapper
 */
int jhd_tls_ecdsa_sign_det(jhd_tls_ecp_group *grp, jhd_tls_mpi *r, jhd_tls_mpi *s, const jhd_tls_mpi *private_key, const unsigned char *buf, size_t blen,
		const jhd_tls_md_info_t *md_info) {
	int ret;
	unsigned char data[2 * JHD_TLS_ECP_MAX_BYTES];
	size_t grp_len = (grp->nbits + 7) / 8;
	jhd_tls_mpi h;
	jhd_tls_mpi_init(&h);
	/* Use private key and message hash (reduced) to initialize HMAC_DRBG */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_write_binary(private_key, data, grp_len));
	JHD_TLS_MPI_CHK(derive_mpi(grp, &h, buf, blen));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_write_binary(&h, data + grp_len, grp_len));
	ret = jhd_tls_ecdsa_sign(grp, r, s, private_key, buf, blen,md_info,data,grp_len);
	cleanup:
	jhd_tls_mpi_free(&h);
	return (ret);
}


/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message)
 */
int jhd_tls_ecdsa_verify(jhd_tls_ecp_group *grp, const unsigned char *buf, size_t blen, const jhd_tls_ecp_point *Q, const jhd_tls_mpi *r, const jhd_tls_mpi *s) {
	int ret= JHD_OK;
	jhd_tls_mpi e, s_inv, u1, u2;
	jhd_tls_ecp_point R;

	jhd_tls_ecp_point_init(&R);
	jhd_tls_mpi_init(&e);
	jhd_tls_mpi_init(&s_inv);
	jhd_tls_mpi_init(&u1);
	jhd_tls_mpi_init(&u2);

	/* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
//	if (grp->N.p == NULL)
//		return ( JHD_TLS_ERR_ECP_BAD_INPUT_DATA);
	log_assert(grp->N.p  != NULL/*,"??????????????????"*/);

	/*
	 * Step 1: make sure r and s are in range 1..n-1
	 */
	if (jhd_tls_mpi_cmp_int(r, 1) < 0 || jhd_tls_mpi_cmp_mpi(r, &grp->N) >= 0 || jhd_tls_mpi_cmp_int(s, 1) < 0 || jhd_tls_mpi_cmp_mpi(s, &grp->N) >= 0) {
		ret = JHD_ERROR;
		goto cleanup;
	}

	/*
	 * Additional precaution: make sure Q is valid
	 */
	JHD_TLS_MPI_CHK(jhd_tls_ecp_check_pubkey(grp, Q));

	/*
	 * Step 3: derive MPI from hashed message
	 */
	JHD_TLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

	/*
	 * Step 4: u1 = e / s mod n, u2 = r / s mod n
	 */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_inv_mod(&s_inv, s, &grp->N));

	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&u1, &e, &s_inv));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mod_mpi(&u1, &u1, &grp->N));

	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&u2, r, &s_inv));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mod_mpi(&u2, &u2, &grp->N));

	/*
	 * Step 5: R = u1 G + u2 Q
	 *
	 * Since we're not using any secret data, no need to pass a RNG to
	 * jhd_tls_ecp_mul() for countermesures.
	 */
	JHD_TLS_MPI_CHK(jhd_tls_ecp_muladd(grp, &R, &u1, &grp->G, &u2, Q));

	if (jhd_tls_ecp_is_zero(&R)) {
		ret = JHD_ERROR;
		goto cleanup;
	}

	/*
	 * Step 6: convert xR to an integer (no-op)
	 * Step 7: reduce xR mod n (gives v)
	 */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mod_mpi(&R.X, &R.X, &grp->N));

	/*
	 * Step 8: check if v (that is, R.X) is equal to r
	 */
	if (jhd_tls_mpi_cmp_mpi(&R.X, r) != 0) {
		ret = JHD_TLS_ERR_ECP_VERIFY_FAILED;
		goto cleanup;
	}

	cleanup: jhd_tls_ecp_point_free(&R);
	jhd_tls_mpi_free(&e);
	jhd_tls_mpi_free(&s_inv);
	jhd_tls_mpi_free(&u1);
	jhd_tls_mpi_free(&u2);

	return (ret);
}


/*
 * Convert a signature (given by context) to ASN.1
 */
static int ecdsa_signature_to_asn1(const jhd_tls_mpi *r, const jhd_tls_mpi *s, unsigned char *sig, size_t *slen) {
	int ret;
	unsigned char buf[JHD_TLS_ECDSA_MAX_LEN];
	unsigned char *p = buf + sizeof(buf);
	size_t len = 0;
	JHD_TLS_ASN1_CHK_ADD(len, jhd_tls_asn1_write_mpi(&p, buf, s));
	JHD_TLS_ASN1_CHK_ADD(len, jhd_tls_asn1_write_mpi(&p, buf, r));
	JHD_TLS_ASN1_CHK_ADD(len, jhd_tls_asn1_write_len(&p, buf, len));
	JHD_TLS_ASN1_CHK_ADD(len, jhd_tls_asn1_write_tag( &p, buf, JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ));
	memcpy(sig, p, len);
	*slen = len;
	return JHD_OK;
}

/*
 * Compute and write signature
 */
int jhd_tls_ecdsa_write_signature(void *ctx, const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hlen, unsigned char *sig,size_t *slen) {
	int ret;
	size_t len;
	jhd_tls_mpi r, s,private_key;

	jhd_tls_mpi_init(&r);
	jhd_tls_mpi_init(&s);
	jhd_tls_mpi_init(&private_key);

	if(JHD_OK !=jhd_tls_mpi_decode(((jhd_tls_ecdsa_context*)ctx)->encode_ctx,JHD_TLS_ECDSA_ENCODE_CTX_LEN,&private_key,&len)){
		log_err("jhd_tls_mpi_decode(............)=%d",-1);
		ret = JHD_ERROR;
		goto cleanup;
	}
	if(JHD_OK !=(ret =(jhd_tls_ecdsa_sign_det(((jhd_tls_ecdsa_context*)ctx)->grp, &r, &s, &private_key, hash, hlen, md_info)))){
		log_err("jhd_tls_ecdsa_sign_det(....)=%d",ret);
		ret = JHD_ERROR;
		goto cleanup;
	}
	JHD_TLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig, slen));
	cleanup: jhd_tls_mpi_free(&r);
	jhd_tls_mpi_free(&s);
	jhd_tls_mpi_free(&private_key);
	return (ret);
}

/*
 * Read and check signature
 */
int jhd_tls_ecdsa_read_signature(void *ctx,const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hlen, const unsigned char *sig, size_t slen) {
	int ret;
	size_t len;
	unsigned char *p = (unsigned char *) sig;
	const unsigned char *end = sig + slen;
	jhd_tls_ecp_keypair kp;

	jhd_tls_mpi r, s;
	(void)md_info;
	jhd_tls_mpi_init(&r);
	jhd_tls_mpi_init(&s);
	jhd_tls_ecp_keypair_init(&kp);

	if ((ret = jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != 0) {
		goto cleanup;
	}

	if (p + len != end) {
		ret = JHD_ERROR;
		goto cleanup;
	}

	if ((ret = jhd_tls_asn1_get_mpi(&p, end, &r)) != 0 || (ret = jhd_tls_asn1_get_mpi(&p, end, &s)) != 0) {
		goto cleanup;
	}

	if(JHD_OK !=(ret == jhd_tls_ecdsa_to_keypair((jhd_tls_ecdsa_context*)ctx,&kp))){
		goto cleanup;
	}
#ifdef JHD_LOG_LEVEL_INFO
	if(JHD_OK !=(ret = jhd_tls_ecdsa_context_check((jhd_tls_ecdsa_context*)ctx,&kp))){
		goto cleanup;
	}
#endif
	if ((ret = jhd_tls_ecdsa_verify(((jhd_tls_ecdsa_context*)ctx)->grp, hash, hlen, &kp.public_key, &r, &s)) != 0){
		goto cleanup;
	}
	/* At this point we know that the buffer starts with a valid signature.
	 * Return 0 if the buffer just contains the signature, and a specific
	 * error code if the valid signature is followed by more data. */
	if (p != end){
		ret = JHD_ERROR;
	}
	cleanup: jhd_tls_mpi_free(&r);
	jhd_tls_mpi_free(&s);
	jhd_tls_ecp_keypair_free(&kp);
	return (ret);
}


/*
 * Generate key pair
 */
int jhd_tls_ecdsa_genkey(jhd_tls_ecdsa_context *ctx, jhd_tls_ecp_group_id gid) {
	int ret;
    jhd_tls_ecp_keypair kp;
	jhd_tls_ecp_keypair_init(&kp);
	kp.grp = jhd_tls_ecp_group_get(gid);
	log_assert(kp.grp!= NULL/*,"bug???????"*/);
	ret =  jhd_tls_ecp_gen_keypair(ctx->grp,&kp.private_key, &kp.public_key);
	if(ret == JHD_OK){
		ret = jhd_tls_ecdsa_from_keypair(ctx,&kp);
#ifdef JHD_LOG_LEVEL_INFO
	if(ret == JHD_OK){
		ret = jhd_tls_ecdsa_context_check(ctx,&kp);
	}
#endif
	}
	jhd_tls_ecp_keypair_free(&kp);
	return ret;
}


/*
 * Set context from an jhd_tls_ecp_keypair
 */
int jhd_tls_ecdsa_from_keypair(jhd_tls_ecdsa_context *ctx, const jhd_tls_ecp_keypair *key) {
	int ret;
	char * p;
    size_t len,olen;
	p = ctx->encode_ctx;
	len = JHD_TLS_ECDSA_ENCODE_CTX_LEN;
    ctx->grp = key->grp;
	if(JHD_OK !=(ret =jhd_tls_mpi_encode(p,len,&key->private_key,&olen))){
		log_err("%s","encode ecdsa->private_key error");
		ret = JHD_ERROR;
		goto cleanup;
	}
	p+=olen;
	len-=olen;
	if(JHD_OK !=(ret =jhd_tls_mpi_encode(p,len,&key->public_key.X,&olen))){
		log_err("%s","encode ecdsa->public_key.X error");
		ret = JHD_ERROR;
		goto cleanup;
	}
	p+=olen;
	len-=olen;
	if(JHD_OK !=(ret =jhd_tls_mpi_encode(p,len,&key->public_key.Y,&olen))){
		log_err("%s","encode ecdsa->public_key.Y error");
		ret = JHD_ERROR;
		goto cleanup;
	}
	p+=olen;
	len-=olen;
	if(JHD_OK !=(ret =jhd_tls_mpi_encode(p,len,&key->public_key.Z,&olen))){
		log_err("%s","encode ecdsa->public_key.Z error");
		ret = JHD_ERROR;
		goto cleanup;
	}
	ret = JHD_OK;
cleanup:
	return (ret);
}
int jhd_tls_ecdsa_to_keypair(const jhd_tls_ecdsa_context *ctx, jhd_tls_ecp_keypair *key){
	int ret;
	const char *p;
    size_t len,olen;
	p = ctx->encode_ctx;
	len = JHD_TLS_ECDSA_ENCODE_CTX_LEN;
	key->grp = ctx->grp;

	if(JHD_OK !=(ret =jhd_tls_mpi_decode(p,len,&key->private_key,&olen))){
			log_err("%s","decode ecdsa->private_key error");
			ret = JHD_ERROR;
			goto cleanup;
		}
		p+=olen;
		len-=olen;
		if(JHD_OK !=(ret =jhd_tls_mpi_decode(p,len,&key->public_key.X,&olen))){
			log_err("%s","decode ecdsa->public_key.X error");
			ret = JHD_ERROR;
			goto cleanup;
		}
		p+=olen;
		len-=olen;
		if(JHD_OK !=(ret =jhd_tls_mpi_decode(p,len,&key->public_key.Y,&olen))){
			log_err("%s","decode ecdsa->public_key.Y error");
			ret = JHD_ERROR;
			goto cleanup;
		}
		p+=olen;
		len-=olen;
		if(JHD_OK !=(ret =jhd_tls_mpi_decode(p,len,&key->public_key.Z,&olen))){
			log_err("%s","decode ecdsa->public_key.Z error");
			ret = JHD_ERROR;
			goto cleanup;
		}
		ret = JHD_OK;
	cleanup:
		return (ret);
}
#ifdef JHD_LOG_LEVEL_INFO
int jhd_tls_ecdsa_context_check(const jhd_tls_ecdsa_context *ecdsa,jhd_tls_ecp_keypair *kp){

	jhd_tls_ecdsa_context ee;
	jhd_tls_ecp_keypair kk;

	int ret = JHD_OK;

	jhd_tls_ecp_keypair_init(&kk);
	jhd_tls_platform_zeroize(&ee,sizeof(jhd_tls_ecdsa_context));

	if(JHD_OK !=(ret = jhd_tls_ecdsa_to_keypair(ecdsa,&kk))){
		goto func_return;
	}
	if(JHD_OK !=(ret = jhd_tls_ecdsa_from_keypair(&ee,kp))){
		goto func_return;
	}
	if(JHD_OK !=(ret = jhd_tls_ecp_keypair_equals(&kk,kp))){
		goto func_return;
	}
	if(0!= memcmp(&ee,ecdsa,sizeof(jhd_tls_ecdsa_context))){
		ret = JHD_ERROR;
	}
	func_return:
	jhd_tls_ecp_keypair_free(&kk);
	return ret;
}
#endif


