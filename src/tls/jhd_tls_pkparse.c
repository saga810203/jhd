#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_pk.h>
#include <tls/jhd_tls_asn1.h>
#include <tls/jhd_tls_oid.h>
#include <string.h>
#include <tls/jhd_tls_rsa.h>
#include <tls/jhd_tls_ecp.h>

#include <tls/jhd_tls_ecdsa.h>

#include <tls/jhd_tls_pem.h>
#include <tls/jhd_tls_pk_internal.h>

#include <tls/jhd_tls_platform.h>


/* Minimally parse an ECParameters buffer to and jhd_tls_asn1_buf
 *
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 *   specifiedCurve     SpecifiedECDomain -- = SEQUENCE { ... }
 *   -- implicitCurve   NULL
 * }
 */
static int pk_get_ecparams(unsigned char **p, const unsigned char *end, jhd_tls_asn1_buf *params) {
	int ret;
	if (end < *p )
		return JHD_ERROR;
	/* Tag may be either OID or SEQUENCE */
	params->tag = **p;
	if (params->tag != JHD_TLS_ASN1_OID && params->tag != ( JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) {
		return JHD_ERROR;
	}
	if ((ret = jhd_tls_asn1_get_tag(p, end, &params->len, params->tag)) != 0) {
		return JHD_ERROR;
	}

	params->p = *p;
	*p += params->len;

	if (*p != end)
		return JHD_ERROR;
	return JHD_OK;
}


/*
 * Parse a SpecifiedECDomain (SEC 1 C.2) and (mostly) fill the group with it.
 * WARNING: the resulting group should only be used with
 * pk_group_id_from_specified(), since its base point may not be set correctly
 * if it was encoded compressed.
 *
 *  SpecifiedECDomain ::= SEQUENCE {
 *      version SpecifiedECDomainVersion(ecdpVer1 | ecdpVer2 | ecdpVer3, ...),
 *      fieldID FieldID {{FieldTypes}},
 *      curve Curve,
 *      base ECPoint,
 *      order INTEGER,
 *      cofactor INTEGER OPTIONAL,
 *      hash HashAlgorithm OPTIONAL,
 *      ...
 *  }
 *
 * We only support prime-field as field type, and ignore hash and cofactor.
 */
static int pk_group_from_specified(const jhd_tls_asn1_buf *params, jhd_tls_ecp_group *grp) {
	int ret;
	unsigned char *p = params->p;
	const unsigned char * const end = params->p + params->len;
	const unsigned char *end_field, *end_curve;
	size_t len;
	int ver;

	/* SpecifiedECDomainVersion ::= INTEGER { 1, 2, 3 } */
	if (JHD_OK != jhd_tls_asn1_get_int(&p, end, &ver)){
		return JHD_ERROR;
	}

	if (ver < 1 || ver > 3){
		return JHD_ERROR;
	}

	/*
	 * FieldID { FIELD-ID:IOSet } ::= SEQUENCE { -- Finite field
	 *       fieldType FIELD-ID.&id({IOSet}),
	 *       parameters FIELD-ID.&Type({IOSet}{@fieldType})
	 * }
	 */
	if ((ret = jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != JHD_OK){
		return (ret);
	}
	end_field = p + len;

	/*
	 * FIELD-ID ::= TYPE-IDENTIFIER
	 * FieldTypes FIELD-ID ::= {
	 *       { Prime-p IDENTIFIED BY prime-field } |
	 *       { Characteristic-two IDENTIFIED BY characteristic-two-field }
	 * }
	 * prime-field OBJECT IDENTIFIER ::= { id-fieldType 1 }
	 */
	if ((ret = jhd_tls_asn1_get_tag(&p, end_field, &len, JHD_TLS_ASN1_OID)) != JHD_OK){
		return ret;
	}
	if (len != JHD_TLS_OID_SIZE(JHD_TLS_OID_ANSI_X9_62_PRIME_FIELD) || memcmp(p, JHD_TLS_OID_ANSI_X9_62_PRIME_FIELD, len) != 0) {
		return JHD_UNSUPPORTED;
	}

	p += len;

	/* Prime-p ::= INTEGER -- Field of size p. */
	if (JHD_OK !=  jhd_tls_asn1_get_mpi(&p, end_field, &grp->P)){
		return JHD_ERROR;
	}

	grp->pbits = jhd_tls_mpi_bitlen(&grp->P);

	if (p != end_field)
		return JHD_ERROR;

	/*
	 * Curve ::= SEQUENCE {
	 *       a FieldElement,
	 *       b FieldElement,
	 *       seed BIT STRING OPTIONAL
	 *       -- Shall be present if used in SpecifiedECDomain
	 *       -- with version equal to ecdpVer2 or ecdpVer3
	 * }
	 */
	if ((ret = jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != JHD_OK)
		return (ret);

	end_curve = p + len;

	/*
	 * FieldElement ::= OCTET STRING
	 * containing an integer in the case of a prime field
	 */
	if ((JHD_OK != jhd_tls_asn1_get_tag(&p, end_curve, &len, JHD_TLS_ASN1_OCTET_STRING)) ||
		(JHD_OK != jhd_tls_mpi_read_binary(&grp->A, p, len))) {
		return JHD_ERROR;
	}

	p += len;

	if ((JHD_OK != jhd_tls_asn1_get_tag(&p, end_curve, &len, JHD_TLS_ASN1_OCTET_STRING))||
		(JHD_OK != jhd_tls_mpi_read_binary(&grp->B, p, len))) {
		return JHD_ERROR;
	}

	p += len;

	/* Ignore seed BIT STRING OPTIONAL */
	if (JHD_OK == jhd_tls_asn1_get_tag(&p, end_curve, &len, JHD_TLS_ASN1_BIT_STRING)){
		p += len;
	}

	if (p != end_curve){
		return JHD_ERROR;
	}
	/*
	 * ECPoint ::= OCTET STRING
	 */
	if (JHD_OK  != jhd_tls_asn1_get_tag(&p, end, &len, JHD_TLS_ASN1_OCTET_STRING))
		return JHD_ERROR;
	if ((ret = jhd_tls_ecp_point_read_binary(grp, &grp->G, (const unsigned char *) p, len)) != JHD_OK) {
		/*
		 * If we can't read the point because it's compressed, cheat by
		 * reading only the X coordinate and the parity bit of Y.
		 */
		if ((ret != JHD_UNEXPECTED) ||
			(p[0] != 0x02 && p[0] != 0x03) ||
			(len != jhd_tls_mpi_size(&grp->P) + 1) ||
			(jhd_tls_mpi_read_binary(&grp->G.X, p + 1, len - 1) != JHD_OK) ||
			(jhd_tls_mpi_lset(&grp->G.Y, p[0] - 2) != JHD_OK) ||
			(jhd_tls_mpi_lset(&grp->G.Z, 1) != JHD_OK)) {
			return JHD_ERROR;
		}
	}

	p += len;

	/*
	 * order INTEGER
	 */
	if (JHD_OK != jhd_tls_asn1_get_mpi(&p, end, &grp->N))
		return JHD_OK;
	grp->nbits = jhd_tls_mpi_bitlen(&grp->N);
	return (0);
}

/*
 * Find the group id associated with an (almost filled) group as generated by
 * pk_group_from_specified(), or return an error if unknown.
 */
static void pk_group_id_from_group(const jhd_tls_ecp_group *grp, jhd_tls_ecp_group_id *grp_id) {
	jhd_tls_ecp_group *ref;
	const jhd_tls_ecp_curve_info *curve_info;
//	for (id = jhd_tls_ecp_grp_id_list(); *id != JHD_TLS_ECP_DP_NONE; id++) {
	for(curve_info = jhd_tls_ecp_curve_list();curve_info->grp_id != JHD_TLS_ECP_DP_NONE;++curve_info){
		ref = jhd_tls_ecp_group_get(curve_info->grp_id);
		if(ref != NULL){
		/* Compare to the group we were given, starting with easy tests */
			if (grp->pbits == ref->pbits &&
				grp->nbits == ref->nbits &&
				jhd_tls_mpi_cmp_mpi(&grp->P, &ref->P) == 0 &&
				jhd_tls_mpi_cmp_mpi(&grp->A, &ref->A) == 0 &&
				jhd_tls_mpi_cmp_mpi(&grp->B, &ref->B) == 0 &&
				jhd_tls_mpi_cmp_mpi(&grp->N, &ref->N) == 0 &&
				jhd_tls_mpi_cmp_mpi(&grp->G.X, &ref->G.X) == 0 &&
				jhd_tls_mpi_cmp_mpi(&grp->G.Z, &ref->G.Z) == 0 &&
					/* For Y we may only know the parity bit, so compare only that */
				jhd_tls_mpi_get_bit(&grp->G.Y, 0) == jhd_tls_mpi_get_bit(&ref->G.Y, 0)) {
				*grp_id = curve_info->grp_id;
			}
		}

	}
	*grp_id = JHD_TLS_ECP_DP_NONE;
}

/*
 * Parse a SpecifiedECDomain (SEC 1 C.2) and find the associated group ID
 */
static int pk_group_id_from_specified(const jhd_tls_asn1_buf *params, jhd_tls_ecp_group_id *grp_id) {
	int ret;
	jhd_tls_ecp_group grp;

	jhd_tls_ecp_group_init(&grp);

	if ((ret = pk_group_from_specified(params, &grp)) != 0)
		goto cleanup;

	pk_group_id_from_group(&grp, grp_id);
	if(grp_id == JHD_TLS_ECP_DP_NONE){
		ret = JHD_UNSUPPORTED;
	}
	cleanup:
    jhd_tls_mpi_free( &grp.P );
    jhd_tls_mpi_free( &grp.A );
    jhd_tls_mpi_free( &grp.B );
    jhd_tls_ecp_point_free(&grp.G );
    jhd_tls_mpi_free( &grp.N );
	return (ret);
}


/*
 * Use EC parameters to initialise an EC group
 *
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 *   specifiedCurve     SpecifiedECDomain -- = SEQUENCE { ... }
 *   -- implicitCurve   NULL
 */
static int pk_use_ecparams(const jhd_tls_asn1_buf *params, jhd_tls_ecp_group **grp) {
	int ret;
	jhd_tls_ecp_group_id grp_id;
	if (params->tag == JHD_TLS_ASN1_OID) {
		jhd_tls_oid_get_ec_grp(params, &grp_id);
		if(grp_id == JHD_TLS_ECP_DP_NONE){
			return JHD_UNSUPPORTED;
		}
	} else {
		if (JHD_OK != (ret =pk_group_id_from_specified(params, &grp_id))) {
			return ret;
		}
	}
	if ((*grp = jhd_tls_ecp_group_get(grp_id)) == NULL)
		return JHD_ERROR;
	return JHD_OK;
}

/*
 * EC public key is an EC point
 *
 * The caller is responsible for clearing the structure upon failure if
 * desired. Take care to pass along the possible ECP_FEATURE_UNAVAILABLE
 * return code of jhd_tls_ecp_point_read_binary() and leave p in a usable state.
 */
static int pk_get_ecpubkey(unsigned char **p, const unsigned char *end, jhd_tls_ecp_keypair *key) {
	int ret;
	if ((ret = jhd_tls_ecp_point_read_binary(key->grp, &key->public_key, (const unsigned char *) *p, end - *p)) == JHD_OK) {
		ret = jhd_tls_ecp_check_pubkey(key->grp, &key->public_key);
	}
	/*
	 * We know jhd_tls_ecp_point_read_binary consumed all bytes or failed
	 */
	*p = (unsigned char *) end;
	return (ret);
}
static int pk_get_ecdsapubkey(unsigned char **p, const unsigned char *end, jhd_tls_ecdsa_context *ctx) {
	int ret;
	jhd_tls_ecp_keypair key;
	jhd_tls_ecp_keypair_init(&key);
	key.grp = ctx->grp;
	ret = pk_get_ecpubkey(p,end,&key);
	if(ret == JHD_OK){
		ret =jhd_tls_ecdsa_from_keypair(ctx,&key);
	}
	jhd_tls_ecp_keypair_free(&key);
	return (ret);
}

/*
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *  }
 */
static int pk_get_rsapubkey(unsigned char **p, const unsigned char *end, jhd_tls_serializa_rsa_context *rsa_s) {
	int ret;
	size_t len;
	jhd_tls_rsa_context rsa;
	jhd_tls_rsa_init(&rsa,0,NULL);
	if ((ret = jhd_tls_asn1_get_tag(p, end, &len, JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != 0)
		return JHD_ERROR;
	if (*p + len != end)
		return JHD_ERROR;
	/* Import N */
	if ((ret = jhd_tls_asn1_get_tag(p, end, &len, JHD_TLS_ASN1_INTEGER)) != 0)
		return JHD_ERROR;;
	if ((ret = jhd_tls_rsa_import_raw(&rsa, *p, len, NULL, 0, NULL, 0,NULL, 0, NULL, 0)) != 0){
		goto func_error;
	}
	*p += len;
	/* Import E */
	if ((ret = jhd_tls_asn1_get_tag(p, end, &len, JHD_TLS_ASN1_INTEGER)) != 0){
		goto func_error;
	}
	if ((ret = jhd_tls_rsa_import_raw(&rsa, NULL, 0, NULL, 0, NULL, 0,NULL, 0, *p, len)) != 0){
		goto func_error;
	}
	*p += len;
	if (jhd_tls_rsa_complete(&rsa) != 0 || jhd_tls_rsa_check_pubkey(&rsa) != 0) {
		goto func_error;
	}
	if (*p != end){
		goto func_error;
	}
	if(jhd_tls_rsa_serialize(&rsa,rsa_s)!= JHD_OK){
		log_err("%s","serialize jhd_tls_rsa_context error");
		goto func_error;
	}

	jhd_tls_rsa_free(&rsa);
	return JHD_OK;

	func_error:
	jhd_tls_rsa_free(&rsa);
	return JHD_ERROR;
}

/* Get a PK algorithm identifier
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
static int pk_get_pk_alg(unsigned char **p, const unsigned char *end, const jhd_tls_pk_info_t **pk_info, jhd_tls_asn1_buf *params) {
	int ret;
	jhd_tls_asn1_buf alg_oid;

	memset(params, 0, sizeof(jhd_tls_asn1_buf));

	if ((ret = jhd_tls_asn1_get_alg(p, end, &alg_oid, params)) != 0)
		return JHD_ERROR;

	jhd_tls_oid_get_pk_alg(&alg_oid, pk_info);
	if(*pk_info == NULL){
		return JHD_UNSUPPORTED;
	}

	/*
	 * No parameters with RSA (only for EC)
	 */
	if (*pk_info == (&jhd_tls_rsa_info) && ((params->tag != JHD_TLS_ASN1_NULL && params->tag != 0) || params->len != 0)) {
		return JHD_ERROR;
	}
	return JHD_OK;
}



int jhd_tls_pk_parse_subpubkey_by_malloc(unsigned char **p, const unsigned char *end, jhd_tls_pk_context *pk){
	int ret;
	size_t len;
	jhd_tls_asn1_buf alg_params;
	jhd_tls_ecdsa_context *ecdsa_ctx;
	jhd_tls_serializa_rsa_context *rsa_ctx;
	const jhd_tls_pk_info_t *pk_info = NULL;
	if ((ret = jhd_tls_asn1_get_tag(p, end, &len, JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != 0) {
		return JHD_ERROR;
	}
	end = *p + len;
	if ((ret = pk_get_pk_alg(p, end, &pk_info, &alg_params)) != JHD_OK)
		return (ret);

	if (jhd_tls_asn1_get_bitstring_null(p, end, &len) != JHD_OK)
		return JHD_ERROR;

	if (*p + len != end)
		return JHD_ERROR;
	pk->pk_ctx = malloc(pk_info->ctx_size);
	if(pk->pk_ctx == NULL ){
		log_stderr("systemcall malloc error");
		return JHD_ERROR;
	}
	pk->pk_info = pk_info;
	pk_info->pk_ctx_init_func(pk->pk_ctx);
	if (pk_info == (&jhd_tls_rsa_info)) {
		rsa_ctx = pk->pk_ctx;
		ret = pk_get_rsapubkey(p, end,rsa_ctx);
	} else {
		ecdsa_ctx = pk->pk_ctx;
		ret = pk_use_ecparams( &alg_params, &ecdsa_ctx->grp );
		if( ret == 0 )
		ret = pk_get_ecdsapubkey( p, end, ecdsa_ctx );
	}
	if (ret == 0 && *p != end)	ret = JHD_ERROR;
	if (ret != JHD_OK){
		free(pk->pk_ctx);
		pk->pk_ctx = NULL;
		pk->pk_info = NULL;
	}
	return (ret);
}


/*
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING }
 */
int jhd_tls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end, jhd_tls_pk_context *pk,void *event) {
	int ret;
	size_t len;
	jhd_tls_asn1_buf alg_params;
	jhd_tls_ecdsa_context *ecdsa_ctx;
	jhd_tls_serializa_rsa_context *rsa_ctx;
	const jhd_tls_pk_info_t *pk_info = NULL;

	if ((ret = jhd_tls_asn1_get_tag(p, end, &len, JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != 0) {
		return JHD_ERROR;
	}
	end = *p + len;
	if ((ret = pk_get_pk_alg(p, end, &pk_info, &alg_params)) != JHD_OK)
		return (ret);

	if (jhd_tls_asn1_get_bitstring_null(p, end, &len) != JHD_OK)
		return JHD_ERROR;

	if (*p + len != end)
		return JHD_ERROR;

	if((pk->pk_ctx != NULL) &&(pk->pk_info->ctx_size != pk_info->ctx_size)){
			jhd_tls_free_with_size(pk->pk_ctx,pk->pk_info->ctx_size);
			pk->pk_ctx = NULL;
	}
	if(pk->pk_ctx == NULL){
		pk->pk_ctx = jhd_tls_alloc(pk_info->ctx_size);
		if(pk->pk_ctx == NULL ){
			//FIXME: add memory waitting queue size ==pk_info->ctx_size;
			if(event != NULL){
				jhd_tls_wait_mem(event,pk_info->ctx_size);
				return JHD_AGAIN;
			}
			return JHD_ERROR;
		}
		pk->pk_info = pk_info;
	}

	pk_info->pk_ctx_init_func(pk->pk_ctx);
	if (pk_info == (&jhd_tls_rsa_info)) {
		rsa_ctx = pk->pk_ctx;
		ret = pk_get_rsapubkey(p, end,rsa_ctx);
	} else {
		ecdsa_ctx = pk->pk_ctx;
		ret = pk_use_ecparams( &alg_params, &ecdsa_ctx->grp );
		if( ret == 0 )
			ret = pk_get_ecdsapubkey( p, end, ecdsa_ctx );
	}
	if (ret == 0 && *p != end)
		ret = JHD_ERROR;

	if (ret != JHD_OK){
		jhd_tls_free_with_size(pk->pk_ctx,pk_info->ctx_size);
		pk->pk_ctx = NULL;
		pk->pk_info = NULL;
	}
	return (ret);
}

/*
 * Parse a PKCS#1 encoded private RSA key
 */
static int pk_parse_key_pkcs1_der(jhd_tls_pk_context *pk, const unsigned char *key, size_t keylen) {
	int ret, version;
	size_t len;
	unsigned char *p, *end;
	jhd_tls_mpi T;
	jhd_tls_rsa_context rsa;
	p = (unsigned char *) key;
	end = p + keylen;
	if (JHD_OK != jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) {
		return JHD_ERROR;
	}
	end = p + len;
	if (JHD_OK != jhd_tls_asn1_get_int(&p, end, &version)){
		return JHD_ERROR;
	}
	if (version != 0) {
		return JHD_ERROR;
	}
	jhd_tls_rsa_init(&rsa,0,NULL);
	jhd_tls_mpi_init(&T);
	/* Import N */
	if (((ret = jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_INTEGER)) != 0) ||
		((ret = jhd_tls_rsa_import_raw(&rsa, p, len, NULL, 0, NULL, 0,NULL, 0, NULL, 0)) != 0)){
		goto cleanup;
	}
	p += len;

	/* Import E */
	if (((ret = jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_INTEGER)) != 0) ||
		((ret = jhd_tls_rsa_import_raw(&rsa, NULL, 0, NULL, 0, NULL, 0,NULL, 0, p, len)) != 0)){
		goto cleanup;
	}
	p += len;

	/* Import D */
	if (((ret = jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_INTEGER)) != 0) ||
		((ret = jhd_tls_rsa_import_raw(&rsa, NULL, 0, NULL, 0, NULL, 0, p, len, NULL, 0)) != 0)){
		goto cleanup;
	}
	p += len;

	/* Import P */
	if (((ret = jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_INTEGER)) != 0) ||
		((ret = jhd_tls_rsa_import_raw(&rsa, NULL, 0, p, len, NULL, 0,NULL, 0, NULL, 0)) != 0)){
		goto cleanup;
	}
	p += len;
	/* Import Q */
	if (((ret = jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_INTEGER)) != 0) ||
		((ret = jhd_tls_rsa_import_raw(&rsa, NULL, 0, NULL, 0, p, len,NULL, 0, NULL, 0)) != 0)){
		goto cleanup;
	}
	p += len;

	/* Complete the RSA private key */
	if ((ret = jhd_tls_rsa_complete(&rsa)) != 0){
		goto cleanup;
	}

	/* Check optional parameters */
	if (((ret = jhd_tls_asn1_get_mpi(&p, end, &T)) != 0) ||
		((ret = jhd_tls_asn1_get_mpi(&p, end, &T)) != 0) ||
		((ret = jhd_tls_asn1_get_mpi(&p, end, &T)) != 0)){
		goto cleanup;
	}
	if (p != end) {
		ret = JHD_ERROR;
	}
	rsa.md_info= NULL;
	pk->pk_ctx = malloc(jhd_tls_rsa_info.ctx_size);
	if(pk->pk_ctx == NULL){
		ret = JHD_ERROR;
	}else{
		jhd_tls_rsa_info.pk_ctx_init_func(pk->pk_ctx);
		ret = jhd_tls_rsa_serialize(&rsa,(jhd_tls_serializa_rsa_context*)pk->pk_ctx);
		if(ret != JHD_OK){
			free(pk->pk_ctx);
			pk->pk_ctx = NULL;
		}
	}
	pk->pk_info = &jhd_tls_rsa_info;
	cleanup:
	jhd_tls_rsa_free(&rsa);
	jhd_tls_mpi_free(&T);
	return (ret);
}

/*
 * Parse a SEC1 encoded private EC key
 */
static int pk_parse_key_sec1_der(jhd_tls_ecdsa_context *ecdsa_ctx, const unsigned char *key, size_t keylen) {
	int ret;
	int version, pubkey_done;
	size_t len;
	jhd_tls_asn1_buf params;
	unsigned char *p = (unsigned char *) key;
	unsigned char *end = p + keylen;
	unsigned char *end2;
	jhd_tls_ecp_keypair eck;

	/*
	 * RFC 5915, or SEC1 Appendix C.4
	 *
	 * ECPrivateKey ::= SEQUENCE {
	 *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
	 *      privateKey     OCTET STRING,
	 *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
	 *      publicKey  [1] BIT STRING OPTIONAL
	 *    }
	 */
	if (JHD_OK != jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)){
		return JHD_ERROR;
	}
	end = p + len;
	if (JHD_OK !=  jhd_tls_asn1_get_int(&p, end, &version)){
		return JHD_ERROR;
	}

	if (version != 1)
		return JHD_ERROR;

	if (JHD_OK != jhd_tls_asn1_get_tag(&p, end, &len, JHD_TLS_ASN1_OCTET_STRING)){
		return JHD_ERROR;
	}
	jhd_tls_ecp_keypair_init(&eck);
	if (JHD_OK != jhd_tls_mpi_read_binary(&eck.private_key, p, len)){
		goto func_error;
	}
	p += len;

	pubkey_done = 0;
	if (p != end) {
		/*
		 * Is 'parameters' present?
		 */
		if (JHD_OK == (ret = jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | 0))) {
			if ((JHD_OK != pk_get_ecparams(&p, p + len, &params)) || (JHD_OK != pk_use_ecparams(&params, &eck.grp))) {
				goto func_error;
			}
		} else if (ret != JHD_UNEXPECTED) {
			goto func_error;
		}
	}

	if (p != end) {
		/*
		 * Is 'publickey' present? If not, or if we can't read it (eg because it
		 * is compressed), create it from the private key.
		 */
		if ((ret = jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | 1)) == JHD_OK) {
			end2 = p + len;
			if ((ret = jhd_tls_asn1_get_bitstring_null(&p, end2, &len)) != 0){
				goto func_error;
			}
			if (p + len != end2){
				goto func_error;
			}

			if ((ret = pk_get_ecpubkey(&p, end2, &eck)) == 0)
				pubkey_done = 1;
			else {
				/*
				 * The only acceptable failure mode of pk_get_ecpubkey() above
				 * is if the point format is not recognized.
				 */
				if (ret != JHD_UNEXPECTED){
					goto func_error;
				}
			}
		} else if (ret != JHD_UNEXPECTED) {
			goto func_error;
		}
	}

	if (!pubkey_done && (JHD_OK != jhd_tls_ecp_mul_specific(eck.grp, &eck.public_key, &eck.private_key, &eck.grp->G,NULL, NULL))) {
		goto func_error;
	}

	if (JHD_OK != jhd_tls_ecp_check_privkey(eck.grp, &eck.private_key)) {
		goto func_error;
	}

	ret = jhd_tls_ecdsa_from_keypair(ecdsa_ctx,&eck);
	jhd_tls_ecp_keypair_free(&eck);
	return JHD_OK;
	func_error:
	jhd_tls_ecp_keypair_free(&eck);
	return JHD_ERROR;

}

/*
 * Parse an unencrypted PKCS#8 encoded private key
 *
 * Notes:
 *
 * - This function does not own the key buffer. It is the
 *   responsibility of the caller to take care of zeroizing
 *   and freeing it after use.
 *
 * - The function is responsible for freeing the provided
 *   PK context on failure.
 *
 */
static int pk_parse_key_pkcs8_unencrypted_der(jhd_tls_pk_context *pk, const unsigned char* key, size_t keylen) {
	int ret, version;
	size_t len;
	jhd_tls_asn1_buf params;
	unsigned char *p = (unsigned char *) key;
	unsigned char *end = p + keylen;
	const jhd_tls_pk_info_t *pk_info;
	jhd_tls_ecdsa_context *ecdsa_ctx;
	if (JHD_OK !=(ret = jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE))) {
		return ret;
	}
	end = p + len;

	if (JHD_OK != jhd_tls_asn1_get_int(&p, end, &version))
		return JHD_ERROR;

	if (version != 0)
		return JHD_ERROR;
	if (JHD_OK != (ret = pk_get_pk_alg(&p, end, &pk_info, &params))){
		return ret;
	}
	if (JHD_OK !=(ret = jhd_tls_asn1_get_tag(&p, end, &len, JHD_TLS_ASN1_OCTET_STRING))){
		return ret;
	}
	if (len < 1)
		return JHD_ERROR;
	if (pk_info == (&jhd_tls_rsa_info)) {
		if (JHD_OK != pk_parse_key_pkcs1_der(pk, p, len)){
			return JHD_ERROR;
		}
	} else{
        pk_info = &jhd_tls_ecdsa_info;
        ecdsa_ctx = malloc(sizeof(jhd_tls_ecdsa_context));
        if(ecdsa_ctx == NULL){
        	return JHD_ERROR;
        }
        pk_info->pk_ctx_init_func(ecdsa_ctx);
		if( JHD_OK == pk_use_ecparams( &params, &ecdsa_ctx->grp)){
			if(JHD_OK ==pk_parse_key_sec1_der(ecdsa_ctx, p, len )){
				pk->pk_ctx = ecdsa_ctx;
				pk->pk_info = pk_info;
				return JHD_OK;
			}
		 }
		 free(ecdsa_ctx);
		 return JHD_ERROR;
	}
	return JHD_OK;
}

/*
 * Parse a private key
 */
int jhd_tls_pk_parse_key(jhd_tls_pk_context *pk, const unsigned char *key, size_t keylen) {
	int ret;
	size_t len,tmp_buf_len = 8192;
	unsigned char tmp_buf[8192];
	jhd_tls_platform_zeroize(tmp_buf,8192);
	if (keylen == 0 || key[keylen - 1] != '\0'){
		return JHD_ERROR;
	}
	else{
		tmp_buf_len = 8192;
		ret = jhd_tls_pem_read_buffer(tmp_buf,&tmp_buf_len, "-----BEGIN RSA PRIVATE KEY-----","-----END RSA PRIVATE KEY-----", key,&len);
	}
	if (ret == 0) {
		return  pk_parse_key_pkcs1_der(pk, tmp_buf, len);
	}
	tmp_buf_len = 8192;
	ret = jhd_tls_pem_read_buffer(tmp_buf,&tmp_buf_len, "-----BEGIN EC PRIVATE KEY-----","-----END EC PRIVATE KEY-----",key,&len );
	if(ret == JHD_OK){
		jhd_tls_ecdsa_context *ecdsa_ctx;
		ecdsa_ctx = malloc(sizeof(jhd_tls_ecdsa_context));
		if(ecdsa_ctx == NULL){
			return JHD_ERROR;
		}
		jhd_tls_ecdsa_info.pk_ctx_init_func(ecdsa_ctx);

		if(JHD_OK ==pk_parse_key_sec1_der(ecdsa_ctx, tmp_buf, len )){
			pk->pk_ctx = ecdsa_ctx;
			pk->pk_info = &jhd_tls_ecdsa_info;
			return JHD_OK;
		}
		free(ecdsa_ctx);
		return JHD_ERROR;
	}
	tmp_buf_len = 8192;
	ret = jhd_tls_pem_read_buffer(tmp_buf,&tmp_buf_len,"-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", key,&len);
	if (ret == JHD_OK) {
		return pk_parse_key_pkcs8_unencrypted_der(pk, tmp_buf, tmp_buf_len);
	}
	if( pk_parse_key_pkcs8_unencrypted_der(pk, key, keylen) == JHD_OK){
		return JHD_OK;
	}
	return pk_parse_key_pkcs1_der(pk, key, keylen);
}

/*
 * Parse a public key
 */
//int jhd_tls_pk_parse_public_key(jhd_tls_pk_context *ctx, const unsigned char *key, size_t keylen) {
//	int ret;
//	unsigned char *p;
//
//	size_t len;
//	jhd_tls_pem_context pem;
//
//	jhd_tls_pem_init(&pem);
//
//	/* Avoid calling jhd_tls_pem_read_buffer() on non-null-terminated string */
//	if (keylen == 0 || key[keylen - 1] != '\0')
//		ret = JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
//	else
//		ret = jhd_tls_pem_read_buffer(&pem, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----", key, NULL, 0, &len);
//
//	if (ret == 0) {
//		p = pem.buf;
//
//		if ((ret = jhd_tls_pk_setup(ctx, &jhd_tls_rsa_info)) != 0)
//			return (ret);
//
//		if ((ret = pk_get_rsapubkey(&p, p + pem.buflen, jhd_tls_pk_rsa(*ctx))) != 0)
//			jhd_tls_pk_free(ctx);
//
//		jhd_tls_pem_free(&pem);
//		return (ret);
//	} else if (ret != JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
//		jhd_tls_pem_free(&pem);
//		return (ret);
//	}
//
//	/* Avoid calling jhd_tls_pem_read_buffer() on non-null-terminated string */
//	if (keylen == 0 || key[keylen - 1] != '\0')
//		ret = JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
//	else
//		ret = jhd_tls_pem_read_buffer(&pem, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", key, NULL, 0, &len);
//
//	if (ret == 0) {
//		/*
//		 * Was PEM encoded
//		 */
//		p = pem.buf;
//
//		ret = jhd_tls_pk_parse_subpubkey(&p, p + pem.buflen, ctx);
//		jhd_tls_pem_free(&pem);
//		return (ret);
//	} else if (ret != JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
//		jhd_tls_pem_free(&pem);
//		return (ret);
//	}
//	jhd_tls_pem_free(&pem);
//
//	if ((ret = jhd_tls_pk_setup(ctx, &jhd_tls_rsa_info)) != 0)
//		return (ret);
//
//	p = (unsigned char *) key;
//	ret = pk_get_rsapubkey(&p, p + keylen, jhd_tls_pk_rsa(*ctx));
//	if (ret == 0) {
//		return (ret);
//	}
//	jhd_tls_pk_free(ctx);
//	if (ret != ( JHD_TLS_ERR_PK_INVALID_PUBKEY + JHD_TLS_ERR_ASN1_UNEXPECTED_TAG)) {
//		return (ret);
//	}
//
//	p = (unsigned char *) key;
//
//	ret = jhd_tls_pk_parse_subpubkey(&p, p + keylen, ctx);
//
//	return (ret);
//}
//
