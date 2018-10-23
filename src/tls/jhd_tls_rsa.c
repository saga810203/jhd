#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>

#include <tls/jhd_tls_rsa.h>
#include <tls/jhd_tls_rsa_internal.h>
#include <tls/jhd_tls_oid.h>
#include <tls/jhd_tls_ctr_drbg.h>
#include <tls/jhd_tls_md_internal.h>
#include <string.h>
#include <tls/jhd_tls_md.h>


#include <stdlib.h>
#include <tls/jhd_tls_platform.h>




#ifdef JHD_LOG_LEVEL_INFO
#define JHD_TLS_TEMP_DEFINE_IN_FUNCTION(MPI) \
if(JHD_OK != jhd_tls_mpi_equals(&ctx1->MPI,&ctx2->MPI)) return JHD_ERROR
int jhd_tls_rsa_context_equals(const jhd_tls_rsa_context *ctx1,const jhd_tls_rsa_context *ctx2){
	if(ctx1->ver != ctx2->ver){
		return JHD_ERROR;
	}
	if(ctx1->len != ctx2->len){
		return JHD_ERROR;
	}
	if(ctx1->padding != ctx2->padding){
		return JHD_ERROR;
	}
	if(ctx1->md_info != ctx2->md_info){
		return JHD_ERROR;
	}
	JHD_TLS_TEMP_DEFINE_IN_FUNCTION(N);
	JHD_TLS_TEMP_DEFINE_IN_FUNCTION(E);
	JHD_TLS_TEMP_DEFINE_IN_FUNCTION(D);
	JHD_TLS_TEMP_DEFINE_IN_FUNCTION(P);
	JHD_TLS_TEMP_DEFINE_IN_FUNCTION(Q);
	JHD_TLS_TEMP_DEFINE_IN_FUNCTION(DP);
	JHD_TLS_TEMP_DEFINE_IN_FUNCTION(DQ);
	JHD_TLS_TEMP_DEFINE_IN_FUNCTION(QP);
	return JHD_OK;
}
#undef JHD_TLS_TEMP_DEFINE_IN_FUNCTION
int jhd_tls_rsa_serialize_check(const jhd_tls_rsa_context *ctx,const jhd_tls_serializa_rsa_context * sctx){
	jhd_tls_rsa_context dr;
	jhd_tls_serializa_rsa_context ds;
	int ret = JHD_OK;

	jhd_tls_rsa_init(&dr,0,NULL);
	jhd_tls_platform_zeroize(&ds,sizeof(jhd_tls_serializa_rsa_context));

	if(JHD_OK!=(ret = jhd_tls_rsa_serialize(ctx,&ds))){
		goto func_return;
	}
	if(JHD_OK!=(ret = jhd_tls_rsa_deserialize(&dr,sctx))){
		goto func_return;
	}
	if(JHD_OK!=(ret = jhd_tls_rsa_context_equals(&dr,ctx))){
		goto func_return;
	}
	if(0!=memcmp(sctx,&ds,sizeof(jhd_tls_serializa_rsa_context))){
		ret = JHD_ERROR;
	}
	func_return:
	if(ret != JHD_OK){
		log_err("%s","bug???????????????????????");
	}
	jhd_tls_rsa_free(&dr);
	return ret;
}
#endif


/* constant-time buffer comparison */
static inline int jhd_tls_safer_memcmp(const void *a, const void *b, size_t n) {
	size_t i;
	const unsigned char *A = (const unsigned char *) a;
	const unsigned char *B = (const unsigned char *) b;
	unsigned char diff = 0;

	for (i = 0; i < n; i++)
		diff |= A[i] ^ B[i];

	return (diff);
}
int jhd_tls_rsa_cache_val(const jhd_tls_mpi *V,jhd_tls_mpi *R){
	int ret;
	JHD_TLS_MPI_CHK( jhd_tls_mpi_lset(R, 1 ) );
	JHD_TLS_MPI_CHK( jhd_tls_mpi_shift_l( R, V->n * 2 * (sizeof(jhd_tls_mpi_uint)<< 3) ) );
	JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi(R, R, V ) );
	cleanup:
	return ret;
}


#define JHD_TLS_ONCE_DEFINE_IN_FUNCTION(X)  if(jhd_tls_mpi_encode(p,len,&ctx->X,&ulen)!=JHD_OK){ \
	return JHD_ERROR; \
} \
 p+=ulen; \
len -=ulen;

 int jhd_tls_rsa_serialize(const jhd_tls_rsa_context *ctx,jhd_tls_serializa_rsa_context * sctx){
	size_t len,ulen;
	char *p;
	sctx->ver = ctx->ver;
	sctx->md_info = ctx->md_info;
	sctx->padding = ctx->padding;
	sctx->len = ctx->len;
	p = sctx->serializa_context;
	len =JHD_TLS_RSA_SERIALZA_LEN;

	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(N)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(E)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(D)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(P)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(Q)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(DP)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(DQ)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(QP)
	return JHD_OK;
}
#undef JHD_TLS_ONCE_DEFINE_IN_FUNCTION
#define JHD_TLS_ONCE_DEFINE_IN_FUNCTION(X) if(JHD_OK != jhd_tls_mpi_decode(p,len,&ctx->X,&ulen)){return JHD_ERROR;}p+=ulen;len -=ulen;

 int jhd_tls_rsa_deserialize(jhd_tls_rsa_context *ctx,const jhd_tls_serializa_rsa_context * sctx){
	size_t len,ulen;
	const char *p;
	jhd_tls_platform_zeroize(ctx,sizeof(jhd_tls_rsa_context));
	ctx->ver = sctx->ver;
	ctx->md_info = sctx->md_info;
	ctx->padding = sctx->padding;
	p = sctx->serializa_context;
	len =JHD_TLS_RSA_SERIALZA_LEN;
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(N)
	ctx->len = jhd_tls_mpi_size( &ctx->N );
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(E)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(D)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(P)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(Q)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(DP)
	JHD_TLS_ONCE_DEFINE_IN_FUNCTION(DQ)
	return jhd_tls_mpi_decode(p,len,&ctx->QP,&ulen);
}
#undef JHD_TLS_ONCE_DEFINE_IN_FUNCTION

//int jhd_tls_rsa_import(jhd_tls_rsa_context *ctx, const jhd_tls_mpi *N, const jhd_tls_mpi *P, const jhd_tls_mpi *Q, const jhd_tls_mpi *D, const jhd_tls_mpi *E) {
//	int ret;
//
//	if ((N != NULL && (ret = jhd_tls_mpi_copy(&ctx->N, N)) != 0) || (P != NULL && (ret = jhd_tls_mpi_copy(&ctx->P, P)) != 0) || (Q != NULL && (ret =
//	        jhd_tls_mpi_copy(&ctx->Q, Q)) != 0) || (D != NULL && (ret = jhd_tls_mpi_copy(&ctx->D, D)) != 0)
//	        || (E != NULL && (ret = jhd_tls_mpi_copy(&ctx->E, E)) != 0)) {
//		return ( JHD_TLS_ERR_RSA_BAD_INPUT_DATA + ret);
//	}
//
//	if (N != NULL)
//		ctx->len = jhd_tls_mpi_size(&ctx->N);
//
//	return (0);
//}

int jhd_tls_rsa_import_raw(jhd_tls_rsa_context *ctx, unsigned char const *N, size_t N_len, unsigned char const *P, size_t P_len, unsigned char const *Q,
        size_t Q_len, unsigned char const *D, size_t D_len, unsigned char const *E, size_t E_len) {
    int ret = 0;
    if( N != NULL )
    {
        JHD_TLS_MPI_CHK( jhd_tls_mpi_read_binary( &ctx->N, N, N_len ) );
        ctx->len = jhd_tls_mpi_size( &ctx->N );
    }
    if( P != NULL )
        JHD_TLS_MPI_CHK( jhd_tls_mpi_read_binary( &ctx->P, P, P_len ) );
    if( Q != NULL )
        JHD_TLS_MPI_CHK( jhd_tls_mpi_read_binary( &ctx->Q, Q, Q_len ) );

    if( D != NULL )
        JHD_TLS_MPI_CHK( jhd_tls_mpi_read_binary( &ctx->D, D, D_len ) );

    if( E != NULL )
        JHD_TLS_MPI_CHK( jhd_tls_mpi_read_binary( &ctx->E, E, E_len ) );
cleanup:
    return JHD_OK;
}



#define JHD_TLS_ONCE_DEFINE_IN_FUNCTION(X) (jhd_tls_mpi_cmp_int( &ctx->X, 0 ) <= 0) || (jhd_tls_mpi_get_bit( &ctx->X, 0 ) == 0 )
/*
 * Checks whether the context fields are set in such a way
 * that the RSA primitives will be able to execute without error.
 * It does *not* make guarantees for consistency of the parameters.
 */


static int rsa_check_context(jhd_tls_rsa_context const *ctx, int is_priv) {

    if( ctx->len != jhd_tls_mpi_size( &ctx->N ) || ctx->len > JHD_TLS_MPI_MAX_SIZE )
    {
        return JHD_ERROR;
    }
    if( jhd_tls_mpi_cmp_int( &ctx->N, 0 ) <= 0 ||jhd_tls_mpi_get_bit( &ctx->N, 0 ) == 0  )
    {
    	 return JHD_ERROR;
    }
    /* Always need E for public key operations */
    if( jhd_tls_mpi_cmp_int( &ctx->E, 0 ) <= 0 ){
        return JHD_ERROR;
    }

    if(is_priv){
    	if(JHD_TLS_ONCE_DEFINE_IN_FUNCTION(P) || JHD_TLS_ONCE_DEFINE_IN_FUNCTION(Q)){
    		return JHD_ERROR;
    	}
    	if(( jhd_tls_mpi_cmp_int( &ctx->DP, 0 ) <= 0) || (jhd_tls_mpi_cmp_int( &ctx->DQ, 0 ) <= 0  )|| (jhd_tls_mpi_cmp_int( &ctx->QP, 0 ) <= 0 )){
    		return JHD_ERROR;
    	}
    }
    return( 0 );
}
#undef JHD_TLS_ONCE_DEFINE_IN_FUNCTION

int jhd_tls_rsa_complete(jhd_tls_rsa_context *ctx) {
    const int have_N = ( jhd_tls_mpi_cmp_int( &ctx->N, 0 ) != 0 );
    const int have_P = ( jhd_tls_mpi_cmp_int( &ctx->P, 0 ) != 0 );
    const int have_Q = ( jhd_tls_mpi_cmp_int( &ctx->Q, 0 ) != 0 );
    const int have_D = ( jhd_tls_mpi_cmp_int( &ctx->D, 0 ) != 0 );
    const int have_E = ( jhd_tls_mpi_cmp_int( &ctx->E, 0 ) != 0 );

    /*
     * Check whether provided parameters are enough
     * to deduce all others. The following incomplete
     * parameter sets for private keys are supported:
     *
     * (1) P, Q missing.
     * (2) D and potentially N missing.
     *
     */
    const int n_missing  =   have_P &&  have_Q &&  have_D && have_E;
    const int pq_missing =   have_N && !have_P && !have_Q &&  have_D && have_E;
    const int d_missing  =   have_P &&  have_Q && !have_D && have_E;
    const int is_pub     =   have_N && !have_P && !have_Q && !have_D && have_E;

    /* These three alternatives are mutually exclusive */
    const int is_priv = n_missing || pq_missing || d_missing;
    if( !is_priv && !is_pub ){
        return JHD_ERROR;
    }
    /*
     * Step 1: Deduce N if P, Q are provided.
     */

    if( !have_N && have_P && have_Q )
    {
        if( jhd_tls_mpi_mul_mpi( &ctx->N, &ctx->P,&ctx->Q ) != JHD_OK )
        {
        	return JHD_ERROR;
        }
        ctx->len = jhd_tls_mpi_size( &ctx->N );
    }

    /*
     * Step 2: Deduce and verify all remaining core parameters.
     */

    if( pq_missing )
    {
       if(JHD_OK != jhd_tls_rsa_cache_val(&ctx->P,&ctx->Q)){
    	   return JHD_ERROR;
       }
       if(JHD_OK !=jhd_tls_rsa_deduce_primes( &ctx->N, &ctx->E, &ctx->D,&ctx->P, &ctx->Q )){
    	   return JHD_ERROR;
       }
    }
    else if( d_missing )
    {
        if(JHD_OK != jhd_tls_rsa_deduce_private_exponent( &ctx->P,&ctx->Q,&ctx->E,&ctx->D )){
        	return JHD_ERROR;
        }
    }

    /*
     * Step 3: Deduce all additional parameters specific
     *         to our current RSA implementation.
     */

    if( is_priv )
    {
        if(JHD_OK != jhd_tls_rsa_deduce_crt( &ctx->P,  &ctx->Q,  &ctx->D,&ctx->DP, &ctx->DQ, &ctx->QP )){
        	return JHD_ERROR;
        }
    }
    /*
     * Step 3: Basic sanity checks
     */

    return  rsa_check_context( ctx, is_priv) ;
}

int jhd_tls_rsa_export_raw(const jhd_tls_rsa_context *ctx, unsigned char *N, size_t N_len, unsigned char *P, size_t P_len, unsigned char *Q, size_t Q_len,
        unsigned char *D, size_t D_len, unsigned char *E, size_t E_len) {
	int ret = 0;

	/* Check if key is private or public */
	const int is_priv = jhd_tls_mpi_cmp_int(&ctx->N, 0) != 0 && jhd_tls_mpi_cmp_int(&ctx->P, 0) != 0 && jhd_tls_mpi_cmp_int(&ctx->Q, 0) != 0
	        && jhd_tls_mpi_cmp_int(&ctx->D, 0) != 0 && jhd_tls_mpi_cmp_int(&ctx->E, 0) != 0;

	if (!is_priv) {
		/* If we're trying to export private parameters for a public key,
		 * something must be wrong. */
		if (P != NULL || Q != NULL || D != NULL)
			return JHD_ERROR;

	}

	if (N != NULL)
		JHD_TLS_MPI_CHK(jhd_tls_mpi_write_binary(&ctx->N, N, N_len));

	if (P != NULL)
		JHD_TLS_MPI_CHK(jhd_tls_mpi_write_binary(&ctx->P, P, P_len));

	if (Q != NULL)
		JHD_TLS_MPI_CHK(jhd_tls_mpi_write_binary(&ctx->Q, Q, Q_len));

	if (D != NULL)
		JHD_TLS_MPI_CHK(jhd_tls_mpi_write_binary(&ctx->D, D, D_len));

	if (E != NULL)
		JHD_TLS_MPI_CHK(jhd_tls_mpi_write_binary(&ctx->E, E, E_len));

	cleanup:

	return (ret);
}

int jhd_tls_rsa_export(const jhd_tls_rsa_context *ctx, jhd_tls_mpi *N, jhd_tls_mpi *P, jhd_tls_mpi *Q, jhd_tls_mpi *D, jhd_tls_mpi *E) {
	int ret;

	/* Check if key is private or public */
	int is_priv = jhd_tls_mpi_cmp_int(&ctx->N, 0) != 0 && jhd_tls_mpi_cmp_int(&ctx->P, 0) != 0 && jhd_tls_mpi_cmp_int(&ctx->Q, 0) != 0
	        && jhd_tls_mpi_cmp_int(&ctx->D, 0) != 0 && jhd_tls_mpi_cmp_int(&ctx->E, 0) != 0;

	if (!is_priv) {
		/* If we're trying to export private parameters for a public key,
		 * something must be wrong. */
		if (P != NULL || Q != NULL || D != NULL)
			return JHD_ERROR;

	}

	/* Export all requested core parameters. */

	if ((N != NULL && (ret = jhd_tls_mpi_copy(N, &ctx->N)) != 0) || (P != NULL && (ret = jhd_tls_mpi_copy(P, &ctx->P)) != 0) || (Q != NULL && (ret =
	        jhd_tls_mpi_copy(Q, &ctx->Q)) != 0) || (D != NULL && (ret = jhd_tls_mpi_copy(D, &ctx->D)) != 0)
	        || (E != NULL && (ret = jhd_tls_mpi_copy(E, &ctx->E)) != 0)) {
		return (ret);
	}

	return (0);
}

/*
 * Export CRT parameters
 * This must also be implemented if CRT is not used, for being able to
 * write DER encoded RSA keys. The helper function jhd_tls_rsa_deduce_crt
 * can be used in this case.
 */
int jhd_tls_rsa_export_crt(const jhd_tls_rsa_context *ctx, jhd_tls_mpi *DP, jhd_tls_mpi *DQ, jhd_tls_mpi *QP) {
	int ret;

	/* Check if key is private or public */
	int is_priv = jhd_tls_mpi_cmp_int(&ctx->N, 0) != 0 && jhd_tls_mpi_cmp_int(&ctx->P, 0) != 0 && jhd_tls_mpi_cmp_int(&ctx->Q, 0) != 0
	        && jhd_tls_mpi_cmp_int(&ctx->D, 0) != 0 && jhd_tls_mpi_cmp_int(&ctx->E, 0) != 0;

	if (!is_priv)
		return JHD_ERROR;
	/* Export all requested blinding parameters. */
	if ((DP != NULL && (ret = jhd_tls_mpi_copy(DP, &ctx->DP)) != 0) || (DQ != NULL && (ret = jhd_tls_mpi_copy(DQ, &ctx->DQ)) != 0) || (QP != NULL && (ret =
	        jhd_tls_mpi_copy(QP, &ctx->QP)) != 0)) {
		return JHD_ERROR;
	}
	return (0);
}

/*
 * Initialize an RSA context
 */
void jhd_tls_rsa_init(jhd_tls_rsa_context *ctx, int padding, jhd_tls_md_info_t *md_info) {
	memset(ctx, 0, sizeof(jhd_tls_rsa_context));
	ctx->N.s = 1;              /*!<  The public modulus. */
    ctx->E.s = 1 ;              /*!<  The public exponent. */

    ctx->D.s = 1 ;              /*!<  The private exponent. */
    ctx->P.s = 1 ;              /*!<  The first prime factor. */
    ctx->Q.s = 1 ;              /*!<  The second prime factor. */

    ctx->DP.s = 1 ;             /*!<  <code>D % (P - 1)</code>. */
    ctx->DQ.s = 1 ;             /*!<  <code>D % (Q - 1)</code>. */
    ctx->QP.s = 1 ;
	ctx->padding = padding;
	ctx->md_info = md_info;
}







/*
 * Set padding for an existing RSA context
 */
void jhd_tls_rsa_set_padding(jhd_tls_rsa_context *ctx, int padding, jhd_tls_md_info_t *md_info) {
	ctx->padding = padding;
//	ctx->hash_id = hash_id;
	ctx->md_info = md_info;
}

/*
 * Get length in bytes of RSA modulus
 */
#if !defined(JHD_TLS_INLINE)
size_t jhd_tls_rsa_get_len(const jhd_tls_rsa_context *ctx) {
	return (ctx->len);
}
#endif


/*
 * Check a public RSA key
 */
int jhd_tls_rsa_check_pubkey(const jhd_tls_rsa_context *ctx) {
    if( rsa_check_context( ctx, 0 /* public */) != 0 ){
        return JHD_ERROR;
    }
    if( jhd_tls_mpi_bitlen( &ctx->N ) < 128 )
    {
    	 return JHD_ERROR;
    }
    if( (jhd_tls_mpi_get_bit( &ctx->E, 0 ) == 0) ||(jhd_tls_mpi_bitlen( &ctx->E )< 2)  || (jhd_tls_mpi_cmp_mpi( &ctx->E, &ctx->N ) >= 0))
    {
    	 return JHD_ERROR;
    }
    return JHD_OK;
}

/*
 * Check for the consistency of all fields in an RSA private key context
 */
int jhd_tls_rsa_check_privkey(const jhd_tls_rsa_context *ctx) {
	if (jhd_tls_rsa_check_pubkey(ctx) != 0 || rsa_check_context(ctx, 1 /* private */ ) != 0) {
		 return JHD_ERROR;
	}

	if (jhd_tls_rsa_validate_params(&ctx->N, &ctx->P, &ctx->Q, &ctx->D, &ctx->E) != 0) {
		 return JHD_ERROR;
	}else if (jhd_tls_rsa_validate_crt(&ctx->P, &ctx->Q, &ctx->D, &ctx->DP, &ctx->DQ, &ctx->QP) != 0) {
		 return JHD_ERROR;
	}
	return (0);
}

/*
 * Check if contexts holding a public and private key match
 */
int jhd_tls_rsa_check_pub_priv(const jhd_tls_rsa_context *pub, const jhd_tls_rsa_context *prv) {
	if (jhd_tls_rsa_check_pubkey(pub) != 0 || jhd_tls_rsa_check_privkey(prv) != 0) {
		 return JHD_ERROR;
	}

	if (jhd_tls_mpi_cmp_mpi(&pub->N, &prv->N) != 0 || jhd_tls_mpi_cmp_mpi(&pub->E, &prv->E) != 0) {
		 return JHD_ERROR;
	}

	return (0);
}

/*
 * Do an RSA public key operation
 */
int jhd_tls_rsa_public(jhd_tls_rsa_context *ctx, const unsigned char *input, unsigned char *output) {
	int ret;
	size_t olen;
	jhd_tls_mpi T,RN;

	log_assert(rsa_check_context(ctx, 0 /* public */) == JHD_OK);
	jhd_tls_mpi_init(&T);
	jhd_tls_mpi_init(&RN);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_binary(&T, input, ctx->len));
	if (jhd_tls_mpi_cmp_mpi(&T, &ctx->N) >= 0) {
		ret = JHD_ERROR;
		goto cleanup;
	}
	olen = ctx->len;
	JHD_TLS_MPI_CHK(jhd_tls_rsa_cache_val(&ctx->N,&RN));

	JHD_TLS_MPI_CHK(jhd_tls_mpi_exp_mod(&T, &T, &ctx->E, &ctx->N, &RN));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_write_binary(&T, output, olen));
	cleanup:
	jhd_tls_mpi_free(&T);
	jhd_tls_mpi_free(&RN);
	return ret;
}

/*
 * Generate or update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static int rsa_prepare_blinding(jhd_tls_rsa_context *ctx,jhd_tls_mpi *Vi,jhd_tls_mpi *Vf,jhd_tls_mpi *RN) {
	int ret, count = 0;

   /* Unblinding value: Vf = random number, invertible mod N */
	do {
		if (count++ > 10){
			return JHD_ERROR;
		}
		JHD_TLS_MPI_CHK(jhd_tls_mpi_fill_random(Vf, ctx->len-1));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_gcd(Vi, Vf, &ctx->N));

	} while (jhd_tls_mpi_cmp_int(Vi, 1) != 0);
	/* Blinding value: Vi =  Vf^(-e) mod N */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_inv_mod(Vi, Vf, &ctx->N));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_exp_mod(Vi, Vi, &ctx->E, &ctx->N,RN));
	cleanup:
	return (ret);
}

/*
 * Exponent blinding supposed to prevent side-channel attacks using multiple
 * traces of measurements to recover the RSA key. The more collisions are there,
 * the more bits of the key can be recovered. See [3].
 *
 * Collecting n collisions with m bit long blinding value requires 2^(m-m/n)
 * observations on avarage.
 *
 * For example with 28 byte blinding to achieve 2 collisions the adversary has
 * to make 2^112 observations on avarage.
 *
 * (With the currently (as of 2017 April) known best algorithms breaking 2048
 * bit RSA requires approximately as much time as trying out 2^112 random keys.
 * Thus in this sense with 28 byte blinding the security is not reduced by
 * side-channel attacks like the one in [3])
 *
 * This countermeasure does not help if the key recovery is possible with a
 * single trace.
 */
#define RSA_EXPONENT_BLINDING 28



/*
 * Do an RSA private key operation
 */

int jhd_tls_rsa_private( jhd_tls_rsa_context *ctx,const unsigned char *input,unsigned char *output )
{
    int ret;
    size_t olen;
    jhd_tls_mpi T;
    jhd_tls_mpi P1, Q1, R;
    jhd_tls_mpi TP, TQ;
    jhd_tls_mpi DP_blind, DQ_blind;
    jhd_tls_mpi *DP = &ctx->DP;
    jhd_tls_mpi *DQ = &ctx->DQ;
    jhd_tls_mpi I, C;
    jhd_tls_mpi Vf,Vi,RN,RP,RQ;

    log_assert(rsa_check_context( ctx, 1/* private key checks */) == JHD_OK/*,"invalid rsa private key"*/);
    /* MPI Initialization */
    jhd_tls_mpi_init( &T );
    jhd_tls_mpi_init( &P1 );
    jhd_tls_mpi_init( &Q1 );
    jhd_tls_mpi_init( &R );
	jhd_tls_mpi_init( &DP_blind );
	jhd_tls_mpi_init( &DQ_blind );
    jhd_tls_mpi_init( &TP );
    jhd_tls_mpi_init( &TQ );
    jhd_tls_mpi_init( &I );
    jhd_tls_mpi_init( &C );
    jhd_tls_mpi_init(&Vi);
    jhd_tls_mpi_init(&Vf);
    jhd_tls_mpi_init(&RN);
    jhd_tls_mpi_init(&RP);
    jhd_tls_mpi_init(&RQ);

    /* End of MPI initialization */

    JHD_TLS_MPI_CHK( jhd_tls_mpi_read_binary( &T, input, ctx->len ) );
    if( jhd_tls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = JHD_ERROR;
        goto cleanup;
    }
    JHD_TLS_MPI_CHK( jhd_tls_mpi_copy( &I, &T ) );

	JHD_TLS_MPI_CHK( jhd_tls_rsa_cache_val(&ctx->N,&RN));
	JHD_TLS_MPI_CHK( jhd_tls_rsa_cache_val(&ctx->P,&RP));
	JHD_TLS_MPI_CHK( jhd_tls_rsa_cache_val(&ctx->Q,&RQ));
        /*
         * Blinding
         * T = T * Vi mod N
         */
	JHD_TLS_MPI_CHK( rsa_prepare_blinding( ctx,&Vi,&Vf,&RN));
	JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &T, &T, &Vi ) );
	JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &T, &T, &ctx->N ) );
	JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &P1, &ctx->P, 1 ) );
	JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &Q1, &ctx->Q, 1 ) );



        /*
         * DP_blind = ( P - 1 ) * R + DP
         */
	JHD_TLS_MPI_CHK( jhd_tls_mpi_fill_random( &R, RSA_EXPONENT_BLINDING) );
	JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &DP_blind, &P1, &R ) );
	JHD_TLS_MPI_CHK( jhd_tls_mpi_add_mpi( &DP_blind, &DP_blind,&ctx->DP ) );
	DP = &DP_blind;
	/*
	 * DQ_blind = ( Q - 1 ) * R + DQ
	 */
	JHD_TLS_MPI_CHK( jhd_tls_mpi_fill_random( &R, RSA_EXPONENT_BLINDING) );
	JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &DQ_blind, &Q1, &R ) );
	JHD_TLS_MPI_CHK( jhd_tls_mpi_add_mpi( &DQ_blind, &DQ_blind,&ctx->DQ ) );
	DQ = &DQ_blind;
    /*
     * Faster decryption using the CRT
     *
     * TP = input ^ dP mod P
     * TQ = input ^ dQ mod Q
     */

    JHD_TLS_MPI_CHK( jhd_tls_mpi_exp_mod( &TP, &T, DP, &ctx->P, &RP) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_exp_mod( &TQ, &T, DQ, &ctx->Q, &RQ) );
    /*
     * T = (TP - TQ) * (Q^-1 mod P) mod P
     */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_mpi( &T, &TP, &TQ ) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &TP, &T, &ctx->QP ) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &T, &TP, &ctx->P ) );

    /*
     * T = TQ + T * Q
     */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &TP, &T, &ctx->Q ) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_add_mpi( &T, &TQ, &TP ) );
        /*
         * Unblind
         * T = T * Vf mod N
         */
	JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &T, &T, &Vf ) );
	JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &T, &T, &ctx->N ) );


    /* Verify the result to prevent glitching attacks. */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_exp_mod( &C, &T, &ctx->E,&ctx->N, &RN ) );
    if( jhd_tls_mpi_cmp_mpi( &C, &I ) != 0 )
    {
        ret = JHD_ERROR;
        goto cleanup;
    }
    olen = ctx->len;
    JHD_TLS_MPI_CHK( jhd_tls_mpi_write_binary( &T, output, olen ) );

cleanup:
    jhd_tls_mpi_free( &P1 );
    jhd_tls_mpi_free( &Q1 );
    jhd_tls_mpi_free( &R );


	jhd_tls_mpi_free( &DP_blind );
	jhd_tls_mpi_free( &DQ_blind );
    jhd_tls_mpi_free( &T );
    jhd_tls_mpi_free( &TP );
    jhd_tls_mpi_free( &TQ );
    jhd_tls_mpi_free( &C );
    jhd_tls_mpi_free( &I );

    jhd_tls_mpi_free(&Vi);
    jhd_tls_mpi_free(&Vf);
    jhd_tls_mpi_free(&RN);
    jhd_tls_mpi_free(&RP);
    jhd_tls_mpi_free(&RQ);
    return ret;
}



/**
 * Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
 *
 * \param dst       buffer to mask
 * \param dlen      length of destination buffer
 * \param src       source of the mask generation
 * \param slen      length of the source buffer
 * \param md_ctx    message digest context to use
 */
static int mgf_mask(unsigned char *dst, size_t dlen, unsigned char *src, size_t slen,const jhd_tls_md_info_t *md_info,void *md_ctx) {
	unsigned char mask[JHD_TLS_MD_MAX_SIZE];
	unsigned char counter[4];
	unsigned char *p,*m;
	unsigned int hlen;
	size_t i, use_len;

	log_assert(JHD_TLS_MD_MAX_SIZE ==64);
	//memset(mask, 0, JHD_TLS_MD_MAX_SIZE);
	mem_zero_64(mask);
	mem_zero_4(counter);

	hlen = jhd_tls_md_get_size(md_info);

	/* Generate and apply dbMask */
	p = dst;

	while (dlen > 0) {
		use_len = hlen;
		if (dlen < hlen)
			use_len = dlen;

		jhd_tls_md_starts(md_info,md_ctx);

		jhd_tls_md_update(md_info,md_ctx, src, slen);

		jhd_tls_md_update(md_info,md_ctx, counter, 4);

		jhd_tls_md_finish(md_info,md_ctx,mask);

		m = mask;
		while(use_len >=8){
			p64_eq_xor(p,m);
			m+=8;
			p+=8;
			use_len -=8;
			dlen -=8;
		}
		for (i = 0; i < use_len; ++i){
			*p++ ^= m[i];
		}
		counter[3]++;
		dlen -= use_len;
	}
	return (0);
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-ENCRYPT function
 */
int jhd_tls_rsa_rsaes_oaep_encrypt(jhd_tls_rsa_context *ctx, int mode, const unsigned char *label, size_t label_len, size_t ilen, const unsigned char *input,
        unsigned char *output) {
	size_t olen;
	int ret;
	unsigned char *p = output;
	unsigned int hlen;
	unsigned char md_ctx[sizeof(jhd_tls_sha512_context)];
	log_assert(!(mode == JHD_TLS_RSA_PRIVATE && ctx->padding != JHD_TLS_RSA_PKCS_V21));
	log_assert(ctx->md_info != NULL);
	olen = ctx->len;
	hlen = jhd_tls_md_get_size(ctx->md_info);

	/* first comparison checks for overflow */
	if (ilen + 2 * hlen + 2 < ilen || olen < ilen + 2 * hlen + 2){
		return JHD_ERROR;
	}

	memset(output, 0, olen);

	*p++ = 0;

	/* Generate a random octet string seed */
	jhd_tls_random(p, hlen);

	p += hlen;

	/* Construct DB */
	  jhd_tls_md(ctx->md_info, label, label_len, p) ;
	p += hlen;
	p += olen - 2 * hlen - 2 - ilen;
	*p++ = 1;
	memcpy(p, input, ilen);

	/* maskedDB: Apply dbMask to DB */
	if ((ret = mgf_mask(output + hlen + 1, olen - hlen - 1, output + 1, hlen, ctx->md_info,md_ctx)) != 0)
		goto exit;

	/* maskedSeed: Apply seedMask to seed */
	if ((ret = mgf_mask(output + 1, hlen, output + hlen + 1, olen - hlen - 1, ctx->md_info,md_ctx)) != 0)
		goto exit;

	exit:

	if (ret != 0)
		return (ret);

	return ((mode == JHD_TLS_RSA_PUBLIC) ? jhd_tls_rsa_public(ctx, output, output) : jhd_tls_rsa_private(ctx, output, output));
}


/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-ENCRYPT function
 */
int jhd_tls_rsa_rsaes_pkcs1_v15_encrypt(jhd_tls_rsa_context *ctx, int mode, size_t ilen, const unsigned char *input, unsigned char *output) {
	size_t nb_pad, olen;
	unsigned char *p = output;

	log_assert(!(mode == JHD_TLS_RSA_PRIVATE && ctx->padding != JHD_TLS_RSA_PKCS_V15));
	// We don't check p_rng because it won't be dereferenced here
	log_assert(input != NULL && output != NULL);

	olen = ctx->len;

	/* first comparison checks for overflow */
	if (ilen + 11 < ilen || olen < ilen + 11)
		return JHD_ERROR;

	nb_pad = olen - 3 - ilen;

	*p++ = 0;
	if (mode == JHD_TLS_RSA_PUBLIC) {
		*p++ = JHD_TLS_RSA_CRYPT;

		while (nb_pad-- > 0) {

			do {
				jhd_tls_random(p, 1);
			} while (*p == 0);

			p++;
		}
	} else {
		*p++ = JHD_TLS_RSA_SIGN;

		while (nb_pad-- > 0)
			*p++ = 0xFF;
	}

	*p++ = 0;
	memcpy(p, input, ilen);

	return ((mode == JHD_TLS_RSA_PUBLIC) ? jhd_tls_rsa_public(ctx, output, output) : jhd_tls_rsa_private(ctx, output, output));
}

/*
 * Add the message padding, then do an RSA operation
 */
int jhd_tls_rsa_pkcs1_encrypt(jhd_tls_rsa_context *ctx, int mode, size_t ilen, const unsigned char *input, unsigned char *output) {
	switch (ctx->padding) {
			return jhd_tls_rsa_rsaes_pkcs1_v15_encrypt(ctx, mode, ilen, input, output);
		case JHD_TLS_RSA_PKCS_V21:
			return jhd_tls_rsa_rsaes_oaep_encrypt(ctx, mode, NULL, 0, ilen, input, output);
		default:
			return JHD_ERROR;
	}
}


/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-DECRYPT function
 */
int jhd_tls_rsa_rsaes_oaep_decrypt(jhd_tls_rsa_context *ctx, int mode, const unsigned char *label, size_t label_len, size_t *olen, const unsigned char *input,
        unsigned char *output, size_t output_max_len) {
	int ret;
	size_t ilen, i, pad_len;
	unsigned char *p, bad, pad_done;
	unsigned char buf[JHD_TLS_MPI_MAX_SIZE];
	unsigned char lhash[JHD_TLS_MD_MAX_SIZE];
	unsigned int hlen;
	JHD_TLS_MD_CONTEXT_DEFINE(md_ctx);
	/*
	 * Parameters sanity checks
	 */
	log_assert(!(mode == JHD_TLS_RSA_PRIVATE && ctx->padding != JHD_TLS_RSA_PKCS_V21));
	ilen = ctx->len;
	log_assert(ilen>=16 && ctx->len <= sizeof(buf));
	log_assert(ctx->md_info != NULL);
	hlen = jhd_tls_md_get_size(ctx->md_info);
	log_assert(ilen <= (2*hlen+2));

	/*
	 * RSA operation
	 */
	ret = (mode == JHD_TLS_RSA_PUBLIC) ? jhd_tls_rsa_public(ctx, input, buf) : jhd_tls_rsa_private(ctx, input, buf);

	if (ret != 0)
		goto cleanup;

	/* seed: Apply seedMask to maskedSeed */
	if ((ret = mgf_mask(buf + 1, hlen, buf + hlen + 1, ilen - hlen - 1,ctx->md_info,md_ctx)) != 0 ||
	/* DB: Apply dbMask to maskedDB */
	(ret = mgf_mask(buf + hlen + 1, ilen - hlen - 1, buf + 1, hlen,ctx->md_info,md_ctx)) != 0) {
		goto cleanup;
	}

	/* Generate lHash */
	 jhd_tls_md(ctx->md_info, label, label_len, lhash) ;

	/*
	 * Check contents, in "constant-time"
	 */
	p = buf;
	bad = 0;

	bad |= *p++; /* First byte must be 0 */

	p += hlen; /* Skip seed */

	/* Check lHash */
	for (i = 0; i < hlen; i++)
		bad |= lhash[i] ^ *p++;

	/* Get zero-padding len, but always read till end of buffer
	 * (minus one, for the 01 byte) */
	pad_len = 0;
	pad_done = 0;
	for (i = 0; i < ilen - 2 * hlen - 2; i++) {
		pad_done |= p[i];
		pad_len += ((pad_done | (unsigned char) -pad_done) >> 7) ^ 1;
	}

	p += pad_len;
	bad |= *p++ ^ 0x01;

	/*
	 * The only information "leaked" is whether the padding was correct or not
	 * (eg, no data is copied if it was not correct). This meets the
	 * recommendations in PKCS#1 v2.2: an opponent cannot distinguish between
	 * the different error conditions.
	 */
	if (bad != 0) {
		ret = JHD_ERROR;
		goto cleanup;
	}

	if (ilen - (p - buf) > output_max_len) {
		ret = JHD_ERROR;
		goto cleanup;
	}

	*olen = ilen - (p - buf);
	memcpy(output, p, *olen);
	ret = 0;

	cleanup:
	return (ret);
}


/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-DECRYPT function
 */
int jhd_tls_rsa_rsaes_pkcs1_v15_decrypt(jhd_tls_rsa_context *ctx, int mode, size_t *olen, const unsigned char *input, unsigned char *output,
        size_t output_max_len) {
	int ret;
	size_t ilen, pad_count = 0, i;
	unsigned char *p, bad, pad_done = 0;
	unsigned char buf[JHD_TLS_MPI_MAX_SIZE];

	log_assert(!(mode == JHD_TLS_RSA_PRIVATE && ctx->padding != JHD_TLS_RSA_PKCS_V15));
	ilen = ctx->len;
	log_assert(ilen>=16 && ctx->len <= sizeof(buf));
	ret = (mode == JHD_TLS_RSA_PUBLIC) ? jhd_tls_rsa_public(ctx, input, buf) : jhd_tls_rsa_private(ctx, input, buf);

	if (ret != 0)
		goto cleanup;

	p = buf;
	bad = 0;

	/*
	 * Check and get padding len in "constant-time"
	 */
	bad |= *p++; /* First byte must be 0 */

	/* This test does not depend on secret data */
	if (mode == JHD_TLS_RSA_PRIVATE) {
		bad |= *p++ ^ JHD_TLS_RSA_CRYPT;

		/* Get padding len, but always read till end of buffer
		 * (minus one, for the 00 byte) */
		for (i = 0; i < ilen - 3; i++) {
			pad_done |= ((p[i] | (unsigned char) -p[i]) >> 7) ^ 1;
			pad_count += ((pad_done | (unsigned char) -pad_done) >> 7) ^ 1;
		}

		p += pad_count;
		bad |= *p++; /* Must be zero */
	} else {
		bad |= *p++ ^ JHD_TLS_RSA_SIGN;

		/* Get padding len, but always read till end of buffer
		 * (minus one, for the 00 byte) */
		for (i = 0; i < ilen - 3; i++) {
			pad_done |= (p[i] != 0xFF);
			pad_count += (pad_done == 0);
		}

		p += pad_count;
		bad |= *p++; /* Must be zero */
	}

	bad |= (pad_count < 8);

	if (bad) {
		ret = JHD_ERROR;
		goto cleanup;
	}

	if (ilen - (p - buf) > output_max_len) {
		ret = JHD_ERROR;
		goto cleanup;
	}

	*olen = ilen - (p - buf);
	memcpy(output, p, *olen);
	ret = 0;

	cleanup:
	jhd_tls_platform_zeroize(buf, sizeof(buf));

	return (ret);
}


/*
 * Do an RSA operation, then remove the message padding
 */
int jhd_tls_rsa_pkcs1_decrypt(jhd_tls_rsa_context *ctx, int mode, size_t *olen, const unsigned char *input, unsigned char *output, size_t output_max_len) {
	switch (ctx->padding) {
		case JHD_TLS_RSA_PKCS_V15:
			return jhd_tls_rsa_rsaes_pkcs1_v15_decrypt(ctx, mode, olen, input, output, output_max_len);
		case JHD_TLS_RSA_PKCS_V21:
			return jhd_tls_rsa_rsaes_oaep_decrypt(ctx, mode, NULL, 0, olen, input, output, output_max_len);
		default:
			return ( JHD_ERROR);
	}
}


/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN function
 */
int jhd_tls_rsa_rsassa_pss_sign(jhd_tls_rsa_context *ctx, int mode, const jhd_tls_md_info_t *md_info, unsigned int hashlen, const unsigned char *hash,unsigned char *sig) {
	size_t olen;
	unsigned char *p = sig;
	unsigned char salt[JHD_TLS_MD_MAX_SIZE];
	unsigned int slen, hlen, offset = 0;
	int ret;
	size_t msb;
	JHD_TLS_MD_CONTEXT_DEFINE(md_ctx);

	olen = ctx->len;

	if (md_info != NULL) {
		hashlen = jhd_tls_md_get_size(md_info);
	}

	log_assert(ctx->md_info != NULL);

	hlen = jhd_tls_md_get_size(ctx->md_info);
	slen = hlen;
	log_assert(!(olen < hlen + slen + 2));
	memset(sig, 0, olen);

	jhd_tls_random(salt, slen);

	/* Note: EMSA-PSS encoding is over the length of N - 1 bits */
	msb = jhd_tls_mpi_bitlen(&ctx->N) - 1;
	p += olen - hlen * 2 - 2;
	*p++ = 0x01;
	memcpy(p, salt, slen);
	p += slen;


	/* Generate H = Hash( M' ) */
	 jhd_tls_md_starts(ctx->md_info,md_ctx);

	 jhd_tls_md_update(ctx->md_info,md_ctx, p, 8);

	 jhd_tls_md_update(ctx->md_info,md_ctx, hash, hashlen);

	 jhd_tls_md_update(ctx->md_info,md_ctx, salt, slen);

	 jhd_tls_md_finish(ctx->md_info,md_ctx, p);


	/* Compensate for boundary condition when applying mask */
	if (msb % 8 == 0)
		offset = 1;

	/* maskedDB: Apply dbMask to DB */
	if ((ret = mgf_mask(sig + offset, olen - hlen - 1 - offset, p, hlen,ctx->md_info,md_ctx)) != 0)
		goto exit;

	msb = jhd_tls_mpi_bitlen(&ctx->N) - 1;
	sig[0] &= 0xFF >> (olen * 8 - msb);

	p += hlen;
	*p++ = 0xBC;

	exit:

	if (ret != 0)
		return (ret);

	return ((mode == JHD_TLS_RSA_PUBLIC) ? jhd_tls_rsa_public(ctx, sig, sig) : jhd_tls_rsa_private(ctx, sig, sig));
}



/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-V1_5-SIGN function
 */

/* Construct a PKCS v1.5 encoding of a hashed message
 *
 * This is used both for signature generation and verification.
 *
 * Parameters:
 * - md_alg:  Identifies the hash algorithm used to generate the given hash;
 *            JHD_TLS_MD_NONE if raw data is signed.
 * - hashlen: Length of hash in case hashlen is JHD_TLS_MD_NONE.
 * - hash:    Buffer containing the hashed message or the raw data.
 * - dst_len: Length of the encoded message.
 * - dst:     Buffer to hold the encoded message.
 *
 * Assumptions:
 * - hash has size hashlen if md_alg == JHD_TLS_MD_NONE.
 * - hash has size corresponding to md_alg if md_alg != JHD_TLS_MD_NONE.
 * - dst points to a buffer of size at least dst_len.
 *
 */
static int rsa_rsassa_pkcs1_v15_encode(const jhd_tls_md_info_t *md_info, unsigned int hashlen, const unsigned char *hash, size_t dst_len, unsigned char *dst) {
	size_t oid_size = 0;
	size_t nb_pad = dst_len;
	unsigned char *p = dst;
	const char *oid = NULL;

	/* Are we signing hashed or raw data? */
	if (md_info != NULL) {
		jhd_tls_oid_get_oid_by_md(md_info, &oid, &oid_size);
		if(oid == NULL){
			return JHD_ERROR;
		}
		hashlen = jhd_tls_md_get_size(md_info);

		/* Double-check that 8 + hashlen + oid_size can be used as a
		 * 1-byte ASN.1 length encoding and that there's no overflow. */
		if (8 + hashlen + oid_size >= 0x80 || 10 + hashlen < hashlen || 10 + hashlen + oid_size < 10 + hashlen){
			return JHD_ERROR;
		}
		/*
		 * Static bounds check:
		 * - Need 10 bytes for five tag-length pairs.
		 *   (Insist on 1-byte length encodings to protect against variants of
		 *    Bleichenbacher's forgery attack against lax PKCS#1v1.5 verification)
		 * - Need hashlen bytes for hash
		 * - Need oid_size bytes for hash alg OID.
		 */
		if (nb_pad < 10 + hashlen + oid_size){
			return JHD_ERROR;
		}
		nb_pad -= 10 + hashlen + oid_size;
	} else {
		if (nb_pad < hashlen){
			return JHD_ERROR;
		}
		nb_pad -= hashlen;
	}

	/* Need space for signature header and padding delimiter (3 bytes),
	 * and 8 bytes for the minimal padding */
	if (nb_pad < 3 + 8){
		return JHD_ERROR;
	}
	nb_pad -= 3;

	/* Now nb_pad is the amount of memory to be filled
	 * with padding, and at least 8 bytes long. */

	/* Write signature header and padding */
	*p++ = 0;
	*p++ = JHD_TLS_RSA_SIGN;
	memset(p, 0xFF, nb_pad);
	p += nb_pad;
	*p++ = 0;

	/* Are we signing raw data? */
	if (md_info == NULL) {
		memcpy(p, hash, hashlen);
		return (0);
	}

	/* Signing hashed data, add corresponding ASN.1 structure
	 *
	 * DigestInfo ::= SEQUENCE {
	 *   digestAlgorithm DigestAlgorithmIdentifier,
	 *   digest Digest }
	 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
	 * Digest ::= OCTET STRING
	 *
	 * Schematic:
	 * TAG-SEQ + LEN [ TAG-SEQ + LEN [ TAG-OID  + LEN [ OID  ]
	 *                                 TAG-NULL + LEN [ NULL ] ]
	 *                 TAG-OCTET + LEN [ HASH ] ]
	 */
	*p++ = JHD_TLS_ASN1_SEQUENCE | JHD_TLS_ASN1_CONSTRUCTED;
	*p++ = (unsigned char) (0x08 + oid_size + hashlen);
	*p++ = JHD_TLS_ASN1_SEQUENCE | JHD_TLS_ASN1_CONSTRUCTED;
	*p++ = (unsigned char) (0x04 + oid_size);
	*p++ = JHD_TLS_ASN1_OID;
	*p++ = (unsigned char) oid_size;
	memcpy(p, oid, oid_size);
	p += oid_size;
	*p++ = JHD_TLS_ASN1_NULL;
	*p++ = 0x00;
	*p++ = JHD_TLS_ASN1_OCTET_STRING;
	*p++ = (unsigned char) hashlen;
	memcpy(p, hash, hashlen);
	p += hashlen;

	/* Just a sanity-check, should be automatic
	 * after the initial bounds check. */
	if (p != dst + dst_len){
		return JHD_ERROR;
	}

	return (0);
}

/*
 * Do an RSA operation to sign the message digest
 */
int jhd_tls_rsa_rsassa_pkcs1_v15_sign(jhd_tls_rsa_context *ctx, int mode, const jhd_tls_md_info_t *md_info, unsigned int hashlen, const unsigned char *hash,
        unsigned char *sig) {
	int ret;
	unsigned char sig_try[1024];
	unsigned char verif[1024];

	/*
	 * Prepare PKCS1-v1.5 encoding (padding and hash identifier)
	 */

	if ((ret = rsa_rsassa_pkcs1_v15_encode(md_info, hashlen, hash, ctx->len, sig)) != 0)
		return (ret);

	/*
	 * Call respective RSA primitive
	 */

	if (mode == JHD_TLS_RSA_PUBLIC) {
		/* Skip verification on a public key operation */
		return (jhd_tls_rsa_public(ctx, sig, sig));
	}

	/* Private key operation
	 *
	 * In order to prevent Lenstra's attack, make the signature in a
	 * temporary buffer and check it before returning it.
	 */

	//TODO:check ctx->len > sizeof(sig_try);


	JHD_TLS_MPI_CHK(jhd_tls_rsa_private(ctx, sig, sig_try));
	JHD_TLS_MPI_CHK(jhd_tls_rsa_public(ctx, sig_try, verif));

	if (jhd_tls_safer_memcmp(verif, sig, ctx->len) != 0) {
		ret = JHD_ERROR;
		goto cleanup;
	}

	memcpy(sig, sig_try, ctx->len);
	cleanup:
	return (ret);
}


/*
 * Do an RSA operation to sign the message digest
 */
int jhd_tls_rsa_pkcs1_sign(jhd_tls_rsa_context *ctx, int mode,const jhd_tls_md_info_t *md_info, unsigned int hashlen, const unsigned char *hash, unsigned char *sig) {
	switch (ctx->padding) {
		case JHD_TLS_RSA_PKCS_V15:
			return jhd_tls_rsa_rsassa_pkcs1_v15_sign(ctx, mode, md_info, hashlen, hash, sig);
		case JHD_TLS_RSA_PKCS_V21:
			return jhd_tls_rsa_rsassa_pss_sign(ctx, mode, md_info, hashlen, hash, sig);
		default:
			return JHD_ERROR;
	}
}


/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-VERIFY function
 */
int jhd_tls_rsa_rsassa_pss_verify_ext(jhd_tls_rsa_context *ctx, int mode, const jhd_tls_md_info_t *md_info, unsigned int hashlen, const unsigned char *hash,
		const jhd_tls_md_info_t *md_info_2, int expected_salt_len, const unsigned char *sig) {
	int ret;
	size_t siglen;
	unsigned char *p;
	unsigned char *hash_start;
	unsigned char result[JHD_TLS_MD_MAX_SIZE];
	unsigned char zeros[8];
	unsigned int hlen;
	size_t observed_salt_len, msb;
	JHD_TLS_MD_CONTEXT_DEFINE(md_ctx);
	unsigned char buf[JHD_TLS_MPI_MAX_SIZE];

	if (mode == JHD_TLS_RSA_PRIVATE && ctx->padding != JHD_TLS_RSA_PKCS_V21){
		return JHD_ERROR;
	}
	siglen = ctx->len;

	if (siglen < 16 || siglen > sizeof(buf)){
		return JHD_ERROR;
	}

	ret = (mode == JHD_TLS_RSA_PUBLIC) ? jhd_tls_rsa_public(ctx, sig, buf) : jhd_tls_rsa_private(ctx, sig, buf);

	if (ret != 0)
		return (ret);

	p = buf;

	if (buf[siglen - 1] != 0xBC){
		return JHD_ERROR;
	}
	if (md_info ) {
		hashlen = jhd_tls_md_get_size(md_info);
	}


	hlen = jhd_tls_md_get_size(md_info_2);

	memset(zeros, 0, 8);

	/*
	 * Note: EMSA-PSS verification is over the length of N - 1 bits
	 */
	msb = jhd_tls_mpi_bitlen(&ctx->N) - 1;

	if (buf[0] >> (8 - siglen * 8 + msb)){
		return JHD_ERROR;
	}

	/* Compensate for boundary condition when applying mask */
	if (msb % 8 == 0) {
		p++;
		siglen -= 1;
	}

	if (siglen < hlen + 2){
		return JHD_ERROR;
	}
	hash_start = p + siglen - hlen - 1;

	ret = mgf_mask(p, siglen - hlen - 1, hash_start, hlen, md_info_2,md_ctx);
	if (ret != 0)
		goto exit;

	buf[0] &= 0xFF >> (siglen * 8 - msb);

	while (p < hash_start - 1 && *p == 0)
		p++;

	if (*p++ != 0x01) {
		ret = JHD_ERROR;
		goto exit;
	}

	observed_salt_len = hash_start - p;

	if (expected_salt_len != JHD_TLS_RSA_SALT_LEN_ANY && observed_salt_len != (size_t) expected_salt_len) {
		ret = JHD_ERROR;
		goto exit;
	}

	/*
	 * Generate H = Hash( M' )
	 */
	  jhd_tls_md_starts(md_info_2,md_ctx);

	 jhd_tls_md_update(md_info_2,md_ctx, zeros, 8);

	  jhd_tls_md_update(md_info_2,md_ctx, hash, hashlen);

	  jhd_tls_md_update(md_info_2,md_ctx, p, observed_salt_len);

	  jhd_tls_md_finish(md_info_2,md_ctx, result);

	if (memcmp(hash_start, result, hlen) != 0) {
		ret = JHD_ERROR;
		goto exit;
	}

	exit:

	return (ret);
}

/*
 * Simplified PKCS#1 v2.1 RSASSA-PSS-VERIFY function
 */
int jhd_tls_rsa_rsassa_pss_verify(jhd_tls_rsa_context *ctx, int mode, const jhd_tls_md_info_t *md_info, unsigned int hashlen, const unsigned char *hash,
        const unsigned char *sig) {
	return (jhd_tls_rsa_rsassa_pss_verify_ext(ctx, mode, md_info, hashlen, hash, ctx->md_info?ctx->md_info:md_info, JHD_TLS_RSA_SALT_LEN_ANY, sig));
}


/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-v1_5-VERIFY function
 */
int jhd_tls_rsa_rsassa_pkcs1_v15_verify(jhd_tls_rsa_context *ctx, int mode, const jhd_tls_md_info_t *md_info, unsigned int hashlen, const unsigned char *hash,
        const unsigned char *sig) {
	int ret = 0;
	unsigned char encoded[8192];
	unsigned char encoded_expected[8192];
	const size_t sig_len = ctx->len;
	log_assert(sig_len <=8192/*,"invalid rsa key:bit len too large"*/);
	if (mode == JHD_TLS_RSA_PRIVATE && ctx->padding != JHD_TLS_RSA_PKCS_V15){
		return JHD_ERROR;
	}
	if (JHD_OK!= rsa_rsassa_pkcs1_v15_encode(md_info, hashlen, hash, sig_len, encoded_expected)) {
		return JHD_ERROR;
	}

	/*
	 * Apply RSA primitive to get what should be PKCS1 encoded hash.
	 */

	if (JHD_OK!= ((mode == JHD_TLS_RSA_PUBLIC) ? jhd_tls_rsa_public(ctx, sig, encoded) : jhd_tls_rsa_private(ctx, sig, encoded))){
		return JHD_ERROR;
	}
	/*
	 * Compare
	 */

	if ((ret = jhd_tls_safer_memcmp(encoded, encoded_expected, sig_len)) != 0) {
		return JHD_ERROR;
	}
	return JHD_OK;
}


/*
 * Do an RSA operation and check the message digest
 */
int jhd_tls_rsa_pkcs1_verify(jhd_tls_rsa_context *ctx, int mode,const jhd_tls_md_info_t *md_info, unsigned int hashlen, const unsigned char *hash,
        const unsigned char *sig) {
	switch (ctx->padding) {
		case JHD_TLS_RSA_PKCS_V15:
			return jhd_tls_rsa_rsassa_pkcs1_v15_verify(ctx, mode, md_info, hashlen, hash, sig);
		case JHD_TLS_RSA_PKCS_V21:
			return jhd_tls_rsa_rsassa_pss_verify(ctx, mode, md_info, hashlen, hash, sig);
		default:
			return JHD_ERROR;
	}
}

///*
// * Copy the components of an RSA key
// */
//int jhd_tls_rsa_copy(jhd_tls_rsa_context *dst, const jhd_tls_rsa_context *src) {
//	int ret;
//
//	dst->ver = src->ver;
//	dst->len = src->len;
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->N, &src->N));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->E, &src->E));
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->D, &src->D));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->P, &src->P));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->Q, &src->Q));
//
//#if !defined(JHD_TLS_RSA_NO_CRT)
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->DP, &src->DP));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->DQ, &src->DQ));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->QP, &src->QP));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->RP, &src->RP));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->RQ, &src->RQ));
//#endif
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->RN, &src->RN));
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->Vi, &src->Vi));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&dst->Vf, &src->Vf));
//
//	dst->padding = src->padding;
//	dst->md_info = src->md_info;
//
//	cleanup: if (ret != 0)
//		jhd_tls_rsa_free(dst);
//
//	return (ret);
//}

/*
 * Free the components of an RSA key
 */
void jhd_tls_rsa_free(jhd_tls_rsa_context *ctx) {
//	jhd_tls_mpi_free(&ctx->Vi);
//	jhd_tls_mpi_free(&ctx->Vf);
//	jhd_tls_mpi_free(&ctx->RN);
	jhd_tls_mpi_free(&ctx->D);
	jhd_tls_mpi_free(&ctx->Q);
	jhd_tls_mpi_free(&ctx->P);
	jhd_tls_mpi_free(&ctx->E);
	jhd_tls_mpi_free(&ctx->N);
//	jhd_tls_mpi_free(&ctx->RQ);
//	jhd_tls_mpi_free(&ctx->RP);
	jhd_tls_mpi_free(&ctx->QP);
	jhd_tls_mpi_free(&ctx->DQ);
	jhd_tls_mpi_free(&ctx->DP);



#undef  JHD_TLS_MPI_TEMP_READ_MPI

#undef JHD_TLS_MPI_TEMP_CHECK_MPI
}





