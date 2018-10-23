#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>



#include <tls/jhd_tls_ecp.h>

#include <string.h>



#include <tls/jhd_tls_platform.h>

#include <tls/jhd_tls_ecp_internal.h>
#include <tls/jhd_tls_ecp.h>

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif



/*
 * List of supported curves:
 *  - internal ID
 *  - TLS NamedCurve ID (RFC 4492 sec. 5.1.1, RFC 7071 sec. 2)
 *  - size in bits
 *  - readable name
 *
 * Curves are listed in order: largest curves first, and for a given size,
 * fastest curves first. This provides the default order for the SSL module.
 *
 * Reminder: update profiles in x509_crt.c when adding a new curves!
 */
#if !defined(JHD_TLS_INLINE)
static
#endif
  jhd_tls_ecp_curve_info ecp_supported_curves[] = {
        { JHD_TLS_ECP_DP_SECP521R1, 25, 521, "secp521r1" },
        { JHD_TLS_ECP_DP_BP512R1, 28, 512, "brainpoolP512r1" },
        { JHD_TLS_ECP_DP_SECP384R1, 24, 384, "secp384r1" },
        { JHD_TLS_ECP_DP_BP384R1, 27, 384, "brainpoolP384r1" },
        { JHD_TLS_ECP_DP_SECP256R1, 23, 256, "secp256r1" },
        { JHD_TLS_ECP_DP_SECP256K1, 22, 256, "secp256k1" },
        { JHD_TLS_ECP_DP_BP256R1, 26, 256, "brainpoolP256r1" },
        { JHD_TLS_ECP_DP_SECP224R1, 21, 224, "secp224r1" },
        { JHD_TLS_ECP_DP_SECP224K1, 20, 224, "secp224k1" },
        { JHD_TLS_ECP_DP_SECP192R1, 19, 192, "secp192r1" },
        { JHD_TLS_ECP_DP_SECP192K1, 18, 192, "secp192k1" },
        { JHD_TLS_ECP_DP_NONE, 0, 0, NULL }, };


static jhd_tls_ecp_group  ecp_supported_ecp_groups[(sizeof(ecp_supported_curves)  / sizeof(jhd_tls_ecp_curve_info))-1];

void jhd_tls_ecp_init(){
	int i = 0;
	jhd_tls_platform_zeroize(ecp_supported_ecp_groups,sizeof(ecp_supported_ecp_groups));
	do{
		jhd_tls_ecp_group_load(&ecp_supported_ecp_groups[i],(jhd_tls_ecp_group_id)(ecp_supported_curves[i].grp_id));
		++i;
	}while(ecp_supported_curves[i].grp_id != JHD_TLS_ECP_DP_NONE);
}
jhd_tls_ecp_group* jhd_tls_ecp_group_get(jhd_tls_ecp_group_id grp_id){
	int i = 0;
	do{
		if(grp_id == ecp_supported_curves[i].grp_id){
			return &ecp_supported_ecp_groups[i];
		}
		++i;
	}while(ecp_supported_curves[i].grp_id != JHD_TLS_ECP_DP_NONE);
	log_err("unsupported ecp_curve_group:%d",(int)grp_id);
	return NULL;

}
#if !defined(JHD_TLS_INLINE)
/*
 * List of supported curves and associated info
 */
const jhd_tls_ecp_curve_info *jhd_tls_ecp_curve_list(void) {
	return (ecp_supported_curves);
}
#endif
/*
 * Get the curve info for the internal identifier
 */
const jhd_tls_ecp_curve_info *jhd_tls_ecp_curve_info_from_grp_id(jhd_tls_ecp_group_id grp_id) {
	const jhd_tls_ecp_curve_info *curve_info;

	for (curve_info = jhd_tls_ecp_curve_list(); curve_info->grp_id != JHD_TLS_ECP_DP_NONE; curve_info++) {
		if (curve_info->grp_id == grp_id)
			return (curve_info);
	}

	return ( NULL);
}

#ifdef JHD_LOG_LEVEL_INFO
int jhd_tls_ecp_point_equals(jhd_tls_ecp_point *p1,jhd_tls_ecp_point *p2){
	if(p1!=p2){
		if(JHD_OK != jhd_tls_mpi_equals(&p1->X,&p2->X)){
					return JHD_ERROR;
		}
		if(JHD_OK != jhd_tls_mpi_equals(&p1->Y,&p2->Y)){
					return JHD_ERROR;
		}
		if(JHD_OK != jhd_tls_mpi_equals(&p1->Z,&p2->Z)){
					return JHD_ERROR;
		}
	}
	return JHD_OK;
}
int jhd_tls_ecp_keypair_equals(jhd_tls_ecp_keypair *key1,jhd_tls_ecp_keypair *key2){
	if(key1 != key2){
		if(key1->grp != key2->grp){
			return JHD_ERROR;
		}
		if(JHD_OK != jhd_tls_mpi_equals(&key1->private_key,&key2->private_key)){
			return JHD_ERROR;
		}
		if(JHD_OK != jhd_tls_ecp_point_equals(&key1->public_key,&key2->public_key)){
			return JHD_ERROR;
		}

	}
	return JHD_OK;
}
#endif

/*
 * Get the curve info from the TLS identifier
 */
const jhd_tls_ecp_curve_info *jhd_tls_ecp_curve_info_from_tls_id(uint16_t tls_id) {
	const jhd_tls_ecp_curve_info *curve_info;

	for (curve_info = jhd_tls_ecp_curve_list(); curve_info->grp_id != JHD_TLS_ECP_DP_NONE; curve_info++) {
		if (curve_info->tls_id == tls_id)
			return (curve_info);
	}

	return ( NULL);
}

/*
 * Get the curve info from the name
 */
const jhd_tls_ecp_curve_info *jhd_tls_ecp_curve_info_from_name(const char *name) {
	const jhd_tls_ecp_curve_info *curve_info;

	for (curve_info = jhd_tls_ecp_curve_list(); curve_info->grp_id != JHD_TLS_ECP_DP_NONE; curve_info++) {
		if (strcmp(curve_info->name, name) == 0)
			return (curve_info);
	}

	return ( NULL);
}


/*
 * Initialize (the components of) a point
 */
void jhd_tls_ecp_point_init(jhd_tls_ecp_point *pt) {
	jhd_tls_mpi_init(&pt->X);
	jhd_tls_mpi_init(&pt->Y);
	jhd_tls_mpi_init(&pt->Z);
}

/*
 * Initialize (the components of) a group
 */
void jhd_tls_ecp_group_init(jhd_tls_ecp_group *grp) {
	memset(grp, 0, sizeof(jhd_tls_ecp_group));
}

/*
 * Initialize (the components of) a key pair
 */
void jhd_tls_ecp_keypair_init(jhd_tls_ecp_keypair *key) {
	jhd_tls_mpi_init(&key->private_key);
	jhd_tls_ecp_point_init(&key->public_key);
}

/*
 * Unallocate (the components of) a point
 */
void jhd_tls_ecp_point_free(jhd_tls_ecp_point *pt) {
	jhd_tls_mpi_free(&(pt->X));
	jhd_tls_mpi_free(&(pt->Y));
	jhd_tls_mpi_free(&(pt->Z));
}


/*
 * Unallocate (the components of) a key pair
 */
void jhd_tls_ecp_keypair_free(jhd_tls_ecp_keypair *key) {
	jhd_tls_mpi_free(&key->private_key);
	jhd_tls_ecp_point_free(&key->public_key);
}

/*
 * Copy the contents of a point
 */
int jhd_tls_ecp_copy(jhd_tls_ecp_point *P, const jhd_tls_ecp_point *Q) {
	int ret;
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&P->X, &Q->X));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&P->Y, &Q->Y));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&P->Z, &Q->Z));
	cleanup: return (ret);
}

/*
 * Set point to zero
 */
int jhd_tls_ecp_set_zero(jhd_tls_ecp_point *pt) {
	int ret;
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&pt->X, 1));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&pt->Y, 1));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&pt->Z, 0));
	cleanup: return (ret);
}

#if !defined(JHD_TLS_INLINE)
/*
 * Tell if a point is zero
 */
int jhd_tls_ecp_is_zero(jhd_tls_ecp_point *pt) {
	return (jhd_tls_mpi_cmp_int(&pt->Z, 0) == 0);
}
#endif
/*
 * Compare two points lazyly
 */
int jhd_tls_ecp_point_cmp(const jhd_tls_ecp_point *P, const jhd_tls_ecp_point *Q) {
	if (jhd_tls_mpi_cmp_mpi(&P->X, &Q->X) == 0 && jhd_tls_mpi_cmp_mpi(&P->Y, &Q->Y) == 0 && jhd_tls_mpi_cmp_mpi(&P->Z, &Q->Z) == 0) {
		return (0);
	}
	return JHD_ERROR;
}

///*
// * Import a non-zero point from ASCII strings
// */
//int jhd_tls_ecp_point_read_string(jhd_tls_ecp_point *P, int radix, const char *x, const char *y) {
//	int ret;
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_string(&P->X, radix, x));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_string(&P->Y, radix, y));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&P->Z, 1));
//
//	cleanup: return (ret);
//}

/*
 * Export a point into unsigned binary data (SEC1 2.3.3)
 */
int jhd_tls_ecp_point_write_binary(const jhd_tls_ecp_group *grp, const jhd_tls_ecp_point *public_key, int format, size_t *olen, unsigned char *buf, size_t buflen) {
	int ret = 0;
	size_t plen;

	/*
	 * Common case: P == 0
	 */
	if (jhd_tls_mpi_cmp_int(&public_key->Z, 0) == 0) {
		if (buflen < 1){
			return JHD_ERROR;
		}
		buf[0] = 0x00;
		*olen = 1;
		return (0);
	}
	plen = jhd_tls_mpi_size(&grp->P);
	if (format == JHD_TLS_ECP_PF_UNCOMPRESSED) {
		*olen = 2 * plen + 1;

		if (buflen < *olen){
			return JHD_ERROR;
		}
		buf[0] = 0x04;
		JHD_TLS_MPI_CHK(jhd_tls_mpi_write_binary(&public_key->X, buf + 1, plen));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_write_binary(&public_key->Y, buf + 1 + plen, plen));
	} else if (format == JHD_TLS_ECP_PF_COMPRESSED) {
		*olen = plen + 1;
		if (buflen < *olen){
			return JHD_ERROR;
		}
		buf[0] = 0x02 + jhd_tls_mpi_get_bit(&public_key->Y, 0);
		JHD_TLS_MPI_CHK(jhd_tls_mpi_write_binary(&public_key->X, buf + 1, plen));
	}
	cleanup: return (ret);
}

/*
 * Import a point from unsigned binary data (SEC1 2.3.4)
 */
int jhd_tls_ecp_point_read_binary(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *pt, const unsigned char *buf, size_t ilen) {
	int ret;
	size_t plen;
	if (ilen < 1){
		return JHD_ERROR;
	}
	if (buf[0] == 0x00) {
		if (ilen == 1){
			return (jhd_tls_ecp_set_zero(pt));
		}else{
			return JHD_ERROR;
		}
	}
	plen = jhd_tls_mpi_size(&grp->P);

	if (buf[0] != 0x04){
		return JHD_UNEXPECTED;
	}
	if (ilen != 2 * plen + 1){
		return JHD_ERROR;
	}
	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_binary(&pt->X, buf + 1, plen));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_binary(&pt->Y, buf + 1 + plen, plen));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&pt->Z, 1));
	cleanup: return (ret);
}

/*
 * Import a point from a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int jhd_tls_ecp_tls_read_point(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *pt, const unsigned char **buf, size_t buf_len) {
	unsigned char data_len;
	const unsigned char *buf_start;
	/*
	 * We must have at least two bytes (1 for length, at least one for data)
	 */
	if (buf_len < 2){
		return JHD_ERROR;
	}
	data_len = *(*buf)++;
	if (data_len < 1 || data_len > buf_len - 1){
		return JHD_ERROR;
	}
	/*
	 * Save buffer start for read_binary and update buf
	 */
	buf_start = *buf;
	*buf += data_len;

	return jhd_tls_ecp_point_read_binary(grp, pt, buf_start, data_len);
}

/*
 * Export a point as a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int jhd_tls_ecp_tls_write_point(const jhd_tls_ecp_group *grp, const jhd_tls_ecp_point *public_key, int format, size_t *olen, unsigned char *buf, size_t blen) {
	int ret;

	/*
	 * buffer length must be at least one, for our length byte
	 */
	if (blen < 1){
		return JHD_ERROR;
	}
	if ((ret = jhd_tls_ecp_point_write_binary(grp, public_key, format, olen, buf + 1, blen - 1)) != 0){
		return (ret);
	}
	/*
	 * write length to the first byte and update total length
	 */
	buf[0] = (unsigned char) *olen;
	++*olen;
	return JHD_OK;
}

/*
 * Set a group from an ECParameters record (RFC 4492)
 */
int jhd_tls_ecp_tls_read_group(jhd_tls_ecp_group **grp, const unsigned char **buf, size_t len) {
	uint16_t tls_id;
	const jhd_tls_ecp_curve_info *curve_info;

	/*
	 * We expect at least three bytes (see below)
	 */
	if (len < 3){
		return JHD_ERROR;
	}

	/*
	 * First byte is curve_type; only named_curve is handled
	 */
	if (*(*buf)++ != JHD_TLS_ECP_TLS_NAMED_CURVE){
		return JHD_ERROR;
	}

	/*
	 * Next two bytes are the namedcurve value
	 */
	tls_id = *(*buf)++;
	tls_id <<= 8;
	tls_id |= *(*buf)++;

	if ((curve_info = jhd_tls_ecp_curve_info_from_tls_id(tls_id)) == NULL){
		return JHD_UNSUPPORTED;
	}

	*grp =  jhd_tls_ecp_group_get(curve_info->grp_id);

	return NULL == (*grp)?JHD_UNSUPPORTED:JHD_OK;
}

/*
 * Write the ECParameters record corresponding to a group (RFC 4492)
 */
void jhd_tls_ecp_tls_write_group(const jhd_tls_ecp_group *grp,unsigned char *buf) {
	const jhd_tls_ecp_curve_info *curve_info;
	curve_info = jhd_tls_ecp_curve_info_from_grp_id(grp->id);
	log_assert(curve_info!= NULL/*,"invalid param grp"*/);
	/*
	 * First byte is curve_type, always named_curve
	 */
	*buf++ = JHD_TLS_ECP_TLS_NAMED_CURVE;
	/*
	 * Next two bytes are the namedcurve value
	 */
	buf[0] = curve_info->tls_id >> 8;
	buf[1] = curve_info->tls_id & 0xFF;
	log_buf_debug("write ecp_group==>",buf-1,3);
}

/*
 * Wrapper around fast quasi-modp functions, with fall-back to jhd_tls_mpi_mod_mpi.
 * See the documentation of struct jhd_tls_ecp_group.
 *
 * This function is in the critial loop for jhd_tls_ecp_mul, so pay attention to perf.
 */
static int ecp_modp(jhd_tls_mpi *N, const jhd_tls_ecp_group *grp) {
	int ret;
	if (grp->modp == NULL){
		return (jhd_tls_mpi_mod_mpi(N, N, &grp->P));
	}

	/* N->s < 0 is a much faster test, which fails only if N is 0 */
	if ((N->s < 0 && jhd_tls_mpi_cmp_int(N, 0) != 0) || jhd_tls_mpi_bitlen(N) > 2 * grp->pbits) {
		return JHD_ERROR;
	}
	JHD_TLS_MPI_CHK(grp->modp(N));

	/* N->s < 0 is a much faster test, which fails only if N is 0 */
	while (N->s < 0 && jhd_tls_mpi_cmp_int(N, 0) != 0){
		JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(N, N, &grp->P));
	}

	while (jhd_tls_mpi_cmp_mpi(N, &grp->P) >= 0){
		/* we known P, N and the result are positive */
		JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_abs(N, N, &grp->P));
	}
	cleanup: return (ret);
}

/*
 * Fast mod-p functions expect their argument to be in the 0..p^2 range.
 *
 * In order to guarantee that, we need to ensure that operands of
 * jhd_tls_mpi_mul_mpi are in the 0..p range. So, after each operation we will
 * bring the result back to this range.
 *
 * The following macros are shortcuts for doing that.
 */

/*
 * Reduce a jhd_tls_mpi mod p in-place, general case, to use after jhd_tls_mpi_mul_mpi
 */

#define INC_MUL_COUNT

#define MOD_MUL( N )    do { JHD_TLS_MPI_CHK( ecp_modp( &N, grp ) ); INC_MUL_COUNT } \
                        while( 0 )

/*
 * Reduce a jhd_tls_mpi mod p in-place, to use after jhd_tls_mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
#define MOD_SUB( N )                                \
    while( N.s < 0 && jhd_tls_mpi_cmp_int( &N, 0 ) != 0 )   \
        JHD_TLS_MPI_CHK( jhd_tls_mpi_add_mpi( &N, &N, &grp->P ) )

/*
 * Reduce a jhd_tls_mpi mod p in-place, to use after jhd_tls_mpi_add_mpi and jhd_tls_mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
#define MOD_ADD( N )                                \
    while( jhd_tls_mpi_cmp_mpi( &N, &grp->P ) >= 0 )        \
        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_abs( &N, &N, &grp->P ) )

/*
 * For curves in short Weierstrass form, we do all the internal operations in
 * Jacobian coordinates.
 *
 * For multiplication, we'll use a comb method with coutermeasueres against
 * SPA, hence timing attacks.
 */

/*
 * Normalize jacobian coordinates so that Z == 0 || Z == 1  (GECC 3.2.1)
 * Cost: 1N := 1I + 3M + 1S
 */
static int ecp_normalize_jac(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *pt) {
	int ret;
	jhd_tls_mpi Zi, ZZi;

	if (jhd_tls_mpi_cmp_int(&pt->Z, 0) == 0){
		return JHD_OK;
	}

#if defined(JHD_TLS_ECP_NORMALIZE_JAC_ALT)
	if ( jhd_tls_internal_ecp_grp_capable( grp ) )
	{
		return jhd_tls_internal_ecp_normalize_jac( grp, pt );
	}
#endif /* JHD_TLS_ECP_NORMALIZE_JAC_ALT */
	jhd_tls_mpi_init(&Zi);
	jhd_tls_mpi_init(&ZZi);

	/*
	 * X = X / Z^2  mod p
	 */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_inv_mod(&Zi, &pt->Z, &grp->P));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&ZZi, &Zi, &Zi));
	MOD_MUL(ZZi);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&pt->X, &pt->X, &ZZi));
	MOD_MUL(pt->X);

	/*
	 * Y = Y / Z^3  mod p
	 */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&pt->Y, &pt->Y, &ZZi));
	MOD_MUL(pt->Y);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&pt->Y, &pt->Y, &Zi));
	MOD_MUL(pt->Y);

	/*
	 * Z = 1
	 */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&pt->Z, 1));

	cleanup:

	jhd_tls_mpi_free(&Zi);
	jhd_tls_mpi_free(&ZZi);

	return (ret);
}

/*
 * Normalize jacobian coordinates of an array of (pointers to) points,
 * using Montgomery's trick to perform only one inversion mod P.
 * (See for example Cohen's "A Course in Computational Algebraic Number
 * Theory", Algorithm 10.3.4.)
 *
 * Warning: fails (returning an error) if one of the points is zero!
 * This should never happen, see choice of w in ecp_mul_comb().
 *
 * Cost: 1N(t) := 1I + (6t - 3)M + 1S
 */
static int ecp_normalize_jac_many(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *T[], size_t t_len) {
	int ret;
	size_t i;
	jhd_tls_mpi c[ (1<< 5) - 1];
	jhd_tls_mpi  u, Zi, ZZi;

	log_assert(t_len <= ((1<<5) -1)/*,"c too small"*/);

	if (t_len < 2){
		return (ecp_normalize_jac(grp, *T));
	}

#if defined(JHD_TLS_ECP_NORMALIZE_JAC_MANY_ALT)
	if ( jhd_tls_internal_ecp_grp_capable( grp ) )
	{
		return jhd_tls_internal_ecp_normalize_jac_many(grp, T, t_len);
	}
#endif



	jhd_tls_platform_zeroize(c, t_len * sizeof(jhd_tls_mpi));

	jhd_tls_mpi_init(&u);
	jhd_tls_mpi_init(&Zi);
	jhd_tls_mpi_init(&ZZi);

	/*
	 * c[i] = Z_0 * ... * Z_i
	 */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&c[0], &T[0]->Z));
	for (i = 1; i < t_len; i++) {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&c[i], &c[i - 1], &T[i]->Z));
		MOD_MUL(c[i]);
	}

	/*
	 * u = 1 / (Z_0 * ... * Z_n) mod P
	 */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_inv_mod(&u, &c[t_len - 1], &grp->P));

	for (i = t_len - 1;; i--) {
		/*
		 * Zi = 1 / Z_i mod p
		 * u = 1 / (Z_0 * ... * Z_i) mod P
		 */
		if (i == 0) {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&Zi, &u));
		} else {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&Zi, &u, &c[i - 1]));
			MOD_MUL(Zi);
			JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&u, &u, &T[i]->Z));MOD_MUL(u);
		}

		/*
		 * proceed as in normalize()
		 */
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&ZZi, &Zi, &Zi));
		MOD_MUL(ZZi);
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T[i]->X, &T[i]->X, &ZZi));
		MOD_MUL(T[i]->X);
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T[i]->Y, &T[i]->Y, &ZZi));
		MOD_MUL(T[i]->Y);
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T[i]->Y, &T[i]->Y, &Zi));
		MOD_MUL(T[i]->Y);

		/*
		 * Post-precessing: reclaim some memory by shrinking coordinates
		 * - not storing Z (always 1)
		 * - shrinking other coordinates, but still keeping the same number of
		 *   limbs as P, as otherwise it will too likely be regrown too fast.
		 */
		JHD_TLS_MPI_CHK(jhd_tls_mpi_shrink(&T[i]->X, grp->P.n));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_shrink(&T[i]->Y, grp->P.n));
		jhd_tls_mpi_free(&T[i]->Z);

		if (i == 0)
			break;
	}

	cleanup:

	jhd_tls_mpi_free(&u);
	jhd_tls_mpi_free(&Zi);
	jhd_tls_mpi_free(&ZZi);
	for (i = 0; i < t_len; i++){
		jhd_tls_mpi_free(&c[i]);
	}
	return (ret);
}

/*
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid
 */
static int ecp_safe_invert_jac(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *Q, unsigned char inv) {
	int ret;
	unsigned char nonzero;
	jhd_tls_mpi mQY;

	jhd_tls_mpi_init(&mQY);

	/* Use the fact that -Q.Y mod P = P - Q.Y unless Q.Y == 0 */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&mQY, &grp->P, &Q->Y));
	nonzero = jhd_tls_mpi_cmp_int(&Q->Y, 0) != 0;
	JHD_TLS_MPI_CHK(jhd_tls_mpi_safe_cond_assign(&Q->Y, &mQY, inv & nonzero));

	cleanup: jhd_tls_mpi_free(&mQY);

	return (ret);
}

/*
 * Point doubling R = 2 P, Jacobian coordinates
 *
 * Based on http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2 .
 *
 * We follow the variable naming fairly closely. The formula variations that trade a MUL for a SQR
 * (plus a few ADDs) aren't useful as our bignum implementation doesn't distinguish squaring.
 *
 * Standard optimizations are applied when curve parameter A is one of { 0, -3 }.
 *
 * Cost: 1D := 3M + 4S          (A ==  0)
 *             4M + 4S          (A == -3)
 *             3M + 6S + 1a     otherwise
 */
static int ecp_double_jac(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *R, const jhd_tls_ecp_point *P) {
	int ret;
	jhd_tls_mpi M, S, T, U;


#if defined(JHD_TLS_ECP_DOUBLE_JAC_ALT)
	if ( jhd_tls_internal_ecp_grp_capable( grp ) )
	{
		return jhd_tls_internal_ecp_double_jac( grp, R, P );
	}
#endif /* JHD_TLS_ECP_DOUBLE_JAC_ALT */

	jhd_tls_mpi_init(&M);
	jhd_tls_mpi_init(&S);
	jhd_tls_mpi_init(&T);
	jhd_tls_mpi_init(&U);

	/* Special case for A = -3 */
	if (grp->A.p == NULL) {
		/* M = 3(X + Z^2)(X - Z^2) */
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&S, &P->Z, &P->Z));
		MOD_MUL(S);
		JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(&T, &P->X, &S));
		MOD_ADD(T);
		JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&U, &P->X, &S));
		MOD_SUB(U);
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&S, &T, &U));
		MOD_MUL(S);
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_int(&M, &S, 3));MOD_ADD(M);
	} else {
		/* M = 3.X^2 */
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&S, &P->X, &P->X));
		MOD_MUL(S);
		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_int(&M, &S, 3));
		MOD_ADD(M);

		/* Optimize away for "koblitz" curves with A = 0 */
		if (jhd_tls_mpi_cmp_int(&grp->A, 0) != 0) {
			/* M += A.Z^4 */
			JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&S, &P->Z, &P->Z));
			MOD_MUL(S);
			JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T, &S, &S));
			MOD_MUL(T);
			JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&S, &T, &grp->A));
			MOD_MUL(S);
			JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(&M, &M, &S));MOD_ADD(M);
		}
	}

	/* S = 4.X.Y^2 */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T, &P->Y, &P->Y));
	MOD_MUL(T);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_l(&T, 1));
	MOD_ADD(T);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&S, &P->X, &T));
	MOD_MUL(S);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_l(&S, 1));
	MOD_ADD(S);

	/* U = 8.Y^4 */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&U, &T, &T));
	MOD_MUL(U);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_l(&U, 1));
	MOD_ADD(U);

	/* T = M^2 - 2.S */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T, &M, &M));
	MOD_MUL(T);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&T, &T, &S));
	MOD_SUB(T);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&T, &T, &S));
	MOD_SUB(T);

	/* S = M(S - T) - U */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&S, &S, &T));
	MOD_SUB(S);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&S, &S, &M));
	MOD_MUL(S);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&S, &S, &U));
	MOD_SUB(S);

	/* U = 2.Y.Z */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&U, &P->Y, &P->Z));
	MOD_MUL(U);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_l(&U, 1));
	MOD_ADD(U);

	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&R->X, &T));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&R->Y, &S));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&R->Z, &U));

	cleanup: jhd_tls_mpi_free(&M);
	jhd_tls_mpi_free(&S);
	jhd_tls_mpi_free(&T);
	jhd_tls_mpi_free(&U);

	return (ret);
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * Special cases: (1) P or Q is zero, (2) R is zero, (3) P == Q.
 * None of these cases can happen as intermediate step in ecp_mul_comb():
 * - at each step, P, Q and R are multiples of the base point, the factor
 *   being less than its order, so none of them is zero;
 * - Q is an odd multiple of the base point, P an even multiple,
 *   due to the choice of precomputed points in the modified comb method.
 * So branches for these cases do not leak secret information.
 *
 * We accept Q->Z being unset (saving memory in tables) as meaning 1.
 *
 * Cost: 1A := 8M + 3S
 */
static int ecp_add_mixed(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *R, const jhd_tls_ecp_point *P, const jhd_tls_ecp_point *Q) {
	int ret;
	jhd_tls_mpi T1, T2, T3, T4, X, Y, Z;

#if defined(JHD_TLS_ECP_ADD_MIXED_ALT)
	if ( jhd_tls_internal_ecp_grp_capable( grp ) )
	{
		return jhd_tls_internal_ecp_add_mixed( grp, R, P, Q );
	}
#endif /* JHD_TLS_ECP_ADD_MIXED_ALT */

	/*
	 * Trivial cases: P == 0 or Q == 0 (case 1)
	 */
	if (jhd_tls_mpi_cmp_int(&P->Z, 0) == 0){
		return (jhd_tls_ecp_copy(R, Q));
	}

	if (Q->Z.p != NULL && jhd_tls_mpi_cmp_int(&Q->Z, 0) == 0){
		return (jhd_tls_ecp_copy(R, P));
	}

	/*
	 * Make sure Q coordinates are normalized
	 */
	if (Q->Z.p != NULL && jhd_tls_mpi_cmp_int(&Q->Z, 1) != 0){
		return JHD_ERROR;
	}

	jhd_tls_mpi_init(&T1);
	jhd_tls_mpi_init(&T2);
	jhd_tls_mpi_init(&T3);
	jhd_tls_mpi_init(&T4);
	jhd_tls_mpi_init(&X);
	jhd_tls_mpi_init(&Y);
	jhd_tls_mpi_init(&Z);

	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T1, &P->Z, &P->Z));
	MOD_MUL(T1);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T2, &T1, &P->Z));
	MOD_MUL(T2);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T1, &T1, &Q->X));
	MOD_MUL(T1);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T2, &T2, &Q->Y));
	MOD_MUL(T2);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&T1, &T1, &P->X));
	MOD_SUB(T1);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&T2, &T2, &P->Y));
	MOD_SUB(T2);

	/* Special cases (2) and (3) */
	if (jhd_tls_mpi_cmp_int(&T1, 0) == 0) {
		if (jhd_tls_mpi_cmp_int(&T2, 0) == 0) {
			ret = ecp_double_jac(grp, R, P);
			goto cleanup;
		} else {
			ret = jhd_tls_ecp_set_zero(R);
			goto cleanup;
		}
	}

	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&Z, &P->Z, &T1));
	MOD_MUL(Z);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T3, &T1, &T1));
	MOD_MUL(T3);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T4, &T3, &T1));
	MOD_MUL(T4);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T3, &T3, &P->X));
	MOD_MUL(T3);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_int(&T1, &T3, 2));
	MOD_ADD(T1);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&X, &T2, &T2));
	MOD_MUL(X);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&X, &X, &T1));
	MOD_SUB(X);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&X, &X, &T4));
	MOD_SUB(X);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&T3, &T3, &X));
	MOD_SUB(T3);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T3, &T3, &T2));
	MOD_MUL(T3);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T4, &T4, &P->Y));
	MOD_MUL(T4);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&Y, &T3, &T4));
	MOD_SUB(Y);

	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&R->X, &X));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&R->Y, &Y));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&R->Z, &Z));

	cleanup:

	jhd_tls_mpi_free(&T1);
	jhd_tls_mpi_free(&T2);
	jhd_tls_mpi_free(&T3);
	jhd_tls_mpi_free(&T4);
	jhd_tls_mpi_free(&X);
	jhd_tls_mpi_free(&Y);
	jhd_tls_mpi_free(&Z);

	return (ret);
}

/*
 * Randomize jacobian coordinates:
 * (X, Y, Z) -> (l^2 X, l^3 Y, l Z) for random l
 * This is sort of the reverse operation of ecp_normalize_jac().
 *
 * This countermeasure was first suggested in [2].
 */
static int ecp_randomize_jac(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *pt) {
	int ret;
	jhd_tls_mpi l, ll;
	size_t p_size;
	int count = 0;

	p_size = (grp->pbits + 7) / 8;
	jhd_tls_mpi_init(&l);
	jhd_tls_mpi_init(&ll);

	/* Generate l such that 1 < l < p */
	do {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_fill_random(&l, p_size));

		while (jhd_tls_mpi_cmp_mpi(&l, &grp->P) >= 0){
			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&l, 1));
		}

		if (count++ > 10){
			log_err("ecp_randomize_jac error;count=%d",count);
			return JHD_ERROR;
		}
	} while (jhd_tls_mpi_cmp_int(&l, 1) <= 0);

	/* Z = l * Z */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&pt->Z, &pt->Z, &l));
	MOD_MUL(pt->Z);

	/* X = l^2 * X */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&ll, &l, &l));
	MOD_MUL(ll);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&pt->X, &pt->X, &ll));
	MOD_MUL(pt->X);

	/* Y = l^3 * Y */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&ll, &ll, &l));
	MOD_MUL(ll);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&pt->Y, &pt->Y, &ll));
	MOD_MUL(pt->Y);

	cleanup: jhd_tls_mpi_free(&l);
	jhd_tls_mpi_free(&ll);

	return (ret);
}
static int ecp_randomize_jac_specific(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *pt, void (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
	int ret;
	jhd_tls_mpi l, ll;
	size_t p_size;
	int count = 0;

	p_size = (grp->pbits + 7) / 8;
	jhd_tls_mpi_init(&l);
	jhd_tls_mpi_init(&ll);

	/* Generate l such that 1 < l < p */
	do {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_fill_random_specific(&l, p_size, f_rng, p_rng));

		while (jhd_tls_mpi_cmp_mpi(&l, &grp->P) >= 0){
			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&l, 1));
		}
		if (count++ > 10){
			log_err("ecp_randomize_jac_specific error;count =%d",count);
			return ( JHD_ERROR);
		}
	} while (jhd_tls_mpi_cmp_int(&l, 1) <= 0);

	/* Z = l * Z */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&pt->Z, &pt->Z, &l));
	MOD_MUL(pt->Z);

	/* X = l^2 * X */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&ll, &l, &l));
	MOD_MUL(ll);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&pt->X, &pt->X, &ll));
	MOD_MUL(pt->X);

	/* Y = l^3 * Y */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&ll, &ll, &l));
	MOD_MUL(ll);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&pt->Y, &pt->Y, &ll));
	MOD_MUL(pt->Y);

	cleanup: jhd_tls_mpi_free(&l);
	jhd_tls_mpi_free(&ll);

	return (ret);
}

/*
 * Check and define parameters used by the comb method (see below for details)
 */
#if JHD_TLS_ECP_WINDOW_SIZE < 2 || JHD_TLS_ECP_WINDOW_SIZE > 7
#error "JHD_TLS_ECP_WINDOW_SIZE out of bounds"
#endif

/* d = ceil( n / w ) */
#define COMB_MAX_D      ( JHD_TLS_ECP_MAX_BITS + 1 ) / 2

/* number of precomputed points */
#define COMB_MAX_PRE    ( 1 << ( JHD_TLS_ECP_WINDOW_SIZE - 1 ) )

/*
 * Compute the representation of m that will be used with our comb method.
 *
 * The basic comb method is described in GECC 3.44 for example. We use a
 * modified version that provides resistance to SPA by avoiding zero
 * digits in the representation as in [3]. We modify the method further by
 * requiring that all K_i be odd, which has the small cost that our
 * representation uses one more K_i, due to carries.
 *
 * Also, for the sake of compactness, only the seven low-order bits of x[i]
 * are used to represent K_i, and the msb of x[i] encodes the the sign (s_i in
 * the paper): it is set if and only if if s_i == -1;
 *
 * Calling conventions:
 * - x is an array of size d + 1
 * - w is the size, ie number of teeth, of the comb, and must be between
 *   2 and 7 (in practice, between 2 and JHD_TLS_ECP_WINDOW_SIZE)
 * - m is the MPI, expected to be odd and such that bitlength(m) <= w * d
 *   (the result will be incorrect if these assumptions are not satisfied)
 */
static void ecp_comb_fixed(unsigned char x[], size_t d, unsigned char w, const jhd_tls_mpi *m) {
	size_t i, j;
	unsigned char c, cc, adjust;

	memset(x, 0, d + 1);

	/* First get the classical comb values (except for x_d = 0) */
	for (i = 0; i < d; i++){
		for (j = 0; j < w; j++){
			x[i] |= jhd_tls_mpi_get_bit(m, i + d * j) << j;
		}
	}

	/* Now make sure x_1 .. x_d are odd */
	c = 0;
	for (i = 1; i <= d; i++) {
		/* Add carry and update it */
		cc = x[i] & c;
		x[i] = x[i] ^ c;
		c = cc;

		/* Adjust if needed, avoiding branches */
		adjust = 1 - (x[i] & 0x01);
		c |= x[i] & (x[i - 1] * adjust);
		x[i] = x[i] ^ (x[i - 1] * adjust);
		x[i - 1] |= adjust << 7;
	}
}

/*
 * Precompute points for the comb method
 *
 * If i = i_{w-1} ... i_1 is the binary representation of i, then
 * T[i] = i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + P
 *
 * T must be able to hold 2^{w - 1} elements
 *
 * Cost: d(w-1) D + (2^{w-1} - 1) A + 1 N(w-1) + 1 N(2^{w-1} - 1)
 */
static int ecp_precompute_comb(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point T[], const jhd_tls_ecp_point *P, unsigned char w, size_t d) {
	int ret;
	unsigned char i, k;
	size_t j;
	jhd_tls_ecp_point *cur, *TT[COMB_MAX_PRE - 1];

	/*
	 * Set T[0] = P and
	 * T[2^{l-1}] = 2^{dl} P for l = 1 .. w-1 (this is not the final value)
	 */
	JHD_TLS_MPI_CHK(jhd_tls_ecp_copy(&T[0], P));

	k = 0;
	for (i = 1; i < (1U << (w - 1)); i <<= 1) {
		cur = T + i;
		JHD_TLS_MPI_CHK(jhd_tls_ecp_copy(cur, T + (i >> 1)));
		for (j = 0; j < d; j++){
			JHD_TLS_MPI_CHK(ecp_double_jac(grp, cur, cur));
		}
		TT[k++] = cur;
	}

	JHD_TLS_MPI_CHK(ecp_normalize_jac_many(grp, TT, k));

	/*
	 * Compute the remaining ones using the minimal number of additions
	 * Be careful to update T[2^l] only after using it!
	 */
	k = 0;
	for (i = 1; i < (1U << (w - 1)); i <<= 1) {
		j = i;
		while (j--) {
			JHD_TLS_MPI_CHK(ecp_add_mixed(grp, &T[i + j], &T[j], &T[i]));
			TT[k++] = &T[i + j];
		}
	}

	JHD_TLS_MPI_CHK(ecp_normalize_jac_many(grp, TT, k));

	cleanup:

	return (ret);
}

/*
 * Select precomputed point: R = sign(i) * T[ abs(i) / 2 ]
 */
static int ecp_select_comb(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *R, const jhd_tls_ecp_point T[], unsigned char t_len, unsigned char i) {
	int ret;
	unsigned char ii, j;

	/* Ignore the "sign" bit and scale down */
	ii = (i & 0x7Fu) >> 1;

	/* Read the whole table to thwart cache-based timing attacks */
	for (j = 0; j < t_len; j++) {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_safe_cond_assign(&R->X, &T[j].X, j == ii));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_safe_cond_assign(&R->Y, &T[j].Y, j == ii));
	}

	/* Safely invert result if i is "negative" */
	JHD_TLS_MPI_CHK(ecp_safe_invert_jac(grp, R, i >> 7));

	cleanup: return (ret);
}

/*
 * Core multiplication algorithm for the (modified) comb method.
 * This part is actually common with the basic comb method (GECC 3.44)
 *
 * Cost: d A + d D + 1 R
 */
static int ecp_mul_comb_core(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *public_key, const jhd_tls_ecp_point T[], unsigned char t_len, const unsigned char x[],
        size_t d) {
	int ret;
	jhd_tls_ecp_point Txi;
	size_t i;

	jhd_tls_ecp_point_init(&Txi);

	/* Start with a non-zero point and randomize its coordinates */
	i = d;
	JHD_TLS_MPI_CHK(ecp_select_comb(grp, public_key, T, t_len, x[i]));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&public_key->Z, 1));

	JHD_TLS_MPI_CHK(ecp_randomize_jac(grp, public_key));

	while (i-- != 0) {
		JHD_TLS_MPI_CHK(ecp_double_jac(grp, public_key, public_key));
		JHD_TLS_MPI_CHK(ecp_select_comb(grp, &Txi, T, t_len, x[i]));
		JHD_TLS_MPI_CHK(ecp_add_mixed(grp, public_key, public_key, &Txi));
	}

	cleanup:

	jhd_tls_ecp_point_free(&Txi);

	return (ret);
}
static int ecp_mul_comb_core_specific(const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *R, const jhd_tls_ecp_point T[], unsigned char t_len,
        const unsigned char x[], size_t d, void (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
	int ret;
	jhd_tls_ecp_point Txi;
	size_t i;

	jhd_tls_ecp_point_init(&Txi);

	/* Start with a non-zero point and randomize its coordinates */
	i = d;
	JHD_TLS_MPI_CHK(ecp_select_comb(grp, R, T, t_len, x[i]));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&R->Z, 1));
	if (f_rng != NULL){
		JHD_TLS_MPI_CHK(ecp_randomize_jac_specific(grp, R, f_rng, p_rng));
	}
	while (i-- != 0) {
		JHD_TLS_MPI_CHK(ecp_double_jac(grp, R, R));
		JHD_TLS_MPI_CHK(ecp_select_comb(grp, &Txi, T, t_len, x[i]));
		JHD_TLS_MPI_CHK(ecp_add_mixed(grp, R, R, &Txi));
	}

	cleanup:

	jhd_tls_ecp_point_free(&Txi);

	return (ret);
}

/*
 * Multiplication using the comb method,
 * for curves in short Weierstrass form
 */
static int ecp_mul_comb_specific(jhd_tls_ecp_group *grp, jhd_tls_ecp_point *R, const jhd_tls_mpi *m, const jhd_tls_ecp_point *P,
        void (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
	int ret;
	unsigned char w, m_is_odd, /*p_eq_g,*/ pre_len, i;
	size_t d;
	unsigned char k[COMB_MAX_D + 1];
	jhd_tls_ecp_point T[1<<5];
	jhd_tls_mpi M, mm;

	jhd_tls_mpi_init(&M);
	jhd_tls_mpi_init(&mm);

	/* we need N to be odd to trnaform m in an odd number, check now */
	if (jhd_tls_mpi_get_bit(&grp->N, 0) != 1){
		return JHD_ERROR;
	}

	/*
	 * Minimize the number of multiplications, that is minimize
	 * 10 * d * w + 18 * 2^(w-1) + 11 * d + 7 * w, with d = ceil( nbits / w )
	 * (see costs of the various parts, with 1S = 1M)
	 */
	w = grp->nbits >= 384 ? 5 : 4;

	/*
	 * If P == G, pre-compute a bit more, since this may be re-used later.
	 * Just adding one avoids upping the cost of the first mul too much,
	 * and the memory cost too.
	 */
//#if JHD_TLS_ECP_FIXED_POINT_OPTIM == 1
//	p_eq_g = (jhd_tls_mpi_cmp_mpi(&P->Y, &grp->G.Y) == 0 && jhd_tls_mpi_cmp_mpi(&P->X, &grp->G.X) == 0);
//	if (p_eq_g)
//		w++;
//#else
//	p_eq_g = 0;
//#endif

	/*
	 * Make sure w is within bounds.
	 * (The last test is useful only for very small curves in the test suite.)
	 */
	if (w > JHD_TLS_ECP_WINDOW_SIZE)
		w = JHD_TLS_ECP_WINDOW_SIZE;
	if (w >= grp->nbits)
		w = 2;

	/* Other sizes that depend on w */
	pre_len = 1U << (w - 1);
	d = (grp->nbits + w - 1) / w;

	/*
	 * Prepare precomputed points: if P == G we want to
	 * use grp->T if already initialized, or initialize it.
	 */
//	T = p_eq_g ? grp->T : NULL;
//
//	if (T == NULL) {
		log_assert(pre_len <= (1<<5)/*,"T too small"*/);
		jhd_tls_platform_zeroize(T, pre_len * sizeof(jhd_tls_ecp_point));

		JHD_TLS_MPI_CHK(ecp_precompute_comb(grp, T, P, w, d));
//
//		if (p_eq_g) {
//			grp->T = T;
//			grp->T_size = pre_len;
//		}
//	}

	/*
	 * Make sure M is odd (M = m or M = N - m, since N is odd)
	 * using the fact that m * P = - (N - m) * P
	 */
	m_is_odd = (jhd_tls_mpi_get_bit(m, 0) == 1);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&M, m));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&mm, &grp->N, m));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_safe_cond_assign(&M, &mm, !m_is_odd));

	/*
	 * Go for comb multiplication, R = M * P
	 */
	ecp_comb_fixed(k, d, w, &M);
	JHD_TLS_MPI_CHK(ecp_mul_comb_core_specific(grp, R, T, pre_len, k, d, f_rng, p_rng));

	/*
	 * Now get m * P from M * P and normalize it
	 */
	JHD_TLS_MPI_CHK(ecp_safe_invert_jac(grp, R, !m_is_odd));
	JHD_TLS_MPI_CHK(ecp_normalize_jac(grp, R));

	cleanup:

//	if (T != NULL && !p_eq_g) {
		for (i = 0; i < pre_len; i++){
			jhd_tls_ecp_point_free(&T[i]);
		}
//	}

	jhd_tls_mpi_free(&M);
	jhd_tls_mpi_free(&mm);

	if (ret != 0){
		jhd_tls_ecp_point_free(R);
	}
	return (ret);
}
static int ecp_mul_comb(jhd_tls_ecp_group *grp, jhd_tls_ecp_point *public_key, const jhd_tls_mpi *private_key, const jhd_tls_ecp_point *P/*&grp->G,*/) {
	int ret;
	unsigned char w, m_is_odd, /*p_eq_g,*/ pre_len, i;
	size_t d;
	unsigned char k[COMB_MAX_D + 1];
	jhd_tls_ecp_point T[1<<5];
	jhd_tls_mpi M, mm;

	jhd_tls_mpi_init(&M);
	jhd_tls_mpi_init(&mm);

	/* we need N to be odd to trnaform m in an odd number, check now */
	if (jhd_tls_mpi_get_bit(&grp->N, 0) != 1){
		return JHD_ERROR;
	}

	/*
	 * Minimize the number of multiplications, that is minimize
	 * 10 * d * w + 18 * 2^(w-1) + 11 * d + 7 * w, with d = ceil( nbits / w )
	 * (see costs of the various parts, with 1S = 1M)
	 */
	w = grp->nbits >= 384 ? 5 : 4;

	/*
	 * If P == G, pre-compute a bit more, since this may be re-used later.
	 * Just adding one avoids upping the cost of the first mul too much,
	 * and the memory cost too.
	 */
//#if JHD_TLS_ECP_FIXED_POINT_OPTIM == 1
//	p_eq_g =  (P== &grp->G) || ( (jhd_tls_mpi_cmp_mpi(&P->Y, &grp->G.Y) == 0 && jhd_tls_mpi_cmp_mpi(&P->X, &grp->G.X) == 0));
//	if (p_eq_g){
//		w++;
//	}
//#else
//	p_eq_g = 0;
//#endif

	/*
	 * Make sure w is within bounds.
	 * (The last test is useful only for very small curves in the test suite.)
	 */
	if (w > JHD_TLS_ECP_WINDOW_SIZE){
		w = JHD_TLS_ECP_WINDOW_SIZE;
	}
	if (w >= grp->nbits){
		w = 2;
	}

	/* Other sizes that depend on w */
	pre_len = 1U << (w - 1);
	d = (grp->nbits + w - 1) / w;

	/*
	 * Prepare precomputed points: if P == G we want to
	 * use grp->T if already initialized, or initialize it.
	 */
//	T = p_eq_g ? grp->T : NULL;
//
//	if (T == NULL) {
	log_assert(pre_len<= (1<<5)/*,"bug:T too small"*/);

		jhd_tls_platform_zeroize(T, pre_len * sizeof(jhd_tls_ecp_point));

		JHD_TLS_MPI_CHK(ecp_precompute_comb(grp, T, P, w, d));

//		if (p_eq_g) {
//			grp->T = T;
//			grp->T_size = pre_len;
//		}
//	}

	/*
	 * Make sure M is odd (M = m or M = N - m, since N is odd)
	 * using the fact that m * P = - (N - m) * P
	 */
	m_is_odd = (jhd_tls_mpi_get_bit(private_key, 0) == 1);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&M, private_key));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&mm, &grp->N, private_key));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_safe_cond_assign(&M, &mm, !m_is_odd));

	/*
	 * Go for comb multiplication, R = M * P
	 */
	ecp_comb_fixed(k, d, w, &M);
	JHD_TLS_MPI_CHK(ecp_mul_comb_core(grp, public_key, T, pre_len, k, d));

	/*
	 * Now get m * P from M * P and normalize it
	 */
	JHD_TLS_MPI_CHK(ecp_safe_invert_jac(grp, public_key, !m_is_odd));
	JHD_TLS_MPI_CHK(ecp_normalize_jac(grp, public_key));

	cleanup:

//	if (T != NULL && !p_eq_g) {
		for (i = 0; i < pre_len; i++){
			jhd_tls_ecp_point_free(&T[i]);
		}
//	}

	jhd_tls_mpi_free(&M);
	jhd_tls_mpi_free(&mm);

	if (ret != 0){
		jhd_tls_ecp_point_free(public_key);
	}
	return (ret);
}




/*
 * Multiplication R = m * P
 */
int jhd_tls_ecp_mul_specific(jhd_tls_ecp_group *grp, jhd_tls_ecp_point *public_key, const jhd_tls_mpi *private_key, const jhd_tls_ecp_point *P /*&grp->G,*/,
        void (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
	int ret;


	/* Common sanity checks */
	if (jhd_tls_mpi_cmp_int(&P->Z, 1) != 0){
		return JHD_ERROR;
	}
	if ((ret = jhd_tls_ecp_check_privkey(grp, private_key)) != 0 || (ret = jhd_tls_ecp_check_pubkey(grp, P)) != 0){
		return (ret);
	}
	ret = ecp_mul_comb_specific(grp, public_key, private_key, P, f_rng, p_rng);
	return (ret);
}
/*
 * Multiplication R = m * P
 */
int jhd_tls_ecp_mul(jhd_tls_ecp_group *grp, jhd_tls_ecp_point *public_key, const jhd_tls_mpi *private_key, const jhd_tls_ecp_point *P /*&grp->G,*/) {
	/* Common sanity checks */
	if (jhd_tls_mpi_cmp_int(&P->Z, 1) != 0){
		log_err("invalid paramter:%s","const jhd_tls_ecp_point *P");
		return JHD_ERROR;

	}
	if ((JHD_OK != jhd_tls_ecp_check_privkey(grp, private_key)) || (JHD_OK != jhd_tls_ecp_check_pubkey(grp, P))){
		return JHD_ERROR;
	}
	return ecp_mul_comb(grp, public_key, private_key, P);
}

/*
 * Check that an affine point is valid as a public key,
 * short weierstrass curves (SEC1 3.2.3.1)
 */
static int ecp_check_pubkey_sw(const jhd_tls_ecp_group *grp, const jhd_tls_ecp_point *public_key) {
	int ret;
	jhd_tls_mpi YY, RHS;
	/* pt coordinates must be normalized for our checks */
	if (jhd_tls_mpi_cmp_int(&public_key->X, 0) < 0 || jhd_tls_mpi_cmp_int(&public_key->Y, 0) < 0 || jhd_tls_mpi_cmp_mpi(&public_key->X, &grp->P) >= 0
	        || jhd_tls_mpi_cmp_mpi(&public_key->Y, &grp->P) >= 0){
		log_err("%s","invalid public key");
		return JHD_ERROR;
	}
	jhd_tls_mpi_init(&YY);
	jhd_tls_mpi_init(&RHS);
	/*
	 * YY = Y^2
	 * RHS = X (X^2 + A) + B = X^3 + A X + B
	 */
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&YY, &public_key->Y, &public_key->Y));
	MOD_MUL(YY);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&RHS, &public_key->X, &public_key->X));
	MOD_MUL(RHS);

	/* Special case for A = -3 */
	if (grp->A.p == NULL) {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_int(&RHS, &RHS, 3));MOD_SUB(RHS);
	} else {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(&RHS, &RHS, &grp->A));MOD_ADD(RHS);
	}

	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&RHS, &RHS, &public_key->X));
	MOD_MUL(RHS);
	JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(&RHS, &RHS, &grp->B));
	MOD_ADD(RHS);

	if (jhd_tls_mpi_cmp_mpi(&YY, &RHS) != 0){
		ret = JHD_ERROR;
	}
	cleanup:

	jhd_tls_mpi_free(&YY);
	jhd_tls_mpi_free(&RHS);
	return (ret);
}

/*
 * R = m * P with shortcuts for m == 1 and m == -1
 * NOT constant-time - ONLY for short Weierstrass!
 */
static int jhd_tls_ecp_mul_shortcuts(jhd_tls_ecp_group *grp, jhd_tls_ecp_point *R, const jhd_tls_mpi *m, const jhd_tls_ecp_point *P) {
	int ret;

	if (jhd_tls_mpi_cmp_int(m, 1) == 0) {
		JHD_TLS_MPI_CHK(jhd_tls_ecp_copy(R, P));
	} else if (jhd_tls_mpi_cmp_int(m, -1) == 0) {
		JHD_TLS_MPI_CHK(jhd_tls_ecp_copy(R, P));
		if (jhd_tls_mpi_cmp_int(&R->Y, 0) != 0){
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&R->Y, &grp->P, &R->Y));
		}
	} else {
		JHD_TLS_MPI_CHK(jhd_tls_ecp_mul_specific( grp, R, m, P, NULL, NULL ));
	}

	cleanup: return (ret);
}

/*
 * Linear combination
 * NOT constant-time
 */
int jhd_tls_ecp_muladd(jhd_tls_ecp_group *grp, jhd_tls_ecp_point *R, const jhd_tls_mpi *m, const jhd_tls_ecp_point *P, const jhd_tls_mpi *n,
        const jhd_tls_ecp_point *Q) {
	int ret;
	jhd_tls_ecp_point mP;
	jhd_tls_ecp_point_init(&mP);

	JHD_TLS_MPI_CHK(jhd_tls_ecp_mul_shortcuts(grp, &mP, m, P));
	JHD_TLS_MPI_CHK(jhd_tls_ecp_mul_shortcuts(grp, R, n, Q));

	JHD_TLS_MPI_CHK(ecp_add_mixed(grp, R, &mP, R));
	JHD_TLS_MPI_CHK(ecp_normalize_jac(grp, R));
	cleanup:
	jhd_tls_ecp_point_free(&mP);
	return (ret);
}



/*
 * Check that a point is valid as a public key
 */
int jhd_tls_ecp_check_pubkey(const jhd_tls_ecp_group *grp, const jhd_tls_ecp_point *public_key) {
	if (jhd_tls_mpi_cmp_int(&public_key->Z, 1) != 0){
		log_err("%s","invalid public key");
		return JHD_ERROR;
	}
	return (ecp_check_pubkey_sw(grp, public_key));
}

/*
 * Check that an jhd_tls_mpi is valid as a private key
 */
int jhd_tls_ecp_check_privkey(const jhd_tls_ecp_group *grp, const jhd_tls_mpi *private_key) {
		/* see SEC1 3.2 */
	if (jhd_tls_mpi_cmp_int(private_key, 1) < 0 || jhd_tls_mpi_cmp_mpi(private_key, &grp->N) >= 0){
		log_err("%s","invalid private key");
		return JHD_ERROR;
	}
	return JHD_OK;
}

/*
 * Generate a keypair with configurable base point
 */
int jhd_tls_ecp_gen_keypair_base(jhd_tls_ecp_group *grp, const jhd_tls_ecp_point *G/*&grp->G*/, jhd_tls_mpi *private_key, jhd_tls_ecp_point *public_key) {
	int ret;
	size_t n_size = (grp->nbits + 7) / 8;
	/* SEC1 3.2.1: Generate d such that 1 <= n < N */
	int count = 0;

	/*
	 * Match the procedure given in RFC 6979 (deterministic ECDSA):
	 * - use the same byte ordering;
	 * - keep the leftmost nbits bits of the generated octet string;
	 * - try until result is in the desired range.
	 * This also avoids any biais, which is especially important for ECDSA.
	 */
	do {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_fill_random(private_key, n_size));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(private_key, 8 * n_size - grp->nbits));

		/*
		 * Each try has at worst a probability 1/2 of failing (the msb has
		 * a probability 1/2 of being 0, and then the result will be < N),
		 * so after 30 tries failure probability is a most 2**(-30).
		 *
		 * For most curves, 1 try is enough with overwhelming probability,
		 * since N starts with a lot of 1s in binary, but some curves
		 * such as secp224k1 are actually very close to the worst case.
		 */
		if (++count > 30){
			log_err("jhd_tls_ecp_gen_keypair_base error; count>%d",count);
			return JHD_ERROR;
		}
	} while (jhd_tls_mpi_cmp_int(private_key, 1) < 0 || jhd_tls_mpi_cmp_mpi(private_key, &grp->N) >= 0);


	cleanup: if (ret != 0)
		return (ret);

	return (jhd_tls_ecp_mul(grp, public_key, private_key, G));
}

#if !defined(JHD_TLS_INLINE)
/*
 * Generate key pair, wrapper for conventional base point
 */
int jhd_tls_ecp_gen_keypair(jhd_tls_ecp_group *grp, jhd_tls_mpi *private_key, jhd_tls_ecp_point *public_key) {
	return (jhd_tls_ecp_gen_keypair_base(grp, &grp->G, private_key, public_key));
}
#endif
int jhd_tls_ecp_gen_keypair_specific(jhd_tls_ecp_group *grp, jhd_tls_mpi *d, jhd_tls_ecp_point *Q, void (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
	int ret;
	size_t n_size = (grp->nbits + 7) / 8;
	jhd_tls_ecp_point *G = &grp->G;
	/* SEC1 3.2.1: Generate d such that 1 <= n < N */
	int count = 0;

	/*
	 * Match the procedure given in RFC 6979 (deterministic ECDSA):
	 * - use the same byte ordering;
	 * - keep the leftmost nbits bits of the generated octet string;
	 * - try until result is in the desired range.
	 * This also avoids any biais, which is especially important for ECDSA.
	 */
	do {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_fill_random_specific(d, n_size, f_rng, p_rng));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(d, 8 * n_size - grp->nbits));

		/*
		 * Each try has at worst a probability 1/2 of failing (the msb has
		 * a probability 1/2 of being 0, and then the result will be < N),
		 * so after 30 tries failure probability is a most 2**(-30).
		 *
		 * For most curves, 1 try is enough with overwhelming probability,
		 * since N starts with a lot of 1s in binary, but some curves
		 * such as secp224k1 are actually very close to the worst case.
		 */
		if (++count > 300){
			log_err("jhd_tls_ecp_gen_keypair_specific error with count>%d",count);
			return JHD_ERROR;
		}
	} while (jhd_tls_mpi_cmp_int(d, 1) < 0 || jhd_tls_mpi_cmp_mpi(d, &grp->N) >= 0);
	cleanup:
	if (ret != 0)
		return (ret);
	return (jhd_tls_ecp_mul_specific(grp, Q, d, G, f_rng, p_rng));
}

/*
 * Generate a keypair, prettier wrapper
 */
int jhd_tls_ecp_gen_key(jhd_tls_ecp_group_id grp_id, jhd_tls_ecp_keypair *key) {
  if(NULL ==  (key->grp = jhd_tls_ecp_group_get(grp_id))){
	  return JHD_ERROR;
  }
  return (jhd_tls_ecp_gen_keypair(key->grp, &key->private_key, &key->public_key));
}

/*
 * Check a public-private key pair
 */
int jhd_tls_ecp_check_pub_priv(const jhd_tls_ecp_keypair *pub, const jhd_tls_ecp_keypair *prv) {
	int ret;
	jhd_tls_ecp_point Q;
	if (pub->grp->id == JHD_TLS_ECP_DP_NONE || pub->grp->id != prv->grp->id || jhd_tls_mpi_cmp_mpi(&pub->public_key.X, &prv->public_key.X)
	        || jhd_tls_mpi_cmp_mpi(&pub->public_key.Y, &prv->public_key.Y) || jhd_tls_mpi_cmp_mpi(&pub->public_key.Z, &prv->public_key.Z)) {
		return JHD_ERROR;
	}

	jhd_tls_ecp_point_init(&Q);

	/* Also checks d is valid */
	JHD_TLS_MPI_CHK(jhd_tls_ecp_mul_specific( prv->grp, &Q, &prv->private_key, &prv->grp->G, NULL, NULL ));

	if (jhd_tls_mpi_cmp_mpi(&Q.X, &prv->public_key.X) || jhd_tls_mpi_cmp_mpi(&Q.Y, &prv->public_key.Y) || jhd_tls_mpi_cmp_mpi(&Q.Z, &prv->public_key.Z)) {
		ret =JHD_ERROR;
		goto cleanup;
	}

	cleanup: jhd_tls_ecp_point_free(&Q);
	return (ret);
}



