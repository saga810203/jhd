#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_bignum.h>
#include <tls/jhd_tls_bn_mul.h>
#include <tls/jhd_tls_ctr_drbg.h>

#include <string.h>
#include <tls/jhd_tls_platform.h>

#define ciL    (sizeof(jhd_tls_mpi_uint))         /* chars in limb  */
#define biL    (ciL << 3)               /* bits  in limb  */
#define biH    (ciL << 2)               /* half limb size */

#define MPI_SIZE_T_MAX  ( (size_t) -1 ) /* SIZE_T_MAX is not standard */

/*
 * Convert between bits/chars and number of limbs
 * Divide first in order to avoid potential overflows
 */
#define BITS_TO_LIMBS(i)  ( (i) / biL + ( (i) % biL != 0 ) )
#define CHARS_TO_LIMBS(i) ( (i) / ciL + ( (i) % ciL != 0 ) )





#ifdef JHD_LOG_LEVEL_INFO
int jhd_tls_mpi_equals(const jhd_tls_mpi *X, const jhd_tls_mpi *Y) {
	int i;
	if (X != Y) {
		if (X->s != Y->s) {
			return JHD_ERROR;
		}
		if(X->n == Y->n){
			for(i = 0 ; i < X->n ; ++i){
				if(X->p[i] != Y->p[i]){
					return JHD_ERROR;
				}
			}
		}else if(X->n > Y->n){
			for(i = 0;i < Y->n;++i){
				if(X->p[i] != Y->p[i]){
					return JHD_ERROR;
				}
			}
			for(i = Y->n ; i < X->n;++i){
				if(X->p[i]!=0){
					return JHD_ERROR;
				}
			}
		}else{
			for(i = 0;i < X->n;++i){
				if(X->p[i] != Y->p[i]){
					return JHD_ERROR;
				}
			}
			for(i = X->n ; i < Y->n;++i){
				if(Y->p[i]!=0){
					return JHD_ERROR;
				}
			}
		}
	}
	return JHD_OK;
}
#endif

#if !defined(JHD_TLS_INLINE)
/*
 * Initialize one MPI
 */
void jhd_tls_mpi_init(jhd_tls_mpi *X) {
	X->s = 1;
	X->n = 0;
	X->tn = 0;
	X->p = NULL;
}
#endif





/*
 * Copy the contents of Y into X
 */
int jhd_tls_mpi_copy(jhd_tls_mpi *X, const jhd_tls_mpi *Y) {
	int ret = JHD_OK;
	size_t i;
	if (X == Y){return JHD_OK;}
	if (Y->n == 0) {
		jhd_tls_mpi_free(X);
		return JHD_OK;
	}
	for (i = Y->n - 1; i > 0; i--){
		if (Y->p[i] != 0){
			break;
		}
	}
	i++;
	X->s = Y->s;
	if (X->n < i) {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(X, i));
	} else {
		memset(X->p + i, 0, (X->n - i) * ciL);
	}
	memcpy(X->p, Y->p, i * ciL);
	cleanup:
	return (ret);
}

/*
 * Swap the contents of X and Y
 */
void jhd_tls_mpi_swap(jhd_tls_mpi *X, jhd_tls_mpi *Y) {
	jhd_tls_mpi T;
	memcpy(&T, X, sizeof(jhd_tls_mpi));
	memcpy(X, Y, sizeof(jhd_tls_mpi));
	memcpy(Y, &T, sizeof(jhd_tls_mpi));
}

/*
 * Conditionally assign X = Y, without leaking information
 * about whether the assignment was made or not.
 * (Leaking information about the respective sizes of X and Y is ok however.)
 */
int jhd_tls_mpi_safe_cond_assign(jhd_tls_mpi *X, const jhd_tls_mpi *Y, unsigned char assign) {
	int ret = 0;
	size_t i;
	/* make sure assign is 0 or 1 in a time-constant manner */
	assign = (assign | (unsigned char) -assign) >> 7;

	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(X, Y->n));

	X->s = X->s * (1 - assign) + Y->s * assign;

	for (i = 0; i < Y->n; i++){
		X->p[i] = X->p[i] * (1 - assign) + Y->p[i] * assign;
	}
	for (; i < X->n; i++){
		X->p[i] *= (1 - assign);
	}
	cleanup: return (ret);
}

/*
 * Conditionally swap X and Y, without leaking information
 * about whether the swap was made or not.
 * Here it is not ok to simply swap the pointers, which whould lead to
 * different memory access patterns when X and Y are used afterwards.
 */
int jhd_tls_mpi_safe_cond_swap(jhd_tls_mpi *X, jhd_tls_mpi *Y, unsigned char swap) {
	int ret, s;
	size_t i;
	jhd_tls_mpi_uint tmp;
	if (X == Y)
		return JHD_OK;

	/* make sure swap is 0 or 1 in a time-constant manner */
	swap = (swap | (unsigned char) -swap) >> 7;

	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(X, Y->n));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(Y, X->n));

	s = X->s;
	X->s = X->s * (1 - swap) + Y->s * swap;
	Y->s = Y->s * (1 - swap) + s * swap;
	for (i = 0; i < X->n; i++) {
		tmp = X->p[i];
		X->p[i] = X->p[i] * (1 - swap) + Y->p[i] * swap;
		Y->p[i] = Y->p[i] * (1 - swap) + tmp * swap;
	}
	cleanup: return (ret);
}

/*
 * Set value from integer
 */
int jhd_tls_mpi_lset(jhd_tls_mpi *X, jhd_tls_mpi_sint z) {
	int ret;

	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(X, 1));
	memset(X->p, 0, X->n * ciL);
	X->p[0] = (z < 0) ? -z : z;
	X->s = (z < 0) ? -1 : 1;
	cleanup:
	return (ret);
}

/*
 * Get a specific bit
 */
int jhd_tls_mpi_get_bit(const jhd_tls_mpi *X, size_t pos) {
	if (X->n * biL <= pos){
		return JHD_OK;
	}

	return ((X->p[pos / biL] >> (pos % biL)) & 0x01);
}

/*
 * Set a bit to a specific value of 0 or 1
 */
int jhd_tls_mpi_set_bit(jhd_tls_mpi *X, size_t pos, unsigned char val) {
	int ret = 0;
	size_t off = pos / biL;
	size_t idx = pos % biL;
	log_assert(val ==0 || val == 1);

	if (X->n * biL <= pos) {
		if (val == 0){
			return JHD_OK;
		}
		JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(X, off + 1));
	}

	X->p[off] &= ~((jhd_tls_mpi_uint) 0x01 << idx);
	X->p[off] |= (jhd_tls_mpi_uint) val << idx;
	cleanup:
	return (ret);
}

/*
 * Return the number of less significant zero-bits
 */
size_t jhd_tls_mpi_lsb(const jhd_tls_mpi *X) {
	size_t i, j, count = 0;
	for (i = 0; i < X->n; i++){
		for (j = 0; j < biL; j++, count++){
			if (((X->p[i] >> j) & 1) != 0){
				return (count);
			}
		}
	}
	return (0);
}

/*
 * Count leading zero bits in a given integer
 */
static size_t jhd_tls_clz(const jhd_tls_mpi_uint x) {
	size_t j;
	jhd_tls_mpi_uint mask = (jhd_tls_mpi_uint) 1 << (biL - 1);
	for (j = 0; j < biL; j++) {
		if (x & mask){
			break;
		}
		mask >>= 1;
	}
	return j;
}

/*
 * Return the number of bits
 */
size_t jhd_tls_mpi_bitlen(const jhd_tls_mpi *X) {
	size_t i, j;
	if (X->n == 0){
		return (0);
	}
	for (i = X->n - 1; i > 0; i--){
		if (X->p[i] != 0){
			break;
		}
	}
	j = biL - jhd_tls_clz(X->p[i]);
	return ((i * biL) + j);
}

/*
 * Return the total size in bytes
 */
size_t jhd_tls_mpi_size(const jhd_tls_mpi *X) {
	return ((jhd_tls_mpi_bitlen(X) + 7) >> 3);
}



/*
 * Import X from unsigned binary data, big endian
 */
int jhd_tls_mpi_read_binary(jhd_tls_mpi *X, const unsigned char *buf, size_t buflen) {
	int ret;
	size_t i, j;
	size_t const limbs = CHARS_TO_LIMBS(buflen);

	/* Ensure that target MPI has exactly the necessary number of limbs */
	if (X->n != limbs) {
		jhd_tls_mpi_free(X);
		jhd_tls_mpi_init(X);
		JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(X, limbs));
	}

	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(X, 0));

	for (i = buflen, j = 0; i > 0; i--, j++){
		X->p[j / ciL] |= ((jhd_tls_mpi_uint) buf[i - 1]) << ((j % ciL) << 3);
	}
	cleanup:
	return (ret);
}

/*
 * Export X into unsigned binary data, big endian
 */
int jhd_tls_mpi_write_binary(const jhd_tls_mpi *X, unsigned char *buf, size_t buflen) {
	size_t i, j, n;
	n = jhd_tls_mpi_size(X);
	JHD_TLS_COMMON_CHECK_RETURN_ERROR(buflen < n)
	memset(buf, 0, buflen);
	for (i = buflen - 1, j = 0; n > 0; i--, j++, n--){
		buf[i] = (unsigned char) (X->p[j / ciL] >> ((j % ciL) << 3));
	}
	return JHD_OK;
}



int jhd_tls_mpi_encode(char* buf,size_t len,const jhd_tls_mpi* X,size_t *olen){
	uint32_t j, n;
	int i;
	n = 0;
	if(X->n>0){
		for(i = X->n -1; i >=0;--i){
			if(X->p[i] != 0){
				n = i+1;
				break;
			}
		}
	}
	if(n>0){
		n <<=3;
		j = n + 8;
		if(len < j){
			return JHD_ERROR;
		}
		*((uint32_t*)buf) = j;
		buf+=4;
		*((int*)(buf)) = X->s;
		buf+=4;
		memcpy(buf,(const void*)(X->p),n);
		*olen = j;
	}else{
		JHD_TLS_COMMON_CHECK_RETURN_ERROR(len < 8)
		*olen = 8;
		*((uint32_t*)buf) = 8;
		buf+=4;
		*((int*)(buf)) = X->s;
	}
	return JHD_OK;
}
int jhd_tls_mpi_decode(const char* buf,size_t len,jhd_tls_mpi *X,size_t *use_len){
	uint32_t n;
	n = *((uint32_t*)buf);
	log_assert((n >=8) && (n % 8 ==0)&& (n<=len));
	*use_len = n;
	n-=8;
	buf+=4;
	X->s = *((int*)(buf));
	buf+=4;
	if(n >0){
		if(JHD_OK != jhd_tls_mpi_grow(X,(n)>>3)){
			return JHD_ERROR;
		}
		memcpy(X->p,buf,n);
	}else{
		jhd_tls_mpi_lset(X,0);
	}
	return JHD_OK;
}

/*
 * Left-shift: X <<= count
 */
int jhd_tls_mpi_shift_l(jhd_tls_mpi *X, size_t count) {
	int ret;
	size_t i, v0, t1;
	jhd_tls_mpi_uint r0 = 0, r1;

	v0 = count / (biL);
	t1 = count & (biL - 1);

	i = jhd_tls_mpi_bitlen(X) + count;

	if (X->n * biL < i){
		JHD_TLS_MPI_CHK(jhd_tls_mpi_grow( X, BITS_TO_LIMBS( i ) ));
	}
	ret = JHD_OK;

	/*
	 * shift by count / limb_size
	 */
	if (v0 > 0) {
		for (i = X->n; i > v0; i--)
			X->p[i - 1] = X->p[i - v0 - 1];

		for (; i > 0; i--)
			X->p[i - 1] = 0;
	}

	/*
	 * shift by count % limb_size
	 */
	if (t1 > 0) {
		for (i = v0; i < X->n; i++) {
			r1 = X->p[i] >> (biL - t1);
			X->p[i] <<= t1;
			X->p[i] |= r0;
			r0 = r1;
		}
	}
	cleanup:
	return (ret);
}

/*
 * Right-shift: X >>= count
 */
int jhd_tls_mpi_shift_r(jhd_tls_mpi *X, size_t count) {
	size_t i, v0, v1;
	jhd_tls_mpi_uint r0 = 0, r1;
	v0 = count / biL;
	v1 = count & (biL - 1);
	if (v0 > X->n || (v0 == X->n && v1 > 0))
		return jhd_tls_mpi_lset(X, 0);
	/*
	 * shift by count / limb_size
	 */
	if (v0 > 0) {
		for (i = 0; i < X->n - v0; i++)
			X->p[i] = X->p[i + v0];

		for (; i < X->n; i++)
			X->p[i] = 0;
	}

	/*
	 * shift by count % limb_size
	 */
	if (v1 > 0) {
		for (i = X->n; i > 0; i--) {
			r1 = X->p[i - 1] << (biL - v1);
			X->p[i - 1] >>= v1;
			X->p[i - 1] |= r0;
			r0 = r1;
		}
	}
	return (0);
}

/*
 * Compare unsigned values
 */
int jhd_tls_mpi_cmp_abs(const jhd_tls_mpi *X, const jhd_tls_mpi *Y) {
	size_t i, j;
	for (i = X->n; i > 0; i--){
		if (X->p[i - 1] != 0){
			break;
		}
	}

	for (j = Y->n; j > 0; j--){
		if (Y->p[j - 1] != 0){
			break;
		}
	}

	if (i == 0 && j == 0){
		return (0);
	}

	if (i > j){
		return (1);
	}
	if (j > i){
		return (-1);
	}
	for (; i > 0; i--) {
		if (X->p[i - 1] > Y->p[i - 1]){
			return (1);
		}
		if (X->p[i - 1] < Y->p[i - 1]){
			return (-1);
		}
	}
	return (0);
}

/*
 * Compare signed values
 */
int jhd_tls_mpi_cmp_mpi(const jhd_tls_mpi *X, const jhd_tls_mpi *Y) {
	size_t i, j;
	for (i = X->n; i > 0; i--){
		if (X->p[i - 1] != 0){
			break;
		}
	}

	for (j = Y->n; j > 0; j--){
		if (Y->p[j - 1] != 0){
			break;
		}
	}

	if (i == 0 && j == 0){
		return (0);
	}

	if (i > j){
		return (X->s);
	}
	if (j > i){
		return (-Y->s);
	}

	if (X->s > 0 && Y->s < 0){
		return (1);
	}
	if (Y->s > 0 && X->s < 0){
		return (-1);
	}

	for (; i > 0; i--) {
		if (X->p[i - 1] > Y->p[i - 1]){
			return (X->s);
		}
		if (X->p[i - 1] < Y->p[i - 1]){
			return (-X->s);
		}
	}
	return (0);
}

/*
 * Compare signed values
 */
int jhd_tls_mpi_cmp_int(const jhd_tls_mpi *X, jhd_tls_mpi_sint z) {
	jhd_tls_mpi Y;
	jhd_tls_mpi_uint p[1];
	*p = (z < 0) ? -z : z;
	Y.s = (z < 0) ? -1 : 1;
	Y.n = 1;
	Y.p = p;
	return (jhd_tls_mpi_cmp_mpi(X, &Y));
}

/*
 * Unsigned addition: X = |A| + |B|  (HAC 14.7)
 */
int jhd_tls_mpi_add_abs(jhd_tls_mpi *X, const jhd_tls_mpi *A, const jhd_tls_mpi *B) {
	int ret;
	size_t i, j;
	jhd_tls_mpi_uint *o, *p, c, tmp;
	if (X == B) {
		const jhd_tls_mpi *T = A;
		A = X;
		B = T;
	}

	if (X != A){
		JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(X, A));
	}
	/*
	 * X should always be positive as a result of unsigned additions.
	 */
	X->s = 1;

	for (j = B->n; j > 0; j--){
		if (B->p[j - 1] != 0){
			break;
		}
	}

	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(X, j));

	o = B->p;
	p = X->p;
	c = 0;

	/*
	 * tmp is used because it might happen that p == o
	 */
	for (i = 0; i < j; i++, o++, p++) {
		tmp = *o;
		*p += c;
		c = (*p < c);
		*p += tmp;
		c += (*p < tmp);
	}

	while (c != 0) {
		if (i >= X->n) {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(X, i + 1));
			p = X->p + i;
		}

		*p += c;
		c = (*p < c);
		i++;
		p++;
	}

	cleanup:

	return (ret);
}

/*
 * Helper for jhd_tls_mpi subtraction
 */
static void mpi_sub_hlp(size_t n, jhd_tls_mpi_uint *s, jhd_tls_mpi_uint *d) {
	size_t i;
	jhd_tls_mpi_uint c, z;

	for (i = c = 0; i < n; i++, s++, d++) {
		z = (*d < c);
		*d -= c;
		c = (*d < *s) + z;
		*d -= *s;
	}

	while (c != 0) {
		z = (*d < c);
		*d -= c;
		c = z;
		d++;
	}
}

/*
 * Unsigned subtraction: X = |A| - |B|  (HAC 14.9)
 */
int jhd_tls_mpi_sub_abs(jhd_tls_mpi *X, const jhd_tls_mpi *A, const jhd_tls_mpi *B) {
	jhd_tls_mpi TB;
	int ret;
	size_t n;

	JHD_TLS_COMMON_CHECK_RETURN_ERROR(jhd_tls_mpi_cmp_abs(A, B) < 0)

	jhd_tls_mpi_init(&TB);

	if (X == B) {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&TB, B));
		B = &TB;
	}

	if (X != A){
		JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(X, A));
	}
	/*
	 * X should always be positive as a result of unsigned subtractions.
	 */
	X->s = 1;

	ret = 0;

	for (n = B->n; n > 0; n--){
		if (B->p[n - 1] != 0){
			break;
		}
	}
	mpi_sub_hlp(n, B->p, X->p);
	cleanup:
	jhd_tls_mpi_free(&TB);
	return (ret);
}

/*
 * Signed addition: X = A + B
 */
int jhd_tls_mpi_add_mpi(jhd_tls_mpi *X, const jhd_tls_mpi *A, const jhd_tls_mpi *B) {
	int ret, s = A->s;
	if (A->s * B->s < 0) {
		if (jhd_tls_mpi_cmp_abs(A, B) >= 0) {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_abs(X, A, B));
			X->s = s;
		} else {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_abs(X, B, A));
			X->s = -s;
		}
	} else {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_add_abs(X, A, B));
		X->s = s;
	}
	cleanup:
	return (ret);
}

/*
 * Signed subtraction: X = A - B
 */
int jhd_tls_mpi_sub_mpi(jhd_tls_mpi *X, const jhd_tls_mpi *A, const jhd_tls_mpi *B) {
	int ret, s = A->s;

	if (A->s * B->s > 0) {
		if (jhd_tls_mpi_cmp_abs(A, B) >= 0) {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_abs(X, A, B));
			X->s = s;
		} else {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_abs(X, B, A));
			X->s = -s;
		}
	} else {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_add_abs(X, A, B));
		X->s = s;
	}

	cleanup:

	return (ret);
}

/*
 * Signed addition: X = A + b
 */
int jhd_tls_mpi_add_int(jhd_tls_mpi *X, const jhd_tls_mpi *A, jhd_tls_mpi_sint b) {
	jhd_tls_mpi _B;
	jhd_tls_mpi_uint p[1];
	p[0] = (b < 0) ? -b : b;
	_B.s = (b < 0) ? -1 : 1;
	_B.n = 1;
	_B.p = p;
	return (jhd_tls_mpi_add_mpi(X, A, &_B));
}

/*
 * Signed subtraction: X = A - b
 */
int jhd_tls_mpi_sub_int(jhd_tls_mpi *X, const jhd_tls_mpi *A, jhd_tls_mpi_sint b) {
	jhd_tls_mpi _B;
	jhd_tls_mpi_uint p[1];
	p[0] = (b < 0) ? -b : b;
	_B.s = (b < 0) ? -1 : 1;
	_B.n = 1;
	_B.p = p;
	return (jhd_tls_mpi_sub_mpi(X, A, &_B));
}

/*
 * Helper for jhd_tls_mpi multiplication
 */
static
#if defined(__APPLE__) && defined(__arm__)
/*
 * Apple LLVM version 4.2 (clang-425.0.24) (based on LLVM 3.2svn)
 * appears to need this to prevent bad ARM code generation at -O3.
 */
__attribute__ ((noinline))
#endif
void mpi_mul_hlp(size_t i, jhd_tls_mpi_uint *s, jhd_tls_mpi_uint *d, jhd_tls_mpi_uint b) {
	jhd_tls_mpi_uint c = 0, t = 0;

#if defined(MULADDC_HUIT)
	for(; i >= 8; i -= 8 )
	{
		MULADDC_INIT
		MULADDC_HUIT
		MULADDC_STOP
	}

	for(; i > 0; i-- )
	{
		MULADDC_INIT
		MULADDC_CORE
		MULADDC_STOP
	}
#else /* MULADDC_HUIT */
	for (; i >= 16; i -= 16) {
		MULADDC_INIT
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE

		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_STOP
	}

	for (; i >= 8; i -= 8) {
		MULADDC_INIT
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE

		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_STOP
	}

	for (; i > 0; i--) {
		MULADDC_INIT
		MULADDC_CORE
		MULADDC_STOP
	}
#endif /* MULADDC_HUIT */

	t++;

	do {
		*d += c;
		c = (*d < c);
		d++;
	} while (c != 0);
}

/*
 * Baseline multiplication: X = A * B  (HAC 14.12)
 */
int jhd_tls_mpi_mul_mpi(jhd_tls_mpi *X, const jhd_tls_mpi *A, const jhd_tls_mpi *B) {
	int ret;
	size_t i, j;
	jhd_tls_mpi TA, TB;

	jhd_tls_mpi_init(&TA);
	jhd_tls_mpi_init(&TB);

	if (X == A) {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&TA, A));
		A = &TA;
	}
	if (X == B) {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&TB, B));
		B = &TB;
	}

	for (i = A->n; i > 0; i--){
		if (A->p[i - 1] != 0){
			break;
		}
	}

	for (j = B->n; j > 0; j--){
		if (B->p[j - 1] != 0){
			break;
		}
	}

	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(X, i + j));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(X, 0));

	for (; j > 0; j--){
		mpi_mul_hlp(i, A->p, X->p + j - 1, B->p[j - 1]);
	}
	X->s = A->s * B->s;
	cleanup:
	jhd_tls_mpi_free(&TB);
	jhd_tls_mpi_free(&TA);
	return (ret);
}

/*
 * Baseline multiplication: X = A * b
 */
int jhd_tls_mpi_mul_int(jhd_tls_mpi *X, const jhd_tls_mpi *A, jhd_tls_mpi_uint b) {
	jhd_tls_mpi _B;
	jhd_tls_mpi_uint p[1];
	_B.s = 1;
	_B.n = 1;
	_B.p = p;
	p[0] = b;
	return (jhd_tls_mpi_mul_mpi(X, A, &_B));
}

/*
 * Unsigned integer divide - double jhd_tls_mpi_uint dividend, u1/u0, and
 * jhd_tls_mpi_uint divisor, d
 */
static jhd_tls_mpi_uint jhd_tls_int_div_int(jhd_tls_mpi_uint u1, jhd_tls_mpi_uint u0, jhd_tls_mpi_uint d, jhd_tls_mpi_uint *r) {
#if defined(JHD_TLS_HAVE_UDBL)
	jhd_tls_t_udbl dividend, quotient;
#else
	const jhd_tls_mpi_uint radix = (jhd_tls_mpi_uint) 1 << biH;
	const jhd_tls_mpi_uint uint_halfword_mask = ( (jhd_tls_mpi_uint) 1 << biH ) - 1;
	jhd_tls_mpi_uint d0, d1, q0, q1, rAX, r0, quotient;
	jhd_tls_mpi_uint u0_msw, u0_lsw;
	size_t s;
#endif
	/*
	 * Check for overflow
	 */
	if (0 == d || u1 >= d) {
		if (r != NULL){
			*r = ~0;
		}

		return (~0);
	}

#if defined(JHD_TLS_HAVE_UDBL)
	dividend = (jhd_tls_t_udbl) u1 << biL;
	dividend |= (jhd_tls_t_udbl) u0;
	quotient = dividend / d;
	if (quotient > ((jhd_tls_t_udbl) 1 << biL) - 1){
		quotient = ((jhd_tls_t_udbl) 1 << biL) - 1;
	}
	if (r != NULL){
		*r = (jhd_tls_mpi_uint) (dividend - (quotient * d));
	}
	return (jhd_tls_mpi_uint) quotient;
#else

	/*
	 * Algorithm D, Section 4.3.1 - The Art of Computer Programming
	 *   Vol. 2 - Seminumerical Algorithms, Knuth
	 */

	/*
	 * Normalize the divisor, d, and dividend, u0, u1
	 */
	s = jhd_tls_clz( d );
	d = d << s;

	u1 = u1 << s;
	u1 |= ( u0 >> ( biL - s ) ) & ( -(jhd_tls_mpi_sint)s >> ( biL - 1 ) );
	u0 = u0 << s;

	d1 = d >> biH;
	d0 = d & uint_halfword_mask;

	u0_msw = u0 >> biH;
	u0_lsw = u0 & uint_halfword_mask;

	/*
	 * Find the first quotient and remainder
	 */
	q1 = u1 / d1;
	r0 = u1 - d1 * q1;

	while( q1 >= radix || ( q1 * d0 > radix * r0 + u0_msw ) )
	{
		q1 -= 1;
		r0 += d1;

		if ( r0 >= radix ) break;
	}

	rAX = ( u1 * radix ) + ( u0_msw - q1 * d );
	q0 = rAX / d1;
	r0 = rAX - q0 * d1;

	while( q0 >= radix || ( q0 * d0 > radix * r0 + u0_lsw ) )
	{
		q0 -= 1;
		r0 += d1;

		if ( r0 >= radix ) break;
	}

	if (r != NULL)
	*r = ( rAX * radix + u0_lsw - q0 * d ) >> s;

	quotient = q1 * radix + q0;

	return quotient;
#endif
}

/*
 * Division by jhd_tls_mpi: A = Q * B + R  (HAC 14.20)
 */
int jhd_tls_mpi_div_mpi(jhd_tls_mpi *Q, jhd_tls_mpi *R, const jhd_tls_mpi *A, const jhd_tls_mpi *B) {
	int ret;
	size_t i, n, t, k;
	jhd_tls_mpi X, Y, Z, T1, T2;

	log_assert(jhd_tls_mpi_cmp_int(B, 0) != 0/*,"div 0"*/);
	jhd_tls_mpi_init(&X);
	jhd_tls_mpi_init(&Y);
	jhd_tls_mpi_init(&Z);
	jhd_tls_mpi_init(&T1);
	jhd_tls_mpi_init(&T2);

	if (jhd_tls_mpi_cmp_abs(A, B) < 0) {
		if (Q != NULL){
			JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(Q, 0));
		}
		if (R != NULL){
			JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(R, A));
		}
		return (0);
	}

	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&X, A));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&Y, B));
	X.s = Y.s = 1;

	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(&Z, A->n + 2));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&Z, 0));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(&T1, 2));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(&T2, 3));

	k = jhd_tls_mpi_bitlen(&Y) % biL;
	if (k < biL - 1) {
		k = biL - 1 - k;
		JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_l(&X, k));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_l(&Y, k));
	} else
		k = 0;

	n = X.n - 1;
	t = Y.n - 1;
	JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_l( &Y, biL * ( n - t ) ));

	while (jhd_tls_mpi_cmp_mpi(&X, &Y) >= 0) {
		Z.p[n - t]++;
		JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&X, &X, &Y));
	}
	JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r( &Y, biL * ( n - t ) ));

	for (i = n; i > t; i--) {
		if (X.p[i] >= Y.p[t])
			Z.p[i - t - 1] = ~0;
		else {
			Z.p[i - t - 1] = jhd_tls_int_div_int(X.p[i], X.p[i - 1], Y.p[t], NULL);
		}

		Z.p[i - t - 1]++;
		do {
			Z.p[i - t - 1]--;

			JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&T1, 0));
			T1.p[0] = (t < 1) ? 0 : Y.p[t - 1];
			T1.p[1] = Y.p[t];
			JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_int(&T1, &T1, Z.p[i - t - 1]));

			JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&T2, 0));
			T2.p[0] = (i < 2) ? 0 : X.p[i - 2];
			T2.p[1] = (i < 1) ? 0 : X.p[i - 1];
			T2.p[2] = X.p[i];
		} while (jhd_tls_mpi_cmp_mpi(&T1, &T2) > 0);

		JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_int(&T1, &Y, Z.p[i - t - 1]));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_l( &T1, biL * ( i - t - 1 ) ));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&X, &X, &T1));

		if (jhd_tls_mpi_cmp_int(&X, 0) < 0) {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&T1, &Y));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_l( &T1, biL * ( i - t - 1 ) ));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(&X, &X, &T1));
			Z.p[i - t - 1]--;
		}
	}

	if (Q != NULL) {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(Q, &Z));
		Q->s = A->s * B->s;
	}

	if (R != NULL) {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&X, k));
		X.s = A->s;
		JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(R, &X));

		if (jhd_tls_mpi_cmp_int(R, 0) == 0)
			R->s = 1;
	}

	cleanup:

	jhd_tls_mpi_free(&X);
	jhd_tls_mpi_free(&Y);
	jhd_tls_mpi_free(&Z);
	jhd_tls_mpi_free(&T1);
	jhd_tls_mpi_free(&T2);

	return (ret);
}

/*
 * Division by int: A = Q * b + R
 */
int jhd_tls_mpi_div_int(jhd_tls_mpi *Q, jhd_tls_mpi *R, const jhd_tls_mpi *A, jhd_tls_mpi_sint b) {
	jhd_tls_mpi _B;
	jhd_tls_mpi_uint p[1];
	log_assert(b!=0/*,"div 0"*/);

	p[0] = (b < 0) ? -b : b;
	_B.s = (b < 0) ? -1 : 1;
	_B.n = 1;
	_B.p = p;

	return (jhd_tls_mpi_div_mpi(Q, R, A, &_B));
}

/*
 * Modulo: R = A mod B
 */
int jhd_tls_mpi_mod_mpi(jhd_tls_mpi *R, const jhd_tls_mpi *A, const jhd_tls_mpi *B) {
	int ret;

	log_assert(jhd_tls_mpi_cmp_int(B, 0) >= 0/*,"mod (?=<0)"*/);

	JHD_TLS_MPI_CHK(jhd_tls_mpi_div_mpi( NULL, R, A, B ));
	while (jhd_tls_mpi_cmp_int(R, 0) < 0){
		JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(R, R, B));
	}
	while (jhd_tls_mpi_cmp_mpi(R, B) >= 0){
		JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(R, R, B));
	}
	cleanup:
	return (ret);
}

/*
 * Modulo: r = A mod b
 */
int jhd_tls_mpi_mod_int(jhd_tls_mpi_uint *r, const jhd_tls_mpi *A, jhd_tls_mpi_sint b) {
	size_t i;
	jhd_tls_mpi_uint x, y, z;
	log_assert(b>0/*,"mod (?<=0"*/);

	/*
	 * handle trivial cases
	 */
	if (b == 1) {
		*r = 0;
		return JHD_OK;
	}

	if (b == 2) {
		*r = A->p[0] & 1;
		return JHD_OK;
	}

	/*
	 * general case
	 */
	for (i = A->n, y = 0; i > 0; i--) {
		x = A->p[i - 1];
		y = (y << biH) | (x >> biH);
		z = y / b;
		y -= z * b;

		x <<= biH;
		y = (y << biH) | (x >> biH);
		z = y / b;
		y -= z * b;
	}

	/*
	 * If A is negative, then the current y represents a negative value.
	 * Flipping it to the positive side.
	 */
	if (A->s < 0 && y != 0)
		y = b - y;

	*r = y;

	return JHD_OK;
}

/*
 * Fast Montgomery initialization (thanks to Tom St Denis)
 */
static void mpi_montg_init(jhd_tls_mpi_uint *mm, const jhd_tls_mpi *N) {
	jhd_tls_mpi_uint x, m0 = N->p[0];
	unsigned int i;

	x = m0;
	x += ((m0 + 2) & 4) << 1;

	for (i = biL; i >= 8; i /= 2)
		x *= (2 - (m0 * x));

	*mm = ~x + 1;
}

/*
 * Montgomery multiplication: A = A * B * R^-1 mod N  (HAC 14.36)
 */

 static int mpi_montmul(jhd_tls_mpi *A, const jhd_tls_mpi *B, const jhd_tls_mpi *N, jhd_tls_mpi_uint mm, const jhd_tls_mpi *T) {
	size_t i, n, m;
	jhd_tls_mpi_uint u0, u1, *d;

	log_assert(!(T->n < N->n + 1 || T->p == NULL)/*,"invalid param T"*/);

//	if (T->n < N->n + 1 || T->p == NULL)
//		return JHD_ERROR;
	memset(T->p, 0, T->n * ciL);
	d = T->p;
	n = N->n;
	m = (B->n < n) ? B->n : n;
	for (i = 0; i < n; i++) {
		/*
		 * T = (T + u0*B + u1*N) / 2^biL
		 */
		u0 = A->p[i];
		u1 = (d[0] + u0 * B->p[0]) * mm;

		mpi_mul_hlp(m, B->p, d, u0);
		mpi_mul_hlp(n, N->p, d, u1);
		*(d++) = u0;
		d[n + 1] = 0;
	}
	memcpy(A->p, d, (n + 1) * ciL);
	if (jhd_tls_mpi_cmp_abs(A, N) >= 0){
		mpi_sub_hlp(n, N->p, A->p);
	}
	else{
		/* prevent timing attacks */
		mpi_sub_hlp(n, A->p, T->p);
	}

	return JHD_OK;
}
/*
 * Montgomery reduction: A = A * R^-1 mod N
 */
static int mpi_montred(jhd_tls_mpi *A, const jhd_tls_mpi *N, jhd_tls_mpi_uint mm, const jhd_tls_mpi *T) {
	jhd_tls_mpi_uint z = 1;
	jhd_tls_mpi U;

	U.n = U.s = (int) z;
	U.p = &z;

	return (mpi_montmul(A, &U, N, mm, T));
}

///*
// * Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)
// */
//int jhd_tls_mpi_exp_mod2(jhd_tls_mpi *X, const jhd_tls_mpi *A, const jhd_tls_mpi *E, const jhd_tls_mpi *N, jhd_tls_mpi *_RR) {
//	int ret;
//	size_t wbits, wsize, one = 1;
//	size_t i, j, nblimbs;
//	size_t bufsize, nbits;
//	jhd_tls_mpi_uint ei, mm, state;
//	jhd_tls_mpi RR, T, W[2 << JHD_TLS_MPI_WINDOW_SIZE], Apos;
//	int neg;
//
//	if (jhd_tls_mpi_cmp_int(N, 0) <= 0 || (N->p[0] & 1) == 0)
//		return JHD_ERROR;
//
//	if (jhd_tls_mpi_cmp_int(E, 0) < 0)
//		return JHD_ERROR;
//
//	/*
//	 * Init temps and window size
//	 */
//	mpi_montg_init(&mm, N);
//	jhd_tls_mpi_init(&RR);
//	jhd_tls_mpi_init(&T);
//	jhd_tls_mpi_init(&Apos);
//	memset(W, 0, sizeof(W));
//
//	i = jhd_tls_mpi_bitlen(E);
//
//	wsize = (i > 671) ? 6 : (i > 239) ? 5 : (i > 79) ? 4 : (i > 23) ? 3 : 1;
//
//	if (wsize > JHD_TLS_MPI_WINDOW_SIZE)
//		wsize = JHD_TLS_MPI_WINDOW_SIZE;
//
//	j = N->n + 1;
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(X, j));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(&W[1], j));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(&T, j * 2));
//
//	/*
//	 * Compensate for negative A (and correct at the end)
//	 */
//	neg = (A->s == -1);
//	if (neg) {
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&Apos, A));
//		Apos.s = 1;
//		A = &Apos;
//	}
//
//	/*
//	 * If 1st call, pre-compute R^2 mod N
//	 */
////	if (_RR == NULL || _RR->p == NULL) {
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&RR, 1));
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_l( &RR, N->n * 2 * biL ));
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_mod_mpi(&RR, &RR, N));
//
////		if (_RR != NULL)
////			memcpy(_RR, &RR, sizeof(jhd_tls_mpi));
////	} else
////		memcpy(&RR, _RR, sizeof(jhd_tls_mpi));
//
//	/*
//	 * W[1] = A * R^2 * R^-1 mod N = A * R mod N
//	 */
//	if (jhd_tls_mpi_cmp_mpi(A, N) >= 0){
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_mod_mpi(&W[1], A, N));
//	}
//	else{
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&W[1], A));
//	}
//
//	JHD_TLS_MPI_CHK(mpi_montmul(&W[1], &RR, N, mm, &T));
//
//	/*
//	 * X = R^2 * R^-1 mod N = R mod N
//	 */
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(X, &RR));
//	JHD_TLS_MPI_CHK(mpi_montred(X, N, mm, &T));
//
//	if (wsize > 1) {
//		/*
//		 * W[1 << (wsize - 1)] = W[1] ^ (wsize - 1)
//		 */
//		j = one << (wsize - 1);
//
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(&W[j], N->n + 1));
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&W[j], &W[1]));
//
//		for (i = 0; i < wsize - 1; i++)
//			JHD_TLS_MPI_CHK(mpi_montmul(&W[j], &W[j], N, mm, &T));
//
//		/*
//		 * W[i] = W[i - 1] * W[1]
//		 */
//		for (i = j + 1; i < (one << wsize); i++) {
//			JHD_TLS_MPI_CHK(jhd_tls_mpi_grow(&W[i], N->n + 1));
//			JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&W[i], &W[i - 1]));
//
//			JHD_TLS_MPI_CHK(mpi_montmul(&W[i], &W[1], N, mm, &T));
//		}
//	}
//
//	nblimbs = E->n;
//	bufsize = 0;
//	nbits = 0;
//	wbits = 0;
//	state = 0;
//
//	while (1) {
//		if (bufsize == 0) {
//			if (nblimbs == 0)
//				break;
//
//			nblimbs--;
//
//			bufsize = sizeof(jhd_tls_mpi_uint) << 3;
//		}
//
//		bufsize--;
//
//		ei = (E->p[nblimbs] >> bufsize) & 1;
//
//		/*
//		 * skip leading 0s
//		 */
//		if (ei == 0 && state == 0)
//			continue;
//
//		if (ei == 0 && state == 1) {
//			/*
//			 * out of window, square X
//			 */
//			JHD_TLS_MPI_CHK(mpi_montmul(X, X, N, mm, &T));
//			continue;
//		}
//
//		/*
//		 * add ei to current window
//		 */
//		state = 2;
//
//		nbits++;
//		wbits |= (ei << (wsize - nbits));
//
//		if (nbits == wsize) {
//			/*
//			 * X = X^wsize R^-1 mod N
//			 */
//			for (i = 0; i < wsize; i++)
//				JHD_TLS_MPI_CHK(mpi_montmul(X, X, N, mm, &T));
//
//			/*
//			 * X = X * W[wbits] R^-1 mod N
//			 */
//			JHD_TLS_MPI_CHK(mpi_montmul(X, &W[wbits], N, mm, &T));
//
//			state--;
//			nbits = 0;
//			wbits = 0;
//		}
//	}
//
//	/*
//	 * process the remaining bits
//	 */
//	for (i = 0; i < nbits; i++) {
//		JHD_TLS_MPI_CHK(mpi_montmul(X, X, N, mm, &T));
//
//		wbits <<= 1;
//
//		if ((wbits & (one << wsize)) != 0)
//			JHD_TLS_MPI_CHK(mpi_montmul(X, &W[1], N, mm, &T));
//	}
//
//	/*
//	 * X = A^E * R * R^-1 mod N = A^E mod N
//	 */
//	JHD_TLS_MPI_CHK(mpi_montred(X, N, mm, &T));
//
//	if (neg && E->n != 0 && (E->p[0] & 1) != 0) {
//		X->s = -1;
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(X, N, X));
//	}
//
//	cleanup:
//
//	for (i = (one << (wsize - 1)); i < (one << wsize); i++)
//		jhd_tls_mpi_free(&W[i]);
//
//	jhd_tls_mpi_free(&W[1]);
//	jhd_tls_mpi_free(&T);
//	jhd_tls_mpi_free(&Apos);
//
//	if (_RR == NULL || _RR->p == NULL)
//		jhd_tls_mpi_free(&RR);
//
//	return (ret);
//}


int jhd_tls_mpi_exp_mod( jhd_tls_mpi *X, const jhd_tls_mpi *A, const jhd_tls_mpi *E, const jhd_tls_mpi *N,const jhd_tls_mpi *RR )
{
    int ret;
    size_t wbits, wsize, one = 1;
    size_t i, j, nblimbs;
    size_t bufsize, nbits;
    jhd_tls_mpi_uint ei, mm, state;
    jhd_tls_mpi T, W[ 2 << JHD_TLS_MPI_WINDOW_SIZE ], Apos;
    int neg;
    log_assert((jhd_tls_mpi_cmp_int( N, 0 ) > 0) && (( N->p[0] & 1 ) != 0)/*,"invalid param N"*/);
    log_assert(jhd_tls_mpi_cmp_int( E, 0 ) >= 0 /*,"invalid param E"*/);

    /*
     * Init temps and window size
     */
    mpi_montg_init( &mm, N );
    jhd_tls_mpi_init( &T );
    jhd_tls_mpi_init( &Apos );
    memset( W, 0, sizeof( W ) );
    for(i = 0 ;i < (2 << JHD_TLS_MPI_WINDOW_SIZE);++i){
    	W[i].s = 1;
    }
    i = jhd_tls_mpi_bitlen( E );
    wsize = ( i > 671 ) ? 6 : ( i > 239 ) ? 5 :
            ( i >  79 ) ? 4 : ( i >  23 ) ? 3 : 1;
    if( wsize > JHD_TLS_MPI_WINDOW_SIZE ){
        wsize = JHD_TLS_MPI_WINDOW_SIZE;
    }
    j = N->n + 1;
    JHD_TLS_MPI_CHK( jhd_tls_mpi_grow( X, j ) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_grow( &W[1],  j ) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_grow( &T, j * 2 ) );
    /*
     * Compensate for negative A (and correct at the end)
     */
    neg = ( A->s == -1 );
    if( neg )
    {
        JHD_TLS_MPI_CHK( jhd_tls_mpi_copy( &Apos, A ) );
        Apos.s = 1;
        A = &Apos;
    }

    /*
     * W[1] = A * R^2 * R^-1 mod N = A * R mod N
     */
    if( jhd_tls_mpi_cmp_mpi( A, N ) >= 0 ){
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &W[1], A, N ) );
    }else{
        JHD_TLS_MPI_CHK( jhd_tls_mpi_copy( &W[1], A ) );
    }


    JHD_TLS_MPI_CHK( mpi_montmul( &W[1], RR, N, mm, &T ) );
    /*
     * X = R^2 * R^-1 mod N = R mod N
     */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_copy( X, RR ) );
    JHD_TLS_MPI_CHK( mpi_montred( X, N, mm, &T ) );
    if( wsize > 1 )
    {
        /*
         * W[1 << (wsize - 1)] = W[1] ^ (wsize - 1)
         */

        j =  one << ( wsize - 1 );

        JHD_TLS_MPI_CHK( jhd_tls_mpi_grow( &W[j], N->n + 1 ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_copy( &W[j], &W[1]    ) );

        for( i = 0; i < wsize - 1; i++ ){
            JHD_TLS_MPI_CHK( mpi_montmul( &W[j], &W[j], N, mm, &T ) );
        }
        /*
         *
         * W[i] = W[i - 1] * W[1]
         */
        for( i = j + 1; i < ( one << wsize ); i++ )
        {
            JHD_TLS_MPI_CHK( jhd_tls_mpi_grow( &W[i], N->n + 1 ) );
            JHD_TLS_MPI_CHK( jhd_tls_mpi_copy( &W[i], &W[i - 1] ) );
            JHD_TLS_MPI_CHK( mpi_montmul( &W[i], &W[1], N, mm, &T ) );
        }
    }

    nblimbs = E->n;
    bufsize = 0;
    nbits   = 0;
    wbits   = 0;
    state   = 0;

    while( 1 )
    {
        if( bufsize == 0 )
        {
            if( nblimbs == 0 )
                break;

            nblimbs--;

            bufsize = sizeof( jhd_tls_mpi_uint ) << 3;
        }

        bufsize--;

        ei = (E->p[nblimbs] >> bufsize) & 1;

        /*
         * skip leading 0s
         */
        if( ei == 0 && state == 0 )
            continue;

        if( ei == 0 && state == 1 )
        {
            /*
             * out of window, square X
             */
            JHD_TLS_MPI_CHK( mpi_montmul( X, X, N, mm, &T ) );
            continue;
        }

        /*
         * add ei to current window
         */
        state = 2;

        nbits++;
        wbits |= ( ei << ( wsize - nbits ) );

        if( nbits == wsize )
        {
            /*
             * X = X^wsize R^-1 mod N
             */
            for( i = 0; i < wsize; i++ ){
                JHD_TLS_MPI_CHK( mpi_montmul( X, X, N, mm, &T ) );
            }
            /*
             * X = X * W[wbits] R^-1 mod N
             */
            JHD_TLS_MPI_CHK( mpi_montmul( X, &W[wbits], N, mm, &T ) );

            state--;
            nbits = 0;
            wbits = 0;
        }
    }

    /*
     * process the remaining bits
     */
    for( i = 0; i < nbits; i++ )
    {
        JHD_TLS_MPI_CHK( mpi_montmul( X, X, N, mm, &T ) );

        wbits <<= 1;

        if( ( wbits & ( one << wsize ) ) != 0 ){
            JHD_TLS_MPI_CHK( mpi_montmul( X, &W[1], N, mm, &T ) );
        }
    }

    /*
     * X = A^E * R * R^-1 mod N = A^E mod N
     */
    JHD_TLS_MPI_CHK( mpi_montred( X, N, mm, &T ) );

    if( neg && E->n != 0 && ( E->p[0] & 1 ) != 0 )
    {
        X->s = -1;
        JHD_TLS_MPI_CHK( jhd_tls_mpi_add_mpi( X, N, X ) );
    }

cleanup:

    for( i = ( one << ( wsize - 1 ) ); i < ( one << wsize ); i++ ){
        jhd_tls_mpi_free( &W[i] );
    }
    jhd_tls_mpi_free( &W[1] );
    jhd_tls_mpi_free( &T );
    jhd_tls_mpi_free( &Apos );
    return( ret );
}

/*
 * Greatest common divisor: G = gcd(A, B)  (HAC 14.54)
 */
int jhd_tls_mpi_gcd(jhd_tls_mpi *G, const jhd_tls_mpi *A, const jhd_tls_mpi *B) {
	int ret;
	size_t lz, lzt;
	jhd_tls_mpi TG, TA, TB;

	jhd_tls_mpi_init(&TG);
	jhd_tls_mpi_init(&TA);
	jhd_tls_mpi_init(&TB);

	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&TA, A));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&TB, B));

	lz = jhd_tls_mpi_lsb(&TA);
	lzt = jhd_tls_mpi_lsb(&TB);

	if (lzt < lz)
		lz = lzt;

	JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&TA, lz));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&TB, lz));

	TA.s = TB.s = 1;

	while (jhd_tls_mpi_cmp_int(&TA, 0) != 0) {
		JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&TA, jhd_tls_mpi_lsb(&TA)));
		JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&TB, jhd_tls_mpi_lsb(&TB)));

		if (jhd_tls_mpi_cmp_mpi(&TA, &TB) >= 0) {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_abs(&TA, &TA, &TB));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&TA, 1));
		} else {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_abs(&TB, &TB, &TA));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&TB, 1));
		}
	}

	JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_l(&TB, lz));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(G, &TB));

	cleanup:

	jhd_tls_mpi_free(&TG);
	jhd_tls_mpi_free(&TA);
	jhd_tls_mpi_free(&TB);

	return (ret);
}

/*
 * Fill X with size bytes of random.
 *
 * Use a temporary bytes representation to make sure the result is the same
 * regardless of the platform endianness (useful when f_rng is actually
 * deterministic, eg for tests).
 */
int jhd_tls_mpi_fill_random(jhd_tls_mpi *X, size_t size) {
	unsigned char buf[JHD_TLS_MPI_MAX_SIZE];
	log_assert(size <= JHD_TLS_MPI_MAX_SIZE/*,"invalid mpi bit length"*/);
	jhd_tls_random(buf,size);
	return jhd_tls_mpi_read_binary(X, buf, size);
}
int jhd_tls_mpi_fill_random_specific(jhd_tls_mpi *X, size_t size, void (*f_rng)(void *, unsigned char *, size_t), void *p_rng){
	unsigned char buf[JHD_TLS_MPI_MAX_SIZE];
	log_assert(size <= JHD_TLS_MPI_MAX_SIZE/*,"invalid mpi bit length"*/);
	f_rng(p_rng, buf, size);
	return jhd_tls_mpi_read_binary(X, buf, size);
}

/*
 * Modular inverse: X = A^-1 mod N  (HAC 14.61 / 14.64)
 */
int jhd_tls_mpi_inv_mod(jhd_tls_mpi *X, const jhd_tls_mpi *A, const jhd_tls_mpi *N) {
	int ret;
	jhd_tls_mpi G, TA, TU, U1, U2, TB, TV, V1, V2;

	if (jhd_tls_mpi_cmp_int(N, 1) <= 0)
		return JHD_ERROR;

	jhd_tls_mpi_init(&TA);
	jhd_tls_mpi_init(&TU);
	jhd_tls_mpi_init(&U1);
	jhd_tls_mpi_init(&U2);
	jhd_tls_mpi_init(&G);
	jhd_tls_mpi_init(&TB);
	jhd_tls_mpi_init(&TV);
	jhd_tls_mpi_init(&V1);
	jhd_tls_mpi_init(&V2);

	JHD_TLS_MPI_CHK(jhd_tls_mpi_gcd(&G, A, N));

	if (jhd_tls_mpi_cmp_int(&G, 1) != 0) {
		ret = JHD_ERROR;
		goto cleanup;
	}

	JHD_TLS_MPI_CHK(jhd_tls_mpi_mod_mpi(&TA, A, N));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&TU, &TA));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&TB, N));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&TV, N));

	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&U1, 1));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&U2, 0));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&V1, 0));
	JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&V2, 1));

	do {
		while ((TU.p[0] & 1) == 0) {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&TU, 1));

			if ((U1.p[0] & 1) != 0 || (U2.p[0] & 1) != 0) {
				JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(&U1, &U1, &TB));
				JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&U2, &U2, &TA));
			}

			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&U1, 1));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&U2, 1));
		}

		while ((TV.p[0] & 1) == 0) {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&TV, 1));

			if ((V1.p[0] & 1) != 0 || (V2.p[0] & 1) != 0) {
				JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(&V1, &V1, &TB));
				JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&V2, &V2, &TA));
			}

			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&V1, 1));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&V2, 1));
		}

		if (jhd_tls_mpi_cmp_mpi(&TU, &TV) >= 0) {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&TU, &TU, &TV));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&U1, &U1, &V1));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&U2, &U2, &V2));
		} else {
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&TV, &TV, &TU));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&V1, &V1, &U1));
			JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&V2, &V2, &U2));
		}
	} while (jhd_tls_mpi_cmp_int(&TU, 0) != 0);

	while (jhd_tls_mpi_cmp_int(&V1, 0) < 0){
		JHD_TLS_MPI_CHK(jhd_tls_mpi_add_mpi(&V1, &V1, N));
	}
	while (jhd_tls_mpi_cmp_mpi(&V1, N) >= 0){
		JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_mpi(&V1, &V1, N));
	}
	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(X, &V1));

	cleanup:

	jhd_tls_mpi_free(&TA);
	jhd_tls_mpi_free(&TU);
	jhd_tls_mpi_free(&U1);
	jhd_tls_mpi_free(&U2);
	jhd_tls_mpi_free(&G);
	jhd_tls_mpi_free(&TB);
	jhd_tls_mpi_free(&TV);
	jhd_tls_mpi_free(&V1);
	jhd_tls_mpi_free(&V2);

	return (ret);
}

#if defined(JHD_TLS_GENPRIME)
//
//static const int small_prime[] = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
//        131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
//        293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
//        479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
//        673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
//        881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, -103 };
//
///*
// * Small divisors test (X must be positive)
// *
// * Return values:
// * 0: no small factor (possible prime, more tests needed)
// * 1: certain prime
// * JHD_UNEXPECTED: certain non-prime
// * other negative: error
// */
//static int mpi_check_small_factors(const jhd_tls_mpi *X) {
//	int ret = 0;
//	size_t i;
//	jhd_tls_mpi_uint r;
//
//	if ((X->p[0] & 1) == 0)
//		return JHD_UNEXPECTED;
//
//	for (i = 0; small_prime[i] > 0; i++) {
//		if (jhd_tls_mpi_cmp_int(X, small_prime[i]) <= 0){
//			return (1);
//		}
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_mod_int(&r, X, small_prime[i]));
//		if (r == 0)
//			return JHD_UNEXPECTED;
//	}
//	cleanup: return (ret);
//}
//
///*
// * Miller-Rabin pseudo-primality test  (HAC 4.24)
// */
//static int mpi_miller_rabin(const jhd_tls_mpi *X) {
//	int ret, count;
//	size_t i, j, k, n, s;
//	jhd_tls_mpi W, R, T, A, RR;
//
//	jhd_tls_mpi_init(&W);
//	jhd_tls_mpi_init(&R);
//	jhd_tls_mpi_init(&T);
//	jhd_tls_mpi_init(&A);
//	jhd_tls_mpi_init(&RR);
//
//	/*
//	 * W = |X| - 1
//	 * R = W >> lsb( W )
//	 */
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_sub_int(&W, X, 1));
//	s = jhd_tls_mpi_lsb(&W);
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&R, &W));
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&R, s));
//
//	i = jhd_tls_mpi_bitlen(X);
//	/*
//	 * HAC, table 4.4
//	 */
//	n = ((i >= 1300) ? 2 : (i >= 850) ? 3 : (i >= 650) ? 4 : (i >= 350) ? 8 : (i >= 250) ? 12 : (i >= 150) ? 18 : 27);
//
//	for (i = 0; i < n; i++) {
//		/*
//		 * pick a random A, 1 < A < |X| - 1
//		 */
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_fill_random( &A, X->n * ciL));
//
//		if (jhd_tls_mpi_cmp_mpi(&A, &W) >= 0) {
//			j = jhd_tls_mpi_bitlen(&A) - jhd_tls_mpi_bitlen(&W);
//			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&A, j + 1));
//		}
//		A.p[0] |= 3;
//
//		count = 0;
//		do {
//			JHD_TLS_MPI_CHK(jhd_tls_mpi_fill_random( &A, X->n * ciL));
//
//			j = jhd_tls_mpi_bitlen(&A);
//			k = jhd_tls_mpi_bitlen(&W);
//			if (j > k) {
//				JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&A, j - k));
//			}
//
//			if (count++ > 30) {
//				return JHD_UNEXPECTED;
//			}
//
//		} while (jhd_tls_mpi_cmp_mpi(&A, &W) >= 0 || jhd_tls_mpi_cmp_int(&A, 1) <= 0);
//
//		/*
//		 * A = A^R mod |X|
//		 */
//		JHD_TLS_MPI_CHK( jhd_tls_mpi_lset(&RR, 1 ) );
//		JHD_TLS_MPI_CHK( jhd_tls_mpi_shift_l( &RR, X->n * 2 * (sizeof(jhd_tls_mpi_uint)<< 3) ) );
//		JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi(&RR, &RR, X ) );
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_exp_mod(&A, &A, &R, X, &RR));
//
//		if (jhd_tls_mpi_cmp_mpi(&A, &W) == 0 || jhd_tls_mpi_cmp_int(&A, 1) == 0)
//			continue;
//
//		j = 1;
//		while (j < s && jhd_tls_mpi_cmp_mpi(&A, &W) != 0) {
//			/*
//			 * A = A * A mod |X|
//			 */
//			JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&T, &A, &A));
//			JHD_TLS_MPI_CHK(jhd_tls_mpi_mod_mpi(&A, &T, X));
//
//			if (jhd_tls_mpi_cmp_int(&A, 1) == 0)
//				break;
//
//			j++;
//		}
//
//		/*
//		 * not prime if A != |X| - 1 or A == 1
//		 */
//		if (jhd_tls_mpi_cmp_mpi(&A, &W) != 0 || jhd_tls_mpi_cmp_int(&A, 1) == 0) {
//			ret = JHD_UNEXPECTED;
//			break;
//		}
//	}
//
//	cleanup: jhd_tls_mpi_free(&W);
//	jhd_tls_mpi_free(&R);
//	jhd_tls_mpi_free(&T);
//	jhd_tls_mpi_free(&A);
//	jhd_tls_mpi_free(&RR);
//
//	return (ret);
//}
//
///*
// * Pseudo-primality test: small factors, then Miller-Rabin
// */
//int jhd_tls_mpi_is_prime(const jhd_tls_mpi *X) {
//	int ret;
//	jhd_tls_mpi XX;
//
//	XX.s = 1;
//	XX.n = X->n;
//	XX.p = X->p;
//
//	if (jhd_tls_mpi_cmp_int(&XX, 0) == 0 || jhd_tls_mpi_cmp_int(&XX, 1) == 0)
//		return JHD_UNEXPECTED;
//
//	if (jhd_tls_mpi_cmp_int(&XX, 2) == 0){
//		return JHD_OK;
//	}
//
//	if ((ret = mpi_check_small_factors(&XX)) != 0) {
//		if (ret == 1){
//			return JHD_OK;
//		}
//		return ret;
//	}
//
//	return (mpi_miller_rabin(&XX));
//}
//
///*
// * Prime number generation
// *
// * If dh_flag is 0 and nbits is at least 1024, then the procedure
// * follows the RSA probably-prime generation method of FIPS 186-4.
// * NB. FIPS 186-4 only allows the specific bit lengths of 1024 and 1536.
// */
//int jhd_tls_mpi_gen_prime(jhd_tls_mpi *X, size_t nbits, int dh_flag) {
//#ifdef JHD_TLS_HAVE_INT64
//// ceil(2^63.5)
//#define CEIL_MAXUINT_DIV_SQRT2 0xb504f333f9de6485ULL
//#else
//// ceil(2^31.5)
//#define CEIL_MAXUINT_DIV_SQRT2 0xb504f334U
//#endif
//	int ret = JHD_UNEXPECTED;
//	size_t k, n;
//	jhd_tls_mpi_uint r;
//	jhd_tls_mpi Y;
//
//	JHD_TLS_COMMON_CHECK_RETURN_ERROR(nbits < 3 || nbits > JHD_TLS_MPI_MAX_BITS)
//	jhd_tls_mpi_init(&Y);
//	n = BITS_TO_LIMBS(nbits);
//	for (;;) {
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_fill_random( X, n * ciL));
//		/* make sure generated number is at least (nbits-1)+0.5 bits (FIPS 186-4 §B.3.3 steps 4.4, 5.5) */
//		if (X->p[n - 1] < CEIL_MAXUINT_DIV_SQRT2)
//			continue;
//		k = n * biL;
//		if (k > nbits){
//			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(X, k - nbits));
//		}
//		X->p[0] |= 1;
//		if (dh_flag == 0) {
//			ret = jhd_tls_mpi_is_prime(X);
//			JHD_TLS_COMMON_CHECK_GOTO_CLEANUP(ret != JHD_UNEXPECTED)
//		} else {
//			/*
//			 * An necessary condition for Y and X = 2Y + 1 to be prime
//			 * is X = 2 mod 3 (which is equivalent to Y = 2 mod 3).
//			 * Make sure it is satisfied, while keeping X = 3 mod 4
//			 */
//			X->p[0] |= 2;
//			JHD_TLS_MPI_CHK(jhd_tls_mpi_mod_int(&r, X, 3));
//			if (r == 0){
//				JHD_TLS_MPI_CHK(jhd_tls_mpi_add_int(X, X, 8));
//			}else if (r == 1){
//				JHD_TLS_MPI_CHK(jhd_tls_mpi_add_int(X, X, 4));
//			}
//			/* Set Y = (X-1) / 2, which is X / 2 because X is odd */
//			JHD_TLS_MPI_CHK(jhd_tls_mpi_copy(&Y, X));
//			JHD_TLS_MPI_CHK(jhd_tls_mpi_shift_r(&Y, 1));
//			for(;;) {
//				/*
//				 * First, check small factors for X and Y
//				 * before doing Miller-Rabin on any of them
//				 */
//				JHD_TLS_COMMON_CHECK_GOTO_CLEANUP(((ret = mpi_check_small_factors(X)) == 0) && ((ret = mpi_check_small_factors(&Y)) == 0) &&
//								((ret = mpi_miller_rabin(X)) == 0) && ((ret = mpi_miller_rabin(&Y)) == 0))
//				if (ret != JHD_UNEXPECTED){
//					goto cleanup;
//				}
//
//				/*
//				 * Next candidates. We want to preserve Y = (X-1) / 2 and
//				 * Y = 1 mod 2 and Y = 2 mod 3 (eq X = 3 mod 4 and X = 2 mod 3)
//				 * so up Y by 6 and X by 12.
//				 */
//				JHD_TLS_MPI_CHK(jhd_tls_mpi_add_int(X, X, 12));
//				JHD_TLS_MPI_CHK(jhd_tls_mpi_add_int(&Y, &Y, 6));
//			}
//		}
//	}
//
//	cleanup:
//
//	jhd_tls_mpi_free(&Y);
//
//	return (ret);
//}

#endif /* JHD_TLS_GENPRIME */

static int mpi_get_digit( jhd_tls_mpi_uint *d, int radix, char c )
{
    *d = 255;
    if( c >= 0x30 && c <= 0x39 ) *d = c - 0x30;
    if( c >= 0x41 && c <= 0x46 ) *d = c - 0x37;
    if( c >= 0x61 && c <= 0x66 ) *d = c - 0x57;
    if( *d >= (jhd_tls_mpi_uint) radix )
        return JHD_ERROR;
    return JHD_OK;
}
/*
 * Import from an ASCII string
 */

int jhd_tls_mpi_read_string( jhd_tls_mpi *X, int radix, const char *s ){
    int ret;
    size_t i, j, slen, n;
    jhd_tls_mpi_uint d;
    jhd_tls_mpi T;

    log_assert(radix>=2 && radix <= 16/*,"unsupported"*/);
    jhd_tls_mpi_init( &T );

    slen = strlen( s );

    if( radix == 16 )
    {
    	log_assert(slen <= (MPI_SIZE_T_MAX >> 2)/*,"unsupported"*/);
        n = BITS_TO_LIMBS( slen << 2 );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_grow( X, n ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_lset( X, 0 ) );

        for( i = slen, j = 0; i > 0; i--, j++ )
        {
            if( i == 1 && s[i - 1] == '-' )
            {
                X->s = -1;
                break;
            }

            JHD_TLS_MPI_CHK( mpi_get_digit( &d, radix, s[i - 1] ) );
            X->p[j / ( 2 * ciL )] |= d << ( ( j % ( 2 * ciL ) ) << 2 );
        }
    }
    else
    {
        JHD_TLS_MPI_CHK( jhd_tls_mpi_lset( X, 0 ) );
        if(s[0]=='-'){
        	X->s = -1;
        	i = 1;
        }else{
        	i = 0;
        }
        for(;i < slen; i++ )
        {
            JHD_TLS_MPI_CHK( mpi_get_digit( &d, radix, s[i] ) );
            JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_int( &T, X, radix ) );

            if( X->s == 1 )
            {
                JHD_TLS_MPI_CHK( jhd_tls_mpi_add_int( X, &T, d ) );
            }
            else
            {
                JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( X, &T, d ) );
            }
        }
    }

cleanup:

    jhd_tls_mpi_free( &T );

    return( ret );
}
/*
 * Helper to write the digits high-order first
 */
static int mpi_write_hlp( jhd_tls_mpi *X, int radix, char *begin,char *end)
{
	int ret= JHD_OK;
    jhd_tls_mpi_uint r;
    size_t len;

    char *e=end;
    *e=0;
    --e;
    len=1;
    do{
    	  JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_int( &r, X, radix ) );
    	  JHD_TLS_MPI_CHK( jhd_tls_mpi_div_int( X, NULL, X, radix ) );
    	  if(e < begin){
    		  return JHD_ERROR;
    	  }
    	  *e=(r<10?((char)( r + 0x30 )):((char)( r + 0x37 )));
    	  --e;
    	  ++len;
    }while(jhd_tls_mpi_cmp_int( X, 0 ) != 0);
    ++e;
    if(begin !=e){
    	memmove(begin,e,len);
    }
cleanup:
    return( ret );
}
int jhd_tls_mpi_write_string(const jhd_tls_mpi *X,int radix,char *buf,size_t buflen){
    int ret = 0;
    char *p,*end;
    jhd_tls_mpi T;
    size_t len;
    int c;
    size_t i, j, k;
    log_assert(radix>=2 && radix <= 16/*,"unsupported"*/);
    log_assert(buflen >= 8/*,"invalid buflen (?< 8)"*/);
    jhd_tls_mpi_init( &T );

    len = 0;
    if( radix == 16 )
    {
    	if(len >= buflen){
    		ret = JHD_ERROR;
    		goto cleanup;
    	}
    	p= buf;
		if( X->s != 1 ){
			len ++;
			*(p++) = '-';
		}
        for( i = X->n, k = 0; i > 0; i-- )
        {
            for( j = ciL; j > 0; j-- )
            {
                c = ( X->p[i - 1] >> ( ( j - 1 ) << 3) ) & 0xFF;

                if( c == 0 && k == 0 && ( i + j ) != 2 )
                    continue;

        		len +=2;
				if(len >= buflen){
					ret = JHD_ERROR;
					goto cleanup;
				}
                *(p++) = "0123456789ABCDEF" [c / 16];
                *(p++) = "0123456789ABCDEF" [c % 16];
                k = 1;
            }
        }
		len ++;
		if(len >= buflen){
			ret = JHD_ERROR;
			goto cleanup;
		}
        *p=0;
        ret = JHD_OK;
    }
    else
    {
        JHD_TLS_MPI_CHK( jhd_tls_mpi_copy( &T, X ) );
        p = buf;
        end = buf+buflen -1;
        if( T.s !=1 ){
            T.s = 1;
            if(jhd_tls_mpi_cmp_int(&T,0)==0){
              *(p++) ='0';
              *p=0;
              ret = JHD_OK;
              goto cleanup;
           }else{
        	   *(p++) ='-';
           }
        }else{
 			if(jhd_tls_mpi_cmp_int(&T,0)==0){
				if(jhd_tls_mpi_cmp_int(&T,0)==0){
				  *(p++) ='0';
				  *p=0;
				  ret = JHD_OK;
				  goto cleanup;
			   }
			}
        }
        ret = mpi_write_hlp( &T, radix, p,end);
    }
cleanup:

    jhd_tls_mpi_free( &T );

    return( ret );
}


#if defined(JHD_TLS_SELF_TEST)
//
//#define GCD_PAIR_COUNT  3
//
//static const int gcd_pairs[GCD_PAIR_COUNT][3] = { { 693, 609, 21 }, { 1764, 868, 28 }, { 768454923, 542167814, 1 } };
//
///*
// * Checkup routine
// */
//int jhd_tls_mpi_self_test(int verbose) {
//	int ret, i;
//	jhd_tls_mpi A, E, N, X, Y, U, V;
//
//	jhd_tls_mpi_init(&A);
//	jhd_tls_mpi_init(&E);
//	jhd_tls_mpi_init(&N);
//	jhd_tls_mpi_init(&X);
//	jhd_tls_mpi_init(&Y);
//	jhd_tls_mpi_init(&U);
//	jhd_tls_mpi_init(&V);
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_string(&A, 16, "EFE021C2645FD1DC586E69184AF4A31E"
//			"D5F53E93B5F123FA41680867BA110131"
//			"944FE7952E2517337780CB0DB80E61AA"
//			"E7C8DDC6C5C6AADEB34EB38A2F40D5E6"));
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_string(&E, 16, "B2E7EFD37075B9F03FF989C7C5051C20"
//			"34D2A323810251127E7BF8625A4F49A5"
//			"F3E27F4DA8BD59C47D6DAABA4C8127BD"
//			"5B5C25763222FEFCCFC38B832366C29E"));
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_string(&N, 16, "0066A198186C18C10B2F5ED9B522752A"
//			"9830B69916E535C8F047518A889A43A5"
//			"94B6BED27A168D31D4A52F88925AA8F5"));
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_mul_mpi(&X, &A, &N));
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_string(&U, 16, "602AB7ECA597A3D6B56FF9829A5E8B85"
//			"9E857EA95A03512E2BAE7391688D264A"
//			"A5663B0341DB9CCFD2C4C5F421FEC814"
//			"8001B72E848A38CAE1C65F78E56ABDEF"
//			"E12D3C039B8A02D6BE593F0BBBDA56F1"
//			"ECF677152EF804370C1A305CAF3B5BF1"
//			"30879B56C61DE584A0F53A2447A51E"));
//
//	if (verbose != 0)
//		jhd_tls_printf("  MPI test #1 (mul_mpi): ");
//
//	if (jhd_tls_mpi_cmp_mpi(&X, &U) != 0) {
//		if (verbose != 0)
//			jhd_tls_printf("failed\n");
//
//		ret = 1;
//		goto cleanup;
//	}
//
//	if (verbose != 0)
//		jhd_tls_printf("passed\n");
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_div_mpi(&X, &Y, &A, &N));
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_string(&U, 16, "256567336059E52CAE22925474705F39A94"));
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_string(&V, 16, "6613F26162223DF488E9CD48CC132C7A"
//			"0AC93C701B001B092E4E5B9F73BCD27B"
//			"9EE50D0657C77F374E903CDFA4C642"));
//
//	if (verbose != 0)
//		jhd_tls_printf("  MPI test #2 (div_mpi): ");
//
//	if (jhd_tls_mpi_cmp_mpi(&X, &U) != 0 || jhd_tls_mpi_cmp_mpi(&Y, &V) != 0) {
//		if (verbose != 0)
//			jhd_tls_printf("failed\n");
//
//		ret = 1;
//		goto cleanup;
//	}
//
//	if (verbose != 0)
//		jhd_tls_printf("passed\n");
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_exp_mod( &X, &A, &E, &N, NULL ));
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_string(&U, 16, "36E139AEA55215609D2816998ED020BB"
//			"BD96C37890F65171D948E9BC7CBAA4D9"
//			"325D24D6A3C12710F10A09FA08AB87"));
//
//	if (verbose != 0)
//		jhd_tls_printf("  MPI test #3 (exp_mod): ");
//
//	if (jhd_tls_mpi_cmp_mpi(&X, &U) != 0) {
//		if (verbose != 0)
//			jhd_tls_printf("failed\n");
//
//		ret = 1;
//		goto cleanup;
//	}
//
//	if (verbose != 0)
//		jhd_tls_printf("passed\n");
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_inv_mod(&X, &A, &N));
//
//	JHD_TLS_MPI_CHK(jhd_tls_mpi_read_string(&U, 16, "003A0AAEDD7E784FC07D8F9EC6E3BFD5"
//			"C3DBA76456363A10869622EAC2DD84EC"
//			"C5B8A74DAC4D09E03B5E0BE779F2DF61"));
//
//	if (verbose != 0)
//		jhd_tls_printf("  MPI test #4 (inv_mod): ");
//
//	if (jhd_tls_mpi_cmp_mpi(&X, &U) != 0) {
//		if (verbose != 0)
//			jhd_tls_printf("failed\n");
//
//		ret = 1;
//		goto cleanup;
//	}
//
//	if (verbose != 0)
//		jhd_tls_printf("passed\n");
//
//	if (verbose != 0)
//		jhd_tls_printf("  MPI test #5 (simple gcd): ");
//
//	for (i = 0; i < GCD_PAIR_COUNT; i++) {
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&X, gcd_pairs[i][0]));
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_lset(&Y, gcd_pairs[i][1]));
//
//		JHD_TLS_MPI_CHK(jhd_tls_mpi_gcd(&A, &X, &Y));
//
//		if (jhd_tls_mpi_cmp_int(&A, gcd_pairs[i][2]) != 0) {
//			if (verbose != 0)
//				jhd_tls_printf("failed at %d\n", i);
//
//			ret = 1;
//			goto cleanup;
//		}
//	}
//
//	if (verbose != 0)
//		jhd_tls_printf("passed\n");
//
//	cleanup:
//
//	if (ret != 0 && verbose != 0)
//		jhd_tls_printf("Unexpected error, return code = %08X\n", ret);
//
//	jhd_tls_mpi_free(&A);
//	jhd_tls_mpi_free(&E);
//	jhd_tls_mpi_free(&N);
//	jhd_tls_mpi_free(&X);
//	jhd_tls_mpi_free(&Y);
//	jhd_tls_mpi_free(&U);
//	jhd_tls_mpi_free(&V);
//
//	if (verbose != 0)
//		jhd_tls_printf("\n");
//
//	return (ret);
//}

#endif /* JHD_TLS_SELF_TEST */

