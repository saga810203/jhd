#ifndef JHD_TLS_MPI_POOL_H_
#define JHD_TLS_MPI_POOL_H_

typedef uint64_t jhd_tls_mpi_uint;
typedef struct {
	int s; /*!<  integer sign      */
	uint16_t n; /*!<  total # of limbs  */
	uint16_t tn;
	jhd_tls_mpi_uint *p; /*!<  pointer to limbs  */
} jhd_tls_mpi;

int jhd_tls_mpi_grow(jhd_tls_mpi *X,uint16_t size);
/**
 * \brief          Resize down, keeping at least the specified number of limbs
 *
 *                 If \c X is smaller than \c nblimbs, it is resized up
 *                 instead.
 *
 * \param X        MPI to shrink
 * \param nblimbs  The minimum number of limbs to keep
 *
 * \return         0 if successful,
 *                 JHD_TLS_ERR_MPI_ALLOC_FAILED if memory allocation failed
 *                 (this can only happen when resizing up).
 */
int jhd_tls_mpi_shrink(jhd_tls_mpi *X, size_t nblimbs);
void jhd_tls_mpi_free(jhd_tls_mpi *X);
size_t jhd_tls_mpi_pool_size();


#endif /* INCLUDE_TLS_JHD_TLS_BIGNUM_POOL_H_ */
