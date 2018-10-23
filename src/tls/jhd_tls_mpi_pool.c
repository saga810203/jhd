#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_mpi_pool.h>

static jhd_tls_mpi_uint *jhd_tls_mpi_pool_1 = NULL;
static jhd_tls_mpi_uint *jhd_tls_mpi_pool_32 = NULL;
static jhd_tls_mpi_uint *jhd_tls_mpi_pool_128 = NULL;
static jhd_tls_mpi_uint *jhd_tls_mpi_pool_256 = NULL;
static jhd_tls_mpi_uint *jhd_tls_mpi_pool_1024 = NULL;
static jhd_tls_mpi_uint *jhd_tls_mpi_pool_2048 = NULL;
static jhd_tls_mpi_uint *jhd_tls_mpi_pool_4096 = NULL;
static jhd_tls_mpi_uint *jhd_tls_mpi_pool_8192 = NULL;
static jhd_tls_mpi_uint *jhd_tls_mpi_pool_10000 = NULL;

#define JHD_TLS_MPI_POOL_FREE(ptr,i) *(ptr) = (jhd_tls_mpi_uint)jhd_tls_mpi_pool_ ## i;jhd_tls_mpi_pool_ ## i  = (jhd_tls_mpi_uint*)(ptr); break;
#define JHD_TLS_MPI_POOL_MALLOC(i) rsize = i;\
	p =  jhd_tls_mpi_pool_ ## i;\
	if(NULL == p){\
		p = malloc( i * sizeof(jhd_tls_mpi_uint));\
		if(NULL!=p){mpi_memory_total_malloc += (sizeof(jhd_tls_mpi_uint)*rsize);} \
	}else{\
		jhd_tls_mpi_pool_ ## i = (jhd_tls_mpi_uint*)(*p);\
	}

static size_t mpi_memory_total_malloc;

static void mpi_pool_free(jhd_tls_mpi_uint* ptr, uint16_t size) {
	switch (size) {
		case 1:
			JHD_TLS_MPI_POOL_FREE(ptr,1)
		case 32:
			JHD_TLS_MPI_POOL_FREE(ptr,32)
		case 128:
			JHD_TLS_MPI_POOL_FREE(ptr,128)
		case 256:
			JHD_TLS_MPI_POOL_FREE(ptr,256)
		case 1024:
			JHD_TLS_MPI_POOL_FREE(ptr,1024)

		case 2048:
			JHD_TLS_MPI_POOL_FREE(ptr,2048)

		case 4096:
			JHD_TLS_MPI_POOL_FREE(ptr,4096)

		case 8192:
			JHD_TLS_MPI_POOL_FREE(ptr,8192)

		default:
			JHD_TLS_MPI_POOL_FREE(ptr,10000)

	}
}

int jhd_tls_mpi_grow(jhd_tls_mpi *X, uint16_t size) {
	jhd_tls_mpi_uint *p;
	uint16_t rsize;
#ifdef JHD_LOG_LEVEL_INFO
	uint16_t  i;
#endif
	log_assert(size <= 10000/*, "invalid jhd_tls_mpi->n"*/);

	if(X->n >= size ){
		return JHD_OK;
	}
	if(X->tn >=size){
#ifdef JHD_LOG_LEVEL_INFO
		for(i =X->n;i<size;++i){
			log_assert(X->p[i]==0/*,"bug???????????????"*/);
		}
#endif


		X->n  = size;
		return JHD_OK;
	}
	if (size > 1) {
		if (size > 32) {
			if (size > 128) {
				if (size > 256) {
					if (size > 1024) {
						if (size > 2048) {
							if (size > 4096) {
								if (size > 8192) {
									JHD_TLS_MPI_POOL_MALLOC(10000)
								} else {
									JHD_TLS_MPI_POOL_MALLOC(8192)
								}
							} else {
								JHD_TLS_MPI_POOL_MALLOC(4096)
							}
						} else {
							JHD_TLS_MPI_POOL_MALLOC(2048)
						}
					} else {
						JHD_TLS_MPI_POOL_MALLOC(1024)
					}
				} else {
					JHD_TLS_MPI_POOL_MALLOC(256)
				}
			} else {
				JHD_TLS_MPI_POOL_MALLOC(128)
			}
		} else {
			JHD_TLS_MPI_POOL_MALLOC(32)
		}
	} else {
		JHD_TLS_MPI_POOL_MALLOC(1)
	}

	if (NULL == p) {
		return JHD_ERROR;
	} else {
		memset(p, 0, rsize * sizeof(jhd_tls_mpi_uint));
		if (X->n != 0) {
			memcpy(p, X->p, X->n * sizeof(jhd_tls_mpi_uint));
		}
		if (X->tn != 0) {
			mpi_pool_free(X->p, X->tn);
		}
		X->p = p;
		X->n  = size;
		X->tn = rsize;
		return JHD_OK;
	}
}
void jhd_tls_mpi_free(jhd_tls_mpi *X) {
	if (X->tn != 0) {
		mpi_pool_free(X->p, X->tn);
	}
	X->p = NULL;
	X->tn = 0;
	X->n = 0;
}
size_t jhd_tls_mpi_pool_size() {
	return mpi_memory_total_malloc;
}


/*
 * Resize down as much as possible,
 * while keeping at least the specified number of limbs
 */
//TODO: use??????????????
int jhd_tls_mpi_shrink(jhd_tls_mpi *X, size_t nblimbs) {
	jhd_tls_mpi_uint *p;
	uint16_t rsize;
    uint16_t size;
    if( X->n == nblimbs ){
        return JHD_OK;
    }else if(X->n<nblimbs){
    	return jhd_tls_mpi_grow(X,nblimbs);
    }
    for( size = X->n - 1; size > 0; size-- )
        if( X->p[size] != 0 )
            break;
    ++size;
    if( size < nblimbs )
        size = nblimbs;
    if (size > 1) {
		if (size > 32) {
			if (size > 128) {
				if (size > 256) {
					if (size > 1024) {
						if (size > 2048) {
							if (size > 4096) {
								if (size > 8192) {
									rsize=(10000);
								} else {
									rsize=(8192);
								}
							} else {
								rsize=(4096);
							}
						} else {
							rsize=(2048);
						}
					} else {
						rsize=(1024);
					}
				} else {
					rsize=(256);
				}
			} else {
				rsize=(128);
			}
		} else {
			rsize=(32);
		}
	} else {
		rsize = 1;
	}
	if(rsize ==  X->tn){
		X->n  = size;
		return JHD_OK;
	}
	switch (rsize) {
		case 1:
			JHD_TLS_MPI_POOL_MALLOC(1)
			break;
		case 32:
			JHD_TLS_MPI_POOL_MALLOC(32)
			break;
		case 128:
			JHD_TLS_MPI_POOL_MALLOC(128)
			break;
		case 256:
			JHD_TLS_MPI_POOL_MALLOC(256)
			break;
		case 1024:
			JHD_TLS_MPI_POOL_MALLOC(1024)
			break;

		case 2048:
			JHD_TLS_MPI_POOL_MALLOC(2048)
			break;

		case 4096:
			JHD_TLS_MPI_POOL_MALLOC(4096)
			break;
		case 8192:
			JHD_TLS_MPI_POOL_MALLOC(8192)
			break;
		default:
			JHD_TLS_MPI_POOL_MALLOC(10000)
			break;
	}
    if(NULL == p){
    	return JHD_ERROR;
    }
    memset(p,0,sizeof(jhd_tls_mpi_uint)* size);
    memcpy(p,X->p,size * sizeof(jhd_tls_mpi_uint));
    mpi_pool_free(X->p,X->tn);
    X->tn = rsize;
    X->p = p;
    X->n = size;
    return JHD_OK;
}

