#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_md_internal.h>
#include <tls/jhd_tls_md5.h>
#include <tls/jhd_tls_ripemd160.h>
#include <tls/jhd_tls_sha1.h>
#include <tls/jhd_tls_sha256.h>
#include <tls/jhd_tls_sha512.h>
#include <tls/jhd_tls_platform.h>


const jhd_tls_md_info_t jhd_tls_md5_info = {
    "MD5",
	sizeof( jhd_tls_md5_context ),
    16,
    64,
    JHD_TLS_SSL_HASH_MD5,
    jhd_tls_md5_starts_ret,
    jhd_tls_md5_update_ret,
    jhd_tls_md5_finish_ret,
    jhd_tls_md5_ret,
    jhd_tls_internal_md5_process,
};
/*static void *ripemd160_ctx_alloc( void )
{
    void *ctx = jhd_tls_malloc(sizeof( jhd_tls_ripemd160_context ) );

    if( ctx != NULL )
        jhd_tls_ripemd160_init( (jhd_tls_ripemd160_context *) ctx );

    return( ctx );
}


const jhd_tls_md_info_t jhd_tls_ripemd160_info = {
    "RIPEMD160",
    20,
    64,
    JHD_TLS_SSL_HASH_MD5,
    jhd_tls_ripemd160_starts_ret,
    jhd_tls_ripemd160_update_ret,
    jhd_tls_ripemd160_finish_ret,
    jhd_tls_ripemd160_ret,
    ripemd160_ctx_alloc,
    md_free,
    jhd_tls_internal_ripemd160_process,
};*/

const jhd_tls_md_info_t jhd_tls_sha1_info = {
    "SHA1",
	sizeof( jhd_tls_sha1_context ),
    20,
    64,
    JHD_TLS_SSL_HASH_SHA1,
    jhd_tls_sha1_starts_ret,
    jhd_tls_sha1_update_ret,
    jhd_tls_sha1_finish_ret,
    jhd_tls_sha1_ret,
    jhd_tls_internal_sha1_process,
};

const jhd_tls_md_info_t jhd_tls_sha224_info = {
    "SHA224",
	sizeof( jhd_tls_sha256_context ),
    28,
    64,
    JHD_TLS_SSL_HASH_SHA224,
    jhd_tls_sha256_starts_ret_with_224,
    jhd_tls_sha256_update_ret,
    jhd_tls_sha256_finish_ret,
    jhd_tls_sha256_ret_with_224,
    jhd_tls_internal_sha256_process,
};
const jhd_tls_md_info_t jhd_tls_sha256_info = {
    "SHA256",
	sizeof( jhd_tls_sha256_context ),
    32,
    64,
    JHD_TLS_SSL_HASH_SHA256,
    jhd_tls_sha256_starts_ret_with_256,
    jhd_tls_sha256_update_ret,
    jhd_tls_sha256_finish_ret,
    jhd_tls_sha256_ret_with_256,
    jhd_tls_internal_sha256_process,
};

const jhd_tls_md_info_t jhd_tls_sha384_info = {
    "SHA384",
	sizeof( jhd_tls_sha512_context ),
    48,
    128,
    JHD_TLS_SSL_HASH_SHA384,
    jhd_tls_sha512_starts_ret_with_384,
    jhd_tls_sha512_update_ret,
    jhd_tls_sha512_finish_ret,
    jhd_tls_sha512_ret_with_384,
    jhd_tls_internal_sha512_process,
};
const jhd_tls_md_info_t jhd_tls_sha512_info = {
    "SHA512",
	sizeof( jhd_tls_sha512_context ),
    64,
    128,
    JHD_TLS_SSL_HASH_SHA512,
    jhd_tls_sha512_starts_ret,
    jhd_tls_sha512_update_ret,
    jhd_tls_sha512_finish_ret,
    jhd_tls_sha512_ret,
    jhd_tls_internal_sha512_process,
};
