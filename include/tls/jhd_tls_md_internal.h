#ifndef JHD_TLS_MD_WRAP_H
#define JHD_TLS_MD_WRAP_H

#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_md.h>



struct jhd_tls_md_info_t
{
    /** Name of the message digest */
    const char * name;
    size_t  ctx_size;
    /** Output length of the digest function in bytes */
    uint8_t size;

    /** Block length of the digest function in bytes */
    uint8_t block_size;

    unsigned char hash_flag;

    /** Digest initialisation function */
    void (*starts_func)( void *ctx );

    /** Digest update function */
    void (*update_func)( void *ctx, const unsigned char *input, size_t ilen );

    /** Digest finalisation function */
    void (*finish_func)( void *ctx, unsigned char *output );

    /** Generic digest function */
    void (*digest_func)( const unsigned char *input, size_t ilen,unsigned char *output );
    /** Internal use only */
    void (*process_func)( void *ctx, const unsigned char *input );
};


extern const jhd_tls_md_info_t jhd_tls_md5_info;

extern const jhd_tls_md_info_t jhd_tls_ripemd160_info;

extern const jhd_tls_md_info_t jhd_tls_sha1_info;

extern const jhd_tls_md_info_t jhd_tls_sha224_info;
extern const jhd_tls_md_info_t jhd_tls_sha256_info;

extern const jhd_tls_md_info_t jhd_tls_sha384_info;
extern const jhd_tls_md_info_t jhd_tls_sha512_info;
#endif /* JHD_TLS_MD_WRAP_H */
