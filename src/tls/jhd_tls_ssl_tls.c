/*
 *  SSLv3/TLSv1 shared functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The SSL 3.0 specification was drafted by Netscape in 1996,
 *  and became an IETF standard in 1999.
 *
 *  http://wp.netscape.com/eng/ssl3/
 *  http://www.ietf.org/rfc/rfc2246.txt
 *  http://www.ietf.org/rfc/rfc4346.txt
 */

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_SSL_TLS_C)

#if defined(JHD_TLS_PLATFORM_C)
#include <tls/jhd_tls_platform.h>
#else
#include <stdlib.h>
#define jhd_tls_calloc    calloc
#define jhd_tls_free      free
#endif

#include <tls/jhd_tls_ssl.h>
#include <tls/jhd_tls_ssl_internal.h>

#include <string.h>

#if defined(JHD_TLS_X509_CRT_PARSE_C)
#include <tls/jhd_tls_oid.h>
#endif

/* Length of the "epoch" field in the record header */
static inline size_t ssl_ep_len( const jhd_tls_ssl_context *ssl )
{
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
        return( 2 );
#else
    ((void) ssl);
#endif
    return( 0 );
}

/*
 * Start a timer.
 * Passing millisecs = 0 cancels a running timer.
 */
static void ssl_set_timer( jhd_tls_ssl_context *ssl, uint32_t millisecs )
{
    if( ssl->f_set_timer == NULL )
        return;

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "set_timer to %d ms", (int) millisecs ) );
    ssl->f_set_timer( ssl->p_timer, millisecs / 4, millisecs );
}

/*
 * Return -1 is timer is expired, 0 if it isn't.
 */
static int ssl_check_timer( jhd_tls_ssl_context *ssl )
{
    if( ssl->f_get_timer == NULL )
        return( 0 );

    if( ssl->f_get_timer( ssl->p_timer ) == 2 )
    {
        JHD_TLS_SSL_DEBUG_MSG( 3, ( "timer expired" ) );
        return( -1 );
    }

    return( 0 );
}

#if defined(JHD_TLS_SSL_PROTO_DTLS)
/*
 * Double the retransmit timeout value, within the allowed range,
 * returning -1 if the maximum value has already been reached.
 */
static int ssl_double_retransmit_timeout( jhd_tls_ssl_context *ssl )
{
    uint32_t new_timeout;

    if( ssl->handshake->retransmit_timeout >= ssl->conf->hs_timeout_max )
        return( -1 );

    new_timeout = 2 * ssl->handshake->retransmit_timeout;

    /* Avoid arithmetic overflow and range overflow */
    if( new_timeout < ssl->handshake->retransmit_timeout ||
        new_timeout > ssl->conf->hs_timeout_max )
    {
        new_timeout = ssl->conf->hs_timeout_max;
    }

    ssl->handshake->retransmit_timeout = new_timeout;
    JHD_TLS_SSL_DEBUG_MSG( 3, ( "update timeout value to %d millisecs",
                        ssl->handshake->retransmit_timeout ) );

    return( 0 );
}

static void ssl_reset_retransmit_timeout( jhd_tls_ssl_context *ssl )
{
    ssl->handshake->retransmit_timeout = ssl->conf->hs_timeout_min;
    JHD_TLS_SSL_DEBUG_MSG( 3, ( "update timeout value to %d millisecs",
                        ssl->handshake->retransmit_timeout ) );
}
#endif /* JHD_TLS_SSL_PROTO_DTLS */

#if defined(JHD_TLS_SSL_MAX_FRAGMENT_LENGTH)
/*
 * Convert max_fragment_length codes to length.
 * RFC 6066 says:
 *    enum{
 *        2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
 *    } MaxFragmentLength;
 * and we add 0 -> extension unused
 */
static unsigned int mfl_code_to_length[JHD_TLS_SSL_MAX_FRAG_LEN_INVALID] =
{
    JHD_TLS_SSL_MAX_CONTENT_LEN,    /* JHD_TLS_SSL_MAX_FRAG_LEN_NONE */
    512,                    /* JHD_TLS_SSL_MAX_FRAG_LEN_512  */
    1024,                   /* JHD_TLS_SSL_MAX_FRAG_LEN_1024 */
    2048,                   /* JHD_TLS_SSL_MAX_FRAG_LEN_2048 */
    4096,                   /* JHD_TLS_SSL_MAX_FRAG_LEN_4096 */
};
#endif /* JHD_TLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(JHD_TLS_SSL_CLI_C)
static int ssl_session_copy( jhd_tls_ssl_session *dst, const jhd_tls_ssl_session *src )
{
    jhd_tls_ssl_session_free( dst );
    memcpy( dst, src, sizeof( jhd_tls_ssl_session ) );

#if defined(JHD_TLS_X509_CRT_PARSE_C)
    if( src->peer_cert != NULL )
    {
        int ret;

        dst->peer_cert = jhd_tls_calloc( 1, sizeof(jhd_tls_x509_crt) );
        if( dst->peer_cert == NULL )
            return( JHD_TLS_ERR_SSL_ALLOC_FAILED );

        jhd_tls_x509_crt_init( dst->peer_cert );

        if( ( ret = jhd_tls_x509_crt_parse_der( dst->peer_cert, src->peer_cert->raw.p,
                                        src->peer_cert->raw.len ) ) != 0 )
        {
            jhd_tls_free( dst->peer_cert );
            dst->peer_cert = NULL;
            return( ret );
        }
    }
#endif /* JHD_TLS_X509_CRT_PARSE_C */

#if defined(JHD_TLS_SSL_SESSION_TICKETS) && defined(JHD_TLS_SSL_CLI_C)
    if( src->ticket != NULL )
    {
        dst->ticket = jhd_tls_calloc( 1, src->ticket_len );
        if( dst->ticket == NULL )
            return( JHD_TLS_ERR_SSL_ALLOC_FAILED );

        memcpy( dst->ticket, src->ticket, src->ticket_len );
    }
#endif /* JHD_TLS_SSL_SESSION_TICKETS && JHD_TLS_SSL_CLI_C */

    return( 0 );
}
#endif /* JHD_TLS_SSL_CLI_C */

#if defined(JHD_TLS_SSL_HW_RECORD_ACCEL)
int (*jhd_tls_ssl_hw_record_init)( jhd_tls_ssl_context *ssl,
                     const unsigned char *key_enc, const unsigned char *key_dec,
                     size_t keylen,
                     const unsigned char *iv_enc,  const unsigned char *iv_dec,
                     size_t ivlen,
                     const unsigned char *mac_enc, const unsigned char *mac_dec,
                     size_t maclen ) = NULL;
int (*jhd_tls_ssl_hw_record_activate)( jhd_tls_ssl_context *ssl, int direction) = NULL;
int (*jhd_tls_ssl_hw_record_reset)( jhd_tls_ssl_context *ssl ) = NULL;
int (*jhd_tls_ssl_hw_record_write)( jhd_tls_ssl_context *ssl ) = NULL;
int (*jhd_tls_ssl_hw_record_read)( jhd_tls_ssl_context *ssl ) = NULL;
int (*jhd_tls_ssl_hw_record_finish)( jhd_tls_ssl_context *ssl ) = NULL;
#endif /* JHD_TLS_SSL_HW_RECORD_ACCEL */

/*
 * Key material generation
 */
#if defined(JHD_TLS_SSL_PROTO_SSL3)
static int ssl3_prf( const unsigned char *secret, size_t slen,
                     const char *label,
                     const unsigned char *random, size_t rlen,
                     unsigned char *dstbuf, size_t dlen )
{
    int ret = 0;
    size_t i;
    jhd_tls_md5_context md5;
    jhd_tls_sha1_context sha1;
    unsigned char padding[16];
    unsigned char sha1sum[20];
    ((void)label);

    jhd_tls_md5_init(  &md5  );
    jhd_tls_sha1_init( &sha1 );

    /*
     *  SSLv3:
     *    block =
     *      MD5( secret + SHA1( 'A'    + secret + random ) ) +
     *      MD5( secret + SHA1( 'BB'   + secret + random ) ) +
     *      MD5( secret + SHA1( 'CCC'  + secret + random ) ) +
     *      ...
     */
    for( i = 0; i < dlen / 16; i++ )
    {
        memset( padding, (unsigned char) ('A' + i), 1 + i );

        if( ( ret = jhd_tls_sha1_starts_ret( &sha1 ) ) != 0 )
            goto exit;
        if( ( ret = jhd_tls_sha1_update_ret( &sha1, padding, 1 + i ) ) != 0 )
            goto exit;
        if( ( ret = jhd_tls_sha1_update_ret( &sha1, secret, slen ) ) != 0 )
            goto exit;
        if( ( ret = jhd_tls_sha1_update_ret( &sha1, random, rlen ) ) != 0 )
            goto exit;
        if( ( ret = jhd_tls_sha1_finish_ret( &sha1, sha1sum ) ) != 0 )
            goto exit;

        if( ( ret = jhd_tls_md5_starts_ret( &md5 ) ) != 0 )
            goto exit;
        if( ( ret = jhd_tls_md5_update_ret( &md5, secret, slen ) ) != 0 )
            goto exit;
        if( ( ret = jhd_tls_md5_update_ret( &md5, sha1sum, 20 ) ) != 0 )
            goto exit;
        if( ( ret = jhd_tls_md5_finish_ret( &md5, dstbuf + i * 16 ) ) != 0 )
            goto exit;
    }

exit:
    jhd_tls_md5_free(  &md5  );
    jhd_tls_sha1_free( &sha1 );

    jhd_tls_platform_zeroize( padding, sizeof( padding ) );
    jhd_tls_platform_zeroize( sha1sum, sizeof( sha1sum ) );

    return( ret );
}
#endif /* JHD_TLS_SSL_PROTO_SSL3 */

#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1)
static int tls1_prf( const unsigned char *secret, size_t slen,
                     const char *label,
                     const unsigned char *random, size_t rlen,
                     unsigned char *dstbuf, size_t dlen )
{
    size_t nb, hs;
    size_t i, j, k;
    const unsigned char *S1, *S2;
    unsigned char tmp[128];
    unsigned char h_i[20];
    const jhd_tls_md_info_t *md_info;
    jhd_tls_md_context_t md_ctx;
    int ret;

    jhd_tls_md_init( &md_ctx );

    if( sizeof( tmp ) < 20 + strlen( label ) + rlen )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    hs = ( slen + 1 ) / 2;
    S1 = secret;
    S2 = secret + slen - hs;

    nb = strlen( label );
    memcpy( tmp + 20, label, nb );
    memcpy( tmp + 20 + nb, random, rlen );
    nb += rlen;

    /*
     * First compute P_md5(secret,label+random)[0..dlen]
     */
    if( ( md_info = jhd_tls_md_info_from_type( JHD_TLS_MD_MD5 ) ) == NULL )
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );

    if( ( ret = jhd_tls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
        return( ret );

    jhd_tls_md_hmac_starts( &md_ctx, S1, hs );
    jhd_tls_md_hmac_update( &md_ctx, tmp + 20, nb );
    jhd_tls_md_hmac_finish( &md_ctx, 4 + tmp );

    for( i = 0; i < dlen; i += 16 )
    {
        jhd_tls_md_hmac_reset ( &md_ctx );
        jhd_tls_md_hmac_update( &md_ctx, 4 + tmp, 16 + nb );
        jhd_tls_md_hmac_finish( &md_ctx, h_i );

        jhd_tls_md_hmac_reset ( &md_ctx );
        jhd_tls_md_hmac_update( &md_ctx, 4 + tmp, 16 );
        jhd_tls_md_hmac_finish( &md_ctx, 4 + tmp );

        k = ( i + 16 > dlen ) ? dlen % 16 : 16;

        for( j = 0; j < k; j++ )
            dstbuf[i + j]  = h_i[j];
    }

    jhd_tls_md_free( &md_ctx );

    /*
     * XOR out with P_sha1(secret,label+random)[0..dlen]
     */
    if( ( md_info = jhd_tls_md_info_from_type( JHD_TLS_MD_SHA1 ) ) == NULL )
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );

    if( ( ret = jhd_tls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
        return( ret );

    jhd_tls_md_hmac_starts( &md_ctx, S2, hs );
    jhd_tls_md_hmac_update( &md_ctx, tmp + 20, nb );
    jhd_tls_md_hmac_finish( &md_ctx, tmp );

    for( i = 0; i < dlen; i += 20 )
    {
        jhd_tls_md_hmac_reset ( &md_ctx );
        jhd_tls_md_hmac_update( &md_ctx, tmp, 20 + nb );
        jhd_tls_md_hmac_finish( &md_ctx, h_i );

        jhd_tls_md_hmac_reset ( &md_ctx );
        jhd_tls_md_hmac_update( &md_ctx, tmp, 20 );
        jhd_tls_md_hmac_finish( &md_ctx, tmp );

        k = ( i + 20 > dlen ) ? dlen % 20 : 20;

        for( j = 0; j < k; j++ )
            dstbuf[i + j] = (unsigned char)( dstbuf[i + j] ^ h_i[j] );
    }

    jhd_tls_md_free( &md_ctx );

    jhd_tls_platform_zeroize( tmp, sizeof( tmp ) );
    jhd_tls_platform_zeroize( h_i, sizeof( h_i ) );

    return( 0 );
}
#endif /* JHD_TLS_SSL_PROTO_TLS1) || JHD_TLS_SSL_PROTO_TLS1_1 */

#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
static int tls_prf_generic( jhd_tls_md_type_t md_type,
                            const unsigned char *secret, size_t slen,
                            const char *label,
                            const unsigned char *random, size_t rlen,
                            unsigned char *dstbuf, size_t dlen )
{
    size_t nb;
    size_t i, j, k, md_len;
    unsigned char tmp[128];
    unsigned char h_i[JHD_TLS_MD_MAX_SIZE];
    const jhd_tls_md_info_t *md_info;
    jhd_tls_md_context_t md_ctx;
    int ret;

    jhd_tls_md_init( &md_ctx );

    if( ( md_info = jhd_tls_md_info_from_type( md_type ) ) == NULL )
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );

    md_len = jhd_tls_md_get_size( md_info );

    if( sizeof( tmp ) < md_len + strlen( label ) + rlen )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    nb = strlen( label );
    memcpy( tmp + md_len, label, nb );
    memcpy( tmp + md_len + nb, random, rlen );
    nb += rlen;

    /*
     * Compute P_<hash>(secret, label + random)[0..dlen]
     */
    if ( ( ret = jhd_tls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
        return( ret );

    jhd_tls_md_hmac_starts( &md_ctx, secret, slen );
    jhd_tls_md_hmac_update( &md_ctx, tmp + md_len, nb );
    jhd_tls_md_hmac_finish( &md_ctx, tmp );

    for( i = 0; i < dlen; i += md_len )
    {
        jhd_tls_md_hmac_reset ( &md_ctx );
        jhd_tls_md_hmac_update( &md_ctx, tmp, md_len + nb );
        jhd_tls_md_hmac_finish( &md_ctx, h_i );

        jhd_tls_md_hmac_reset ( &md_ctx );
        jhd_tls_md_hmac_update( &md_ctx, tmp, md_len );
        jhd_tls_md_hmac_finish( &md_ctx, tmp );

        k = ( i + md_len > dlen ) ? dlen % md_len : md_len;

        for( j = 0; j < k; j++ )
            dstbuf[i + j]  = h_i[j];
    }

    jhd_tls_md_free( &md_ctx );

    jhd_tls_platform_zeroize( tmp, sizeof( tmp ) );
    jhd_tls_platform_zeroize( h_i, sizeof( h_i ) );

    return( 0 );
}

#if defined(JHD_TLS_SHA256_C)
static int tls_prf_sha256( const unsigned char *secret, size_t slen,
                           const char *label,
                           const unsigned char *random, size_t rlen,
                           unsigned char *dstbuf, size_t dlen )
{
    return( tls_prf_generic( JHD_TLS_MD_SHA256, secret, slen,
                             label, random, rlen, dstbuf, dlen ) );
}
#endif /* JHD_TLS_SHA256_C */

#if defined(JHD_TLS_SHA512_C)
static int tls_prf_sha384( const unsigned char *secret, size_t slen,
                           const char *label,
                           const unsigned char *random, size_t rlen,
                           unsigned char *dstbuf, size_t dlen )
{
    return( tls_prf_generic( JHD_TLS_MD_SHA384, secret, slen,
                             label, random, rlen, dstbuf, dlen ) );
}
#endif /* JHD_TLS_SHA512_C */
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */

static void ssl_update_checksum_start( jhd_tls_ssl_context *, const unsigned char *, size_t );

#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_1)
static void ssl_update_checksum_md5sha1( jhd_tls_ssl_context *, const unsigned char *, size_t );
#endif

#if defined(JHD_TLS_SSL_PROTO_SSL3)
static void ssl_calc_verify_ssl( jhd_tls_ssl_context *, unsigned char * );
static void ssl_calc_finished_ssl( jhd_tls_ssl_context *, unsigned char *, int );
#endif

#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1)
static void ssl_calc_verify_tls( jhd_tls_ssl_context *, unsigned char * );
static void ssl_calc_finished_tls( jhd_tls_ssl_context *, unsigned char *, int );
#endif

#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#if defined(JHD_TLS_SHA256_C)
static void ssl_update_checksum_sha256( jhd_tls_ssl_context *, const unsigned char *, size_t );
static void ssl_calc_verify_tls_sha256( jhd_tls_ssl_context *,unsigned char * );
static void ssl_calc_finished_tls_sha256( jhd_tls_ssl_context *,unsigned char *, int );
#endif

#if defined(JHD_TLS_SHA512_C)
static void ssl_update_checksum_sha384( jhd_tls_ssl_context *, const unsigned char *, size_t );
static void ssl_calc_verify_tls_sha384( jhd_tls_ssl_context *, unsigned char * );
static void ssl_calc_finished_tls_sha384( jhd_tls_ssl_context *, unsigned char *, int );
#endif
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */

int jhd_tls_ssl_derive_keys( jhd_tls_ssl_context *ssl )
{
    int ret = 0;
    unsigned char tmp[64];
    unsigned char keyblk[256];
    unsigned char *key1;
    unsigned char *key2;
    unsigned char *mac_enc;
    unsigned char *mac_dec;
    size_t mac_key_len;
    size_t iv_copy_len;
    const jhd_tls_cipher_info_t *cipher_info;
    const jhd_tls_md_info_t *md_info;

    jhd_tls_ssl_session *session = ssl->session_negotiate;
    jhd_tls_ssl_transform *transform = ssl->transform_negotiate;
    jhd_tls_ssl_handshake_params *handshake = ssl->handshake;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> derive keys" ) );

    cipher_info = jhd_tls_cipher_info_from_type( transform->ciphersuite_info->cipher );
    if( cipher_info == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "cipher info for %d not found",
                            transform->ciphersuite_info->cipher ) );
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

    md_info = jhd_tls_md_info_from_type( transform->ciphersuite_info->mac );
    if( md_info == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "jhd_tls_md info for %d not found",
                            transform->ciphersuite_info->mac ) );
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

    /*
     * Set appropriate PRF function and other SSL / TLS / TLS1.2 functions
     */
#if defined(JHD_TLS_SSL_PROTO_SSL3)
    if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 )
    {
        handshake->tls_prf = ssl3_prf;
        handshake->calc_verify = ssl_calc_verify_ssl;
        handshake->calc_finished = ssl_calc_finished_ssl;
    }
    else
#endif
#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1)
    if( ssl->minor_ver < JHD_TLS_SSL_MINOR_VERSION_3 )
    {
        handshake->tls_prf = tls1_prf;
        handshake->calc_verify = ssl_calc_verify_tls;
        handshake->calc_finished = ssl_calc_finished_tls;
    }
    else
#endif
#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#if defined(JHD_TLS_SHA512_C)
    if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3 &&
        transform->ciphersuite_info->mac == JHD_TLS_MD_SHA384 )
    {
        handshake->tls_prf = tls_prf_sha384;
        handshake->calc_verify = ssl_calc_verify_tls_sha384;
        handshake->calc_finished = ssl_calc_finished_tls_sha384;
    }
    else
#endif
#if defined(JHD_TLS_SHA256_C)
    if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3 )
    {
        handshake->tls_prf = tls_prf_sha256;
        handshake->calc_verify = ssl_calc_verify_tls_sha256;
        handshake->calc_finished = ssl_calc_finished_tls_sha256;
    }
    else
#endif
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

    /*
     * SSLv3:
     *   master =
     *     MD5( premaster + SHA1( 'A'   + premaster + randbytes ) ) +
     *     MD5( premaster + SHA1( 'BB'  + premaster + randbytes ) ) +
     *     MD5( premaster + SHA1( 'CCC' + premaster + randbytes ) )
     *
     * TLSv1+:
     *   master = PRF( premaster, "master secret", randbytes )[0..47]
     */
    if( handshake->resume == 0 )
    {
        JHD_TLS_SSL_DEBUG_BUF( 3, "premaster secret", handshake->premaster,
                       handshake->pmslen );

#if defined(JHD_TLS_SSL_EXTENDED_MASTER_SECRET)
        if( ssl->handshake->extended_ms == JHD_TLS_SSL_EXTENDED_MS_ENABLED )
        {
            unsigned char session_hash[48];
            size_t hash_len;

            JHD_TLS_SSL_DEBUG_MSG( 3, ( "using extended master secret" ) );

            ssl->handshake->calc_verify( ssl, session_hash );

#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
            if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3 )
            {
#if defined(JHD_TLS_SHA512_C)
                if( ssl->transform_negotiate->ciphersuite_info->mac ==
                    JHD_TLS_MD_SHA384 )
                {
                    hash_len = 48;
                }
                else
#endif
                    hash_len = 32;
            }
            else
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */
                hash_len = 36;

            JHD_TLS_SSL_DEBUG_BUF( 3, "session hash", session_hash, hash_len );

            ret = handshake->tls_prf( handshake->premaster, handshake->pmslen,
                                      "extended master secret",
                                      session_hash, hash_len,
                                      session->master, 48 );
            if( ret != 0 )
            {
                JHD_TLS_SSL_DEBUG_RET( 1, "prf", ret );
                return( ret );
            }

        }
        else
#endif
        ret = handshake->tls_prf( handshake->premaster, handshake->pmslen,
                                  "master secret",
                                  handshake->randbytes, 64,
                                  session->master, 48 );
        if( ret != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "prf", ret );
            return( ret );
        }

        jhd_tls_platform_zeroize( handshake->premaster,
                                  sizeof(handshake->premaster) );
    }
    else
        JHD_TLS_SSL_DEBUG_MSG( 3, ( "no premaster (session resumed)" ) );

    /*
     * Swap the client and server random values.
     */
    memcpy( tmp, handshake->randbytes, 64 );
    memcpy( handshake->randbytes, tmp + 32, 32 );
    memcpy( handshake->randbytes + 32, tmp, 32 );
    jhd_tls_platform_zeroize( tmp, sizeof( tmp ) );

    /*
     *  SSLv3:
     *    key block =
     *      MD5( master + SHA1( 'A'    + master + randbytes ) ) +
     *      MD5( master + SHA1( 'BB'   + master + randbytes ) ) +
     *      MD5( master + SHA1( 'CCC'  + master + randbytes ) ) +
     *      MD5( master + SHA1( 'DDDD' + master + randbytes ) ) +
     *      ...
     *
     *  TLSv1:
     *    key block = PRF( master, "key expansion", randbytes )
     */
    ret = handshake->tls_prf( session->master, 48, "key expansion",
                              handshake->randbytes, 64, keyblk, 256 );
    if( ret != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "prf", ret );
        return( ret );
    }

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "ciphersuite = %s",
                   jhd_tls_ssl_get_ciphersuite_name( session->ciphersuite ) ) );
    JHD_TLS_SSL_DEBUG_BUF( 3, "master secret", session->master, 48 );
    JHD_TLS_SSL_DEBUG_BUF( 4, "random bytes", handshake->randbytes, 64 );
    JHD_TLS_SSL_DEBUG_BUF( 4, "key block", keyblk, 256 );

    jhd_tls_platform_zeroize( handshake->randbytes,
                              sizeof( handshake->randbytes ) );

    /*
     * Determine the appropriate key, IV and MAC length.
     */

    transform->keylen = cipher_info->key_bitlen / 8;

    if( cipher_info->mode == JHD_TLS_MODE_GCM ||
        cipher_info->mode == JHD_TLS_MODE_CCM )
    {
        transform->maclen = 0;
        mac_key_len = 0;

        transform->ivlen = 12;
        transform->fixed_ivlen = 4;

        /* Minimum length is expicit IV + tag */
        transform->minlen = transform->ivlen - transform->fixed_ivlen
                            + ( transform->ciphersuite_info->flags &
                                JHD_TLS_CIPHERSUITE_SHORT_TAG ? 8 : 16 );
    }
    else
    {
        /* Initialize HMAC contexts */
        if( ( ret = jhd_tls_md_setup( &transform->md_ctx_enc, md_info, 1 ) ) != 0 ||
            ( ret = jhd_tls_md_setup( &transform->md_ctx_dec, md_info, 1 ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_md_setup", ret );
            return( ret );
        }

        /* Get MAC length */
        mac_key_len = jhd_tls_md_get_size( md_info );
        transform->maclen = mac_key_len;

#if defined(JHD_TLS_SSL_TRUNCATED_HMAC)
        /*
         * If HMAC is to be truncated, we shall keep the leftmost bytes,
         * (rfc 6066 page 13 or rfc 2104 section 4),
         * so we only need to adjust the length here.
         */
        if( session->trunc_hmac == JHD_TLS_SSL_TRUNC_HMAC_ENABLED )
        {
            transform->maclen = JHD_TLS_SSL_TRUNCATED_HMAC_LEN;

#if defined(JHD_TLS_SSL_TRUNCATED_HMAC_COMPAT)
            /* Fall back to old, non-compliant version of the truncated
             * HMAC implementation which also truncates the key
             * (Mbed TLS versions from 1.3 to 2.6.0) */
            mac_key_len = transform->maclen;
#endif
        }
#endif /* JHD_TLS_SSL_TRUNCATED_HMAC */

        /* IV length */
        transform->ivlen = cipher_info->iv_size;

        /* Minimum length */
        if( cipher_info->mode == JHD_TLS_MODE_STREAM )
            transform->minlen = transform->maclen;
        else
        {
            /*
             * GenericBlockCipher:
             * 1. if EtM is in use: one block plus MAC
             *    otherwise: * first multiple of blocklen greater than maclen
             * 2. IV except for SSL3 and TLS 1.0
             */
#if defined(JHD_TLS_SSL_ENCRYPT_THEN_MAC)
            if( session->encrypt_then_mac == JHD_TLS_SSL_ETM_ENABLED )
            {
                transform->minlen = transform->maclen
                                  + cipher_info->block_size;
            }
            else
#endif
            {
                transform->minlen = transform->maclen
                                  + cipher_info->block_size
                                  - transform->maclen % cipher_info->block_size;
            }

#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1)
            if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 ||
                ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_1 )
                ; /* No need to adjust minlen */
            else
#endif
#if defined(JHD_TLS_SSL_PROTO_TLS1_1) || defined(JHD_TLS_SSL_PROTO_TLS1_2)
            if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_2 ||
                ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3 )
            {
                transform->minlen += transform->ivlen;
            }
            else
#endif
            {
                JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
            }
        }
    }

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "keylen: %d, minlen: %d, ivlen: %d, maclen: %d",
                   transform->keylen, transform->minlen, transform->ivlen,
                   transform->maclen ) );

    /*
     * Finally setup the cipher contexts, IVs and MAC secrets.
     */
#if defined(JHD_TLS_SSL_CLI_C)
    if( ssl->conf->endpoint == JHD_TLS_SSL_IS_CLIENT )
    {
        key1 = keyblk + mac_key_len * 2;
        key2 = keyblk + mac_key_len * 2 + transform->keylen;

        mac_enc = keyblk;
        mac_dec = keyblk + mac_key_len;

        /*
         * This is not used in TLS v1.1.
         */
        iv_copy_len = ( transform->fixed_ivlen ) ?
                            transform->fixed_ivlen : transform->ivlen;
        memcpy( transform->iv_enc, key2 + transform->keylen,  iv_copy_len );
        memcpy( transform->iv_dec, key2 + transform->keylen + iv_copy_len,
                iv_copy_len );
    }
    else
#endif /* JHD_TLS_SSL_CLI_C */
#if defined(JHD_TLS_SSL_SRV_C)
    if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER )
    {
        key1 = keyblk + mac_key_len * 2 + transform->keylen;
        key2 = keyblk + mac_key_len * 2;

        mac_enc = keyblk + mac_key_len;
        mac_dec = keyblk;

        /*
         * This is not used in TLS v1.1.
         */
        iv_copy_len = ( transform->fixed_ivlen ) ?
                            transform->fixed_ivlen : transform->ivlen;
        memcpy( transform->iv_dec, key1 + transform->keylen,  iv_copy_len );
        memcpy( transform->iv_enc, key1 + transform->keylen + iv_copy_len,
                iv_copy_len );
    }
    else
#endif /* JHD_TLS_SSL_SRV_C */
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

#if defined(JHD_TLS_SSL_PROTO_SSL3)
    if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 )
    {
        if( mac_key_len > sizeof transform->mac_enc )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

        memcpy( transform->mac_enc, mac_enc, mac_key_len );
        memcpy( transform->mac_dec, mac_dec, mac_key_len );
    }
    else
#endif /* JHD_TLS_SSL_PROTO_SSL3 */
#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_2)
    if( ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_1 )
    {
        /* For HMAC-based ciphersuites, initialize the HMAC transforms.
           For AEAD-based ciphersuites, there is nothing to do here. */
        if( mac_key_len != 0 )
        {
            jhd_tls_md_hmac_starts( &transform->md_ctx_enc, mac_enc, mac_key_len );
            jhd_tls_md_hmac_starts( &transform->md_ctx_dec, mac_dec, mac_key_len );
        }
    }
    else
#endif
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

#if defined(JHD_TLS_SSL_HW_RECORD_ACCEL)
    if( jhd_tls_ssl_hw_record_init != NULL )
    {
        int ret = 0;

        JHD_TLS_SSL_DEBUG_MSG( 2, ( "going for jhd_tls_ssl_hw_record_init()" ) );

        if( ( ret = jhd_tls_ssl_hw_record_init( ssl, key1, key2, transform->keylen,
                                        transform->iv_enc, transform->iv_dec,
                                        iv_copy_len,
                                        mac_enc, mac_dec,
                                        mac_key_len ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_hw_record_init", ret );
            return( JHD_TLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif /* JHD_TLS_SSL_HW_RECORD_ACCEL */

#if defined(JHD_TLS_SSL_EXPORT_KEYS)
    if( ssl->conf->f_export_keys != NULL )
    {
        ssl->conf->f_export_keys( ssl->conf->p_export_keys,
                                  session->master, keyblk,
                                  mac_key_len, transform->keylen,
                                  iv_copy_len );
    }
#endif

    if( ( ret = jhd_tls_cipher_setup( &transform->cipher_ctx_enc,
                                 cipher_info ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_setup", ret );
        return( ret );
    }

    if( ( ret = jhd_tls_cipher_setup( &transform->cipher_ctx_dec,
                                 cipher_info ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_setup", ret );
        return( ret );
    }

    if( ( ret = jhd_tls_cipher_setkey( &transform->cipher_ctx_enc, key1,
                               cipher_info->key_bitlen,
                               JHD_TLS_ENCRYPT ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_setkey", ret );
        return( ret );
    }

    if( ( ret = jhd_tls_cipher_setkey( &transform->cipher_ctx_dec, key2,
                               cipher_info->key_bitlen,
                               JHD_TLS_DECRYPT ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_setkey", ret );
        return( ret );
    }

#if defined(JHD_TLS_CIPHER_MODE_CBC)
    if( cipher_info->mode == JHD_TLS_MODE_CBC )
    {
        if( ( ret = jhd_tls_cipher_set_padding_mode( &transform->cipher_ctx_enc,
                                             JHD_TLS_PADDING_NONE ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_set_padding_mode", ret );
            return( ret );
        }

        if( ( ret = jhd_tls_cipher_set_padding_mode( &transform->cipher_ctx_dec,
                                             JHD_TLS_PADDING_NONE ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_set_padding_mode", ret );
            return( ret );
        }
    }
#endif /* JHD_TLS_CIPHER_MODE_CBC */

    jhd_tls_platform_zeroize( keyblk, sizeof( keyblk ) );

#if defined(JHD_TLS_ZLIB_SUPPORT)
    // Initialize compression
    //
    if( session->compression == JHD_TLS_SSL_COMPRESS_DEFLATE )
    {
        if( ssl->compress_buf == NULL )
        {
            JHD_TLS_SSL_DEBUG_MSG( 3, ( "Allocating compression buffer" ) );
            ssl->compress_buf = jhd_tls_calloc( 1, JHD_TLS_SSL_BUFFER_LEN );
            if( ssl->compress_buf == NULL )
            {
                JHD_TLS_SSL_DEBUG_MSG( 1, ( "alloc(%d bytes) failed",
                                    JHD_TLS_SSL_BUFFER_LEN ) );
                return( JHD_TLS_ERR_SSL_ALLOC_FAILED );
            }
        }

        JHD_TLS_SSL_DEBUG_MSG( 3, ( "Initializing zlib states" ) );

        memset( &transform->ctx_deflate, 0, sizeof( transform->ctx_deflate ) );
        memset( &transform->ctx_inflate, 0, sizeof( transform->ctx_inflate ) );

        if( deflateInit( &transform->ctx_deflate,
                         Z_DEFAULT_COMPRESSION )   != Z_OK ||
            inflateInit( &transform->ctx_inflate ) != Z_OK )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "Failed to initialize compression" ) );
            return( JHD_TLS_ERR_SSL_COMPRESSION_FAILED );
        }
    }
#endif /* JHD_TLS_ZLIB_SUPPORT */

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= derive keys" ) );

    return( 0 );
}

#if defined(JHD_TLS_SSL_PROTO_SSL3)
void ssl_calc_verify_ssl( jhd_tls_ssl_context *ssl, unsigned char hash[36] )
{
    jhd_tls_md5_context md5;
    jhd_tls_sha1_context sha1;
    unsigned char pad_1[48];
    unsigned char pad_2[48];

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> calc verify ssl" ) );

    jhd_tls_md5_init( &md5 );
    jhd_tls_sha1_init( &sha1 );

    jhd_tls_md5_clone( &md5, &ssl->handshake->fin_md5 );
    jhd_tls_sha1_clone( &sha1, &ssl->handshake->fin_sha1 );

    memset( pad_1, 0x36, 48 );
    memset( pad_2, 0x5C, 48 );

    jhd_tls_md5_update_ret( &md5, ssl->session_negotiate->master, 48 );
    jhd_tls_md5_update_ret( &md5, pad_1, 48 );
    jhd_tls_md5_finish_ret( &md5, hash );

    jhd_tls_md5_starts_ret( &md5 );
    jhd_tls_md5_update_ret( &md5, ssl->session_negotiate->master, 48 );
    jhd_tls_md5_update_ret( &md5, pad_2, 48 );
    jhd_tls_md5_update_ret( &md5, hash,  16 );
    jhd_tls_md5_finish_ret( &md5, hash );

    jhd_tls_sha1_update_ret( &sha1, ssl->session_negotiate->master, 48 );
    jhd_tls_sha1_update_ret( &sha1, pad_1, 40 );
    jhd_tls_sha1_finish_ret( &sha1, hash + 16 );

    jhd_tls_sha1_starts_ret( &sha1 );
    jhd_tls_sha1_update_ret( &sha1, ssl->session_negotiate->master, 48 );
    jhd_tls_sha1_update_ret( &sha1, pad_2, 40 );
    jhd_tls_sha1_update_ret( &sha1, hash + 16, 20 );
    jhd_tls_sha1_finish_ret( &sha1, hash + 16 );

    JHD_TLS_SSL_DEBUG_BUF( 3, "calculated verify result", hash, 36 );
    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= calc verify" ) );

    jhd_tls_md5_free(  &md5  );
    jhd_tls_sha1_free( &sha1 );

    return;
}
#endif /* JHD_TLS_SSL_PROTO_SSL3 */

#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1)
void ssl_calc_verify_tls( jhd_tls_ssl_context *ssl, unsigned char hash[36] )
{
    jhd_tls_md5_context md5;
    jhd_tls_sha1_context sha1;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> calc verify tls" ) );

    jhd_tls_md5_init( &md5 );
    jhd_tls_sha1_init( &sha1 );

    jhd_tls_md5_clone( &md5, &ssl->handshake->fin_md5 );
    jhd_tls_sha1_clone( &sha1, &ssl->handshake->fin_sha1 );

     jhd_tls_md5_finish_ret( &md5,  hash );
    jhd_tls_sha1_finish_ret( &sha1, hash + 16 );

    JHD_TLS_SSL_DEBUG_BUF( 3, "calculated verify result", hash, 36 );
    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= calc verify" ) );

    jhd_tls_md5_free(  &md5  );
    jhd_tls_sha1_free( &sha1 );

    return;
}
#endif /* JHD_TLS_SSL_PROTO_TLS1 || JHD_TLS_SSL_PROTO_TLS1_1 */

#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#if defined(JHD_TLS_SHA256_C)
void ssl_calc_verify_tls_sha256( jhd_tls_ssl_context *ssl, unsigned char hash[32] )
{
    jhd_tls_sha256_context sha256;

    jhd_tls_sha256_init( &sha256 );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> calc verify sha256" ) );

    jhd_tls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );
    jhd_tls_sha256_finish_ret( &sha256, hash );

    JHD_TLS_SSL_DEBUG_BUF( 3, "calculated verify result", hash, 32 );
    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= calc verify" ) );

    jhd_tls_sha256_free( &sha256 );

    return;
}
#endif /* JHD_TLS_SHA256_C */

#if defined(JHD_TLS_SHA512_C)
void ssl_calc_verify_tls_sha384( jhd_tls_ssl_context *ssl, unsigned char hash[48] )
{
    jhd_tls_sha512_context sha512;

    jhd_tls_sha512_init( &sha512 );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> calc verify sha384" ) );

    jhd_tls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );
    jhd_tls_sha512_finish_ret( &sha512, hash );

    JHD_TLS_SSL_DEBUG_BUF( 3, "calculated verify result", hash, 48 );
    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= calc verify" ) );

    jhd_tls_sha512_free( &sha512 );

    return;
}
#endif /* JHD_TLS_SHA512_C */
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */

#if defined(JHD_TLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int jhd_tls_ssl_psk_derive_premaster( jhd_tls_ssl_context *ssl, jhd_tls_key_exchange_type_t key_ex )
{
    unsigned char *p = ssl->handshake->premaster;
    unsigned char *end = p + sizeof( ssl->handshake->premaster );
    const unsigned char *psk = ssl->conf->psk;
    size_t psk_len = ssl->conf->psk_len;

    /* If the psk callback was called, use its result */
    if( ssl->handshake->psk != NULL )
    {
        psk = ssl->handshake->psk;
        psk_len = ssl->handshake->psk_len;
    }

    /*
     * PMS = struct {
     *     opaque other_secret<0..2^16-1>;
     *     opaque psk<0..2^16-1>;
     * };
     * with "other_secret" depending on the particular key exchange
     */
#if defined(JHD_TLS_KEY_EXCHANGE_PSK_ENABLED)
    if( key_ex == JHD_TLS_KEY_EXCHANGE_PSK )
    {
        if( end - p < 2 )
            return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

        *(p++) = (unsigned char)( psk_len >> 8 );
        *(p++) = (unsigned char)( psk_len      );

        if( end < p || (size_t)( end - p ) < psk_len )
            return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

        memset( p, 0, psk_len );
        p += psk_len;
    }
    else
#endif /* JHD_TLS_KEY_EXCHANGE_PSK_ENABLED */
#if defined(JHD_TLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    if( key_ex == JHD_TLS_KEY_EXCHANGE_RSA_PSK )
    {
        /*
         * other_secret already set by the ClientKeyExchange message,
         * and is 48 bytes long
         */
        *p++ = 0;
        *p++ = 48;
        p += 48;
    }
    else
#endif /* JHD_TLS_KEY_EXCHANGE_RSA_PSK_ENABLED */
#if defined(JHD_TLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
    if( key_ex == JHD_TLS_KEY_EXCHANGE_DHE_PSK )
    {
        int ret;
        size_t len;

        /* Write length only when we know the actual value */
        if( ( ret = jhd_tls_dhm_calc_secret( &ssl->handshake->dhm_ctx,
                                      p + 2, end - ( p + 2 ), &len,
                                      ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_dhm_calc_secret", ret );
            return( ret );
        }
        *(p++) = (unsigned char)( len >> 8 );
        *(p++) = (unsigned char)( len );
        p += len;

        JHD_TLS_SSL_DEBUG_MPI( 3, "DHM: K ", &ssl->handshake->dhm_ctx.K  );
    }
    else
#endif /* JHD_TLS_KEY_EXCHANGE_DHE_PSK_ENABLED */
#if defined(JHD_TLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
    if( key_ex == JHD_TLS_KEY_EXCHANGE_ECDHE_PSK )
    {
        int ret;
        size_t zlen;

        if( ( ret = jhd_tls_ecdh_calc_secret( &ssl->handshake->ecdh_ctx, &zlen,
                                       p + 2, end - ( p + 2 ),
                                       ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ecdh_calc_secret", ret );
            return( ret );
        }

        *(p++) = (unsigned char)( zlen >> 8 );
        *(p++) = (unsigned char)( zlen      );
        p += zlen;

        JHD_TLS_SSL_DEBUG_MPI( 3, "ECDH: z", &ssl->handshake->ecdh_ctx.z );
    }
    else
#endif /* JHD_TLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED */
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* opaque psk<0..2^16-1>; */
    if( end - p < 2 )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    *(p++) = (unsigned char)( psk_len >> 8 );
    *(p++) = (unsigned char)( psk_len      );

    if( end < p || (size_t)( end - p ) < psk_len )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    memcpy( p, psk, psk_len );
    p += psk_len;

    ssl->handshake->pmslen = p - ssl->handshake->premaster;

    return( 0 );
}
#endif /* JHD_TLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(JHD_TLS_SSL_PROTO_SSL3)
/*
 * SSLv3.0 MAC functions
 */
#define SSL_MAC_MAX_BYTES   20  /* MD-5 or SHA-1 */
static void ssl_mac( jhd_tls_md_context_t *md_ctx,
                     const unsigned char *secret,
                     const unsigned char *buf, size_t len,
                     const unsigned char *ctr, int type,
                     unsigned char out[SSL_MAC_MAX_BYTES] )
{
    unsigned char header[11];
    unsigned char padding[48];
    int padlen;
    int md_size = jhd_tls_md_get_size( md_ctx->md_info );
    int md_type = jhd_tls_md_get_type( md_ctx->md_info );

    /* Only MD5 and SHA-1 supported */
    if( md_type == JHD_TLS_MD_MD5 )
        padlen = 48;
    else
        padlen = 40;

    memcpy( header, ctr, 8 );
    header[ 8] = (unsigned char)  type;
    header[ 9] = (unsigned char)( len >> 8 );
    header[10] = (unsigned char)( len      );

    memset( padding, 0x36, padlen );
    jhd_tls_md_starts( md_ctx );
    jhd_tls_md_update( md_ctx, secret,  md_size );
    jhd_tls_md_update( md_ctx, padding, padlen  );
    jhd_tls_md_update( md_ctx, header,  11      );
    jhd_tls_md_update( md_ctx, buf,     len     );
    jhd_tls_md_finish( md_ctx, out              );

    memset( padding, 0x5C, padlen );
    jhd_tls_md_starts( md_ctx );
    jhd_tls_md_update( md_ctx, secret,    md_size );
    jhd_tls_md_update( md_ctx, padding,   padlen  );
    jhd_tls_md_update( md_ctx, out,       md_size );
    jhd_tls_md_finish( md_ctx, out                );
}
#endif /* JHD_TLS_SSL_PROTO_SSL3 */

#if defined(JHD_TLS_ARC4_C) || defined(JHD_TLS_CIPHER_NULL_CIPHER) ||     \
    ( defined(JHD_TLS_CIPHER_MODE_CBC) &&                                  \
      ( defined(JHD_TLS_AES_C) || defined(JHD_TLS_CAMELLIA_C) || defined(JHD_TLS_ARIA_C)) )
#define SSL_SOME_MODES_USE_MAC
#endif

/*
 * Encryption/decryption functions
 */
static int ssl_encrypt_buf( jhd_tls_ssl_context *ssl )
{
    jhd_tls_cipher_mode_t mode;
    int auth_done = 0;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> encrypt buf" ) );

    if( ssl->session_out == NULL || ssl->transform_out == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

    mode = jhd_tls_cipher_get_cipher_mode( &ssl->transform_out->cipher_ctx_enc );

    JHD_TLS_SSL_DEBUG_BUF( 4, "before encrypt: output payload",
                      ssl->out_msg, ssl->out_msglen );

    if( ssl->out_msglen > JHD_TLS_SSL_MAX_CONTENT_LEN )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "Record content %u too large, maximum %d",
                                    (unsigned) ssl->out_msglen,
                                    JHD_TLS_SSL_MAX_CONTENT_LEN ) );
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

    /*
     * Add MAC before if needed
     */
#if defined(SSL_SOME_MODES_USE_MAC)
    if( mode == JHD_TLS_MODE_STREAM ||
        ( mode == JHD_TLS_MODE_CBC
#if defined(JHD_TLS_SSL_ENCRYPT_THEN_MAC)
          && ssl->session_out->encrypt_then_mac == JHD_TLS_SSL_ETM_DISABLED
#endif
        ) )
    {
#if defined(JHD_TLS_SSL_PROTO_SSL3)
        if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 )
        {
            unsigned char mac[SSL_MAC_MAX_BYTES];

            ssl_mac( &ssl->transform_out->md_ctx_enc,
                      ssl->transform_out->mac_enc,
                      ssl->out_msg, ssl->out_msglen,
                      ssl->out_ctr, ssl->out_msgtype,
                      mac );

            memcpy( ssl->out_msg + ssl->out_msglen, mac, ssl->transform_out->maclen );
        }
        else
#endif
#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1) || \
        defined(JHD_TLS_SSL_PROTO_TLS1_2)
        if( ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_1 )
        {
            unsigned char mac[JHD_TLS_SSL_MAC_ADD];

            jhd_tls_md_hmac_update( &ssl->transform_out->md_ctx_enc, ssl->out_ctr, 8 );
            jhd_tls_md_hmac_update( &ssl->transform_out->md_ctx_enc, ssl->out_hdr, 3 );
            jhd_tls_md_hmac_update( &ssl->transform_out->md_ctx_enc, ssl->out_len, 2 );
            jhd_tls_md_hmac_update( &ssl->transform_out->md_ctx_enc,
                             ssl->out_msg, ssl->out_msglen );
            jhd_tls_md_hmac_finish( &ssl->transform_out->md_ctx_enc, mac );
            jhd_tls_md_hmac_reset( &ssl->transform_out->md_ctx_enc );

            memcpy( ssl->out_msg + ssl->out_msglen, mac, ssl->transform_out->maclen );
        }
        else
#endif
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

        JHD_TLS_SSL_DEBUG_BUF( 4, "computed mac",
                       ssl->out_msg + ssl->out_msglen,
                       ssl->transform_out->maclen );

        ssl->out_msglen += ssl->transform_out->maclen;
        auth_done++;
    }
#endif /* AEAD not the only option */

    /*
     * Encrypt
     */
#if defined(JHD_TLS_ARC4_C) || defined(JHD_TLS_CIPHER_NULL_CIPHER)
    if( mode == JHD_TLS_MODE_STREAM )
    {
        int ret;
        size_t olen = 0;

        JHD_TLS_SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
                            "including %d bytes of padding",
                       ssl->out_msglen, 0 ) );

        if( ( ret = jhd_tls_cipher_crypt( &ssl->transform_out->cipher_ctx_enc,
                                   ssl->transform_out->iv_enc,
                                   ssl->transform_out->ivlen,
                                   ssl->out_msg, ssl->out_msglen,
                                   ssl->out_msg, &olen ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_crypt", ret );
            return( ret );
        }

        if( ssl->out_msglen != olen )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
#endif /* JHD_TLS_ARC4_C || JHD_TLS_CIPHER_NULL_CIPHER */
#if defined(JHD_TLS_GCM_C) || defined(JHD_TLS_CCM_C)
    if( mode == JHD_TLS_MODE_GCM ||
        mode == JHD_TLS_MODE_CCM )
    {
        int ret;
        size_t enc_msglen, olen;
        unsigned char *enc_msg;
        unsigned char add_data[13];
        unsigned char taglen = ssl->transform_out->ciphersuite_info->flags &
                               JHD_TLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;

        memcpy( add_data, ssl->out_ctr, 8 );
        add_data[8]  = ssl->out_msgtype;
        jhd_tls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                           ssl->conf->transport, add_data + 9 );
        add_data[11] = ( ssl->out_msglen >> 8 ) & 0xFF;
        add_data[12] = ssl->out_msglen & 0xFF;

        JHD_TLS_SSL_DEBUG_BUF( 4, "additional data used for AEAD",
                       add_data, 13 );

        /*
         * Generate IV
         */
        if( ssl->transform_out->ivlen - ssl->transform_out->fixed_ivlen != 8 )
        {
            /* Reminder if we ever add an AEAD mode with a different size */
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

        memcpy( ssl->transform_out->iv_enc + ssl->transform_out->fixed_ivlen,
                             ssl->out_ctr, 8 );
        memcpy( ssl->out_iv, ssl->out_ctr, 8 );

        JHD_TLS_SSL_DEBUG_BUF( 4, "IV used", ssl->out_iv,
                ssl->transform_out->ivlen - ssl->transform_out->fixed_ivlen );

        /*
         * Fix pointer positions and message length with added IV
         */
        enc_msg = ssl->out_msg;
        enc_msglen = ssl->out_msglen;
        ssl->out_msglen += ssl->transform_out->ivlen -
                           ssl->transform_out->fixed_ivlen;

        JHD_TLS_SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
                            "including %d bytes of padding",
                       ssl->out_msglen, 0 ) );

        /*
         * Encrypt and authenticate
         */
        if( ( ret = jhd_tls_cipher_auth_encrypt( &ssl->transform_out->cipher_ctx_enc,
                                         ssl->transform_out->iv_enc,
                                         ssl->transform_out->ivlen,
                                         add_data, 13,
                                         enc_msg, enc_msglen,
                                         enc_msg, &olen,
                                         enc_msg + enc_msglen, taglen ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_auth_encrypt", ret );
            return( ret );
        }

        if( olen != enc_msglen )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

        ssl->out_msglen += taglen;
        auth_done++;

        JHD_TLS_SSL_DEBUG_BUF( 4, "after encrypt: tag", enc_msg + enc_msglen, taglen );
    }
    else
#endif /* JHD_TLS_GCM_C || JHD_TLS_CCM_C */
#if defined(JHD_TLS_CIPHER_MODE_CBC) &&                                    \
    ( defined(JHD_TLS_AES_C) || defined(JHD_TLS_CAMELLIA_C) || defined(JHD_TLS_ARIA_C) )
    if( mode == JHD_TLS_MODE_CBC )
    {
        int ret;
        unsigned char *enc_msg;
        size_t enc_msglen, padlen, olen = 0, i;

        padlen = ssl->transform_out->ivlen - ( ssl->out_msglen + 1 ) %
                 ssl->transform_out->ivlen;
        if( padlen == ssl->transform_out->ivlen )
            padlen = 0;

        for( i = 0; i <= padlen; i++ )
            ssl->out_msg[ssl->out_msglen + i] = (unsigned char) padlen;

        ssl->out_msglen += padlen + 1;

        enc_msglen = ssl->out_msglen;
        enc_msg = ssl->out_msg;

#if defined(JHD_TLS_SSL_PROTO_TLS1_1) || defined(JHD_TLS_SSL_PROTO_TLS1_2)
        /*
         * Prepend per-record IV for block cipher in TLS v1.1 and up as per
         * Method 1 (6.2.3.2. in RFC4346 and RFC5246)
         */
        if( ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_2 )
        {
            /*
             * Generate IV
             */
            ret = ssl->conf->f_rng( ssl->conf->p_rng, ssl->transform_out->iv_enc,
                                  ssl->transform_out->ivlen );
            if( ret != 0 )
                return( ret );

            memcpy( ssl->out_iv, ssl->transform_out->iv_enc,
                    ssl->transform_out->ivlen );

            /*
             * Fix pointer positions and message length with added IV
             */
            enc_msg = ssl->out_msg;
            enc_msglen = ssl->out_msglen;
            ssl->out_msglen += ssl->transform_out->ivlen;
        }
#endif /* JHD_TLS_SSL_PROTO_TLS1_1 || JHD_TLS_SSL_PROTO_TLS1_2 */

        JHD_TLS_SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
                            "including %d bytes of IV and %d bytes of padding",
                            ssl->out_msglen, ssl->transform_out->ivlen,
                            padlen + 1 ) );

        if( ( ret = jhd_tls_cipher_crypt( &ssl->transform_out->cipher_ctx_enc,
                                   ssl->transform_out->iv_enc,
                                   ssl->transform_out->ivlen,
                                   enc_msg, enc_msglen,
                                   enc_msg, &olen ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_crypt", ret );
            return( ret );
        }

        if( enc_msglen != olen )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1)
        if( ssl->minor_ver < JHD_TLS_SSL_MINOR_VERSION_2 )
        {
            /*
             * Save IV in SSL3 and TLS1
             */
            memcpy( ssl->transform_out->iv_enc,
                    ssl->transform_out->cipher_ctx_enc.iv,
                    ssl->transform_out->ivlen );
        }
#endif

#if defined(JHD_TLS_SSL_ENCRYPT_THEN_MAC)
        if( auth_done == 0 )
        {
            /*
             * MAC(MAC_write_key, seq_num +
             *     TLSCipherText.type +
             *     TLSCipherText.version +
             *     length_of( (IV +) ENC(...) ) +
             *     IV + // except for TLS 1.0
             *     ENC(content + padding + padding_length));
             */
            unsigned char pseudo_hdr[13];

            JHD_TLS_SSL_DEBUG_MSG( 3, ( "using encrypt then mac" ) );

            memcpy( pseudo_hdr +  0, ssl->out_ctr, 8 );
            memcpy( pseudo_hdr +  8, ssl->out_hdr, 3 );
            pseudo_hdr[11] = (unsigned char)( ( ssl->out_msglen >> 8 ) & 0xFF );
            pseudo_hdr[12] = (unsigned char)( ( ssl->out_msglen      ) & 0xFF );

            JHD_TLS_SSL_DEBUG_BUF( 4, "MAC'd meta-data", pseudo_hdr, 13 );

            jhd_tls_md_hmac_update( &ssl->transform_out->md_ctx_enc, pseudo_hdr, 13 );
            jhd_tls_md_hmac_update( &ssl->transform_out->md_ctx_enc,
                             ssl->out_iv, ssl->out_msglen );
            jhd_tls_md_hmac_finish( &ssl->transform_out->md_ctx_enc,
                             ssl->out_iv + ssl->out_msglen );
            jhd_tls_md_hmac_reset( &ssl->transform_out->md_ctx_enc );

            ssl->out_msglen += ssl->transform_out->maclen;
            auth_done++;
        }
#endif /* JHD_TLS_SSL_ENCRYPT_THEN_MAC */
    }
    else
#endif /* JHD_TLS_CIPHER_MODE_CBC &&
          ( JHD_TLS_AES_C || JHD_TLS_CAMELLIA_C || JHD_TLS_ARIA_C ) */
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Make extra sure authentication was performed, exactly once */
    if( auth_done != 1 )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= encrypt buf" ) );

    return( 0 );
}

static int ssl_decrypt_buf( jhd_tls_ssl_context *ssl )
{
    size_t i;
    jhd_tls_cipher_mode_t mode;
    int auth_done = 0;
#if defined(SSL_SOME_MODES_USE_MAC)
    size_t padlen = 0, correct = 1;
#endif

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> decrypt buf" ) );

    if( ssl->session_in == NULL || ssl->transform_in == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

    mode = jhd_tls_cipher_get_cipher_mode( &ssl->transform_in->cipher_ctx_dec );

    if( ssl->in_msglen < ssl->transform_in->minlen )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "in_msglen (%d) < minlen (%d)",
                       ssl->in_msglen, ssl->transform_in->minlen ) );
        return( JHD_TLS_ERR_SSL_INVALID_MAC );
    }

#if defined(JHD_TLS_ARC4_C) || defined(JHD_TLS_CIPHER_NULL_CIPHER)
    if( mode == JHD_TLS_MODE_STREAM )
    {
        int ret;
        size_t olen = 0;

        padlen = 0;

        if( ( ret = jhd_tls_cipher_crypt( &ssl->transform_in->cipher_ctx_dec,
                                   ssl->transform_in->iv_dec,
                                   ssl->transform_in->ivlen,
                                   ssl->in_msg, ssl->in_msglen,
                                   ssl->in_msg, &olen ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_crypt", ret );
            return( ret );
        }

        if( ssl->in_msglen != olen )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
#endif /* JHD_TLS_ARC4_C || JHD_TLS_CIPHER_NULL_CIPHER */
#if defined(JHD_TLS_GCM_C) || defined(JHD_TLS_CCM_C)
    if( mode == JHD_TLS_MODE_GCM ||
        mode == JHD_TLS_MODE_CCM )
    {
        int ret;
        size_t dec_msglen, olen;
        unsigned char *dec_msg;
        unsigned char *dec_msg_result;
        unsigned char add_data[13];
        unsigned char taglen = ssl->transform_in->ciphersuite_info->flags &
                               JHD_TLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;
        size_t explicit_iv_len = ssl->transform_in->ivlen -
                                 ssl->transform_in->fixed_ivlen;

        if( ssl->in_msglen < explicit_iv_len + taglen )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) < explicit_iv_len (%d) "
                                "+ taglen (%d)", ssl->in_msglen,
                                explicit_iv_len, taglen ) );
            return( JHD_TLS_ERR_SSL_INVALID_MAC );
        }
        dec_msglen = ssl->in_msglen - explicit_iv_len - taglen;

        dec_msg = ssl->in_msg;
        dec_msg_result = ssl->in_msg;
        ssl->in_msglen = dec_msglen;

        memcpy( add_data, ssl->in_ctr, 8 );
        add_data[8]  = ssl->in_msgtype;
        jhd_tls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                           ssl->conf->transport, add_data + 9 );
        add_data[11] = ( ssl->in_msglen >> 8 ) & 0xFF;
        add_data[12] = ssl->in_msglen & 0xFF;

        JHD_TLS_SSL_DEBUG_BUF( 4, "additional data used for AEAD",
                       add_data, 13 );

        memcpy( ssl->transform_in->iv_dec + ssl->transform_in->fixed_ivlen,
                ssl->in_iv,
                ssl->transform_in->ivlen - ssl->transform_in->fixed_ivlen );

        JHD_TLS_SSL_DEBUG_BUF( 4, "IV used", ssl->transform_in->iv_dec,
                                     ssl->transform_in->ivlen );
        JHD_TLS_SSL_DEBUG_BUF( 4, "TAG used", dec_msg + dec_msglen, taglen );

        /*
         * Decrypt and authenticate
         */
        if( ( ret = jhd_tls_cipher_auth_decrypt( &ssl->transform_in->cipher_ctx_dec,
                                         ssl->transform_in->iv_dec,
                                         ssl->transform_in->ivlen,
                                         add_data, 13,
                                         dec_msg, dec_msglen,
                                         dec_msg_result, &olen,
                                         dec_msg + dec_msglen, taglen ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_auth_decrypt", ret );

            if( ret == JHD_TLS_ERR_CIPHER_AUTH_FAILED )
                return( JHD_TLS_ERR_SSL_INVALID_MAC );

            return( ret );
        }
        auth_done++;

        if( olen != dec_msglen )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
#endif /* JHD_TLS_GCM_C || JHD_TLS_CCM_C */
#if defined(JHD_TLS_CIPHER_MODE_CBC) &&                                    \
    ( defined(JHD_TLS_AES_C) || defined(JHD_TLS_CAMELLIA_C) || defined(JHD_TLS_ARIA_C) )
    if( mode == JHD_TLS_MODE_CBC )
    {
        /*
         * Decrypt and check the padding
         */
        int ret;
        unsigned char *dec_msg;
        unsigned char *dec_msg_result;
        size_t dec_msglen;
        size_t minlen = 0;
        size_t olen = 0;

        /*
         * Check immediate ciphertext sanity
         */
#if defined(JHD_TLS_SSL_PROTO_TLS1_1) || defined(JHD_TLS_SSL_PROTO_TLS1_2)
        if( ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_2 )
            minlen += ssl->transform_in->ivlen;
#endif

        if( ssl->in_msglen < minlen + ssl->transform_in->ivlen ||
            ssl->in_msglen < minlen + ssl->transform_in->maclen + 1 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) < max( ivlen(%d), maclen (%d) "
                                "+ 1 ) ( + expl IV )", ssl->in_msglen,
                                ssl->transform_in->ivlen,
                                ssl->transform_in->maclen ) );
            return( JHD_TLS_ERR_SSL_INVALID_MAC );
        }

        dec_msglen = ssl->in_msglen;
        dec_msg = ssl->in_msg;
        dec_msg_result = ssl->in_msg;

        /*
         * Authenticate before decrypt if enabled
         */
#if defined(JHD_TLS_SSL_ENCRYPT_THEN_MAC)
        if( ssl->session_in->encrypt_then_mac == JHD_TLS_SSL_ETM_ENABLED )
        {
            unsigned char mac_expect[JHD_TLS_SSL_MAC_ADD];
            unsigned char pseudo_hdr[13];

            JHD_TLS_SSL_DEBUG_MSG( 3, ( "using encrypt then mac" ) );

            dec_msglen -= ssl->transform_in->maclen;
            ssl->in_msglen -= ssl->transform_in->maclen;

            memcpy( pseudo_hdr +  0, ssl->in_ctr, 8 );
            memcpy( pseudo_hdr +  8, ssl->in_hdr, 3 );
            pseudo_hdr[11] = (unsigned char)( ( ssl->in_msglen >> 8 ) & 0xFF );
            pseudo_hdr[12] = (unsigned char)( ( ssl->in_msglen      ) & 0xFF );

            JHD_TLS_SSL_DEBUG_BUF( 4, "MAC'd meta-data", pseudo_hdr, 13 );

            jhd_tls_md_hmac_update( &ssl->transform_in->md_ctx_dec, pseudo_hdr, 13 );
            jhd_tls_md_hmac_update( &ssl->transform_in->md_ctx_dec,
                             ssl->in_iv, ssl->in_msglen );
            jhd_tls_md_hmac_finish( &ssl->transform_in->md_ctx_dec, mac_expect );
            jhd_tls_md_hmac_reset( &ssl->transform_in->md_ctx_dec );

            JHD_TLS_SSL_DEBUG_BUF( 4, "message  mac", ssl->in_iv + ssl->in_msglen,
                                              ssl->transform_in->maclen );
            JHD_TLS_SSL_DEBUG_BUF( 4, "expected mac", mac_expect,
                                              ssl->transform_in->maclen );

            if( jhd_tls_ssl_safer_memcmp( ssl->in_iv + ssl->in_msglen, mac_expect,
                                          ssl->transform_in->maclen ) != 0 )
            {
                JHD_TLS_SSL_DEBUG_MSG( 1, ( "message mac does not match" ) );

                return( JHD_TLS_ERR_SSL_INVALID_MAC );
            }
            auth_done++;
        }
#endif /* JHD_TLS_SSL_ENCRYPT_THEN_MAC */

        /*
         * Check length sanity
         */
        if( ssl->in_msglen % ssl->transform_in->ivlen != 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) %% ivlen (%d) != 0",
                           ssl->in_msglen, ssl->transform_in->ivlen ) );
            return( JHD_TLS_ERR_SSL_INVALID_MAC );
        }

#if defined(JHD_TLS_SSL_PROTO_TLS1_1) || defined(JHD_TLS_SSL_PROTO_TLS1_2)
        /*
         * Initialize for prepended IV for block cipher in TLS v1.1 and up
         */
        if( ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_2 )
        {
            dec_msglen -= ssl->transform_in->ivlen;
            ssl->in_msglen -= ssl->transform_in->ivlen;

            for( i = 0; i < ssl->transform_in->ivlen; i++ )
                ssl->transform_in->iv_dec[i] = ssl->in_iv[i];
        }
#endif /* JHD_TLS_SSL_PROTO_TLS1_1 || JHD_TLS_SSL_PROTO_TLS1_2 */

        if( ( ret = jhd_tls_cipher_crypt( &ssl->transform_in->cipher_ctx_dec,
                                   ssl->transform_in->iv_dec,
                                   ssl->transform_in->ivlen,
                                   dec_msg, dec_msglen,
                                   dec_msg_result, &olen ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_cipher_crypt", ret );
            return( ret );
        }

        if( dec_msglen != olen )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1)
        if( ssl->minor_ver < JHD_TLS_SSL_MINOR_VERSION_2 )
        {
            /*
             * Save IV in SSL3 and TLS1
             */
            memcpy( ssl->transform_in->iv_dec,
                    ssl->transform_in->cipher_ctx_dec.iv,
                    ssl->transform_in->ivlen );
        }
#endif

        padlen = 1 + ssl->in_msg[ssl->in_msglen - 1];

        if( ssl->in_msglen < ssl->transform_in->maclen + padlen &&
            auth_done == 0 )
        {
#if defined(JHD_TLS_SSL_DEBUG_ALL)
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "msglen (%d) < maclen (%d) + padlen (%d)",
                        ssl->in_msglen, ssl->transform_in->maclen, padlen ) );
#endif
            padlen = 0;
            correct = 0;
        }

#if defined(JHD_TLS_SSL_PROTO_SSL3)
        if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 )
        {
            if( padlen > ssl->transform_in->ivlen )
            {
#if defined(JHD_TLS_SSL_DEBUG_ALL)
                JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad padding length: is %d, "
                                    "should be no more than %d",
                               padlen, ssl->transform_in->ivlen ) );
#endif
                correct = 0;
            }
        }
        else
#endif /* JHD_TLS_SSL_PROTO_SSL3 */
#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_2)
        if( ssl->minor_ver > JHD_TLS_SSL_MINOR_VERSION_0 )
        {
            /*
             * TLSv1+: always check the padding up to the first failure
             * and fake check up to 256 bytes of padding
             */
            size_t pad_count = 0, real_count = 1;
            size_t padding_idx = ssl->in_msglen - padlen - 1;

            /*
             * Padding is guaranteed to be incorrect if:
             *   1. padlen >= ssl->in_msglen
             *
             *   2. padding_idx >= JHD_TLS_SSL_MAX_CONTENT_LEN +
             *                     ssl->transform_in->maclen
             *
             * In both cases we reset padding_idx to a safe value (0) to
             * prevent out-of-buffer reads.
             */
            correct &= ( ssl->in_msglen >= padlen + 1 );
            correct &= ( padding_idx < JHD_TLS_SSL_MAX_CONTENT_LEN +
                                       ssl->transform_in->maclen );

            padding_idx *= correct;

            for( i = 1; i <= 256; i++ )
            {
                real_count &= ( i <= padlen );
                pad_count += real_count *
                             ( ssl->in_msg[padding_idx + i] == padlen - 1 );
            }

            correct &= ( pad_count == padlen ); /* Only 1 on correct padding */

#if defined(JHD_TLS_SSL_DEBUG_ALL)
            if( padlen > 0 && correct == 0 )
                JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad padding byte detected" ) );
#endif
            padlen &= correct * 0x1FF;
        }
        else
#endif /* JHD_TLS_SSL_PROTO_TLS1 || JHD_TLS_SSL_PROTO_TLS1_1 || \
          JHD_TLS_SSL_PROTO_TLS1_2 */
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

        ssl->in_msglen -= padlen;
    }
    else
#endif /* JHD_TLS_CIPHER_MODE_CBC &&
          ( JHD_TLS_AES_C || JHD_TLS_CAMELLIA_C || JHD_TLS_ARIA_C ) */
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

    JHD_TLS_SSL_DEBUG_BUF( 4, "raw buffer after decryption",
                   ssl->in_msg, ssl->in_msglen );

    /*
     * Authenticate if not done yet.
     * Compute the MAC regardless of the padding result (RFC4346, CBCTIME).
     */
#if defined(SSL_SOME_MODES_USE_MAC)
    if( auth_done == 0 )
    {
        unsigned char mac_expect[JHD_TLS_SSL_MAC_ADD];

        ssl->in_msglen -= ssl->transform_in->maclen;

        ssl->in_len[0] = (unsigned char)( ssl->in_msglen >> 8 );
        ssl->in_len[1] = (unsigned char)( ssl->in_msglen      );

#if defined(JHD_TLS_SSL_PROTO_SSL3)
        if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 )
        {
            ssl_mac( &ssl->transform_in->md_ctx_dec,
                      ssl->transform_in->mac_dec,
                      ssl->in_msg, ssl->in_msglen,
                      ssl->in_ctr, ssl->in_msgtype,
                      mac_expect );
        }
        else
#endif /* JHD_TLS_SSL_PROTO_SSL3 */
#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1) || \
        defined(JHD_TLS_SSL_PROTO_TLS1_2)
        if( ssl->minor_ver > JHD_TLS_SSL_MINOR_VERSION_0 )
        {
            /*
             * Process MAC and always update for padlen afterwards to make
             * total time independent of padlen
             *
             * extra_run compensates MAC check for padlen
             *
             * Known timing attacks:
             *  - Lucky Thirteen (http://www.isg.rhul.ac.uk/tls/TLStiming.pdf)
             *
             * We use ( ( Lx + 8 ) / 64 ) to handle 'negative Lx' values
             * correctly. (We round down instead of up, so -56 is the correct
             * value for our calculations instead of -55)
             */
            size_t j, extra_run = 0;
            extra_run = ( 13 + ssl->in_msglen + padlen + 8 ) / 64 -
                        ( 13 + ssl->in_msglen          + 8 ) / 64;

            extra_run &= correct * 0xFF;

            jhd_tls_md_hmac_update( &ssl->transform_in->md_ctx_dec, ssl->in_ctr, 8 );
            jhd_tls_md_hmac_update( &ssl->transform_in->md_ctx_dec, ssl->in_hdr, 3 );
            jhd_tls_md_hmac_update( &ssl->transform_in->md_ctx_dec, ssl->in_len, 2 );
            jhd_tls_md_hmac_update( &ssl->transform_in->md_ctx_dec, ssl->in_msg,
                             ssl->in_msglen );
            jhd_tls_md_hmac_finish( &ssl->transform_in->md_ctx_dec, mac_expect );
            /* Call jhd_tls_md_process at least once due to cache attacks */
            for( j = 0; j < extra_run + 1; j++ )
                jhd_tls_md_process( &ssl->transform_in->md_ctx_dec, ssl->in_msg );

            jhd_tls_md_hmac_reset( &ssl->transform_in->md_ctx_dec );
        }
        else
#endif /* JHD_TLS_SSL_PROTO_TLS1 || JHD_TLS_SSL_PROTO_TLS1_1 || \
              JHD_TLS_SSL_PROTO_TLS1_2 */
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

        JHD_TLS_SSL_DEBUG_BUF( 4, "expected mac", mac_expect, ssl->transform_in->maclen );
        JHD_TLS_SSL_DEBUG_BUF( 4, "message  mac", ssl->in_msg + ssl->in_msglen,
                               ssl->transform_in->maclen );

        if( jhd_tls_ssl_safer_memcmp( ssl->in_msg + ssl->in_msglen, mac_expect,
                                      ssl->transform_in->maclen ) != 0 )
        {
#if defined(JHD_TLS_SSL_DEBUG_ALL)
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "message mac does not match" ) );
#endif
            correct = 0;
        }
        auth_done++;

        /*
         * Finally check the correct flag
         */
        if( correct == 0 )
            return( JHD_TLS_ERR_SSL_INVALID_MAC );
    }
#endif /* SSL_SOME_MODES_USE_MAC */

    /* Make extra sure authentication was performed, exactly once */
    if( auth_done != 1 )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( ssl->in_msglen == 0 )
    {
        ssl->nb_zero++;

        /*
         * Three or more empty messages may be a DoS attack
         * (excessive CPU consumption).
         */
        if( ssl->nb_zero > 3 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "received four consecutive empty "
                                "messages, possible DoS attack" ) );
            return( JHD_TLS_ERR_SSL_INVALID_MAC );
        }
    }
    else
        ssl->nb_zero = 0;

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        ; /* in_ctr read from peer, not maintained internally */
    }
    else
#endif
    {
        for( i = 8; i > ssl_ep_len( ssl ); i-- )
            if( ++ssl->in_ctr[i - 1] != 0 )
                break;

        /* The loop goes to its end iff the counter is wrapping */
        if( i == ssl_ep_len( ssl ) )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "incoming message counter would wrap" ) );
            return( JHD_TLS_ERR_SSL_COUNTER_WRAPPING );
        }
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= decrypt buf" ) );

    return( 0 );
}

#undef MAC_NONE
#undef MAC_PLAINTEXT
#undef MAC_CIPHERTEXT

#if defined(JHD_TLS_ZLIB_SUPPORT)
/*
 * Compression/decompression functions
 */
static int ssl_compress_buf( jhd_tls_ssl_context *ssl )
{
    int ret;
    unsigned char *msg_post = ssl->out_msg;
    ptrdiff_t bytes_written = ssl->out_msg - ssl->out_buf;
    size_t len_pre = ssl->out_msglen;
    unsigned char *msg_pre = ssl->compress_buf;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> compress buf" ) );

    if( len_pre == 0 )
        return( 0 );

    memcpy( msg_pre, ssl->out_msg, len_pre );

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "before compression: msglen = %d, ",
                   ssl->out_msglen ) );

    JHD_TLS_SSL_DEBUG_BUF( 4, "before compression: output payload",
                   ssl->out_msg, ssl->out_msglen );

    ssl->transform_out->ctx_deflate.next_in = msg_pre;
    ssl->transform_out->ctx_deflate.avail_in = len_pre;
    ssl->transform_out->ctx_deflate.next_out = msg_post;
    ssl->transform_out->ctx_deflate.avail_out = JHD_TLS_SSL_BUFFER_LEN - bytes_written;

    ret = deflate( &ssl->transform_out->ctx_deflate, Z_SYNC_FLUSH );
    if( ret != Z_OK )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "failed to perform compression (%d)", ret ) );
        return( JHD_TLS_ERR_SSL_COMPRESSION_FAILED );
    }

    ssl->out_msglen = JHD_TLS_SSL_BUFFER_LEN -
                      ssl->transform_out->ctx_deflate.avail_out - bytes_written;

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "after compression: msglen = %d, ",
                   ssl->out_msglen ) );

    JHD_TLS_SSL_DEBUG_BUF( 4, "after compression: output payload",
                   ssl->out_msg, ssl->out_msglen );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= compress buf" ) );

    return( 0 );
}

static int ssl_decompress_buf( jhd_tls_ssl_context *ssl )
{
    int ret;
    unsigned char *msg_post = ssl->in_msg;
    ptrdiff_t header_bytes = ssl->in_msg - ssl->in_buf;
    size_t len_pre = ssl->in_msglen;
    unsigned char *msg_pre = ssl->compress_buf;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> decompress buf" ) );

    if( len_pre == 0 )
        return( 0 );

    memcpy( msg_pre, ssl->in_msg, len_pre );

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "before decompression: msglen = %d, ",
                   ssl->in_msglen ) );

    JHD_TLS_SSL_DEBUG_BUF( 4, "before decompression: input payload",
                   ssl->in_msg, ssl->in_msglen );

    ssl->transform_in->ctx_inflate.next_in = msg_pre;
    ssl->transform_in->ctx_inflate.avail_in = len_pre;
    ssl->transform_in->ctx_inflate.next_out = msg_post;
    ssl->transform_in->ctx_inflate.avail_out = JHD_TLS_SSL_BUFFER_LEN -
                                               header_bytes;

    ret = inflate( &ssl->transform_in->ctx_inflate, Z_SYNC_FLUSH );
    if( ret != Z_OK )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "failed to perform decompression (%d)", ret ) );
        return( JHD_TLS_ERR_SSL_COMPRESSION_FAILED );
    }

    ssl->in_msglen = JHD_TLS_SSL_BUFFER_LEN -
                     ssl->transform_in->ctx_inflate.avail_out - header_bytes;

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "after decompression: msglen = %d, ",
                   ssl->in_msglen ) );

    JHD_TLS_SSL_DEBUG_BUF( 4, "after decompression: input payload",
                   ssl->in_msg, ssl->in_msglen );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= decompress buf" ) );

    return( 0 );
}
#endif /* JHD_TLS_ZLIB_SUPPORT */

#if defined(JHD_TLS_SSL_SRV_C) && defined(JHD_TLS_SSL_RENEGOTIATION)
static int ssl_write_hello_request( jhd_tls_ssl_context *ssl );

#if defined(JHD_TLS_SSL_PROTO_DTLS)
static int ssl_resend_hello_request( jhd_tls_ssl_context *ssl )
{
    /* If renegotiation is not enforced, retransmit until we would reach max
     * timeout if we were using the usual handshake doubling scheme */
    if( ssl->conf->renego_max_records < 0 )
    {
        uint32_t ratio = ssl->conf->hs_timeout_max / ssl->conf->hs_timeout_min + 1;
        unsigned char doublings = 1;

        while( ratio != 0 )
        {
            ++doublings;
            ratio >>= 1;
        }

        if( ++ssl->renego_records_seen > doublings )
        {
            JHD_TLS_SSL_DEBUG_MSG( 2, ( "no longer retransmitting hello request" ) );
            return( 0 );
        }
    }

    return( ssl_write_hello_request( ssl ) );
}
#endif
#endif /* JHD_TLS_SSL_SRV_C && JHD_TLS_SSL_RENEGOTIATION */

/*
 * Fill the input message buffer by appending data to it.
 * The amount of data already fetched is in ssl->in_left.
 *
 * If we return 0, is it guaranteed that (at least) nb_want bytes are
 * available (from this read and/or a previous one). Otherwise, an error code
 * is returned (possibly EOF or WANT_READ).
 *
 * With stream transport (TLS) on success ssl->in_left == nb_want, but
 * with datagram transport (DTLS) on success ssl->in_left >= nb_want,
 * since we always read a whole datagram at once.
 *
 * For DTLS, it is up to the caller to set ssl->next_record_offset when
 * they're done reading a record.
 */
int jhd_tls_ssl_fetch_input( jhd_tls_ssl_context *ssl, size_t nb_want )
{
    int ret;
    size_t len;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> fetch input" ) );

    if( ssl->f_recv == NULL && ssl->f_recv_timeout == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "Bad usage of jhd_tls_ssl_set_bio() "
                            "or jhd_tls_ssl_set_bio()" ) );
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

    if( nb_want > JHD_TLS_SSL_BUFFER_LEN - (size_t)( ssl->in_hdr - ssl->in_buf ) )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "requesting more data than fits" ) );
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        uint32_t timeout;

        /* Just to be sure */
        if( ssl->f_set_timer == NULL || ssl->f_get_timer == NULL )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "You must use "
                        "jhd_tls_ssl_set_timer_cb() for DTLS" ) );
            return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
        }

        /*
         * The point is, we need to always read a full datagram at once, so we
         * sometimes read more then requested, and handle the additional data.
         * It could be the rest of the current record (while fetching the
         * header) and/or some other records in the same datagram.
         */

        /*
         * Move to the next record in the already read datagram if applicable
         */
        if( ssl->next_record_offset != 0 )
        {
            if( ssl->in_left < ssl->next_record_offset )
            {
                JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
            }

            ssl->in_left -= ssl->next_record_offset;

            if( ssl->in_left != 0 )
            {
                JHD_TLS_SSL_DEBUG_MSG( 2, ( "next record in same datagram, offset: %d",
                                    ssl->next_record_offset ) );
                memmove( ssl->in_hdr,
                         ssl->in_hdr + ssl->next_record_offset,
                         ssl->in_left );
            }

            ssl->next_record_offset = 0;
        }

        JHD_TLS_SSL_DEBUG_MSG( 2, ( "in_left: %d, nb_want: %d",
                       ssl->in_left, nb_want ) );

        /*
         * Done if we already have enough data.
         */
        if( nb_want <= ssl->in_left)
        {
            JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= fetch input" ) );
            return( 0 );
        }

        /*
         * A record can't be split accross datagrams. If we need to read but
         * are not at the beginning of a new record, the caller did something
         * wrong.
         */
        if( ssl->in_left != 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

        /*
         * Don't even try to read if time's out already.
         * This avoids by-passing the timer when repeatedly receiving messages
         * that will end up being dropped.
         */
        if( ssl_check_timer( ssl ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 2, ( "timer has expired" ) );
            ret = JHD_TLS_ERR_SSL_TIMEOUT;
        }
        else
        {
            len = JHD_TLS_SSL_BUFFER_LEN - ( ssl->in_hdr - ssl->in_buf );

            if( ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER )
                timeout = ssl->handshake->retransmit_timeout;
            else
                timeout = ssl->conf->read_timeout;

            JHD_TLS_SSL_DEBUG_MSG( 3, ( "f_recv_timeout: %u ms", timeout ) );

            if( ssl->f_recv_timeout != NULL )
                ret = ssl->f_recv_timeout( ssl->p_bio, ssl->in_hdr, len,
                                                                    timeout );
            else
                ret = ssl->f_recv( ssl->p_bio, ssl->in_hdr, len );

            JHD_TLS_SSL_DEBUG_RET( 2, "ssl->f_recv(_timeout)", ret );

            if( ret == 0 )
                return( JHD_TLS_ERR_SSL_CONN_EOF );
        }

        if( ret == JHD_TLS_ERR_SSL_TIMEOUT )
        {
            JHD_TLS_SSL_DEBUG_MSG( 2, ( "timeout" ) );
            ssl_set_timer( ssl, 0 );

            if( ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER )
            {
                if( ssl_double_retransmit_timeout( ssl ) != 0 )
                {
                    JHD_TLS_SSL_DEBUG_MSG( 1, ( "handshake timeout" ) );
                    return( JHD_TLS_ERR_SSL_TIMEOUT );
                }

                if( ( ret = jhd_tls_ssl_resend( ssl ) ) != 0 )
                {
                    JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_resend", ret );
                    return( ret );
                }

                return( JHD_TLS_ERR_SSL_WANT_READ );
            }
#if defined(JHD_TLS_SSL_SRV_C) && defined(JHD_TLS_SSL_RENEGOTIATION)
            else if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER &&
                     ssl->renego_status == JHD_TLS_SSL_RENEGOTIATION_PENDING )
            {
                if( ( ret = ssl_resend_hello_request( ssl ) ) != 0 )
                {
                    JHD_TLS_SSL_DEBUG_RET( 1, "ssl_resend_hello_request", ret );
                    return( ret );
                }

                return( JHD_TLS_ERR_SSL_WANT_READ );
            }
#endif /* JHD_TLS_SSL_SRV_C && JHD_TLS_SSL_RENEGOTIATION */
        }

        if( ret < 0 )
            return( ret );

        ssl->in_left = ret;
    }
    else
#endif
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "in_left: %d, nb_want: %d",
                       ssl->in_left, nb_want ) );

        while( ssl->in_left < nb_want )
        {
            len = nb_want - ssl->in_left;

            if( ssl_check_timer( ssl ) != 0 )
                ret = JHD_TLS_ERR_SSL_TIMEOUT;
            else
            {
                if( ssl->f_recv_timeout != NULL )
                {
                    ret = ssl->f_recv_timeout( ssl->p_bio,
                                               ssl->in_hdr + ssl->in_left, len,
                                               ssl->conf->read_timeout );
                }
                else
                {
                    ret = ssl->f_recv( ssl->p_bio,
                                       ssl->in_hdr + ssl->in_left, len );
                }
            }

            JHD_TLS_SSL_DEBUG_MSG( 2, ( "in_left: %d, nb_want: %d",
                                        ssl->in_left, nb_want ) );
            JHD_TLS_SSL_DEBUG_RET( 2, "ssl->f_recv(_timeout)", ret );

            if( ret == 0 )
                return( JHD_TLS_ERR_SSL_CONN_EOF );

            if( ret < 0 )
                return( ret );

            if ( (size_t)ret > len || ( INT_MAX > SIZE_MAX && ret > SIZE_MAX ) )
            {
                JHD_TLS_SSL_DEBUG_MSG( 1,
                    ( "f_recv returned %d bytes but only %lu were requested",
                    ret, (unsigned long)len ) );
                return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
            }

            ssl->in_left += ret;
        }
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= fetch input" ) );

    return( 0 );
}

/*
 * Flush any data not yet written
 */
int jhd_tls_ssl_flush_output( jhd_tls_ssl_context *ssl )
{
    int ret;
    unsigned char *buf, i;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> flush output" ) );

    if( ssl->f_send == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "Bad usage of jhd_tls_ssl_set_bio() "
                            "or jhd_tls_ssl_set_bio()" ) );
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

    /* Avoid incrementing counter if data is flushed */
    if( ssl->out_left == 0 )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= flush output" ) );
        return( 0 );
    }

    while( ssl->out_left > 0 )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "message length: %d, out_left: %d",
                       jhd_tls_ssl_hdr_len( ssl ) + ssl->out_msglen, ssl->out_left ) );

        buf = ssl->out_hdr + jhd_tls_ssl_hdr_len( ssl ) +
              ssl->out_msglen - ssl->out_left;
        ret = ssl->f_send( ssl->p_bio, buf, ssl->out_left );

        JHD_TLS_SSL_DEBUG_RET( 2, "ssl->f_send", ret );

        if( ret <= 0 )
            return( ret );

        if( (size_t)ret > ssl->out_left || ( INT_MAX > SIZE_MAX && ret > SIZE_MAX ) )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1,
                ( "f_send returned %d bytes but only %lu bytes were sent",
                ret, (unsigned long)ssl->out_left ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

        ssl->out_left -= ret;
    }

    for( i = 8; i > ssl_ep_len( ssl ); i-- )
        if( ++ssl->out_ctr[i - 1] != 0 )
            break;

    /* The loop goes to its end iff the counter is wrapping */
    if( i == ssl_ep_len( ssl ) )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "outgoing message counter would wrap" ) );
        return( JHD_TLS_ERR_SSL_COUNTER_WRAPPING );
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= flush output" ) );

    return( 0 );
}

/*
 * Functions to handle the DTLS retransmission state machine
 */
#if defined(JHD_TLS_SSL_PROTO_DTLS)
/*
 * Append current handshake message to current outgoing flight
 */
static int ssl_flight_append( jhd_tls_ssl_context *ssl )
{
    jhd_tls_ssl_flight_item *msg;

    /* Allocate space for current message */
    if( ( msg = jhd_tls_calloc( 1, sizeof(  jhd_tls_ssl_flight_item ) ) ) == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "alloc %d bytes failed",
                            sizeof( jhd_tls_ssl_flight_item ) ) );
        return( JHD_TLS_ERR_SSL_ALLOC_FAILED );
    }

    if( ( msg->p = jhd_tls_calloc( 1, ssl->out_msglen ) ) == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "alloc %d bytes failed", ssl->out_msglen ) );
        jhd_tls_free( msg );
        return( JHD_TLS_ERR_SSL_ALLOC_FAILED );
    }

    /* Copy current handshake message with headers */
    memcpy( msg->p, ssl->out_msg, ssl->out_msglen );
    msg->len = ssl->out_msglen;
    msg->type = ssl->out_msgtype;
    msg->next = NULL;

    /* Append to the current flight */
    if( ssl->handshake->flight == NULL )
        ssl->handshake->flight = msg;
    else
    {
        jhd_tls_ssl_flight_item *cur = ssl->handshake->flight;
        while( cur->next != NULL )
            cur = cur->next;
        cur->next = msg;
    }

    return( 0 );
}

/*
 * Free the current flight of handshake messages
 */
static void ssl_flight_free( jhd_tls_ssl_flight_item *flight )
{
    jhd_tls_ssl_flight_item *cur = flight;
    jhd_tls_ssl_flight_item *next;

    while( cur != NULL )
    {
        next = cur->next;

        jhd_tls_free( cur->p );
        jhd_tls_free( cur );

        cur = next;
    }
}

#if defined(JHD_TLS_SSL_DTLS_ANTI_REPLAY)
static void ssl_dtls_replay_reset( jhd_tls_ssl_context *ssl );
#endif

/*
 * Swap transform_out and out_ctr with the alternative ones
 */
static void ssl_swap_epochs( jhd_tls_ssl_context *ssl )
{
    jhd_tls_ssl_transform *tmp_transform;
    unsigned char tmp_out_ctr[8];

    if( ssl->transform_out == ssl->handshake->alt_transform_out )
    {
        JHD_TLS_SSL_DEBUG_MSG( 3, ( "skip swap epochs" ) );
        return;
    }

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "swap epochs" ) );

    /* Swap transforms */
    tmp_transform                     = ssl->transform_out;
    ssl->transform_out                = ssl->handshake->alt_transform_out;
    ssl->handshake->alt_transform_out = tmp_transform;

    /* Swap epoch + sequence_number */
    memcpy( tmp_out_ctr,                 ssl->out_ctr,                8 );
    memcpy( ssl->out_ctr,                ssl->handshake->alt_out_ctr, 8 );
    memcpy( ssl->handshake->alt_out_ctr, tmp_out_ctr,                 8 );

    /* Adjust to the newly activated transform */
    if( ssl->transform_out != NULL &&
        ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_2 )
    {
        ssl->out_msg = ssl->out_iv + ssl->transform_out->ivlen -
                                     ssl->transform_out->fixed_ivlen;
    }
    else
        ssl->out_msg = ssl->out_iv;

#if defined(JHD_TLS_SSL_HW_RECORD_ACCEL)
    if( jhd_tls_ssl_hw_record_activate != NULL )
    {
        if( ( ret = jhd_tls_ssl_hw_record_activate( ssl, JHD_TLS_SSL_CHANNEL_OUTBOUND ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_hw_record_activate", ret );
            return( JHD_TLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif
}

/*
 * Retransmit the current flight of messages.
 *
 * Need to remember the current message in case flush_output returns
 * WANT_WRITE, causing us to exit this function and come back later.
 * This function must be called until state is no longer SENDING.
 */
int jhd_tls_ssl_resend( jhd_tls_ssl_context *ssl )
{
    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> jhd_tls_ssl_resend" ) );

    if( ssl->handshake->retransmit_state != JHD_TLS_SSL_RETRANS_SENDING )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "initialise resending" ) );

        ssl->handshake->cur_msg = ssl->handshake->flight;
        ssl_swap_epochs( ssl );

        ssl->handshake->retransmit_state = JHD_TLS_SSL_RETRANS_SENDING;
    }

    while( ssl->handshake->cur_msg != NULL )
    {
        int ret;
        jhd_tls_ssl_flight_item *cur = ssl->handshake->cur_msg;

        /* Swap epochs before sending Finished: we can't do it after
         * sending ChangeCipherSpec, in case write returns WANT_READ.
         * Must be done before copying, may change out_msg pointer */
        if( cur->type == JHD_TLS_SSL_MSG_HANDSHAKE &&
            cur->p[0] == JHD_TLS_SSL_HS_FINISHED )
        {
            ssl_swap_epochs( ssl );
        }

        memcpy( ssl->out_msg, cur->p, cur->len );
        ssl->out_msglen = cur->len;
        ssl->out_msgtype = cur->type;

        ssl->handshake->cur_msg = cur->next;

        JHD_TLS_SSL_DEBUG_BUF( 3, "resent handshake message header", ssl->out_msg, 12 );

        if( ( ret = jhd_tls_ssl_write_record( ssl ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_write_record", ret );
            return( ret );
        }
    }

    if( ssl->state == JHD_TLS_SSL_HANDSHAKE_OVER )
        ssl->handshake->retransmit_state = JHD_TLS_SSL_RETRANS_FINISHED;
    else
    {
        ssl->handshake->retransmit_state = JHD_TLS_SSL_RETRANS_WAITING;
        ssl_set_timer( ssl, ssl->handshake->retransmit_timeout );
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= jhd_tls_ssl_resend" ) );

    return( 0 );
}

/*
 * To be called when the last message of an incoming flight is received.
 */
void jhd_tls_ssl_recv_flight_completed( jhd_tls_ssl_context *ssl )
{
    /* We won't need to resend that one any more */
    ssl_flight_free( ssl->handshake->flight );
    ssl->handshake->flight = NULL;
    ssl->handshake->cur_msg = NULL;

    /* The next incoming flight will start with this msg_seq */
    ssl->handshake->in_flight_start_seq = ssl->handshake->in_msg_seq;

    /* Cancel timer */
    ssl_set_timer( ssl, 0 );

    if( ssl->in_msgtype == JHD_TLS_SSL_MSG_HANDSHAKE &&
        ssl->in_msg[0] == JHD_TLS_SSL_HS_FINISHED )
    {
        ssl->handshake->retransmit_state = JHD_TLS_SSL_RETRANS_FINISHED;
    }
    else
        ssl->handshake->retransmit_state = JHD_TLS_SSL_RETRANS_PREPARING;
}

/*
 * To be called when the last message of an outgoing flight is send.
 */
void jhd_tls_ssl_send_flight_completed( jhd_tls_ssl_context *ssl )
{
    ssl_reset_retransmit_timeout( ssl );
    ssl_set_timer( ssl, ssl->handshake->retransmit_timeout );

    if( ssl->in_msgtype == JHD_TLS_SSL_MSG_HANDSHAKE &&
        ssl->in_msg[0] == JHD_TLS_SSL_HS_FINISHED )
    {
        ssl->handshake->retransmit_state = JHD_TLS_SSL_RETRANS_FINISHED;
    }
    else
        ssl->handshake->retransmit_state = JHD_TLS_SSL_RETRANS_WAITING;
}
#endif /* JHD_TLS_SSL_PROTO_DTLS */

/*
 * Record layer functions
 */

/*
 * Write current record.
 * Uses ssl->out_msgtype, ssl->out_msglen and bytes at ssl->out_msg.
 */
int jhd_tls_ssl_write_record( jhd_tls_ssl_context *ssl )
{
    int ret, done = 0, out_msg_type;
    size_t len = ssl->out_msglen;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> write record" ) );

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL &&
        ssl->handshake->retransmit_state == JHD_TLS_SSL_RETRANS_SENDING )
    {
        ; /* Skip special handshake treatment when resending */
    }
    else
#endif
    if( ssl->out_msgtype == JHD_TLS_SSL_MSG_HANDSHAKE )
    {
        out_msg_type = ssl->out_msg[0];

        if( out_msg_type != JHD_TLS_SSL_HS_HELLO_REQUEST &&
            ssl->handshake == NULL )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

        ssl->out_msg[1] = (unsigned char)( ( len - 4 ) >> 16 );
        ssl->out_msg[2] = (unsigned char)( ( len - 4 ) >>  8 );
        ssl->out_msg[3] = (unsigned char)( ( len - 4 )       );

        /*
         * DTLS has additional fields in the Handshake layer,
         * between the length field and the actual payload:
         *      uint16 message_seq;
         *      uint24 fragment_offset;
         *      uint24 fragment_length;
         */
#if defined(JHD_TLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
        {
            /* Make room for the additional DTLS fields */
            if( JHD_TLS_SSL_MAX_CONTENT_LEN - ssl->out_msglen < 8 )
            {
                JHD_TLS_SSL_DEBUG_MSG( 1, ( "DTLS handshake message too large: "
                              "size %u, maximum %u",
                               (unsigned) ( ssl->in_hslen - 4 ),
                               (unsigned) ( JHD_TLS_SSL_MAX_CONTENT_LEN - 12 ) ) );
                return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
            }

            memmove( ssl->out_msg + 12, ssl->out_msg + 4, len - 4 );
            ssl->out_msglen += 8;
            len += 8;

            /* Write message_seq and update it, except for HelloRequest */
            if( out_msg_type != JHD_TLS_SSL_HS_HELLO_REQUEST )
            {
                ssl->out_msg[4] = ( ssl->handshake->out_msg_seq >> 8 ) & 0xFF;
                ssl->out_msg[5] = ( ssl->handshake->out_msg_seq      ) & 0xFF;
                ++( ssl->handshake->out_msg_seq );
            }
            else
            {
                ssl->out_msg[4] = 0;
                ssl->out_msg[5] = 0;
            }

            /* We don't fragment, so frag_offset = 0 and frag_len = len */
            memset( ssl->out_msg + 6, 0x00, 3 );
            memcpy( ssl->out_msg + 9, ssl->out_msg + 1, 3 );
        }
#endif /* JHD_TLS_SSL_PROTO_DTLS */

        if( out_msg_type != JHD_TLS_SSL_HS_HELLO_REQUEST )
            ssl->handshake->update_checksum( ssl, ssl->out_msg, len );
    }

    /* Save handshake and CCS messages for resending */
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL &&
        ssl->handshake->retransmit_state != JHD_TLS_SSL_RETRANS_SENDING &&
        ( ssl->out_msgtype == JHD_TLS_SSL_MSG_CHANGE_CIPHER_SPEC ||
          ssl->out_msgtype == JHD_TLS_SSL_MSG_HANDSHAKE ) )
    {
        if( ( ret = ssl_flight_append( ssl ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "ssl_flight_append", ret );
            return( ret );
        }
    }
#endif

#if defined(JHD_TLS_ZLIB_SUPPORT)
    if( ssl->transform_out != NULL &&
        ssl->session_out->compression == JHD_TLS_SSL_COMPRESS_DEFLATE )
    {
        if( ( ret = ssl_compress_buf( ssl ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "ssl_compress_buf", ret );
            return( ret );
        }

        len = ssl->out_msglen;
    }
#endif /*JHD_TLS_ZLIB_SUPPORT */

#if defined(JHD_TLS_SSL_HW_RECORD_ACCEL)
    if( jhd_tls_ssl_hw_record_write != NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "going for jhd_tls_ssl_hw_record_write()" ) );

        ret = jhd_tls_ssl_hw_record_write( ssl );
        if( ret != 0 && ret != JHD_TLS_ERR_SSL_HW_ACCEL_FALLTHROUGH )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_hw_record_write", ret );
            return( JHD_TLS_ERR_SSL_HW_ACCEL_FAILED );
        }

        if( ret == 0 )
            done = 1;
    }
#endif /* JHD_TLS_SSL_HW_RECORD_ACCEL */
    if( !done )
    {
        ssl->out_hdr[0] = (unsigned char) ssl->out_msgtype;
        jhd_tls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                           ssl->conf->transport, ssl->out_hdr + 1 );

        ssl->out_len[0] = (unsigned char)( len >> 8 );
        ssl->out_len[1] = (unsigned char)( len      );

        if( ssl->transform_out != NULL )
        {
            if( ( ret = ssl_encrypt_buf( ssl ) ) != 0 )
            {
                JHD_TLS_SSL_DEBUG_RET( 1, "ssl_encrypt_buf", ret );
                return( ret );
            }

            len = ssl->out_msglen;
            ssl->out_len[0] = (unsigned char)( len >> 8 );
            ssl->out_len[1] = (unsigned char)( len      );
        }

        ssl->out_left = jhd_tls_ssl_hdr_len( ssl ) + ssl->out_msglen;

        JHD_TLS_SSL_DEBUG_MSG( 3, ( "output record: msgtype = %d, "
                            "version = [%d:%d], msglen = %d",
                       ssl->out_hdr[0], ssl->out_hdr[1], ssl->out_hdr[2],
                     ( ssl->out_len[0] << 8 ) | ssl->out_len[1] ) );

        JHD_TLS_SSL_DEBUG_BUF( 4, "output record sent to network",
                       ssl->out_hdr, jhd_tls_ssl_hdr_len( ssl ) + ssl->out_msglen );
    }

    if( ( ret = jhd_tls_ssl_flush_output( ssl ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_flush_output", ret );
        return( ret );
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= write record" ) );

    return( 0 );
}

#if defined(JHD_TLS_SSL_PROTO_DTLS)
/*
 * Mark bits in bitmask (used for DTLS HS reassembly)
 */
static void ssl_bitmask_set( unsigned char *mask, size_t offset, size_t len )
{
    unsigned int start_bits, end_bits;

    start_bits = 8 - ( offset % 8 );
    if( start_bits != 8 )
    {
        size_t first_byte_idx = offset / 8;

        /* Special case */
        if( len <= start_bits )
        {
            for( ; len != 0; len-- )
                mask[first_byte_idx] |= 1 << ( start_bits - len );

            /* Avoid potential issues with offset or len becoming invalid */
            return;
        }

        offset += start_bits; /* Now offset % 8 == 0 */
        len -= start_bits;

        for( ; start_bits != 0; start_bits-- )
            mask[first_byte_idx] |= 1 << ( start_bits - 1 );
    }

    end_bits = len % 8;
    if( end_bits != 0 )
    {
        size_t last_byte_idx = ( offset + len ) / 8;

        len -= end_bits; /* Now len % 8 == 0 */

        for( ; end_bits != 0; end_bits-- )
            mask[last_byte_idx] |= 1 << ( 8 - end_bits );
    }

    memset( mask + offset / 8, 0xFF, len / 8 );
}

/*
 * Check that bitmask is full
 */
static int ssl_bitmask_check( unsigned char *mask, size_t len )
{
    size_t i;

    for( i = 0; i < len / 8; i++ )
        if( mask[i] != 0xFF )
            return( -1 );

    for( i = 0; i < len % 8; i++ )
        if( ( mask[len / 8] & ( 1 << ( 7 - i ) ) ) == 0 )
            return( -1 );

    return( 0 );
}

/*
 * Reassemble fragmented DTLS handshake messages.
 *
 * Use a temporary buffer for reassembly, divided in two parts:
 * - the first holds the reassembled message (including handshake header),
 * - the second holds a bitmask indicating which parts of the message
 *   (excluding headers) have been received so far.
 */
static int ssl_reassemble_dtls_handshake( jhd_tls_ssl_context *ssl )
{
    unsigned char *msg, *bitmask;
    size_t frag_len, frag_off;
    size_t msg_len = ssl->in_hslen - 12; /* Without headers */

    if( ssl->handshake == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "not supported outside handshake (for now)" ) );
        return( JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    /*
     * For first fragment, check size and allocate buffer
     */
    if( ssl->handshake->hs_msg == NULL )
    {
        size_t alloc_len;

        JHD_TLS_SSL_DEBUG_MSG( 2, ( "initialize reassembly, total length = %d",
                            msg_len ) );

        if( ssl->in_hslen > JHD_TLS_SSL_MAX_CONTENT_LEN )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "handshake message too large" ) );
            return( JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE );
        }

        /* The bitmask needs one bit per byte of message excluding header */
        alloc_len = 12 + msg_len + msg_len / 8 + ( msg_len % 8 != 0 );

        ssl->handshake->hs_msg = jhd_tls_calloc( 1, alloc_len );
        if( ssl->handshake->hs_msg == NULL )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "alloc failed (%d bytes)", alloc_len ) );
            return( JHD_TLS_ERR_SSL_ALLOC_FAILED );
        }

        /* Prepare final header: copy msg_type, length and message_seq,
         * then add standardised fragment_offset and fragment_length */
        memcpy( ssl->handshake->hs_msg, ssl->in_msg, 6 );
        memset( ssl->handshake->hs_msg + 6, 0, 3 );
        memcpy( ssl->handshake->hs_msg + 9,
                ssl->handshake->hs_msg + 1, 3 );
    }
    else
    {
        /* Make sure msg_type and length are consistent */
        if( memcmp( ssl->handshake->hs_msg, ssl->in_msg, 4 ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "fragment header mismatch" ) );
            return( JHD_TLS_ERR_SSL_INVALID_RECORD );
        }
    }

    msg = ssl->handshake->hs_msg + 12;
    bitmask = msg + msg_len;

    /*
     * Check and copy current fragment
     */
    frag_off = ( ssl->in_msg[6]  << 16 ) |
               ( ssl->in_msg[7]  << 8  ) |
                 ssl->in_msg[8];
    frag_len = ( ssl->in_msg[9]  << 16 ) |
               ( ssl->in_msg[10] << 8  ) |
                 ssl->in_msg[11];

    if( frag_off + frag_len > msg_len )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "invalid fragment offset/len: %d + %d > %d",
                          frag_off, frag_len, msg_len ) );
        return( JHD_TLS_ERR_SSL_INVALID_RECORD );
    }

    if( frag_len + 12 > ssl->in_msglen )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "invalid fragment length: %d + 12 > %d",
                          frag_len, ssl->in_msglen ) );
        return( JHD_TLS_ERR_SSL_INVALID_RECORD );
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "adding fragment, offset = %d, length = %d",
                        frag_off, frag_len ) );

    memcpy( msg + frag_off, ssl->in_msg + 12, frag_len );
    ssl_bitmask_set( bitmask, frag_off, frag_len );

    /*
     * Do we have the complete message by now?
     * If yes, finalize it, else ask to read the next record.
     */
    if( ssl_bitmask_check( bitmask, msg_len ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "message is not complete yet" ) );
        return( JHD_TLS_ERR_SSL_CONTINUE_PROCESSING );
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "handshake message completed" ) );

    if( frag_len + 12 < ssl->in_msglen )
    {
        /*
         * We'got more handshake messages in the same record.
         * This case is not handled now because no know implementation does
         * that and it's hard to test, so we prefer to fail cleanly for now.
         */
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "last fragment not alone in its record" ) );
        return( JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    if( ssl->in_left > ssl->next_record_offset )
    {
        /*
         * We've got more data in the buffer after the current record,
         * that we don't want to overwrite. Move it before writing the
         * reassembled message, and adjust in_left and next_record_offset.
         */
        unsigned char *cur_remain = ssl->in_hdr + ssl->next_record_offset;
        unsigned char *new_remain = ssl->in_msg + ssl->in_hslen;
        size_t remain_len = ssl->in_left - ssl->next_record_offset;

        /* First compute and check new lengths */
        ssl->next_record_offset = new_remain - ssl->in_hdr;
        ssl->in_left = ssl->next_record_offset + remain_len;

        if( ssl->in_left > JHD_TLS_SSL_BUFFER_LEN -
                           (size_t)( ssl->in_hdr - ssl->in_buf ) )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "reassembled message too large for buffer" ) );
            return( JHD_TLS_ERR_SSL_BUFFER_TOO_SMALL );
        }

        memmove( new_remain, cur_remain, remain_len );
    }

    memcpy( ssl->in_msg, ssl->handshake->hs_msg, ssl->in_hslen );

    jhd_tls_free( ssl->handshake->hs_msg );
    ssl->handshake->hs_msg = NULL;

    JHD_TLS_SSL_DEBUG_BUF( 3, "reassembled handshake message",
                   ssl->in_msg, ssl->in_hslen );

    return( 0 );
}
#endif /* JHD_TLS_SSL_PROTO_DTLS */

int jhd_tls_ssl_prepare_handshake_record( jhd_tls_ssl_context *ssl )
{
    if( ssl->in_msglen < jhd_tls_ssl_hs_hdr_len( ssl ) )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "handshake message too short: %d",
                            ssl->in_msglen ) );
        return( JHD_TLS_ERR_SSL_INVALID_RECORD );
    }

    ssl->in_hslen = jhd_tls_ssl_hs_hdr_len( ssl ) + (
                    ( ssl->in_msg[1] << 16 ) |
                    ( ssl->in_msg[2] << 8  ) |
                      ssl->in_msg[3] );

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "handshake message: msglen ="
                        " %d, type = %d, hslen = %d",
                        ssl->in_msglen, ssl->in_msg[0], ssl->in_hslen ) );

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        int ret;
        unsigned int recv_msg_seq = ( ssl->in_msg[4] << 8 ) | ssl->in_msg[5];

        if( ssl->handshake != NULL &&
            ( ( ssl->state   != JHD_TLS_SSL_HANDSHAKE_OVER &&
                recv_msg_seq != ssl->handshake->in_msg_seq ) ||
              ( ssl->state  == JHD_TLS_SSL_HANDSHAKE_OVER &&
                ssl->in_msg[0] != JHD_TLS_SSL_HS_CLIENT_HELLO ) ) )
        {
            /* Retransmit only on last message from previous flight, to avoid
             * too many retransmissions.
             * Besides, No sane server ever retransmits HelloVerifyRequest */
            if( recv_msg_seq == ssl->handshake->in_flight_start_seq - 1 &&
                ssl->in_msg[0] != JHD_TLS_SSL_HS_HELLO_VERIFY_REQUEST )
            {
                JHD_TLS_SSL_DEBUG_MSG( 2, ( "received message from last flight, "
                                    "message_seq = %d, start_of_flight = %d",
                                    recv_msg_seq,
                                    ssl->handshake->in_flight_start_seq ) );

                if( ( ret = jhd_tls_ssl_resend( ssl ) ) != 0 )
                {
                    JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_resend", ret );
                    return( ret );
                }
            }
            else
            {
                JHD_TLS_SSL_DEBUG_MSG( 2, ( "dropping out-of-sequence message: "
                                    "message_seq = %d, expected = %d",
                                    recv_msg_seq,
                                    ssl->handshake->in_msg_seq ) );
            }

            return( JHD_TLS_ERR_SSL_CONTINUE_PROCESSING );
        }
        /* Wait until message completion to increment in_msg_seq */

        /* Reassemble if current message is fragmented or reassembly is
         * already in progress */
        if( ssl->in_msglen < ssl->in_hslen ||
            memcmp( ssl->in_msg + 6, "\0\0\0",        3 ) != 0 ||
            memcmp( ssl->in_msg + 9, ssl->in_msg + 1, 3 ) != 0 ||
            ( ssl->handshake != NULL && ssl->handshake->hs_msg != NULL ) )
        {
            JHD_TLS_SSL_DEBUG_MSG( 2, ( "found fragmented DTLS handshake message" ) );

            if( ( ret = ssl_reassemble_dtls_handshake( ssl ) ) != 0 )
            {
                JHD_TLS_SSL_DEBUG_RET( 1, "ssl_reassemble_dtls_handshake", ret );
                return( ret );
            }
        }
    }
    else
#endif /* JHD_TLS_SSL_PROTO_DTLS */
    /* With TLS we don't handle fragmentation (for now) */
    if( ssl->in_msglen < ssl->in_hslen )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "TLS handshake fragmentation not supported" ) );
        return( JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    return( 0 );
}

void jhd_tls_ssl_update_handshake_status( jhd_tls_ssl_context *ssl )
{

    if( ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER &&
        ssl->handshake != NULL )
    {
        ssl->handshake->update_checksum( ssl, ssl->in_msg, ssl->in_hslen );
    }

    /* Handshake message is complete, increment counter */
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL )
    {
        ssl->handshake->in_msg_seq++;
    }
#endif
}

/*
 * DTLS anti-replay: RFC 6347 4.1.2.6
 *
 * in_window is a field of bits numbered from 0 (lsb) to 63 (msb).
 * Bit n is set iff record number in_window_top - n has been seen.
 *
 * Usually, in_window_top is the last record number seen and the lsb of
 * in_window is set. The only exception is the initial state (record number 0
 * not seen yet).
 */
#if defined(JHD_TLS_SSL_DTLS_ANTI_REPLAY)
static void ssl_dtls_replay_reset( jhd_tls_ssl_context *ssl )
{
    ssl->in_window_top = 0;
    ssl->in_window = 0;
}

static inline uint64_t ssl_load_six_bytes( unsigned char *buf )
{
    return( ( (uint64_t) buf[0] << 40 ) |
            ( (uint64_t) buf[1] << 32 ) |
            ( (uint64_t) buf[2] << 24 ) |
            ( (uint64_t) buf[3] << 16 ) |
            ( (uint64_t) buf[4] <<  8 ) |
            ( (uint64_t) buf[5]       ) );
}

/*
 * Return 0 if sequence number is acceptable, -1 otherwise
 */
int jhd_tls_ssl_dtls_replay_check( jhd_tls_ssl_context *ssl )
{
    uint64_t rec_seqnum = ssl_load_six_bytes( ssl->in_ctr + 2 );
    uint64_t bit;

    if( ssl->conf->anti_replay == JHD_TLS_SSL_ANTI_REPLAY_DISABLED )
        return( 0 );

    if( rec_seqnum > ssl->in_window_top )
        return( 0 );

    bit = ssl->in_window_top - rec_seqnum;

    if( bit >= 64 )
        return( -1 );

    if( ( ssl->in_window & ( (uint64_t) 1 << bit ) ) != 0 )
        return( -1 );

    return( 0 );
}

/*
 * Update replay window on new validated record
 */
void jhd_tls_ssl_dtls_replay_update( jhd_tls_ssl_context *ssl )
{
    uint64_t rec_seqnum = ssl_load_six_bytes( ssl->in_ctr + 2 );

    if( ssl->conf->anti_replay == JHD_TLS_SSL_ANTI_REPLAY_DISABLED )
        return;

    if( rec_seqnum > ssl->in_window_top )
    {
        /* Update window_top and the contents of the window */
        uint64_t shift = rec_seqnum - ssl->in_window_top;

        if( shift >= 64 )
            ssl->in_window = 1;
        else
        {
            ssl->in_window <<= shift;
            ssl->in_window |= 1;
        }

        ssl->in_window_top = rec_seqnum;
    }
    else
    {
        /* Mark that number as seen in the current window */
        uint64_t bit = ssl->in_window_top - rec_seqnum;

        if( bit < 64 ) /* Always true, but be extra sure */
            ssl->in_window |= (uint64_t) 1 << bit;
    }
}
#endif /* JHD_TLS_SSL_DTLS_ANTI_REPLAY */

#if defined(JHD_TLS_SSL_DTLS_CLIENT_PORT_REUSE) && defined(JHD_TLS_SSL_SRV_C)
/* Forward declaration */
static int ssl_session_reset_int( jhd_tls_ssl_context *ssl, int partial );

/*
 * Without any SSL context, check if a datagram looks like a ClientHello with
 * a valid cookie, and if it doesn't, generate a HelloVerifyRequest message.
 * Both input and output include full DTLS headers.
 *
 * - if cookie is valid, return 0
 * - if ClientHello looks superficially valid but cookie is not,
 *   fill obuf and set olen, then
 *   return JHD_TLS_ERR_SSL_HELLO_VERIFY_REQUIRED
 * - otherwise return a specific error code
 */
static int ssl_check_dtls_clihlo_cookie(
                           jhd_tls_ssl_cookie_write_t *f_cookie_write,
                           jhd_tls_ssl_cookie_check_t *f_cookie_check,
                           void *p_cookie,
                           const unsigned char *cli_id, size_t cli_id_len,
                           const unsigned char *in, size_t in_len,
                           unsigned char *obuf, size_t buf_len, size_t *olen )
{
    size_t sid_len, cookie_len;
    unsigned char *p;

    if( f_cookie_write == NULL || f_cookie_check == NULL )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    /*
     * Structure of ClientHello with record and handshake headers,
     * and expected values. We don't need to check a lot, more checks will be
     * done when actually parsing the ClientHello - skipping those checks
     * avoids code duplication and does not make cookie forging any easier.
     *
     *  0-0  ContentType type;                  copied, must be handshake
     *  1-2  ProtocolVersion version;           copied
     *  3-4  uint16 epoch;                      copied, must be 0
     *  5-10 uint48 sequence_number;            copied
     * 11-12 uint16 length;                     (ignored)
     *
     * 13-13 HandshakeType msg_type;            (ignored)
     * 14-16 uint24 length;                     (ignored)
     * 17-18 uint16 message_seq;                copied
     * 19-21 uint24 fragment_offset;            copied, must be 0
     * 22-24 uint24 fragment_length;            (ignored)
     *
     * 25-26 ProtocolVersion client_version;    (ignored)
     * 27-58 Random random;                     (ignored)
     * 59-xx SessionID session_id;              1 byte len + sid_len content
     * 60+   opaque cookie<0..2^8-1>;           1 byte len + content
     *       ...
     *
     * Minimum length is 61 bytes.
     */
    if( in_len < 61 ||
        in[0] != JHD_TLS_SSL_MSG_HANDSHAKE ||
        in[3] != 0 || in[4] != 0 ||
        in[19] != 0 || in[20] != 0 || in[21] != 0 )
    {
        return( JHD_TLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    sid_len = in[59];
    if( sid_len > in_len - 61 )
        return( JHD_TLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

    cookie_len = in[60 + sid_len];
    if( cookie_len > in_len - 60 )
        return( JHD_TLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

    if( f_cookie_check( p_cookie, in + sid_len + 61, cookie_len,
                        cli_id, cli_id_len ) == 0 )
    {
        /* Valid cookie */
        return( 0 );
    }

    /*
     * If we get here, we've got an invalid cookie, let's prepare HVR.
     *
     *  0-0  ContentType type;                  copied
     *  1-2  ProtocolVersion version;           copied
     *  3-4  uint16 epoch;                      copied
     *  5-10 uint48 sequence_number;            copied
     * 11-12 uint16 length;                     olen - 13
     *
     * 13-13 HandshakeType msg_type;            hello_verify_request
     * 14-16 uint24 length;                     olen - 25
     * 17-18 uint16 message_seq;                copied
     * 19-21 uint24 fragment_offset;            copied
     * 22-24 uint24 fragment_length;            olen - 25
     *
     * 25-26 ProtocolVersion server_version;    0xfe 0xff
     * 27-27 opaque cookie<0..2^8-1>;           cookie_len = olen - 27, cookie
     *
     * Minimum length is 28.
     */
    if( buf_len < 28 )
        return( JHD_TLS_ERR_SSL_BUFFER_TOO_SMALL );

    /* Copy most fields and adapt others */
    memcpy( obuf, in, 25 );
    obuf[13] = JHD_TLS_SSL_HS_HELLO_VERIFY_REQUEST;
    obuf[25] = 0xfe;
    obuf[26] = 0xff;

    /* Generate and write actual cookie */
    p = obuf + 28;
    if( f_cookie_write( p_cookie,
                        &p, obuf + buf_len, cli_id, cli_id_len ) != 0 )
    {
        return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

    *olen = p - obuf;

    /* Go back and fill length fields */
    obuf[27] = (unsigned char)( *olen - 28 );

    obuf[14] = obuf[22] = (unsigned char)( ( *olen - 25 ) >> 16 );
    obuf[15] = obuf[23] = (unsigned char)( ( *olen - 25 ) >>  8 );
    obuf[16] = obuf[24] = (unsigned char)( ( *olen - 25 )       );

    obuf[11] = (unsigned char)( ( *olen - 13 ) >>  8 );
    obuf[12] = (unsigned char)( ( *olen - 13 )       );

    return( JHD_TLS_ERR_SSL_HELLO_VERIFY_REQUIRED );
}

/*
 * Handle possible client reconnect with the same UDP quadruplet
 * (RFC 6347 Section 4.2.8).
 *
 * Called by ssl_parse_record_header() in case we receive an epoch 0 record
 * that looks like a ClientHello.
 *
 * - if the input looks like a ClientHello without cookies,
 *   send back HelloVerifyRequest, then
 *   return JHD_TLS_ERR_SSL_HELLO_VERIFY_REQUIRED
 * - if the input looks like a ClientHello with a valid cookie,
 *   reset the session of the current context, and
 *   return JHD_TLS_ERR_SSL_CLIENT_RECONNECT
 * - if anything goes wrong, return a specific error code
 *
 * jhd_tls_ssl_read_record() will ignore the record if anything else than
 * JHD_TLS_ERR_SSL_CLIENT_RECONNECT or 0 is returned, although this function
 * cannot not return 0.
 */
static int ssl_handle_possible_reconnect( jhd_tls_ssl_context *ssl )
{
    int ret;
    size_t len;

    ret = ssl_check_dtls_clihlo_cookie(
            ssl->conf->f_cookie_write,
            ssl->conf->f_cookie_check,
            ssl->conf->p_cookie,
            ssl->cli_id, ssl->cli_id_len,
            ssl->in_buf, ssl->in_left,
            ssl->out_buf, JHD_TLS_SSL_MAX_CONTENT_LEN, &len );

    JHD_TLS_SSL_DEBUG_RET( 2, "ssl_check_dtls_clihlo_cookie", ret );

    if( ret == JHD_TLS_ERR_SSL_HELLO_VERIFY_REQUIRED )
    {
        /* Don't check write errors as we can't do anything here.
         * If the error is permanent we'll catch it later,
         * if it's not, then hopefully it'll work next time. */
        (void) ssl->f_send( ssl->p_bio, ssl->out_buf, len );

        return( JHD_TLS_ERR_SSL_HELLO_VERIFY_REQUIRED );
    }

    if( ret == 0 )
    {
        /* Got a valid cookie, partially reset context */
        if( ( ret = ssl_session_reset_int( ssl, 1 ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "reset", ret );
            return( ret );
        }

        return( JHD_TLS_ERR_SSL_CLIENT_RECONNECT );
    }

    return( ret );
}
#endif /* JHD_TLS_SSL_DTLS_CLIENT_PORT_REUSE && JHD_TLS_SSL_SRV_C */

/*
 * ContentType type;
 * ProtocolVersion version;
 * uint16 epoch;            // DTLS only
 * uint48 sequence_number;  // DTLS only
 * uint16 length;
 *
 * Return 0 if header looks sane (and, for DTLS, the record is expected)
 * JHD_TLS_ERR_SSL_INVALID_RECORD if the header looks bad,
 * JHD_TLS_ERR_SSL_UNEXPECTED_RECORD (DTLS only) if sane but unexpected.
 *
 * With DTLS, jhd_tls_ssl_read_record() will:
 * 1. proceed with the record if this function returns 0
 * 2. drop only the current record if this function returns UNEXPECTED_RECORD
 * 3. return CLIENT_RECONNECT if this function return that value
 * 4. drop the whole datagram if this function returns anything else.
 * Point 2 is needed when the peer is resending, and we have already received
 * the first record from a datagram but are still waiting for the others.
 */
static int ssl_parse_record_header( jhd_tls_ssl_context *ssl )
{
    int major_ver, minor_ver;

    JHD_TLS_SSL_DEBUG_BUF( 4, "input record header", ssl->in_hdr, jhd_tls_ssl_hdr_len( ssl ) );

    ssl->in_msgtype =  ssl->in_hdr[0];
    ssl->in_msglen = ( ssl->in_len[0] << 8 ) | ssl->in_len[1];
    jhd_tls_ssl_read_version( &major_ver, &minor_ver, ssl->conf->transport, ssl->in_hdr + 1 );

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "input record: msgtype = %d, "
                        "version = [%d:%d], msglen = %d",
                        ssl->in_msgtype,
                        major_ver, minor_ver, ssl->in_msglen ) );

    /* Check record type */
    if( ssl->in_msgtype != JHD_TLS_SSL_MSG_HANDSHAKE &&
        ssl->in_msgtype != JHD_TLS_SSL_MSG_ALERT &&
        ssl->in_msgtype != JHD_TLS_SSL_MSG_CHANGE_CIPHER_SPEC &&
        ssl->in_msgtype != JHD_TLS_SSL_MSG_APPLICATION_DATA )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "unknown record type" ) );

#if defined(JHD_TLS_SSL_PROTO_DTLS)
        /* Silently ignore invalid DTLS records as recommended by RFC 6347
         * Section 4.1.2.7 */
        if( ssl->conf->transport != JHD_TLS_SSL_TRANSPORT_DATAGRAM )
#endif /* JHD_TLS_SSL_PROTO_DTLS */
            jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                    JHD_TLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );

        return( JHD_TLS_ERR_SSL_INVALID_RECORD );
    }

    /* Check version */
    if( major_ver != ssl->major_ver )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "major version mismatch" ) );
        return( JHD_TLS_ERR_SSL_INVALID_RECORD );
    }

    if( minor_ver > ssl->conf->max_minor_ver )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "minor version mismatch" ) );
        return( JHD_TLS_ERR_SSL_INVALID_RECORD );
    }

    /* Check length against the size of our buffer */
    if( ssl->in_msglen > JHD_TLS_SSL_BUFFER_LEN
                         - (size_t)( ssl->in_msg - ssl->in_buf ) )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
        return( JHD_TLS_ERR_SSL_INVALID_RECORD );
    }

    /*
     * DTLS-related tests.
     * Check epoch before checking length constraint because
     * the latter varies with the epoch. E.g., if a ChangeCipherSpec
     * message gets duplicated before the corresponding Finished message,
     * the second ChangeCipherSpec should be discarded because it belongs
     * to an old epoch, but not because its length is shorter than
     * the minimum record length for packets using the new record transform.
     * Note that these two kinds of failures are handled differently,
     * as an unexpected record is silently skipped but an invalid
     * record leads to the entire datagram being dropped.
     */
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        unsigned int rec_epoch = ( ssl->in_ctr[0] << 8 ) | ssl->in_ctr[1];

        /* Check epoch (and sequence number) with DTLS */
        if( rec_epoch != ssl->in_epoch )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "record from another epoch: "
                                        "expected %d, received %d",
                                        ssl->in_epoch, rec_epoch ) );

#if defined(JHD_TLS_SSL_DTLS_CLIENT_PORT_REUSE) && defined(JHD_TLS_SSL_SRV_C)
            /*
             * Check for an epoch 0 ClientHello. We can't use in_msg here to
             * access the first byte of record content (handshake type), as we
             * have an active transform (possibly iv_len != 0), so use the
             * fact that the record header len is 13 instead.
             */
            if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER &&
                ssl->state == JHD_TLS_SSL_HANDSHAKE_OVER &&
                rec_epoch == 0 &&
                ssl->in_msgtype == JHD_TLS_SSL_MSG_HANDSHAKE &&
                ssl->in_left > 13 &&
                ssl->in_buf[13] == JHD_TLS_SSL_HS_CLIENT_HELLO )
            {
                JHD_TLS_SSL_DEBUG_MSG( 1, ( "possible client reconnect "
                                            "from the same port" ) );
                return( ssl_handle_possible_reconnect( ssl ) );
            }
            else
#endif /* JHD_TLS_SSL_DTLS_CLIENT_PORT_REUSE && JHD_TLS_SSL_SRV_C */
                return( JHD_TLS_ERR_SSL_UNEXPECTED_RECORD );
        }

#if defined(JHD_TLS_SSL_DTLS_ANTI_REPLAY)
        /* Replay detection only works for the current epoch */
        if( rec_epoch == ssl->in_epoch &&
            jhd_tls_ssl_dtls_replay_check( ssl ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "replayed record" ) );
            return( JHD_TLS_ERR_SSL_UNEXPECTED_RECORD );
        }
#endif

        /* Drop unexpected ChangeCipherSpec messages */
        if( ssl->in_msgtype == JHD_TLS_SSL_MSG_CHANGE_CIPHER_SPEC &&
            ssl->state != JHD_TLS_SSL_CLIENT_CHANGE_CIPHER_SPEC &&
            ssl->state != JHD_TLS_SSL_SERVER_CHANGE_CIPHER_SPEC )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "dropping unexpected ChangeCipherSpec" ) );
            return( JHD_TLS_ERR_SSL_UNEXPECTED_RECORD );
        }

        /* Drop unexpected ApplicationData records,
         * except at the beginning of renegotiations */
        if( ssl->in_msgtype == JHD_TLS_SSL_MSG_APPLICATION_DATA &&
            ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER
#if defined(JHD_TLS_SSL_RENEGOTIATION)
            && ! ( ssl->renego_status == JHD_TLS_SSL_RENEGOTIATION_IN_PROGRESS &&
                   ssl->state == JHD_TLS_SSL_SERVER_HELLO )
#endif
            )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "dropping unexpected ApplicationData" ) );
            return( JHD_TLS_ERR_SSL_UNEXPECTED_RECORD );
        }
    }
#endif /* JHD_TLS_SSL_PROTO_DTLS */


    /* Check length against bounds of the current transform and version */
    if( ssl->transform_in == NULL )
    {
        if( ssl->in_msglen < 1 ||
            ssl->in_msglen > JHD_TLS_SSL_MAX_CONTENT_LEN )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( JHD_TLS_ERR_SSL_INVALID_RECORD );
        }
    }
    else
    {
        if( ssl->in_msglen < ssl->transform_in->minlen )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( JHD_TLS_ERR_SSL_INVALID_RECORD );
        }

#if defined(JHD_TLS_SSL_PROTO_SSL3)
        if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 &&
            ssl->in_msglen > ssl->transform_in->minlen + JHD_TLS_SSL_MAX_CONTENT_LEN )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( JHD_TLS_ERR_SSL_INVALID_RECORD );
        }
#endif
#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_2)
        /*
         * TLS encrypted messages can have up to 256 bytes of padding
         */
        if( ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_1 &&
            ssl->in_msglen > ssl->transform_in->minlen +
                             JHD_TLS_SSL_MAX_CONTENT_LEN + 256 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( JHD_TLS_ERR_SSL_INVALID_RECORD );
        }
#endif
    }

    return( 0 );
}

/*
 * If applicable, decrypt (and decompress) record content
 */
static int ssl_prepare_record_content( jhd_tls_ssl_context *ssl )
{
    int ret, done = 0;

    JHD_TLS_SSL_DEBUG_BUF( 4, "input record from network",
                   ssl->in_hdr, jhd_tls_ssl_hdr_len( ssl ) + ssl->in_msglen );

#if defined(JHD_TLS_SSL_HW_RECORD_ACCEL)
    if( jhd_tls_ssl_hw_record_read != NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "going for jhd_tls_ssl_hw_record_read()" ) );

        ret = jhd_tls_ssl_hw_record_read( ssl );
        if( ret != 0 && ret != JHD_TLS_ERR_SSL_HW_ACCEL_FALLTHROUGH )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_hw_record_read", ret );
            return( JHD_TLS_ERR_SSL_HW_ACCEL_FAILED );
        }

        if( ret == 0 )
            done = 1;
    }
#endif /* JHD_TLS_SSL_HW_RECORD_ACCEL */
    if( !done && ssl->transform_in != NULL )
    {
        if( ( ret = ssl_decrypt_buf( ssl ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "ssl_decrypt_buf", ret );
            return( ret );
        }

        JHD_TLS_SSL_DEBUG_BUF( 4, "input payload after decrypt",
                       ssl->in_msg, ssl->in_msglen );

        if( ssl->in_msglen > JHD_TLS_SSL_MAX_CONTENT_LEN )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( JHD_TLS_ERR_SSL_INVALID_RECORD );
        }
    }

#if defined(JHD_TLS_ZLIB_SUPPORT)
    if( ssl->transform_in != NULL &&
        ssl->session_in->compression == JHD_TLS_SSL_COMPRESS_DEFLATE )
    {
        if( ( ret = ssl_decompress_buf( ssl ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "ssl_decompress_buf", ret );
            return( ret );
        }
    }
#endif /* JHD_TLS_ZLIB_SUPPORT */

#if defined(JHD_TLS_SSL_DTLS_ANTI_REPLAY)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        jhd_tls_ssl_dtls_replay_update( ssl );
    }
#endif

    return( 0 );
}

static void ssl_handshake_wrapup_free_hs_transform( jhd_tls_ssl_context *ssl );

/*
 * Read a record.
 *
 * Silently ignore non-fatal alert (and for DTLS, invalid records as well,
 * RFC 6347 4.1.2.7) and continue reading until a valid record is found.
 *
 */
int jhd_tls_ssl_read_record( jhd_tls_ssl_context *ssl )
{
    int ret;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> read record" ) );

    if( ssl->keep_current_message == 0 )
    {
        do {

            do ret = jhd_tls_ssl_read_record_layer( ssl );
            while( ret == JHD_TLS_ERR_SSL_CONTINUE_PROCESSING );

            if( ret != 0 )
            {
                JHD_TLS_SSL_DEBUG_RET( 1, ( "jhd_tls_ssl_read_record_layer" ), ret );
                return( ret );
            }

            ret = jhd_tls_ssl_handle_message_type( ssl );

        } while( JHD_TLS_ERR_SSL_NON_FATAL           == ret  ||
                 JHD_TLS_ERR_SSL_CONTINUE_PROCESSING == ret );

        if( 0 != ret )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, ( "jhd_tls_ssl_handle_message_type" ), ret );
            return( ret );
        }

        if( ssl->in_msgtype == JHD_TLS_SSL_MSG_HANDSHAKE )
        {
            jhd_tls_ssl_update_handshake_status( ssl );
        }
    }
    else
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= reuse previously read message" ) );
        ssl->keep_current_message = 0;
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= read record" ) );

    return( 0 );
}

int jhd_tls_ssl_read_record_layer( jhd_tls_ssl_context *ssl )
{
    int ret;

    /*
     * Step A
     *
     * Consume last content-layer message and potentially
     * update in_msglen which keeps track of the contents'
     * consumption state.
     *
     * (1) Handshake messages:
     *     Remove last handshake message, move content
     *     and adapt in_msglen.
     *
     * (2) Alert messages:
     *     Consume whole record content, in_msglen = 0.
     *
     * (3) Change cipher spec:
     *     Consume whole record content, in_msglen = 0.
     *
     * (4) Application data:
     *     Don't do anything - the record layer provides
     *     the application data as a stream transport
     *     and consumes through jhd_tls_ssl_read only.
     *
     */

    /* Case (1): Handshake messages */
    if( ssl->in_hslen != 0 )
    {
        /* Hard assertion to be sure that no application data
         * is in flight, as corrupting ssl->in_msglen during
         * ssl->in_offt != NULL is fatal. */
        if( ssl->in_offt != NULL )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
        }

        /*
         * Get next Handshake message in the current record
         */

        /* Notes:
         * (1) in_hslen is not necessarily the size of the
         *     current handshake content: If DTLS handshake
         *     fragmentation is used, that's the fragment
         *     size instead. Using the total handshake message
         *     size here is faulty and should be changed at
         *     some point.
         * (2) While it doesn't seem to cause problems, one
         *     has to be very careful not to assume that in_hslen
         *     is always <= in_msglen in a sensible communication.
         *     Again, it's wrong for DTLS handshake fragmentation.
         *     The following check is therefore mandatory, and
         *     should not be treated as a silently corrected assertion.
         *     Additionally, ssl->in_hslen might be arbitrarily out of
         *     bounds after handling a DTLS message with an unexpected
         *     sequence number, see jhd_tls_ssl_prepare_handshake_record.
         */
        if( ssl->in_hslen < ssl->in_msglen )
        {
            ssl->in_msglen -= ssl->in_hslen;
            memmove( ssl->in_msg, ssl->in_msg + ssl->in_hslen,
                     ssl->in_msglen );

            JHD_TLS_SSL_DEBUG_BUF( 4, "remaining content in record",
                                   ssl->in_msg, ssl->in_msglen );
        }
        else
        {
            ssl->in_msglen = 0;
        }

        ssl->in_hslen   = 0;
    }
    /* Case (4): Application data */
    else if( ssl->in_offt != NULL )
    {
        return( 0 );
    }
    /* Everything else (CCS & Alerts) */
    else
    {
        ssl->in_msglen = 0;
    }

    /*
     * Step B
     *
     * Fetch and decode new record if current one is fully consumed.
     *
     */

    if( ssl->in_msglen > 0 )
    {
        /* There's something left to be processed in the current record. */
        return( 0 );
    }

    /* Current record either fully processed or to be discarded. */

    if( ( ret = jhd_tls_ssl_fetch_input( ssl, jhd_tls_ssl_hdr_len( ssl ) ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_fetch_input", ret );
        return( ret );
    }

    if( ( ret = ssl_parse_record_header( ssl ) ) != 0 )
    {
#if defined(JHD_TLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM &&
            ret != JHD_TLS_ERR_SSL_CLIENT_RECONNECT )
        {
            if( ret == JHD_TLS_ERR_SSL_UNEXPECTED_RECORD )
            {
                /* Skip unexpected record (but not whole datagram) */
                ssl->next_record_offset = ssl->in_msglen
                                        + jhd_tls_ssl_hdr_len( ssl );

                JHD_TLS_SSL_DEBUG_MSG( 1, ( "discarding unexpected record "
                                            "(header)" ) );
            }
            else
            {
                /* Skip invalid record and the rest of the datagram */
                ssl->next_record_offset = 0;
                ssl->in_left = 0;

                JHD_TLS_SSL_DEBUG_MSG( 1, ( "discarding invalid record "
                                            "(header)" ) );
            }

            /* Get next record */
            return( JHD_TLS_ERR_SSL_CONTINUE_PROCESSING );
        }
#endif
        return( ret );
    }

    /*
     * Read and optionally decrypt the message contents
     */
    if( ( ret = jhd_tls_ssl_fetch_input( ssl,
                                 jhd_tls_ssl_hdr_len( ssl ) + ssl->in_msglen ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_fetch_input", ret );
        return( ret );
    }

    /* Done reading this record, get ready for the next one */
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        ssl->next_record_offset = ssl->in_msglen + jhd_tls_ssl_hdr_len( ssl );
        if( ssl->next_record_offset < ssl->in_left )
        {
            JHD_TLS_SSL_DEBUG_MSG( 3, ( "more than one record within datagram" ) );
        }
    }
    else
#endif
        ssl->in_left = 0;

    if( ( ret = ssl_prepare_record_content( ssl ) ) != 0 )
    {
#if defined(JHD_TLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
        {
            /* Silently discard invalid records */
            if( ret == JHD_TLS_ERR_SSL_INVALID_RECORD ||
                ret == JHD_TLS_ERR_SSL_INVALID_MAC )
            {
                /* Except when waiting for Finished as a bad mac here
                 * probably means something went wrong in the handshake
                 * (eg wrong psk used, mitm downgrade attempt, etc.) */
                if( ssl->state == JHD_TLS_SSL_CLIENT_FINISHED ||
                    ssl->state == JHD_TLS_SSL_SERVER_FINISHED )
                {
#if defined(JHD_TLS_SSL_ALL_ALERT_MESSAGES)
                    if( ret == JHD_TLS_ERR_SSL_INVALID_MAC )
                    {
                        jhd_tls_ssl_send_alert_message( ssl,
                                JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                JHD_TLS_SSL_ALERT_MSG_BAD_RECORD_MAC );
                    }
#endif
                    return( ret );
                }

#if defined(JHD_TLS_SSL_DTLS_BADMAC_LIMIT)
                if( ssl->conf->badmac_limit != 0 &&
                    ++ssl->badmac_seen >= ssl->conf->badmac_limit )
                {
                    JHD_TLS_SSL_DEBUG_MSG( 1, ( "too many records with bad MAC" ) );
                    return( JHD_TLS_ERR_SSL_INVALID_MAC );
                }
#endif

                /* As above, invalid records cause
                 * dismissal of the whole datagram. */

                ssl->next_record_offset = 0;
                ssl->in_left = 0;

                JHD_TLS_SSL_DEBUG_MSG( 1, ( "discarding invalid record (mac)" ) );
                return( JHD_TLS_ERR_SSL_CONTINUE_PROCESSING );
            }

            return( ret );
        }
        else
#endif
        {
            /* Error out (and send alert) on invalid records */
#if defined(JHD_TLS_SSL_ALL_ALERT_MESSAGES)
            if( ret == JHD_TLS_ERR_SSL_INVALID_MAC )
            {
                jhd_tls_ssl_send_alert_message( ssl,
                        JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                        JHD_TLS_SSL_ALERT_MSG_BAD_RECORD_MAC );
            }
#endif
            return( ret );
        }
    }

    return( 0 );
}

int jhd_tls_ssl_handle_message_type( jhd_tls_ssl_context *ssl )
{
    int ret;

    /*
     * Handle particular types of records
     */
    if( ssl->in_msgtype == JHD_TLS_SSL_MSG_HANDSHAKE )
    {
        if( ( ret = jhd_tls_ssl_prepare_handshake_record( ssl ) ) != 0 )
        {
            return( ret );
        }
    }

    if( ssl->in_msgtype == JHD_TLS_SSL_MSG_ALERT )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "got an alert message, type: [%d:%d]",
                       ssl->in_msg[0], ssl->in_msg[1] ) );

        /*
         * Ignore non-fatal alerts, except close_notify and no_renegotiation
         */
        if( ssl->in_msg[0] == JHD_TLS_SSL_ALERT_LEVEL_FATAL )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "is a fatal alert message (msg %d)",
                           ssl->in_msg[1] ) );
            return( JHD_TLS_ERR_SSL_FATAL_ALERT_MESSAGE );
        }

        if( ssl->in_msg[0] == JHD_TLS_SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == JHD_TLS_SSL_ALERT_MSG_CLOSE_NOTIFY )
        {
            JHD_TLS_SSL_DEBUG_MSG( 2, ( "is a close notify message" ) );
            return( JHD_TLS_ERR_SSL_PEER_CLOSE_NOTIFY );
        }

#if defined(JHD_TLS_SSL_RENEGOTIATION_ENABLED)
        if( ssl->in_msg[0] == JHD_TLS_SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == JHD_TLS_SSL_ALERT_MSG_NO_RENEGOTIATION )
        {
            JHD_TLS_SSL_DEBUG_MSG( 2, ( "is a SSLv3 no renegotiation alert" ) );
            /* Will be handled when trying to parse ServerHello */
            return( 0 );
        }
#endif

#if defined(JHD_TLS_SSL_PROTO_SSL3) && defined(JHD_TLS_SSL_SRV_C)
        if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 &&
            ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER &&
            ssl->in_msg[0] == JHD_TLS_SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == JHD_TLS_SSL_ALERT_MSG_NO_CERT )
        {
            JHD_TLS_SSL_DEBUG_MSG( 2, ( "is a SSLv3 no_cert" ) );
            /* Will be handled in jhd_tls_ssl_parse_certificate() */
            return( 0 );
        }
#endif /* JHD_TLS_SSL_PROTO_SSL3 && JHD_TLS_SSL_SRV_C */

        /* Silently ignore: fetch new message */
        return JHD_TLS_ERR_SSL_NON_FATAL;
    }

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL &&
        ssl->state == JHD_TLS_SSL_HANDSHAKE_OVER  )
    {
        ssl_handshake_wrapup_free_hs_transform( ssl );
    }
#endif

    return( 0 );
}

int jhd_tls_ssl_send_fatal_handshake_failure( jhd_tls_ssl_context *ssl )
{
    int ret;

    if( ( ret = jhd_tls_ssl_send_alert_message( ssl,
                    JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                    JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int jhd_tls_ssl_send_alert_message( jhd_tls_ssl_context *ssl,
                            unsigned char level,
                            unsigned char message )
{
    int ret;

    if( ssl == NULL || ssl->conf == NULL )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> send alert message" ) );
    JHD_TLS_SSL_DEBUG_MSG( 3, ( "send alert level=%u message=%u", level, message ));

    ssl->out_msgtype = JHD_TLS_SSL_MSG_ALERT;
    ssl->out_msglen = 2;
    ssl->out_msg[0] = level;
    ssl->out_msg[1] = message;

    if( ( ret = jhd_tls_ssl_write_record( ssl ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_write_record", ret );
        return( ret );
    }
    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= send alert message" ) );

    return( 0 );
}

/*
 * Handshake functions
 */
#if !defined(JHD_TLS_KEY_EXCHANGE_RSA_ENABLED)         && \
    !defined(JHD_TLS_KEY_EXCHANGE_RSA_PSK_ENABLED)     && \
    !defined(JHD_TLS_KEY_EXCHANGE_DHE_RSA_ENABLED)     && \
    !defined(JHD_TLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)   && \
    !defined(JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) && \
    !defined(JHD_TLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)    && \
    !defined(JHD_TLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
/* No certificate support -> dummy functions */
int jhd_tls_ssl_write_certificate( jhd_tls_ssl_context *ssl )
{
    const jhd_tls_ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> write certificate" ) );

    if( ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_DHE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECJPAKE )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
        ssl->state++;
        return( 0 );
    }

    JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
}

int jhd_tls_ssl_parse_certificate( jhd_tls_ssl_context *ssl )
{
    const jhd_tls_ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate" ) );

    if( ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_DHE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECJPAKE )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
        ssl->state++;
        return( 0 );
    }

    JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
}

#else
/* Some certificate support -> implement write and parse */

int jhd_tls_ssl_write_certificate( jhd_tls_ssl_context *ssl )
{
    int ret = JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t i, n;
    const jhd_tls_x509_crt *crt;
    const jhd_tls_ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> write certificate" ) );

    if( ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_DHE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECJPAKE )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
        ssl->state++;
        return( 0 );
    }

#if defined(JHD_TLS_SSL_CLI_C)
    if( ssl->conf->endpoint == JHD_TLS_SSL_IS_CLIENT )
    {
        if( ssl->client_auth == 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
            ssl->state++;
            return( 0 );
        }

#if defined(JHD_TLS_SSL_PROTO_SSL3)
        /*
         * If using SSLv3 and got no cert, send an Alert message
         * (otherwise an empty Certificate message will be sent).
         */
        if( jhd_tls_ssl_own_cert( ssl )  == NULL &&
            ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 )
        {
            ssl->out_msglen  = 2;
            ssl->out_msgtype = JHD_TLS_SSL_MSG_ALERT;
            ssl->out_msg[0]  = JHD_TLS_SSL_ALERT_LEVEL_WARNING;
            ssl->out_msg[1]  = JHD_TLS_SSL_ALERT_MSG_NO_CERT;

            JHD_TLS_SSL_DEBUG_MSG( 2, ( "got no certificate to send" ) );
            goto write_msg;
        }
#endif /* JHD_TLS_SSL_PROTO_SSL3 */
    }
#endif /* JHD_TLS_SSL_CLI_C */
#if defined(JHD_TLS_SSL_SRV_C)
    if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER )
    {
        if( jhd_tls_ssl_own_cert( ssl ) == NULL )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "got no certificate to send" ) );
            return( JHD_TLS_ERR_SSL_CERTIFICATE_REQUIRED );
        }
    }
#endif

    JHD_TLS_SSL_DEBUG_CRT( 3, "own certificate", jhd_tls_ssl_own_cert( ssl ) );

    /*
     *     0  .  0    handshake type
     *     1  .  3    handshake length
     *     4  .  6    length of all certs
     *     7  .  9    length of cert. 1
     *    10  . n-1   peer certificate
     *     n  . n+2   length of cert. 2
     *    n+3 . ...   upper level cert, etc.
     */
    i = 7;
    crt = jhd_tls_ssl_own_cert( ssl );

    while( crt != NULL )
    {
        n = crt->raw.len;
        if( n > JHD_TLS_SSL_MAX_CONTENT_LEN - 3 - i )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "certificate too large, %d > %d",
                           i + 3 + n, JHD_TLS_SSL_MAX_CONTENT_LEN ) );
            return( JHD_TLS_ERR_SSL_CERTIFICATE_TOO_LARGE );
        }

        ssl->out_msg[i    ] = (unsigned char)( n >> 16 );
        ssl->out_msg[i + 1] = (unsigned char)( n >>  8 );
        ssl->out_msg[i + 2] = (unsigned char)( n       );

        i += 3; memcpy( ssl->out_msg + i, crt->raw.p, n );
        i += n; crt = crt->next;
    }

    ssl->out_msg[4]  = (unsigned char)( ( i - 7 ) >> 16 );
    ssl->out_msg[5]  = (unsigned char)( ( i - 7 ) >>  8 );
    ssl->out_msg[6]  = (unsigned char)( ( i - 7 )       );

    ssl->out_msglen  = i;
    ssl->out_msgtype = JHD_TLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = JHD_TLS_SSL_HS_CERTIFICATE;

#if defined(JHD_TLS_SSL_PROTO_SSL3) && defined(JHD_TLS_SSL_CLI_C)
write_msg:
#endif

    ssl->state++;

    if( ( ret = jhd_tls_ssl_write_record( ssl ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_write_record", ret );
        return( ret );
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= write certificate" ) );

    return( ret );
}

int jhd_tls_ssl_parse_certificate( jhd_tls_ssl_context *ssl )
{
    int ret = JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t i, n;
    const jhd_tls_ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;
    int authmode = ssl->conf->authmode;
    uint8_t alert;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate" ) );

    if( ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_DHE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_PSK ||
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECJPAKE )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
        ssl->state++;
        return( 0 );
    }

#if defined(JHD_TLS_SSL_SRV_C)
    if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER &&
        ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_RSA_PSK )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
        ssl->state++;
        return( 0 );
    }

#if defined(JHD_TLS_SSL_SERVER_NAME_INDICATION)
    if( ssl->handshake->sni_authmode != JHD_TLS_SSL_VERIFY_UNSET )
        authmode = ssl->handshake->sni_authmode;
#endif

    if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER &&
        authmode == JHD_TLS_SSL_VERIFY_NONE )
    {
        ssl->session_negotiate->verify_result = JHD_TLS_X509_BADCERT_SKIP_VERIFY;
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
        ssl->state++;
        return( 0 );
    }
#endif

    if( ( ret = jhd_tls_ssl_read_record( ssl ) ) != 0 )
    {
        /* jhd_tls_ssl_read_record may have sent an alert already. We
           let it decide whether to alert. */
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_read_record", ret );
        return( ret );
    }

    ssl->state++;

#if defined(JHD_TLS_SSL_SRV_C)
#if defined(JHD_TLS_SSL_PROTO_SSL3)
    /*
     * Check if the client sent an empty certificate
     */
    if( ssl->conf->endpoint  == JHD_TLS_SSL_IS_SERVER &&
        ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 )
    {
        if( ssl->in_msglen  == 2                        &&
            ssl->in_msgtype == JHD_TLS_SSL_MSG_ALERT            &&
            ssl->in_msg[0]  == JHD_TLS_SSL_ALERT_LEVEL_WARNING  &&
            ssl->in_msg[1]  == JHD_TLS_SSL_ALERT_MSG_NO_CERT )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "SSLv3 client has no certificate" ) );

            /* The client was asked for a certificate but didn't send
               one. The client should know what's going on, so we
               don't send an alert. */
            ssl->session_negotiate->verify_result = JHD_TLS_X509_BADCERT_MISSING;
            if( authmode == JHD_TLS_SSL_VERIFY_OPTIONAL )
                return( 0 );
            else
                return( JHD_TLS_ERR_SSL_NO_CLIENT_CERTIFICATE );
        }
    }
#endif /* JHD_TLS_SSL_PROTO_SSL3 */

#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_2)
    if( ssl->conf->endpoint  == JHD_TLS_SSL_IS_SERVER &&
        ssl->minor_ver != JHD_TLS_SSL_MINOR_VERSION_0 )
    {
        if( ssl->in_hslen   == 3 + jhd_tls_ssl_hs_hdr_len( ssl ) &&
            ssl->in_msgtype == JHD_TLS_SSL_MSG_HANDSHAKE    &&
            ssl->in_msg[0]  == JHD_TLS_SSL_HS_CERTIFICATE   &&
            memcmp( ssl->in_msg + jhd_tls_ssl_hs_hdr_len( ssl ), "\0\0\0", 3 ) == 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "TLSv1 client has no certificate" ) );

            /* The client was asked for a certificate but didn't send
               one. The client should know what's going on, so we
               don't send an alert. */
            ssl->session_negotiate->verify_result = JHD_TLS_X509_BADCERT_MISSING;
            if( authmode == JHD_TLS_SSL_VERIFY_OPTIONAL )
                return( 0 );
            else
                return( JHD_TLS_ERR_SSL_NO_CLIENT_CERTIFICATE );
        }
    }
#endif /* JHD_TLS_SSL_PROTO_TLS1 || JHD_TLS_SSL_PROTO_TLS1_1 || \
          JHD_TLS_SSL_PROTO_TLS1_2 */
#endif /* JHD_TLS_SSL_SRV_C */

    if( ssl->in_msgtype != JHD_TLS_SSL_MSG_HANDSHAKE )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                        JHD_TLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
        return( JHD_TLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_msg[0] != JHD_TLS_SSL_HS_CERTIFICATE ||
        ssl->in_hslen < jhd_tls_ssl_hs_hdr_len( ssl ) + 3 + 3 )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                        JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR );
        return( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    i = jhd_tls_ssl_hs_hdr_len( ssl );

    /*
     * Same message structure as in jhd_tls_ssl_write_certificate()
     */
    n = ( ssl->in_msg[i+1] << 8 ) | ssl->in_msg[i+2];

    if( ssl->in_msg[i] != 0 ||
        ssl->in_hslen != n + 3 + jhd_tls_ssl_hs_hdr_len( ssl ) )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                        JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR );
        return( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    /* In case we tried to reuse a session but it failed */
    if( ssl->session_negotiate->peer_cert != NULL )
    {
        jhd_tls_x509_crt_free( ssl->session_negotiate->peer_cert );
        jhd_tls_free( ssl->session_negotiate->peer_cert );
    }

    if( ( ssl->session_negotiate->peer_cert = jhd_tls_calloc( 1,
                    sizeof( jhd_tls_x509_crt ) ) ) == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "alloc(%d bytes) failed",
                       sizeof( jhd_tls_x509_crt ) ) );
        jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                        JHD_TLS_SSL_ALERT_MSG_INTERNAL_ERROR );
        return( JHD_TLS_ERR_SSL_ALLOC_FAILED );
    }

    jhd_tls_x509_crt_init( ssl->session_negotiate->peer_cert );

    i += 3;

    while( i < ssl->in_hslen )
    {
        if( ssl->in_msg[i] != 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                            JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR );
            return( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        n = ( (unsigned int) ssl->in_msg[i + 1] << 8 )
            | (unsigned int) ssl->in_msg[i + 2];
        i += 3;

        if( n < 128 || i + n > ssl->in_hslen )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                            JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR );
            return( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        ret = jhd_tls_x509_crt_parse_der( ssl->session_negotiate->peer_cert,
                                  ssl->in_msg + i, n );
        switch( ret )
        {
        case 0: /*ok*/
        case JHD_TLS_ERR_X509_UNKNOWN_SIG_ALG + JHD_TLS_ERR_OID_NOT_FOUND:
            /* Ignore certificate with an unknown algorithm: maybe a
               prior certificate was already trusted. */
            break;

        case JHD_TLS_ERR_X509_ALLOC_FAILED:
            alert = JHD_TLS_SSL_ALERT_MSG_INTERNAL_ERROR;
            goto crt_parse_der_failed;

        case JHD_TLS_ERR_X509_UNKNOWN_VERSION:
            alert = JHD_TLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
            goto crt_parse_der_failed;

        default:
            alert = JHD_TLS_SSL_ALERT_MSG_BAD_CERT;
        crt_parse_der_failed:
            jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL, alert );
            JHD_TLS_SSL_DEBUG_RET( 1, " jhd_tls_x509_crt_parse_der", ret );
            return( ret );
        }

        i += n;
    }

    JHD_TLS_SSL_DEBUG_CRT( 3, "peer certificate", ssl->session_negotiate->peer_cert );

    /*
     * On client, make sure the server cert doesn't change during renego to
     * avoid "triple handshake" attack: https://secure-resumption.com/
     */
#if defined(JHD_TLS_SSL_RENEGOTIATION) && defined(JHD_TLS_SSL_CLI_C)
    if( ssl->conf->endpoint == JHD_TLS_SSL_IS_CLIENT &&
        ssl->renego_status == JHD_TLS_SSL_RENEGOTIATION_IN_PROGRESS )
    {
        if( ssl->session->peer_cert == NULL )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "new server cert during renegotiation" ) );
            jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                            JHD_TLS_SSL_ALERT_MSG_ACCESS_DENIED );
            return( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        if( ssl->session->peer_cert->raw.len !=
            ssl->session_negotiate->peer_cert->raw.len ||
            memcmp( ssl->session->peer_cert->raw.p,
                    ssl->session_negotiate->peer_cert->raw.p,
                    ssl->session->peer_cert->raw.len ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "server cert changed during renegotiation" ) );
            jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                            JHD_TLS_SSL_ALERT_MSG_ACCESS_DENIED );
            return( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }
    }
#endif /* JHD_TLS_SSL_RENEGOTIATION && JHD_TLS_SSL_CLI_C */

    if( authmode != JHD_TLS_SSL_VERIFY_NONE )
    {
        jhd_tls_x509_crt *ca_chain;
        jhd_tls_x509_crl *ca_crl;

#if defined(JHD_TLS_SSL_SERVER_NAME_INDICATION)
        if( ssl->handshake->sni_ca_chain != NULL )
        {
            ca_chain = ssl->handshake->sni_ca_chain;
            ca_crl   = ssl->handshake->sni_ca_crl;
        }
        else
#endif
        {
            ca_chain = ssl->conf->ca_chain;
            ca_crl   = ssl->conf->ca_crl;
        }

        /*
         * Main check: verify certificate
         */
        ret = jhd_tls_x509_crt_verify_with_profile(
                                ssl->session_negotiate->peer_cert,
                                ca_chain, ca_crl,
                                ssl->conf->cert_profile,
                                ssl->hostname,
                               &ssl->session_negotiate->verify_result,
                                ssl->conf->f_vrfy, ssl->conf->p_vrfy );

        if( ret != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "x509_verify_cert", ret );
        }

        /*
         * Secondary checks: always done, but change 'ret' only if it was 0
         */

#if defined(JHD_TLS_ECP_C)
        {
            const jhd_tls_pk_context *pk = &ssl->session_negotiate->peer_cert->pk;

            /* If certificate uses an EC key, make sure the curve is OK */
            if( jhd_tls_pk_can_do( pk, JHD_TLS_PK_ECKEY ) &&
                jhd_tls_ssl_check_curve( ssl, jhd_tls_pk_ec( *pk )->grp.id ) != 0 )
            {
                ssl->session_negotiate->verify_result |= JHD_TLS_X509_BADCERT_BAD_KEY;

                JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad certificate (EC key curve)" ) );
                if( ret == 0 )
                    ret = JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE;
            }
        }
#endif /* JHD_TLS_ECP_C */

        if( jhd_tls_ssl_check_cert_usage( ssl->session_negotiate->peer_cert,
                                 ciphersuite_info,
                                 ! ssl->conf->endpoint,
                                 &ssl->session_negotiate->verify_result ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad certificate (usage extensions)" ) );
            if( ret == 0 )
                ret = JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE;
        }

        /* jhd_tls_x509_crt_verify_with_profile is supposed to report a
         * verification failure through JHD_TLS_ERR_X509_CERT_VERIFY_FAILED,
         * with details encoded in the verification flags. All other kinds
         * of error codes, including those from the user provided f_vrfy
         * functions, are treated as fatal and lead to a failure of
         * ssl_parse_certificate even if verification was optional. */
        if( authmode == JHD_TLS_SSL_VERIFY_OPTIONAL &&
            ( ret == JHD_TLS_ERR_X509_CERT_VERIFY_FAILED ||
              ret == JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE ) )
        {
            ret = 0;
        }

        if( ca_chain == NULL && authmode == JHD_TLS_SSL_VERIFY_REQUIRED )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "got no CA chain" ) );
            ret = JHD_TLS_ERR_SSL_CA_CHAIN_REQUIRED;
        }

        if( ret != 0 )
        {
            /* The certificate may have been rejected for several reasons.
               Pick one and send the corresponding alert. Which alert to send
               may be a subject of debate in some cases. */
            if( ssl->session_negotiate->verify_result & JHD_TLS_X509_BADCERT_OTHER )
                alert = JHD_TLS_SSL_ALERT_MSG_ACCESS_DENIED;
            else if( ssl->session_negotiate->verify_result & JHD_TLS_X509_BADCERT_CN_MISMATCH )
                alert = JHD_TLS_SSL_ALERT_MSG_BAD_CERT;
            else if( ssl->session_negotiate->verify_result & JHD_TLS_X509_BADCERT_KEY_USAGE )
                alert = JHD_TLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
            else if( ssl->session_negotiate->verify_result & JHD_TLS_X509_BADCERT_EXT_KEY_USAGE )
                alert = JHD_TLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
            else if( ssl->session_negotiate->verify_result & JHD_TLS_X509_BADCERT_NS_CERT_TYPE )
                alert = JHD_TLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
            else if( ssl->session_negotiate->verify_result & JHD_TLS_X509_BADCERT_BAD_PK )
                alert = JHD_TLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
            else if( ssl->session_negotiate->verify_result & JHD_TLS_X509_BADCERT_BAD_KEY )
                alert = JHD_TLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
            else if( ssl->session_negotiate->verify_result & JHD_TLS_X509_BADCERT_EXPIRED )
                alert = JHD_TLS_SSL_ALERT_MSG_CERT_EXPIRED;
            else if( ssl->session_negotiate->verify_result & JHD_TLS_X509_BADCERT_REVOKED )
                alert = JHD_TLS_SSL_ALERT_MSG_CERT_REVOKED;
            else if( ssl->session_negotiate->verify_result & JHD_TLS_X509_BADCERT_NOT_TRUSTED )
                alert = JHD_TLS_SSL_ALERT_MSG_UNKNOWN_CA;
            else
                alert = JHD_TLS_SSL_ALERT_MSG_CERT_UNKNOWN;
            jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                            alert );
        }

#if defined(JHD_TLS_DEBUG_C)
        if( ssl->session_negotiate->verify_result != 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 3, ( "! Certificate verification flags %x",
                                        ssl->session_negotiate->verify_result ) );
        }
        else
        {
            JHD_TLS_SSL_DEBUG_MSG( 3, ( "Certificate verification flags clear" ) );
        }
#endif /* JHD_TLS_DEBUG_C */
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate" ) );

    return( ret );
}
#endif /* !JHD_TLS_KEY_EXCHANGE_RSA_ENABLED
          !JHD_TLS_KEY_EXCHANGE_RSA_PSK_ENABLED
          !JHD_TLS_KEY_EXCHANGE_DHE_RSA_ENABLED
          !JHD_TLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
          !JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
          !JHD_TLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
          !JHD_TLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED */

int jhd_tls_ssl_write_change_cipher_spec( jhd_tls_ssl_context *ssl )
{
    int ret;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> write change cipher spec" ) );

    ssl->out_msgtype = JHD_TLS_SSL_MSG_CHANGE_CIPHER_SPEC;
    ssl->out_msglen  = 1;
    ssl->out_msg[0]  = 1;

    ssl->state++;

    if( ( ret = jhd_tls_ssl_write_record( ssl ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_write_record", ret );
        return( ret );
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= write change cipher spec" ) );

    return( 0 );
}

int jhd_tls_ssl_parse_change_cipher_spec( jhd_tls_ssl_context *ssl )
{
    int ret;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> parse change cipher spec" ) );

    if( ( ret = jhd_tls_ssl_read_record( ssl ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_read_record", ret );
        return( ret );
    }

    if( ssl->in_msgtype != JHD_TLS_SSL_MSG_CHANGE_CIPHER_SPEC )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad change cipher spec message" ) );
        jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                        JHD_TLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
        return( JHD_TLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_msglen != 1 || ssl->in_msg[0] != 1 )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad change cipher spec message" ) );
        jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                        JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR );
        return( JHD_TLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC );
    }

    /*
     * Switch to our negotiated transform and session parameters for inbound
     * data.
     */
    JHD_TLS_SSL_DEBUG_MSG( 3, ( "switching to new transform spec for inbound data" ) );
    ssl->transform_in = ssl->transform_negotiate;
    ssl->session_in = ssl->session_negotiate;

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
#if defined(JHD_TLS_SSL_DTLS_ANTI_REPLAY)
        ssl_dtls_replay_reset( ssl );
#endif

        /* Increment epoch */
        if( ++ssl->in_epoch == 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "DTLS epoch would wrap" ) );
            /* This is highly unlikely to happen for legitimate reasons, so
               treat it as an attack and don't send an alert. */
            return( JHD_TLS_ERR_SSL_COUNTER_WRAPPING );
        }
    }
    else
#endif /* JHD_TLS_SSL_PROTO_DTLS */
    memset( ssl->in_ctr, 0, 8 );

    /*
     * Set the in_msg pointer to the correct location based on IV length
     */
    if( ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_2 )
    {
        ssl->in_msg = ssl->in_iv + ssl->transform_negotiate->ivlen -
                      ssl->transform_negotiate->fixed_ivlen;
    }
    else
        ssl->in_msg = ssl->in_iv;

#if defined(JHD_TLS_SSL_HW_RECORD_ACCEL)
    if( jhd_tls_ssl_hw_record_activate != NULL )
    {
        if( ( ret = jhd_tls_ssl_hw_record_activate( ssl, JHD_TLS_SSL_CHANNEL_INBOUND ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_hw_record_activate", ret );
            jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                            JHD_TLS_SSL_ALERT_MSG_INTERNAL_ERROR );
            return( JHD_TLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif

    ssl->state++;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= parse change cipher spec" ) );

    return( 0 );
}

void jhd_tls_ssl_optimize_checksum( jhd_tls_ssl_context *ssl,
                            const jhd_tls_ssl_ciphersuite_t *ciphersuite_info )
{
    ((void) ciphersuite_info);

#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_1)
    if( ssl->minor_ver < JHD_TLS_SSL_MINOR_VERSION_3 )
        ssl->handshake->update_checksum = ssl_update_checksum_md5sha1;
    else
#endif
#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#if defined(JHD_TLS_SHA512_C)
    if( ciphersuite_info->mac == JHD_TLS_MD_SHA384 )
        ssl->handshake->update_checksum = ssl_update_checksum_sha384;
    else
#endif
#if defined(JHD_TLS_SHA256_C)
    if( ciphersuite_info->mac != JHD_TLS_MD_SHA384 )
        ssl->handshake->update_checksum = ssl_update_checksum_sha256;
    else
#endif
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return;
    }
}

void jhd_tls_ssl_reset_checksum( jhd_tls_ssl_context *ssl )
{
#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_1)
     jhd_tls_md5_starts_ret( &ssl->handshake->fin_md5  );
    jhd_tls_sha1_starts_ret( &ssl->handshake->fin_sha1 );
#endif
#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#if defined(JHD_TLS_SHA256_C)
    jhd_tls_sha256_starts_ret( &ssl->handshake->fin_sha256, 0 );
#endif
#if defined(JHD_TLS_SHA512_C)
    jhd_tls_sha512_starts_ret( &ssl->handshake->fin_sha512, 1 );
#endif
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */
}

static void ssl_update_checksum_start( jhd_tls_ssl_context *ssl,
                                       const unsigned char *buf, size_t len )
{
#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_1)
     jhd_tls_md5_update_ret( &ssl->handshake->fin_md5 , buf, len );
    jhd_tls_sha1_update_ret( &ssl->handshake->fin_sha1, buf, len );
#endif
#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#if defined(JHD_TLS_SHA256_C)
    jhd_tls_sha256_update_ret( &ssl->handshake->fin_sha256, buf, len );
#endif
#if defined(JHD_TLS_SHA512_C)
    jhd_tls_sha512_update_ret( &ssl->handshake->fin_sha512, buf, len );
#endif
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */
}

#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_1)
static void ssl_update_checksum_md5sha1( jhd_tls_ssl_context *ssl,
                                         const unsigned char *buf, size_t len )
{
     jhd_tls_md5_update_ret( &ssl->handshake->fin_md5 , buf, len );
    jhd_tls_sha1_update_ret( &ssl->handshake->fin_sha1, buf, len );
}
#endif

#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#if defined(JHD_TLS_SHA256_C)
static void ssl_update_checksum_sha256( jhd_tls_ssl_context *ssl,
                                        const unsigned char *buf, size_t len )
{
    jhd_tls_sha256_update_ret( &ssl->handshake->fin_sha256, buf, len );
}
#endif

#if defined(JHD_TLS_SHA512_C)
static void ssl_update_checksum_sha384( jhd_tls_ssl_context *ssl,
                                        const unsigned char *buf, size_t len )
{
    jhd_tls_sha512_update_ret( &ssl->handshake->fin_sha512, buf, len );
}
#endif
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */

#if defined(JHD_TLS_SSL_PROTO_SSL3)
static void ssl_calc_finished_ssl(
                jhd_tls_ssl_context *ssl, unsigned char *buf, int from )
{
    const char *sender;
    jhd_tls_md5_context  md5;
    jhd_tls_sha1_context sha1;

    unsigned char padbuf[48];
    unsigned char md5sum[16];
    unsigned char sha1sum[20];

    jhd_tls_ssl_session *session = ssl->session_negotiate;
    if( !session )
        session = ssl->session;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> calc  finished ssl" ) );

    jhd_tls_md5_init( &md5 );
    jhd_tls_sha1_init( &sha1 );

    jhd_tls_md5_clone( &md5, &ssl->handshake->fin_md5 );
    jhd_tls_sha1_clone( &sha1, &ssl->handshake->fin_sha1 );

    /*
     * SSLv3:
     *   hash =
     *      MD5( master + pad2 +
     *          MD5( handshake + sender + master + pad1 ) )
     *   + SHA1( master + pad2 +
     *         SHA1( handshake + sender + master + pad1 ) )
     */

#if !defined(JHD_TLS_MD5_ALT)
    JHD_TLS_SSL_DEBUG_BUF( 4, "finished  md5 state", (unsigned char *)
                    md5.state, sizeof(  md5.state ) );
#endif

#if !defined(JHD_TLS_SHA1_ALT)
    JHD_TLS_SSL_DEBUG_BUF( 4, "finished sha1 state", (unsigned char *)
                   sha1.state, sizeof( sha1.state ) );
#endif

    sender = ( from == JHD_TLS_SSL_IS_CLIENT ) ? "CLNT"
                                       : "SRVR";

    memset( padbuf, 0x36, 48 );

    jhd_tls_md5_update_ret( &md5, (const unsigned char *) sender, 4 );
    jhd_tls_md5_update_ret( &md5, session->master, 48 );
    jhd_tls_md5_update_ret( &md5, padbuf, 48 );
    jhd_tls_md5_finish_ret( &md5, md5sum );

    jhd_tls_sha1_update_ret( &sha1, (const unsigned char *) sender, 4 );
    jhd_tls_sha1_update_ret( &sha1, session->master, 48 );
    jhd_tls_sha1_update_ret( &sha1, padbuf, 40 );
    jhd_tls_sha1_finish_ret( &sha1, sha1sum );

    memset( padbuf, 0x5C, 48 );

    jhd_tls_md5_starts_ret( &md5 );
    jhd_tls_md5_update_ret( &md5, session->master, 48 );
    jhd_tls_md5_update_ret( &md5, padbuf, 48 );
    jhd_tls_md5_update_ret( &md5, md5sum, 16 );
    jhd_tls_md5_finish_ret( &md5, buf );

    jhd_tls_sha1_starts_ret( &sha1 );
    jhd_tls_sha1_update_ret( &sha1, session->master, 48 );
    jhd_tls_sha1_update_ret( &sha1, padbuf , 40 );
    jhd_tls_sha1_update_ret( &sha1, sha1sum, 20 );
    jhd_tls_sha1_finish_ret( &sha1, buf + 16 );

    JHD_TLS_SSL_DEBUG_BUF( 3, "calc finished result", buf, 36 );

    jhd_tls_md5_free(  &md5  );
    jhd_tls_sha1_free( &sha1 );

    jhd_tls_platform_zeroize(  padbuf, sizeof(  padbuf ) );
    jhd_tls_platform_zeroize(  md5sum, sizeof(  md5sum ) );
    jhd_tls_platform_zeroize( sha1sum, sizeof( sha1sum ) );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= calc  finished" ) );
}
#endif /* JHD_TLS_SSL_PROTO_SSL3 */

#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1)
static void ssl_calc_finished_tls(
                jhd_tls_ssl_context *ssl, unsigned char *buf, int from )
{
    int len = 12;
    const char *sender;
    jhd_tls_md5_context  md5;
    jhd_tls_sha1_context sha1;
    unsigned char padbuf[36];

    jhd_tls_ssl_session *session = ssl->session_negotiate;
    if( !session )
        session = ssl->session;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> calc  finished tls" ) );

    jhd_tls_md5_init( &md5 );
    jhd_tls_sha1_init( &sha1 );

    jhd_tls_md5_clone( &md5, &ssl->handshake->fin_md5 );
    jhd_tls_sha1_clone( &sha1, &ssl->handshake->fin_sha1 );

    /*
     * TLSv1:
     *   hash = PRF( master, finished_label,
     *               MD5( handshake ) + SHA1( handshake ) )[0..11]
     */

#if !defined(JHD_TLS_MD5_ALT)
    JHD_TLS_SSL_DEBUG_BUF( 4, "finished  md5 state", (unsigned char *)
                    md5.state, sizeof(  md5.state ) );
#endif

#if !defined(JHD_TLS_SHA1_ALT)
    JHD_TLS_SSL_DEBUG_BUF( 4, "finished sha1 state", (unsigned char *)
                   sha1.state, sizeof( sha1.state ) );
#endif

    sender = ( from == JHD_TLS_SSL_IS_CLIENT )
             ? "client finished"
             : "server finished";

    jhd_tls_md5_finish_ret(  &md5, padbuf );
    jhd_tls_sha1_finish_ret( &sha1, padbuf + 16 );

    ssl->handshake->tls_prf( session->master, 48, sender,
                             padbuf, 36, buf, len );

    JHD_TLS_SSL_DEBUG_BUF( 3, "calc finished result", buf, len );

    jhd_tls_md5_free(  &md5  );
    jhd_tls_sha1_free( &sha1 );

    jhd_tls_platform_zeroize(  padbuf, sizeof(  padbuf ) );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= calc  finished" ) );
}
#endif /* JHD_TLS_SSL_PROTO_TLS1 || JHD_TLS_SSL_PROTO_TLS1_1 */

#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#if defined(JHD_TLS_SHA256_C)
static void ssl_calc_finished_tls_sha256(
                jhd_tls_ssl_context *ssl, unsigned char *buf, int from )
{
    int len = 12;
    const char *sender;
    jhd_tls_sha256_context sha256;
    unsigned char padbuf[32];

    jhd_tls_ssl_session *session = ssl->session_negotiate;
    if( !session )
        session = ssl->session;

    jhd_tls_sha256_init( &sha256 );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> calc  finished tls sha256" ) );

    jhd_tls_sha256_clone( &sha256, &ssl->handshake->fin_sha256 );

    /*
     * TLSv1.2:
     *   hash = PRF( master, finished_label,
     *               Hash( handshake ) )[0.11]
     */

#if !defined(JHD_TLS_SHA256_ALT)
    JHD_TLS_SSL_DEBUG_BUF( 4, "finished sha2 state", (unsigned char *)
                   sha256.state, sizeof( sha256.state ) );
#endif

    sender = ( from == JHD_TLS_SSL_IS_CLIENT )
             ? "client finished"
             : "server finished";

    jhd_tls_sha256_finish_ret( &sha256, padbuf );

    ssl->handshake->tls_prf( session->master, 48, sender,
                             padbuf, 32, buf, len );

    JHD_TLS_SSL_DEBUG_BUF( 3, "calc finished result", buf, len );

    jhd_tls_sha256_free( &sha256 );

    jhd_tls_platform_zeroize(  padbuf, sizeof(  padbuf ) );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= calc  finished" ) );
}
#endif /* JHD_TLS_SHA256_C */

#if defined(JHD_TLS_SHA512_C)
static void ssl_calc_finished_tls_sha384(
                jhd_tls_ssl_context *ssl, unsigned char *buf, int from )
{
    int len = 12;
    const char *sender;
    jhd_tls_sha512_context sha512;
    unsigned char padbuf[48];

    jhd_tls_ssl_session *session = ssl->session_negotiate;
    if( !session )
        session = ssl->session;

    jhd_tls_sha512_init( &sha512 );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> calc  finished tls sha384" ) );

    jhd_tls_sha512_clone( &sha512, &ssl->handshake->fin_sha512 );

    /*
     * TLSv1.2:
     *   hash = PRF( master, finished_label,
     *               Hash( handshake ) )[0.11]
     */

#if !defined(JHD_TLS_SHA512_ALT)
    JHD_TLS_SSL_DEBUG_BUF( 4, "finished sha512 state", (unsigned char *)
                   sha512.state, sizeof( sha512.state ) );
#endif

    sender = ( from == JHD_TLS_SSL_IS_CLIENT )
             ? "client finished"
             : "server finished";

    jhd_tls_sha512_finish_ret( &sha512, padbuf );

    ssl->handshake->tls_prf( session->master, 48, sender,
                             padbuf, 48, buf, len );

    JHD_TLS_SSL_DEBUG_BUF( 3, "calc finished result", buf, len );

    jhd_tls_sha512_free( &sha512 );

    jhd_tls_platform_zeroize(  padbuf, sizeof( padbuf ) );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= calc  finished" ) );
}
#endif /* JHD_TLS_SHA512_C */
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */

static void ssl_handshake_wrapup_free_hs_transform( jhd_tls_ssl_context *ssl )
{
    JHD_TLS_SSL_DEBUG_MSG( 3, ( "=> handshake wrapup: final free" ) );

    /*
     * Free our handshake params
     */
    jhd_tls_ssl_handshake_free( ssl );
    jhd_tls_free( ssl->handshake );
    ssl->handshake = NULL;

    /*
     * Free the previous transform and swith in the current one
     */
    if( ssl->transform )
    {
        jhd_tls_ssl_transform_free( ssl->transform );
        jhd_tls_free( ssl->transform );
    }
    ssl->transform = ssl->transform_negotiate;
    ssl->transform_negotiate = NULL;

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "<= handshake wrapup: final free" ) );
}

void jhd_tls_ssl_handshake_wrapup( jhd_tls_ssl_context *ssl )
{
    int resume = ssl->handshake->resume;

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "=> handshake wrapup" ) );

#if defined(JHD_TLS_SSL_RENEGOTIATION)
    if( ssl->renego_status == JHD_TLS_SSL_RENEGOTIATION_IN_PROGRESS )
    {
        ssl->renego_status =  JHD_TLS_SSL_RENEGOTIATION_DONE;
        ssl->renego_records_seen = 0;
    }
#endif

    /*
     * Free the previous session and switch in the current one
     */
    if( ssl->session )
    {
#if defined(JHD_TLS_SSL_ENCRYPT_THEN_MAC)
        /* RFC 7366 3.1: keep the EtM state */
        ssl->session_negotiate->encrypt_then_mac =
                  ssl->session->encrypt_then_mac;
#endif

        jhd_tls_ssl_session_free( ssl->session );
        jhd_tls_free( ssl->session );
    }
    ssl->session = ssl->session_negotiate;
    ssl->session_negotiate = NULL;

    /*
     * Add cache entry
     */
    if( ssl->conf->f_set_cache != NULL &&
        ssl->session->id_len != 0 &&
        resume == 0 )
    {
        if( ssl->conf->f_set_cache( ssl->conf->p_cache, ssl->session ) != 0 )
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "cache did not store session" ) );
    }

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake->flight != NULL )
    {
        /* Cancel handshake timer */
        ssl_set_timer( ssl, 0 );

        /* Keep last flight around in case we need to resend it:
         * we need the handshake and transform structures for that */
        JHD_TLS_SSL_DEBUG_MSG( 3, ( "skip freeing handshake and transform" ) );
    }
    else
#endif
        ssl_handshake_wrapup_free_hs_transform( ssl );

    ssl->state++;

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "<= handshake wrapup" ) );
}

int jhd_tls_ssl_write_finished( jhd_tls_ssl_context *ssl )
{
    int ret, hash_len;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> write finished" ) );

    /*
     * Set the out_msg pointer to the correct location based on IV length
     */
    if( ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_2 )
    {
        ssl->out_msg = ssl->out_iv + ssl->transform_negotiate->ivlen -
                       ssl->transform_negotiate->fixed_ivlen;
    }
    else
        ssl->out_msg = ssl->out_iv;

    ssl->handshake->calc_finished( ssl, ssl->out_msg + 4, ssl->conf->endpoint );

    /*
     * RFC 5246 7.4.9 (Page 63) says 12 is the default length and ciphersuites
     * may define some other value. Currently (early 2016), no defined
     * ciphersuite does this (and this is unlikely to change as activity has
     * moved to TLS 1.3 now) so we can keep the hardcoded 12 here.
     */
    hash_len = ( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 ) ? 36 : 12;

#if defined(JHD_TLS_SSL_RENEGOTIATION)
    ssl->verify_data_len = hash_len;
    memcpy( ssl->own_verify_data, ssl->out_msg + 4, hash_len );
#endif

    ssl->out_msglen  = 4 + hash_len;
    ssl->out_msgtype = JHD_TLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = JHD_TLS_SSL_HS_FINISHED;

    /*
     * In case of session resuming, invert the client and server
     * ChangeCipherSpec messages order.
     */
    if( ssl->handshake->resume != 0 )
    {
#if defined(JHD_TLS_SSL_CLI_C)
        if( ssl->conf->endpoint == JHD_TLS_SSL_IS_CLIENT )
            ssl->state = JHD_TLS_SSL_HANDSHAKE_WRAPUP;
#endif
#if defined(JHD_TLS_SSL_SRV_C)
        if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER )
            ssl->state = JHD_TLS_SSL_CLIENT_CHANGE_CIPHER_SPEC;
#endif
    }
    else
        ssl->state++;

    /*
     * Switch to our negotiated transform and session parameters for outbound
     * data.
     */
    JHD_TLS_SSL_DEBUG_MSG( 3, ( "switching to new transform spec for outbound data" ) );

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        unsigned char i;

        /* Remember current epoch settings for resending */
        ssl->handshake->alt_transform_out = ssl->transform_out;
        memcpy( ssl->handshake->alt_out_ctr, ssl->out_ctr, 8 );

        /* Set sequence_number to zero */
        memset( ssl->out_ctr + 2, 0, 6 );

        /* Increment epoch */
        for( i = 2; i > 0; i-- )
            if( ++ssl->out_ctr[i - 1] != 0 )
                break;

        /* The loop goes to its end iff the counter is wrapping */
        if( i == 0 )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "DTLS epoch would wrap" ) );
            return( JHD_TLS_ERR_SSL_COUNTER_WRAPPING );
        }
    }
    else
#endif /* JHD_TLS_SSL_PROTO_DTLS */
    memset( ssl->out_ctr, 0, 8 );

    ssl->transform_out = ssl->transform_negotiate;
    ssl->session_out = ssl->session_negotiate;

#if defined(JHD_TLS_SSL_HW_RECORD_ACCEL)
    if( jhd_tls_ssl_hw_record_activate != NULL )
    {
        if( ( ret = jhd_tls_ssl_hw_record_activate( ssl, JHD_TLS_SSL_CHANNEL_OUTBOUND ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_hw_record_activate", ret );
            return( JHD_TLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
        jhd_tls_ssl_send_flight_completed( ssl );
#endif

    if( ( ret = jhd_tls_ssl_write_record( ssl ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_write_record", ret );
        return( ret );
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= write finished" ) );

    return( 0 );
}

#if defined(JHD_TLS_SSL_PROTO_SSL3)
#define SSL_MAX_HASH_LEN 36
#else
#define SSL_MAX_HASH_LEN 12
#endif

int jhd_tls_ssl_parse_finished( jhd_tls_ssl_context *ssl )
{
    int ret;
    unsigned int hash_len;
    unsigned char buf[SSL_MAX_HASH_LEN];

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> parse finished" ) );

    ssl->handshake->calc_finished( ssl, buf, ssl->conf->endpoint ^ 1 );

    if( ( ret = jhd_tls_ssl_read_record( ssl ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_read_record", ret );
        return( ret );
    }

    if( ssl->in_msgtype != JHD_TLS_SSL_MSG_HANDSHAKE )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );
        jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                        JHD_TLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
        return( JHD_TLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    /* There is currently no ciphersuite using another length with TLS 1.2 */
#if defined(JHD_TLS_SSL_PROTO_SSL3)
    if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 )
        hash_len = 36;
    else
#endif
        hash_len = 12;

    if( ssl->in_msg[0] != JHD_TLS_SSL_HS_FINISHED ||
        ssl->in_hslen  != jhd_tls_ssl_hs_hdr_len( ssl ) + hash_len )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );
        jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                        JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR );
        return( JHD_TLS_ERR_SSL_BAD_HS_FINISHED );
    }

    if( jhd_tls_ssl_safer_memcmp( ssl->in_msg + jhd_tls_ssl_hs_hdr_len( ssl ),
                      buf, hash_len ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );
        jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                        JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR );
        return( JHD_TLS_ERR_SSL_BAD_HS_FINISHED );
    }

#if defined(JHD_TLS_SSL_RENEGOTIATION)
    ssl->verify_data_len = hash_len;
    memcpy( ssl->peer_verify_data, buf, hash_len );
#endif

    if( ssl->handshake->resume != 0 )
    {
#if defined(JHD_TLS_SSL_CLI_C)
        if( ssl->conf->endpoint == JHD_TLS_SSL_IS_CLIENT )
            ssl->state = JHD_TLS_SSL_CLIENT_CHANGE_CIPHER_SPEC;
#endif
#if defined(JHD_TLS_SSL_SRV_C)
        if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER )
            ssl->state = JHD_TLS_SSL_HANDSHAKE_WRAPUP;
#endif
    }
    else
        ssl->state++;

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
        jhd_tls_ssl_recv_flight_completed( ssl );
#endif

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= parse finished" ) );

    return( 0 );
}

static void ssl_handshake_params_init( jhd_tls_ssl_handshake_params *handshake )
{
    memset( handshake, 0, sizeof( jhd_tls_ssl_handshake_params ) );

#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_1)
     jhd_tls_md5_init(   &handshake->fin_md5  );
    jhd_tls_sha1_init(   &handshake->fin_sha1 );
     jhd_tls_md5_starts_ret( &handshake->fin_md5  );
    jhd_tls_sha1_starts_ret( &handshake->fin_sha1 );
#endif
#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#if defined(JHD_TLS_SHA256_C)
    jhd_tls_sha256_init(   &handshake->fin_sha256    );
    jhd_tls_sha256_starts_ret( &handshake->fin_sha256, 0 );
#endif
#if defined(JHD_TLS_SHA512_C)
    jhd_tls_sha512_init(   &handshake->fin_sha512    );
    jhd_tls_sha512_starts_ret( &handshake->fin_sha512, 1 );
#endif
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */

    handshake->update_checksum = ssl_update_checksum_start;

#if defined(JHD_TLS_SSL_PROTO_TLS1_2) && \
    defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
    jhd_tls_ssl_sig_hash_set_init( &handshake->hash_algs );
#endif

#if defined(JHD_TLS_DHM_C)
    jhd_tls_dhm_init( &handshake->dhm_ctx );
#endif
#if defined(JHD_TLS_ECDH_C)
    jhd_tls_ecdh_init( &handshake->ecdh_ctx );
#endif
#if defined(JHD_TLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    jhd_tls_ecjpake_init( &handshake->ecjpake_ctx );
#if defined(JHD_TLS_SSL_CLI_C)
    handshake->ecjpake_cache = NULL;
    handshake->ecjpake_cache_len = 0;
#endif
#endif

#if defined(JHD_TLS_SSL_SERVER_NAME_INDICATION)
    handshake->sni_authmode = JHD_TLS_SSL_VERIFY_UNSET;
#endif
}

static void ssl_transform_init( jhd_tls_ssl_transform *transform )
{
    memset( transform, 0, sizeof(jhd_tls_ssl_transform) );

    jhd_tls_cipher_init( &transform->cipher_ctx_enc );
    jhd_tls_cipher_init( &transform->cipher_ctx_dec );

    jhd_tls_md_init( &transform->md_ctx_enc );
    jhd_tls_md_init( &transform->md_ctx_dec );
}

void jhd_tls_ssl_session_init( jhd_tls_ssl_session *session )
{
    memset( session, 0, sizeof(jhd_tls_ssl_session) );
}

static int ssl_handshake_init( jhd_tls_ssl_context *ssl )
{
    /* Clear old handshake information if present */
    if( ssl->transform_negotiate )
        jhd_tls_ssl_transform_free( ssl->transform_negotiate );
    if( ssl->session_negotiate )
        jhd_tls_ssl_session_free( ssl->session_negotiate );
    if( ssl->handshake )
        jhd_tls_ssl_handshake_free( ssl );

    /*
     * Either the pointers are now NULL or cleared properly and can be freed.
     * Now allocate missing structures.
     */
    if( ssl->transform_negotiate == NULL )
    {
        ssl->transform_negotiate = jhd_tls_calloc( 1, sizeof(jhd_tls_ssl_transform) );
    }

    if( ssl->session_negotiate == NULL )
    {
        ssl->session_negotiate = jhd_tls_calloc( 1, sizeof(jhd_tls_ssl_session) );
    }

    if( ssl->handshake == NULL )
    {
        ssl->handshake = jhd_tls_calloc( 1, sizeof(jhd_tls_ssl_handshake_params) );
    }

    /* All pointers should exist and can be directly freed without issue */
    if( ssl->handshake == NULL ||
        ssl->transform_negotiate == NULL ||
        ssl->session_negotiate == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "alloc() of ssl sub-contexts failed" ) );

        jhd_tls_free( ssl->handshake );
        jhd_tls_free( ssl->transform_negotiate );
        jhd_tls_free( ssl->session_negotiate );

        ssl->handshake = NULL;
        ssl->transform_negotiate = NULL;
        ssl->session_negotiate = NULL;

        return( JHD_TLS_ERR_SSL_ALLOC_FAILED );
    }

    /* Initialize structures */
    jhd_tls_ssl_session_init( ssl->session_negotiate );
    ssl_transform_init( ssl->transform_negotiate );
    ssl_handshake_params_init( ssl->handshake );

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        ssl->handshake->alt_transform_out = ssl->transform_out;

        if( ssl->conf->endpoint == JHD_TLS_SSL_IS_CLIENT )
            ssl->handshake->retransmit_state = JHD_TLS_SSL_RETRANS_PREPARING;
        else
            ssl->handshake->retransmit_state = JHD_TLS_SSL_RETRANS_WAITING;

        ssl_set_timer( ssl, 0 );
    }
#endif

    return( 0 );
}

#if defined(JHD_TLS_SSL_DTLS_HELLO_VERIFY) && defined(JHD_TLS_SSL_SRV_C)
/* Dummy cookie callbacks for defaults */
static int ssl_cookie_write_dummy( void *ctx,
                      unsigned char **p, unsigned char *end,
                      const unsigned char *cli_id, size_t cli_id_len )
{
    ((void) ctx);
    ((void) p);
    ((void) end);
    ((void) cli_id);
    ((void) cli_id_len);

    return( JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

static int ssl_cookie_check_dummy( void *ctx,
                      const unsigned char *cookie, size_t cookie_len,
                      const unsigned char *cli_id, size_t cli_id_len )
{
    ((void) ctx);
    ((void) cookie);
    ((void) cookie_len);
    ((void) cli_id);
    ((void) cli_id_len);

    return( JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE );
}
#endif /* JHD_TLS_SSL_DTLS_HELLO_VERIFY && JHD_TLS_SSL_SRV_C */

/*
 * Initialize an SSL context
 */
void jhd_tls_ssl_init( jhd_tls_ssl_context *ssl )
{
    memset( ssl, 0, sizeof( jhd_tls_ssl_context ) );
}

/*
 * Setup an SSL context
 */
int jhd_tls_ssl_setup( jhd_tls_ssl_context *ssl,
                       const jhd_tls_ssl_config *conf )
{
    int ret;
    const size_t len = JHD_TLS_SSL_BUFFER_LEN;

    ssl->conf = conf;

    /*
     * Prepare base structures
     */
    if( ( ssl-> in_buf = jhd_tls_calloc( 1, len ) ) == NULL ||
        ( ssl->out_buf = jhd_tls_calloc( 1, len ) ) == NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 1, ( "alloc(%d bytes) failed", len ) );
        jhd_tls_free( ssl->in_buf );
        ssl->in_buf = NULL;
        return( JHD_TLS_ERR_SSL_ALLOC_FAILED );
    }

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        ssl->out_hdr = ssl->out_buf;
        ssl->out_ctr = ssl->out_buf +  3;
        ssl->out_len = ssl->out_buf + 11;
        ssl->out_iv  = ssl->out_buf + 13;
        ssl->out_msg = ssl->out_buf + 13;

        ssl->in_hdr = ssl->in_buf;
        ssl->in_ctr = ssl->in_buf +  3;
        ssl->in_len = ssl->in_buf + 11;
        ssl->in_iv  = ssl->in_buf + 13;
        ssl->in_msg = ssl->in_buf + 13;
    }
    else
#endif
    {
        ssl->out_ctr = ssl->out_buf;
        ssl->out_hdr = ssl->out_buf +  8;
        ssl->out_len = ssl->out_buf + 11;
        ssl->out_iv  = ssl->out_buf + 13;
        ssl->out_msg = ssl->out_buf + 13;

        ssl->in_ctr = ssl->in_buf;
        ssl->in_hdr = ssl->in_buf +  8;
        ssl->in_len = ssl->in_buf + 11;
        ssl->in_iv  = ssl->in_buf + 13;
        ssl->in_msg = ssl->in_buf + 13;
    }

    if( ( ret = ssl_handshake_init( ssl ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Reset an initialized and used SSL context for re-use while retaining
 * all application-set variables, function pointers and data.
 *
 * If partial is non-zero, keep data in the input buffer and client ID.
 * (Use when a DTLS client reconnects from the same port.)
 */
static int ssl_session_reset_int( jhd_tls_ssl_context *ssl, int partial )
{
    int ret;

    ssl->state = JHD_TLS_SSL_HELLO_REQUEST;

    /* Cancel any possibly running timer */
    ssl_set_timer( ssl, 0 );

#if defined(JHD_TLS_SSL_RENEGOTIATION)
    ssl->renego_status = JHD_TLS_SSL_INITIAL_HANDSHAKE;
    ssl->renego_records_seen = 0;

    ssl->verify_data_len = 0;
    memset( ssl->own_verify_data, 0, JHD_TLS_SSL_VERIFY_DATA_MAX_LEN );
    memset( ssl->peer_verify_data, 0, JHD_TLS_SSL_VERIFY_DATA_MAX_LEN );
#endif
    ssl->secure_renegotiation = JHD_TLS_SSL_LEGACY_RENEGOTIATION;

    ssl->in_offt = NULL;

    ssl->in_msg = ssl->in_buf + 13;
    ssl->in_msgtype = 0;
    ssl->in_msglen = 0;
    if( partial == 0 )
        ssl->in_left = 0;
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    ssl->next_record_offset = 0;
    ssl->in_epoch = 0;
#endif
#if defined(JHD_TLS_SSL_DTLS_ANTI_REPLAY)
    ssl_dtls_replay_reset( ssl );
#endif

    ssl->in_hslen = 0;
    ssl->nb_zero = 0;

    ssl->keep_current_message = 0;

    ssl->out_msg = ssl->out_buf + 13;
    ssl->out_msgtype = 0;
    ssl->out_msglen = 0;
    ssl->out_left = 0;
#if defined(JHD_TLS_SSL_CBC_RECORD_SPLITTING)
    if( ssl->split_done != JHD_TLS_SSL_CBC_RECORD_SPLITTING_DISABLED )
        ssl->split_done = 0;
#endif

    ssl->transform_in = NULL;
    ssl->transform_out = NULL;

    memset( ssl->out_buf, 0, JHD_TLS_SSL_BUFFER_LEN );
    if( partial == 0 )
        memset( ssl->in_buf, 0, JHD_TLS_SSL_BUFFER_LEN );

#if defined(JHD_TLS_SSL_HW_RECORD_ACCEL)
    if( jhd_tls_ssl_hw_record_reset != NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "going for jhd_tls_ssl_hw_record_reset()" ) );
        if( ( ret = jhd_tls_ssl_hw_record_reset( ssl ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_hw_record_reset", ret );
            return( JHD_TLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif

    if( ssl->transform )
    {
        jhd_tls_ssl_transform_free( ssl->transform );
        jhd_tls_free( ssl->transform );
        ssl->transform = NULL;
    }

    if( ssl->session )
    {
        jhd_tls_ssl_session_free( ssl->session );
        jhd_tls_free( ssl->session );
        ssl->session = NULL;
    }

#if defined(JHD_TLS_SSL_ALPN)
    ssl->alpn_chosen = NULL;
#endif

#if defined(JHD_TLS_SSL_DTLS_HELLO_VERIFY) && defined(JHD_TLS_SSL_SRV_C)
    if( partial == 0 )
    {
        jhd_tls_free( ssl->cli_id );
        ssl->cli_id = NULL;
        ssl->cli_id_len = 0;
    }
#endif

    if( ( ret = ssl_handshake_init( ssl ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Reset an initialized and used SSL context for re-use while retaining
 * all application-set variables, function pointers and data.
 */
int jhd_tls_ssl_session_reset( jhd_tls_ssl_context *ssl )
{
    return( ssl_session_reset_int( ssl, 0 ) );
}

/*
 * SSL set accessors
 */
void jhd_tls_ssl_conf_endpoint( jhd_tls_ssl_config *conf, int endpoint )
{
    conf->endpoint   = endpoint;
}

void jhd_tls_ssl_conf_transport( jhd_tls_ssl_config *conf, int transport )
{
    conf->transport = transport;
}

#if defined(JHD_TLS_SSL_DTLS_ANTI_REPLAY)
void jhd_tls_ssl_conf_dtls_anti_replay( jhd_tls_ssl_config *conf, char mode )
{
    conf->anti_replay = mode;
}
#endif

#if defined(JHD_TLS_SSL_DTLS_BADMAC_LIMIT)
void jhd_tls_ssl_conf_dtls_badmac_limit( jhd_tls_ssl_config *conf, unsigned limit )
{
    conf->badmac_limit = limit;
}
#endif

#if defined(JHD_TLS_SSL_PROTO_DTLS)
void jhd_tls_ssl_conf_handshake_timeout( jhd_tls_ssl_config *conf, uint32_t min, uint32_t max )
{
    conf->hs_timeout_min = min;
    conf->hs_timeout_max = max;
}
#endif

void jhd_tls_ssl_conf_authmode( jhd_tls_ssl_config *conf, int authmode )
{
    conf->authmode   = authmode;
}

#if defined(JHD_TLS_X509_CRT_PARSE_C)
void jhd_tls_ssl_conf_verify( jhd_tls_ssl_config *conf,
                     int (*f_vrfy)(void *, jhd_tls_x509_crt *, int, uint32_t *),
                     void *p_vrfy )
{
    conf->f_vrfy      = f_vrfy;
    conf->p_vrfy      = p_vrfy;
}
#endif /* JHD_TLS_X509_CRT_PARSE_C */

void jhd_tls_ssl_conf_rng( jhd_tls_ssl_config *conf,
                  int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng )
{
    conf->f_rng      = f_rng;
    conf->p_rng      = p_rng;
}

void jhd_tls_ssl_conf_dbg( jhd_tls_ssl_config *conf,
                  void (*f_dbg)(void *, int, const char *, int, const char *),
                  void  *p_dbg )
{
    conf->f_dbg      = f_dbg;
    conf->p_dbg      = p_dbg;
}

void jhd_tls_ssl_set_bio( jhd_tls_ssl_context *ssl,
        void *p_bio,
        jhd_tls_ssl_send_t *f_send,
        jhd_tls_ssl_recv_t *f_recv,
        jhd_tls_ssl_recv_timeout_t *f_recv_timeout )
{
    ssl->p_bio          = p_bio;
    ssl->f_send         = f_send;
    ssl->f_recv         = f_recv;
    ssl->f_recv_timeout = f_recv_timeout;
}

void jhd_tls_ssl_conf_read_timeout( jhd_tls_ssl_config *conf, uint32_t timeout )
{
    conf->read_timeout   = timeout;
}

void jhd_tls_ssl_set_timer_cb( jhd_tls_ssl_context *ssl,
                               void *p_timer,
                               jhd_tls_ssl_set_timer_t *f_set_timer,
                               jhd_tls_ssl_get_timer_t *f_get_timer )
{
    ssl->p_timer        = p_timer;
    ssl->f_set_timer    = f_set_timer;
    ssl->f_get_timer    = f_get_timer;

    /* Make sure we start with no timer running */
    ssl_set_timer( ssl, 0 );
}

#if defined(JHD_TLS_SSL_SRV_C)
void jhd_tls_ssl_conf_session_cache( jhd_tls_ssl_config *conf,
        void *p_cache,
        int (*f_get_cache)(void *, jhd_tls_ssl_session *),
        int (*f_set_cache)(void *, const jhd_tls_ssl_session *) )
{
    conf->p_cache = p_cache;
    conf->f_get_cache = f_get_cache;
    conf->f_set_cache = f_set_cache;
}
#endif /* JHD_TLS_SSL_SRV_C */

#if defined(JHD_TLS_SSL_CLI_C)
int jhd_tls_ssl_set_session( jhd_tls_ssl_context *ssl, const jhd_tls_ssl_session *session )
{
    int ret;

    if( ssl == NULL ||
        session == NULL ||
        ssl->session_negotiate == NULL ||
        ssl->conf->endpoint != JHD_TLS_SSL_IS_CLIENT )
    {
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

    if( ( ret = ssl_session_copy( ssl->session_negotiate, session ) ) != 0 )
        return( ret );

    ssl->handshake->resume = 1;

    return( 0 );
}
#endif /* JHD_TLS_SSL_CLI_C */

void jhd_tls_ssl_conf_ciphersuites( jhd_tls_ssl_config *conf,
                                   const int *ciphersuites )
{
    conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_0] = ciphersuites;
    conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_1] = ciphersuites;
    conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_2] = ciphersuites;
    conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_3] = ciphersuites;
}

void jhd_tls_ssl_conf_ciphersuites_for_version( jhd_tls_ssl_config *conf,
                                       const int *ciphersuites,
                                       int major, int minor )
{
    if( major != JHD_TLS_SSL_MAJOR_VERSION_3 )
        return;

    if( minor < JHD_TLS_SSL_MINOR_VERSION_0 || minor > JHD_TLS_SSL_MINOR_VERSION_3 )
        return;

    conf->ciphersuite_list[minor] = ciphersuites;
}

#if defined(JHD_TLS_X509_CRT_PARSE_C)
void jhd_tls_ssl_conf_cert_profile( jhd_tls_ssl_config *conf,
                                    const jhd_tls_x509_crt_profile *profile )
{
    conf->cert_profile = profile;
}

/* Append a new keycert entry to a (possibly empty) list */
static int ssl_append_key_cert( jhd_tls_ssl_key_cert **head,
                                jhd_tls_x509_crt *cert,
                                jhd_tls_pk_context *key )
{
    jhd_tls_ssl_key_cert *new;

    new = jhd_tls_calloc( 1, sizeof( jhd_tls_ssl_key_cert ) );
    if( new == NULL )
        return( JHD_TLS_ERR_SSL_ALLOC_FAILED );

    new->cert = cert;
    new->key  = key;
    new->next = NULL;

    /* Update head is the list was null, else add to the end */
    if( *head == NULL )
    {
        *head = new;
    }
    else
    {
        jhd_tls_ssl_key_cert *cur = *head;
        while( cur->next != NULL )
            cur = cur->next;
        cur->next = new;
    }

    return( 0 );
}

int jhd_tls_ssl_conf_own_cert( jhd_tls_ssl_config *conf,
                              jhd_tls_x509_crt *own_cert,
                              jhd_tls_pk_context *pk_key )
{
    return( ssl_append_key_cert( &conf->key_cert, own_cert, pk_key ) );
}

void jhd_tls_ssl_conf_ca_chain( jhd_tls_ssl_config *conf,
                               jhd_tls_x509_crt *ca_chain,
                               jhd_tls_x509_crl *ca_crl )
{
    conf->ca_chain   = ca_chain;
    conf->ca_crl     = ca_crl;
}
#endif /* JHD_TLS_X509_CRT_PARSE_C */

#if defined(JHD_TLS_SSL_SERVER_NAME_INDICATION)
int jhd_tls_ssl_set_hs_own_cert( jhd_tls_ssl_context *ssl,
                                 jhd_tls_x509_crt *own_cert,
                                 jhd_tls_pk_context *pk_key )
{
    return( ssl_append_key_cert( &ssl->handshake->sni_key_cert,
                                 own_cert, pk_key ) );
}

void jhd_tls_ssl_set_hs_ca_chain( jhd_tls_ssl_context *ssl,
                                  jhd_tls_x509_crt *ca_chain,
                                  jhd_tls_x509_crl *ca_crl )
{
    ssl->handshake->sni_ca_chain   = ca_chain;
    ssl->handshake->sni_ca_crl     = ca_crl;
}

void jhd_tls_ssl_set_hs_authmode( jhd_tls_ssl_context *ssl,
                                  int authmode )
{
    ssl->handshake->sni_authmode = authmode;
}
#endif /* JHD_TLS_SSL_SERVER_NAME_INDICATION */

#if defined(JHD_TLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
/*
 * Set EC J-PAKE password for current handshake
 */
int jhd_tls_ssl_set_hs_ecjpake_password( jhd_tls_ssl_context *ssl,
                                         const unsigned char *pw,
                                         size_t pw_len )
{
    jhd_tls_ecjpake_role role;

    if( ssl->handshake == NULL || ssl->conf == NULL )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER )
        role = JHD_TLS_ECJPAKE_SERVER;
    else
        role = JHD_TLS_ECJPAKE_CLIENT;

    return( jhd_tls_ecjpake_setup( &ssl->handshake->ecjpake_ctx,
                                   role,
                                   JHD_TLS_MD_SHA256,
                                   JHD_TLS_ECP_DP_SECP256R1,
                                   pw, pw_len ) );
}
#endif /* JHD_TLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(JHD_TLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int jhd_tls_ssl_conf_psk( jhd_tls_ssl_config *conf,
                const unsigned char *psk, size_t psk_len,
                const unsigned char *psk_identity, size_t psk_identity_len )
{
    if( psk == NULL || psk_identity == NULL )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    if( psk_len > JHD_TLS_PSK_MAX_LEN )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    /* Identity len will be encoded on two bytes */
    if( ( psk_identity_len >> 16 ) != 0 ||
        psk_identity_len > JHD_TLS_SSL_MAX_CONTENT_LEN )
    {
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

    if( conf->psk != NULL )
    {
        jhd_tls_platform_zeroize( conf->psk, conf->psk_len );

        jhd_tls_free( conf->psk );
        conf->psk = NULL;
        conf->psk_len = 0;
    }
    if( conf->psk_identity != NULL )
    {
        jhd_tls_free( conf->psk_identity );
        conf->psk_identity = NULL;
        conf->psk_identity_len = 0;
    }

    if( ( conf->psk = jhd_tls_calloc( 1, psk_len ) ) == NULL ||
        ( conf->psk_identity = jhd_tls_calloc( 1, psk_identity_len ) ) == NULL )
    {
        jhd_tls_free( conf->psk );
        jhd_tls_free( conf->psk_identity );
        conf->psk = NULL;
        conf->psk_identity = NULL;
        return( JHD_TLS_ERR_SSL_ALLOC_FAILED );
    }

    conf->psk_len = psk_len;
    conf->psk_identity_len = psk_identity_len;

    memcpy( conf->psk, psk, conf->psk_len );
    memcpy( conf->psk_identity, psk_identity, conf->psk_identity_len );

    return( 0 );
}

int jhd_tls_ssl_set_hs_psk( jhd_tls_ssl_context *ssl,
                            const unsigned char *psk, size_t psk_len )
{
    if( psk == NULL || ssl->handshake == NULL )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    if( psk_len > JHD_TLS_PSK_MAX_LEN )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    if( ssl->handshake->psk != NULL )
    {
        jhd_tls_platform_zeroize( ssl->handshake->psk,
                                  ssl->handshake->psk_len );
        jhd_tls_free( ssl->handshake->psk );
        ssl->handshake->psk_len = 0;
    }

    if( ( ssl->handshake->psk = jhd_tls_calloc( 1, psk_len ) ) == NULL )
        return( JHD_TLS_ERR_SSL_ALLOC_FAILED );

    ssl->handshake->psk_len = psk_len;
    memcpy( ssl->handshake->psk, psk, ssl->handshake->psk_len );

    return( 0 );
}

void jhd_tls_ssl_conf_psk_cb( jhd_tls_ssl_config *conf,
                     int (*f_psk)(void *, jhd_tls_ssl_context *, const unsigned char *,
                     size_t),
                     void *p_psk )
{
    conf->f_psk = f_psk;
    conf->p_psk = p_psk;
}
#endif /* JHD_TLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(JHD_TLS_DHM_C) && defined(JHD_TLS_SSL_SRV_C)

#if !defined(JHD_TLS_DEPRECATED_REMOVED)
int jhd_tls_ssl_conf_dh_param( jhd_tls_ssl_config *conf, const char *dhm_P, const char *dhm_G )
{
    int ret;

    if( ( ret = jhd_tls_mpi_read_string( &conf->dhm_P, 16, dhm_P ) ) != 0 ||
        ( ret = jhd_tls_mpi_read_string( &conf->dhm_G, 16, dhm_G ) ) != 0 )
    {
        jhd_tls_mpi_free( &conf->dhm_P );
        jhd_tls_mpi_free( &conf->dhm_G );
        return( ret );
    }

    return( 0 );
}
#endif /* JHD_TLS_DEPRECATED_REMOVED */

int jhd_tls_ssl_conf_dh_param_bin( jhd_tls_ssl_config *conf,
                                   const unsigned char *dhm_P, size_t P_len,
                                   const unsigned char *dhm_G, size_t G_len )
{
    int ret;

    if( ( ret = jhd_tls_mpi_read_binary( &conf->dhm_P, dhm_P, P_len ) ) != 0 ||
        ( ret = jhd_tls_mpi_read_binary( &conf->dhm_G, dhm_G, G_len ) ) != 0 )
    {
        jhd_tls_mpi_free( &conf->dhm_P );
        jhd_tls_mpi_free( &conf->dhm_G );
        return( ret );
    }

    return( 0 );
}

int jhd_tls_ssl_conf_dh_param_ctx( jhd_tls_ssl_config *conf, jhd_tls_dhm_context *dhm_ctx )
{
    int ret;

    if( ( ret = jhd_tls_mpi_copy( &conf->dhm_P, &dhm_ctx->P ) ) != 0 ||
        ( ret = jhd_tls_mpi_copy( &conf->dhm_G, &dhm_ctx->G ) ) != 0 )
    {
        jhd_tls_mpi_free( &conf->dhm_P );
        jhd_tls_mpi_free( &conf->dhm_G );
        return( ret );
    }

    return( 0 );
}
#endif /* JHD_TLS_DHM_C && JHD_TLS_SSL_SRV_C */

#if defined(JHD_TLS_DHM_C) && defined(JHD_TLS_SSL_CLI_C)
/*
 * Set the minimum length for Diffie-Hellman parameters
 */
void jhd_tls_ssl_conf_dhm_min_bitlen( jhd_tls_ssl_config *conf,
                                      unsigned int bitlen )
{
    conf->dhm_min_bitlen = bitlen;
}
#endif /* JHD_TLS_DHM_C && JHD_TLS_SSL_CLI_C */

#if defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
/*
 * Set allowed/preferred hashes for handshake signatures
 */
void jhd_tls_ssl_conf_sig_hashes( jhd_tls_ssl_config *conf,
                                  const int *hashes )
{
    conf->sig_hashes = hashes;
}
#endif /* JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

#if defined(JHD_TLS_ECP_C)
/*
 * Set the allowed elliptic curves
 */
void jhd_tls_ssl_conf_curves( jhd_tls_ssl_config *conf,
                             const jhd_tls_ecp_group_id *curve_list )
{
    conf->curve_list = curve_list;
}
#endif /* JHD_TLS_ECP_C */

#if defined(JHD_TLS_X509_CRT_PARSE_C)
int jhd_tls_ssl_set_hostname( jhd_tls_ssl_context *ssl, const char *hostname )
{
    /* Initialize to suppress unnecessary compiler warning */
    size_t hostname_len = 0;

    /* Check if new hostname is valid before
     * making any change to current one */
    if( hostname != NULL )
    {
        hostname_len = strlen( hostname );

        if( hostname_len > JHD_TLS_SSL_MAX_HOST_NAME_LEN )
            return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

    /* Now it's clear that we will overwrite the old hostname,
     * so we can free it safely */

    if( ssl->hostname != NULL )
    {
        jhd_tls_platform_zeroize( ssl->hostname, strlen( ssl->hostname ) );
        jhd_tls_free( ssl->hostname );
    }

    /* Passing NULL as hostname shall clear the old one */

    if( hostname == NULL )
    {
        ssl->hostname = NULL;
    }
    else
    {
        ssl->hostname = jhd_tls_calloc( 1, hostname_len + 1 );
        if( ssl->hostname == NULL )
            return( JHD_TLS_ERR_SSL_ALLOC_FAILED );

        memcpy( ssl->hostname, hostname, hostname_len );

        ssl->hostname[hostname_len] = '\0';
    }

    return( 0 );
}
#endif /* JHD_TLS_X509_CRT_PARSE_C */

#if defined(JHD_TLS_SSL_SERVER_NAME_INDICATION)
void jhd_tls_ssl_conf_sni( jhd_tls_ssl_config *conf,
                  int (*f_sni)(void *, jhd_tls_ssl_context *,
                                const unsigned char *, size_t),
                  void *p_sni )
{
    conf->f_sni = f_sni;
    conf->p_sni = p_sni;
}
#endif /* JHD_TLS_SSL_SERVER_NAME_INDICATION */

#if defined(JHD_TLS_SSL_ALPN)
int jhd_tls_ssl_conf_alpn_protocols( jhd_tls_ssl_config *conf, const char **protos )
{
    size_t cur_len, tot_len;
    const char **p;

    /*
     * RFC 7301 3.1: "Empty strings MUST NOT be included and byte strings
     * MUST NOT be truncated."
     * We check lengths now rather than later.
     */
    tot_len = 0;
    for( p = protos; *p != NULL; p++ )
    {
        cur_len = strlen( *p );
        tot_len += cur_len;

        if( cur_len == 0 || cur_len > 255 || tot_len > 65535 )
            return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

    conf->alpn_list = protos;

    return( 0 );
}

const char *jhd_tls_ssl_get_alpn_protocol( const jhd_tls_ssl_context *ssl )
{
    return( ssl->alpn_chosen );
}
#endif /* JHD_TLS_SSL_ALPN */

void jhd_tls_ssl_conf_max_version( jhd_tls_ssl_config *conf, int major, int minor )
{
    conf->max_major_ver = major;
    conf->max_minor_ver = minor;
}

void jhd_tls_ssl_conf_min_version( jhd_tls_ssl_config *conf, int major, int minor )
{
    conf->min_major_ver = major;
    conf->min_minor_ver = minor;
}

#if defined(JHD_TLS_SSL_FALLBACK_SCSV) && defined(JHD_TLS_SSL_CLI_C)
void jhd_tls_ssl_conf_fallback( jhd_tls_ssl_config *conf, char fallback )
{
    conf->fallback = fallback;
}
#endif

#if defined(JHD_TLS_SSL_SRV_C)
void jhd_tls_ssl_conf_cert_req_ca_list( jhd_tls_ssl_config *conf,
                                          char cert_req_ca_list )
{
    conf->cert_req_ca_list = cert_req_ca_list;
}
#endif

#if defined(JHD_TLS_SSL_ENCRYPT_THEN_MAC)
void jhd_tls_ssl_conf_encrypt_then_mac( jhd_tls_ssl_config *conf, char etm )
{
    conf->encrypt_then_mac = etm;
}
#endif

#if defined(JHD_TLS_SSL_EXTENDED_MASTER_SECRET)
void jhd_tls_ssl_conf_extended_master_secret( jhd_tls_ssl_config *conf, char ems )
{
    conf->extended_ms = ems;
}
#endif

#if defined(JHD_TLS_ARC4_C)
void jhd_tls_ssl_conf_arc4_support( jhd_tls_ssl_config *conf, char arc4 )
{
    conf->arc4_disabled = arc4;
}
#endif

#if defined(JHD_TLS_SSL_MAX_FRAGMENT_LENGTH)
int jhd_tls_ssl_conf_max_frag_len( jhd_tls_ssl_config *conf, unsigned char mfl_code )
{
    if( mfl_code >= JHD_TLS_SSL_MAX_FRAG_LEN_INVALID ||
        mfl_code_to_length[mfl_code] > JHD_TLS_SSL_MAX_CONTENT_LEN )
    {
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

    conf->mfl_code = mfl_code;

    return( 0 );
}
#endif /* JHD_TLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(JHD_TLS_SSL_TRUNCATED_HMAC)
void jhd_tls_ssl_conf_truncated_hmac( jhd_tls_ssl_config *conf, int truncate )
{
    conf->trunc_hmac = truncate;
}
#endif /* JHD_TLS_SSL_TRUNCATED_HMAC */

#if defined(JHD_TLS_SSL_CBC_RECORD_SPLITTING)
void jhd_tls_ssl_conf_cbc_record_splitting( jhd_tls_ssl_config *conf, char split )
{
    conf->cbc_record_splitting = split;
}
#endif

void jhd_tls_ssl_conf_legacy_renegotiation( jhd_tls_ssl_config *conf, int allow_legacy )
{
    conf->allow_legacy_renegotiation = allow_legacy;
}

#if defined(JHD_TLS_SSL_RENEGOTIATION)
void jhd_tls_ssl_conf_renegotiation( jhd_tls_ssl_config *conf, int renegotiation )
{
    conf->disable_renegotiation = renegotiation;
}

void jhd_tls_ssl_conf_renegotiation_enforced( jhd_tls_ssl_config *conf, int max_records )
{
    conf->renego_max_records = max_records;
}

void jhd_tls_ssl_conf_renegotiation_period( jhd_tls_ssl_config *conf,
                                   const unsigned char period[8] )
{
    memcpy( conf->renego_period, period, 8 );
}
#endif /* JHD_TLS_SSL_RENEGOTIATION */

#if defined(JHD_TLS_SSL_SESSION_TICKETS)
#if defined(JHD_TLS_SSL_CLI_C)
void jhd_tls_ssl_conf_session_tickets( jhd_tls_ssl_config *conf, int use_tickets )
{
    conf->session_tickets = use_tickets;
}
#endif

#if defined(JHD_TLS_SSL_SRV_C)
void jhd_tls_ssl_conf_session_tickets_cb( jhd_tls_ssl_config *conf,
        jhd_tls_ssl_ticket_write_t *f_ticket_write,
        jhd_tls_ssl_ticket_parse_t *f_ticket_parse,
        void *p_ticket )
{
    conf->f_ticket_write = f_ticket_write;
    conf->f_ticket_parse = f_ticket_parse;
    conf->p_ticket       = p_ticket;
}
#endif
#endif /* JHD_TLS_SSL_SESSION_TICKETS */

#if defined(JHD_TLS_SSL_EXPORT_KEYS)
void jhd_tls_ssl_conf_export_keys_cb( jhd_tls_ssl_config *conf,
        jhd_tls_ssl_export_keys_t *f_export_keys,
        void *p_export_keys )
{
    conf->f_export_keys = f_export_keys;
    conf->p_export_keys = p_export_keys;
}
#endif

#if defined(JHD_TLS_SSL_ASYNC_PRIVATE)
void jhd_tls_ssl_conf_async_private_cb(
    jhd_tls_ssl_config *conf,
    jhd_tls_ssl_async_sign_t *f_async_sign,
    jhd_tls_ssl_async_decrypt_t *f_async_decrypt,
    jhd_tls_ssl_async_resume_t *f_async_resume,
    jhd_tls_ssl_async_cancel_t *f_async_cancel,
    void *async_config_data )
{
    conf->f_async_sign_start = f_async_sign;
    conf->f_async_decrypt_start = f_async_decrypt;
    conf->f_async_resume = f_async_resume;
    conf->f_async_cancel = f_async_cancel;
    conf->p_async_config_data = async_config_data;
}

void *jhd_tls_ssl_conf_get_async_config_data( const jhd_tls_ssl_config *conf )
{
    return( conf->p_async_config_data );
}

void *jhd_tls_ssl_get_async_operation_data( const jhd_tls_ssl_context *ssl )
{
    if( ssl->handshake == NULL )
        return( NULL );
    else
        return( ssl->handshake->user_async_ctx );
}

void jhd_tls_ssl_set_async_operation_data( jhd_tls_ssl_context *ssl,
                                 void *ctx )
{
    if( ssl->handshake != NULL )
        ssl->handshake->user_async_ctx = ctx;
}
#endif /* JHD_TLS_SSL_ASYNC_PRIVATE */

/*
 * SSL get accessors
 */
size_t jhd_tls_ssl_get_bytes_avail( const jhd_tls_ssl_context *ssl )
{
    return( ssl->in_offt == NULL ? 0 : ssl->in_msglen );
}

int jhd_tls_ssl_check_pending( const jhd_tls_ssl_context *ssl )
{
    /*
     * Case A: We're currently holding back
     * a message for further processing.
     */

    if( ssl->keep_current_message == 1 )
    {
        JHD_TLS_SSL_DEBUG_MSG( 3, ( "ssl_check_pending: record held back for processing" ) );
        return( 1 );
    }

    /*
     * Case B: Further records are pending in the current datagram.
     */

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->in_left > ssl->next_record_offset )
    {
        JHD_TLS_SSL_DEBUG_MSG( 3, ( "ssl_check_pending: more records within current datagram" ) );
        return( 1 );
    }
#endif /* JHD_TLS_SSL_PROTO_DTLS */

    /*
     * Case C: A handshake message is being processed.
     */

    if( ssl->in_hslen > 0 && ssl->in_hslen < ssl->in_msglen )
    {
        JHD_TLS_SSL_DEBUG_MSG( 3, ( "ssl_check_pending: more handshake messages within current record" ) );
        return( 1 );
    }

    /*
     * Case D: An application data message is being processed
     */
    if( ssl->in_offt != NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 3, ( "ssl_check_pending: application data record is being processed" ) );
        return( 1 );
    }

    /*
     * In all other cases, the rest of the message can be dropped.
     * As in ssl_read_record_layer, this needs to be adapted if
     * we implement support for multiple alerts in single records.
     */

    JHD_TLS_SSL_DEBUG_MSG( 3, ( "ssl_check_pending: nothing pending" ) );
    return( 0 );
}

uint32_t jhd_tls_ssl_get_verify_result( const jhd_tls_ssl_context *ssl )
{
    if( ssl->session != NULL )
        return( ssl->session->verify_result );

    if( ssl->session_negotiate != NULL )
        return( ssl->session_negotiate->verify_result );

    return( 0xFFFFFFFF );
}

const char *jhd_tls_ssl_get_ciphersuite( const jhd_tls_ssl_context *ssl )
{
    if( ssl == NULL || ssl->session == NULL )
        return( NULL );

    return jhd_tls_ssl_get_ciphersuite_name( ssl->session->ciphersuite );
}

const char *jhd_tls_ssl_get_version( const jhd_tls_ssl_context *ssl )
{
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        switch( ssl->minor_ver )
        {
            case JHD_TLS_SSL_MINOR_VERSION_2:
                return( "DTLSv1.0" );

            case JHD_TLS_SSL_MINOR_VERSION_3:
                return( "DTLSv1.2" );

            default:
                return( "unknown (DTLS)" );
        }
    }
#endif

    switch( ssl->minor_ver )
    {
        case JHD_TLS_SSL_MINOR_VERSION_0:
            return( "SSLv3.0" );

        case JHD_TLS_SSL_MINOR_VERSION_1:
            return( "TLSv1.0" );

        case JHD_TLS_SSL_MINOR_VERSION_2:
            return( "TLSv1.1" );

        case JHD_TLS_SSL_MINOR_VERSION_3:
            return( "TLSv1.2" );

        default:
            return( "unknown" );
    }
}

int jhd_tls_ssl_get_record_expansion( const jhd_tls_ssl_context *ssl )
{
    size_t transform_expansion;
    const jhd_tls_ssl_transform *transform = ssl->transform_out;

#if defined(JHD_TLS_ZLIB_SUPPORT)
    if( ssl->session_out->compression != JHD_TLS_SSL_COMPRESS_NULL )
        return( JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE );
#endif

    if( transform == NULL )
        return( (int) jhd_tls_ssl_hdr_len( ssl ) );

    switch( jhd_tls_cipher_get_cipher_mode( &transform->cipher_ctx_enc ) )
    {
        case JHD_TLS_MODE_GCM:
        case JHD_TLS_MODE_CCM:
        case JHD_TLS_MODE_STREAM:
            transform_expansion = transform->minlen;
            break;

        case JHD_TLS_MODE_CBC:
            transform_expansion = transform->maclen
                      + jhd_tls_cipher_get_block_size( &transform->cipher_ctx_enc );
            break;

        default:
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( (int)( jhd_tls_ssl_hdr_len( ssl ) + transform_expansion ) );
}

#if defined(JHD_TLS_SSL_MAX_FRAGMENT_LENGTH)
size_t jhd_tls_ssl_get_max_frag_len( const jhd_tls_ssl_context *ssl )
{
    size_t max_len;

    /*
     * Assume mfl_code is correct since it was checked when set
     */
    max_len = mfl_code_to_length[ssl->conf->mfl_code];

    /*
     * Check if a smaller max length was negotiated
     */
    if( ssl->session_out != NULL &&
        mfl_code_to_length[ssl->session_out->mfl_code] < max_len )
    {
        max_len = mfl_code_to_length[ssl->session_out->mfl_code];
    }

    return max_len;
}
#endif /* JHD_TLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(JHD_TLS_X509_CRT_PARSE_C)
const jhd_tls_x509_crt *jhd_tls_ssl_get_peer_cert( const jhd_tls_ssl_context *ssl )
{
    if( ssl == NULL || ssl->session == NULL )
        return( NULL );

    return( ssl->session->peer_cert );
}
#endif /* JHD_TLS_X509_CRT_PARSE_C */

#if defined(JHD_TLS_SSL_CLI_C)
int jhd_tls_ssl_get_session( const jhd_tls_ssl_context *ssl, jhd_tls_ssl_session *dst )
{
    if( ssl == NULL ||
        dst == NULL ||
        ssl->session == NULL ||
        ssl->conf->endpoint != JHD_TLS_SSL_IS_CLIENT )
    {
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ssl_session_copy( dst, ssl->session ) );
}
#endif /* JHD_TLS_SSL_CLI_C */

/*
 * Perform a single step of the SSL handshake
 */
int jhd_tls_ssl_handshake_step( jhd_tls_ssl_context *ssl )
{
    int ret = JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE;

    if( ssl == NULL || ssl->conf == NULL )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

#if defined(JHD_TLS_SSL_CLI_C)
    if( ssl->conf->endpoint == JHD_TLS_SSL_IS_CLIENT )
        ret = jhd_tls_ssl_handshake_client_step( ssl );
#endif
#if defined(JHD_TLS_SSL_SRV_C)
    if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER )
        ret = jhd_tls_ssl_handshake_server_step( ssl );
#endif

    return( ret );
}

/*
 * Perform the SSL handshake
 */
int jhd_tls_ssl_handshake( jhd_tls_ssl_context *ssl )
{
    int ret = 0;

    if( ssl == NULL || ssl->conf == NULL )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> handshake" ) );

    while( ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER )
    {
        ret = jhd_tls_ssl_handshake_step( ssl );

        if( ret != 0 )
            break;
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= handshake" ) );

    return( ret );
}

#if defined(JHD_TLS_SSL_RENEGOTIATION)
#if defined(JHD_TLS_SSL_SRV_C)
/*
 * Write HelloRequest to request renegotiation on server
 */
static int ssl_write_hello_request( jhd_tls_ssl_context *ssl )
{
    int ret;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> write hello request" ) );

    ssl->out_msglen  = 4;
    ssl->out_msgtype = JHD_TLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = JHD_TLS_SSL_HS_HELLO_REQUEST;

    if( ( ret = jhd_tls_ssl_write_record( ssl ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_write_record", ret );
        return( ret );
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= write hello request" ) );

    return( 0 );
}
#endif /* JHD_TLS_SSL_SRV_C */

/*
 * Actually renegotiate current connection, triggered by either:
 * - any side: calling jhd_tls_ssl_renegotiate(),
 * - client: receiving a HelloRequest during jhd_tls_ssl_read(),
 * - server: receiving any handshake message on server during jhd_tls_ssl_read() after
 *   the initial handshake is completed.
 * If the handshake doesn't complete due to waiting for I/O, it will continue
 * during the next calls to jhd_tls_ssl_renegotiate() or jhd_tls_ssl_read() respectively.
 */
static int ssl_start_renegotiation( jhd_tls_ssl_context *ssl )
{
    int ret;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> renegotiate" ) );

    if( ( ret = ssl_handshake_init( ssl ) ) != 0 )
        return( ret );

    /* RFC 6347 4.2.2: "[...] the HelloRequest will have message_seq = 0 and
     * the ServerHello will have message_seq = 1" */
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->renego_status == JHD_TLS_SSL_RENEGOTIATION_PENDING )
    {
        if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER )
            ssl->handshake->out_msg_seq = 1;
        else
            ssl->handshake->in_msg_seq = 1;
    }
#endif

    ssl->state = JHD_TLS_SSL_HELLO_REQUEST;
    ssl->renego_status = JHD_TLS_SSL_RENEGOTIATION_IN_PROGRESS;

    if( ( ret = jhd_tls_ssl_handshake( ssl ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_handshake", ret );
        return( ret );
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= renegotiate" ) );

    return( 0 );
}

/*
 * Renegotiate current connection on client,
 * or request renegotiation on server
 */
int jhd_tls_ssl_renegotiate( jhd_tls_ssl_context *ssl )
{
    int ret = JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE;

    if( ssl == NULL || ssl->conf == NULL )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

#if defined(JHD_TLS_SSL_SRV_C)
    /* On server, just send the request */
    if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER )
    {
        if( ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER )
            return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

        ssl->renego_status = JHD_TLS_SSL_RENEGOTIATION_PENDING;

        /* Did we already try/start sending HelloRequest? */
        if( ssl->out_left != 0 )
            return( jhd_tls_ssl_flush_output( ssl ) );

        return( ssl_write_hello_request( ssl ) );
    }
#endif /* JHD_TLS_SSL_SRV_C */

#if defined(JHD_TLS_SSL_CLI_C)
    /*
     * On client, either start the renegotiation process or,
     * if already in progress, continue the handshake
     */
    if( ssl->renego_status != JHD_TLS_SSL_RENEGOTIATION_IN_PROGRESS )
    {
        if( ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER )
            return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

        if( ( ret = ssl_start_renegotiation( ssl ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "ssl_start_renegotiation", ret );
            return( ret );
        }
    }
    else
    {
        if( ( ret = jhd_tls_ssl_handshake( ssl ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_handshake", ret );
            return( ret );
        }
    }
#endif /* JHD_TLS_SSL_CLI_C */

    return( ret );
}

/*
 * Check record counters and renegotiate if they're above the limit.
 */
static int ssl_check_ctr_renegotiate( jhd_tls_ssl_context *ssl )
{
    size_t ep_len = ssl_ep_len( ssl );
    int in_ctr_cmp;
    int out_ctr_cmp;

    if( ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER ||
        ssl->renego_status == JHD_TLS_SSL_RENEGOTIATION_PENDING ||
        ssl->conf->disable_renegotiation == JHD_TLS_SSL_RENEGOTIATION_DISABLED )
    {
        return( 0 );
    }

    in_ctr_cmp = memcmp( ssl->in_ctr + ep_len,
                        ssl->conf->renego_period + ep_len, 8 - ep_len );
    out_ctr_cmp = memcmp( ssl->out_ctr + ep_len,
                          ssl->conf->renego_period + ep_len, 8 - ep_len );

    if( in_ctr_cmp <= 0 && out_ctr_cmp <= 0 )
    {
        return( 0 );
    }

    JHD_TLS_SSL_DEBUG_MSG( 1, ( "record counter limit reached: renegotiate" ) );
    return( jhd_tls_ssl_renegotiate( ssl ) );
}
#endif /* JHD_TLS_SSL_RENEGOTIATION */

/*
 * Receive application data decrypted from the SSL layer
 */
int jhd_tls_ssl_read( jhd_tls_ssl_context *ssl, unsigned char *buf, size_t len )
{
    int ret;
    size_t n;

    if( ssl == NULL || ssl->conf == NULL )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> read" ) );

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        if( ( ret = jhd_tls_ssl_flush_output( ssl ) ) != 0 )
            return( ret );

        if( ssl->handshake != NULL &&
            ssl->handshake->retransmit_state == JHD_TLS_SSL_RETRANS_SENDING )
        {
            if( ( ret = jhd_tls_ssl_resend( ssl ) ) != 0 )
                return( ret );
        }
    }
#endif

    /*
     * Check if renegotiation is necessary and/or handshake is
     * in process. If yes, perform/continue, and fall through
     * if an unexpected packet is received while the client
     * is waiting for the ServerHello.
     *
     * (There is no equivalent to the last condition on
     *  the server-side as it is not treated as within
     *  a handshake while waiting for the ClientHello
     *  after a renegotiation request.)
     */

#if defined(JHD_TLS_SSL_RENEGOTIATION)
    ret = ssl_check_ctr_renegotiate( ssl );
    if( ret != JHD_TLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO &&
        ret != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "ssl_check_ctr_renegotiate", ret );
        return( ret );
    }
#endif

    if( ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER )
    {
        ret = jhd_tls_ssl_handshake( ssl );
        if( ret != JHD_TLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO &&
            ret != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_handshake", ret );
            return( ret );
        }
    }

    /* Loop as long as no application data record is available */
    while( ssl->in_offt == NULL )
    {
        /* Start timer if not already running */
        if( ssl->f_get_timer != NULL &&
            ssl->f_get_timer( ssl->p_timer ) == -1 )
        {
            ssl_set_timer( ssl, ssl->conf->read_timeout );
        }

        if( ( ret = jhd_tls_ssl_read_record( ssl ) ) != 0 )
        {
            if( ret == JHD_TLS_ERR_SSL_CONN_EOF )
                return( 0 );

            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_read_record", ret );
            return( ret );
        }

        if( ssl->in_msglen  == 0 &&
            ssl->in_msgtype == JHD_TLS_SSL_MSG_APPLICATION_DATA )
        {
            /*
             * OpenSSL sends empty messages to randomize the IV
             */
            if( ( ret = jhd_tls_ssl_read_record( ssl ) ) != 0 )
            {
                if( ret == JHD_TLS_ERR_SSL_CONN_EOF )
                    return( 0 );

                JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_read_record", ret );
                return( ret );
            }
        }

        if( ssl->in_msgtype == JHD_TLS_SSL_MSG_HANDSHAKE )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "received handshake message" ) );

            /*
             * - For client-side, expect SERVER_HELLO_REQUEST.
             * - For server-side, expect CLIENT_HELLO.
             * - Fail (TLS) or silently drop record (DTLS) in other cases.
             */

#if defined(JHD_TLS_SSL_CLI_C)
            if( ssl->conf->endpoint == JHD_TLS_SSL_IS_CLIENT &&
                ( ssl->in_msg[0] != JHD_TLS_SSL_HS_HELLO_REQUEST ||
                  ssl->in_hslen  != jhd_tls_ssl_hs_hdr_len( ssl ) ) )
            {
                JHD_TLS_SSL_DEBUG_MSG( 1, ( "handshake received (not HelloRequest)" ) );

                /* With DTLS, drop the packet (probably from last handshake) */
#if defined(JHD_TLS_SSL_PROTO_DTLS)
                if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
                {
                    continue;
                }
#endif
                return( JHD_TLS_ERR_SSL_UNEXPECTED_MESSAGE );
            }
#endif /* JHD_TLS_SSL_CLI_C */

#if defined(JHD_TLS_SSL_SRV_C)
            if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER &&
                ssl->in_msg[0] != JHD_TLS_SSL_HS_CLIENT_HELLO )
            {
                JHD_TLS_SSL_DEBUG_MSG( 1, ( "handshake received (not ClientHello)" ) );

                /* With DTLS, drop the packet (probably from last handshake) */
#if defined(JHD_TLS_SSL_PROTO_DTLS)
                if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
                {
                    continue;
                }
#endif
                return( JHD_TLS_ERR_SSL_UNEXPECTED_MESSAGE );
            }
#endif /* JHD_TLS_SSL_SRV_C */

#if defined(JHD_TLS_SSL_RENEGOTIATION)
            /* Determine whether renegotiation attempt should be accepted */
            if( ! ( ssl->conf->disable_renegotiation == JHD_TLS_SSL_RENEGOTIATION_DISABLED ||
                    ( ssl->secure_renegotiation == JHD_TLS_SSL_LEGACY_RENEGOTIATION &&
                      ssl->conf->allow_legacy_renegotiation ==
                                                   JHD_TLS_SSL_LEGACY_NO_RENEGOTIATION ) ) )
            {
                /*
                 * Accept renegotiation request
                 */

                /* DTLS clients need to know renego is server-initiated */
#if defined(JHD_TLS_SSL_PROTO_DTLS)
                if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM &&
                    ssl->conf->endpoint == JHD_TLS_SSL_IS_CLIENT )
                {
                    ssl->renego_status = JHD_TLS_SSL_RENEGOTIATION_PENDING;
                }
#endif
                ret = ssl_start_renegotiation( ssl );
                if( ret != JHD_TLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO &&
                    ret != 0 )
                {
                    JHD_TLS_SSL_DEBUG_RET( 1, "ssl_start_renegotiation", ret );
                    return( ret );
                }
            }
            else
#endif /* JHD_TLS_SSL_RENEGOTIATION */
            {
                /*
                 * Refuse renegotiation
                 */

                JHD_TLS_SSL_DEBUG_MSG( 3, ( "refusing renegotiation, sending alert" ) );

#if defined(JHD_TLS_SSL_PROTO_SSL3)
                if( ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 )
                {
                    /* SSLv3 does not have a "no_renegotiation" warning, so
                       we send a fatal alert and abort the connection. */
                    jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                                    JHD_TLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
                    return( JHD_TLS_ERR_SSL_UNEXPECTED_MESSAGE );
                }
                else
#endif /* JHD_TLS_SSL_PROTO_SSL3 */
#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_2)
                if( ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_1 )
                {
                    if( ( ret = jhd_tls_ssl_send_alert_message( ssl,
                                    JHD_TLS_SSL_ALERT_LEVEL_WARNING,
                                    JHD_TLS_SSL_ALERT_MSG_NO_RENEGOTIATION ) ) != 0 )
                    {
                        return( ret );
                    }
                }
                else
#endif /* JHD_TLS_SSL_PROTO_TLS1 || JHD_TLS_SSL_PROTO_TLS1_1 ||
          JHD_TLS_SSL_PROTO_TLS1_2 */
                {
                    JHD_TLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                    return( JHD_TLS_ERR_SSL_INTERNAL_ERROR );
                }
            }

            /* At this point, we don't know whether the renegotiation has been
             * completed or not. The cases to consider are the following:
             * 1) The renegotiation is complete. In this case, no new record
             *    has been read yet.
             * 2) The renegotiation is incomplete because the client received
             *    an application data record while awaiting the ServerHello.
             * 3) The renegotiation is incomplete because the client received
             *    a non-handshake, non-application data message while awaiting
             *    the ServerHello.
             * In each of these case, looping will be the proper action:
             * - For 1), the next iteration will read a new record and check
             *   if it's application data.
             * - For 2), the loop condition isn't satisfied as application data
             *   is present, hence continue is the same as break
             * - For 3), the loop condition is satisfied and read_record
             *   will re-deliver the message that was held back by the client
             *   when expecting the ServerHello.
             */
            continue;
        }
#if defined(JHD_TLS_SSL_RENEGOTIATION)
        else if( ssl->renego_status == JHD_TLS_SSL_RENEGOTIATION_PENDING )
        {
            if( ssl->conf->renego_max_records >= 0 )
            {
                if( ++ssl->renego_records_seen > ssl->conf->renego_max_records )
                {
                    JHD_TLS_SSL_DEBUG_MSG( 1, ( "renegotiation requested, "
                                        "but not honored by client" ) );
                    return( JHD_TLS_ERR_SSL_UNEXPECTED_MESSAGE );
                }
            }
        }
#endif /* JHD_TLS_SSL_RENEGOTIATION */

        /* Fatal and closure alerts handled by jhd_tls_ssl_read_record() */
        if( ssl->in_msgtype == JHD_TLS_SSL_MSG_ALERT )
        {
            JHD_TLS_SSL_DEBUG_MSG( 2, ( "ignoring non-fatal non-closure alert" ) );
            return( JHD_TLS_ERR_SSL_WANT_READ );
        }

        if( ssl->in_msgtype != JHD_TLS_SSL_MSG_APPLICATION_DATA )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "bad application data message" ) );
            return( JHD_TLS_ERR_SSL_UNEXPECTED_MESSAGE );
        }

        ssl->in_offt = ssl->in_msg;

        /* We're going to return something now, cancel timer,
         * except if handshake (renegotiation) is in progress */
        if( ssl->state == JHD_TLS_SSL_HANDSHAKE_OVER )
            ssl_set_timer( ssl, 0 );

#if defined(JHD_TLS_SSL_PROTO_DTLS)
        /* If we requested renego but received AppData, resend HelloRequest.
         * Do it now, after setting in_offt, to avoid taking this branch
         * again if ssl_write_hello_request() returns WANT_WRITE */
#if defined(JHD_TLS_SSL_SRV_C) && defined(JHD_TLS_SSL_RENEGOTIATION)
        if( ssl->conf->endpoint == JHD_TLS_SSL_IS_SERVER &&
            ssl->renego_status == JHD_TLS_SSL_RENEGOTIATION_PENDING )
        {
            if( ( ret = ssl_resend_hello_request( ssl ) ) != 0 )
            {
                JHD_TLS_SSL_DEBUG_RET( 1, "ssl_resend_hello_request", ret );
                return( ret );
            }
        }
#endif /* JHD_TLS_SSL_SRV_C && JHD_TLS_SSL_RENEGOTIATION */
#endif /* JHD_TLS_SSL_PROTO_DTLS */
    }

    n = ( len < ssl->in_msglen )
        ? len : ssl->in_msglen;

    memcpy( buf, ssl->in_offt, n );
    ssl->in_msglen -= n;

    if( ssl->in_msglen == 0 )
    {
        /* all bytes consumed */
        ssl->in_offt = NULL;
        ssl->keep_current_message = 0;
    }
    else
    {
        /* more data available */
        ssl->in_offt += n;
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= read" ) );

    return( (int) n );
}

/*
 * Send application data to be encrypted by the SSL layer,
 * taking care of max fragment length and buffer size
 */
static int ssl_write_real( jhd_tls_ssl_context *ssl,
                           const unsigned char *buf, size_t len )
{
    int ret;
#if defined(JHD_TLS_SSL_MAX_FRAGMENT_LENGTH)
    size_t max_len = jhd_tls_ssl_get_max_frag_len( ssl );
#else
    size_t max_len = JHD_TLS_SSL_MAX_CONTENT_LEN;
#endif /* JHD_TLS_SSL_MAX_FRAGMENT_LENGTH */
    if( len > max_len )
    {
#if defined(JHD_TLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
        {
            JHD_TLS_SSL_DEBUG_MSG( 1, ( "fragment larger than the (negotiated) "
                                "maximum fragment length: %d > %d",
                                len, max_len ) );
            return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );
        }
        else
#endif
            len = max_len;
    }

    if( ssl->out_left != 0 )
    {
        if( ( ret = jhd_tls_ssl_flush_output( ssl ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_flush_output", ret );
            return( ret );
        }
    }
    else
    {
        ssl->out_msglen  = len;
        ssl->out_msgtype = JHD_TLS_SSL_MSG_APPLICATION_DATA;
        memcpy( ssl->out_msg, buf, len );

        if( ( ret = jhd_tls_ssl_write_record( ssl ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_write_record", ret );
            return( ret );
        }
    }

    return( (int) len );
}

/*
 * Write application data, doing 1/n-1 splitting if necessary.
 *
 * With non-blocking I/O, ssl_write_real() may return WANT_WRITE,
 * then the caller will call us again with the same arguments, so
 * remember whether we already did the split or not.
 */
#if defined(JHD_TLS_SSL_CBC_RECORD_SPLITTING)
static int ssl_write_split( jhd_tls_ssl_context *ssl,
                            const unsigned char *buf, size_t len )
{
    int ret;

    if( ssl->conf->cbc_record_splitting ==
            JHD_TLS_SSL_CBC_RECORD_SPLITTING_DISABLED ||
        len <= 1 ||
        ssl->minor_ver > JHD_TLS_SSL_MINOR_VERSION_1 ||
        jhd_tls_cipher_get_cipher_mode( &ssl->transform_out->cipher_ctx_enc )
                                != JHD_TLS_MODE_CBC )
    {
        return( ssl_write_real( ssl, buf, len ) );
    }

    if( ssl->split_done == 0 )
    {
        if( ( ret = ssl_write_real( ssl, buf, 1 ) ) <= 0 )
            return( ret );
        ssl->split_done = 1;
    }

    if( ( ret = ssl_write_real( ssl, buf + 1, len - 1 ) ) <= 0 )
        return( ret );
    ssl->split_done = 0;

    return( ret + 1 );
}
#endif /* JHD_TLS_SSL_CBC_RECORD_SPLITTING */

/*
 * Write application data (public-facing wrapper)
 */
int jhd_tls_ssl_write( jhd_tls_ssl_context *ssl, const unsigned char *buf, size_t len )
{
    int ret;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> write" ) );

    if( ssl == NULL || ssl->conf == NULL )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

#if defined(JHD_TLS_SSL_RENEGOTIATION)
    if( ( ret = ssl_check_ctr_renegotiate( ssl ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "ssl_check_ctr_renegotiate", ret );
        return( ret );
    }
#endif

    if( ssl->state != JHD_TLS_SSL_HANDSHAKE_OVER )
    {
        if( ( ret = jhd_tls_ssl_handshake( ssl ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_handshake", ret );
            return( ret );
        }
    }

#if defined(JHD_TLS_SSL_CBC_RECORD_SPLITTING)
    ret = ssl_write_split( ssl, buf, len );
#else
    ret = ssl_write_real( ssl, buf, len );
#endif

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= write" ) );

    return( ret );
}

/*
 * Notify the peer that the connection is being closed
 */
int jhd_tls_ssl_close_notify( jhd_tls_ssl_context *ssl )
{
    int ret;

    if( ssl == NULL || ssl->conf == NULL )
        return( JHD_TLS_ERR_SSL_BAD_INPUT_DATA );

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> write close notify" ) );

    if( ssl->out_left != 0 )
        return( jhd_tls_ssl_flush_output( ssl ) );

    if( ssl->state == JHD_TLS_SSL_HANDSHAKE_OVER )
    {
        if( ( ret = jhd_tls_ssl_send_alert_message( ssl,
                        JHD_TLS_SSL_ALERT_LEVEL_WARNING,
                        JHD_TLS_SSL_ALERT_MSG_CLOSE_NOTIFY ) ) != 0 )
        {
            JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_ssl_send_alert_message", ret );
            return( ret );
        }
    }

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= write close notify" ) );

    return( 0 );
}

void jhd_tls_ssl_transform_free( jhd_tls_ssl_transform *transform )
{
    if( transform == NULL )
        return;

#if defined(JHD_TLS_ZLIB_SUPPORT)
    deflateEnd( &transform->ctx_deflate );
    inflateEnd( &transform->ctx_inflate );
#endif

    jhd_tls_cipher_free( &transform->cipher_ctx_enc );
    jhd_tls_cipher_free( &transform->cipher_ctx_dec );

    jhd_tls_md_free( &transform->md_ctx_enc );
    jhd_tls_md_free( &transform->md_ctx_dec );

    jhd_tls_platform_zeroize( transform, sizeof( jhd_tls_ssl_transform ) );
}

#if defined(JHD_TLS_X509_CRT_PARSE_C)
static void ssl_key_cert_free( jhd_tls_ssl_key_cert *key_cert )
{
    jhd_tls_ssl_key_cert *cur = key_cert, *next;

    while( cur != NULL )
    {
        next = cur->next;
        jhd_tls_free( cur );
        cur = next;
    }
}
#endif /* JHD_TLS_X509_CRT_PARSE_C */

void jhd_tls_ssl_handshake_free( jhd_tls_ssl_context *ssl )
{
    jhd_tls_ssl_handshake_params *handshake = ssl->handshake;

    if( handshake == NULL )
        return;

#if defined(JHD_TLS_SSL_ASYNC_PRIVATE)
    if( ssl->conf->f_async_cancel != NULL && handshake->async_in_progress != 0 )
    {
        ssl->conf->f_async_cancel( ssl );
        handshake->async_in_progress = 0;
    }
#endif /* JHD_TLS_SSL_ASYNC_PRIVATE */

#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_1)
    jhd_tls_md5_free(    &handshake->fin_md5  );
    jhd_tls_sha1_free(   &handshake->fin_sha1 );
#endif
#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#if defined(JHD_TLS_SHA256_C)
    jhd_tls_sha256_free(   &handshake->fin_sha256    );
#endif
#if defined(JHD_TLS_SHA512_C)
    jhd_tls_sha512_free(   &handshake->fin_sha512    );
#endif
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */

#if defined(JHD_TLS_DHM_C)
    jhd_tls_dhm_free( &handshake->dhm_ctx );
#endif
#if defined(JHD_TLS_ECDH_C)
    jhd_tls_ecdh_free( &handshake->ecdh_ctx );
#endif
#if defined(JHD_TLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    jhd_tls_ecjpake_free( &handshake->ecjpake_ctx );
#if defined(JHD_TLS_SSL_CLI_C)
    jhd_tls_free( handshake->ecjpake_cache );
    handshake->ecjpake_cache = NULL;
    handshake->ecjpake_cache_len = 0;
#endif
#endif

#if defined(JHD_TLS_ECDH_C) || defined(JHD_TLS_ECDSA_C) || \
    defined(JHD_TLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    /* explicit void pointer cast for buggy MS compiler */
    jhd_tls_free( (void *) handshake->curves );
#endif

#if defined(JHD_TLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    if( handshake->psk != NULL )
    {
        jhd_tls_platform_zeroize( handshake->psk, handshake->psk_len );
        jhd_tls_free( handshake->psk );
    }
#endif

#if defined(JHD_TLS_X509_CRT_PARSE_C) && \
    defined(JHD_TLS_SSL_SERVER_NAME_INDICATION)
    /*
     * Free only the linked list wrapper, not the keys themselves
     * since the belong to the SNI callback
     */
    if( handshake->sni_key_cert != NULL )
    {
        jhd_tls_ssl_key_cert *cur = handshake->sni_key_cert, *next;

        while( cur != NULL )
        {
            next = cur->next;
            jhd_tls_free( cur );
            cur = next;
        }
    }
#endif /* JHD_TLS_X509_CRT_PARSE_C && JHD_TLS_SSL_SERVER_NAME_INDICATION */

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    jhd_tls_free( handshake->verify_cookie );
    jhd_tls_free( handshake->hs_msg );
    ssl_flight_free( handshake->flight );
#endif

    jhd_tls_platform_zeroize( handshake,
                              sizeof( jhd_tls_ssl_handshake_params ) );
}

void jhd_tls_ssl_session_free( jhd_tls_ssl_session *session )
{
    if( session == NULL )
        return;

#if defined(JHD_TLS_X509_CRT_PARSE_C)
    if( session->peer_cert != NULL )
    {
        jhd_tls_x509_crt_free( session->peer_cert );
        jhd_tls_free( session->peer_cert );
    }
#endif

#if defined(JHD_TLS_SSL_SESSION_TICKETS) && defined(JHD_TLS_SSL_CLI_C)
    jhd_tls_free( session->ticket );
#endif

    jhd_tls_platform_zeroize( session, sizeof( jhd_tls_ssl_session ) );
}

/*
 * Free an SSL context
 */
void jhd_tls_ssl_free( jhd_tls_ssl_context *ssl )
{
    if( ssl == NULL )
        return;

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "=> free" ) );

    if( ssl->out_buf != NULL )
    {
        jhd_tls_platform_zeroize( ssl->out_buf, JHD_TLS_SSL_BUFFER_LEN );
        jhd_tls_free( ssl->out_buf );
    }

    if( ssl->in_buf != NULL )
    {
        jhd_tls_platform_zeroize( ssl->in_buf, JHD_TLS_SSL_BUFFER_LEN );
        jhd_tls_free( ssl->in_buf );
    }

#if defined(JHD_TLS_ZLIB_SUPPORT)
    if( ssl->compress_buf != NULL )
    {
        jhd_tls_platform_zeroize( ssl->compress_buf, JHD_TLS_SSL_BUFFER_LEN );
        jhd_tls_free( ssl->compress_buf );
    }
#endif

    if( ssl->transform )
    {
        jhd_tls_ssl_transform_free( ssl->transform );
        jhd_tls_free( ssl->transform );
    }

    if( ssl->handshake )
    {
        jhd_tls_ssl_handshake_free( ssl );
        jhd_tls_ssl_transform_free( ssl->transform_negotiate );
        jhd_tls_ssl_session_free( ssl->session_negotiate );

        jhd_tls_free( ssl->handshake );
        jhd_tls_free( ssl->transform_negotiate );
        jhd_tls_free( ssl->session_negotiate );
    }

    if( ssl->session )
    {
        jhd_tls_ssl_session_free( ssl->session );
        jhd_tls_free( ssl->session );
    }

#if defined(JHD_TLS_X509_CRT_PARSE_C)
    if( ssl->hostname != NULL )
    {
        jhd_tls_platform_zeroize( ssl->hostname, strlen( ssl->hostname ) );
        jhd_tls_free( ssl->hostname );
    }
#endif

#if defined(JHD_TLS_SSL_HW_RECORD_ACCEL)
    if( jhd_tls_ssl_hw_record_finish != NULL )
    {
        JHD_TLS_SSL_DEBUG_MSG( 2, ( "going for jhd_tls_ssl_hw_record_finish()" ) );
        jhd_tls_ssl_hw_record_finish( ssl );
    }
#endif

#if defined(JHD_TLS_SSL_DTLS_HELLO_VERIFY) && defined(JHD_TLS_SSL_SRV_C)
    jhd_tls_free( ssl->cli_id );
#endif

    JHD_TLS_SSL_DEBUG_MSG( 2, ( "<= free" ) );

    /* Actually clear after last debug message */
    jhd_tls_platform_zeroize( ssl, sizeof( jhd_tls_ssl_context ) );
}

/*
 * Initialze jhd_tls_ssl_config
 */
void jhd_tls_ssl_config_init( jhd_tls_ssl_config *conf )
{
    memset( conf, 0, sizeof( jhd_tls_ssl_config ) );
}

#if defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
static int ssl_preset_default_hashes[] = {
#if defined(JHD_TLS_SHA512_C)
    JHD_TLS_MD_SHA512,
    JHD_TLS_MD_SHA384,
#endif
#if defined(JHD_TLS_SHA256_C)
    JHD_TLS_MD_SHA256,
    JHD_TLS_MD_SHA224,
#endif
#if defined(JHD_TLS_SHA1_C) && defined(JHD_TLS_TLS_DEFAULT_ALLOW_SHA1_IN_KEY_EXCHANGE)
    JHD_TLS_MD_SHA1,
#endif
    JHD_TLS_MD_NONE
};
#endif

static int ssl_preset_suiteb_ciphersuites[] = {
    JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    0
};

#if defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
static int ssl_preset_suiteb_hashes[] = {
    JHD_TLS_MD_SHA256,
    JHD_TLS_MD_SHA384,
    JHD_TLS_MD_NONE
};
#endif

#if defined(JHD_TLS_ECP_C)
static jhd_tls_ecp_group_id ssl_preset_suiteb_curves[] = {
    JHD_TLS_ECP_DP_SECP256R1,
    JHD_TLS_ECP_DP_SECP384R1,
    JHD_TLS_ECP_DP_NONE
};
#endif

/*
 * Load default in jhd_tls_ssl_config
 */
int jhd_tls_ssl_config_defaults( jhd_tls_ssl_config *conf,
                                 int endpoint, int transport, int preset )
{
#if defined(JHD_TLS_DHM_C) && defined(JHD_TLS_SSL_SRV_C)
    int ret;
#endif

    /* Use the functions here so that they are covered in tests,
     * but otherwise access member directly for efficiency */
    jhd_tls_ssl_conf_endpoint( conf, endpoint );
    jhd_tls_ssl_conf_transport( conf, transport );

    /*
     * Things that are common to all presets
     */
#if defined(JHD_TLS_SSL_CLI_C)
    if( endpoint == JHD_TLS_SSL_IS_CLIENT )
    {
        conf->authmode = JHD_TLS_SSL_VERIFY_REQUIRED;
#if defined(JHD_TLS_SSL_SESSION_TICKETS)
        conf->session_tickets = JHD_TLS_SSL_SESSION_TICKETS_ENABLED;
#endif
    }
#endif

#if defined(JHD_TLS_ARC4_C)
    conf->arc4_disabled = JHD_TLS_SSL_ARC4_DISABLED;
#endif

#if defined(JHD_TLS_SSL_ENCRYPT_THEN_MAC)
    conf->encrypt_then_mac = JHD_TLS_SSL_ETM_ENABLED;
#endif

#if defined(JHD_TLS_SSL_EXTENDED_MASTER_SECRET)
    conf->extended_ms = JHD_TLS_SSL_EXTENDED_MS_ENABLED;
#endif

#if defined(JHD_TLS_SSL_CBC_RECORD_SPLITTING)
    conf->cbc_record_splitting = JHD_TLS_SSL_CBC_RECORD_SPLITTING_ENABLED;
#endif

#if defined(JHD_TLS_SSL_DTLS_HELLO_VERIFY) && defined(JHD_TLS_SSL_SRV_C)
    conf->f_cookie_write = ssl_cookie_write_dummy;
    conf->f_cookie_check = ssl_cookie_check_dummy;
#endif

#if defined(JHD_TLS_SSL_DTLS_ANTI_REPLAY)
    conf->anti_replay = JHD_TLS_SSL_ANTI_REPLAY_ENABLED;
#endif

#if defined(JHD_TLS_SSL_SRV_C)
    conf->cert_req_ca_list = JHD_TLS_SSL_CERT_REQ_CA_LIST_ENABLED;
#endif

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    conf->hs_timeout_min = JHD_TLS_SSL_DTLS_TIMEOUT_DFL_MIN;
    conf->hs_timeout_max = JHD_TLS_SSL_DTLS_TIMEOUT_DFL_MAX;
#endif

#if defined(JHD_TLS_SSL_RENEGOTIATION)
    conf->renego_max_records = JHD_TLS_SSL_RENEGO_MAX_RECORDS_DEFAULT;
    memset( conf->renego_period,     0x00, 2 );
    memset( conf->renego_period + 2, 0xFF, 6 );
#endif

#if defined(JHD_TLS_DHM_C) && defined(JHD_TLS_SSL_SRV_C)
            if( endpoint == JHD_TLS_SSL_IS_SERVER )
            {
                const unsigned char dhm_p[] =
                    JHD_TLS_DHM_RFC3526_MODP_2048_P_BIN;
                const unsigned char dhm_g[] =
                    JHD_TLS_DHM_RFC3526_MODP_2048_G_BIN;

                if ( ( ret = jhd_tls_ssl_conf_dh_param_bin( conf,
                                               dhm_p, sizeof( dhm_p ),
                                               dhm_g, sizeof( dhm_g ) ) ) != 0 )
                {
                    return( ret );
                }
            }
#endif

    /*
     * Preset-specific defaults
     */
    switch( preset )
    {
        /*
         * NSA Suite B
         */
        case JHD_TLS_SSL_PRESET_SUITEB:
            conf->min_major_ver = JHD_TLS_SSL_MAJOR_VERSION_3;
            conf->min_minor_ver = JHD_TLS_SSL_MINOR_VERSION_3; /* TLS 1.2 */
            conf->max_major_ver = JHD_TLS_SSL_MAX_MAJOR_VERSION;
            conf->max_minor_ver = JHD_TLS_SSL_MAX_MINOR_VERSION;

            conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_0] =
            conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_1] =
            conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_2] =
            conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_3] =
                                   ssl_preset_suiteb_ciphersuites;

#if defined(JHD_TLS_X509_CRT_PARSE_C)
            conf->cert_profile = &jhd_tls_x509_crt_profile_suiteb;
#endif

#if defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
            conf->sig_hashes = ssl_preset_suiteb_hashes;
#endif

#if defined(JHD_TLS_ECP_C)
            conf->curve_list = ssl_preset_suiteb_curves;
#endif
            break;

        /*
         * Default
         */
        default:
            conf->min_major_ver = ( JHD_TLS_SSL_MIN_MAJOR_VERSION >
                                    JHD_TLS_SSL_MIN_VALID_MAJOR_VERSION ) ?
                                    JHD_TLS_SSL_MIN_MAJOR_VERSION :
                                    JHD_TLS_SSL_MIN_VALID_MAJOR_VERSION;
            conf->min_minor_ver = ( JHD_TLS_SSL_MIN_MINOR_VERSION >
                                    JHD_TLS_SSL_MIN_VALID_MINOR_VERSION ) ?
                                    JHD_TLS_SSL_MIN_MINOR_VERSION :
                                    JHD_TLS_SSL_MIN_VALID_MINOR_VERSION;
            conf->max_major_ver = JHD_TLS_SSL_MAX_MAJOR_VERSION;
            conf->max_minor_ver = JHD_TLS_SSL_MAX_MINOR_VERSION;

#if defined(JHD_TLS_SSL_PROTO_DTLS)
            if( transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
                conf->min_minor_ver = JHD_TLS_SSL_MINOR_VERSION_2;
#endif

            conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_0] =
            conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_1] =
            conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_2] =
            conf->ciphersuite_list[JHD_TLS_SSL_MINOR_VERSION_3] =
                                   jhd_tls_ssl_list_ciphersuites();

#if defined(JHD_TLS_X509_CRT_PARSE_C)
            conf->cert_profile = &jhd_tls_x509_crt_profile_default;
#endif

#if defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
            conf->sig_hashes = ssl_preset_default_hashes;
#endif

#if defined(JHD_TLS_ECP_C)
            conf->curve_list = jhd_tls_ecp_grp_id_list();
#endif

#if defined(JHD_TLS_DHM_C) && defined(JHD_TLS_SSL_CLI_C)
            conf->dhm_min_bitlen = 1024;
#endif
    }

    return( 0 );
}

/*
 * Free jhd_tls_ssl_config
 */
void jhd_tls_ssl_config_free( jhd_tls_ssl_config *conf )
{
#if defined(JHD_TLS_DHM_C)
    jhd_tls_mpi_free( &conf->dhm_P );
    jhd_tls_mpi_free( &conf->dhm_G );
#endif

#if defined(JHD_TLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    if( conf->psk != NULL )
    {
        jhd_tls_platform_zeroize( conf->psk, conf->psk_len );
        jhd_tls_free( conf->psk );
        conf->psk = NULL;
        conf->psk_len = 0;
    }

    if( conf->psk_identity != NULL )
    {
        jhd_tls_platform_zeroize( conf->psk_identity, conf->psk_identity_len );
        jhd_tls_free( conf->psk_identity );
        conf->psk_identity = NULL;
        conf->psk_identity_len = 0;
    }
#endif

#if defined(JHD_TLS_X509_CRT_PARSE_C)
    ssl_key_cert_free( conf->key_cert );
#endif

    jhd_tls_platform_zeroize( conf, sizeof( jhd_tls_ssl_config ) );
}

#if defined(JHD_TLS_PK_C) && \
    ( defined(JHD_TLS_RSA_C) || defined(JHD_TLS_ECDSA_C) )
/*
 * Convert between JHD_TLS_PK_XXX and SSL_SIG_XXX
 */
unsigned char jhd_tls_ssl_sig_from_pk( jhd_tls_pk_context *pk )
{
#if defined(JHD_TLS_RSA_C)
    if( jhd_tls_pk_can_do( pk, JHD_TLS_PK_RSA ) )
        return( JHD_TLS_SSL_SIG_RSA );
#endif
#if defined(JHD_TLS_ECDSA_C)
    if( jhd_tls_pk_can_do( pk, JHD_TLS_PK_ECDSA ) )
        return( JHD_TLS_SSL_SIG_ECDSA );
#endif
    return( JHD_TLS_SSL_SIG_ANON );
}

unsigned char jhd_tls_ssl_sig_from_pk_alg( jhd_tls_pk_type_t type )
{
    switch( type ) {
        case JHD_TLS_PK_RSA:
            return( JHD_TLS_SSL_SIG_RSA );
        case JHD_TLS_PK_ECDSA:
        case JHD_TLS_PK_ECKEY:
            return( JHD_TLS_SSL_SIG_ECDSA );
        default:
            return( JHD_TLS_SSL_SIG_ANON );
    }
}

jhd_tls_pk_type_t jhd_tls_ssl_pk_alg_from_sig( unsigned char sig )
{
    switch( sig )
    {
#if defined(JHD_TLS_RSA_C)
        case JHD_TLS_SSL_SIG_RSA:
            return( JHD_TLS_PK_RSA );
#endif
#if defined(JHD_TLS_ECDSA_C)
        case JHD_TLS_SSL_SIG_ECDSA:
            return( JHD_TLS_PK_ECDSA );
#endif
        default:
            return( JHD_TLS_PK_NONE );
    }
}
#endif /* JHD_TLS_PK_C && ( JHD_TLS_RSA_C || JHD_TLS_ECDSA_C ) */

#if defined(JHD_TLS_SSL_PROTO_TLS1_2) && \
    defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

/* Find an entry in a signature-hash set matching a given hash algorithm. */
jhd_tls_md_type_t jhd_tls_ssl_sig_hash_set_find( jhd_tls_ssl_sig_hash_set_t *set,
                                                 jhd_tls_pk_type_t sig_alg )
{
    switch( sig_alg )
    {
        case JHD_TLS_PK_RSA:
            return( set->rsa );
        case JHD_TLS_PK_ECDSA:
            return( set->ecdsa );
        default:
            return( JHD_TLS_MD_NONE );
    }
}

/* Add a signature-hash-pair to a signature-hash set */
void jhd_tls_ssl_sig_hash_set_add( jhd_tls_ssl_sig_hash_set_t *set,
                                   jhd_tls_pk_type_t sig_alg,
                                   jhd_tls_md_type_t md_alg )
{
    switch( sig_alg )
    {
        case JHD_TLS_PK_RSA:
            if( set->rsa == JHD_TLS_MD_NONE )
                set->rsa = md_alg;
            break;

        case JHD_TLS_PK_ECDSA:
            if( set->ecdsa == JHD_TLS_MD_NONE )
                set->ecdsa = md_alg;
            break;

        default:
            break;
    }
}

/* Allow exactly one hash algorithm for each signature. */
void jhd_tls_ssl_sig_hash_set_const_hash( jhd_tls_ssl_sig_hash_set_t *set,
                                          jhd_tls_md_type_t md_alg )
{
    set->rsa   = md_alg;
    set->ecdsa = md_alg;
}

#endif /* JHD_TLS_SSL_PROTO_TLS1_2) &&
          JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

/*
 * Convert from JHD_TLS_SSL_HASH_XXX to JHD_TLS_MD_XXX
 */
jhd_tls_md_type_t jhd_tls_ssl_md_alg_from_hash( unsigned char hash )
{
    switch( hash )
    {
#if defined(JHD_TLS_MD5_C)
        case JHD_TLS_SSL_HASH_MD5:
            return( JHD_TLS_MD_MD5 );
#endif
#if defined(JHD_TLS_SHA1_C)
        case JHD_TLS_SSL_HASH_SHA1:
            return( JHD_TLS_MD_SHA1 );
#endif
#if defined(JHD_TLS_SHA256_C)
        case JHD_TLS_SSL_HASH_SHA224:
            return( JHD_TLS_MD_SHA224 );
        case JHD_TLS_SSL_HASH_SHA256:
            return( JHD_TLS_MD_SHA256 );
#endif
#if defined(JHD_TLS_SHA512_C)
        case JHD_TLS_SSL_HASH_SHA384:
            return( JHD_TLS_MD_SHA384 );
        case JHD_TLS_SSL_HASH_SHA512:
            return( JHD_TLS_MD_SHA512 );
#endif
        default:
            return( JHD_TLS_MD_NONE );
    }
}

/*
 * Convert from JHD_TLS_MD_XXX to JHD_TLS_SSL_HASH_XXX
 */
unsigned char jhd_tls_ssl_hash_from_md_alg( int md )
{
    switch( md )
    {
#if defined(JHD_TLS_MD5_C)
        case JHD_TLS_MD_MD5:
            return( JHD_TLS_SSL_HASH_MD5 );
#endif
#if defined(JHD_TLS_SHA1_C)
        case JHD_TLS_MD_SHA1:
            return( JHD_TLS_SSL_HASH_SHA1 );
#endif
#if defined(JHD_TLS_SHA256_C)
        case JHD_TLS_MD_SHA224:
            return( JHD_TLS_SSL_HASH_SHA224 );
        case JHD_TLS_MD_SHA256:
            return( JHD_TLS_SSL_HASH_SHA256 );
#endif
#if defined(JHD_TLS_SHA512_C)
        case JHD_TLS_MD_SHA384:
            return( JHD_TLS_SSL_HASH_SHA384 );
        case JHD_TLS_MD_SHA512:
            return( JHD_TLS_SSL_HASH_SHA512 );
#endif
        default:
            return( JHD_TLS_SSL_HASH_NONE );
    }
}

#if defined(JHD_TLS_ECP_C)
/*
 * Check if a curve proposed by the peer is in our list.
 * Return 0 if we're willing to use it, -1 otherwise.
 */
int jhd_tls_ssl_check_curve( const jhd_tls_ssl_context *ssl, jhd_tls_ecp_group_id grp_id )
{
    const jhd_tls_ecp_group_id *gid;

    if( ssl->conf->curve_list == NULL )
        return( -1 );

    for( gid = ssl->conf->curve_list; *gid != JHD_TLS_ECP_DP_NONE; gid++ )
        if( *gid == grp_id )
            return( 0 );

    return( -1 );
}
#endif /* JHD_TLS_ECP_C */

#if defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
/*
 * Check if a hash proposed by the peer is in our list.
 * Return 0 if we're willing to use it, -1 otherwise.
 */
int jhd_tls_ssl_check_sig_hash( const jhd_tls_ssl_context *ssl,
                                jhd_tls_md_type_t md )
{
    const int *cur;

    if( ssl->conf->sig_hashes == NULL )
        return( -1 );

    for( cur = ssl->conf->sig_hashes; *cur != JHD_TLS_MD_NONE; cur++ )
        if( *cur == (int) md )
            return( 0 );

    return( -1 );
}
#endif /* JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

#if defined(JHD_TLS_X509_CRT_PARSE_C)
int jhd_tls_ssl_check_cert_usage( const jhd_tls_x509_crt *cert,
                          const jhd_tls_ssl_ciphersuite_t *ciphersuite,
                          int cert_endpoint,
                          uint32_t *flags )
{
    int ret = 0;
#if defined(JHD_TLS_X509_CHECK_KEY_USAGE)
    int usage = 0;
#endif
#if defined(JHD_TLS_X509_CHECK_EXTENDED_KEY_USAGE)
    const char *ext_oid;
    size_t ext_len;
#endif

#if !defined(JHD_TLS_X509_CHECK_KEY_USAGE) &&          \
    !defined(JHD_TLS_X509_CHECK_EXTENDED_KEY_USAGE)
    ((void) cert);
    ((void) cert_endpoint);
    ((void) flags);
#endif

#if defined(JHD_TLS_X509_CHECK_KEY_USAGE)
    if( cert_endpoint == JHD_TLS_SSL_IS_SERVER )
    {
        /* Server part of the key exchange */
        switch( ciphersuite->key_exchange )
        {
            case JHD_TLS_KEY_EXCHANGE_RSA:
            case JHD_TLS_KEY_EXCHANGE_RSA_PSK:
                usage = JHD_TLS_X509_KU_KEY_ENCIPHERMENT;
                break;

            case JHD_TLS_KEY_EXCHANGE_DHE_RSA:
            case JHD_TLS_KEY_EXCHANGE_ECDHE_RSA:
            case JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA:
                usage = JHD_TLS_X509_KU_DIGITAL_SIGNATURE;
                break;

            case JHD_TLS_KEY_EXCHANGE_ECDH_RSA:
            case JHD_TLS_KEY_EXCHANGE_ECDH_ECDSA:
                usage = JHD_TLS_X509_KU_KEY_AGREEMENT;
                break;

            /* Don't use default: we want warnings when adding new values */
            case JHD_TLS_KEY_EXCHANGE_NONE:
            case JHD_TLS_KEY_EXCHANGE_PSK:
            case JHD_TLS_KEY_EXCHANGE_DHE_PSK:
            case JHD_TLS_KEY_EXCHANGE_ECDHE_PSK:
            case JHD_TLS_KEY_EXCHANGE_ECJPAKE:
                usage = 0;
        }
    }
    else
    {
        /* Client auth: we only implement rsa_sign and jhd_tls_ecdsa_sign for now */
        usage = JHD_TLS_X509_KU_DIGITAL_SIGNATURE;
    }

    if( jhd_tls_x509_crt_check_key_usage( cert, usage ) != 0 )
    {
        *flags |= JHD_TLS_X509_BADCERT_KEY_USAGE;
        ret = -1;
    }
#else
    ((void) ciphersuite);
#endif /* JHD_TLS_X509_CHECK_KEY_USAGE */

#if defined(JHD_TLS_X509_CHECK_EXTENDED_KEY_USAGE)
    if( cert_endpoint == JHD_TLS_SSL_IS_SERVER )
    {
        ext_oid = JHD_TLS_OID_SERVER_AUTH;
        ext_len = JHD_TLS_OID_SIZE( JHD_TLS_OID_SERVER_AUTH );
    }
    else
    {
        ext_oid = JHD_TLS_OID_CLIENT_AUTH;
        ext_len = JHD_TLS_OID_SIZE( JHD_TLS_OID_CLIENT_AUTH );
    }

    if( jhd_tls_x509_crt_check_extended_key_usage( cert, ext_oid, ext_len ) != 0 )
    {
        *flags |= JHD_TLS_X509_BADCERT_EXT_KEY_USAGE;
        ret = -1;
    }
#endif /* JHD_TLS_X509_CHECK_EXTENDED_KEY_USAGE */

    return( ret );
}
#endif /* JHD_TLS_X509_CRT_PARSE_C */

/*
 * Convert version numbers to/from wire format
 * and, for DTLS, to/from TLS equivalent.
 *
 * For TLS this is the identity.
 * For DTLS, use 1's complement (v -> 255 - v, and then map as follows:
 * 1.0 <-> 3.2      (DTLS 1.0 is based on TLS 1.1)
 * 1.x <-> 3.x+1    for x != 0 (DTLS 1.2 based on TLS 1.2)
 */
void jhd_tls_ssl_write_version( int major, int minor, int transport,
                        unsigned char ver[2] )
{
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        if( minor == JHD_TLS_SSL_MINOR_VERSION_2 )
            --minor; /* DTLS 1.0 stored as TLS 1.1 internally */

        ver[0] = (unsigned char)( 255 - ( major - 2 ) );
        ver[1] = (unsigned char)( 255 - ( minor - 1 ) );
    }
    else
#else
    ((void) transport);
#endif
    {
        ver[0] = (unsigned char) major;
        ver[1] = (unsigned char) minor;
    }
}

void jhd_tls_ssl_read_version( int *major, int *minor, int transport,
                       const unsigned char ver[2] )
{
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
    {
        *major = 255 - ver[0] + 2;
        *minor = 255 - ver[1] + 1;

        if( *minor == JHD_TLS_SSL_MINOR_VERSION_1 )
            ++*minor; /* DTLS 1.0 stored as TLS 1.1 internally */
    }
    else
#else
    ((void) transport);
#endif
    {
        *major = ver[0];
        *minor = ver[1];
    }
}

int jhd_tls_ssl_set_calc_verify_md( jhd_tls_ssl_context *ssl, int md )
{
#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
    if( ssl->minor_ver != JHD_TLS_SSL_MINOR_VERSION_3 )
        return JHD_TLS_ERR_SSL_INVALID_VERIFY_HASH;

    switch( md )
    {
#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1)
#if defined(JHD_TLS_MD5_C)
        case JHD_TLS_SSL_HASH_MD5:
            return JHD_TLS_ERR_SSL_INVALID_VERIFY_HASH;
#endif
#if defined(JHD_TLS_SHA1_C)
        case JHD_TLS_SSL_HASH_SHA1:
            ssl->handshake->calc_verify = ssl_calc_verify_tls;
            break;
#endif
#endif /* JHD_TLS_SSL_PROTO_TLS1 || JHD_TLS_SSL_PROTO_TLS1_1 */
#if defined(JHD_TLS_SHA512_C)
        case JHD_TLS_SSL_HASH_SHA384:
            ssl->handshake->calc_verify = ssl_calc_verify_tls_sha384;
            break;
#endif
#if defined(JHD_TLS_SHA256_C)
        case JHD_TLS_SSL_HASH_SHA256:
            ssl->handshake->calc_verify = ssl_calc_verify_tls_sha256;
            break;
#endif
        default:
            return JHD_TLS_ERR_SSL_INVALID_VERIFY_HASH;
    }

    return 0;
#else /* !JHD_TLS_SSL_PROTO_TLS1_2 */
    (void) ssl;
    (void) md;

    return JHD_TLS_ERR_SSL_INVALID_VERIFY_HASH;
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */
}

#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_1)
int jhd_tls_ssl_get_key_exchange_md_ssl_tls( jhd_tls_ssl_context *ssl,
                                        unsigned char *output,
                                        unsigned char *data, size_t data_len )
{
    int ret = 0;
    jhd_tls_md5_context jhd_tls_md5;
    jhd_tls_sha1_context jhd_tls_sha1;

    jhd_tls_md5_init( &jhd_tls_md5 );
    jhd_tls_sha1_init( &jhd_tls_sha1 );

    /*
     * digitally-signed struct {
     *     opaque md5_hash[16];
     *     opaque sha_hash[20];
     * };
     *
     * md5_hash
     *     MD5(ClientHello.random + ServerHello.random
     *                            + ServerParams);
     * sha_hash
     *     SHA(ClientHello.random + ServerHello.random
     *                            + ServerParams);
     */
    if( ( ret = jhd_tls_md5_starts_ret( &jhd_tls_md5 ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_md5_starts_ret", ret );
        goto exit;
    }
    if( ( ret = jhd_tls_md5_update_ret( &jhd_tls_md5,
                                        ssl->handshake->randbytes, 64 ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_md5_update_ret", ret );
        goto exit;
    }
    if( ( ret = jhd_tls_md5_update_ret( &jhd_tls_md5, data, data_len ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_md5_update_ret", ret );
        goto exit;
    }
    if( ( ret = jhd_tls_md5_finish_ret( &jhd_tls_md5, output ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_md5_finish_ret", ret );
        goto exit;
    }

    if( ( ret = jhd_tls_sha1_starts_ret( &jhd_tls_sha1 ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_sha1_starts_ret", ret );
        goto exit;
    }
    if( ( ret = jhd_tls_sha1_update_ret( &jhd_tls_sha1,
                                         ssl->handshake->randbytes, 64 ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_sha1_update_ret", ret );
        goto exit;
    }
    if( ( ret = jhd_tls_sha1_update_ret( &jhd_tls_sha1, data,
                                         data_len ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_sha1_update_ret", ret );
        goto exit;
    }
    if( ( ret = jhd_tls_sha1_finish_ret( &jhd_tls_sha1,
                                         output + 16 ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_sha1_finish_ret", ret );
        goto exit;
    }

exit:
    jhd_tls_md5_free( &jhd_tls_md5 );
    jhd_tls_sha1_free( &jhd_tls_sha1 );

    if( ret != 0 )
        jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                        JHD_TLS_SSL_ALERT_MSG_INTERNAL_ERROR );

    return( ret );

}
#endif /* JHD_TLS_SSL_PROTO_SSL3 || JHD_TLS_SSL_PROTO_TLS1 || \
          JHD_TLS_SSL_PROTO_TLS1_1 */

#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_2)
int jhd_tls_ssl_get_key_exchange_md_tls1_2( jhd_tls_ssl_context *ssl,
                                            unsigned char *hash, size_t *hashlen,
                                            unsigned char *data, size_t data_len,
                                            jhd_tls_md_type_t md_alg )
{
    int ret = 0;
    jhd_tls_md_context_t ctx;
    const jhd_tls_md_info_t *md_info = jhd_tls_md_info_from_type( md_alg );
    *hashlen = jhd_tls_md_get_size( md_info );

    jhd_tls_md_init( &ctx );

    /*
     * digitally-signed struct {
     *     opaque client_random[32];
     *     opaque server_random[32];
     *     ServerDHParams params;
     * };
     */
    if( ( ret = jhd_tls_md_setup( &ctx, md_info, 0 ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_md_setup", ret );
        goto exit;
    }
    if( ( ret = jhd_tls_md_starts( &ctx ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_md_starts", ret );
        goto exit;
    }
    if( ( ret = jhd_tls_md_update( &ctx, ssl->handshake->randbytes, 64 ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_md_update", ret );
        goto exit;
    }
    if( ( ret = jhd_tls_md_update( &ctx, data, data_len ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_md_update", ret );
        goto exit;
    }
    if( ( ret = jhd_tls_md_finish( &ctx, hash ) ) != 0 )
    {
        JHD_TLS_SSL_DEBUG_RET( 1, "jhd_tls_md_finish", ret );
        goto exit;
    }

exit:
    jhd_tls_md_free( &ctx );

    if( ret != 0 )
        jhd_tls_ssl_send_alert_message( ssl, JHD_TLS_SSL_ALERT_LEVEL_FATAL,
                                        JHD_TLS_SSL_ALERT_MSG_INTERNAL_ERROR );

    return( ret );
}
#endif /* JHD_TLS_SSL_PROTO_TLS1 || JHD_TLS_SSL_PROTO_TLS1_1 || \
          JHD_TLS_SSL_PROTO_TLS1_2 */

#endif /* JHD_TLS_SSL_TLS_C */