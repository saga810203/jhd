/*
 *  Public Key abstraction layer
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

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_PK_C)
#include <tls/jhd_tls_pk.h>
#include <tls/jhd_tls_pk_internal.h>


#if defined(JHD_TLS_RSA_C)
#include <tls/jhd_tls_rsa.h>
#endif
#if defined(JHD_TLS_ECP_C)
#include <tls/jhd_tls_ecp.h>
#endif
#if defined(JHD_TLS_ECDSA_C)
#include <tls/jhd_tls_ecdsa.h>
#endif

#include <limits.h>
#include <stdint.h>

/*
 * Initialise a jhd_tls_pk_context
 */
void jhd_tls_pk_init( jhd_tls_pk_context *ctx )
{
    if( ctx == NULL )
        return;

    ctx->pk_info = NULL;
    ctx->pk_ctx = NULL;
}

/*
 * Free (the components of) a jhd_tls_pk_context
 */
void jhd_tls_pk_free( jhd_tls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return;

    ctx->pk_info->ctx_free_func( ctx->pk_ctx );

    jhd_tls_platform_zeroize( ctx, sizeof( jhd_tls_pk_context ) );
}

/*
 * Get pk_info structure from type
 */
const jhd_tls_pk_info_t * jhd_tls_pk_info_from_type( jhd_tls_pk_type_t pk_type )
{
    switch( pk_type ) {
#if defined(JHD_TLS_RSA_C)
        case JHD_TLS_PK_RSA:
            return( &jhd_tls_rsa_info );
#endif
#if defined(JHD_TLS_ECP_C)
        case JHD_TLS_PK_ECKEY:
            return( &jhd_tls_eckey_info );
        case JHD_TLS_PK_ECKEY_DH:
            return( &jhd_tls_eckeydh_info );
#endif
#if defined(JHD_TLS_ECDSA_C)
        case JHD_TLS_PK_ECDSA:
            return( &jhd_tls_ecdsa_info );
#endif
        /* JHD_TLS_PK_RSA_ALT omitted on purpose */
        default:
            return( NULL );
    }
}

/*
 * Initialise context
 */
int jhd_tls_pk_setup( jhd_tls_pk_context *ctx, const jhd_tls_pk_info_t *info )
{
    if( ctx == NULL || info == NULL || ctx->pk_info != NULL )
        return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( JHD_TLS_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    return( 0 );
}

#if defined(JHD_TLS_PK_RSA_ALT_SUPPORT)
/*
 * Initialize an RSA-alt context
 */
int jhd_tls_pk_setup_rsa_alt( jhd_tls_pk_context *ctx, void * key,
                         jhd_tls_pk_rsa_alt_decrypt_func decrypt_func,
                         jhd_tls_pk_rsa_alt_sign_func sign_func,
                         jhd_tls_pk_rsa_alt_key_len_func key_len_func )
{
    jhd_tls_rsa_alt_context *rsa_alt;
    const jhd_tls_pk_info_t *info = &jhd_tls_rsa_alt_info;

    if( ctx == NULL || ctx->pk_info != NULL )
        return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( JHD_TLS_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    rsa_alt = (jhd_tls_rsa_alt_context *) ctx->pk_ctx;

    rsa_alt->key = key;
    rsa_alt->decrypt_func = decrypt_func;
    rsa_alt->sign_func = sign_func;
    rsa_alt->key_len_func = key_len_func;

    return( 0 );
}
#endif /* JHD_TLS_PK_RSA_ALT_SUPPORT */

/*
 * Tell if a PK can do the operations of the given type
 */
int jhd_tls_pk_can_do( const jhd_tls_pk_context *ctx, jhd_tls_pk_type_t type )
{
    /* null or NONE context can't do anything */
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->can_do( type ) );
}

/*
 * Helper for jhd_tls_pk_sign and jhd_tls_pk_verify
 */
static inline int pk_hashlen_helper( jhd_tls_md_type_t md_alg, size_t *hash_len )
{
    const jhd_tls_md_info_t *md_info;

    if( *hash_len != 0 )
        return( 0 );

    if( ( md_info = jhd_tls_md_info_from_type( md_alg ) ) == NULL )
        return( -1 );

    *hash_len = jhd_tls_md_get_size( md_info );
    return( 0 );
}

/*
 * Verify a signature
 */
int jhd_tls_pk_verify( jhd_tls_pk_context *ctx, jhd_tls_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len )
{
    if( ctx == NULL || ctx->pk_info == NULL ||
        pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->verify_func == NULL )
        return( JHD_TLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->verify_func( ctx->pk_ctx, md_alg, hash, hash_len,
                                       sig, sig_len ) );
}

/*
 * Verify a signature with options
 */
int jhd_tls_pk_verify_ext( jhd_tls_pk_type_t type, const void *options,
                   jhd_tls_pk_context *ctx, jhd_tls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );

    if( ! jhd_tls_pk_can_do( ctx, type ) )
        return( JHD_TLS_ERR_PK_TYPE_MISMATCH );

    if( type == JHD_TLS_PK_RSASSA_PSS )
    {
#if defined(JHD_TLS_RSA_C) && defined(JHD_TLS_PKCS1_V21)
        int ret;
        const jhd_tls_pk_rsassa_pss_options *pss_opts;

#if SIZE_MAX > UINT_MAX
        if( md_alg == JHD_TLS_MD_NONE && UINT_MAX < hash_len )
            return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

        if( options == NULL )
            return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );

        pss_opts = (const jhd_tls_pk_rsassa_pss_options *) options;

        if( sig_len < jhd_tls_pk_get_len( ctx ) )
            return( JHD_TLS_ERR_RSA_VERIFY_FAILED );

        ret = jhd_tls_rsa_rsassa_pss_verify_ext( jhd_tls_pk_rsa( *ctx ),
                NULL, NULL, JHD_TLS_RSA_PUBLIC,
                md_alg, (unsigned int) hash_len, hash,
                pss_opts->mgf1_hash_id,
                pss_opts->expected_salt_len,
                sig );
        if( ret != 0 )
            return( ret );

        if( sig_len > jhd_tls_pk_get_len( ctx ) )
            return( JHD_TLS_ERR_PK_SIG_LEN_MISMATCH );

        return( 0 );
#else
        return( JHD_TLS_ERR_PK_FEATURE_UNAVAILABLE );
#endif /* JHD_TLS_RSA_C && JHD_TLS_PKCS1_V21 */
    }

    /* General case: no options */
    if( options != NULL )
        return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );

    return( jhd_tls_pk_verify( ctx, md_alg, hash, hash_len, sig, sig_len ) );
}

/*
 * Make a signature
 */
int jhd_tls_pk_sign( jhd_tls_pk_context *ctx, jhd_tls_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL ||
        pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->sign_func == NULL )
        return( JHD_TLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->sign_func( ctx->pk_ctx, md_alg, hash, hash_len,
                                     sig, sig_len, f_rng, p_rng ) );
}

/*
 * Decrypt message
 */
int jhd_tls_pk_decrypt( jhd_tls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->decrypt_func == NULL )
        return( JHD_TLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->decrypt_func( ctx->pk_ctx, input, ilen,
                output, olen, osize, f_rng, p_rng ) );
}

/*
 * Encrypt message
 */
int jhd_tls_pk_encrypt( jhd_tls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->encrypt_func == NULL )
        return( JHD_TLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->encrypt_func( ctx->pk_ctx, input, ilen,
                output, olen, osize, f_rng, p_rng ) );
}

/*
 * Check public-private key pair
 */
int jhd_tls_pk_check_pair( const jhd_tls_pk_context *pub, const jhd_tls_pk_context *prv )
{
    if( pub == NULL || pub->pk_info == NULL ||
        prv == NULL || prv->pk_info == NULL ||
        prv->pk_info->check_pair_func == NULL )
    {
        return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );
    }

    if( prv->pk_info->type == JHD_TLS_PK_RSA_ALT )
    {
        if( pub->pk_info->type != JHD_TLS_PK_RSA )
            return( JHD_TLS_ERR_PK_TYPE_MISMATCH );
    }
    else
    {
        if( pub->pk_info != prv->pk_info )
            return( JHD_TLS_ERR_PK_TYPE_MISMATCH );
    }

    return( prv->pk_info->check_pair_func( pub->pk_ctx, prv->pk_ctx ) );
}

/*
 * Get key size in bits
 */
size_t jhd_tls_pk_get_bitlen( const jhd_tls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->get_bitlen( ctx->pk_ctx ) );
}

/*
 * Export debug information
 */
int jhd_tls_pk_debug( const jhd_tls_pk_context *ctx, jhd_tls_pk_debug_item *items )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( JHD_TLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->debug_func == NULL )
        return( JHD_TLS_ERR_PK_TYPE_MISMATCH );

    ctx->pk_info->debug_func( ctx->pk_ctx, items );
    return( 0 );
}

/*
 * Access the PK type name
 */
const char *jhd_tls_pk_get_name( const jhd_tls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( "invalid PK" );

    return( ctx->pk_info->name );
}

/*
 * Access the PK type
 */
jhd_tls_pk_type_t jhd_tls_pk_get_type( const jhd_tls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( JHD_TLS_PK_NONE );

    return( ctx->pk_info->type );
}

#endif /* JHD_TLS_PK_C */
