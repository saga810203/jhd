/**
 * \file jhd_tls_md.c
 *
 * \brief Generic message digest wrapper for mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
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

#if defined(JHD_TLS_MD_C)

#include <tls/jhd_tls_md.h>
#include <tls/jhd_tls_md_internal.h>

#if defined(JHD_TLS_PLATFORM_C)
#include <tls/jhd_tls_platform.h>
#else
#include <stdlib.h>
#define jhd_tls_calloc    calloc
#define jhd_tls_free       free
#endif

#include <string.h>

#if defined(JHD_TLS_FS_IO)
#include <stdio.h>
#endif

/*
 * Reminder: update profiles in x509_crt.c when adding a new hash!
 */
static const int supported_digests[] = {

#if defined(JHD_TLS_SHA512_C)
        JHD_TLS_MD_SHA512,
        JHD_TLS_MD_SHA384,
#endif

#if defined(JHD_TLS_SHA256_C)
        JHD_TLS_MD_SHA256,
        JHD_TLS_MD_SHA224,
#endif

#if defined(JHD_TLS_SHA1_C)
        JHD_TLS_MD_SHA1,
#endif

#if defined(JHD_TLS_RIPEMD160_C)
        JHD_TLS_MD_RIPEMD160,
#endif

#if defined(JHD_TLS_MD5_C)
        JHD_TLS_MD_MD5,
#endif

#if defined(JHD_TLS_MD4_C)
        JHD_TLS_MD_MD4,
#endif

#if defined(JHD_TLS_MD2_C)
        JHD_TLS_MD_MD2,
#endif

        JHD_TLS_MD_NONE
};

const int *jhd_tls_md_list( void )
{
    return( supported_digests );
}

const jhd_tls_md_info_t *jhd_tls_md_info_from_string( const char *md_name )
{
    if( NULL == md_name )
        return( NULL );

    /* Get the appropriate digest information */
#if defined(JHD_TLS_MD2_C)
    if( !strcmp( "MD2", md_name ) )
        return jhd_tls_md_info_from_type( JHD_TLS_MD_MD2 );
#endif
#if defined(JHD_TLS_MD4_C)
    if( !strcmp( "MD4", md_name ) )
        return jhd_tls_md_info_from_type( JHD_TLS_MD_MD4 );
#endif
#if defined(JHD_TLS_MD5_C)
    if( !strcmp( "MD5", md_name ) )
        return jhd_tls_md_info_from_type( JHD_TLS_MD_MD5 );
#endif
#if defined(JHD_TLS_RIPEMD160_C)
    if( !strcmp( "RIPEMD160", md_name ) )
        return jhd_tls_md_info_from_type( JHD_TLS_MD_RIPEMD160 );
#endif
#if defined(JHD_TLS_SHA1_C)
    if( !strcmp( "SHA1", md_name ) || !strcmp( "SHA", md_name ) )
        return jhd_tls_md_info_from_type( JHD_TLS_MD_SHA1 );
#endif
#if defined(JHD_TLS_SHA256_C)
    if( !strcmp( "SHA224", md_name ) )
        return jhd_tls_md_info_from_type( JHD_TLS_MD_SHA224 );
    if( !strcmp( "SHA256", md_name ) )
        return jhd_tls_md_info_from_type( JHD_TLS_MD_SHA256 );
#endif
#if defined(JHD_TLS_SHA512_C)
    if( !strcmp( "SHA384", md_name ) )
        return jhd_tls_md_info_from_type( JHD_TLS_MD_SHA384 );
    if( !strcmp( "SHA512", md_name ) )
        return jhd_tls_md_info_from_type( JHD_TLS_MD_SHA512 );
#endif
    return( NULL );
}

const jhd_tls_md_info_t *jhd_tls_md_info_from_type( jhd_tls_md_type_t md_type )
{
    switch( md_type )
    {
#if defined(JHD_TLS_MD2_C)
        case JHD_TLS_MD_MD2:
            return( &jhd_tls_md2_info );
#endif
#if defined(JHD_TLS_MD4_C)
        case JHD_TLS_MD_MD4:
            return( &jhd_tls_md4_info );
#endif
#if defined(JHD_TLS_MD5_C)
        case JHD_TLS_MD_MD5:
            return( &jhd_tls_md5_info );
#endif
#if defined(JHD_TLS_RIPEMD160_C)
        case JHD_TLS_MD_RIPEMD160:
            return( &jhd_tls_ripemd160_info );
#endif
#if defined(JHD_TLS_SHA1_C)
        case JHD_TLS_MD_SHA1:
            return( &jhd_tls_sha1_info );
#endif
#if defined(JHD_TLS_SHA256_C)
        case JHD_TLS_MD_SHA224:
            return( &jhd_tls_sha224_info );
        case JHD_TLS_MD_SHA256:
            return( &jhd_tls_sha256_info );
#endif
#if defined(JHD_TLS_SHA512_C)
        case JHD_TLS_MD_SHA384:
            return( &jhd_tls_sha384_info );
        case JHD_TLS_MD_SHA512:
            return( &jhd_tls_sha512_info );
#endif
        default:
            return( NULL );
    }
}

void jhd_tls_md_init( jhd_tls_md_context_t *ctx )
{
    memset( ctx, 0, sizeof( jhd_tls_md_context_t ) );
}

void jhd_tls_md_free( jhd_tls_md_context_t *ctx )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return;

    if( ctx->md_ctx != NULL )
        ctx->md_info->ctx_free_func( ctx->md_ctx );

    if( ctx->hmac_ctx != NULL )
    {
        jhd_tls_platform_zeroize( ctx->hmac_ctx,
                                  2 * ctx->md_info->block_size );
        jhd_tls_free( ctx->hmac_ctx );
    }

    jhd_tls_platform_zeroize( ctx, sizeof( jhd_tls_md_context_t ) );
}

int jhd_tls_md_clone( jhd_tls_md_context_t *dst,
                      const jhd_tls_md_context_t *src )
{
    if( dst == NULL || dst->md_info == NULL ||
        src == NULL || src->md_info == NULL ||
        dst->md_info != src->md_info )
    {
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );
    }

    dst->md_info->clone_func( dst->md_ctx, src->md_ctx );

    return( 0 );
}

#if ! defined(JHD_TLS_DEPRECATED_REMOVED)
int jhd_tls_md_init_ctx( jhd_tls_md_context_t *ctx, const jhd_tls_md_info_t *md_info )
{
    return jhd_tls_md_setup( ctx, md_info, 1 );
}
#endif

int jhd_tls_md_setup( jhd_tls_md_context_t *ctx, const jhd_tls_md_info_t *md_info, int hmac )
{
    if( md_info == NULL || ctx == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    if( ( ctx->md_ctx = md_info->ctx_alloc_func() ) == NULL )
        return( JHD_TLS_ERR_MD_ALLOC_FAILED );

    if( hmac != 0 )
    {
        ctx->hmac_ctx = jhd_tls_calloc( 2, md_info->block_size );
        if( ctx->hmac_ctx == NULL )
        {
            md_info->ctx_free_func( ctx->md_ctx );
            return( JHD_TLS_ERR_MD_ALLOC_FAILED );
        }
    }

    ctx->md_info = md_info;

    return( 0 );
}

int jhd_tls_md_starts( jhd_tls_md_context_t *ctx )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    return( ctx->md_info->starts_func( ctx->md_ctx ) );
}

int jhd_tls_md_update( jhd_tls_md_context_t *ctx, const unsigned char *input, size_t ilen )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    return( ctx->md_info->update_func( ctx->md_ctx, input, ilen ) );
}

int jhd_tls_md_finish( jhd_tls_md_context_t *ctx, unsigned char *output )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    return( ctx->md_info->finish_func( ctx->md_ctx, output ) );
}

int jhd_tls_md( const jhd_tls_md_info_t *md_info, const unsigned char *input, size_t ilen,
            unsigned char *output )
{
    if( md_info == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    return( md_info->digest_func( input, ilen, output ) );
}

#if defined(JHD_TLS_FS_IO)
int jhd_tls_md_file( const jhd_tls_md_info_t *md_info, const char *path, unsigned char *output )
{
    int ret;
    FILE *f;
    size_t n;
    jhd_tls_md_context_t ctx;
    unsigned char buf[1024];

    if( md_info == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( JHD_TLS_ERR_MD_FILE_IO_ERROR );

    jhd_tls_md_init( &ctx );

    if( ( ret = jhd_tls_md_setup( &ctx, md_info, 0 ) ) != 0 )
        goto cleanup;

    if( ( ret = md_info->starts_func( ctx.md_ctx ) ) != 0 )
        goto cleanup;

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
        if( ( ret = md_info->update_func( ctx.md_ctx, buf, n ) ) != 0 )
            goto cleanup;

    if( ferror( f ) != 0 )
        ret = JHD_TLS_ERR_MD_FILE_IO_ERROR;
    else
        ret = md_info->finish_func( ctx.md_ctx, output );

cleanup:
    jhd_tls_platform_zeroize( buf, sizeof( buf ) );
    fclose( f );
    jhd_tls_md_free( &ctx );

    return( ret );
}
#endif /* JHD_TLS_FS_IO */

int jhd_tls_md_hmac_starts( jhd_tls_md_context_t *ctx, const unsigned char *key, size_t keylen )
{
    int ret;
    unsigned char sum[JHD_TLS_MD_MAX_SIZE];
    unsigned char *ipad, *opad;
    size_t i;

    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    if( keylen > (size_t) ctx->md_info->block_size )
    {
        if( ( ret = ctx->md_info->starts_func( ctx->md_ctx ) ) != 0 )
            goto cleanup;
        if( ( ret = ctx->md_info->update_func( ctx->md_ctx, key, keylen ) ) != 0 )
            goto cleanup;
        if( ( ret = ctx->md_info->finish_func( ctx->md_ctx, sum ) ) != 0 )
            goto cleanup;

        keylen = ctx->md_info->size;
        key = sum;
    }

    ipad = (unsigned char *) ctx->hmac_ctx;
    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    memset( ipad, 0x36, ctx->md_info->block_size );
    memset( opad, 0x5C, ctx->md_info->block_size );

    for( i = 0; i < keylen; i++ )
    {
        ipad[i] = (unsigned char)( ipad[i] ^ key[i] );
        opad[i] = (unsigned char)( opad[i] ^ key[i] );
    }

    if( ( ret = ctx->md_info->starts_func( ctx->md_ctx ) ) != 0 )
        goto cleanup;
    if( ( ret = ctx->md_info->update_func( ctx->md_ctx, ipad,
                                           ctx->md_info->block_size ) ) != 0 )
        goto cleanup;

cleanup:
    jhd_tls_platform_zeroize( sum, sizeof( sum ) );

    return( ret );
}

int jhd_tls_md_hmac_update( jhd_tls_md_context_t *ctx, const unsigned char *input, size_t ilen )
{
    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    return( ctx->md_info->update_func( ctx->md_ctx, input, ilen ) );
}

int jhd_tls_md_hmac_finish( jhd_tls_md_context_t *ctx, unsigned char *output )
{
    int ret;
    unsigned char tmp[JHD_TLS_MD_MAX_SIZE];
    unsigned char *opad;

    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    if( ( ret = ctx->md_info->finish_func( ctx->md_ctx, tmp ) ) != 0 )
        return( ret );
    if( ( ret = ctx->md_info->starts_func( ctx->md_ctx ) ) != 0 )
        return( ret );
    if( ( ret = ctx->md_info->update_func( ctx->md_ctx, opad,
                                           ctx->md_info->block_size ) ) != 0 )
        return( ret );
    if( ( ret = ctx->md_info->update_func( ctx->md_ctx, tmp,
                                           ctx->md_info->size ) ) != 0 )
        return( ret );
    return( ctx->md_info->finish_func( ctx->md_ctx, output ) );
}

int jhd_tls_md_hmac_reset( jhd_tls_md_context_t *ctx )
{
    int ret;
    unsigned char *ipad;

    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    ipad = (unsigned char *) ctx->hmac_ctx;

    if( ( ret = ctx->md_info->starts_func( ctx->md_ctx ) ) != 0 )
        return( ret );
    return( ctx->md_info->update_func( ctx->md_ctx, ipad,
                                       ctx->md_info->block_size ) );
}

int jhd_tls_md_hmac( const jhd_tls_md_info_t *md_info,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *input, size_t ilen,
                     unsigned char *output )
{
    jhd_tls_md_context_t ctx;
    int ret;

    if( md_info == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    jhd_tls_md_init( &ctx );

    if( ( ret = jhd_tls_md_setup( &ctx, md_info, 1 ) ) != 0 )
        goto cleanup;

    if( ( ret = jhd_tls_md_hmac_starts( &ctx, key, keylen ) ) != 0 )
        goto cleanup;
    if( ( ret = jhd_tls_md_hmac_update( &ctx, input, ilen ) ) != 0 )
        goto cleanup;
    if( ( ret = jhd_tls_md_hmac_finish( &ctx, output ) ) != 0 )
        goto cleanup;

cleanup:
    jhd_tls_md_free( &ctx );

    return( ret );
}

int jhd_tls_md_process( jhd_tls_md_context_t *ctx, const unsigned char *data )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( JHD_TLS_ERR_MD_BAD_INPUT_DATA );

    return( ctx->md_info->process_func( ctx->md_ctx, data ) );
}

unsigned char jhd_tls_md_get_size( const jhd_tls_md_info_t *md_info )
{
    if( md_info == NULL )
        return( 0 );

    return md_info->size;
}

jhd_tls_md_type_t jhd_tls_md_get_type( const jhd_tls_md_info_t *md_info )
{
    if( md_info == NULL )
        return( JHD_TLS_MD_NONE );

    return md_info->type;
}

const char *jhd_tls_md_get_name( const jhd_tls_md_info_t *md_info )
{
    if( md_info == NULL )
        return( NULL );

    return md_info->name;
}

#endif /* JHD_TLS_MD_C */
