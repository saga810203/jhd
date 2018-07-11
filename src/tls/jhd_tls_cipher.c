/**
 * \file cipher.c
 *
 * \brief Generic cipher wrapper for mbed TLS
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

#if defined(JHD_TLS_CIPHER_C)

#include <tls/jhd_tls_cipher.h>
#include <tls/jhd_tls_cipher_internal.h>

#include <stdlib.h>
#include <string.h>

#if defined(JHD_TLS_GCM_C)
#include <tls/jhd_tls_gcm.h>
#endif

#if defined(JHD_TLS_CCM_C)
#include <tls/jhd_tls_ccm.h>
#endif

#if defined(JHD_TLS_CMAC_C)
#include <tls/jhd_tls_cmac.h>
#endif

#if defined(JHD_TLS_PLATFORM_C)
#include <tls/jhd_tls_platform.h>
#else
#define jhd_tls_calloc calloc
#define jhd_tls_free   free
#endif

#if defined(JHD_TLS_ARC4_C) || defined(JHD_TLS_CIPHER_NULL_CIPHER)
#define JHD_TLS_CIPHER_MODE_STREAM
#endif

static int supported_init = 0;

const int *jhd_tls_cipher_list( void )
{
    const jhd_tls_cipher_definition_t *def;
    int *type;

    if( ! supported_init )
    {
        def = jhd_tls_cipher_definitions;
        type = jhd_tls_cipher_supported;

        while( def->type != 0 )
            *type++ = (*def++).type;

        *type = 0;

        supported_init = 1;
    }

    return( jhd_tls_cipher_supported );
}

const jhd_tls_cipher_info_t *jhd_tls_cipher_info_from_type( const jhd_tls_cipher_type_t cipher_type )
{
    const jhd_tls_cipher_definition_t *def;

    for( def = jhd_tls_cipher_definitions; def->info != NULL; def++ )
        if( def->type == cipher_type )
            return( def->info );

    return( NULL );
}

const jhd_tls_cipher_info_t *jhd_tls_cipher_info_from_string( const char *cipher_name )
{
    const jhd_tls_cipher_definition_t *def;

    if( NULL == cipher_name )
        return( NULL );

    for( def = jhd_tls_cipher_definitions; def->info != NULL; def++ )
        if( !  strcmp( def->info->name, cipher_name ) )
            return( def->info );

    return( NULL );
}

const jhd_tls_cipher_info_t *jhd_tls_cipher_info_from_values( const jhd_tls_cipher_id_t cipher_id,
                                              int key_bitlen,
                                              const jhd_tls_cipher_mode_t mode )
{
    const jhd_tls_cipher_definition_t *def;

    for( def = jhd_tls_cipher_definitions; def->info != NULL; def++ )
        if( def->info->base->cipher == cipher_id &&
            def->info->key_bitlen == (unsigned) key_bitlen &&
            def->info->mode == mode )
            return( def->info );

    return( NULL );
}

void jhd_tls_cipher_init( jhd_tls_cipher_context_t *ctx )
{
    memset( ctx, 0, sizeof( jhd_tls_cipher_context_t ) );
}

void jhd_tls_cipher_free( jhd_tls_cipher_context_t *ctx )
{
    if( ctx == NULL )
        return;

#if defined(JHD_TLS_CMAC_C)
    if( ctx->cmac_ctx )
    {
       jhd_tls_platform_zeroize( ctx->cmac_ctx,
                                 sizeof( jhd_tls_cmac_context_t ) );
       jhd_tls_free( ctx->cmac_ctx );
    }
#endif

    if( ctx->cipher_ctx )
        ctx->cipher_info->base->ctx_free_func( ctx->cipher_ctx );

    jhd_tls_platform_zeroize( ctx, sizeof(jhd_tls_cipher_context_t) );
}

int jhd_tls_cipher_setup( jhd_tls_cipher_context_t *ctx, const jhd_tls_cipher_info_t *cipher_info )
{
    if( NULL == cipher_info || NULL == ctx )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    memset( ctx, 0, sizeof( jhd_tls_cipher_context_t ) );

    if( NULL == ( ctx->cipher_ctx = cipher_info->base->ctx_alloc_func() ) )
        return( JHD_TLS_ERR_CIPHER_ALLOC_FAILED );

    ctx->cipher_info = cipher_info;

#if defined(JHD_TLS_CIPHER_MODE_WITH_PADDING)
    /*
     * Ignore possible errors caused by a cipher mode that doesn't use padding
     */
#if defined(JHD_TLS_CIPHER_PADDING_PKCS7)
    (void) jhd_tls_cipher_set_padding_mode( ctx, JHD_TLS_PADDING_PKCS7 );
#else
    (void) jhd_tls_cipher_set_padding_mode( ctx, JHD_TLS_PADDING_NONE );
#endif
#endif /* JHD_TLS_CIPHER_MODE_WITH_PADDING */

    return( 0 );
}

int jhd_tls_cipher_setkey( jhd_tls_cipher_context_t *ctx, const unsigned char *key,
        int key_bitlen, const jhd_tls_operation_t operation )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( ( ctx->cipher_info->flags & JHD_TLS_CIPHER_VARIABLE_KEY_LEN ) == 0 &&
        (int) ctx->cipher_info->key_bitlen != key_bitlen )
    {
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    ctx->key_bitlen = key_bitlen;
    ctx->operation = operation;

    /*
     * For OFB, CFB and CTR mode always use the encryption key schedule
     */
    if( JHD_TLS_ENCRYPT == operation ||
        JHD_TLS_MODE_CFB == ctx->cipher_info->mode ||
        JHD_TLS_MODE_OFB == ctx->cipher_info->mode ||
        JHD_TLS_MODE_CTR == ctx->cipher_info->mode )
    {
        return ctx->cipher_info->base->setkey_enc_func( ctx->cipher_ctx, key,
                ctx->key_bitlen );
    }

    if( JHD_TLS_DECRYPT == operation )
        return ctx->cipher_info->base->setkey_dec_func( ctx->cipher_ctx, key,
                ctx->key_bitlen );

    return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );
}

int jhd_tls_cipher_set_iv( jhd_tls_cipher_context_t *ctx,
                   const unsigned char *iv, size_t iv_len )
{
    size_t actual_iv_size;

    if( NULL == ctx || NULL == ctx->cipher_info || NULL == iv )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    /* avoid buffer overflow in ctx->iv */
    if( iv_len > JHD_TLS_MAX_IV_LENGTH )
        return( JHD_TLS_ERR_CIPHER_FEATURE_UNAVAILABLE );

    if( ( ctx->cipher_info->flags & JHD_TLS_CIPHER_VARIABLE_IV_LEN ) != 0 )
        actual_iv_size = iv_len;
    else
    {
        actual_iv_size = ctx->cipher_info->iv_size;

        /* avoid reading past the end of input buffer */
        if( actual_iv_size > iv_len )
            return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    memcpy( ctx->iv, iv, actual_iv_size );
    ctx->iv_size = actual_iv_size;

    return( 0 );
}

int jhd_tls_cipher_reset( jhd_tls_cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    ctx->unprocessed_len = 0;

    return( 0 );
}

#if defined(JHD_TLS_GCM_C)
int jhd_tls_cipher_update_ad( jhd_tls_cipher_context_t *ctx,
                      const unsigned char *ad, size_t ad_len )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( JHD_TLS_MODE_GCM == ctx->cipher_info->mode )
    {
        return jhd_tls_gcm_starts( (jhd_tls_gcm_context *) ctx->cipher_ctx, ctx->operation,
                           ctx->iv, ctx->iv_size, ad, ad_len );
    }

    return( 0 );
}
#endif /* JHD_TLS_GCM_C */

int jhd_tls_cipher_update( jhd_tls_cipher_context_t *ctx, const unsigned char *input,
                   size_t ilen, unsigned char *output, size_t *olen )
{
    int ret;
    size_t block_size = 0;

    if( NULL == ctx || NULL == ctx->cipher_info || NULL == olen )
    {
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    *olen = 0;
    block_size = jhd_tls_cipher_get_block_size( ctx );

    if( ctx->cipher_info->mode == JHD_TLS_MODE_ECB )
    {
        if( ilen != block_size )
            return( JHD_TLS_ERR_CIPHER_FULL_BLOCK_EXPECTED );

        *olen = ilen;

        if( 0 != ( ret = ctx->cipher_info->base->ecb_func( ctx->cipher_ctx,
                    ctx->operation, input, output ) ) )
        {
            return( ret );
        }

        return( 0 );
    }

#if defined(JHD_TLS_GCM_C)
    if( ctx->cipher_info->mode == JHD_TLS_MODE_GCM )
    {
        *olen = ilen;
        return jhd_tls_gcm_update( (jhd_tls_gcm_context *) ctx->cipher_ctx, ilen, input,
                           output );
    }
#endif

    if ( 0 == block_size )
    {
        return JHD_TLS_ERR_CIPHER_INVALID_CONTEXT;
    }

    if( input == output &&
       ( ctx->unprocessed_len != 0 || ilen % block_size ) )
    {
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

#if defined(JHD_TLS_CIPHER_MODE_CBC)
    if( ctx->cipher_info->mode == JHD_TLS_MODE_CBC )
    {
        size_t copy_len = 0;

        /*
         * If there is not enough data for a full block, cache it.
         */
        if( ( ctx->operation == JHD_TLS_DECRYPT && NULL != ctx->add_padding &&
                ilen <= block_size - ctx->unprocessed_len ) ||
            ( ctx->operation == JHD_TLS_DECRYPT && NULL == ctx->add_padding &&
                ilen < block_size - ctx->unprocessed_len ) ||
             ( ctx->operation == JHD_TLS_ENCRYPT &&
                ilen < block_size - ctx->unprocessed_len ) )
        {
            memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ), input,
                    ilen );

            ctx->unprocessed_len += ilen;
            return( 0 );
        }

        /*
         * Process cached data first
         */
        if( 0 != ctx->unprocessed_len )
        {
            copy_len = block_size - ctx->unprocessed_len;

            memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ), input,
                    copy_len );

            if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                    ctx->operation, block_size, ctx->iv,
                    ctx->unprocessed_data, output ) ) )
            {
                return( ret );
            }

            *olen += block_size;
            output += block_size;
            ctx->unprocessed_len = 0;

            input += copy_len;
            ilen -= copy_len;
        }

        /*
         * Cache final, incomplete block
         */
        if( 0 != ilen )
        {
            if( 0 == block_size )
            {
                return JHD_TLS_ERR_CIPHER_INVALID_CONTEXT;
            }

            /* Encryption: only cache partial blocks
             * Decryption w/ padding: always keep at least one whole block
             * Decryption w/o padding: only cache partial blocks
             */
            copy_len = ilen % block_size;
            if( copy_len == 0 &&
                ctx->operation == JHD_TLS_DECRYPT &&
                NULL != ctx->add_padding)
            {
                copy_len = block_size;
            }

            memcpy( ctx->unprocessed_data, &( input[ilen - copy_len] ),
                    copy_len );

            ctx->unprocessed_len += copy_len;
            ilen -= copy_len;
        }

        /*
         * Process remaining full blocks
         */
        if( ilen )
        {
            if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                    ctx->operation, ilen, ctx->iv, input, output ) ) )
            {
                return( ret );
            }

            *olen += ilen;
        }

        return( 0 );
    }
#endif /* JHD_TLS_CIPHER_MODE_CBC */

#if defined(JHD_TLS_CIPHER_MODE_CFB)
    if( ctx->cipher_info->mode == JHD_TLS_MODE_CFB )
    {
        if( 0 != ( ret = ctx->cipher_info->base->cfb_func( ctx->cipher_ctx,
                ctx->operation, ilen, &ctx->unprocessed_len, ctx->iv,
                input, output ) ) )
        {
            return( ret );
        }

        *olen = ilen;

        return( 0 );
    }
#endif /* JHD_TLS_CIPHER_MODE_CFB */

#if defined(JHD_TLS_CIPHER_MODE_OFB)
    if( ctx->cipher_info->mode == JHD_TLS_MODE_OFB )
    {
        if( 0 != ( ret = ctx->cipher_info->base->ofb_func( ctx->cipher_ctx,
                ilen, &ctx->unprocessed_len, ctx->iv, input, output ) ) )
        {
            return( ret );
        }

        *olen = ilen;

        return( 0 );
    }
#endif /* JHD_TLS_CIPHER_MODE_OFB */

#if defined(JHD_TLS_CIPHER_MODE_CTR)
    if( ctx->cipher_info->mode == JHD_TLS_MODE_CTR )
    {
        if( 0 != ( ret = ctx->cipher_info->base->ctr_func( ctx->cipher_ctx,
                ilen, &ctx->unprocessed_len, ctx->iv,
                ctx->unprocessed_data, input, output ) ) )
        {
            return( ret );
        }

        *olen = ilen;

        return( 0 );
    }
#endif /* JHD_TLS_CIPHER_MODE_CTR */

#if defined(JHD_TLS_CIPHER_MODE_XTS)
    if( ctx->cipher_info->mode == JHD_TLS_MODE_XTS )
    {
        if( ctx->unprocessed_len > 0 ) {
            /* We can only process an entire data unit at a time. */
            return( JHD_TLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
        }

        ret = ctx->cipher_info->base->xts_func( ctx->cipher_ctx,
                ctx->operation, ilen, ctx->iv, input, output );
        if( ret != 0 )
        {
            return( ret );
        }

        *olen = ilen;

        return( 0 );
    }
#endif /* JHD_TLS_CIPHER_MODE_XTS */

#if defined(JHD_TLS_CIPHER_MODE_STREAM)
    if( ctx->cipher_info->mode == JHD_TLS_MODE_STREAM )
    {
        if( 0 != ( ret = ctx->cipher_info->base->stream_func( ctx->cipher_ctx,
                                                    ilen, input, output ) ) )
        {
            return( ret );
        }

        *olen = ilen;

        return( 0 );
    }
#endif /* JHD_TLS_CIPHER_MODE_STREAM */

    return( JHD_TLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
}

#if defined(JHD_TLS_CIPHER_MODE_WITH_PADDING)
#if defined(JHD_TLS_CIPHER_PADDING_PKCS7)
/*
 * PKCS7 (and PKCS5) padding: fill with ll bytes, with ll = padding_len
 */
static void add_pkcs_padding( unsigned char *output, size_t output_len,
        size_t data_len )
{
    size_t padding_len = output_len - data_len;
    unsigned char i;

    for( i = 0; i < padding_len; i++ )
        output[data_len + i] = (unsigned char) padding_len;
}

static int get_pkcs_padding( unsigned char *input, size_t input_len,
        size_t *data_len )
{
    size_t i, pad_idx;
    unsigned char padding_len, bad = 0;

    if( NULL == input || NULL == data_len )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    padding_len = input[input_len - 1];
    *data_len = input_len - padding_len;

    /* Avoid logical || since it results in a branch */
    bad |= padding_len > input_len;
    bad |= padding_len == 0;

    /* The number of bytes checked must be independent of padding_len,
     * so pick input_len, which is usually 8 or 16 (one block) */
    pad_idx = input_len - padding_len;
    for( i = 0; i < input_len; i++ )
        bad |= ( input[i] ^ padding_len ) * ( i >= pad_idx );

    return( JHD_TLS_ERR_CIPHER_INVALID_PADDING * ( bad != 0 ) );
}
#endif /* JHD_TLS_CIPHER_PADDING_PKCS7 */

#if defined(JHD_TLS_CIPHER_PADDING_ONE_AND_ZEROS)
/*
 * One and zeros padding: fill with 80 00 ... 00
 */
static void add_one_and_zeros_padding( unsigned char *output,
                                       size_t output_len, size_t data_len )
{
    size_t padding_len = output_len - data_len;
    unsigned char i = 0;

    output[data_len] = 0x80;
    for( i = 1; i < padding_len; i++ )
        output[data_len + i] = 0x00;
}

static int get_one_and_zeros_padding( unsigned char *input, size_t input_len,
                                      size_t *data_len )
{
    size_t i;
    unsigned char done = 0, prev_done, bad;

    if( NULL == input || NULL == data_len )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    bad = 0x80;
    *data_len = 0;
    for( i = input_len; i > 0; i-- )
    {
        prev_done = done;
        done |= ( input[i - 1] != 0 );
        *data_len |= ( i - 1 ) * ( done != prev_done );
        bad ^= input[i - 1] * ( done != prev_done );
    }

    return( JHD_TLS_ERR_CIPHER_INVALID_PADDING * ( bad != 0 ) );

}
#endif /* JHD_TLS_CIPHER_PADDING_ONE_AND_ZEROS */

#if defined(JHD_TLS_CIPHER_PADDING_ZEROS_AND_LEN)
/*
 * Zeros and len padding: fill with 00 ... 00 ll, where ll is padding length
 */
static void add_zeros_and_len_padding( unsigned char *output,
                                       size_t output_len, size_t data_len )
{
    size_t padding_len = output_len - data_len;
    unsigned char i = 0;

    for( i = 1; i < padding_len; i++ )
        output[data_len + i - 1] = 0x00;
    output[output_len - 1] = (unsigned char) padding_len;
}

static int get_zeros_and_len_padding( unsigned char *input, size_t input_len,
                                      size_t *data_len )
{
    size_t i, pad_idx;
    unsigned char padding_len, bad = 0;

    if( NULL == input || NULL == data_len )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    padding_len = input[input_len - 1];
    *data_len = input_len - padding_len;

    /* Avoid logical || since it results in a branch */
    bad |= padding_len > input_len;
    bad |= padding_len == 0;

    /* The number of bytes checked must be independent of padding_len */
    pad_idx = input_len - padding_len;
    for( i = 0; i < input_len - 1; i++ )
        bad |= input[i] * ( i >= pad_idx );

    return( JHD_TLS_ERR_CIPHER_INVALID_PADDING * ( bad != 0 ) );
}
#endif /* JHD_TLS_CIPHER_PADDING_ZEROS_AND_LEN */

#if defined(JHD_TLS_CIPHER_PADDING_ZEROS)
/*
 * Zero padding: fill with 00 ... 00
 */
static void add_zeros_padding( unsigned char *output,
                               size_t output_len, size_t data_len )
{
    size_t i;

    for( i = data_len; i < output_len; i++ )
        output[i] = 0x00;
}

static int get_zeros_padding( unsigned char *input, size_t input_len,
                              size_t *data_len )
{
    size_t i;
    unsigned char done = 0, prev_done;

    if( NULL == input || NULL == data_len )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    *data_len = 0;
    for( i = input_len; i > 0; i-- )
    {
        prev_done = done;
        done |= ( input[i-1] != 0 );
        *data_len |= i * ( done != prev_done );
    }

    return( 0 );
}
#endif /* JHD_TLS_CIPHER_PADDING_ZEROS */

/*
 * No padding: don't pad :)
 *
 * There is no add_padding function (check for NULL in jhd_tls_cipher_finish)
 * but a trivial get_padding function
 */
static int get_no_padding( unsigned char *input, size_t input_len,
                              size_t *data_len )
{
    if( NULL == input || NULL == data_len )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    *data_len = input_len;

    return( 0 );
}
#endif /* JHD_TLS_CIPHER_MODE_WITH_PADDING */

int jhd_tls_cipher_finish( jhd_tls_cipher_context_t *ctx,
                   unsigned char *output, size_t *olen )
{
    if( NULL == ctx || NULL == ctx->cipher_info || NULL == olen )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    *olen = 0;

    if( JHD_TLS_MODE_CFB == ctx->cipher_info->mode ||
        JHD_TLS_MODE_OFB == ctx->cipher_info->mode ||
        JHD_TLS_MODE_CTR == ctx->cipher_info->mode ||
        JHD_TLS_MODE_GCM == ctx->cipher_info->mode ||
        JHD_TLS_MODE_XTS == ctx->cipher_info->mode ||
        JHD_TLS_MODE_STREAM == ctx->cipher_info->mode )
    {
        return( 0 );
    }

    if( JHD_TLS_MODE_ECB == ctx->cipher_info->mode )
    {
        if( ctx->unprocessed_len != 0 )
            return( JHD_TLS_ERR_CIPHER_FULL_BLOCK_EXPECTED );

        return( 0 );
    }

#if defined(JHD_TLS_CIPHER_MODE_CBC)
    if( JHD_TLS_MODE_CBC == ctx->cipher_info->mode )
    {
        int ret = 0;

        if( JHD_TLS_ENCRYPT == ctx->operation )
        {
            /* check for 'no padding' mode */
            if( NULL == ctx->add_padding )
            {
                if( 0 != ctx->unprocessed_len )
                    return( JHD_TLS_ERR_CIPHER_FULL_BLOCK_EXPECTED );

                return( 0 );
            }

            ctx->add_padding( ctx->unprocessed_data, jhd_tls_cipher_get_iv_size( ctx ),
                    ctx->unprocessed_len );
        }
        else if( jhd_tls_cipher_get_block_size( ctx ) != ctx->unprocessed_len )
        {
            /*
             * For decrypt operations, expect a full block,
             * or an empty block if no padding
             */
            if( NULL == ctx->add_padding && 0 == ctx->unprocessed_len )
                return( 0 );

            return( JHD_TLS_ERR_CIPHER_FULL_BLOCK_EXPECTED );
        }

        /* cipher block */
        if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                ctx->operation, jhd_tls_cipher_get_block_size( ctx ), ctx->iv,
                ctx->unprocessed_data, output ) ) )
        {
            return( ret );
        }

        /* Set output size for decryption */
        if( JHD_TLS_DECRYPT == ctx->operation )
            return ctx->get_padding( output, jhd_tls_cipher_get_block_size( ctx ),
                                     olen );

        /* Set output size for encryption */
        *olen = jhd_tls_cipher_get_block_size( ctx );
        return( 0 );
    }
#else
    ((void) output);
#endif /* JHD_TLS_CIPHER_MODE_CBC */

    return( JHD_TLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
}

#if defined(JHD_TLS_CIPHER_MODE_WITH_PADDING)
int jhd_tls_cipher_set_padding_mode( jhd_tls_cipher_context_t *ctx, jhd_tls_cipher_padding_t mode )
{
    if( NULL == ctx ||
        JHD_TLS_MODE_CBC != ctx->cipher_info->mode )
    {
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    switch( mode )
    {
#if defined(JHD_TLS_CIPHER_PADDING_PKCS7)
    case JHD_TLS_PADDING_PKCS7:
        ctx->add_padding = add_pkcs_padding;
        ctx->get_padding = get_pkcs_padding;
        break;
#endif
#if defined(JHD_TLS_CIPHER_PADDING_ONE_AND_ZEROS)
    case JHD_TLS_PADDING_ONE_AND_ZEROS:
        ctx->add_padding = add_one_and_zeros_padding;
        ctx->get_padding = get_one_and_zeros_padding;
        break;
#endif
#if defined(JHD_TLS_CIPHER_PADDING_ZEROS_AND_LEN)
    case JHD_TLS_PADDING_ZEROS_AND_LEN:
        ctx->add_padding = add_zeros_and_len_padding;
        ctx->get_padding = get_zeros_and_len_padding;
        break;
#endif
#if defined(JHD_TLS_CIPHER_PADDING_ZEROS)
    case JHD_TLS_PADDING_ZEROS:
        ctx->add_padding = add_zeros_padding;
        ctx->get_padding = get_zeros_padding;
        break;
#endif
    case JHD_TLS_PADDING_NONE:
        ctx->add_padding = NULL;
        ctx->get_padding = get_no_padding;
        break;

    default:
        return( JHD_TLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
    }

    return( 0 );
}
#endif /* JHD_TLS_CIPHER_MODE_WITH_PADDING */

#if defined(JHD_TLS_GCM_C)
int jhd_tls_cipher_write_tag( jhd_tls_cipher_context_t *ctx,
                      unsigned char *tag, size_t tag_len )
{
    if( NULL == ctx || NULL == ctx->cipher_info || NULL == tag )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( JHD_TLS_ENCRYPT != ctx->operation )
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( JHD_TLS_MODE_GCM == ctx->cipher_info->mode )
        return jhd_tls_gcm_finish( (jhd_tls_gcm_context *) ctx->cipher_ctx, tag, tag_len );

    return( 0 );
}

int jhd_tls_cipher_check_tag( jhd_tls_cipher_context_t *ctx,
                      const unsigned char *tag, size_t tag_len )
{
    int ret;

    if( NULL == ctx || NULL == ctx->cipher_info ||
        JHD_TLS_DECRYPT != ctx->operation )
    {
        return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    if( JHD_TLS_MODE_GCM == ctx->cipher_info->mode )
    {
        unsigned char check_tag[16];
        size_t i;
        int diff;

        if( tag_len > sizeof( check_tag ) )
            return( JHD_TLS_ERR_CIPHER_BAD_INPUT_DATA );

        if( 0 != ( ret = jhd_tls_gcm_finish( (jhd_tls_gcm_context *) ctx->cipher_ctx,
                                     check_tag, tag_len ) ) )
        {
            return( ret );
        }

        /* Check the tag in "constant-time" */
        for( diff = 0, i = 0; i < tag_len; i++ )
            diff |= tag[i] ^ check_tag[i];

        if( diff != 0 )
            return( JHD_TLS_ERR_CIPHER_AUTH_FAILED );

        return( 0 );
    }

    return( 0 );
}
#endif /* JHD_TLS_GCM_C */

/*
 * Packet-oriented wrapper for non-AEAD modes
 */
int jhd_tls_cipher_crypt( jhd_tls_cipher_context_t *ctx,
                  const unsigned char *iv, size_t iv_len,
                  const unsigned char *input, size_t ilen,
                  unsigned char *output, size_t *olen )
{
    int ret;
    size_t finish_olen;

    if( ( ret = jhd_tls_cipher_set_iv( ctx, iv, iv_len ) ) != 0 )
        return( ret );

    if( ( ret = jhd_tls_cipher_reset( ctx ) ) != 0 )
        return( ret );

    if( ( ret = jhd_tls_cipher_update( ctx, input, ilen, output, olen ) ) != 0 )
        return( ret );

    if( ( ret = jhd_tls_cipher_finish( ctx, output + *olen, &finish_olen ) ) != 0 )
        return( ret );

    *olen += finish_olen;

    return( 0 );
}

#if defined(JHD_TLS_CIPHER_MODE_AEAD)
/*
 * Packet-oriented encryption for AEAD modes
 */
int jhd_tls_cipher_auth_encrypt( jhd_tls_cipher_context_t *ctx,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *ad, size_t ad_len,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen,
                         unsigned char *tag, size_t tag_len )
{
#if defined(JHD_TLS_GCM_C)
    if( JHD_TLS_MODE_GCM == ctx->cipher_info->mode )
    {
        *olen = ilen;
        return( jhd_tls_gcm_crypt_and_tag( ctx->cipher_ctx, JHD_TLS_GCM_ENCRYPT, ilen,
                                   iv, iv_len, ad, ad_len, input, output,
                                   tag_len, tag ) );
    }
#endif /* JHD_TLS_GCM_C */
#if defined(JHD_TLS_CCM_C)
    if( JHD_TLS_MODE_CCM == ctx->cipher_info->mode )
    {
        *olen = ilen;
        return( jhd_tls_ccm_encrypt_and_tag( ctx->cipher_ctx, ilen,
                                     iv, iv_len, ad, ad_len, input, output,
                                     tag, tag_len ) );
    }
#endif /* JHD_TLS_CCM_C */

    return( JHD_TLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
}

/*
 * Packet-oriented decryption for AEAD modes
 */
int jhd_tls_cipher_auth_decrypt( jhd_tls_cipher_context_t *ctx,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *ad, size_t ad_len,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen,
                         const unsigned char *tag, size_t tag_len )
{
#if defined(JHD_TLS_GCM_C)
    if( JHD_TLS_MODE_GCM == ctx->cipher_info->mode )
    {
        int ret;

        *olen = ilen;
        ret = jhd_tls_gcm_auth_decrypt( ctx->cipher_ctx, ilen,
                                iv, iv_len, ad, ad_len,
                                tag, tag_len, input, output );

        if( ret == JHD_TLS_ERR_GCM_AUTH_FAILED )
            ret = JHD_TLS_ERR_CIPHER_AUTH_FAILED;

        return( ret );
    }
#endif /* JHD_TLS_GCM_C */
#if defined(JHD_TLS_CCM_C)
    if( JHD_TLS_MODE_CCM == ctx->cipher_info->mode )
    {
        int ret;

        *olen = ilen;
        ret = jhd_tls_ccm_auth_decrypt( ctx->cipher_ctx, ilen,
                                iv, iv_len, ad, ad_len,
                                input, output, tag, tag_len );

        if( ret == JHD_TLS_ERR_CCM_AUTH_FAILED )
            ret = JHD_TLS_ERR_CIPHER_AUTH_FAILED;

        return( ret );
    }
#endif /* JHD_TLS_CCM_C */

    return( JHD_TLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
}
#endif /* JHD_TLS_CIPHER_MODE_AEAD */

#endif /* JHD_TLS_CIPHER_C */
