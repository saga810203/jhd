/*
 *  HKDF implementation -- RFC 5869
 *
 *  Copyright (C) 2016-2018, ARM Limited, All Rights Reserved
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

#if defined(JHD_TLS_HKDF_C)

#include <string.h>
#include <tls/jhd_tls_hkdf.h>

int jhd_tls_hkdf( const jhd_tls_md_info_t *md, const unsigned char *salt,
                  size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                  const unsigned char *info, size_t info_len,
                  unsigned char *okm, size_t okm_len )
{
    int ret;
    unsigned char prk[JHD_TLS_MD_MAX_SIZE];

    ret = jhd_tls_hkdf_extract( md, salt, salt_len, ikm, ikm_len, prk );

    if( ret == 0 )
    {
        ret = jhd_tls_hkdf_expand( md, prk, jhd_tls_md_get_size( md ),
                                   info, info_len, okm, okm_len );
    }

    jhd_tls_platform_zeroize( prk, sizeof( prk ) );

    return( ret );
}

int jhd_tls_hkdf_extract( const jhd_tls_md_info_t *md,
                          const unsigned char *salt, size_t salt_len,
                          const unsigned char *ikm, size_t ikm_len,
                          unsigned char *prk )
{
    unsigned char null_salt[JHD_TLS_MD_MAX_SIZE] = { '\0' };

    if( salt == NULL )
    {
        size_t hash_len;

        hash_len = jhd_tls_md_get_size( md );

        if( hash_len == 0 )
        {
            return JHD_TLS_ERR_HKDF_BAD_INPUT_DATA;
        }

        salt = null_salt;
        salt_len = hash_len;
    }

    return( jhd_tls_md_hmac( md, salt, salt_len, ikm, ikm_len, prk ) );
}

int jhd_tls_hkdf_expand( const jhd_tls_md_info_t *md, const unsigned char *prk,
                         size_t prk_len, const unsigned char *info,
                         size_t info_len, unsigned char *okm, size_t okm_len )
{
    size_t hash_len;
    size_t where = 0;
    size_t n;
    size_t t_len = 0;
    size_t i;
    int ret = 0;
    jhd_tls_md_context_t ctx;
    unsigned char t[JHD_TLS_MD_MAX_SIZE];

    if( okm == NULL )
    {
        return( JHD_TLS_ERR_HKDF_BAD_INPUT_DATA );
    }

    hash_len = jhd_tls_md_get_size( md );

    if( prk_len < hash_len || hash_len == 0 )
    {
        return( JHD_TLS_ERR_HKDF_BAD_INPUT_DATA );
    }

    if( info == NULL )
    {
        info = (const unsigned char *) "";
        info_len = 0;
    }

    n = okm_len / hash_len;

    if( (okm_len % hash_len) != 0 )
    {
        n++;
    }

    if( n > 255 )
    {
        return( JHD_TLS_ERR_HKDF_BAD_INPUT_DATA );
    }

    jhd_tls_md_init( &ctx );

    if( (ret = jhd_tls_md_setup( &ctx, md, 1) ) != 0 )
    {
        goto exit;
    }

    /* RFC 5869 Section 2.3. */
    for( i = 1; i <= n; i++ )
    {
        size_t num_to_copy;
        unsigned char c = i & 0xff;

        ret = jhd_tls_md_hmac_starts( &ctx, prk, prk_len );
        if( ret != 0 )
        {
            goto exit;
        }

        ret = jhd_tls_md_hmac_update( &ctx, t, t_len );
        if( ret != 0 )
        {
            goto exit;
        }

        ret = jhd_tls_md_hmac_update( &ctx, info, info_len );
        if( ret != 0 )
        {
            goto exit;
        }

        /* The constant concatenated to the end of each t(n) is a single octet.
         * */
        ret = jhd_tls_md_hmac_update( &ctx, &c, 1 );
        if( ret != 0 )
        {
            goto exit;
        }

        ret = jhd_tls_md_hmac_finish( &ctx, t );
        if( ret != 0 )
        {
            goto exit;
        }

        num_to_copy = i != n ? hash_len : okm_len - where;
        memcpy( okm + where, t, num_to_copy );
        where += hash_len;
        t_len = hash_len;
    }

exit:
    jhd_tls_md_free( &ctx );
    jhd_tls_platform_zeroize( t, sizeof( t ) );

    return( ret );
}

#endif /* JHD_TLS_HKDF_C */
