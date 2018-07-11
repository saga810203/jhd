/*
 *  PKCS#12 Personal Information Exchange Syntax
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
 *  The PKCS #12 Personal Information Exchange Syntax Standard v1.1
 *
 *  http://www.rsa.com/rsalabs/pkcs/files/h11301-wp-pkcs-12v1-1-personal-information-exchange-syntax.pdf
 *  ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-12/pkcs-12v1-1.asn
 */

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_PKCS12_C)

#include <tls/jhd_tls_pkcs12.h>
#include <tls/jhd_tls_asn1.h>
#include <tls/jhd_tls_cipher.h>

#include <string.h>

#if defined(JHD_TLS_ARC4_C)
#include <tls/jhd_tls_arc4.h>
#endif

#if defined(JHD_TLS_DES_C)
#include <tls/jhd_tls_des.h>
#endif

static int pkcs12_parse_pbe_params( jhd_tls_asn1_buf *params,
                                    jhd_tls_asn1_buf *salt, int *iterations )
{
    int ret;
    unsigned char **p = &params->p;
    const unsigned char *end = params->p + params->len;

    /*
     *  pkcs-12PbeParams ::= SEQUENCE {
     *    salt          OCTET STRING,
     *    iterations    INTEGER
     *  }
     *
     */
    if( params->tag != ( JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) )
        return( JHD_TLS_ERR_PKCS12_PBE_INVALID_FORMAT +
                JHD_TLS_ERR_ASN1_UNEXPECTED_TAG );

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &salt->len, JHD_TLS_ASN1_OCTET_STRING ) ) != 0 )
        return( JHD_TLS_ERR_PKCS12_PBE_INVALID_FORMAT + ret );

    salt->p = *p;
    *p += salt->len;

    if( ( ret = jhd_tls_asn1_get_int( p, end, iterations ) ) != 0 )
        return( JHD_TLS_ERR_PKCS12_PBE_INVALID_FORMAT + ret );

    if( *p != end )
        return( JHD_TLS_ERR_PKCS12_PBE_INVALID_FORMAT +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

#define PKCS12_MAX_PWDLEN 128

static int pkcs12_pbe_derive_key_iv( jhd_tls_asn1_buf *pbe_params, jhd_tls_md_type_t md_type,
                                     const unsigned char *pwd,  size_t pwdlen,
                                     unsigned char *key, size_t keylen,
                                     unsigned char *iv,  size_t ivlen )
{
    int ret, iterations = 0;
    jhd_tls_asn1_buf salt;
    size_t i;
    unsigned char unipwd[PKCS12_MAX_PWDLEN * 2 + 2];

    if( pwdlen > PKCS12_MAX_PWDLEN )
        return( JHD_TLS_ERR_PKCS12_BAD_INPUT_DATA );

    memset( &salt, 0, sizeof(jhd_tls_asn1_buf) );
    memset( &unipwd, 0, sizeof(unipwd) );

    if( ( ret = pkcs12_parse_pbe_params( pbe_params, &salt,
                                         &iterations ) ) != 0 )
        return( ret );

    for( i = 0; i < pwdlen; i++ )
        unipwd[i * 2 + 1] = pwd[i];

    if( ( ret = jhd_tls_pkcs12_derivation( key, keylen, unipwd, pwdlen * 2 + 2,
                                   salt.p, salt.len, md_type,
                                   JHD_TLS_PKCS12_DERIVE_KEY, iterations ) ) != 0 )
    {
        return( ret );
    }

    if( iv == NULL || ivlen == 0 )
        return( 0 );

    if( ( ret = jhd_tls_pkcs12_derivation( iv, ivlen, unipwd, pwdlen * 2 + 2,
                                   salt.p, salt.len, md_type,
                                   JHD_TLS_PKCS12_DERIVE_IV, iterations ) ) != 0 )
    {
        return( ret );
    }
    return( 0 );
}

#undef PKCS12_MAX_PWDLEN

int jhd_tls_pkcs12_pbe_sha1_rc4_128( jhd_tls_asn1_buf *pbe_params, int mode,
                             const unsigned char *pwd,  size_t pwdlen,
                             const unsigned char *data, size_t len,
                             unsigned char *output )
{
#if !defined(JHD_TLS_ARC4_C)
    ((void) pbe_params);
    ((void) mode);
    ((void) pwd);
    ((void) pwdlen);
    ((void) data);
    ((void) len);
    ((void) output);
    return( JHD_TLS_ERR_PKCS12_FEATURE_UNAVAILABLE );
#else
    int ret;
    unsigned char key[16];
    jhd_tls_arc4_context ctx;
    ((void) mode);

    jhd_tls_arc4_init( &ctx );

    if( ( ret = pkcs12_pbe_derive_key_iv( pbe_params, JHD_TLS_MD_SHA1,
                                          pwd, pwdlen,
                                          key, 16, NULL, 0 ) ) != 0 )
    {
        return( ret );
    }

    jhd_tls_arc4_setup( &ctx, key, 16 );
    if( ( ret = jhd_tls_arc4_crypt( &ctx, len, data, output ) ) != 0 )
        goto exit;

exit:
    jhd_tls_platform_zeroize( key, sizeof( key ) );
    jhd_tls_arc4_free( &ctx );

    return( ret );
#endif /* JHD_TLS_ARC4_C */
}

int jhd_tls_pkcs12_pbe( jhd_tls_asn1_buf *pbe_params, int mode,
                jhd_tls_cipher_type_t cipher_type, jhd_tls_md_type_t md_type,
                const unsigned char *pwd,  size_t pwdlen,
                const unsigned char *data, size_t len,
                unsigned char *output )
{
    int ret, keylen = 0;
    unsigned char key[32];
    unsigned char iv[16];
    const jhd_tls_cipher_info_t *cipher_info;
    jhd_tls_cipher_context_t cipher_ctx;
    size_t olen = 0;

    cipher_info = jhd_tls_cipher_info_from_type( cipher_type );
    if( cipher_info == NULL )
        return( JHD_TLS_ERR_PKCS12_FEATURE_UNAVAILABLE );

    keylen = cipher_info->key_bitlen / 8;

    if( ( ret = pkcs12_pbe_derive_key_iv( pbe_params, md_type, pwd, pwdlen,
                                          key, keylen,
                                          iv, cipher_info->iv_size ) ) != 0 )
    {
        return( ret );
    }

    jhd_tls_cipher_init( &cipher_ctx );

    if( ( ret = jhd_tls_cipher_setup( &cipher_ctx, cipher_info ) ) != 0 )
        goto exit;

    if( ( ret = jhd_tls_cipher_setkey( &cipher_ctx, key, 8 * keylen, (jhd_tls_operation_t) mode ) ) != 0 )
        goto exit;

    if( ( ret = jhd_tls_cipher_set_iv( &cipher_ctx, iv, cipher_info->iv_size ) ) != 0 )
        goto exit;

    if( ( ret = jhd_tls_cipher_reset( &cipher_ctx ) ) != 0 )
        goto exit;

    if( ( ret = jhd_tls_cipher_update( &cipher_ctx, data, len,
                                output, &olen ) ) != 0 )
    {
        goto exit;
    }

    if( ( ret = jhd_tls_cipher_finish( &cipher_ctx, output + olen, &olen ) ) != 0 )
        ret = JHD_TLS_ERR_PKCS12_PASSWORD_MISMATCH;

exit:
    jhd_tls_platform_zeroize( key, sizeof( key ) );
    jhd_tls_platform_zeroize( iv,  sizeof( iv  ) );
    jhd_tls_cipher_free( &cipher_ctx );

    return( ret );
}

static void pkcs12_fill_buffer( unsigned char *data, size_t data_len,
                                const unsigned char *filler, size_t fill_len )
{
    unsigned char *p = data;
    size_t use_len;

    while( data_len > 0 )
    {
        use_len = ( data_len > fill_len ) ? fill_len : data_len;
        memcpy( p, filler, use_len );
        p += use_len;
        data_len -= use_len;
    }
}

int jhd_tls_pkcs12_derivation( unsigned char *data, size_t datalen,
                       const unsigned char *pwd, size_t pwdlen,
                       const unsigned char *salt, size_t saltlen,
                       jhd_tls_md_type_t md_type, int id, int iterations )
{
    int ret;
    unsigned int j;

    unsigned char diversifier[128];
    unsigned char salt_block[128], pwd_block[128], hash_block[128];
    unsigned char hash_output[JHD_TLS_MD_MAX_SIZE];
    unsigned char *p;
    unsigned char c;

    size_t hlen, use_len, v, i;

    const jhd_tls_md_info_t *md_info;
    jhd_tls_md_context_t md_ctx;

    // This version only allows max of 64 bytes of password or salt
    if( datalen > 128 || pwdlen > 64 || saltlen > 64 )
        return( JHD_TLS_ERR_PKCS12_BAD_INPUT_DATA );

    md_info = jhd_tls_md_info_from_type( md_type );
    if( md_info == NULL )
        return( JHD_TLS_ERR_PKCS12_FEATURE_UNAVAILABLE );

    jhd_tls_md_init( &md_ctx );

    if( ( ret = jhd_tls_md_setup( &md_ctx, md_info, 0 ) ) != 0 )
        return( ret );
    hlen = jhd_tls_md_get_size( md_info );

    if( hlen <= 32 )
        v = 64;
    else
        v = 128;

    memset( diversifier, (unsigned char) id, v );

    pkcs12_fill_buffer( salt_block, v, salt, saltlen );
    pkcs12_fill_buffer( pwd_block,  v, pwd,  pwdlen  );

    p = data;
    while( datalen > 0 )
    {
        // Calculate hash( diversifier || salt_block || pwd_block )
        if( ( ret = jhd_tls_md_starts( &md_ctx ) ) != 0 )
            goto exit;

        if( ( ret = jhd_tls_md_update( &md_ctx, diversifier, v ) ) != 0 )
            goto exit;

        if( ( ret = jhd_tls_md_update( &md_ctx, salt_block, v ) ) != 0 )
            goto exit;

        if( ( ret = jhd_tls_md_update( &md_ctx, pwd_block, v ) ) != 0 )
            goto exit;

        if( ( ret = jhd_tls_md_finish( &md_ctx, hash_output ) ) != 0 )
            goto exit;

        // Perform remaining ( iterations - 1 ) recursive hash calculations
        for( i = 1; i < (size_t) iterations; i++ )
        {
            if( ( ret = jhd_tls_md( md_info, hash_output, hlen, hash_output ) ) != 0 )
                goto exit;
        }

        use_len = ( datalen > hlen ) ? hlen : datalen;
        memcpy( p, hash_output, use_len );
        datalen -= use_len;
        p += use_len;

        if( datalen == 0 )
            break;

        // Concatenating copies of hash_output into hash_block (B)
        pkcs12_fill_buffer( hash_block, v, hash_output, hlen );

        // B += 1
        for( i = v; i > 0; i-- )
            if( ++hash_block[i - 1] != 0 )
                break;

        // salt_block += B
        c = 0;
        for( i = v; i > 0; i-- )
        {
            j = salt_block[i - 1] + hash_block[i - 1] + c;
            c = (unsigned char) (j >> 8);
            salt_block[i - 1] = j & 0xFF;
        }

        // pwd_block  += B
        c = 0;
        for( i = v; i > 0; i-- )
        {
            j = pwd_block[i - 1] + hash_block[i - 1] + c;
            c = (unsigned char) (j >> 8);
            pwd_block[i - 1] = j & 0xFF;
        }
    }

    ret = 0;

exit:
    jhd_tls_platform_zeroize( salt_block, sizeof( salt_block ) );
    jhd_tls_platform_zeroize( pwd_block, sizeof( pwd_block ) );
    jhd_tls_platform_zeroize( hash_block, sizeof( hash_block ) );
    jhd_tls_platform_zeroize( hash_output, sizeof( hash_output ) );

    jhd_tls_md_free( &md_ctx );

    return( ret );
}

#endif /* JHD_TLS_PKCS12_C */
