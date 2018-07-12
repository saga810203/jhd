/*
 *  X.509 Certificate Signing Request writing
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
 * References:
 * - CSRs: PKCS#10 v1.7 aka RFC 2986
 * - attributes: PKCS#9 v2.0 aka RFC 2985
 */

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_X509_CSR_WRITE_C)

#include <tls/jhd_tls_x509_csr.h>
#include <tls/jhd_tls_oid.h>
#include <tls/jhd_tls_asn1write.h>

#include <string.h>
#include <stdlib.h>

#if defined(JHD_TLS_PEM_WRITE_C)
#include <tls/jhd_tls_pem.h>
#endif

void jhd_tls_x509write_csr_init( jhd_tls_x509write_csr *ctx )
{
    memset( ctx, 0, sizeof( jhd_tls_x509write_csr ) );
}

void jhd_tls_x509write_csr_free( jhd_tls_x509write_csr *ctx )
{
    jhd_tls_asn1_free_named_data_list( &ctx->subject );
    jhd_tls_asn1_free_named_data_list( &ctx->extensions );

    jhd_tls_platform_zeroize( ctx, sizeof( jhd_tls_x509write_csr ) );
}

void jhd_tls_x509write_csr_set_md_alg( jhd_tls_x509write_csr *ctx, jhd_tls_md_type_t md_alg )
{
    ctx->md_alg = md_alg;
}

void jhd_tls_x509write_csr_set_key( jhd_tls_x509write_csr *ctx, jhd_tls_pk_context *key )
{
    ctx->key = key;
}

int jhd_tls_x509write_csr_set_subject_name( jhd_tls_x509write_csr *ctx,
                                    const char *subject_name )
{
    return jhd_tls_x509_string_to_names( &ctx->subject, subject_name );
}

int jhd_tls_x509write_csr_set_extension( jhd_tls_x509write_csr *ctx,
                                 const char *oid, size_t oid_len,
                                 const unsigned char *val, size_t val_len )
{
    return jhd_tls_x509_set_extension( &ctx->extensions, oid, oid_len,
                               0, val, val_len );
}

int jhd_tls_x509write_csr_set_key_usage( jhd_tls_x509write_csr *ctx, unsigned char key_usage )
{
    unsigned char buf[4];
    unsigned char *c;
    int ret;

    c = buf + 4;

    if( ( ret = jhd_tls_asn1_write_bitstring( &c, buf, &key_usage, 7 ) ) != 4 )
        return( ret );

    ret = jhd_tls_x509write_csr_set_extension( ctx, JHD_TLS_OID_KEY_USAGE,
                                       JHD_TLS_OID_SIZE( JHD_TLS_OID_KEY_USAGE ),
                                       buf, 4 );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int jhd_tls_x509write_csr_set_ns_cert_type( jhd_tls_x509write_csr *ctx,
                                    unsigned char ns_cert_type )
{
    unsigned char buf[4];
    unsigned char *c;
    int ret;

    c = buf + 4;

    if( ( ret = jhd_tls_asn1_write_bitstring( &c, buf, &ns_cert_type, 8 ) ) != 4 )
        return( ret );

    ret = jhd_tls_x509write_csr_set_extension( ctx, JHD_TLS_OID_NS_CERT_TYPE,
                                       JHD_TLS_OID_SIZE( JHD_TLS_OID_NS_CERT_TYPE ),
                                       buf, 4 );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int jhd_tls_x509write_csr_der( jhd_tls_x509write_csr *ctx, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char hash[64];
    unsigned char sig[JHD_TLS_MPI_MAX_SIZE];
    unsigned char tmp_buf[2048];
    size_t pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    jhd_tls_pk_type_t pk_alg;

    /*
     * Prepare data to be signed in tmp_buf
     */
    c = tmp_buf + sizeof( tmp_buf );

    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_x509_write_extensions( &c, tmp_buf, ctx->extensions ) );

    if( len )
    {
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, tmp_buf, len ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, tmp_buf, JHD_TLS_ASN1_CONSTRUCTED |
                                                        JHD_TLS_ASN1_SEQUENCE ) );

        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, tmp_buf, len ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, tmp_buf, JHD_TLS_ASN1_CONSTRUCTED |
                                                        JHD_TLS_ASN1_SET ) );

        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_oid( &c, tmp_buf, JHD_TLS_OID_PKCS9_CSR_EXT_REQ,
                                          JHD_TLS_OID_SIZE( JHD_TLS_OID_PKCS9_CSR_EXT_REQ ) ) );

        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, tmp_buf, len ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, tmp_buf, JHD_TLS_ASN1_CONSTRUCTED |
                                                        JHD_TLS_ASN1_SEQUENCE ) );
    }

    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, tmp_buf, len ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, tmp_buf, JHD_TLS_ASN1_CONSTRUCTED |
                                                    JHD_TLS_ASN1_CONTEXT_SPECIFIC ) );

    JHD_TLS_ASN1_CHK_ADD( pub_len, jhd_tls_pk_write_pubkey_der( ctx->key,
                                                tmp_buf, c - tmp_buf ) );
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_x509_write_names( &c, tmp_buf, ctx->subject ) );

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_int( &c, tmp_buf, 0 ) );

    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, tmp_buf, len ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, tmp_buf, JHD_TLS_ASN1_CONSTRUCTED |
                                                    JHD_TLS_ASN1_SEQUENCE ) );

    /*
     * Prepare signature
     */
    jhd_tls_md( jhd_tls_md_info_from_type( ctx->md_alg ), c, len, hash );

    if( ( ret = jhd_tls_pk_sign( ctx->key, ctx->md_alg, hash, 0, sig, &sig_len,
                                 f_rng, p_rng ) ) != 0 )
    {
        return( ret );
    }

    if( jhd_tls_pk_can_do( ctx->key, JHD_TLS_PK_RSA ) )
        pk_alg = JHD_TLS_PK_RSA;
    else if( jhd_tls_pk_can_do( ctx->key, JHD_TLS_PK_ECDSA ) )
        pk_alg = JHD_TLS_PK_ECDSA;
    else
        return( JHD_TLS_ERR_X509_INVALID_ALG );

    if( ( ret = jhd_tls_oid_get_oid_by_sig_alg( pk_alg, ctx->md_alg,
                                                &sig_oid, &sig_oid_len ) ) != 0 )
    {
        return( ret );
    }

    /*
     * Write data to output buffer
     */
    c2 = buf + size;
    JHD_TLS_ASN1_CHK_ADD( sig_and_oid_len, jhd_tls_x509_write_sig( &c2, buf,
                                        sig_oid, sig_oid_len, sig, sig_len ) );

    if( len > (size_t)( c2 - buf ) )
        return( JHD_TLS_ERR_ASN1_BUF_TOO_SMALL );

    c2 -= len;
    memcpy( c2, c, len );

    len += sig_and_oid_len;
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c2, buf, len ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c2, buf, JHD_TLS_ASN1_CONSTRUCTED |
                                                 JHD_TLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

#define PEM_BEGIN_CSR           "-----BEGIN CERTIFICATE REQUEST-----\n"
#define PEM_END_CSR             "-----END CERTIFICATE REQUEST-----\n"

#if defined(JHD_TLS_PEM_WRITE_C)
int jhd_tls_x509write_csr_pem( jhd_tls_x509write_csr *ctx, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    unsigned char output_buf[4096];
    size_t olen = 0;

    if( ( ret = jhd_tls_x509write_csr_der( ctx, output_buf, sizeof(output_buf),
                                   f_rng, p_rng ) ) < 0 )
    {
        return( ret );
    }

    if( ( ret = jhd_tls_pem_write_buffer( PEM_BEGIN_CSR, PEM_END_CSR,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}
#endif /* JHD_TLS_PEM_WRITE_C */

#endif /* JHD_TLS_X509_CSR_WRITE_C */
