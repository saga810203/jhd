/*
 *  X.509 certificate writing
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
 * - certificates: RFC 5280, updated by RFC 6818
 * - CSRs: PKCS#10 v1.7 aka RFC 2986
 * - attributes: PKCS#9 v2.0 aka RFC 2985
 */

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_X509_CRT_WRITE_C)

#include <tls/jhd_tls_x509_crt.h>
#include <tls/jhd_tls_oid.h>
#include <tls/jhd_tls_asn1write.h>
#include <tls/jhd_tls_sha1.h>

#include <string.h>

#if defined(JHD_TLS_PEM_WRITE_C)
#include <tls/jhd_tls_pem.h>
#endif /* JHD_TLS_PEM_WRITE_C */

void jhd_tls_x509write_crt_init( jhd_tls_x509write_cert *ctx )
{
    memset( ctx, 0, sizeof( jhd_tls_x509write_cert ) );

    jhd_tls_mpi_init( &ctx->serial );
    ctx->version = JHD_TLS_X509_CRT_VERSION_3;
}

void jhd_tls_x509write_crt_free( jhd_tls_x509write_cert *ctx )
{
    jhd_tls_mpi_free( &ctx->serial );

    jhd_tls_asn1_free_named_data_list( &ctx->subject );
    jhd_tls_asn1_free_named_data_list( &ctx->issuer );
    jhd_tls_asn1_free_named_data_list( &ctx->extensions );

    jhd_tls_platform_zeroize( ctx, sizeof( jhd_tls_x509write_cert ) );
}

void jhd_tls_x509write_crt_set_version( jhd_tls_x509write_cert *ctx, int version )
{
    ctx->version = version;
}

void jhd_tls_x509write_crt_set_md_alg( jhd_tls_x509write_cert *ctx, jhd_tls_md_type_t md_alg )
{
    ctx->md_alg = md_alg;
}

void jhd_tls_x509write_crt_set_subject_key( jhd_tls_x509write_cert *ctx, jhd_tls_pk_context *key )
{
    ctx->subject_key = key;
}

void jhd_tls_x509write_crt_set_issuer_key( jhd_tls_x509write_cert *ctx, jhd_tls_pk_context *key )
{
    ctx->issuer_key = key;
}

int jhd_tls_x509write_crt_set_subject_name( jhd_tls_x509write_cert *ctx,
                                    const char *subject_name )
{
    return jhd_tls_x509_string_to_names( &ctx->subject, subject_name );
}

int jhd_tls_x509write_crt_set_issuer_name( jhd_tls_x509write_cert *ctx,
                                   const char *issuer_name )
{
    return jhd_tls_x509_string_to_names( &ctx->issuer, issuer_name );
}

int jhd_tls_x509write_crt_set_serial( jhd_tls_x509write_cert *ctx, const jhd_tls_mpi *serial )
{
    int ret;

    if( ( ret = jhd_tls_mpi_copy( &ctx->serial, serial ) ) != 0 )
        return( ret );

    return( 0 );
}

int jhd_tls_x509write_crt_set_validity( jhd_tls_x509write_cert *ctx, const char *not_before,
                                const char *not_after )
{
    if( strlen( not_before ) != JHD_TLS_X509_RFC5280_UTC_TIME_LEN - 1 ||
        strlen( not_after )  != JHD_TLS_X509_RFC5280_UTC_TIME_LEN - 1 )
    {
        return( JHD_TLS_ERR_X509_BAD_INPUT_DATA );
    }
    strncpy( ctx->not_before, not_before, JHD_TLS_X509_RFC5280_UTC_TIME_LEN );
    strncpy( ctx->not_after , not_after , JHD_TLS_X509_RFC5280_UTC_TIME_LEN );
    ctx->not_before[JHD_TLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
    ctx->not_after[JHD_TLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

    return( 0 );
}

int jhd_tls_x509write_crt_set_extension( jhd_tls_x509write_cert *ctx,
                                 const char *oid, size_t oid_len,
                                 int critical,
                                 const unsigned char *val, size_t val_len )
{
    return jhd_tls_x509_set_extension( &ctx->extensions, oid, oid_len,
                               critical, val, val_len );
}

int jhd_tls_x509write_crt_set_basic_constraints( jhd_tls_x509write_cert *ctx,
                                         int is_ca, int max_pathlen )
{
    int ret;
    unsigned char buf[9];
    unsigned char *c = buf + sizeof(buf);
    size_t len = 0;

    memset( buf, 0, sizeof(buf) );

    if( is_ca && max_pathlen > 127 )
        return( JHD_TLS_ERR_X509_BAD_INPUT_DATA );

    if( is_ca )
    {
        if( max_pathlen >= 0 )
        {
            JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_int( &c, buf, max_pathlen ) );
        }
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_bool( &c, buf, 1 ) );
    }

    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, buf, len ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, buf, JHD_TLS_ASN1_CONSTRUCTED |
                                                JHD_TLS_ASN1_SEQUENCE ) );

    return jhd_tls_x509write_crt_set_extension( ctx, JHD_TLS_OID_BASIC_CONSTRAINTS,
                                        JHD_TLS_OID_SIZE( JHD_TLS_OID_BASIC_CONSTRAINTS ),
                                        0, buf + sizeof(buf) - len, len );
}

#if defined(JHD_TLS_SHA1_C)
int jhd_tls_x509write_crt_set_subject_key_identifier( jhd_tls_x509write_cert *ctx )
{
    int ret;
    unsigned char buf[JHD_TLS_MPI_MAX_SIZE * 2 + 20]; /* tag, length + 2xMPI */
    unsigned char *c = buf + sizeof(buf);
    size_t len = 0;

    memset( buf, 0, sizeof(buf) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_pk_write_pubkey( &c, buf, ctx->subject_key ) );

    ret = jhd_tls_sha1_ret( buf + sizeof( buf ) - len, len,
                            buf + sizeof( buf ) - 20 );
    if( ret != 0 )
        return( ret );
    c = buf + sizeof( buf ) - 20;
    len = 20;

    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, buf, len ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, buf, JHD_TLS_ASN1_OCTET_STRING ) );

    return jhd_tls_x509write_crt_set_extension( ctx, JHD_TLS_OID_SUBJECT_KEY_IDENTIFIER,
                                        JHD_TLS_OID_SIZE( JHD_TLS_OID_SUBJECT_KEY_IDENTIFIER ),
                                        0, buf + sizeof(buf) - len, len );
}

int jhd_tls_x509write_crt_set_authority_key_identifier( jhd_tls_x509write_cert *ctx )
{
    int ret;
    unsigned char buf[JHD_TLS_MPI_MAX_SIZE * 2 + 20]; /* tag, length + 2xMPI */
    unsigned char *c = buf + sizeof( buf );
    size_t len = 0;

    memset( buf, 0, sizeof(buf) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_pk_write_pubkey( &c, buf, ctx->issuer_key ) );

    ret = jhd_tls_sha1_ret( buf + sizeof( buf ) - len, len,
                            buf + sizeof( buf ) - 20 );
    if( ret != 0 )
        return( ret );
    c = buf + sizeof( buf ) - 20;
    len = 20;

    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, buf, len ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, buf, JHD_TLS_ASN1_CONTEXT_SPECIFIC | 0 ) );

    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, buf, len ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, buf, JHD_TLS_ASN1_CONSTRUCTED |
                                                JHD_TLS_ASN1_SEQUENCE ) );

    return jhd_tls_x509write_crt_set_extension( ctx, JHD_TLS_OID_AUTHORITY_KEY_IDENTIFIER,
                                   JHD_TLS_OID_SIZE( JHD_TLS_OID_AUTHORITY_KEY_IDENTIFIER ),
                                   0, buf + sizeof( buf ) - len, len );
}
#endif /* JHD_TLS_SHA1_C */

int jhd_tls_x509write_crt_set_key_usage( jhd_tls_x509write_cert *ctx,
                                         unsigned int key_usage )
{
    unsigned char buf[4], ku;
    unsigned char *c;
    int ret;

    /* We currently only support 7 bits, from 0x80 to 0x02 */
    if( ( key_usage & ~0xfe ) != 0 )
        return( JHD_TLS_ERR_X509_FEATURE_UNAVAILABLE );

    c = buf + 4;
    ku = (unsigned char) key_usage;

    if( ( ret = jhd_tls_asn1_write_bitstring( &c, buf, &ku, 7 ) ) != 4 )
        return( ret );

    ret = jhd_tls_x509write_crt_set_extension( ctx, JHD_TLS_OID_KEY_USAGE,
                                       JHD_TLS_OID_SIZE( JHD_TLS_OID_KEY_USAGE ),
                                       1, buf, 4 );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int jhd_tls_x509write_crt_set_ns_cert_type( jhd_tls_x509write_cert *ctx,
                                    unsigned char ns_cert_type )
{
    unsigned char buf[4];
    unsigned char *c;
    int ret;

    c = buf + 4;

    if( ( ret = jhd_tls_asn1_write_bitstring( &c, buf, &ns_cert_type, 8 ) ) != 4 )
        return( ret );

    ret = jhd_tls_x509write_crt_set_extension( ctx, JHD_TLS_OID_NS_CERT_TYPE,
                                       JHD_TLS_OID_SIZE( JHD_TLS_OID_NS_CERT_TYPE ),
                                       0, buf, 4 );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

static int x509_write_time( unsigned char **p, unsigned char *start,
                            const char *t, size_t size )
{
    int ret;
    size_t len = 0;

    /*
     * write JHD_TLS_ASN1_UTC_TIME if year < 2050 (2 bytes shorter)
     */
    if( t[0] == '2' && t[1] == '0' && t[2] < '5' )
    {
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_raw_buffer( p, start,
                                             (const unsigned char *) t + 2,
                                             size - 2 ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( p, start, len ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( p, start, JHD_TLS_ASN1_UTC_TIME ) );
    }
    else
    {
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_raw_buffer( p, start,
                                                  (const unsigned char *) t,
                                                  size ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( p, start, len ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( p, start, JHD_TLS_ASN1_GENERALIZED_TIME ) );
    }

    return( (int) len );
}

int jhd_tls_x509write_crt_der( jhd_tls_x509write_cert *ctx, unsigned char *buf, size_t size,
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
    size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    jhd_tls_pk_type_t pk_alg;

    /*
     * Prepare data to be signed in tmp_buf
     */
    c = tmp_buf + sizeof( tmp_buf );

    /* Signature algorithm needed in TBS, and later for actual signature */

    /* There's no direct way of extracting a signature algorithm
     * (represented as an element of jhd_tls_pk_type_t) from a PK instance. */
    if( jhd_tls_pk_can_do( ctx->issuer_key, JHD_TLS_PK_RSA ) )
        pk_alg = JHD_TLS_PK_RSA;
    else if( jhd_tls_pk_can_do( ctx->issuer_key, JHD_TLS_PK_ECDSA ) )
        pk_alg = JHD_TLS_PK_ECDSA;
    else
        return( JHD_TLS_ERR_X509_INVALID_ALG );

    if( ( ret = jhd_tls_oid_get_oid_by_sig_alg( pk_alg, ctx->md_alg,
                                          &sig_oid, &sig_oid_len ) ) != 0 )
    {
        return( ret );
    }

    /*
     *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */

    /* Only for v3 */
    if( ctx->version == JHD_TLS_X509_CRT_VERSION_3 )
    {
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_x509_write_extensions( &c, tmp_buf, ctx->extensions ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, tmp_buf, len ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, tmp_buf, JHD_TLS_ASN1_CONSTRUCTED |
                                                           JHD_TLS_ASN1_SEQUENCE ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, tmp_buf, len ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, tmp_buf, JHD_TLS_ASN1_CONTEXT_SPECIFIC |
                                                           JHD_TLS_ASN1_CONSTRUCTED | 3 ) );
    }

    /*
     *  SubjectPublicKeyInfo
     */
    JHD_TLS_ASN1_CHK_ADD( pub_len, jhd_tls_pk_write_pubkey_der( ctx->subject_key,
                                                tmp_buf, c - tmp_buf ) );
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_x509_write_names( &c, tmp_buf, ctx->subject ) );

    /*
     *  Validity ::= SEQUENCE {
     *       notBefore      Time,
     *       notAfter       Time }
     */
    sub_len = 0;

    JHD_TLS_ASN1_CHK_ADD( sub_len, x509_write_time( &c, tmp_buf, ctx->not_after,
                                            JHD_TLS_X509_RFC5280_UTC_TIME_LEN ) );

    JHD_TLS_ASN1_CHK_ADD( sub_len, x509_write_time( &c, tmp_buf, ctx->not_before,
                                            JHD_TLS_X509_RFC5280_UTC_TIME_LEN ) );

    len += sub_len;
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, tmp_buf, sub_len ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, tmp_buf, JHD_TLS_ASN1_CONSTRUCTED |
                                                    JHD_TLS_ASN1_SEQUENCE ) );

    /*
     *  Issuer  ::=  Name
     */
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_x509_write_names( &c, tmp_buf, ctx->issuer ) );

    /*
     *  Signature   ::=  AlgorithmIdentifier
     */
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_algorithm_identifier( &c, tmp_buf,
                       sig_oid, strlen( sig_oid ), 0 ) );

    /*
     *  Serial   ::=  INTEGER
     */
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_mpi( &c, tmp_buf, &ctx->serial ) );

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */

    /* Can be omitted for v1 */
    if( ctx->version != JHD_TLS_X509_CRT_VERSION_1 )
    {
        sub_len = 0;
        JHD_TLS_ASN1_CHK_ADD( sub_len, jhd_tls_asn1_write_int( &c, tmp_buf, ctx->version ) );
        len += sub_len;
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, tmp_buf, sub_len ) );
        JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, tmp_buf, JHD_TLS_ASN1_CONTEXT_SPECIFIC |
                                                           JHD_TLS_ASN1_CONSTRUCTED | 0 ) );
    }

    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &c, tmp_buf, len ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &c, tmp_buf, JHD_TLS_ASN1_CONSTRUCTED |
                                                       JHD_TLS_ASN1_SEQUENCE ) );

    /*
     * Make signature
     */
    if( ( ret = jhd_tls_md( jhd_tls_md_info_from_type( ctx->md_alg ), c,
                            len, hash ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = jhd_tls_pk_sign( ctx->issuer_key, ctx->md_alg, hash, 0, sig, &sig_len,
                         f_rng, p_rng ) ) != 0 )
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

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"

#if defined(JHD_TLS_PEM_WRITE_C)
int jhd_tls_x509write_crt_pem( jhd_tls_x509write_cert *crt, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    unsigned char output_buf[4096];
    size_t olen = 0;

    if( ( ret = jhd_tls_x509write_crt_der( crt, output_buf, sizeof(output_buf),
                                   f_rng, p_rng ) ) < 0 )
    {
        return( ret );
    }

    if( ( ret = jhd_tls_pem_write_buffer( PEM_BEGIN_CRT, PEM_END_CRT,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}
#endif /* JHD_TLS_PEM_WRITE_C */

#endif /* JHD_TLS_X509_CRT_WRITE_C */
