/*
 *  X.509 Certificate Signing Request (CSR) parsing
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
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_X509_CSR_PARSE_C)

#include <tls/jhd_tls_x509_csr.h>
#include <tls/jhd_tls_oid.h>

#include <string.h>

#if defined(JHD_TLS_PEM_PARSE_C)
#include <tls/jhd_tls_pem.h>
#endif

#if defined(JHD_TLS_PLATFORM_C)
#include <tls/jhd_tls_platform.h>
#else
#include <stdlib.h>
#include <stdio.h>
#define jhd_tls_free       free
#define jhd_tls_calloc    calloc
#define jhd_tls_snprintf   snprintf
#endif

#if defined(JHD_TLS_FS_IO) || defined(EFIX64) || defined(EFI32)
#include <stdio.h>
#endif

/*
 *  Version  ::=  INTEGER  {  v1(0)  }
 */
static int x509_csr_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret;

    if( ( ret = jhd_tls_asn1_get_int( p, end, ver ) ) != 0 )
    {
        if( ret == JHD_TLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( JHD_TLS_ERR_X509_INVALID_VERSION + ret );
    }

    return( 0 );
}

/*
 * Parse a CSR in DER format
 */
int jhd_tls_x509_csr_parse_der( jhd_tls_x509_csr *csr,
                        const unsigned char *buf, size_t buflen )
{
    int ret;
    size_t len;
    unsigned char *p, *end;
    jhd_tls_x509_buf sig_params;

    memset( &sig_params, 0, sizeof( jhd_tls_x509_buf ) );

    /*
     * Check for valid input
     */
    if( csr == NULL || buf == NULL || buflen == 0 )
        return( JHD_TLS_ERR_X509_BAD_INPUT_DATA );

    jhd_tls_x509_csr_init( csr );

    /*
     * first copy the raw DER data
     */
    p = jhd_tls_calloc( 1, len = buflen );

    if( p == NULL )
        return( JHD_TLS_ERR_X509_ALLOC_FAILED );

    memcpy( p, buf, buflen );

    csr->raw.p = p;
    csr->raw.len = len;
    end = p + len;

    /*
     *  CertificationRequest ::= SEQUENCE {
     *       certificationRequestInfo CertificationRequestInfo,
     *       signatureAlgorithm AlgorithmIdentifier,
     *       signature          BIT STRING
     *  }
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
    {
        jhd_tls_x509_csr_free( csr );
        return( JHD_TLS_ERR_X509_INVALID_FORMAT );
    }

    if( len != (size_t) ( end - p ) )
    {
        jhd_tls_x509_csr_free( csr );
        return( JHD_TLS_ERR_X509_INVALID_FORMAT +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    /*
     *  CertificationRequestInfo ::= SEQUENCE {
     */
    csr->cri.p = p;

    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
    {
        jhd_tls_x509_csr_free( csr );
        return( JHD_TLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = p + len;
    csr->cri.len = end - csr->cri.p;

    /*
     *  Version  ::=  INTEGER {  v1(0) }
     */
    if( ( ret = x509_csr_get_version( &p, end, &csr->version ) ) != 0 )
    {
        jhd_tls_x509_csr_free( csr );
        return( ret );
    }

    if( csr->version != 0 )
    {
        jhd_tls_x509_csr_free( csr );
        return( JHD_TLS_ERR_X509_UNKNOWN_VERSION );
    }

    csr->version++;

    /*
     *  subject               Name
     */
    csr->subject_raw.p = p;

    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
    {
        jhd_tls_x509_csr_free( csr );
        return( JHD_TLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( ( ret = jhd_tls_x509_get_name( &p, p + len, &csr->subject ) ) != 0 )
    {
        jhd_tls_x509_csr_free( csr );
        return( ret );
    }

    csr->subject_raw.len = p - csr->subject_raw.p;

    /*
     *  subjectPKInfo SubjectPublicKeyInfo
     */
    if( ( ret = jhd_tls_pk_parse_subpubkey( &p, end, &csr->pk ) ) != 0 )
    {
        jhd_tls_x509_csr_free( csr );
        return( ret );
    }

    /*
     *  attributes    [0] Attributes
     *
     *  The list of possible attributes is open-ended, though RFC 2985
     *  (PKCS#9) defines a few in section 5.4. We currently don't support any,
     *  so we just ignore them. This is a safe thing to do as the worst thing
     *  that could happen is that we issue a certificate that does not match
     *  the requester's expectations - this cannot cause a violation of our
     *  signature policies.
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_CONTEXT_SPECIFIC ) ) != 0 )
    {
        jhd_tls_x509_csr_free( csr );
        return( JHD_TLS_ERR_X509_INVALID_FORMAT + ret );
    }

    p += len;

    end = csr->raw.p + csr->raw.len;

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signature            BIT STRING
     */
    if( ( ret = jhd_tls_x509_get_alg( &p, end, &csr->sig_oid, &sig_params ) ) != 0 )
    {
        jhd_tls_x509_csr_free( csr );
        return( ret );
    }

    if( ( ret = jhd_tls_x509_get_sig_alg( &csr->sig_oid, &sig_params,
                                  &csr->sig_md, &csr->sig_pk,
                                  &csr->sig_opts ) ) != 0 )
    {
        jhd_tls_x509_csr_free( csr );
        return( JHD_TLS_ERR_X509_UNKNOWN_SIG_ALG );
    }

    if( ( ret = jhd_tls_x509_get_sig( &p, end, &csr->sig ) ) != 0 )
    {
        jhd_tls_x509_csr_free( csr );
        return( ret );
    }

    if( p != end )
    {
        jhd_tls_x509_csr_free( csr );
        return( JHD_TLS_ERR_X509_INVALID_FORMAT +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    return( 0 );
}

/*
 * Parse a CSR, allowing for PEM or raw DER encoding
 */
int jhd_tls_x509_csr_parse( jhd_tls_x509_csr *csr, const unsigned char *buf, size_t buflen )
{
#if defined(JHD_TLS_PEM_PARSE_C)
    int ret;
    size_t use_len;
    jhd_tls_pem_context pem;
#endif

    /*
     * Check for valid input
     */
    if( csr == NULL || buf == NULL || buflen == 0 )
        return( JHD_TLS_ERR_X509_BAD_INPUT_DATA );

#if defined(JHD_TLS_PEM_PARSE_C)
    jhd_tls_pem_init( &pem );

    /* Avoid calling jhd_tls_pem_read_buffer() on non-null-terminated string */
    if( buf[buflen - 1] != '\0' )
        ret = JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = jhd_tls_pem_read_buffer( &pem,
                               "-----BEGIN CERTIFICATE REQUEST-----",
                               "-----END CERTIFICATE REQUEST-----",
                               buf, NULL, 0, &use_len );

    if( ret == 0 )
    {
        /*
         * Was PEM encoded, parse the result
         */
        if( ( ret = jhd_tls_x509_csr_parse_der( csr, pem.buf, pem.buflen ) ) != 0 )
            return( ret );

        jhd_tls_pem_free( &pem );
        return( 0 );
    }
    else if( ret != JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
    {
        jhd_tls_pem_free( &pem );
        return( ret );
    }
    else
#endif /* JHD_TLS_PEM_PARSE_C */
    return( jhd_tls_x509_csr_parse_der( csr, buf, buflen ) );
}

#if defined(JHD_TLS_FS_IO)
/*
 * Load a CSR into the structure
 */
int jhd_tls_x509_csr_parse_file( jhd_tls_x509_csr *csr, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = jhd_tls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = jhd_tls_x509_csr_parse( csr, buf, n );

    jhd_tls_platform_zeroize( buf, n );
    jhd_tls_free( buf );

    return( ret );
}
#endif /* JHD_TLS_FS_IO */

#define BEFORE_COLON    14
#define BC              "14"
/*
 * Return an informational string about the CSR.
 */
int jhd_tls_x509_csr_info( char *buf, size_t size, const char *prefix,
                   const jhd_tls_x509_csr *csr )
{
    int ret;
    size_t n;
    char *p;
    char key_size_str[BEFORE_COLON];

    p = buf;
    n = size;

    ret = jhd_tls_snprintf( p, n, "%sCSR version   : %d",
                               prefix, csr->version );
    JHD_TLS_X509_SAFE_SNPRINTF;

    ret = jhd_tls_snprintf( p, n, "\n%ssubject name  : ", prefix );
    JHD_TLS_X509_SAFE_SNPRINTF;
    ret = jhd_tls_x509_dn_gets( p, n, &csr->subject );
    JHD_TLS_X509_SAFE_SNPRINTF;

    ret = jhd_tls_snprintf( p, n, "\n%ssigned using  : ", prefix );
    JHD_TLS_X509_SAFE_SNPRINTF;

    ret = jhd_tls_x509_sig_alg_gets( p, n, &csr->sig_oid, csr->sig_pk, csr->sig_md,
                             csr->sig_opts );
    JHD_TLS_X509_SAFE_SNPRINTF;

    if( ( ret = jhd_tls_x509_key_size_helper( key_size_str, BEFORE_COLON,
                                      jhd_tls_pk_get_name( &csr->pk ) ) ) != 0 )
    {
        return( ret );
    }

    ret = jhd_tls_snprintf( p, n, "\n%s%-" BC "s: %d bits\n", prefix, key_size_str,
                          (int) jhd_tls_pk_get_bitlen( &csr->pk ) );
    JHD_TLS_X509_SAFE_SNPRINTF;

    return( (int) ( size - n ) );
}

/*
 * Initialize a CSR
 */
void jhd_tls_x509_csr_init( jhd_tls_x509_csr *csr )
{
    memset( csr, 0, sizeof(jhd_tls_x509_csr) );
}

/*
 * Unallocate all CSR data
 */
void jhd_tls_x509_csr_free( jhd_tls_x509_csr *csr )
{
    jhd_tls_x509_name *name_cur;
    jhd_tls_x509_name *name_prv;

    if( csr == NULL )
        return;

    jhd_tls_pk_free( &csr->pk );

#if defined(JHD_TLS_X509_RSASSA_PSS_SUPPORT)
    jhd_tls_free( csr->sig_opts );
#endif

    name_cur = csr->subject.next;
    while( name_cur != NULL )
    {
        name_prv = name_cur;
        name_cur = name_cur->next;
        jhd_tls_platform_zeroize( name_prv, sizeof( jhd_tls_x509_name ) );
        jhd_tls_free( name_prv );
    }

    if( csr->raw.p != NULL )
    {
        jhd_tls_platform_zeroize( csr->raw.p, csr->raw.len );
        jhd_tls_free( csr->raw.p );
    }

    jhd_tls_platform_zeroize( csr, sizeof( jhd_tls_x509_csr ) );
}

#endif /* JHD_TLS_X509_CSR_PARSE_C */
