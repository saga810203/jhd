/*
 *  X.509 common functions for parsing and verification
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

#if defined(JHD_TLS_X509_USE_C)

#include <tls/jhd_tls_x509.h>
#include <tls/jhd_tls_asn1.h>
#include <tls/jhd_tls_oid.h>

#include <stdio.h>
#include <string.h>

#if defined(JHD_TLS_PEM_PARSE_C)
#include <tls/jhd_tls_pem.h>
#endif

#if defined(JHD_TLS_PLATFORM_C)
#include <tls/jhd_tls_platform.h>
#else
#include <stdio.h>
#include <stdlib.h>
#define jhd_tls_free      free
#define jhd_tls_calloc    calloc
#define jhd_tls_printf    printf
#define jhd_tls_snprintf  snprintf
#endif


#if defined(JHD_TLS_HAVE_TIME)
#include <tls/jhd_tls_platform_time.h>
#endif


#include <time.h>


#if defined(JHD_TLS_FS_IO)
#include <stdio.h>
#if !defined(_WIN32)
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#endif
#endif

#define CHECK(code) if( ( ret = code ) != 0 ){ return( ret ); }
#define CHECK_RANGE(min, max, val) if( val < min || val > max ){ return( ret ); }

/*
 *  CertificateSerialNumber  ::=  INTEGER
 */
int jhd_tls_x509_get_serial( unsigned char **p, const unsigned char *end,
                     jhd_tls_x509_buf *serial )
{
    int ret;

    if( ( end - *p ) < 1 )
        return( JHD_TLS_ERR_X509_INVALID_SERIAL +
                JHD_TLS_ERR_ASN1_OUT_OF_DATA );

    if( **p != ( JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_PRIMITIVE | 2 ) &&
        **p !=   JHD_TLS_ASN1_INTEGER )
        return( JHD_TLS_ERR_X509_INVALID_SERIAL +
                JHD_TLS_ERR_ASN1_UNEXPECTED_TAG );

    serial->tag = *(*p)++;

    if( ( ret = jhd_tls_asn1_get_len( p, end, &serial->len ) ) != 0 )
        return( JHD_TLS_ERR_X509_INVALID_SERIAL + ret );

    serial->p = *p;
    *p += serial->len;

    return( 0 );
}

/* Get an algorithm identifier without parameters (eg for signatures)
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
int jhd_tls_x509_get_alg_null( unsigned char **p, const unsigned char *end,
                       jhd_tls_x509_buf *alg )
{
    int ret;

    if( ( ret = jhd_tls_asn1_get_alg_null( p, end, alg ) ) != 0 )
        return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

    return( 0 );
}

/*
 * Parse an algorithm identifier with (optional) paramaters
 */
int jhd_tls_x509_get_alg( unsigned char **p, const unsigned char *end,
                  jhd_tls_x509_buf *alg, jhd_tls_x509_buf *params )
{
    int ret;

    if( ( ret = jhd_tls_asn1_get_alg( p, end, alg, params ) ) != 0 )
        return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

    return( 0 );
}

#if defined(JHD_TLS_X509_RSASSA_PSS_SUPPORT)
/*
 * HashAlgorithm ::= AlgorithmIdentifier
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm               OBJECT IDENTIFIER,
 *      parameters              ANY DEFINED BY algorithm OPTIONAL  }
 *
 * For HashAlgorithm, parameters MUST be NULL or absent.
 */
static int x509_get_hash_alg( const jhd_tls_x509_buf *alg, jhd_tls_md_type_t *md_alg )
{
    int ret;
    unsigned char *p;
    const unsigned char *end;
    jhd_tls_x509_buf md_oid;
    size_t len;

    /* Make sure we got a SEQUENCE and setup bounds */
    if( alg->tag != ( JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) )
        return( JHD_TLS_ERR_X509_INVALID_ALG +
                JHD_TLS_ERR_ASN1_UNEXPECTED_TAG );

    p = (unsigned char *) alg->p;
    end = p + alg->len;

    if( p >= end )
        return( JHD_TLS_ERR_X509_INVALID_ALG +
                JHD_TLS_ERR_ASN1_OUT_OF_DATA );

    /* Parse md_oid */
    md_oid.tag = *p;

    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &md_oid.len, JHD_TLS_ASN1_OID ) ) != 0 )
        return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

    md_oid.p = p;
    p += md_oid.len;

    /* Get md_alg from md_oid */
    if( ( ret = jhd_tls_oid_get_md_alg( &md_oid, md_alg ) ) != 0 )
        return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

    /* Make sure params is absent of NULL */
    if( p == end )
        return( 0 );

    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len, JHD_TLS_ASN1_NULL ) ) != 0 || len != 0 )
        return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

    if( p != end )
        return( JHD_TLS_ERR_X509_INVALID_ALG +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 *    RSASSA-PSS-params  ::=  SEQUENCE  {
 *       hashAlgorithm     [0] HashAlgorithm DEFAULT sha1Identifier,
 *       maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
 *       saltLength        [2] INTEGER DEFAULT 20,
 *       trailerField      [3] INTEGER DEFAULT 1  }
 *    -- Note that the tags in this Sequence are explicit.
 *
 * RFC 4055 (which defines use of RSASSA-PSS in PKIX) states that the value
 * of trailerField MUST be 1, and PKCS#1 v2.2 doesn't even define any other
 * option. Enfore this at parsing time.
 */
int jhd_tls_x509_get_rsassa_pss_params( const jhd_tls_x509_buf *params,
                                jhd_tls_md_type_t *md_alg, jhd_tls_md_type_t *mgf_md,
                                int *salt_len )
{
    int ret;
    unsigned char *p;
    const unsigned char *end, *end2;
    size_t len;
    jhd_tls_x509_buf alg_id, alg_params;

    /* First set everything to defaults */
    *md_alg = JHD_TLS_MD_SHA1;
    *mgf_md = JHD_TLS_MD_SHA1;
    *salt_len = 20;

    /* Make sure params is a SEQUENCE and setup bounds */
    if( params->tag != ( JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) )
        return( JHD_TLS_ERR_X509_INVALID_ALG +
                JHD_TLS_ERR_ASN1_UNEXPECTED_TAG );

    p = (unsigned char *) params->p;
    end = p + params->len;

    if( p == end )
        return( 0 );

    /*
     * HashAlgorithm
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                    JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | 0 ) ) == 0 )
    {
        end2 = p + len;

        /* HashAlgorithm ::= AlgorithmIdentifier (without parameters) */
        if( ( ret = jhd_tls_x509_get_alg_null( &p, end2, &alg_id ) ) != 0 )
            return( ret );

        if( ( ret = jhd_tls_oid_get_md_alg( &alg_id, md_alg ) ) != 0 )
            return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

        if( p != end2 )
            return( JHD_TLS_ERR_X509_INVALID_ALG +
                    JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    else if( ret != JHD_TLS_ERR_ASN1_UNEXPECTED_TAG )
        return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

    if( p == end )
        return( 0 );

    /*
     * MaskGenAlgorithm
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                    JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | 1 ) ) == 0 )
    {
        end2 = p + len;

        /* MaskGenAlgorithm ::= AlgorithmIdentifier (params = HashAlgorithm) */
        if( ( ret = jhd_tls_x509_get_alg( &p, end2, &alg_id, &alg_params ) ) != 0 )
            return( ret );

        /* Only MFG1 is recognised for now */
        if( JHD_TLS_OID_CMP( JHD_TLS_OID_MGF1, &alg_id ) != 0 )
            return( JHD_TLS_ERR_X509_FEATURE_UNAVAILABLE +
                    JHD_TLS_ERR_OID_NOT_FOUND );

        /* Parse HashAlgorithm */
        if( ( ret = x509_get_hash_alg( &alg_params, mgf_md ) ) != 0 )
            return( ret );

        if( p != end2 )
            return( JHD_TLS_ERR_X509_INVALID_ALG +
                    JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    else if( ret != JHD_TLS_ERR_ASN1_UNEXPECTED_TAG )
        return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

    if( p == end )
        return( 0 );

    /*
     * salt_len
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                    JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | 2 ) ) == 0 )
    {
        end2 = p + len;

        if( ( ret = jhd_tls_asn1_get_int( &p, end2, salt_len ) ) != 0 )
            return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

        if( p != end2 )
            return( JHD_TLS_ERR_X509_INVALID_ALG +
                    JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    else if( ret != JHD_TLS_ERR_ASN1_UNEXPECTED_TAG )
        return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

    if( p == end )
        return( 0 );

    /*
     * trailer_field (if present, must be 1)
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                    JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | 3 ) ) == 0 )
    {
        int trailer_field;

        end2 = p + len;

        if( ( ret = jhd_tls_asn1_get_int( &p, end2, &trailer_field ) ) != 0 )
            return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

        if( p != end2 )
            return( JHD_TLS_ERR_X509_INVALID_ALG +
                    JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

        if( trailer_field != 1 )
            return( JHD_TLS_ERR_X509_INVALID_ALG );
    }
    else if( ret != JHD_TLS_ERR_ASN1_UNEXPECTED_TAG )
        return( JHD_TLS_ERR_X509_INVALID_ALG + ret );

    if( p != end )
        return( JHD_TLS_ERR_X509_INVALID_ALG +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}
#endif /* JHD_TLS_X509_RSASSA_PSS_SUPPORT */

/*
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
static int x509_get_attr_type_value( unsigned char **p,
                                     const unsigned char *end,
                                     jhd_tls_x509_name *cur )
{
    int ret;
    size_t len;
    jhd_tls_x509_buf *oid;
    jhd_tls_x509_buf *val;

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
        return( JHD_TLS_ERR_X509_INVALID_NAME + ret );

    if( ( end - *p ) < 1 )
        return( JHD_TLS_ERR_X509_INVALID_NAME +
                JHD_TLS_ERR_ASN1_OUT_OF_DATA );

    oid = &cur->oid;
    oid->tag = **p;

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &oid->len, JHD_TLS_ASN1_OID ) ) != 0 )
        return( JHD_TLS_ERR_X509_INVALID_NAME + ret );

    oid->p = *p;
    *p += oid->len;

    if( ( end - *p ) < 1 )
        return( JHD_TLS_ERR_X509_INVALID_NAME +
                JHD_TLS_ERR_ASN1_OUT_OF_DATA );

    if( **p != JHD_TLS_ASN1_BMP_STRING && **p != JHD_TLS_ASN1_UTF8_STRING      &&
        **p != JHD_TLS_ASN1_T61_STRING && **p != JHD_TLS_ASN1_PRINTABLE_STRING &&
        **p != JHD_TLS_ASN1_IA5_STRING && **p != JHD_TLS_ASN1_UNIVERSAL_STRING &&
        **p != JHD_TLS_ASN1_BIT_STRING )
        return( JHD_TLS_ERR_X509_INVALID_NAME +
                JHD_TLS_ERR_ASN1_UNEXPECTED_TAG );

    val = &cur->val;
    val->tag = *(*p)++;

    if( ( ret = jhd_tls_asn1_get_len( p, end, &val->len ) ) != 0 )
        return( JHD_TLS_ERR_X509_INVALID_NAME + ret );

    val->p = *p;
    *p += val->len;

    cur->next = NULL;

    return( 0 );
}

/*
 *  Name ::= CHOICE { -- only one possibility for now --
 *       rdnSequence  RDNSequence }
 *
 *  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 *
 * The data structure is optimized for the common case where each RDN has only
 * one element, which is represented as a list of AttributeTypeAndValue.
 * For the general case we still use a flat list, but we mark elements of the
 * same set so that they are "merged" together in the functions that consume
 * this list, eg jhd_tls_x509_dn_gets().
 */
int jhd_tls_x509_get_name( unsigned char **p, const unsigned char *end,
                   jhd_tls_x509_name *cur )
{
    int ret;
    size_t set_len;
    const unsigned char *end_set;

    /* don't use recursion, we'd risk stack overflow if not optimized */
    while( 1 )
    {
        /*
         * parse SET
         */
        if( ( ret = jhd_tls_asn1_get_tag( p, end, &set_len,
                JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SET ) ) != 0 )
            return( JHD_TLS_ERR_X509_INVALID_NAME + ret );

        end_set  = *p + set_len;

        while( 1 )
        {
            if( ( ret = x509_get_attr_type_value( p, end_set, cur ) ) != 0 )
                return( ret );

            if( *p == end_set )
                break;

            /* Mark this item as being no the only one in a set */
            cur->next_merged = 1;

            cur->next = jhd_tls_calloc( 1, sizeof( jhd_tls_x509_name ) );

            if( cur->next == NULL )
                return( JHD_TLS_ERR_X509_ALLOC_FAILED );

            cur = cur->next;
        }

        /*
         * continue until end of SEQUENCE is reached
         */
        if( *p == end )
            return( 0 );

        cur->next = jhd_tls_calloc( 1, sizeof( jhd_tls_x509_name ) );

        if( cur->next == NULL )
            return( JHD_TLS_ERR_X509_ALLOC_FAILED );

        cur = cur->next;
    }
}

static int x509_parse_int( unsigned char **p, size_t n, int *res )
{
    *res = 0;

    for( ; n > 0; --n )
    {
        if( ( **p < '0') || ( **p > '9' ) )
            return ( JHD_TLS_ERR_X509_INVALID_DATE );

        *res *= 10;
        *res += ( *(*p)++ - '0' );
    }

    return( 0 );
}

static int x509_date_is_valid(const jhd_tls_x509_time *t )
{
    int ret = JHD_TLS_ERR_X509_INVALID_DATE;
    int month_len;

    CHECK_RANGE( 0, 9999, t->year );
    CHECK_RANGE( 0, 23,   t->hour );
    CHECK_RANGE( 0, 59,   t->min  );
    CHECK_RANGE( 0, 59,   t->sec  );

    switch( t->mon )
    {
        case 1: case 3: case 5: case 7: case 8: case 10: case 12:
            month_len = 31;
            break;
        case 4: case 6: case 9: case 11:
            month_len = 30;
            break;
        case 2:
            if( ( !( t->year % 4 ) && t->year % 100 ) ||
                !( t->year % 400 ) )
                month_len = 29;
            else
                month_len = 28;
            break;
        default:
            return( ret );
    }
    CHECK_RANGE( 1, month_len, t->day );

    return( 0 );
}

/*
 * Parse an ASN1_UTC_TIME (yearlen=2) or ASN1_GENERALIZED_TIME (yearlen=4)
 * field.
 */
static int x509_parse_time( unsigned char **p, size_t len, size_t yearlen,
                            jhd_tls_x509_time *tm )
{
    int ret;

    /*
     * Minimum length is 10 or 12 depending on yearlen
     */
    if ( len < yearlen + 8 )
        return ( JHD_TLS_ERR_X509_INVALID_DATE );
    len -= yearlen + 8;

    /*
     * Parse year, month, day, hour, minute
     */
    CHECK( x509_parse_int( p, yearlen, &tm->year ) );
    if ( 2 == yearlen )
    {
        if ( tm->year < 50 )
            tm->year += 100;

        tm->year += 1900;
    }

    CHECK( x509_parse_int( p, 2, &tm->mon ) );
    CHECK( x509_parse_int( p, 2, &tm->day ) );
    CHECK( x509_parse_int( p, 2, &tm->hour ) );
    CHECK( x509_parse_int( p, 2, &tm->min ) );

    /*
     * Parse seconds if present
     */
    if ( len >= 2 )
    {
        CHECK( x509_parse_int( p, 2, &tm->sec ) );
        len -= 2;
    }
    else
        return ( JHD_TLS_ERR_X509_INVALID_DATE );

    /*
     * Parse trailing 'Z' if present
     */
    if ( 1 == len && 'Z' == **p )
    {
        (*p)++;
        len--;
    }

    /*
     * We should have parsed all characters at this point
     */
    if ( 0 != len )
        return ( JHD_TLS_ERR_X509_INVALID_DATE );

    CHECK( x509_date_is_valid( tm ) );

    return ( 0 );
}

/*
 *  Time ::= CHOICE {
 *       utcTime        UTCTime,
 *       generalTime    GeneralizedTime }
 */
int jhd_tls_x509_get_time( unsigned char **p, const unsigned char *end,
                           jhd_tls_x509_time *tm )
{
    int ret;
    size_t len, year_len;
    unsigned char tag;

    if( ( end - *p ) < 1 )
        return( JHD_TLS_ERR_X509_INVALID_DATE +
                JHD_TLS_ERR_ASN1_OUT_OF_DATA );

    tag = **p;

    if( tag == JHD_TLS_ASN1_UTC_TIME )
        year_len = 2;
    else if( tag == JHD_TLS_ASN1_GENERALIZED_TIME )
        year_len = 4;
    else
        return( JHD_TLS_ERR_X509_INVALID_DATE +
                JHD_TLS_ERR_ASN1_UNEXPECTED_TAG );

    (*p)++;
    ret = jhd_tls_asn1_get_len( p, end, &len );

    if( ret != 0 )
        return( JHD_TLS_ERR_X509_INVALID_DATE + ret );

    return x509_parse_time( p, len, year_len, tm );
}

int jhd_tls_x509_get_sig( unsigned char **p, const unsigned char *end, jhd_tls_x509_buf *sig )
{
    int ret;
    size_t len;
    int tag_type;

    if( ( end - *p ) < 1 )
        return( JHD_TLS_ERR_X509_INVALID_SIGNATURE +
                JHD_TLS_ERR_ASN1_OUT_OF_DATA );

    tag_type = **p;

    if( ( ret = jhd_tls_asn1_get_bitstring_null( p, end, &len ) ) != 0 )
        return( JHD_TLS_ERR_X509_INVALID_SIGNATURE + ret );

    sig->tag = tag_type;
    sig->len = len;
    sig->p = *p;

    *p += len;

    return( 0 );
}

/*
 * Get signature algorithm from alg OID and optional parameters
 */
int jhd_tls_x509_get_sig_alg( const jhd_tls_x509_buf *sig_oid, const jhd_tls_x509_buf *sig_params,
                      jhd_tls_md_type_t *md_alg, jhd_tls_pk_type_t *pk_alg,
                      void **sig_opts )
{
    int ret;

    if( *sig_opts != NULL )
        return( JHD_TLS_ERR_X509_BAD_INPUT_DATA );

    if( ( ret = jhd_tls_oid_get_sig_alg( sig_oid, md_alg, pk_alg ) ) != 0 )
        return( JHD_TLS_ERR_X509_UNKNOWN_SIG_ALG + ret );

#if defined(JHD_TLS_X509_RSASSA_PSS_SUPPORT)
    if( *pk_alg == JHD_TLS_PK_RSASSA_PSS )
    {
        jhd_tls_pk_rsassa_pss_options *pss_opts;

        pss_opts = jhd_tls_calloc( 1, sizeof( jhd_tls_pk_rsassa_pss_options ) );
        if( pss_opts == NULL )
            return( JHD_TLS_ERR_X509_ALLOC_FAILED );

        ret = jhd_tls_x509_get_rsassa_pss_params( sig_params,
                                          md_alg,
                                          &pss_opts->mgf1_hash_id,
                                          &pss_opts->expected_salt_len );
        if( ret != 0 )
        {
            jhd_tls_free( pss_opts );
            return( ret );
        }

        *sig_opts = (void *) pss_opts;
    }
    else
#endif /* JHD_TLS_X509_RSASSA_PSS_SUPPORT */
    {
        /* Make sure parameters are absent or NULL */
        if( ( sig_params->tag != JHD_TLS_ASN1_NULL && sig_params->tag != 0 ) ||
              sig_params->len != 0 )
        return( JHD_TLS_ERR_X509_INVALID_ALG );
    }

    return( 0 );
}

/*
 * X.509 Extensions (No parsing of extensions, pointer should
 * be either manually updated or extensions should be parsed!)
 */
int jhd_tls_x509_get_ext( unsigned char **p, const unsigned char *end,
                  jhd_tls_x509_buf *ext, int tag )
{
    int ret;
    size_t len;

    if( *p == end )
        return( 0 );

    ext->tag = **p;

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &ext->len,
            JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | tag ) ) != 0 )
        return( ret );

    ext->p = *p;
    end = *p + ext->len;

    /*
     * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     *
     * Extension  ::=  SEQUENCE  {
     *      extnID      OBJECT IDENTIFIER,
     *      critical    BOOLEAN DEFAULT FALSE,
     *      extnValue   OCTET STRING  }
     */
    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
        return( JHD_TLS_ERR_X509_INVALID_EXTENSIONS + ret );

    if( end != *p + len )
        return( JHD_TLS_ERR_X509_INVALID_EXTENSIONS +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * Store the name in printable form into buf; no more
 * than size characters will be written
 */
int jhd_tls_x509_dn_gets( char *buf, size_t size, const jhd_tls_x509_name *dn )
{
    int ret;
    size_t i, n;
    unsigned char c, merge = 0;
    const jhd_tls_x509_name *name;
    const char *short_name = NULL;
    char s[JHD_TLS_X509_MAX_DN_NAME_SIZE], *p;

    memset( s, 0, sizeof( s ) );

    name = dn;
    p = buf;
    n = size;

    while( name != NULL )
    {
        if( !name->oid.p )
        {
            name = name->next;
            continue;
        }

        if( name != dn )
        {
            ret = jhd_tls_snprintf( p, n, merge ? " + " : ", " );
            JHD_TLS_X509_SAFE_SNPRINTF;
        }

        ret = jhd_tls_oid_get_attr_short_name( &name->oid, &short_name );

        if( ret == 0 )
            ret = jhd_tls_snprintf( p, n, "%s=", short_name );
        else
            ret = jhd_tls_snprintf( p, n, "\?\?=" );
        JHD_TLS_X509_SAFE_SNPRINTF;

        for( i = 0; i < name->val.len; i++ )
        {
            if( i >= sizeof( s ) - 1 )
                break;

            c = name->val.p[i];
            if( c < 32 || c == 127 || ( c > 128 && c < 160 ) )
                 s[i] = '?';
            else s[i] = c;
        }
        s[i] = '\0';
        ret = jhd_tls_snprintf( p, n, "%s", s );
        JHD_TLS_X509_SAFE_SNPRINTF;

        merge = name->next_merged;
        name = name->next;
    }

    return( (int) ( size - n ) );
}

/*
 * Store the serial in printable form into buf; no more
 * than size characters will be written
 */
int jhd_tls_x509_serial_gets( char *buf, size_t size, const jhd_tls_x509_buf *serial )
{
    int ret;
    size_t i, n, nr;
    char *p;

    p = buf;
    n = size;

    nr = ( serial->len <= 32 )
        ? serial->len  : 28;

    for( i = 0; i < nr; i++ )
    {
        if( i == 0 && nr > 1 && serial->p[i] == 0x0 )
            continue;

        ret = jhd_tls_snprintf( p, n, "%02X%s",
                serial->p[i], ( i < nr - 1 ) ? ":" : "" );
        JHD_TLS_X509_SAFE_SNPRINTF;
    }

    if( nr != serial->len )
    {
        ret = jhd_tls_snprintf( p, n, "...." );
        JHD_TLS_X509_SAFE_SNPRINTF;
    }

    return( (int) ( size - n ) );
}

/*
 * Helper for writing signature algorithms
 */
int jhd_tls_x509_sig_alg_gets( char *buf, size_t size, const jhd_tls_x509_buf *sig_oid,
                       jhd_tls_pk_type_t pk_alg, jhd_tls_md_type_t md_alg,
                       const void *sig_opts )
{
    int ret;
    char *p = buf;
    size_t n = size;
    const char *desc = NULL;

    ret = jhd_tls_oid_get_sig_alg_desc( sig_oid, &desc );
    if( ret != 0 )
        ret = jhd_tls_snprintf( p, n, "???"  );
    else
        ret = jhd_tls_snprintf( p, n, "%s", desc );
    JHD_TLS_X509_SAFE_SNPRINTF;

#if defined(JHD_TLS_X509_RSASSA_PSS_SUPPORT)
    if( pk_alg == JHD_TLS_PK_RSASSA_PSS )
    {
        const jhd_tls_pk_rsassa_pss_options *pss_opts;
        const jhd_tls_md_info_t *md_info, *mgf_md_info;

        pss_opts = (const jhd_tls_pk_rsassa_pss_options *) sig_opts;

        md_info = jhd_tls_md_info_from_type( md_alg );
        mgf_md_info = jhd_tls_md_info_from_type( pss_opts->mgf1_hash_id );

        ret = jhd_tls_snprintf( p, n, " (%s, MGF1-%s, 0x%02X)",
                              md_info ? jhd_tls_md_get_name( md_info ) : "???",
                              mgf_md_info ? jhd_tls_md_get_name( mgf_md_info ) : "???",
                              pss_opts->expected_salt_len );
        JHD_TLS_X509_SAFE_SNPRINTF;
    }
#else
    ((void) pk_alg);
    ((void) md_alg);
    ((void) sig_opts);
#endif /* JHD_TLS_X509_RSASSA_PSS_SUPPORT */

    return( (int)( size - n ) );
}

/*
 * Helper for writing "RSA key size", "EC key size", etc
 */
int jhd_tls_x509_key_size_helper( char *buf, size_t buf_size, const char *name )
{
    char *p = buf;
    size_t n = buf_size;
    int ret;

    ret = jhd_tls_snprintf( p, n, "%s key size", name );
    JHD_TLS_X509_SAFE_SNPRINTF;

    return( 0 );
}

#if defined(JHD_TLS_HAVE_TIME_DATE)
/*
 * Set the time structure to the current time.
 * Return 0 on success, non-zero on failure.
 */
#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)
static int x509_get_current_time( jhd_tls_x509_time *now )
{
    SYSTEMTIME st;

    GetSystemTime( &st );

    now->year = st.wYear;
    now->mon  = st.wMonth;
    now->day  = st.wDay;
    now->hour = st.wHour;
    now->min  = st.wMinute;
    now->sec  = st.wSecond;

    return( 0 );
}
#else
static int x509_get_current_time( jhd_tls_x509_time *now )
{
    struct tm *lt;
    jhd_tls_time_t tt;
    int ret = 0;

#if defined(JHD_TLS_THREADING_C)
    if( jhd_tls_mutex_lock( &jhd_tls_threading_gmtime_mutex ) != 0 )
        return( JHD_TLS_ERR_THREADING_MUTEX_ERROR );
#endif

    tt = jhd_tls_time( NULL );
    lt = gmtime( &tt );

    if( lt == NULL )
        ret = -1;
    else
    {
        now->year = lt->tm_year + 1900;
        now->mon  = lt->tm_mon  + 1;
        now->day  = lt->tm_mday;
        now->hour = lt->tm_hour;
        now->min  = lt->tm_min;
        now->sec  = lt->tm_sec;
    }

#if defined(JHD_TLS_THREADING_C)
    if( jhd_tls_mutex_unlock( &jhd_tls_threading_gmtime_mutex ) != 0 )
        return( JHD_TLS_ERR_THREADING_MUTEX_ERROR );
#endif

    return( ret );
}
#endif /* _WIN32 && !EFIX64 && !EFI32 */

/*
 * Return 0 if before <= after, 1 otherwise
 */
static int x509_check_time( const jhd_tls_x509_time *before, const jhd_tls_x509_time *after )
{
    if( before->year  > after->year )
        return( 1 );

    if( before->year == after->year &&
        before->mon   > after->mon )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day   > after->day )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour  > after->hour )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour == after->hour &&
        before->min   > after->min  )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour == after->hour &&
        before->min  == after->min  &&
        before->sec   > after->sec  )
        return( 1 );

    return( 0 );
}

int jhd_tls_x509_time_is_past( const jhd_tls_x509_time *to )
{
    jhd_tls_x509_time now;

    if( x509_get_current_time( &now ) != 0 )
        return( 1 );

    return( x509_check_time( &now, to ) );
}

int jhd_tls_x509_time_is_future( const jhd_tls_x509_time *from )
{
    jhd_tls_x509_time now;

    if( x509_get_current_time( &now ) != 0 )
        return( 1 );

    return( x509_check_time( from, &now ) );
}

#else  /* JHD_TLS_HAVE_TIME_DATE */

int jhd_tls_x509_time_is_past( const jhd_tls_x509_time *to )
{
    ((void) to);
    return( 0 );
}

int jhd_tls_x509_time_is_future( const jhd_tls_x509_time *from )
{
    ((void) from);
    return( 0 );
}
#endif /* JHD_TLS_HAVE_TIME_DATE */

#if defined(JHD_TLS_SELF_TEST)

#include <tls/jhd_tls_x509_crt.h"
#include <tls/jhd_tls_certs.h"

/*
 * Checkup routine
 */
int jhd_tls_x509_self_test( int verbose )
{
#if defined(JHD_TLS_CERTS_C) && defined(JHD_TLS_SHA256_C)
    int ret;
    uint32_t flags;
    jhd_tls_x509_crt cacert;
    jhd_tls_x509_crt clicert;

    if( verbose != 0 )
        jhd_tls_printf( "  X.509 certificate load: " );

    jhd_tls_x509_crt_init( &clicert );

    ret = jhd_tls_x509_crt_parse( &clicert, (const unsigned char *) jhd_tls_test_cli_crt,
                           jhd_tls_test_cli_crt_len );
    if( ret != 0 )
    {
        if( verbose != 0 )
            jhd_tls_printf( "failed\n" );

        return( ret );
    }

    jhd_tls_x509_crt_init( &cacert );

    ret = jhd_tls_x509_crt_parse( &cacert, (const unsigned char *) jhd_tls_test_ca_crt,
                          jhd_tls_test_ca_crt_len );
    if( ret != 0 )
    {
        if( verbose != 0 )
            jhd_tls_printf( "failed\n" );

        return( ret );
    }

    if( verbose != 0 )
        jhd_tls_printf( "passed\n  X.509 signature verify: ");

    ret = jhd_tls_x509_crt_verify( &clicert, &cacert, NULL, NULL, &flags, NULL, NULL );
    if( ret != 0 )
    {
        if( verbose != 0 )
            jhd_tls_printf( "failed\n" );

        return( ret );
    }

    if( verbose != 0 )
        jhd_tls_printf( "passed\n\n");

    jhd_tls_x509_crt_free( &cacert  );
    jhd_tls_x509_crt_free( &clicert );

    return( 0 );
#else
    ((void) verbose);
    return( 0 );
#endif /* JHD_TLS_CERTS_C && JHD_TLS_SHA1_C */
}

#endif /* JHD_TLS_SELF_TEST */

#endif /* JHD_TLS_X509_USE_C */
