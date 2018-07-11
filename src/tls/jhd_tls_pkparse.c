/*
 *  Public Key layer for parsing key files and structures
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

#if defined(JHD_TLS_PK_PARSE_C)

#include <tls/jhd_tls_pk.h>
#include <tls/jhd_tls_asn1.h>
#include <tls/jhd_tls_oid.h>

#include <string.h>

#if defined(JHD_TLS_RSA_C)
#include <tls/jhd_tls_rsa.h>
#endif
#if defined(JHD_TLS_ECP_C)
#include <tls/jhd_tls_ecp.h>
#endif
#if defined(JHD_TLS_ECDSA_C)
#include <tls/jhd_tls_ecdsa.h>
#endif
#if defined(JHD_TLS_PEM_PARSE_C)
#include <tls/jhd_tls_pem.h>
#endif
#if defined(JHD_TLS_PKCS5_C)
#include <tls/jhd_tls_pkcs5.h>
#endif
#if defined(JHD_TLS_PKCS12_C)
#include <tls/jhd_tls_pkcs12.h>
#endif

#if defined(JHD_TLS_PLATFORM_C)
#include <tls/jhd_tls_platform.h>
#else
#include <stdlib.h>
#define jhd_tls_calloc    calloc
#define jhd_tls_free       free
#endif

#if defined(JHD_TLS_FS_IO)
/*
 * Load all data from a file into a given buffer.
 *
 * The file is expected to contain either PEM or DER encoded data.
 * A terminating null byte is always appended. It is included in the announced
 * length only if the data looks like it is PEM encoded.
 */
int jhd_tls_pk_load_file( const char *path, unsigned char **buf, size_t *n )
{
    FILE *f;
    long size;

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( JHD_TLS_ERR_PK_FILE_IO_ERROR );

    fseek( f, 0, SEEK_END );
    if( ( size = ftell( f ) ) == -1 )
    {
        fclose( f );
        return( JHD_TLS_ERR_PK_FILE_IO_ERROR );
    }
    fseek( f, 0, SEEK_SET );

    *n = (size_t) size;

    if( *n + 1 == 0 ||
        ( *buf = jhd_tls_calloc( 1, *n + 1 ) ) == NULL )
    {
        fclose( f );
        return( JHD_TLS_ERR_PK_ALLOC_FAILED );
    }

    if( fread( *buf, 1, *n, f ) != *n )
    {
        fclose( f );

        jhd_tls_platform_zeroize( *buf, *n );
        jhd_tls_free( *buf );

        return( JHD_TLS_ERR_PK_FILE_IO_ERROR );
    }

    fclose( f );

    (*buf)[*n] = '\0';

    if( strstr( (const char *) *buf, "-----BEGIN " ) != NULL )
        ++*n;

    return( 0 );
}

/*
 * Load and parse a private key
 */
int jhd_tls_pk_parse_keyfile( jhd_tls_pk_context *ctx,
                      const char *path, const char *pwd )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = jhd_tls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    if( pwd == NULL )
        ret = jhd_tls_pk_parse_key( ctx, buf, n, NULL, 0 );
    else
        ret = jhd_tls_pk_parse_key( ctx, buf, n,
                (const unsigned char *) pwd, strlen( pwd ) );

    jhd_tls_platform_zeroize( buf, n );
    jhd_tls_free( buf );

    return( ret );
}

/*
 * Load and parse a public key
 */
int jhd_tls_pk_parse_public_keyfile( jhd_tls_pk_context *ctx, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = jhd_tls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = jhd_tls_pk_parse_public_key( ctx, buf, n );

    jhd_tls_platform_zeroize( buf, n );
    jhd_tls_free( buf );

    return( ret );
}
#endif /* JHD_TLS_FS_IO */

#if defined(JHD_TLS_ECP_C)
/* Minimally parse an ECParameters buffer to and jhd_tls_asn1_buf
 *
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 *   specifiedCurve     SpecifiedECDomain -- = SEQUENCE { ... }
 *   -- implicitCurve   NULL
 * }
 */
static int pk_get_ecparams( unsigned char **p, const unsigned char *end,
                            jhd_tls_asn1_buf *params )
{
    int ret;

    if ( end - *p < 1 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT +
                JHD_TLS_ERR_ASN1_OUT_OF_DATA );

    /* Tag may be either OID or SEQUENCE */
    params->tag = **p;
    if( params->tag != JHD_TLS_ASN1_OID
#if defined(JHD_TLS_PK_PARSE_EC_EXTENDED)
            && params->tag != ( JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE )
#endif
            )
    {
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT +
                JHD_TLS_ERR_ASN1_UNEXPECTED_TAG );
    }

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &params->len, params->tag ) ) != 0 )
    {
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    params->p = *p;
    *p += params->len;

    if( *p != end )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

#if defined(JHD_TLS_PK_PARSE_EC_EXTENDED)
/*
 * Parse a SpecifiedECDomain (SEC 1 C.2) and (mostly) fill the group with it.
 * WARNING: the resulting group should only be used with
 * pk_group_id_from_specified(), since its base point may not be set correctly
 * if it was encoded compressed.
 *
 *  SpecifiedECDomain ::= SEQUENCE {
 *      version SpecifiedECDomainVersion(ecdpVer1 | ecdpVer2 | ecdpVer3, ...),
 *      fieldID FieldID {{FieldTypes}},
 *      curve Curve,
 *      base ECPoint,
 *      order INTEGER,
 *      cofactor INTEGER OPTIONAL,
 *      hash HashAlgorithm OPTIONAL,
 *      ...
 *  }
 *
 * We only support prime-field as field type, and ignore hash and cofactor.
 */
static int pk_group_from_specified( const jhd_tls_asn1_buf *params, jhd_tls_ecp_group *grp )
{
    int ret;
    unsigned char *p = params->p;
    const unsigned char * const end = params->p + params->len;
    const unsigned char *end_field, *end_curve;
    size_t len;
    int ver;

    /* SpecifiedECDomainVersion ::= INTEGER { 1, 2, 3 } */
    if( ( ret = jhd_tls_asn1_get_int( &p, end, &ver ) ) != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ver < 1 || ver > 3 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT );

    /*
     * FieldID { FIELD-ID:IOSet } ::= SEQUENCE { -- Finite field
     *       fieldType FIELD-ID.&id({IOSet}),
     *       parameters FIELD-ID.&Type({IOSet}{@fieldType})
     * }
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
        return( ret );

    end_field = p + len;

    /*
     * FIELD-ID ::= TYPE-IDENTIFIER
     * FieldTypes FIELD-ID ::= {
     *       { Prime-p IDENTIFIED BY prime-field } |
     *       { Characteristic-two IDENTIFIED BY characteristic-two-field }
     * }
     * prime-field OBJECT IDENTIFIER ::= { id-fieldType 1 }
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end_field, &len, JHD_TLS_ASN1_OID ) ) != 0 )
        return( ret );

    if( len != JHD_TLS_OID_SIZE( JHD_TLS_OID_ANSI_X9_62_PRIME_FIELD ) ||
        memcmp( p, JHD_TLS_OID_ANSI_X9_62_PRIME_FIELD, len ) != 0 )
    {
        return( JHD_TLS_ERR_PK_FEATURE_UNAVAILABLE );
    }

    p += len;

    /* Prime-p ::= INTEGER -- Field of size p. */
    if( ( ret = jhd_tls_asn1_get_mpi( &p, end_field, &grp->P ) ) != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    grp->pbits = jhd_tls_mpi_bitlen( &grp->P );

    if( p != end_field )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

    /*
     * Curve ::= SEQUENCE {
     *       a FieldElement,
     *       b FieldElement,
     *       seed BIT STRING OPTIONAL
     *       -- Shall be present if used in SpecifiedECDomain
     *       -- with version equal to ecdpVer2 or ecdpVer3
     * }
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
        return( ret );

    end_curve = p + len;

    /*
     * FieldElement ::= OCTET STRING
     * containing an integer in the case of a prime field
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end_curve, &len, JHD_TLS_ASN1_OCTET_STRING ) ) != 0 ||
        ( ret = jhd_tls_mpi_read_binary( &grp->A, p, len ) ) != 0 )
    {
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    p += len;

    if( ( ret = jhd_tls_asn1_get_tag( &p, end_curve, &len, JHD_TLS_ASN1_OCTET_STRING ) ) != 0 ||
        ( ret = jhd_tls_mpi_read_binary( &grp->B, p, len ) ) != 0 )
    {
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    p += len;

    /* Ignore seed BIT STRING OPTIONAL */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end_curve, &len, JHD_TLS_ASN1_BIT_STRING ) ) == 0 )
        p += len;

    if( p != end_curve )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

    /*
     * ECPoint ::= OCTET STRING
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len, JHD_TLS_ASN1_OCTET_STRING ) ) != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ( ret = jhd_tls_ecp_point_read_binary( grp, &grp->G,
                                      ( const unsigned char *) p, len ) ) != 0 )
    {
        /*
         * If we can't read the point because it's compressed, cheat by
         * reading only the X coordinate and the parity bit of Y.
         */
        if( ret != JHD_TLS_ERR_ECP_FEATURE_UNAVAILABLE ||
            ( p[0] != 0x02 && p[0] != 0x03 ) ||
            len != jhd_tls_mpi_size( &grp->P ) + 1 ||
            jhd_tls_mpi_read_binary( &grp->G.X, p + 1, len - 1 ) != 0 ||
            jhd_tls_mpi_lset( &grp->G.Y, p[0] - 2 ) != 0 ||
            jhd_tls_mpi_lset( &grp->G.Z, 1 ) != 0 )
        {
            return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT );
        }
    }

    p += len;

    /*
     * order INTEGER
     */
    if( ( ret = jhd_tls_asn1_get_mpi( &p, end, &grp->N ) ) != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    grp->nbits = jhd_tls_mpi_bitlen( &grp->N );

    /*
     * Allow optional elements by purposefully not enforcing p == end here.
     */

    return( 0 );
}

/*
 * Find the group id associated with an (almost filled) group as generated by
 * pk_group_from_specified(), or return an error if unknown.
 */
static int pk_group_id_from_group( const jhd_tls_ecp_group *grp, jhd_tls_ecp_group_id *grp_id )
{
    int ret = 0;
    jhd_tls_ecp_group ref;
    const jhd_tls_ecp_group_id *id;

    jhd_tls_ecp_group_init( &ref );

    for( id = jhd_tls_ecp_grp_id_list(); *id != JHD_TLS_ECP_DP_NONE; id++ )
    {
        /* Load the group associated to that id */
        jhd_tls_ecp_group_free( &ref );
        JHD_TLS_MPI_CHK( jhd_tls_ecp_group_load( &ref, *id ) );

        /* Compare to the group we were given, starting with easy tests */
        if( grp->pbits == ref.pbits && grp->nbits == ref.nbits &&
            jhd_tls_mpi_cmp_mpi( &grp->P, &ref.P ) == 0 &&
            jhd_tls_mpi_cmp_mpi( &grp->A, &ref.A ) == 0 &&
            jhd_tls_mpi_cmp_mpi( &grp->B, &ref.B ) == 0 &&
            jhd_tls_mpi_cmp_mpi( &grp->N, &ref.N ) == 0 &&
            jhd_tls_mpi_cmp_mpi( &grp->G.X, &ref.G.X ) == 0 &&
            jhd_tls_mpi_cmp_mpi( &grp->G.Z, &ref.G.Z ) == 0 &&
            /* For Y we may only know the parity bit, so compare only that */
            jhd_tls_mpi_get_bit( &grp->G.Y, 0 ) == jhd_tls_mpi_get_bit( &ref.G.Y, 0 ) )
        {
            break;
        }

    }

cleanup:
    jhd_tls_ecp_group_free( &ref );

    *grp_id = *id;

    if( ret == 0 && *id == JHD_TLS_ECP_DP_NONE )
        ret = JHD_TLS_ERR_ECP_FEATURE_UNAVAILABLE;

    return( ret );
}

/*
 * Parse a SpecifiedECDomain (SEC 1 C.2) and find the associated group ID
 */
static int pk_group_id_from_specified( const jhd_tls_asn1_buf *params,
                                       jhd_tls_ecp_group_id *grp_id )
{
    int ret;
    jhd_tls_ecp_group grp;

    jhd_tls_ecp_group_init( &grp );

    if( ( ret = pk_group_from_specified( params, &grp ) ) != 0 )
        goto cleanup;

    ret = pk_group_id_from_group( &grp, grp_id );

cleanup:
    jhd_tls_ecp_group_free( &grp );

    return( ret );
}
#endif /* JHD_TLS_PK_PARSE_EC_EXTENDED */

/*
 * Use EC parameters to initialise an EC group
 *
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 *   specifiedCurve     SpecifiedECDomain -- = SEQUENCE { ... }
 *   -- implicitCurve   NULL
 */
static int pk_use_ecparams( const jhd_tls_asn1_buf *params, jhd_tls_ecp_group *grp )
{
    int ret;
    jhd_tls_ecp_group_id grp_id;

    if( params->tag == JHD_TLS_ASN1_OID )
    {
        if( jhd_tls_oid_get_ec_grp( params, &grp_id ) != 0 )
            return( JHD_TLS_ERR_PK_UNKNOWN_NAMED_CURVE );
    }
    else
    {
#if defined(JHD_TLS_PK_PARSE_EC_EXTENDED)
        if( ( ret = pk_group_id_from_specified( params, &grp_id ) ) != 0 )
            return( ret );
#else
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT );
#endif
    }

    /*
     * grp may already be initilialized; if so, make sure IDs match
     */
    if( grp->id != JHD_TLS_ECP_DP_NONE && grp->id != grp_id )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT );

    if( ( ret = jhd_tls_ecp_group_load( grp, grp_id ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * EC public key is an EC point
 *
 * The caller is responsible for clearing the structure upon failure if
 * desired. Take care to pass along the possible ECP_FEATURE_UNAVAILABLE
 * return code of jhd_tls_ecp_point_read_binary() and leave p in a usable state.
 */
static int pk_get_ecpubkey( unsigned char **p, const unsigned char *end,
                            jhd_tls_ecp_keypair *key )
{
    int ret;

    if( ( ret = jhd_tls_ecp_point_read_binary( &key->grp, &key->Q,
                    (const unsigned char *) *p, end - *p ) ) == 0 )
    {
        ret = jhd_tls_ecp_check_pubkey( &key->grp, &key->Q );
    }

    /*
     * We know jhd_tls_ecp_point_read_binary consumed all bytes or failed
     */
    *p = (unsigned char *) end;

    return( ret );
}
#endif /* JHD_TLS_ECP_C */

#if defined(JHD_TLS_RSA_C)
/*
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *  }
 */
static int pk_get_rsapubkey( unsigned char **p,
                             const unsigned char *end,
                             jhd_tls_rsa_context *rsa )
{
    int ret;
    size_t len;

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
        return( JHD_TLS_ERR_PK_INVALID_PUBKEY + ret );

    if( *p + len != end )
        return( JHD_TLS_ERR_PK_INVALID_PUBKEY +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

    /* Import N */
    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len, JHD_TLS_ASN1_INTEGER ) ) != 0 )
        return( JHD_TLS_ERR_PK_INVALID_PUBKEY + ret );

    if( ( ret = jhd_tls_rsa_import_raw( rsa, *p, len, NULL, 0, NULL, 0,
                                        NULL, 0, NULL, 0 ) ) != 0 )
        return( JHD_TLS_ERR_PK_INVALID_PUBKEY );

    *p += len;

    /* Import E */
    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len, JHD_TLS_ASN1_INTEGER ) ) != 0 )
        return( JHD_TLS_ERR_PK_INVALID_PUBKEY + ret );

    if( ( ret = jhd_tls_rsa_import_raw( rsa, NULL, 0, NULL, 0, NULL, 0,
                                        NULL, 0, *p, len ) ) != 0 )
        return( JHD_TLS_ERR_PK_INVALID_PUBKEY );

    *p += len;

    if( jhd_tls_rsa_complete( rsa ) != 0 ||
        jhd_tls_rsa_check_pubkey( rsa ) != 0 )
    {
        return( JHD_TLS_ERR_PK_INVALID_PUBKEY );
    }

    if( *p != end )
        return( JHD_TLS_ERR_PK_INVALID_PUBKEY +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}
#endif /* JHD_TLS_RSA_C */

/* Get a PK algorithm identifier
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
static int pk_get_pk_alg( unsigned char **p,
                          const unsigned char *end,
                          jhd_tls_pk_type_t *pk_alg, jhd_tls_asn1_buf *params )
{
    int ret;
    jhd_tls_asn1_buf alg_oid;

    memset( params, 0, sizeof(jhd_tls_asn1_buf) );

    if( ( ret = jhd_tls_asn1_get_alg( p, end, &alg_oid, params ) ) != 0 )
        return( JHD_TLS_ERR_PK_INVALID_ALG + ret );

    if( jhd_tls_oid_get_pk_alg( &alg_oid, pk_alg ) != 0 )
        return( JHD_TLS_ERR_PK_UNKNOWN_PK_ALG );

    /*
     * No parameters with RSA (only for EC)
     */
    if( *pk_alg == JHD_TLS_PK_RSA &&
            ( ( params->tag != JHD_TLS_ASN1_NULL && params->tag != 0 ) ||
                params->len != 0 ) )
    {
        return( JHD_TLS_ERR_PK_INVALID_ALG );
    }

    return( 0 );
}

/*
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING }
 */
int jhd_tls_pk_parse_subpubkey( unsigned char **p, const unsigned char *end,
                        jhd_tls_pk_context *pk )
{
    int ret;
    size_t len;
    jhd_tls_asn1_buf alg_params;
    jhd_tls_pk_type_t pk_alg = JHD_TLS_PK_NONE;
    const jhd_tls_pk_info_t *pk_info;

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len,
                    JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = *p + len;

    if( ( ret = pk_get_pk_alg( p, end, &pk_alg, &alg_params ) ) != 0 )
        return( ret );

    if( ( ret = jhd_tls_asn1_get_bitstring_null( p, end, &len ) ) != 0 )
        return( JHD_TLS_ERR_PK_INVALID_PUBKEY + ret );

    if( *p + len != end )
        return( JHD_TLS_ERR_PK_INVALID_PUBKEY +
                JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

    if( ( pk_info = jhd_tls_pk_info_from_type( pk_alg ) ) == NULL )
        return( JHD_TLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = jhd_tls_pk_setup( pk, pk_info ) ) != 0 )
        return( ret );

#if defined(JHD_TLS_RSA_C)
    if( pk_alg == JHD_TLS_PK_RSA )
    {
        ret = pk_get_rsapubkey( p, end, jhd_tls_pk_rsa( *pk ) );
    } else
#endif /* JHD_TLS_RSA_C */
#if defined(JHD_TLS_ECP_C)
    if( pk_alg == JHD_TLS_PK_ECKEY_DH || pk_alg == JHD_TLS_PK_ECKEY )
    {
        ret = pk_use_ecparams( &alg_params, &jhd_tls_pk_ec( *pk )->grp );
        if( ret == 0 )
            ret = pk_get_ecpubkey( p, end, jhd_tls_pk_ec( *pk ) );
    } else
#endif /* JHD_TLS_ECP_C */
        ret = JHD_TLS_ERR_PK_UNKNOWN_PK_ALG;

    if( ret == 0 && *p != end )
        ret = JHD_TLS_ERR_PK_INVALID_PUBKEY
              JHD_TLS_ERR_ASN1_LENGTH_MISMATCH;

    if( ret != 0 )
        jhd_tls_pk_free( pk );

    return( ret );
}

#if defined(JHD_TLS_RSA_C)
/*
 * Parse a PKCS#1 encoded private RSA key
 */
static int pk_parse_key_pkcs1_der( jhd_tls_rsa_context *rsa,
                                   const unsigned char *key,
                                   size_t keylen )
{
    int ret, version;
    size_t len;
    unsigned char *p, *end;

    jhd_tls_mpi T;
    jhd_tls_mpi_init( &T );

    p = (unsigned char *) key;
    end = p + keylen;

    /*
     * This function parses the RSAPrivateKey (PKCS#1)
     *
     *  RSAPrivateKey ::= SEQUENCE {
     *      version           Version,
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER,  -- e
     *      privateExponent   INTEGER,  -- d
     *      prime1            INTEGER,  -- p
     *      prime2            INTEGER,  -- q
     *      exponent1         INTEGER,  -- d mod (p-1)
     *      exponent2         INTEGER,  -- d mod (q-1)
     *      coefficient       INTEGER,  -- (inverse of q) mod p
     *      otherPrimeInfos   OtherPrimeInfos OPTIONAL
     *  }
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = jhd_tls_asn1_get_int( &p, end, &version ) ) != 0 )
    {
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    if( version != 0 )
    {
        return( JHD_TLS_ERR_PK_KEY_INVALID_VERSION );
    }

    /* Import N */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                                      JHD_TLS_ASN1_INTEGER ) ) != 0 ||
        ( ret = jhd_tls_rsa_import_raw( rsa, p, len, NULL, 0, NULL, 0,
                                        NULL, 0, NULL, 0 ) ) != 0 )
        goto cleanup;
    p += len;

    /* Import E */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                                      JHD_TLS_ASN1_INTEGER ) ) != 0 ||
        ( ret = jhd_tls_rsa_import_raw( rsa, NULL, 0, NULL, 0, NULL, 0,
                                        NULL, 0, p, len ) ) != 0 )
        goto cleanup;
    p += len;

    /* Import D */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                                      JHD_TLS_ASN1_INTEGER ) ) != 0 ||
        ( ret = jhd_tls_rsa_import_raw( rsa, NULL, 0, NULL, 0, NULL, 0,
                                        p, len, NULL, 0 ) ) != 0 )
        goto cleanup;
    p += len;

    /* Import P */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                                      JHD_TLS_ASN1_INTEGER ) ) != 0 ||
        ( ret = jhd_tls_rsa_import_raw( rsa, NULL, 0, p, len, NULL, 0,
                                        NULL, 0, NULL, 0 ) ) != 0 )
        goto cleanup;
    p += len;

    /* Import Q */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                                      JHD_TLS_ASN1_INTEGER ) ) != 0 ||
        ( ret = jhd_tls_rsa_import_raw( rsa, NULL, 0, NULL, 0, p, len,
                                        NULL, 0, NULL, 0 ) ) != 0 )
        goto cleanup;
    p += len;

    /* Complete the RSA private key */
    if( ( ret = jhd_tls_rsa_complete( rsa ) ) != 0 )
        goto cleanup;

    /* Check optional parameters */
    if( ( ret = jhd_tls_asn1_get_mpi( &p, end, &T ) ) != 0 ||
        ( ret = jhd_tls_asn1_get_mpi( &p, end, &T ) ) != 0 ||
        ( ret = jhd_tls_asn1_get_mpi( &p, end, &T ) ) != 0 )
        goto cleanup;

    if( p != end )
    {
        ret = JHD_TLS_ERR_PK_KEY_INVALID_FORMAT +
              JHD_TLS_ERR_ASN1_LENGTH_MISMATCH ;
    }

cleanup:

    jhd_tls_mpi_free( &T );

    if( ret != 0 )
    {
        /* Wrap error code if it's coming from a lower level */
        if( ( ret & 0xff80 ) == 0 )
            ret = JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret;
        else
            ret = JHD_TLS_ERR_PK_KEY_INVALID_FORMAT;

        jhd_tls_rsa_free( rsa );
    }

    return( ret );
}
#endif /* JHD_TLS_RSA_C */

#if defined(JHD_TLS_ECP_C)
/*
 * Parse a SEC1 encoded private EC key
 */
static int pk_parse_key_sec1_der( jhd_tls_ecp_keypair *eck,
                                  const unsigned char *key,
                                  size_t keylen )
{
    int ret;
    int version, pubkey_done;
    size_t len;
    jhd_tls_asn1_buf params;
    unsigned char *p = (unsigned char *) key;
    unsigned char *end = p + keylen;
    unsigned char *end2;

    /*
     * RFC 5915, or SEC1 Appendix C.4
     *
     * ECPrivateKey ::= SEQUENCE {
     *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *      privateKey     OCTET STRING,
     *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     *      publicKey  [1] BIT STRING OPTIONAL
     *    }
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = jhd_tls_asn1_get_int( &p, end, &version ) ) != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( version != 1 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_VERSION );

    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len, JHD_TLS_ASN1_OCTET_STRING ) ) != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ( ret = jhd_tls_mpi_read_binary( &eck->d, p, len ) ) != 0 )
    {
        jhd_tls_ecp_keypair_free( eck );
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    p += len;

    pubkey_done = 0;
    if( p != end )
    {
        /*
         * Is 'parameters' present?
         */
        if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                        JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | 0 ) ) == 0 )
        {
            if( ( ret = pk_get_ecparams( &p, p + len, &params) ) != 0 ||
                ( ret = pk_use_ecparams( &params, &eck->grp )  ) != 0 )
            {
                jhd_tls_ecp_keypair_free( eck );
                return( ret );
            }
        }
        else if( ret != JHD_TLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            jhd_tls_ecp_keypair_free( eck );
            return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
        }
    }

    if( p != end )
    {
        /*
         * Is 'publickey' present? If not, or if we can't read it (eg because it
         * is compressed), create it from the private key.
         */
        if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                        JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | 1 ) ) == 0 )
        {
            end2 = p + len;

            if( ( ret = jhd_tls_asn1_get_bitstring_null( &p, end2, &len ) ) != 0 )
                return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

            if( p + len != end2 )
                return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT +
                        JHD_TLS_ERR_ASN1_LENGTH_MISMATCH );

            if( ( ret = pk_get_ecpubkey( &p, end2, eck ) ) == 0 )
                pubkey_done = 1;
            else
            {
                /*
                 * The only acceptable failure mode of pk_get_ecpubkey() above
                 * is if the point format is not recognized.
                 */
                if( ret != JHD_TLS_ERR_ECP_FEATURE_UNAVAILABLE )
                    return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT );
            }
        }
        else if( ret != JHD_TLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            jhd_tls_ecp_keypair_free( eck );
            return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
        }
    }

    if( ! pubkey_done &&
        ( ret = jhd_tls_ecp_mul( &eck->grp, &eck->Q, &eck->d, &eck->grp.G,
                                                      NULL, NULL ) ) != 0 )
    {
        jhd_tls_ecp_keypair_free( eck );
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    if( ( ret = jhd_tls_ecp_check_privkey( &eck->grp, &eck->d ) ) != 0 )
    {
        jhd_tls_ecp_keypair_free( eck );
        return( ret );
    }

    return( 0 );
}
#endif /* JHD_TLS_ECP_C */

/*
 * Parse an unencrypted PKCS#8 encoded private key
 *
 * Notes:
 *
 * - This function does not own the key buffer. It is the
 *   responsibility of the caller to take care of zeroizing
 *   and freeing it after use.
 *
 * - The function is responsible for freeing the provided
 *   PK context on failure.
 *
 */
static int pk_parse_key_pkcs8_unencrypted_der(
                                    jhd_tls_pk_context *pk,
                                    const unsigned char* key,
                                    size_t keylen )
{
    int ret, version;
    size_t len;
    jhd_tls_asn1_buf params;
    unsigned char *p = (unsigned char *) key;
    unsigned char *end = p + keylen;
    jhd_tls_pk_type_t pk_alg = JHD_TLS_PK_NONE;
    const jhd_tls_pk_info_t *pk_info;

    /*
     * This function parses the PrivateKeyInfo object (PKCS#8 v1.2 = RFC 5208)
     *
     *    PrivateKeyInfo ::= SEQUENCE {
     *      version                   Version,
     *      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
     *      privateKey                PrivateKey,
     *      attributes           [0]  IMPLICIT Attributes OPTIONAL }
     *
     *    Version ::= INTEGER
     *    PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     *    PrivateKey ::= OCTET STRING
     *
     *  The PrivateKey OCTET STRING is a SEC1 ECPrivateKey
     */

    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = jhd_tls_asn1_get_int( &p, end, &version ) ) != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( version != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_VERSION + ret );

    if( ( ret = pk_get_pk_alg( &p, end, &pk_alg, &params ) ) != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len, JHD_TLS_ASN1_OCTET_STRING ) ) != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( len < 1 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT +
                JHD_TLS_ERR_ASN1_OUT_OF_DATA );

    if( ( pk_info = jhd_tls_pk_info_from_type( pk_alg ) ) == NULL )
        return( JHD_TLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = jhd_tls_pk_setup( pk, pk_info ) ) != 0 )
        return( ret );

#if defined(JHD_TLS_RSA_C)
    if( pk_alg == JHD_TLS_PK_RSA )
    {
        if( ( ret = pk_parse_key_pkcs1_der( jhd_tls_pk_rsa( *pk ), p, len ) ) != 0 )
        {
            jhd_tls_pk_free( pk );
            return( ret );
        }
    } else
#endif /* JHD_TLS_RSA_C */
#if defined(JHD_TLS_ECP_C)
    if( pk_alg == JHD_TLS_PK_ECKEY || pk_alg == JHD_TLS_PK_ECKEY_DH )
    {
        if( ( ret = pk_use_ecparams( &params, &jhd_tls_pk_ec( *pk )->grp ) ) != 0 ||
            ( ret = pk_parse_key_sec1_der( jhd_tls_pk_ec( *pk ), p, len )  ) != 0 )
        {
            jhd_tls_pk_free( pk );
            return( ret );
        }
    } else
#endif /* JHD_TLS_ECP_C */
        return( JHD_TLS_ERR_PK_UNKNOWN_PK_ALG );

    return( 0 );
}

/*
 * Parse an encrypted PKCS#8 encoded private key
 *
 * To save space, the decryption happens in-place on the given key buffer.
 * Also, while this function may modify the keybuffer, it doesn't own it,
 * and instead it is the responsibility of the caller to zeroize and properly
 * free it after use.
 *
 */
#if defined(JHD_TLS_PKCS12_C) || defined(JHD_TLS_PKCS5_C)
static int pk_parse_key_pkcs8_encrypted_der(
                                    jhd_tls_pk_context *pk,
                                    unsigned char *key, size_t keylen,
                                    const unsigned char *pwd, size_t pwdlen )
{
    int ret, decrypted = 0;
    size_t len;
    unsigned char *buf;
    unsigned char *p, *end;
    jhd_tls_asn1_buf pbe_alg_oid, pbe_params;
#if defined(JHD_TLS_PKCS12_C)
    jhd_tls_cipher_type_t cipher_alg;
    jhd_tls_md_type_t md_alg;
#endif

    p = key;
    end = p + keylen;

    if( pwdlen == 0 )
        return( JHD_TLS_ERR_PK_PASSWORD_REQUIRED );

    /*
     * This function parses the EncryptedPrivateKeyInfo object (PKCS#8)
     *
     *  EncryptedPrivateKeyInfo ::= SEQUENCE {
     *    encryptionAlgorithm  EncryptionAlgorithmIdentifier,
     *    encryptedData        EncryptedData
     *  }
     *
     *  EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
     *
     *  EncryptedData ::= OCTET STRING
     *
     *  The EncryptedData OCTET STRING is a PKCS#8 PrivateKeyInfo
     *
     */
    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
            JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = jhd_tls_asn1_get_alg( &p, end, &pbe_alg_oid, &pbe_params ) ) != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len, JHD_TLS_ASN1_OCTET_STRING ) ) != 0 )
        return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    buf = p;

    /*
     * Decrypt EncryptedData with appropriate PBE
     */
#if defined(JHD_TLS_PKCS12_C)
    if( jhd_tls_oid_get_pkcs12_pbe_alg( &pbe_alg_oid, &md_alg, &cipher_alg ) == 0 )
    {
        if( ( ret = jhd_tls_pkcs12_pbe( &pbe_params, JHD_TLS_PKCS12_PBE_DECRYPT,
                                cipher_alg, md_alg,
                                pwd, pwdlen, p, len, buf ) ) != 0 )
        {
            if( ret == JHD_TLS_ERR_PKCS12_PASSWORD_MISMATCH )
                return( JHD_TLS_ERR_PK_PASSWORD_MISMATCH );

            return( ret );
        }

        decrypted = 1;
    }
    else if( JHD_TLS_OID_CMP( JHD_TLS_OID_PKCS12_PBE_SHA1_RC4_128, &pbe_alg_oid ) == 0 )
    {
        if( ( ret = jhd_tls_pkcs12_pbe_sha1_rc4_128( &pbe_params,
                                             JHD_TLS_PKCS12_PBE_DECRYPT,
                                             pwd, pwdlen,
                                             p, len, buf ) ) != 0 )
        {
            return( ret );
        }

        // Best guess for password mismatch when using RC4. If first tag is
        // not JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE
        //
        if( *buf != ( JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) )
            return( JHD_TLS_ERR_PK_PASSWORD_MISMATCH );

        decrypted = 1;
    }
    else
#endif /* JHD_TLS_PKCS12_C */
#if defined(JHD_TLS_PKCS5_C)
    if( JHD_TLS_OID_CMP( JHD_TLS_OID_PKCS5_PBES2, &pbe_alg_oid ) == 0 )
    {
        if( ( ret = jhd_tls_pkcs5_pbes2( &pbe_params, JHD_TLS_PKCS5_DECRYPT, pwd, pwdlen,
                                  p, len, buf ) ) != 0 )
        {
            if( ret == JHD_TLS_ERR_PKCS5_PASSWORD_MISMATCH )
                return( JHD_TLS_ERR_PK_PASSWORD_MISMATCH );

            return( ret );
        }

        decrypted = 1;
    }
    else
#endif /* JHD_TLS_PKCS5_C */
    {
        ((void) pwd);
    }

    if( decrypted == 0 )
        return( JHD_TLS_ERR_PK_FEATURE_UNAVAILABLE );

    return( pk_parse_key_pkcs8_unencrypted_der( pk, buf, len ) );
}
#endif /* JHD_TLS_PKCS12_C || JHD_TLS_PKCS5_C */

/*
 * Parse a private key
 */
int jhd_tls_pk_parse_key( jhd_tls_pk_context *pk,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *pwd, size_t pwdlen )
{
    int ret;
    const jhd_tls_pk_info_t *pk_info;

#if defined(JHD_TLS_PEM_PARSE_C)
    size_t len;
    jhd_tls_pem_context pem;

    jhd_tls_pem_init( &pem );

#if defined(JHD_TLS_RSA_C)
    /* Avoid calling jhd_tls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = jhd_tls_pem_read_buffer( &pem,
                               "-----BEGIN RSA PRIVATE KEY-----",
                               "-----END RSA PRIVATE KEY-----",
                               key, pwd, pwdlen, &len );

    if( ret == 0 )
    {
        pk_info = jhd_tls_pk_info_from_type( JHD_TLS_PK_RSA );
        if( ( ret = jhd_tls_pk_setup( pk, pk_info ) ) != 0 ||
            ( ret = pk_parse_key_pkcs1_der( jhd_tls_pk_rsa( *pk ),
                                            pem.buf, pem.buflen ) ) != 0 )
        {
            jhd_tls_pk_free( pk );
        }

        jhd_tls_pem_free( &pem );
        return( ret );
    }
    else if( ret == JHD_TLS_ERR_PEM_PASSWORD_MISMATCH )
        return( JHD_TLS_ERR_PK_PASSWORD_MISMATCH );
    else if( ret == JHD_TLS_ERR_PEM_PASSWORD_REQUIRED )
        return( JHD_TLS_ERR_PK_PASSWORD_REQUIRED );
    else if( ret != JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );
#endif /* JHD_TLS_RSA_C */

#if defined(JHD_TLS_ECP_C)
    /* Avoid calling jhd_tls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = jhd_tls_pem_read_buffer( &pem,
                               "-----BEGIN EC PRIVATE KEY-----",
                               "-----END EC PRIVATE KEY-----",
                               key, pwd, pwdlen, &len );
    if( ret == 0 )
    {
        pk_info = jhd_tls_pk_info_from_type( JHD_TLS_PK_ECKEY );

        if( ( ret = jhd_tls_pk_setup( pk, pk_info ) ) != 0 ||
            ( ret = pk_parse_key_sec1_der( jhd_tls_pk_ec( *pk ),
                                           pem.buf, pem.buflen ) ) != 0 )
        {
            jhd_tls_pk_free( pk );
        }

        jhd_tls_pem_free( &pem );
        return( ret );
    }
    else if( ret == JHD_TLS_ERR_PEM_PASSWORD_MISMATCH )
        return( JHD_TLS_ERR_PK_PASSWORD_MISMATCH );
    else if( ret == JHD_TLS_ERR_PEM_PASSWORD_REQUIRED )
        return( JHD_TLS_ERR_PK_PASSWORD_REQUIRED );
    else if( ret != JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );
#endif /* JHD_TLS_ECP_C */

    /* Avoid calling jhd_tls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = jhd_tls_pem_read_buffer( &pem,
                               "-----BEGIN PRIVATE KEY-----",
                               "-----END PRIVATE KEY-----",
                               key, NULL, 0, &len );
    if( ret == 0 )
    {
        if( ( ret = pk_parse_key_pkcs8_unencrypted_der( pk,
                                                pem.buf, pem.buflen ) ) != 0 )
        {
            jhd_tls_pk_free( pk );
        }

        jhd_tls_pem_free( &pem );
        return( ret );
    }
    else if( ret != JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );

#if defined(JHD_TLS_PKCS12_C) || defined(JHD_TLS_PKCS5_C)
    /* Avoid calling jhd_tls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = jhd_tls_pem_read_buffer( &pem,
                               "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                               "-----END ENCRYPTED PRIVATE KEY-----",
                               key, NULL, 0, &len );
    if( ret == 0 )
    {
        if( ( ret = pk_parse_key_pkcs8_encrypted_der( pk,
                                                      pem.buf, pem.buflen,
                                                      pwd, pwdlen ) ) != 0 )
        {
            jhd_tls_pk_free( pk );
        }

        jhd_tls_pem_free( &pem );
        return( ret );
    }
    else if( ret != JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );
#endif /* JHD_TLS_PKCS12_C || JHD_TLS_PKCS5_C */
#else
    ((void) ret);
    ((void) pwd);
    ((void) pwdlen);
#endif /* JHD_TLS_PEM_PARSE_C */

    /*
     * At this point we only know it's not a PEM formatted key. Could be any
     * of the known DER encoded private key formats
     *
     * We try the different DER format parsers to see if one passes without
     * error
     */
#if defined(JHD_TLS_PKCS12_C) || defined(JHD_TLS_PKCS5_C)
    {
        unsigned char *key_copy;

        if( keylen == 0 )
            return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT );

        if( ( key_copy = jhd_tls_calloc( 1, keylen ) ) == NULL )
            return( JHD_TLS_ERR_PK_ALLOC_FAILED );

        memcpy( key_copy, key, keylen );

        ret = pk_parse_key_pkcs8_encrypted_der( pk, key_copy, keylen,
                                                pwd, pwdlen );

        jhd_tls_platform_zeroize( key_copy, keylen );
        jhd_tls_free( key_copy );
    }

    if( ret == 0 )
        return( 0 );

    jhd_tls_pk_free( pk );

    if( ret == JHD_TLS_ERR_PK_PASSWORD_MISMATCH )
    {
        return( ret );
    }
#endif /* JHD_TLS_PKCS12_C || JHD_TLS_PKCS5_C */

    if( ( ret = pk_parse_key_pkcs8_unencrypted_der( pk, key, keylen ) ) == 0 )
        return( 0 );

    jhd_tls_pk_free( pk );

#if defined(JHD_TLS_RSA_C)

    pk_info = jhd_tls_pk_info_from_type( JHD_TLS_PK_RSA );
    if( ( ret = jhd_tls_pk_setup( pk, pk_info ) ) != 0 ||
        ( ret = pk_parse_key_pkcs1_der( jhd_tls_pk_rsa( *pk ),
                                        key, keylen ) ) != 0 )
    {
        jhd_tls_pk_free( pk );
    }
    else
    {
        return( 0 );
    }

#endif /* JHD_TLS_RSA_C */

#if defined(JHD_TLS_ECP_C)

    pk_info = jhd_tls_pk_info_from_type( JHD_TLS_PK_ECKEY );
    if( ( ret = jhd_tls_pk_setup( pk, pk_info ) ) != 0 ||
        ( ret = pk_parse_key_sec1_der( jhd_tls_pk_ec( *pk ),
                                       key, keylen ) ) != 0 )
    {
        jhd_tls_pk_free( pk );
    }
    else
    {
        return( 0 );
    }

#endif /* JHD_TLS_ECP_C */

    return( JHD_TLS_ERR_PK_KEY_INVALID_FORMAT );
}

/*
 * Parse a public key
 */
int jhd_tls_pk_parse_public_key( jhd_tls_pk_context *ctx,
                         const unsigned char *key, size_t keylen )
{
    int ret;
    unsigned char *p;
#if defined(JHD_TLS_RSA_C)
    const jhd_tls_pk_info_t *pk_info;
#endif
#if defined(JHD_TLS_PEM_PARSE_C)
    size_t len;
    jhd_tls_pem_context pem;

    jhd_tls_pem_init( &pem );
#if defined(JHD_TLS_RSA_C)
    /* Avoid calling jhd_tls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = jhd_tls_pem_read_buffer( &pem,
                               "-----BEGIN RSA PUBLIC KEY-----",
                               "-----END RSA PUBLIC KEY-----",
                               key, NULL, 0, &len );

    if( ret == 0 )
    {
        p = pem.buf;
        if( ( pk_info = jhd_tls_pk_info_from_type( JHD_TLS_PK_RSA ) ) == NULL )
            return( JHD_TLS_ERR_PK_UNKNOWN_PK_ALG );

        if( ( ret = jhd_tls_pk_setup( ctx, pk_info ) ) != 0 )
            return( ret );

        if ( ( ret = pk_get_rsapubkey( &p, p + pem.buflen, jhd_tls_pk_rsa( *ctx ) ) ) != 0 )
            jhd_tls_pk_free( ctx );

        jhd_tls_pem_free( &pem );
        return( ret );
    }
    else if( ret != JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
    {
        jhd_tls_pem_free( &pem );
        return( ret );
    }
#endif /* JHD_TLS_RSA_C */

    /* Avoid calling jhd_tls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = jhd_tls_pem_read_buffer( &pem,
                "-----BEGIN PUBLIC KEY-----",
                "-----END PUBLIC KEY-----",
                key, NULL, 0, &len );

    if( ret == 0 )
    {
        /*
         * Was PEM encoded
         */
        p = pem.buf;

        ret = jhd_tls_pk_parse_subpubkey( &p,  p + pem.buflen, ctx );
        jhd_tls_pem_free( &pem );
        return( ret );
    }
    else if( ret != JHD_TLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
    {
        jhd_tls_pem_free( &pem );
        return( ret );
    }
    jhd_tls_pem_free( &pem );
#endif /* JHD_TLS_PEM_PARSE_C */

#if defined(JHD_TLS_RSA_C)
    if( ( pk_info = jhd_tls_pk_info_from_type( JHD_TLS_PK_RSA ) ) == NULL )
        return( JHD_TLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = jhd_tls_pk_setup( ctx, pk_info ) ) != 0 )
        return( ret );

    p = (unsigned char *)key;
    ret = pk_get_rsapubkey( &p, p + keylen, jhd_tls_pk_rsa( *ctx ) );
    if( ret == 0 )
    {
        return( ret );
    }
    jhd_tls_pk_free( ctx );
    if( ret != ( JHD_TLS_ERR_PK_INVALID_PUBKEY + JHD_TLS_ERR_ASN1_UNEXPECTED_TAG ) )
    {
        return( ret );
    }
#endif /* JHD_TLS_RSA_C */
    p = (unsigned char *) key;

    ret = jhd_tls_pk_parse_subpubkey( &p, p + keylen, ctx );

    return( ret );
}

#endif /* JHD_TLS_PK_PARSE_C */
