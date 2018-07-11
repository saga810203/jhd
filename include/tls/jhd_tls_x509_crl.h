/**
 * \file x509_crl.h
 *
 * \brief X.509 certificate revocation list parsing
 */
/*
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
#ifndef JHD_TLS_X509_CRL_H
#define JHD_TLS_X509_CRL_H

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#include <tls/jhd_tls_x509.h>



/**
 * \addtogroup x509_module
 * \{ */

/**
 * \name Structures and functions for parsing CRLs
 * \{
 */

/**
 * Certificate revocation list entry.
 * Contains the CA-specific serial numbers and revocation dates.
 */
typedef struct jhd_tls_x509_crl_entry
{
    jhd_tls_x509_buf raw;

    jhd_tls_x509_buf serial;

    jhd_tls_x509_time revocation_date;

    jhd_tls_x509_buf entry_ext;

    struct jhd_tls_x509_crl_entry *next;
}
jhd_tls_x509_crl_entry;

/**
 * Certificate revocation list structure.
 * Every CRL may have multiple entries.
 */
typedef struct jhd_tls_x509_crl
{
    jhd_tls_x509_buf raw;           /**< The raw certificate data (DER). */
    jhd_tls_x509_buf tbs;           /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;            /**< CRL version (1=v1, 2=v2) */
    jhd_tls_x509_buf sig_oid;       /**< CRL signature type identifier */

    jhd_tls_x509_buf issuer_raw;    /**< The raw issuer data (DER). */

    jhd_tls_x509_name issuer;       /**< The parsed issuer data (named information object). */

    jhd_tls_x509_time this_update;
    jhd_tls_x509_time next_update;

    jhd_tls_x509_crl_entry entry;   /**< The CRL entries containing the certificate revocation times for this CA. */

    jhd_tls_x509_buf crl_ext;

    jhd_tls_x509_buf sig_oid2;
    jhd_tls_x509_buf sig;
    jhd_tls_md_type_t sig_md;           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. JHD_TLS_MD_SHA256 */
    jhd_tls_pk_type_t sig_pk;           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. JHD_TLS_PK_RSA */
    void *sig_opts;             /**< Signature options to be passed to jhd_tls_pk_verify_ext(), e.g. for RSASSA-PSS */

    struct jhd_tls_x509_crl *next;
}
jhd_tls_x509_crl;

/**
 * \brief          Parse a DER-encoded CRL and append it to the chained list
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the CRL data in DER format
 * \param buflen   size of the buffer
 *                 (including the terminating null byte for PEM data)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int jhd_tls_x509_crl_parse_der( jhd_tls_x509_crl *chain,
                        const unsigned char *buf, size_t buflen );
/**
 * \brief          Parse one or more CRLs and append them to the chained list
 *
 * \note           Mutliple CRLs are accepted only if using PEM format
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the CRL data in PEM or DER format
 * \param buflen   size of the buffer
 *                 (including the terminating null byte for PEM data)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int jhd_tls_x509_crl_parse( jhd_tls_x509_crl *chain, const unsigned char *buf, size_t buflen );

#if defined(JHD_TLS_FS_IO)
/**
 * \brief          Load one or more CRLs and append them to the chained list
 *
 * \note           Mutliple CRLs are accepted only if using PEM format
 *
 * \param chain    points to the start of the chain
 * \param path     filename to read the CRLs from (in PEM or DER encoding)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int jhd_tls_x509_crl_parse_file( jhd_tls_x509_crl *chain, const char *path );
#endif /* JHD_TLS_FS_IO */

/**
 * \brief          Returns an informational string about the CRL.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param crl      The X509 CRL to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int jhd_tls_x509_crl_info( char *buf, size_t size, const char *prefix,
                   const jhd_tls_x509_crl *crl );

/**
 * \brief          Initialize a CRL (chain)
 *
 * \param crl      CRL chain to initialize
 */
void jhd_tls_x509_crl_init( jhd_tls_x509_crl *crl );

/**
 * \brief          Unallocate all CRL data
 *
 * \param crl      CRL chain to free
 */
void jhd_tls_x509_crl_free( jhd_tls_x509_crl *crl );

/* \} name */
/* \} addtogroup x509_module */



#endif /* jhd_tls_x509_crl.h */
