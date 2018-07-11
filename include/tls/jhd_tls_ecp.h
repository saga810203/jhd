/**
 * \file ecp.h
 *
 * \brief This file provides an API for Elliptic Curves over GF(P) (ECP).
 *
 * The use of ECP in cryptography and TLS is defined in
 * <em>Standards for Efficient Cryptography Group (SECG): SEC1
 * Elliptic Curve Cryptography</em> and
 * <em>RFC-4492: Elliptic Curve Cryptography (ECC) Cipher Suites
 * for Transport Layer Security (TLS)</em>.
 *
 * <em>RFC-2409: The Internet Key Exchange (IKE)</em> defines ECP
 * group types.
 *
 */

/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef JHD_TLS_ECP_H
#define JHD_TLS_ECP_H

#include <tls/jhd_tls_bignum.h>

/*
 * ECP error codes
 */
#define JHD_TLS_ERR_ECP_BAD_INPUT_DATA                    -0x4F80  /**< Bad input parameters to function. */
#define JHD_TLS_ERR_ECP_BUFFER_TOO_SMALL                  -0x4F00  /**< The buffer is too small to write to. */
#define JHD_TLS_ERR_ECP_FEATURE_UNAVAILABLE               -0x4E80  /**< The requested feature is not available, for example, the requested curve is not supported. */
#define JHD_TLS_ERR_ECP_VERIFY_FAILED                     -0x4E00  /**< The signature is not valid. */
#define JHD_TLS_ERR_ECP_ALLOC_FAILED                      -0x4D80  /**< Memory allocation failed. */
#define JHD_TLS_ERR_ECP_RANDOM_FAILED                     -0x4D00  /**< Generation of random value, such as ephemeral key, failed. */
#define JHD_TLS_ERR_ECP_INVALID_KEY                       -0x4C80  /**< Invalid private or public key. */
#define JHD_TLS_ERR_ECP_SIG_LEN_MISMATCH                  -0x4C00  /**< The buffer contains a valid signature followed by more data. */
#define JHD_TLS_ERR_ECP_HW_ACCEL_FAILED                   -0x4B80  /**< The ECP hardware accelerator failed. */



/**
 * Domain-parameter identifiers: curve, subgroup, and generator.
 *
 * \note Only curves over prime fields are supported.
 *
 * \warning This library does not support validation of arbitrary domain
 * parameters. Therefore, only standardized domain parameters from trusted
 * sources should be used. See jhd_tls_ecp_group_load().
 */
typedef enum
{
    JHD_TLS_ECP_DP_NONE = 0,       /*!< Curve not defined. */
    JHD_TLS_ECP_DP_SECP192R1,      /*!< Domain parameters for the 192-bit curve defined by FIPS 186-4 and SEC1. */
    JHD_TLS_ECP_DP_SECP224R1,      /*!< Domain parameters for the 224-bit curve defined by FIPS 186-4 and SEC1. */
    JHD_TLS_ECP_DP_SECP256R1,      /*!< Domain parameters for the 256-bit curve defined by FIPS 186-4 and SEC1. */
    JHD_TLS_ECP_DP_SECP384R1,      /*!< Domain parameters for the 384-bit curve defined by FIPS 186-4 and SEC1. */
    JHD_TLS_ECP_DP_SECP521R1,      /*!< Domain parameters for the 521-bit curve defined by FIPS 186-4 and SEC1. */
    JHD_TLS_ECP_DP_BP256R1,        /*!< Domain parameters for 256-bit Brainpool curve. */
    JHD_TLS_ECP_DP_BP384R1,        /*!< Domain parameters for 384-bit Brainpool curve. */
    JHD_TLS_ECP_DP_BP512R1,        /*!< Domain parameters for 512-bit Brainpool curve. */
    JHD_TLS_ECP_DP_CURVE25519,     /*!< Domain parameters for Curve25519. */
    JHD_TLS_ECP_DP_SECP192K1,      /*!< Domain parameters for 192-bit "Koblitz" curve. */
    JHD_TLS_ECP_DP_SECP224K1,      /*!< Domain parameters for 224-bit "Koblitz" curve. */
    JHD_TLS_ECP_DP_SECP256K1,      /*!< Domain parameters for 256-bit "Koblitz" curve. */
    JHD_TLS_ECP_DP_CURVE448,       /*!< Domain parameters for Curve448. */
} jhd_tls_ecp_group_id;

/**
 * The number of supported curves, plus one for #JHD_TLS_ECP_DP_NONE.
 *
 * \note Montgomery curves are currently excluded.
 */
#define JHD_TLS_ECP_DP_MAX     12

/**
 * Curve information, for use by other modules.
 */
typedef struct
{
    jhd_tls_ecp_group_id grp_id;    /*!< An internal identifier. */
    uint16_t tls_id;                /*!< The TLS NamedCurve identifier. */
    uint16_t bit_size;              /*!< The curve size in bits. */
    const char *name;               /*!< A human-friendly name. */
} jhd_tls_ecp_curve_info;

/**
 * \brief           The ECP point structure, in Jacobian coordinates.
 *
 * \note            All functions expect and return points satisfying
 *                  the following condition: <code>Z == 0</code> or
 *                  <code>Z == 1</code>. Other values of \p Z are
 *                  used only by internal functions.
 *                  The point is zero, or "at infinity", if <code>Z == 0</code>.
 *                  Otherwise, \p X and \p Y are its standard (affine)
 *                  coordinates.
 */
typedef struct
{
    jhd_tls_mpi X;          /*!< The X coordinate of the ECP point. */
    jhd_tls_mpi Y;          /*!< The Y coordinate of the ECP point. */
    jhd_tls_mpi Z;          /*!< The Z coordinate of the ECP point. */
}
jhd_tls_ecp_point;

#if !defined(JHD_TLS_ECP_ALT)
/*
 * default mbed TLS elliptic curve arithmetic implementation
 *
 * (in case JHD_TLS_ECP_ALT is defined then the developer has to provide an
 * alternative implementation for the whole module and it will replace this
 * one.)
 */

/**
 * \brief           The ECP group structure.
 *
 * We consider two types of curve equations:
 * <ul><li>Short Weierstrass: <code>y^2 = x^3 + A x + B mod P</code>
 * (SEC1 + RFC-4492)</li>
 * <li>Montgomery: <code>y^2 = x^3 + A x^2 + x mod P</code> (Curve25519,
 * Curve448)</li></ul>
 * In both cases, the generator (\p G) for a prime-order subgroup is fixed.
 *
 * For Short Weierstrass, this subgroup is the whole curve, and its
 * cardinality is denoted by \p N. Our code requires that \p N is an
 * odd prime as jhd_tls_ecp_mul() requires an odd number, and
 * jhd_tls_ecdsa_sign() requires that it is prime for blinding purposes.
 *
 * For Montgomery curves, we do not store \p A, but <code>(A + 2) / 4</code>,
 * which is the quantity used in the formulas. Additionally, \p nbits is
 * not the size of \p N but the required size for private keys.
 *
 * If \p modp is NULL, reduction modulo \p P is done using a generic algorithm.
 * Otherwise, \p modp must point to a function that takes an \p jhd_tls_mpi in the
 * range of <code>0..2^(2*pbits)-1</code>, and transforms it in-place to an integer
 * which is congruent mod \p P to the given MPI, and is close enough to \p pbits
 * in size, so that it may be efficiently brought in the 0..P-1 range by a few
 * additions or subtractions. Therefore, it is only an approximative modular
 * reduction. It must return 0 on success and non-zero on failure.
 *
 */
typedef struct
{
    jhd_tls_ecp_group_id id;    /*!< An internal group identifier. */
    jhd_tls_mpi P;              /*!< The prime modulus of the base field. */
    jhd_tls_mpi A;              /*!< For Short Weierstrass: \p A in the equation. For
                                     Montgomery curves: <code>(A + 2) / 4</code>. */
    jhd_tls_mpi B;              /*!< For Short Weierstrass: \p B in the equation.
                                     For Montgomery curves: unused. */
    jhd_tls_ecp_point G;        /*!< The generator of the subgroup used. */
    jhd_tls_mpi N;              /*!< The order of \p G. */
    size_t pbits;               /*!< The number of bits in \p P.*/
    size_t nbits;               /*!< For Short Weierstrass: The number of bits in \p P.
                                     For Montgomery curves: the number of bits in the
                                     private keys. */
    unsigned int h;             /*!< \internal 1 if the constants are static. */
    int (*modp)(jhd_tls_mpi *); /*!< The function for fast pseudo-reduction
                                     mod \p P (see above).*/
    int (*t_pre)(jhd_tls_ecp_point *, void *);  /*!< Unused. */
    int (*t_post)(jhd_tls_ecp_point *, void *); /*!< Unused. */
    void *t_data;               /*!< Unused. */
    jhd_tls_ecp_point *T;       /*!< Pre-computed points for ecp_mul_comb(). */
    size_t T_size;              /*!< The number of pre-computed points. */
}
jhd_tls_ecp_group;

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h, or define them using the compiler command line.
 * \{
 */

#if !defined(JHD_TLS_ECP_MAX_BITS)
/**
 * The maximum size of the groups, that is, of \c N and \c P.
 */
#define JHD_TLS_ECP_MAX_BITS     521   /**< The maximum size of groups, in bits. */
#endif

#define JHD_TLS_ECP_MAX_BYTES    ( ( JHD_TLS_ECP_MAX_BITS + 7 ) / 8 )
#define JHD_TLS_ECP_MAX_PT_LEN   ( 2 * JHD_TLS_ECP_MAX_BYTES + 1 )

#if !defined(JHD_TLS_ECP_WINDOW_SIZE)
/*
 * Maximum "window" size used for point multiplication.
 * Default: 6.
 * Minimum value: 2. Maximum value: 7.
 *
 * Result is an array of at most ( 1 << ( JHD_TLS_ECP_WINDOW_SIZE - 1 ) )
 * points used for point multiplication. This value is directly tied to EC
 * peak memory usage, so decreasing it by one should roughly cut memory usage
 * by two (if large curves are in use).
 *
 * Reduction in size may reduce speed, but larger curves are impacted first.
 * Sample performances (in ECDHE handshakes/s, with FIXED_POINT_OPTIM = 1):
 *      w-size:     6       5       4       3       2
 *      521       145     141     135     120      97
 *      384       214     209     198     177     146
 *      256       320     320     303     262     226
 *      224       475     475     453     398     342
 *      192       640     640     633     587     476
 */
#define JHD_TLS_ECP_WINDOW_SIZE    6   /**< The maximum window size used. */
#endif /* JHD_TLS_ECP_WINDOW_SIZE */

#if !defined(JHD_TLS_ECP_FIXED_POINT_OPTIM)
/*
 * Trade memory for speed on fixed-point multiplication.
 *
 * This speeds up repeated multiplication of the generator (that is, the
 * multiplication in ECDSA signatures, and half of the multiplications in
 * ECDSA verification and ECDHE) by a factor roughly 3 to 4.
 *
 * The cost is increasing EC peak memory usage by a factor roughly 2.
 *
 * Change this value to 0 to reduce peak memory usage.
 */
#define JHD_TLS_ECP_FIXED_POINT_OPTIM  1   /**< Enable fixed-point speed-up. */
#endif /* JHD_TLS_ECP_FIXED_POINT_OPTIM */

/* \} name SECTION: Module settings */

#else  /* JHD_TLS_ECP_ALT */
#include "ecp_alt.h"
#endif /* JHD_TLS_ECP_ALT */

/**
 * \brief    The ECP key-pair structure.
 *
 * A generic key-pair that may be used for ECDSA and fixed ECDH, for example.
 *
 * \note    Members are deliberately in the same order as in the
 *          ::jhd_tls_ecdsa_context structure.
 */
typedef struct
{
    jhd_tls_ecp_group grp;      /*!<  Elliptic curve and base point     */
    jhd_tls_mpi d;              /*!<  our secret value                  */
    jhd_tls_ecp_point Q;        /*!<  our public value                  */
}
jhd_tls_ecp_keypair;

/*
 * Point formats, from RFC 4492's enum ECPointFormat
 */
#define JHD_TLS_ECP_PF_UNCOMPRESSED    0   /**< Uncompressed point format. */
#define JHD_TLS_ECP_PF_COMPRESSED      1   /**< Compressed point format. */

/*
 * Some other constants from RFC 4492
 */
#define JHD_TLS_ECP_TLS_NAMED_CURVE    3   /**< The named_curve of ECCurveType. */

/**
 * \brief           This function retrieves the information defined in
 *                  jhd_tls_ecp_curve_info() for all supported curves in order
 *                  of preference.
 *
 * \return          A statically allocated array. The last entry is 0.
 */
const jhd_tls_ecp_curve_info *jhd_tls_ecp_curve_list( void );

/**
 * \brief           This function retrieves the list of internal group
 *                  identifiers of all supported curves in the order of
 *                  preference.
 *
 * \return          A statically allocated array,
 *                  terminated with JHD_TLS_ECP_DP_NONE.
 */
const jhd_tls_ecp_group_id *jhd_tls_ecp_grp_id_list( void );

/**
 * \brief           This function retrieves curve information from an internal
 *                  group identifier.
 *
 * \param grp_id    An \c JHD_TLS_ECP_DP_XXX value.
 *
 * \return          The associated curve information on success.
 * \return          NULL on failure.
 */
const jhd_tls_ecp_curve_info *jhd_tls_ecp_curve_info_from_grp_id( jhd_tls_ecp_group_id grp_id );

/**
 * \brief           This function retrieves curve information from a TLS
 *                  NamedCurve value.
 *
 * \param tls_id    An \c JHD_TLS_ECP_DP_XXX value.
 *
 * \return          The associated curve information on success.
 * \return          NULL on failure.
 */
const jhd_tls_ecp_curve_info *jhd_tls_ecp_curve_info_from_tls_id( uint16_t tls_id );

/**
 * \brief           This function retrieves curve information from a
 *                  human-readable name.
 *
 * \param name      The human-readable name.
 *
 * \return          The associated curve information on success.
 * \return          NULL on failure.
 */
const jhd_tls_ecp_curve_info *jhd_tls_ecp_curve_info_from_name( const char *name );

/**
 * \brief           This function initializes a point as zero.
 *
 * \param pt        The point to initialize.
 */
void jhd_tls_ecp_point_init( jhd_tls_ecp_point *pt );

/**
 * \brief           This function initializes an ECP group context
 *                  without loading any domain parameters.
 *
 * \note            After this function is called, domain parameters
 *                  for various ECP groups can be loaded through the
 *                  jhd_tls_ecp_load() or jhd_tls_ecp_tls_read_group()
 *                  functions.
 */
void jhd_tls_ecp_group_init( jhd_tls_ecp_group *grp );

/**
 * \brief           This function initializes a key pair as an invalid one.
 *
 * \param key       The key pair to initialize.
 */
void jhd_tls_ecp_keypair_init( jhd_tls_ecp_keypair *key );

/**
 * \brief           This function frees the components of a point.
 *
 * \param pt        The point to free.
 */
void jhd_tls_ecp_point_free( jhd_tls_ecp_point *pt );

/**
 * \brief           This function frees the components of an ECP group.
 * \param grp       The group to free.
 */
void jhd_tls_ecp_group_free( jhd_tls_ecp_group *grp );

/**
 * \brief           This function frees the components of a key pair.
 * \param key       The key pair to free.
 */
void jhd_tls_ecp_keypair_free( jhd_tls_ecp_keypair *key );

/**
 * \brief           This function copies the contents of point \p Q into
 *                  point \p P.
 *
 * \param P         The destination point.
 * \param Q         The source point.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int jhd_tls_ecp_copy( jhd_tls_ecp_point *P, const jhd_tls_ecp_point *Q );

/**
 * \brief           This function copies the contents of group \p src into
 *                  group \p dst.
 *
 * \param dst       The destination group.
 * \param src       The source group.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int jhd_tls_ecp_group_copy( jhd_tls_ecp_group *dst, const jhd_tls_ecp_group *src );

/**
 * \brief           This function sets a point to zero.
 *
 * \param pt        The point to set.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int jhd_tls_ecp_set_zero( jhd_tls_ecp_point *pt );

/**
 * \brief           This function checks if a point is zero.
 *
 * \param pt        The point to test.
 *
 * \return          \c 1 if the point is zero.
 * \return          \c 0 if the point is non-zero.
 */
int jhd_tls_ecp_is_zero( jhd_tls_ecp_point *pt );

/**
 * \brief           This function compares two points.
 *
 * \note            This assumes that the points are normalized. Otherwise,
 *                  they may compare as "not equal" even if they are.
 *
 * \param P         The first point to compare.
 * \param Q         The second point to compare.
 *
 * \return          \c 0 if the points are equal.
 * \return          #JHD_TLS_ERR_ECP_BAD_INPUT_DATA if the points are not equal.
 */
int jhd_tls_ecp_point_cmp( const jhd_tls_ecp_point *P,
                           const jhd_tls_ecp_point *Q );

/**
 * \brief           This function imports a non-zero point from two ASCII
 *                  strings.
 *
 * \param P         The destination point.
 * \param radix     The numeric base of the input.
 * \param x         The first affine coordinate, as a null-terminated string.
 * \param y         The second affine coordinate, as a null-terminated string.
 *
 * \return          \c 0 on success.
 * \return          An \c JHD_TLS_ERR_MPI_XXX error code on failure.
 */
int jhd_tls_ecp_point_read_string( jhd_tls_ecp_point *P, int radix,
                           const char *x, const char *y );

/**
 * \brief           This function exports a point into unsigned binary data.
 *
 * \param grp       The group to which the point should belong.
 * \param P         The point to export.
 * \param format    The point format. Should be an \c JHD_TLS_ECP_PF_XXX macro.
 * \param olen      The length of the output.
 * \param buf       The output buffer.
 * \param buflen    The length of the output buffer.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_ECP_BAD_INPUT_DATA
 *                  or #JHD_TLS_ERR_ECP_BUFFER_TOO_SMALL on failure.
 */
int jhd_tls_ecp_point_write_binary( const jhd_tls_ecp_group *grp, const jhd_tls_ecp_point *P,
                            int format, size_t *olen,
                            unsigned char *buf, size_t buflen );

/**
 * \brief           This function imports a point from unsigned binary data.
 *
 * \note            This function does not check that the point actually
 *                  belongs to the given group, see jhd_tls_ecp_check_pubkey()
 *                  for that.
 *
 * \param grp       The group to which the point should belong.
 * \param P         The point to import.
 * \param buf       The input buffer.
 * \param ilen      The length of the input.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_ECP_BAD_INPUT_DATA if input is invalid.
 * \return          #JHD_TLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return          #JHD_TLS_ERR_ECP_FEATURE_UNAVAILABLE if the point format
 *                  is not implemented.
 *
 */
int jhd_tls_ecp_point_read_binary( const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *P,
                           const unsigned char *buf, size_t ilen );

/**
 * \brief           This function imports a point from a TLS ECPoint record.
 *
 * \note            On function return, \p buf is updated to point to immediately
 *                  after the ECPoint record.
 *
 * \param grp       The ECP group used.
 * \param pt        The destination point.
 * \param buf       The address of the pointer to the start of the input buffer.
 * \param len       The length of the buffer.
 *
 * \return          \c 0 on success.
 * \return          An \c JHD_TLS_ERR_MPI_XXX error code on initialization failure.
 * \return          #JHD_TLS_ERR_ECP_BAD_INPUT_DATA if input is invalid.
 */
int jhd_tls_ecp_tls_read_point( const jhd_tls_ecp_group *grp, jhd_tls_ecp_point *pt,
                        const unsigned char **buf, size_t len );

/**
 * \brief           This function exports a point as a TLS ECPoint record.
 *
 * \param grp       The ECP group used.
 * \param pt        The point format to export to. The point format is an
 *                  \c JHD_TLS_ECP_PF_XXX constant.
 * \param format    The export format.
 * \param olen      The length of the data written.
 * \param buf       The buffer to write to.
 * \param blen      The length of the buffer.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_ECP_BAD_INPUT_DATA or
 *                  #JHD_TLS_ERR_ECP_BUFFER_TOO_SMALL on failure.
 */
int jhd_tls_ecp_tls_write_point( const jhd_tls_ecp_group *grp, const jhd_tls_ecp_point *pt,
                         int format, size_t *olen,
                         unsigned char *buf, size_t blen );

/**
 * \brief           This function sets a group using standardized domain parameters.
 *
 * \note            The index should be a value of the NamedCurve enum,
 *                  as defined in <em>RFC-4492: Elliptic Curve Cryptography
 *                  (ECC) Cipher Suites for Transport Layer Security (TLS)</em>,
 *                  usually in the form of an \c JHD_TLS_ECP_DP_XXX macro.
 *
 * \param grp       The destination group.
 * \param id        The identifier of the domain parameter set to load.
 *
 * \return          \c 0 on success,
 * \return          An \c JHD_TLS_ERR_MPI_XXX error code on initialization failure.
 * \return          #JHD_TLS_ERR_ECP_FEATURE_UNAVAILABLE for unkownn groups.

 */
int jhd_tls_ecp_group_load( jhd_tls_ecp_group *grp, jhd_tls_ecp_group_id id );

/**
 * \brief           This function sets a group from a TLS ECParameters record.
 *
 * \note            \p buf is updated to point right after the ECParameters record
 *                  on exit.
 *
 * \param grp       The destination group.
 * \param buf       The address of the pointer to the start of the input buffer.
 * \param len       The length of the buffer.
 *
 * \return          \c 0 on success.
 * \return          An \c JHD_TLS_ERR_MPI_XXX error code on initialization failure.
 * \return          #JHD_TLS_ERR_ECP_BAD_INPUT_DATA if input is invalid.
 */
int jhd_tls_ecp_tls_read_group( jhd_tls_ecp_group *grp, const unsigned char **buf, size_t len );

/**
 * \brief           This function writes the TLS ECParameters record for a group.
 *
 * \param grp       The ECP group used.
 * \param olen      The number of Bytes written.
 * \param buf       The buffer to write to.
 * \param blen      The length of the buffer.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_ECP_BUFFER_TOO_SMALL on failure.
 */
int jhd_tls_ecp_tls_write_group( const jhd_tls_ecp_group *grp, size_t *olen,
                         unsigned char *buf, size_t blen );

/**
 * \brief           This function performs multiplication of a point by
 *                  an integer: \p R = \p m * \p P.
 *
 *                  It is not thread-safe to use same group in multiple threads.
 *
 * \note            To prevent timing attacks, this function
 *                  executes the exact same sequence of base-field
 *                  operations for any valid \p m. It avoids any if-branch or
 *                  array index depending on the value of \p m.
 *
 * \note            If \p f_rng is not NULL, it is used to randomize
 *                  intermediate results to prevent potential timing attacks
 *                  targeting these results. We recommend always providing
 *                  a non-NULL \p f_rng. The overhead is negligible.
 *
 * \param grp       The ECP group.
 * \param R         The destination point.
 * \param m         The integer by which to multiply.
 * \param P         The point to multiply.
 * \param f_rng     The RNG function.
 * \param p_rng     The RNG context.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_ECP_INVALID_KEY if \p m is not a valid private
 *                  key, or \p P is not a valid public key.
 * \return          #JHD_TLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int jhd_tls_ecp_mul( jhd_tls_ecp_group *grp, jhd_tls_ecp_point *R,
             const jhd_tls_mpi *m, const jhd_tls_ecp_point *P,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           This function performs multiplication and addition of two
 *                  points by integers: \p R = \p m * \p P + \p n * \p Q
 *
 *                  It is not thread-safe to use same group in multiple threads.
 *
 * \note            In contrast to jhd_tls_ecp_mul(), this function does not
 *                  guarantee a constant execution flow and timing.
 *
 * \param grp       The ECP group.
 * \param R         The destination point.
 * \param m         The integer by which to multiply \p P.
 * \param P         The point to multiply by \p m.
 * \param n         The integer by which to multiply \p Q.
 * \param Q         The point to be multiplied by \p n.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_ECP_INVALID_KEY if \p m or \p n are not
 *                  valid private keys, or \p P or \p Q are not valid public
 *                  keys.
 * \return          #JHD_TLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int jhd_tls_ecp_muladd( jhd_tls_ecp_group *grp, jhd_tls_ecp_point *R,
             const jhd_tls_mpi *m, const jhd_tls_ecp_point *P,
             const jhd_tls_mpi *n, const jhd_tls_ecp_point *Q );

/**
 * \brief           This function checks that a point is a valid public key
 *                  on this curve.
 *
 *                  It only checks that the point is non-zero, has
 *                  valid coordinates and lies on the curve. It does not verify
 *                  that it is indeed a multiple of \p G. This additional
 *                  check is computationally more expensive, is not required
 *                  by standards, and should not be necessary if the group
 *                  used has a small cofactor. In particular, it is useless for
 *                  the NIST groups which all have a cofactor of 1.
 *
 * \note            This function uses bare components rather than an
 *                  ::jhd_tls_ecp_keypair structure, to ease use with other
 *                  structures, such as ::jhd_tls_ecdh_context or
 *                  ::jhd_tls_ecdsa_context.
 *
 * \param grp       The curve the point should lie on.
 * \param pt        The point to check.
 *
 * \return          \c 0 if the point is a valid public key.
 * \return          #JHD_TLS_ERR_ECP_INVALID_KEY on failure.
 */
int jhd_tls_ecp_check_pubkey( const jhd_tls_ecp_group *grp, const jhd_tls_ecp_point *pt );

/**
 * \brief           This function checks that an \p jhd_tls_mpi is a valid private
 *                  key for this curve.
 *
 * \note            This function uses bare components rather than an
 *                  ::jhd_tls_ecp_keypair structure to ease use with other
 *                  structures, such as ::jhd_tls_ecdh_context or
 *                  ::jhd_tls_ecdsa_context.
 *
 * \param grp       The group used.
 * \param d         The integer to check.
 *
 * \return          \c 0 if the point is a valid private key.
 * \return          #JHD_TLS_ERR_ECP_INVALID_KEY on failure.
 */
int jhd_tls_ecp_check_privkey( const jhd_tls_ecp_group *grp, const jhd_tls_mpi *d );

/**
 * \brief           This function generates a keypair with a configurable base
 *                  point.
 *
 * \note            This function uses bare components rather than an
 *                  ::jhd_tls_ecp_keypair structure to ease use with other
 *                  structures, such as ::jhd_tls_ecdh_context or
 *                  ::jhd_tls_ecdsa_context.
 *
 * \param grp       The ECP group.
 * \param G         The chosen base point.
 * \param d         The destination MPI (secret part).
 * \param Q         The destination point (public part).
 * \param f_rng     The RNG function.
 * \param p_rng     The RNG context.
 *
 * \return          \c 0 on success.
 * \return          An \c JHD_TLS_ERR_ECP_XXX or \c JHD_TLS_MPI_XXX error code
 *                  on failure.
 */
int jhd_tls_ecp_gen_keypair_base( jhd_tls_ecp_group *grp,
                     const jhd_tls_ecp_point *G,
                     jhd_tls_mpi *d, jhd_tls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief           This function generates an ECP keypair.
 *
 * \note            This function uses bare components rather than an
 *                  ::jhd_tls_ecp_keypair structure to ease use with other
 *                  structures, such as ::jhd_tls_ecdh_context or
 *                  ::jhd_tls_ecdsa_context.
 *
 * \param grp       The ECP group.
 * \param d         The destination MPI (secret part).
 * \param Q         The destination point (public part).
 * \param f_rng     The RNG function.
 * \param p_rng     The RNG context.
 *
 * \return          \c 0 on success.
 * \return          An \c JHD_TLS_ERR_ECP_XXX or \c JHD_TLS_MPI_XXX error code
 *                  on failure.
 */
int jhd_tls_ecp_gen_keypair( jhd_tls_ecp_group *grp, jhd_tls_mpi *d, jhd_tls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief           This function generates an ECP key.
 *
 * \param grp_id    The ECP group identifier.
 * \param key       The destination key.
 * \param f_rng     The RNG function.
 * \param p_rng     The RNG context.
 *
 * \return          \c 0 on success.
 * \return          An \c JHD_TLS_ERR_ECP_XXX or \c JHD_TLS_MPI_XXX error code
 *                  on failure.
 */
int jhd_tls_ecp_gen_key( jhd_tls_ecp_group_id grp_id, jhd_tls_ecp_keypair *key,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           This function checks that the keypair objects
 *                  \p pub and \p prv have the same group and the
 *                  same public point, and that the private key in
 *                  \p prv is consistent with the public key.
 *
 * \param pub       The keypair structure holding the public key.
 *                  If it contains a private key, that part is ignored.
 * \param prv       The keypair structure holding the full keypair.
 *
 * \return          \c 0 on success, meaning that the keys are valid and match.
 * \return          #JHD_TLS_ERR_ECP_BAD_INPUT_DATA if the keys are invalid or do not match.
 * \return          An \c JHD_TLS_ERR_ECP_XXX or an \c JHD_TLS_ERR_MPI_XXX
 *                  error code on calculation failure.
 */
int jhd_tls_ecp_check_pub_priv( const jhd_tls_ecp_keypair *pub, const jhd_tls_ecp_keypair *prv );

#if defined(JHD_TLS_SELF_TEST)

/**
 * \brief          The ECP checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */
int jhd_tls_ecp_self_test( int verbose );

#endif /* JHD_TLS_SELF_TEST */



#endif /* ecp.h */
