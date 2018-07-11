/*
 *  Helper functions for the RSA module
 *
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
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
 *
 */

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_RSA_C)

#include <tls/jhd_tls_rsa.h>
#include <tls/jhd_tls_bignum.h>
#include <tls/jhd_tls_rsa_internal.h>

/*
 * Compute RSA prime factors from public and private exponents
 *
 * Summary of algorithm:
 * Setting F := lcm(P-1,Q-1), the idea is as follows:
 *
 * (a) For any 1 <= X < N with gcd(X,N)=1, we have X^F = 1 modulo N, so X^(F/2)
 *     is a square root of 1 in Z/NZ. Since Z/NZ ~= Z/PZ x Z/QZ by CRT and the
 *     square roots of 1 in Z/PZ and Z/QZ are +1 and -1, this leaves the four
 *     possibilities X^(F/2) = (+-1, +-1). If it happens that X^(F/2) = (-1,+1)
 *     or (+1,-1), then gcd(X^(F/2) + 1, N) will be equal to one of the prime
 *     factors of N.
 *
 * (b) If we don't know F/2 but (F/2) * K for some odd (!) K, then the same
 *     construction still applies since (-)^K is the identity on the set of
 *     roots of 1 in Z/NZ.
 *
 * The public and private key primitives (-)^E and (-)^D are mutually inverse
 * bijections on Z/NZ if and only if (-)^(DE) is the identity on Z/NZ, i.e.
 * if and only if DE - 1 is a multiple of F, say DE - 1 = F * L.
 * Splitting L = 2^t * K with K odd, we have
 *
 *   DE - 1 = FL = (F/2) * (2^(t+1)) * K,
 *
 * so (F / 2) * K is among the numbers
 *
 *   (DE - 1) >> 1, (DE - 1) >> 2, ..., (DE - 1) >> ord
 *
 * where ord is the order of 2 in (DE - 1).
 * We can therefore iterate through these numbers apply the construction
 * of (a) and (b) above to attempt to factor N.
 *
 */
int jhd_tls_rsa_deduce_primes( jhd_tls_mpi const *N,
                     jhd_tls_mpi const *E, jhd_tls_mpi const *D,
                     jhd_tls_mpi *P, jhd_tls_mpi *Q )
{
    int ret = 0;

    uint16_t attempt;  /* Number of current attempt  */
    uint16_t iter;     /* Number of squares computed in the current attempt */

    uint16_t order;    /* Order of 2 in DE - 1 */

    jhd_tls_mpi T;  /* Holds largest odd divisor of DE - 1     */
    jhd_tls_mpi K;  /* Temporary holding the current candidate */

    const unsigned char primes[] = { 2,
           3,    5,    7,   11,   13,   17,   19,   23,
          29,   31,   37,   41,   43,   47,   53,   59,
          61,   67,   71,   73,   79,   83,   89,   97,
         101,  103,  107,  109,  113,  127,  131,  137,
         139,  149,  151,  157,  163,  167,  173,  179,
         181,  191,  193,  197,  199,  211,  223,  227,
         229,  233,  239,  241,  251
    };

    const size_t num_primes = sizeof( primes ) / sizeof( *primes );

    if( P == NULL || Q == NULL || P->p != NULL || Q->p != NULL )
        return( JHD_TLS_ERR_MPI_BAD_INPUT_DATA );

    if( jhd_tls_mpi_cmp_int( N, 0 ) <= 0 ||
        jhd_tls_mpi_cmp_int( D, 1 ) <= 0 ||
        jhd_tls_mpi_cmp_mpi( D, N ) >= 0 ||
        jhd_tls_mpi_cmp_int( E, 1 ) <= 0 ||
        jhd_tls_mpi_cmp_mpi( E, N ) >= 0 )
    {
        return( JHD_TLS_ERR_MPI_BAD_INPUT_DATA );
    }

    /*
     * Initializations and temporary changes
     */

    jhd_tls_mpi_init( &K );
    jhd_tls_mpi_init( &T );

    /* T := DE - 1 */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &T, D,  E ) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &T, &T, 1 ) );

    if( ( order = (uint16_t) jhd_tls_mpi_lsb( &T ) ) == 0 )
    {
        ret = JHD_TLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    /* After this operation, T holds the largest odd divisor of DE - 1. */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_shift_r( &T, order ) );

    /*
     * Actual work
     */

    /* Skip trying 2 if N == 1 mod 8 */
    attempt = 0;
    if( N->p[0] % 8 == 1 )
        attempt = 1;

    for( ; attempt < num_primes; ++attempt )
    {
        jhd_tls_mpi_lset( &K, primes[attempt] );

        /* Check if gcd(K,N) = 1 */
        JHD_TLS_MPI_CHK( jhd_tls_mpi_gcd( P, &K, N ) );
        if( jhd_tls_mpi_cmp_int( P, 1 ) != 0 )
            continue;

        /* Go through K^T + 1, K^(2T) + 1, K^(4T) + 1, ...
         * and check whether they have nontrivial GCD with N. */
        JHD_TLS_MPI_CHK( jhd_tls_mpi_exp_mod( &K, &K, &T, N,
                             Q /* temporarily use Q for storing Montgomery
                                * multiplication helper values */ ) );

        for( iter = 1; iter <= order; ++iter )
        {
            /* If we reach 1 prematurely, there's no point
             * in continuing to square K */
            if( jhd_tls_mpi_cmp_int( &K, 1 ) == 0 )
                break;

            JHD_TLS_MPI_CHK( jhd_tls_mpi_add_int( &K, &K, 1 ) );
            JHD_TLS_MPI_CHK( jhd_tls_mpi_gcd( P, &K, N ) );

            if( jhd_tls_mpi_cmp_int( P, 1 ) ==  1 &&
                jhd_tls_mpi_cmp_mpi( P, N ) == -1 )
            {
                /*
                 * Have found a nontrivial divisor P of N.
                 * Set Q := N / P.
                 */

                JHD_TLS_MPI_CHK( jhd_tls_mpi_div_mpi( Q, NULL, N, P ) );
                goto cleanup;
            }

            JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &K, &K, 1 ) );
            JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &K, &K, &K ) );
            JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &K, &K, N ) );
        }

        /*
         * If we get here, then either we prematurely aborted the loop because
         * we reached 1, or K holds primes[attempt]^(DE - 1) mod N, which must
         * be 1 if D,E,N were consistent.
         * Check if that's the case and abort if not, to avoid very long,
         * yet eventually failing, computations if N,D,E were not sane.
         */
        if( jhd_tls_mpi_cmp_int( &K, 1 ) != 0 )
        {
            break;
        }
    }

    ret = JHD_TLS_ERR_MPI_BAD_INPUT_DATA;

cleanup:

    jhd_tls_mpi_free( &K );
    jhd_tls_mpi_free( &T );
    return( ret );
}

/*
 * Given P, Q and the public exponent E, deduce D.
 * This is essentially a modular inversion.
 */
int jhd_tls_rsa_deduce_private_exponent( jhd_tls_mpi const *P,
                                         jhd_tls_mpi const *Q,
                                         jhd_tls_mpi const *E,
                                         jhd_tls_mpi *D )
{
    int ret = 0;
    jhd_tls_mpi K, L;

    if( D == NULL || jhd_tls_mpi_cmp_int( D, 0 ) != 0 )
        return( JHD_TLS_ERR_MPI_BAD_INPUT_DATA );

    if( jhd_tls_mpi_cmp_int( P, 1 ) <= 0 ||
        jhd_tls_mpi_cmp_int( Q, 1 ) <= 0 ||
        jhd_tls_mpi_cmp_int( E, 0 ) == 0 )
    {
        return( JHD_TLS_ERR_MPI_BAD_INPUT_DATA );
    }

    jhd_tls_mpi_init( &K );
    jhd_tls_mpi_init( &L );

    /* Temporarily put K := P-1 and L := Q-1 */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &K, P, 1 ) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &L, Q, 1 ) );

    /* Temporarily put D := gcd(P-1, Q-1) */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_gcd( D, &K, &L ) );

    /* K := LCM(P-1, Q-1) */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &K, &K, &L ) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_div_mpi( &K, NULL, &K, D ) );

    /* Compute modular inverse of E in LCM(P-1, Q-1) */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_inv_mod( D, E, &K ) );

cleanup:

    jhd_tls_mpi_free( &K );
    jhd_tls_mpi_free( &L );

    return( ret );
}

/*
 * Check that RSA CRT parameters are in accordance with core parameters.
 */
int jhd_tls_rsa_validate_crt( const jhd_tls_mpi *P,  const jhd_tls_mpi *Q,
                              const jhd_tls_mpi *D,  const jhd_tls_mpi *DP,
                              const jhd_tls_mpi *DQ, const jhd_tls_mpi *QP )
{
    int ret = 0;

    jhd_tls_mpi K, L;
    jhd_tls_mpi_init( &K );
    jhd_tls_mpi_init( &L );

    /* Check that DP - D == 0 mod P - 1 */
    if( DP != NULL )
    {
        if( P == NULL )
        {
            ret = JHD_TLS_ERR_RSA_BAD_INPUT_DATA;
            goto cleanup;
        }

        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &K, P, 1 ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_mpi( &L, DP, D ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &L, &L, &K ) );

        if( jhd_tls_mpi_cmp_int( &L, 0 ) != 0 )
        {
            ret = JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

    /* Check that DQ - D == 0 mod Q - 1 */
    if( DQ != NULL )
    {
        if( Q == NULL )
        {
            ret = JHD_TLS_ERR_RSA_BAD_INPUT_DATA;
            goto cleanup;
        }

        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &K, Q, 1 ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_mpi( &L, DQ, D ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &L, &L, &K ) );

        if( jhd_tls_mpi_cmp_int( &L, 0 ) != 0 )
        {
            ret = JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

    /* Check that QP * Q - 1 == 0 mod P */
    if( QP != NULL )
    {
        if( P == NULL || Q == NULL )
        {
            ret = JHD_TLS_ERR_RSA_BAD_INPUT_DATA;
            goto cleanup;
        }

        JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &K, QP, Q ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &K, &K, 1 ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &K, &K, P ) );
        if( jhd_tls_mpi_cmp_int( &K, 0 ) != 0 )
        {
            ret = JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

cleanup:

    /* Wrap MPI error codes by RSA check failure error code */
    if( ret != 0 &&
        ret != JHD_TLS_ERR_RSA_KEY_CHECK_FAILED &&
        ret != JHD_TLS_ERR_RSA_BAD_INPUT_DATA )
    {
        ret += JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    jhd_tls_mpi_free( &K );
    jhd_tls_mpi_free( &L );

    return( ret );
}

/*
 * Check that core RSA parameters are sane.
 */
int jhd_tls_rsa_validate_params( const jhd_tls_mpi *N, const jhd_tls_mpi *P,
                                 const jhd_tls_mpi *Q, const jhd_tls_mpi *D,
                                 const jhd_tls_mpi *E,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng )
{
    int ret = 0;
    jhd_tls_mpi K, L;

    jhd_tls_mpi_init( &K );
    jhd_tls_mpi_init( &L );

    /*
     * Step 1: If PRNG provided, check that P and Q are prime
     */

#if defined(JHD_TLS_GENPRIME)
    if( f_rng != NULL && P != NULL &&
        ( ret = jhd_tls_mpi_is_prime( P, f_rng, p_rng ) ) != 0 )
    {
        ret = JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
        goto cleanup;
    }

    if( f_rng != NULL && Q != NULL &&
        ( ret = jhd_tls_mpi_is_prime( Q, f_rng, p_rng ) ) != 0 )
    {
        ret = JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
        goto cleanup;
    }
#else
    ((void) f_rng);
    ((void) p_rng);
#endif /* JHD_TLS_GENPRIME */

    /*
     * Step 2: Check that 1 < N = P * Q
     */

    if( P != NULL && Q != NULL && N != NULL )
    {
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &K, P, Q ) );
        if( jhd_tls_mpi_cmp_int( N, 1 )  <= 0 ||
            jhd_tls_mpi_cmp_mpi( &K, N ) != 0 )
        {
            ret = JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

    /*
     * Step 3: Check and 1 < D, E < N if present.
     */

    if( N != NULL && D != NULL && E != NULL )
    {
        if ( jhd_tls_mpi_cmp_int( D, 1 ) <= 0 ||
             jhd_tls_mpi_cmp_int( E, 1 ) <= 0 ||
             jhd_tls_mpi_cmp_mpi( D, N ) >= 0 ||
             jhd_tls_mpi_cmp_mpi( E, N ) >= 0 )
        {
            ret = JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

    /*
     * Step 4: Check that D, E are inverse modulo P-1 and Q-1
     */

    if( P != NULL && Q != NULL && D != NULL && E != NULL )
    {
        if( jhd_tls_mpi_cmp_int( P, 1 ) <= 0 ||
            jhd_tls_mpi_cmp_int( Q, 1 ) <= 0 )
        {
            ret = JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }

        /* Compute DE-1 mod P-1 */
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &K, D, E ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &K, &K, 1 ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &L, P, 1 ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &K, &K, &L ) );
        if( jhd_tls_mpi_cmp_int( &K, 0 ) != 0 )
        {
            ret = JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }

        /* Compute DE-1 mod Q-1 */
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &K, D, E ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &K, &K, 1 ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &L, Q, 1 ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &K, &K, &L ) );
        if( jhd_tls_mpi_cmp_int( &K, 0 ) != 0 )
        {
            ret = JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

cleanup:

    jhd_tls_mpi_free( &K );
    jhd_tls_mpi_free( &L );

    /* Wrap MPI error codes by RSA check failure error code */
    if( ret != 0 && ret != JHD_TLS_ERR_RSA_KEY_CHECK_FAILED )
    {
        ret += JHD_TLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    return( ret );
}

int jhd_tls_rsa_deduce_crt( const jhd_tls_mpi *P, const jhd_tls_mpi *Q,
                            const jhd_tls_mpi *D, jhd_tls_mpi *DP,
                            jhd_tls_mpi *DQ, jhd_tls_mpi *QP )
{
    int ret = 0;
    jhd_tls_mpi K;
    jhd_tls_mpi_init( &K );

    /* DP = D mod P-1 */
    if( DP != NULL )
    {
        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &K, P, 1  ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( DP, D, &K ) );
    }

    /* DQ = D mod Q-1 */
    if( DQ != NULL )
    {
        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_int( &K, Q, 1  ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( DQ, D, &K ) );
    }

    /* QP = Q^{-1} mod P */
    if( QP != NULL )
    {
        JHD_TLS_MPI_CHK( jhd_tls_mpi_inv_mod( QP, Q, P ) );
    }

cleanup:
    jhd_tls_mpi_free( &K );

    return( ret );
}

#endif /* JHD_TLS_RSA_C */
