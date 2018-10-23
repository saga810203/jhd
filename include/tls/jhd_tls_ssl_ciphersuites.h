/**
 * \file ssl_ciphersuites.h
 *
 * \brief SSL Ciphersuites for mbed TLS
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
#ifndef JHD_TLS_SSL_CIPHERSUITES_H
#define JHD_TLS_SSL_CIPHERSUITES_H

#include <tls/jhd_tls_cipher_internal.h>
#include <tls/jhd_tls_pk_internal.h>
#include <tls/jhd_tls_md_internal.h>
#include <tls/jhd_tls_pk.h>



/*
 * Supported ciphersuites (Official IANA names)
 */
#define JHD_TLS_TLS_RSA_WITH_NULL_MD5                    0x01   /**< Weak! */
#define JHD_TLS_TLS_RSA_WITH_NULL_SHA                    0x02   /**< Weak! */

#define JHD_TLS_TLS_RSA_WITH_RC4_128_MD5                 0x04
#define JHD_TLS_TLS_RSA_WITH_RC4_128_SHA                 0x05
#define JHD_TLS_TLS_RSA_WITH_DES_CBC_SHA                 0x09   /**< Weak! Not in TLS 1.2 */

#define JHD_TLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA            0x0A

#define JHD_TLS_TLS_DHE_RSA_WITH_DES_CBC_SHA             0x15   /**< Weak! Not in TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA        0x16

#define JHD_TLS_TLS_PSK_WITH_NULL_SHA                    0x2C   /**< Weak! */
#define JHD_TLS_TLS_DHE_PSK_WITH_NULL_SHA                0x2D   /**< Weak! */
#define JHD_TLS_TLS_RSA_PSK_WITH_NULL_SHA                0x2E   /**< Weak! */
#define JHD_TLS_TLS_RSA_WITH_AES_128_CBC_SHA             0x2F

#define JHD_TLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA         0x33
#define JHD_TLS_TLS_RSA_WITH_AES_256_CBC_SHA             0x35
#define JHD_TLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA         0x39

#define JHD_TLS_TLS_RSA_WITH_NULL_SHA256                 0x3B   /**< Weak! */
#define JHD_TLS_TLS_RSA_WITH_AES_128_CBC_SHA256          0x3C   /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_WITH_AES_256_CBC_SHA256          0x3D   /**< TLS 1.2 */

#define JHD_TLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA        0x41
#define JHD_TLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA    0x45

#define JHD_TLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256      0x67   /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256      0x6B   /**< TLS 1.2 */

#define JHD_TLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA        0x84
#define JHD_TLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA    0x88

#define JHD_TLS_TLS_PSK_WITH_RC4_128_SHA                 0x8A
#define JHD_TLS_TLS_PSK_WITH_3DES_EDE_CBC_SHA            0x8B
#define JHD_TLS_TLS_PSK_WITH_AES_128_CBC_SHA             0x8C
#define JHD_TLS_TLS_PSK_WITH_AES_256_CBC_SHA             0x8D

#define JHD_TLS_TLS_DHE_PSK_WITH_RC4_128_SHA             0x8E
#define JHD_TLS_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA        0x8F
#define JHD_TLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA         0x90
#define JHD_TLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA         0x91

#define JHD_TLS_TLS_RSA_PSK_WITH_RC4_128_SHA             0x92
#define JHD_TLS_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA        0x93
#define JHD_TLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA         0x94
#define JHD_TLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA         0x95

#define JHD_TLS_TLS_RSA_WITH_AES_128_GCM_SHA256          0x9C   /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_WITH_AES_256_GCM_SHA384          0x9D   /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256      0x9E   /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384      0x9F   /**< TLS 1.2 */

#define JHD_TLS_TLS_PSK_WITH_AES_128_GCM_SHA256          0xA8   /**< TLS 1.2 */
#define JHD_TLS_TLS_PSK_WITH_AES_256_GCM_SHA384          0xA9   /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256      0xAA   /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384      0xAB   /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256      0xAC   /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384      0xAD   /**< TLS 1.2 */

#define JHD_TLS_TLS_PSK_WITH_AES_128_CBC_SHA256          0xAE
#define JHD_TLS_TLS_PSK_WITH_AES_256_CBC_SHA384          0xAF
#define JHD_TLS_TLS_PSK_WITH_NULL_SHA256                 0xB0   /**< Weak! */
#define JHD_TLS_TLS_PSK_WITH_NULL_SHA384                 0xB1   /**< Weak! */

#define JHD_TLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256      0xB2
#define JHD_TLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384      0xB3
#define JHD_TLS_TLS_DHE_PSK_WITH_NULL_SHA256             0xB4   /**< Weak! */
#define JHD_TLS_TLS_DHE_PSK_WITH_NULL_SHA384             0xB5   /**< Weak! */

#define JHD_TLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256      0xB6
#define JHD_TLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384      0xB7
#define JHD_TLS_TLS_RSA_PSK_WITH_NULL_SHA256             0xB8   /**< Weak! */
#define JHD_TLS_TLS_RSA_PSK_WITH_NULL_SHA384             0xB9   /**< Weak! */

#define JHD_TLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256     0xBA   /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 0xBE   /**< TLS 1.2 */

#define JHD_TLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256     0xC0   /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 0xC4   /**< TLS 1.2 */

#define JHD_TLS_TLS_ECDH_ECDSA_WITH_NULL_SHA             0xC001 /**< Weak! */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_RC4_128_SHA          0xC002 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA     0xC003 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA      0xC004 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA      0xC005 /**< Not in SSL3! */

#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA            0xC006 /**< Weak! */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA         0xC007 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA    0xC008 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA     0xC009 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA     0xC00A /**< Not in SSL3! */

#define JHD_TLS_TLS_ECDH_RSA_WITH_NULL_SHA               0xC00B /**< Weak! */
#define JHD_TLS_TLS_ECDH_RSA_WITH_RC4_128_SHA            0xC00C /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA       0xC00D /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA        0xC00E /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA        0xC00F /**< Not in SSL3! */

#define JHD_TLS_TLS_ECDHE_RSA_WITH_NULL_SHA              0xC010 /**< Weak! */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_RC4_128_SHA           0xC011 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA      0xC012 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA       0xC013 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA       0xC014 /**< Not in SSL3! */

#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256  0xC023 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384  0xC024 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256   0xC025 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384   0xC026 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256    0xC027 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384    0xC028 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256     0xC029 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384     0xC02A /**< TLS 1.2 */

#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  0xC02B /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  0xC02C /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256   0xC02D /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384   0xC02E /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    0xC02F /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    0xC030 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256     0xC031 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384     0xC032 /**< TLS 1.2 */

#define JHD_TLS_TLS_ECDHE_PSK_WITH_RC4_128_SHA           0xC033 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA      0xC034 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA       0xC035 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA       0xC036 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256    0xC037 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384    0xC038 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_PSK_WITH_NULL_SHA              0xC039 /**< Weak! No SSL3! */
#define JHD_TLS_TLS_ECDHE_PSK_WITH_NULL_SHA256           0xC03A /**< Weak! No SSL3! */
#define JHD_TLS_TLS_ECDHE_PSK_WITH_NULL_SHA384           0xC03B /**< Weak! No SSL3! */

#define JHD_TLS_TLS_RSA_WITH_ARIA_128_CBC_SHA256         0xC03C /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_WITH_ARIA_256_CBC_SHA384         0xC03D /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256     0xC044 /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384     0xC045 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 0xC048 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 0xC049 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256  0xC04A /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384  0xC04B /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256   0xC04C /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384   0xC04D /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256    0xC04E /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384    0xC04F /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_WITH_ARIA_128_GCM_SHA256         0xC050 /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_WITH_ARIA_256_GCM_SHA384         0xC051 /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256     0xC052 /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384     0xC053 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 0xC05C /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 0xC05D /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256  0xC05E /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384  0xC05F /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256   0xC060 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384   0xC061 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256    0xC062 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384    0xC063 /**< TLS 1.2 */
#define JHD_TLS_TLS_PSK_WITH_ARIA_128_CBC_SHA256         0xC064 /**< TLS 1.2 */
#define JHD_TLS_TLS_PSK_WITH_ARIA_256_CBC_SHA384         0xC065 /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256     0xC066 /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384     0xC067 /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256     0xC068 /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384     0xC069 /**< TLS 1.2 */
#define JHD_TLS_TLS_PSK_WITH_ARIA_128_GCM_SHA256         0xC06A /**< TLS 1.2 */
#define JHD_TLS_TLS_PSK_WITH_ARIA_256_GCM_SHA384         0xC06B /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256     0xC06C /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384     0xC06D /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256     0xC06E /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384     0xC06F /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256   0xC070 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384   0xC071 /**< TLS 1.2 */

#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 0xC072 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 0xC073 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  0xC074 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  0xC075 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   0xC076 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384   0xC077 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256    0xC078 /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384    0xC079 /**< Not in SSL3! */

#define JHD_TLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256         0xC07A /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384         0xC07B /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256     0xC07C /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384     0xC07D /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 0xC086 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 0xC087 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  0xC088 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  0xC089 /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256   0xC08A /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384   0xC08B /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256    0xC08C /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384    0xC08D /**< TLS 1.2 */

#define JHD_TLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256       0xC08E /**< TLS 1.2 */
#define JHD_TLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384       0xC08F /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256   0xC090 /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384   0xC091 /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256   0xC092 /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384   0xC093 /**< TLS 1.2 */

#define JHD_TLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256       0xC094
#define JHD_TLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384       0xC095
#define JHD_TLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256   0xC096
#define JHD_TLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384   0xC097
#define JHD_TLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256   0xC098
#define JHD_TLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384   0xC099
#define JHD_TLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 0xC09A /**< Not in SSL3! */
#define JHD_TLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 0xC09B /**< Not in SSL3! */

#define JHD_TLS_TLS_RSA_WITH_AES_128_CCM                0xC09C  /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_WITH_AES_256_CCM                0xC09D  /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_AES_128_CCM            0xC09E  /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_AES_256_CCM            0xC09F  /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_WITH_AES_128_CCM_8              0xC0A0  /**< TLS 1.2 */
#define JHD_TLS_TLS_RSA_WITH_AES_256_CCM_8              0xC0A1  /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_AES_128_CCM_8          0xC0A2  /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_RSA_WITH_AES_256_CCM_8          0xC0A3  /**< TLS 1.2 */
#define JHD_TLS_TLS_PSK_WITH_AES_128_CCM                0xC0A4  /**< TLS 1.2 */
#define JHD_TLS_TLS_PSK_WITH_AES_256_CCM                0xC0A5  /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_AES_128_CCM            0xC0A6  /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_AES_256_CCM            0xC0A7  /**< TLS 1.2 */
#define JHD_TLS_TLS_PSK_WITH_AES_128_CCM_8              0xC0A8  /**< TLS 1.2 */
#define JHD_TLS_TLS_PSK_WITH_AES_256_CCM_8              0xC0A9  /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_AES_128_CCM_8          0xC0AA  /**< TLS 1.2 */
#define JHD_TLS_TLS_DHE_PSK_WITH_AES_256_CCM_8          0xC0AB  /**< TLS 1.2 */
/* The last two are named with PSK_DHE in the RFC, which looks like a typo */

#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM        0xC0AC  /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM        0xC0AD  /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8      0xC0AE  /**< TLS 1.2 */
#define JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8      0xC0AF  /**< TLS 1.2 */

#define JHD_TLS_TLS_ECJPAKE_WITH_AES_128_CCM_8          0xC0FF  /**< experimental */

/* Reminder: update jhd_tls_ssl_premaster_secret when adding a new key exchange.
 * Reminder: update JHD_TLS_KEY_EXCHANGE__xxx below
 */
typedef enum {
    JHD_TLS_KEY_EXCHANGE_NONE = 0,
    JHD_TLS_KEY_EXCHANGE_RSA,
    JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,
    JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,
} jhd_tls_key_exchange_type_t;


#define JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED

#define JHD_TLS_KEY_EXCHANGE__CERT_REQ_ALLOWED__ENABLED






#define JHD_TLS_KEY_EXCHANGE__SOME_NON_PFS__ENABLED




typedef struct jhd_tls_ssl_ciphersuite_t jhd_tls_ssl_ciphersuite_t;

//#define JHD_TLS_CIPHERSUITE_WEAK       0x01    /**< Weak ciphersuite flag  */
//#define JHD_TLS_CIPHERSUITE_SHORT_TAG  0x02    /**< Short authentication tag,
//                                                     eg for CCM_8 */
//#define JHD_TLS_CIPHERSUITE_NODTLS     0x04    /**< Can't be used with DTLS */

/**
 * \brief   This structure is used for storing ciphersuite information
 */
struct jhd_tls_ssl_ciphersuite_t
{
    int id;
    const char * name;

    jhd_tls_cipher_type_t cipher;
    const jhd_tls_md_info_t	*md_info;
    jhd_tls_key_exchange_type_t key_exchange;
    const jhd_tls_pk_info_t *pk_info;

    int min_major_ver;
    int min_minor_ver;
    int max_major_ver;
    int max_minor_ver;
//unsupported  JHD_TLS_CIPHERSUITE_WEAK    JHD_TLS_CIPHERSUITE_SHORT_TAG    JHD_TLS_CIPHERSUITE_NODTLS
//    unsigned char flags;
};

extern const jhd_tls_ssl_ciphersuite_t supported_ciphersuites[];


#if !defined(JHD_TLS_INLINE)
const jhd_tls_pk_info_t* jhd_tls_ssl_get_ciphersuite_sig_pk_alg( const jhd_tls_ssl_ciphersuite_t *info );
const jhd_tls_pk_info_t* jhd_tls_ssl_get_ciphersuite_sig_alg( const jhd_tls_ssl_ciphersuite_t *info );


int jhd_tls_ssl_ciphersuite_uses_ec( const jhd_tls_ssl_ciphersuite_t *info );
#else

#define jhd_tls_ssl_get_ciphersuite_sig_pk_alg(info) ((info)->pk_info)

#define jhd_tls_ssl_get_ciphersuite_sig_alg(info) ((info)->pk_info)

#define jhd_tls_ssl_ciphersuite_uses_ec(info)  (((info)->key_exchange ==	JHD_TLS_KEY_EXCHANGE_ECDHE_RSA ||(info)->key_exchange ==	JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA))


#endif


const jhd_tls_ssl_ciphersuite_t *jhd_tls_ssl_ciphersuite_from_string( const char *ciphersuite_name );
const jhd_tls_ssl_ciphersuite_t *jhd_tls_ssl_ciphersuite_from_id( int ciphersuite_id );





static inline int jhd_tls_ssl_ciphersuite_has_pfs( const jhd_tls_ssl_ciphersuite_t *info )
{
    switch( info->key_exchange )
    {
        case JHD_TLS_KEY_EXCHANGE_ECDHE_RSA:
        case JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return( 1 );
        default:
            return( 0 );
    }
}


#if defined(JHD_TLS_KEY_EXCHANGE__SOME_NON_PFS__ENABLED)
#if !defined(JHD_TLS_INLINE)


static inline int jhd_tls_ssl_ciphersuite_no_pfs( const jhd_tls_ssl_ciphersuite_t *info )
{
	return info->key_exchange == JHD_TLS_KEY_EXCHANGE_RSA;
}

#else
#define jhd_tls_ssl_ciphersuite_no_pfs(info) ((info)->key_exchange == JHD_TLS_KEY_EXCHANGE_RSA)
#endif
#endif /* JHD_TLS_KEY_EXCHANGE__SOME_NON_PFS__ENABLED */



#if !defined(JHD_TLS_INLINE)
static inline int jhd_tls_ssl_ciphersuite_uses_ecdhe( const jhd_tls_ssl_ciphersuite_t *info )
{
	return info->key_exchange ==JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA || info->key_exchange ==JHD_TLS_KEY_EXCHANGE_ECDHE_RSA;
}
#else
#define jhd_tls_ssl_ciphersuite_uses_ecdhe(info) ((info)->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA || (info)->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_RSA))
#endif



#if !defined(JHD_TLS_INLINE)
static inline int jhd_tls_ssl_ciphersuite_uses_server_signature( const jhd_tls_ssl_ciphersuite_t *info )
{
	return info->key_exchange ==JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA || info->key_exchange ==JHD_TLS_KEY_EXCHANGE_ECDHE_RSA;
}
#else
#define jhd_tls_ssl_ciphersuite_uses_server_signature(info) ((info)->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA || (info)->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_RSA))
#endif



#endif /* ssl_ciphersuites.h */
