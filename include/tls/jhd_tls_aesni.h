#ifndef JHD_TLS_AESNI_H
#define JHD_TLS_AESNI_H

#include <tls/jhd_tls_aes.h>

#define JHD_TLS_AESNI_AES      0x02000000u
#define JHD_TLS_AESNI_CLMUL    0x00000002u

#if defined(JHD_TLS_HAVE_ASM) && defined(__GNUC__) &&  \
    ( defined(__amd64__) || defined(__x86_64__) )   &&  \
    ! defined(JHD_TLS_HAVE_X86_64)
#define JHD_TLS_HAVE_X86_64
#endif

#if defined(JHD_TLS_HAVE_X86_64)

extern unsigned char aesni_support_aes;
extern unsigned char aesni_support_clmul;

/**
 * \brief          AES-NI features detection routine
 *
 * \param what     The feature to detect
 *                 (JHD_TLS_AESNI_AES or JHD_TLS_AESNI_CLMUL)
 *
 * \return         1 if CPU has support for the feature, 0 otherwise
 */
void jhd_tls_aesni_has_support();

/**
 * \brief          AES-NI AES-ECB block en(de)cryption
 *
 * \param ctx      AES context
 * \param mode     JHD_TLS_AES_ENCRYPT or JHD_TLS_AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 on success (cannot fail)
 */
void jhd_tls_aesni_crypt_ecb( jhd_tls_aes_context *ctx,int mode,const unsigned char input[16],unsigned char output[16] );


void jhd_tls_aes_ecb_encrypt_with_aesni( jhd_tls_aes_context *ctx,const unsigned char input[16],unsigned char output[16]);

void jhd_tls_aes_ecb_decrypt_with_aesni( jhd_tls_aes_context *ctx,const unsigned char input[16],unsigned char output[16]);

/**
 * \brief          GCM multiplication: c = a * b in GF(2^128)
 *
 * \param c        Result
 * \param a        First operand
 * \param b        Second operand
 *
 * \note           Both operands and result are bit strings interpreted as
 *                 elements of GF(2^128) as per the GCM spec.
 */
void jhd_tls_aesni_gcm_mult( unsigned char c[16],const unsigned char a[16],const unsigned char b[16] );

/**
 * \brief           Compute decryption round keys from encryption round keys
 *
 * \param invkey    Round keys for the equivalent inverse cipher
 * \param fwdkey    Original round keys (for encryption)
 * \param nr        Number of rounds (that is, number of round keys minus one)
 */
void jhd_tls_aesni_inverse_key( unsigned char *invkey,
                        const unsigned char *fwdkey, int nr );

/**
 * \brief           Perform key expansion (for encryption)
 *
 * \param rk        Destination buffer where the round keys are written
 * \param key       Encryption key
 * \param bits      Key size in bits (must be 128, 192 or 256)
 *
 * \return          0 if successful, or JHD_TLS_ERR_AES_INVALID_KEY_LENGTH
 */
void jhd_tls_aesni_setkey_enc( unsigned char *rk,const unsigned char *key,size_t bits );

#endif /* JHD_TLS_HAVE_X86_64 */

#endif /* JHD_TLS_AESNI_H */
