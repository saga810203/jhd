#ifndef JHD_TLS_GCM_H
#define JHD_TLS_GCM_H

#include <stdint.h>
#include <tls/jhd_tls_cipher.h>

#define JHD_TLS_GCM_ENCRYPT     1
#define JHD_TLS_GCM_DECRYPT     0

#define JHD_TLS_ERR_GCM_AUTH_FAILED                       -0x0012  /**< Authenticated decryption failed. */
#define JHD_TLS_ERR_GCM_HW_ACCEL_FAILED                   -0x0013  /**< GCM hardware accelerator failed. */
#define JHD_TLS_ERR_GCM_BAD_INPUT                         -0x0014  /**< Bad input parameters to function. */



/**
 * \brief          The GCM context structure.
 */
typedef struct {
    jhd_tls_cipher_context_t cipher_ctx;  /*!< The cipher context used. */
    uint64_t HL[16];                      /*!< Precalculated HTable low. */
    uint64_t HH[16];                      /*!< Precalculated HTable high. */
//    unsigned char base_ectr[16];          /*!< The first ECTR for tag. */
//    unsigned char y[16];                  /*!< The Y working value. */
//    unsigned char buf[16];                /*!< The buf working value. */
}
jhd_tls_gcm_context;

void jhd_tls_gcm_init_with_aesni();


void jhd_tls_gcm_setkey_enc( jhd_tls_gcm_context *gcm_ctx,const unsigned char *key,unsigned int keybits );
void jhd_tls_gcm_setkey_dec( jhd_tls_gcm_context *gcm_ctx,const unsigned char *key,unsigned int keybits );
void jhd_tls_gcm_encrypt( jhd_tls_gcm_context *gcm_ctx,const unsigned char *fixed_iv,const unsigned char *ctr,const unsigned char *add,unsigned char *tag, uint16_t length, const unsigned char *input, unsigned char *output);



void jhd_tls_gcm_decrypt( jhd_tls_gcm_context *gcm_ctx,const unsigned char *fixed_iv,const unsigned char *ctr,const unsigned char *add,unsigned char *tag, uint16_t length, const unsigned char *input, unsigned char *output);



#endif /* gcm.h */
