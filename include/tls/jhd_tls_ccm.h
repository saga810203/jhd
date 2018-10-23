#ifndef JHD_TLS_CCM_H
#define JHD_TLS_CCM_H

#include <tls/jhd_tls_cipher_internal.h>

#define JHD_TLS_ERR_CCM_BAD_INPUT       -0x000D /**< Bad input parameters to the function. */
#define JHD_TLS_ERR_CCM_AUTH_FAILED     -0x000F /**< Authenticated decryption failed. */
#define JHD_TLS_ERR_CCM_HW_ACCEL_FAILED -0x0011 /**< CCM hardware accelerator failed. */

#define JHD_TLS_CCM_ENCRYPT 0
#define JHD_TLS_CCM_DECRYPT 1



// Regular implementation
//

/**
 * \brief    The CCM context-type definition. The CCM context is passed
 *           to the APIs called.
 */
typedef struct {
    jhd_tls_cipher_context_t cipher_ctx;    /*!< The cipher context used. */
}
jhd_tls_ccm_context;

void jhd_tls_ccm_setkey( jhd_tls_ccm_context *ccm_ctx,const unsigned char *key,unsigned int keybits );

void jhd_tls_ccm_encrypt( jhd_tls_ccm_context *ccm_ctx,const unsigned char *fixed_iv,const unsigned char *ctr,const unsigned char *add,unsigned char *tag, uint16_t length, const unsigned char *input, unsigned char *output);

void jhd_tls_ccm_decrypt( jhd_tls_ccm_context *ccm_ctx,const unsigned char *fixed_iv,const unsigned char *ctr,const unsigned char *add,unsigned char *tag, uint16_t length, const unsigned char *input, unsigned char *output);
#endif /* JHD_TLS_CCM_H */
