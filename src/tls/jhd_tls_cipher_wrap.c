#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_cipher_internal.h>
#include <tls/jhd_tls_aes.h>
#include <tls/jhd_tls_camellia.h>
#include <tls/jhd_tls_aria.h>
#include <tls/jhd_tls_des.h>
#include <tls/jhd_tls_blowfish.h>
#include <tls/jhd_tls_gcm.h>
#include <tls/jhd_tls_ccm.h>
#include <tls/jhd_tls_platform.h>

 void jhd_tls_cipher_size_init(void *ctx,const jhd_tls_cipher_info_t *info){
	jhd_tls_platform_zeroize(ctx,info->base->ctx_size);
}



static const jhd_tls_cipher_info_t aes_128_ecb_info = { JHD_TLS_CIPHER_AES_128_ECB, JHD_TLS_MODE_ECB, 128, "AES-128-ECB", 16, &aes_info };

static const jhd_tls_cipher_info_t aes_192_ecb_info = { JHD_TLS_CIPHER_AES_192_ECB, JHD_TLS_MODE_ECB, 192, "AES-192-ECB", 16, &aes_info };

static const jhd_tls_cipher_info_t aes_256_ecb_info = { JHD_TLS_CIPHER_AES_256_ECB, JHD_TLS_MODE_ECB, 256, "AES-256-ECB", 16, &aes_info };


static const jhd_tls_cipher_info_t aes_128_cbc_info = { JHD_TLS_CIPHER_AES_128_CBC, JHD_TLS_MODE_CBC, 128, "AES-128-CBC", 16, &aes_info };

static const jhd_tls_cipher_info_t aes_192_cbc_info = { JHD_TLS_CIPHER_AES_192_CBC, JHD_TLS_MODE_CBC, 192, "AES-192-CBC", 16, &aes_info };

static const jhd_tls_cipher_info_t aes_256_cbc_info = { JHD_TLS_CIPHER_AES_256_CBC, JHD_TLS_MODE_CBC, 256, "AES-256-CBC", 16, &aes_info };

static void cipher_gcm_init(void* ctx,const jhd_tls_cipher_info_t *info){
	const jhd_tls_cipher_info_t *cipher_info;
	jhd_tls_platform_zeroize(ctx,info->base->ctx_size);
	cipher_info = jhd_tls_cipher_info_from_values(info->base->cipher, info->key_bitlen, JHD_TLS_MODE_ECB);
	log_assert((cipher_info != NULL) &&  (cipher_info->block_size == 16)/*,"invalid param info"*/);
	((jhd_tls_gcm_context*)ctx)->cipher_ctx.cipher_ctx  =(void*)(((uint64_t)ctx)+sizeof(jhd_tls_gcm_context));
	((jhd_tls_gcm_context*)ctx)->cipher_ctx.cipher_info = cipher_info;
}
static const jhd_tls_cipher_base_t gcm_aes_info = {
		JHD_TLS_CIPHER_ID_AES,
		sizeof(jhd_tls_gcm_context)+sizeof(jhd_tls_aes_context),
		cipher_gcm_init,
//		NULL,
//        NULL,
		NULL,
		NULL,
		NULL,
		NULL,
        (jhd_tls_cipher_setkey_enc_pt) jhd_tls_gcm_setkey_enc,
        (jhd_tls_cipher_setkey_dec_pt) jhd_tls_gcm_setkey_dec,
};



static const jhd_tls_cipher_info_t aes_128_gcm_info = { JHD_TLS_CIPHER_AES_128_GCM, JHD_TLS_MODE_GCM, 128, "AES-128-GCM",16, &gcm_aes_info };

static const jhd_tls_cipher_info_t aes_192_gcm_info = { JHD_TLS_CIPHER_AES_192_GCM, JHD_TLS_MODE_GCM, 192, "AES-192-GCM",16, &gcm_aes_info };

static const jhd_tls_cipher_info_t aes_256_gcm_info = { JHD_TLS_CIPHER_AES_256_GCM, JHD_TLS_MODE_GCM, 256, "AES-256-GCM",16, &gcm_aes_info };
static void cipher_ccm_init(void* ctx,const jhd_tls_cipher_info_t *info){
	const jhd_tls_cipher_info_t *cipher_info;
	cipher_info = jhd_tls_cipher_info_from_values(info->base->cipher, info->key_bitlen, JHD_TLS_MODE_ECB);
	log_assert((cipher_info != NULL) && (cipher_info->block_size == 16)/*,"invalid param info"*/);
	jhd_tls_platform_zeroize(ctx, info->base->ctx_size);
	((jhd_tls_ccm_context*)ctx)->cipher_ctx.cipher_ctx  =(void*)(((uint64_t)ctx)+sizeof(jhd_tls_ccm_context));
	((jhd_tls_ccm_context*)ctx)->cipher_ctx.cipher_info = cipher_info;
}

static const jhd_tls_cipher_base_t ccm_aes_info = {
		JHD_TLS_CIPHER_ID_AES,
		sizeof(jhd_tls_ccm_context)+sizeof(jhd_tls_aes_context),
		cipher_ccm_init,
//        NULL,
//        NULL,
		NULL,
		NULL,
		NULL,
		NULL,
        (jhd_tls_cipher_setkey_enc_pt) jhd_tls_ccm_setkey,
        (jhd_tls_cipher_setkey_dec_pt) jhd_tls_ccm_setkey,
};




static const jhd_tls_cipher_info_t aes_128_ccm_info = {JHD_TLS_CIPHER_AES_128_CCM, JHD_TLS_MODE_CCM, 128, "AES-128-CCM", 16, &ccm_aes_info };

static const jhd_tls_cipher_info_t aes_192_ccm_info = { JHD_TLS_CIPHER_AES_192_CCM, JHD_TLS_MODE_CCM, 192, "AES-192-CCM", 16, &ccm_aes_info };

static const jhd_tls_cipher_info_t aes_256_ccm_info = { JHD_TLS_CIPHER_AES_256_CCM, JHD_TLS_MODE_CCM, 256, "AES-256-CCM", 16, &ccm_aes_info };
static const jhd_tls_cipher_base_t camellia_info = {
		JHD_TLS_CIPHER_ID_CAMELLIA,
		sizeof(jhd_tls_camellia_context),
		jhd_tls_cipher_size_init,
//		(jhd_tls_cipher_ecb_pt) jhd_tls_camellia_crypt_ecb,
//        (jhd_tls_cipher_cbc_pt) jhd_tls_camellia_crypt_cbc,
        (jhd_tls_cipher_ecb_encrypt_pt)jhd_tls_camellia_ecb_encrypt,
        (jhd_tls_cipher_ecb_decrypt_pt)jhd_tls_camellia_ecb_decrypt,
        (jhd_tls_cipher_cbc_encrypt_pt)jhd_tls_camellia_cbc_encrypt,
        (jhd_tls_cipher_cbc_decrypt_pt)jhd_tls_camellia_cbc_decrypt,
        (jhd_tls_cipher_setkey_enc_pt) jhd_tls_camellia_setkey_enc,
        (jhd_tls_cipher_setkey_dec_pt) jhd_tls_camellia_setkey_dec,
};

static const jhd_tls_cipher_info_t camellia_128_ecb_info = { JHD_TLS_CIPHER_CAMELLIA_128_ECB, JHD_TLS_MODE_ECB, 128, "CAMELLIA-128-ECB",  16,&camellia_info };

static const jhd_tls_cipher_info_t camellia_192_ecb_info = { JHD_TLS_CIPHER_CAMELLIA_192_ECB, JHD_TLS_MODE_ECB, 192, "CAMELLIA-192-ECB",  16,&camellia_info };

static const jhd_tls_cipher_info_t camellia_256_ecb_info = { JHD_TLS_CIPHER_CAMELLIA_256_ECB, JHD_TLS_MODE_ECB, 256, "CAMELLIA-256-ECB",  16,&camellia_info };
static const jhd_tls_cipher_info_t camellia_128_cbc_info = { JHD_TLS_CIPHER_CAMELLIA_128_CBC, JHD_TLS_MODE_CBC, 128, "CAMELLIA-128-CBC",  16,&camellia_info };

static const jhd_tls_cipher_info_t camellia_192_cbc_info = { JHD_TLS_CIPHER_CAMELLIA_192_CBC, JHD_TLS_MODE_CBC, 192, "CAMELLIA-192-CBC",  16,&camellia_info };

static const jhd_tls_cipher_info_t camellia_256_cbc_info = { JHD_TLS_CIPHER_CAMELLIA_256_CBC, JHD_TLS_MODE_CBC, 256, "CAMELLIA-256-CBC",  16,&camellia_info };

static const jhd_tls_cipher_base_t gcm_camellia_info = {
		JHD_TLS_CIPHER_ID_CAMELLIA,
		sizeof(jhd_tls_gcm_context)+sizeof(jhd_tls_camellia_context),
		cipher_gcm_init,
//		NULL,
//        NULL,
		NULL,
		NULL,
		NULL,
		NULL,
        (jhd_tls_cipher_setkey_enc_pt)jhd_tls_gcm_setkey_enc,
        (jhd_tls_cipher_setkey_dec_pt)jhd_tls_gcm_setkey_dec,
};


static const jhd_tls_cipher_info_t camellia_128_gcm_info = { JHD_TLS_CIPHER_CAMELLIA_128_GCM, JHD_TLS_MODE_GCM, 128, "CAMELLIA-128-GCM", 16, &gcm_camellia_info };

static const jhd_tls_cipher_info_t camellia_192_gcm_info = { JHD_TLS_CIPHER_CAMELLIA_192_GCM, JHD_TLS_MODE_GCM, 192, "CAMELLIA-192-GCM", 16, &gcm_camellia_info };

static const jhd_tls_cipher_info_t camellia_256_gcm_info = { JHD_TLS_CIPHER_CAMELLIA_256_GCM, JHD_TLS_MODE_GCM, 256, "CAMELLIA-256-GCM", 16, &gcm_camellia_info };

static const jhd_tls_cipher_base_t ccm_camellia_info = {
		JHD_TLS_CIPHER_ID_CAMELLIA,
		sizeof(jhd_tls_ccm_context)+sizeof(jhd_tls_camellia_context),
		cipher_ccm_init,
//        NULL,
//        NULL,
		NULL,
		NULL,
		NULL,
		NULL,
        (jhd_tls_cipher_setkey_enc_pt) jhd_tls_ccm_setkey,
        (jhd_tls_cipher_setkey_dec_pt)jhd_tls_ccm_setkey,
};
static const jhd_tls_cipher_info_t camellia_128_ccm_info = { JHD_TLS_CIPHER_CAMELLIA_128_CCM, JHD_TLS_MODE_CCM, 128, "CAMELLIA-128-CCM", 16, &ccm_camellia_info };

static const jhd_tls_cipher_info_t camellia_192_ccm_info = { JHD_TLS_CIPHER_CAMELLIA_192_CCM, JHD_TLS_MODE_CCM, 192, "CAMELLIA-192-CCM", 16, &ccm_camellia_info };

static const jhd_tls_cipher_info_t camellia_256_ccm_info = { JHD_TLS_CIPHER_CAMELLIA_256_CCM, JHD_TLS_MODE_CCM, 256, "CAMELLIA-256-CCM", 16, &ccm_camellia_info };



static const jhd_tls_cipher_base_t aria_info = {
		JHD_TLS_CIPHER_ID_ARIA,
		sizeof(jhd_tls_aria_context),
		jhd_tls_cipher_size_init,
//		(jhd_tls_cipher_ecb_pt) jhd_tls_aria_crypt_ecb,
//        (jhd_tls_cipher_cbc_pt) jhd_tls_aria_crypt_cbc,
        (jhd_tls_cipher_ecb_encrypt_pt)jhd_tls_aria_ecb_encrypt,
        (jhd_tls_cipher_ecb_decrypt_pt)jhd_tls_aria_ecb_decrypt,
        (jhd_tls_cipher_cbc_encrypt_pt)jhd_tls_aria_cbc_encrypt,
        (jhd_tls_cipher_cbc_decrypt_pt)jhd_tls_aria_cbc_decrypt,
        (jhd_tls_cipher_setkey_enc_pt) jhd_tls_aria_setkey_enc,
        (jhd_tls_cipher_setkey_dec_pt) jhd_tls_aria_setkey_dec,
};

static const jhd_tls_cipher_info_t aria_128_ecb_info = { JHD_TLS_CIPHER_ARIA_128_ECB, JHD_TLS_MODE_ECB, 128, "ARIA-128-ECB", 16, &aria_info };

static const jhd_tls_cipher_info_t aria_192_ecb_info = { JHD_TLS_CIPHER_ARIA_192_ECB, JHD_TLS_MODE_ECB, 192, "ARIA-192-ECB", 16, &aria_info };

static const jhd_tls_cipher_info_t aria_256_ecb_info = { JHD_TLS_CIPHER_ARIA_256_ECB, JHD_TLS_MODE_ECB, 256, "ARIA-256-ECB", 16, &aria_info };

static const jhd_tls_cipher_info_t aria_128_cbc_info = { JHD_TLS_CIPHER_ARIA_128_CBC, JHD_TLS_MODE_CBC, 128, "ARIA-128-CBC", 16, &aria_info };

static const jhd_tls_cipher_info_t aria_192_cbc_info = { JHD_TLS_CIPHER_ARIA_192_CBC, JHD_TLS_MODE_CBC, 192, "ARIA-192-CBC", 16, &aria_info };

static const jhd_tls_cipher_info_t aria_256_cbc_info = { JHD_TLS_CIPHER_ARIA_256_CBC, JHD_TLS_MODE_CBC, 256, "ARIA-256-CBC", 16, &aria_info };

static const jhd_tls_cipher_base_t gcm_aria_info = {
		JHD_TLS_CIPHER_ID_ARIA,
		sizeof(jhd_tls_gcm_context)+sizeof(jhd_tls_aria_context),
		cipher_gcm_init,
//        NULL,
//        NULL,
		NULL,
		NULL,
		NULL,
		NULL,
        (jhd_tls_cipher_setkey_enc_pt)jhd_tls_gcm_setkey_enc,
        (jhd_tls_cipher_setkey_enc_pt)jhd_tls_gcm_setkey_dec,
};



static const jhd_tls_cipher_info_t aria_128_gcm_info = { JHD_TLS_CIPHER_ARIA_128_GCM, JHD_TLS_MODE_GCM, 128, "ARIA-128-GCM", 16, &gcm_aria_info };

static const jhd_tls_cipher_info_t aria_192_gcm_info = { JHD_TLS_CIPHER_ARIA_192_GCM, JHD_TLS_MODE_GCM, 192, "ARIA-192-GCM", 16, &gcm_aria_info };

static const jhd_tls_cipher_info_t aria_256_gcm_info = { JHD_TLS_CIPHER_ARIA_256_GCM, JHD_TLS_MODE_GCM, 256, "ARIA-256-GCM", 16, &gcm_aria_info };
static const jhd_tls_cipher_base_t ccm_aria_info = {
		JHD_TLS_CIPHER_ID_ARIA,
		sizeof(jhd_tls_ccm_context)+sizeof(jhd_tls_aria_context),
		cipher_ccm_init,
//		NULL,
//        NULL,
		NULL,
		NULL,
		NULL,
		NULL,
        (jhd_tls_cipher_setkey_enc_pt)jhd_tls_ccm_setkey,
        (jhd_tls_cipher_setkey_dec_pt)jhd_tls_ccm_setkey,
};

static const jhd_tls_cipher_info_t aria_128_ccm_info = { JHD_TLS_CIPHER_ARIA_128_CCM, JHD_TLS_MODE_CCM, 128, "ARIA-128-CCM", 16, &ccm_aria_info };

static const jhd_tls_cipher_info_t aria_192_ccm_info = { JHD_TLS_CIPHER_ARIA_192_CCM, JHD_TLS_MODE_CCM, 192, "ARIA-192-CCM", 16, &ccm_aria_info };

static const jhd_tls_cipher_info_t aria_256_ccm_info = { JHD_TLS_CIPHER_ARIA_256_CCM, JHD_TLS_MODE_CCM, 256, "ARIA-256-CCM", 16, &ccm_aria_info };

static const jhd_tls_cipher_base_t des_info = {
		JHD_TLS_CIPHER_ID_DES,
		sizeof(jhd_tls_des_context),
		jhd_tls_cipher_size_init,
//		(jhd_tls_cipher_ecb_pt) jhd_tls_des_crypt_ecb,
//        (jhd_tls_cipher_cbc_pt) jhd_tls_des_crypt_cbc,
        (jhd_tls_cipher_ecb_encrypt_pt)jhd_tls_des_ecb_encrypt,
        (jhd_tls_cipher_ecb_decrypt_pt)jhd_tls_des_ecb_decrypt,
        (jhd_tls_cipher_cbc_encrypt_pt)jhd_tls_des_cbc_encrypt,
        (jhd_tls_cipher_cbc_decrypt_pt)jhd_tls_des_cbc_decrypt,
        (jhd_tls_cipher_setkey_enc_pt) jhd_tls_des_setkey_enc,
        (jhd_tls_cipher_setkey_dec_pt) jhd_tls_des_setkey_dec,
};

static const jhd_tls_cipher_info_t des_ecb_info = { JHD_TLS_CIPHER_DES_ECB, JHD_TLS_MODE_ECB, JHD_TLS_KEY_LENGTH_DES, "DES-ECB",8, &des_info };

static const jhd_tls_cipher_info_t des_cbc_info = { JHD_TLS_CIPHER_DES_CBC, JHD_TLS_MODE_CBC, JHD_TLS_KEY_LENGTH_DES, "DES-CBC",8, &des_info };

static const jhd_tls_cipher_base_t des_ede_info = {
		JHD_TLS_CIPHER_ID_DES,
		sizeof(jhd_tls_des3_context),
		jhd_tls_cipher_size_init,
//		(jhd_tls_cipher_ecb_pt) jhd_tls_des3_crypt_ecb,
//        (jhd_tls_cipher_cbc_pt) jhd_tls_des3_crypt_cbc,
        (jhd_tls_cipher_ecb_encrypt_pt)jhd_tls_des3_ecb_encrypt,
        (jhd_tls_cipher_ecb_decrypt_pt)jhd_tls_des3_ecb_decrypt,
        (jhd_tls_cipher_cbc_encrypt_pt)jhd_tls_des3_cbc_encrypt,
        (jhd_tls_cipher_cbc_decrypt_pt)jhd_tls_des3_cbc_decrypt,
        (jhd_tls_cipher_setkey_enc_pt) jhd_tls_des3_set2key_enc,
        (jhd_tls_cipher_setkey_dec_pt) jhd_tls_des3_set2key_dec,
};

static const jhd_tls_cipher_info_t des_ede_ecb_info = { JHD_TLS_CIPHER_DES_EDE_ECB, JHD_TLS_MODE_ECB, JHD_TLS_KEY_LENGTH_DES_EDE, "DES-EDE-ECB", 8,&des_ede_info };


static const jhd_tls_cipher_info_t des_ede_cbc_info = { JHD_TLS_CIPHER_DES_EDE_CBC, JHD_TLS_MODE_CBC, JHD_TLS_KEY_LENGTH_DES_EDE, "DES-EDE-CBC", 8,&des_ede_info };

static const jhd_tls_cipher_base_t des_ede3_info = {
		JHD_TLS_CIPHER_ID_3DES,
		sizeof(jhd_tls_des3_context),
		jhd_tls_cipher_size_init,
//		(jhd_tls_cipher_ecb_pt) jhd_tls_des3_crypt_ecb,
//        (jhd_tls_cipher_cbc_pt) jhd_tls_des3_crypt_cbc,
        (jhd_tls_cipher_ecb_encrypt_pt)jhd_tls_des3_ecb_encrypt,
        (jhd_tls_cipher_ecb_decrypt_pt)jhd_tls_des3_ecb_decrypt,
        (jhd_tls_cipher_cbc_encrypt_pt)jhd_tls_des3_cbc_encrypt,
        (jhd_tls_cipher_cbc_decrypt_pt)jhd_tls_des3_cbc_decrypt,
        (jhd_tls_cipher_setkey_enc_pt) jhd_tls_des3_set3key_enc,
        (jhd_tls_cipher_setkey_dec_pt) jhd_tls_des3_set3key_dec,
};

static const jhd_tls_cipher_info_t des_ede3_ecb_info = { JHD_TLS_CIPHER_DES_EDE3_ECB, JHD_TLS_MODE_ECB, JHD_TLS_KEY_LENGTH_DES_EDE3, "DES-EDE3-ECB",8,&des_ede3_info };

static const jhd_tls_cipher_info_t des_ede3_cbc_info = { JHD_TLS_CIPHER_DES_EDE3_CBC, JHD_TLS_MODE_CBC, JHD_TLS_KEY_LENGTH_DES_EDE3, "DES-EDE3-CBC",8,&des_ede3_info };


const jhd_tls_cipher_definition_t jhd_tls_cipher_definitions[] = {

        { JHD_TLS_CIPHER_AES_128_ECB, &aes_128_ecb_info },
        { JHD_TLS_CIPHER_AES_192_ECB, &aes_192_ecb_info },
        { JHD_TLS_CIPHER_AES_256_ECB, &aes_256_ecb_info },

        { JHD_TLS_CIPHER_AES_128_CBC, &aes_128_cbc_info },
        { JHD_TLS_CIPHER_AES_192_CBC, &aes_192_cbc_info },
        { JHD_TLS_CIPHER_AES_256_CBC, &aes_256_cbc_info },

        { JHD_TLS_CIPHER_AES_128_GCM, &aes_128_gcm_info },
        { JHD_TLS_CIPHER_AES_192_GCM, &aes_192_gcm_info },
        { JHD_TLS_CIPHER_AES_256_GCM, &aes_256_gcm_info },
        { JHD_TLS_CIPHER_AES_128_CCM, &aes_128_ccm_info },
        { JHD_TLS_CIPHER_AES_192_CCM, &aes_192_ccm_info },
        { JHD_TLS_CIPHER_AES_256_CCM, &aes_256_ccm_info },
        { JHD_TLS_CIPHER_CAMELLIA_128_ECB, &camellia_128_ecb_info },
        { JHD_TLS_CIPHER_CAMELLIA_192_ECB, &camellia_192_ecb_info },
        { JHD_TLS_CIPHER_CAMELLIA_256_ECB, &camellia_256_ecb_info },
        { JHD_TLS_CIPHER_CAMELLIA_128_CBC, &camellia_128_cbc_info },
        { JHD_TLS_CIPHER_CAMELLIA_192_CBC, &camellia_192_cbc_info },
        { JHD_TLS_CIPHER_CAMELLIA_256_CBC, &camellia_256_cbc_info },
        { JHD_TLS_CIPHER_CAMELLIA_128_GCM, &camellia_128_gcm_info },
        { JHD_TLS_CIPHER_CAMELLIA_192_GCM, &camellia_192_gcm_info },
        { JHD_TLS_CIPHER_CAMELLIA_256_GCM, &camellia_256_gcm_info },
        { JHD_TLS_CIPHER_CAMELLIA_128_CCM, &camellia_128_ccm_info },
        { JHD_TLS_CIPHER_CAMELLIA_192_CCM, &camellia_192_ccm_info },
        {JHD_TLS_CIPHER_CAMELLIA_256_CCM, &camellia_256_ccm_info },

        { JHD_TLS_CIPHER_ARIA_128_ECB, &aria_128_ecb_info },
        { JHD_TLS_CIPHER_ARIA_192_ECB, &aria_192_ecb_info },
        { JHD_TLS_CIPHER_ARIA_256_ECB, &aria_256_ecb_info },
        { JHD_TLS_CIPHER_ARIA_128_CBC, &aria_128_cbc_info },
        { JHD_TLS_CIPHER_ARIA_192_CBC, &aria_192_cbc_info },
        { JHD_TLS_CIPHER_ARIA_256_CBC, &aria_256_cbc_info },
        { JHD_TLS_CIPHER_ARIA_128_GCM, &aria_128_gcm_info },
        { JHD_TLS_CIPHER_ARIA_192_GCM, &aria_192_gcm_info },
        { JHD_TLS_CIPHER_ARIA_256_GCM, &aria_256_gcm_info },
        { JHD_TLS_CIPHER_ARIA_128_CCM, &aria_128_ccm_info },
        { JHD_TLS_CIPHER_ARIA_192_CCM, &aria_192_ccm_info },
        { JHD_TLS_CIPHER_ARIA_256_CCM, &aria_256_ccm_info },

        { JHD_TLS_CIPHER_DES_ECB, &des_ecb_info },
        { JHD_TLS_CIPHER_DES_EDE_ECB, &des_ede_ecb_info },
        { JHD_TLS_CIPHER_DES_EDE3_ECB, &des_ede3_ecb_info },
        { JHD_TLS_CIPHER_DES_CBC, &des_cbc_info },
        { JHD_TLS_CIPHER_DES_EDE_CBC, &des_ede_cbc_info },
        { JHD_TLS_CIPHER_DES_EDE3_CBC, &des_ede3_cbc_info },
        { JHD_TLS_CIPHER_NONE, NULL } };

#define NUM_CIPHERS ((sizeof(jhd_tls_cipher_definitions)) / (sizeof(jhd_tls_cipher_definitions[0])))
int jhd_tls_cipher_supported[NUM_CIPHERS];

void jhd_tls_ciphers_init(){
	uint32_t i ;
	for(i = 0 ;i < NUM_CIPHERS; ++i){
		jhd_tls_cipher_supported[i] = (int)jhd_tls_cipher_definitions[i].type;

	}
}

