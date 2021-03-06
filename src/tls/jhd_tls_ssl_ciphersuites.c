#include <tls/jhd_tls_config.h>

#include <tls/jhd_tls_platform.h>

#include <tls/jhd_tls_ssl_ciphersuites.h>
#include <tls/jhd_tls_ssl.h>

#include <string.h>


const jhd_tls_ssl_ciphersuite_t supported_ciphersuites[] = {

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA", JHD_TLS_CIPHER_AES_128_CBC, &jhd_tls_sha1_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_1, JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},
        {JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA", JHD_TLS_CIPHER_AES_256_CBC, &jhd_tls_sha1_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_1, JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256", JHD_TLS_CIPHER_AES_128_CBC, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3, JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256", JHD_TLS_CIPHER_AES_128_GCM, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3, JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384", JHD_TLS_CIPHER_AES_256_CBC, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3, JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384", JHD_TLS_CIPHER_AES_256_GCM, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM, "TLS-ECDHE-ECDSA-WITH-AES-256-CCM", JHD_TLS_CIPHER_AES_256_CCM, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},
// unsupported ccm-8
//        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,"TLS-ECDHE-ECDSA-WITH-AES-256-CCM-8", JHD_TLS_CIPHER_AES_256_CCM, &jhd_tls_sha256_info, JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
//                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_CIPHERSUITE_SHORT_TAG },
        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM, "TLS-ECDHE-ECDSA-WITH-AES-128-CCM", JHD_TLS_CIPHER_AES_128_CCM,&jhd_tls_sha256_info, JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},
// unsupported ccm-8
//        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,"TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8", JHD_TLS_CIPHER_AES_128_CCM, &jhd_tls_sha256_info, JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
//                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_CIPHERSUITE_SHORT_TAG },

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256, "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256", JHD_TLS_CIPHER_CAMELLIA_128_CBC,&jhd_tls_sha256_info, JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_1,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384, "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA384", JHD_TLS_CIPHER_CAMELLIA_256_CBC,&jhd_tls_sha384_info, JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_1,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},
        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256, "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-GCM-SHA256", JHD_TLS_CIPHER_CAMELLIA_128_GCM,&jhd_tls_sha256_info, JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384, "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-GCM-SHA384", JHD_TLS_CIPHER_CAMELLIA_256_GCM,&jhd_tls_sha384_info, JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, "TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA", JHD_TLS_CIPHER_DES_EDE3_CBC, &jhd_tls_sha1_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_1,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA", JHD_TLS_CIPHER_AES_128_CBC, &jhd_tls_sha1_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_1,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},
        { JHD_TLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,"TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA", JHD_TLS_CIPHER_AES_256_CBC, &jhd_tls_sha1_info, JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_1,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256", JHD_TLS_CIPHER_AES_128_CBC, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256", JHD_TLS_CIPHER_AES_128_GCM, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384", JHD_TLS_CIPHER_AES_256_CBC, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384", JHD_TLS_CIPHER_AES_256_GCM, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256, "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256", JHD_TLS_CIPHER_CAMELLIA_128_CBC, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_1,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384, "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA384", JHD_TLS_CIPHER_CAMELLIA_256_CBC, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_1,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256, "TLS-ECDHE-RSA-WITH-CAMELLIA-128-GCM-SHA256", JHD_TLS_CIPHER_CAMELLIA_128_GCM, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384, "TLS-ECDHE-RSA-WITH-CAMELLIA-256-GCM-SHA384", JHD_TLS_CIPHER_CAMELLIA_256_GCM, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA", JHD_TLS_CIPHER_DES_EDE3_CBC, &jhd_tls_sha1_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_1,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_AES_256_GCM_SHA384, "TLS-RSA-WITH-AES-256-GCM-SHA384", JHD_TLS_CIPHER_AES_256_GCM, &jhd_tls_sha384_info, JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
        		JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_AES_128_GCM_SHA256, "TLS-RSA-WITH-AES-128-GCM-SHA256", JHD_TLS_CIPHER_AES_128_GCM, &jhd_tls_sha256_info, JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
        		JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_AES_128_CBC_SHA256, "TLS-RSA-WITH-AES-128-CBC-SHA256", JHD_TLS_CIPHER_AES_128_CBC, &jhd_tls_sha256_info, JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
        		JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_AES_256_CBC_SHA256, "TLS-RSA-WITH-AES-256-CBC-SHA256", JHD_TLS_CIPHER_AES_256_CBC, &jhd_tls_sha256_info, JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
        		JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_AES_128_CBC_SHA, "TLS-RSA-WITH-AES-128-CBC-SHA", JHD_TLS_CIPHER_AES_128_CBC, &jhd_tls_sha1_info, JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
        		JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_0,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_AES_256_CBC_SHA, "TLS-RSA-WITH-AES-256-CBC-SHA", JHD_TLS_CIPHER_AES_256_CBC, &jhd_tls_sha1_info, JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
        		JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_0,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_AES_256_CCM, "TLS-RSA-WITH-AES-256-CCM", JHD_TLS_CIPHER_AES_256_CCM, &jhd_tls_sha256_info, JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
        		JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},
// unsupported ccm-8
//        { JHD_TLS_TLS_RSA_WITH_AES_256_CCM_8, "TLS-RSA-WITH-AES-256-CCM-8",JHD_TLS_CIPHER_AES_256_CCM, &jhd_tls_sha256_info, JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
//                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_CIPHERSUITE_SHORT_TAG },
        { JHD_TLS_TLS_RSA_WITH_AES_128_CCM, "TLS-RSA-WITH-AES-128-CCM", JHD_TLS_CIPHER_AES_128_CCM, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},
// unsupported ccm-8
//        { JHD_TLS_TLS_RSA_WITH_AES_128_CCM_8, "TLS-RSA-WITH-AES-128-CCM-8",JHD_TLS_CIPHER_AES_128_CCM, &jhd_tls_sha256_info, JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
//                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_CIPHERSUITE_SHORT_TAG },

        { JHD_TLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256, "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256", JHD_TLS_CIPHER_CAMELLIA_128_CBC, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256, "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256", JHD_TLS_CIPHER_CAMELLIA_256_CBC, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA, "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA", JHD_TLS_CIPHER_CAMELLIA_128_CBC, &jhd_tls_sha1_info,JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_0,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA, "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA", JHD_TLS_CIPHER_CAMELLIA_256_CBC, &jhd_tls_sha1_info,JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_0,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256, "TLS-RSA-WITH-CAMELLIA-128-GCM-SHA256", JHD_TLS_CIPHER_CAMELLIA_128_GCM, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384, "TLS-RSA-WITH-CAMELLIA-256-GCM-SHA384", JHD_TLS_CIPHER_CAMELLIA_256_GCM, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS-RSA-WITH-3DES-EDE-CBC-SHA", JHD_TLS_CIPHER_DES_EDE3_CBC, &jhd_tls_sha1_info, JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
        		JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_0,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_ARIA_256_GCM_SHA384, "TLS-RSA-WITH-ARIA-256-GCM-SHA384", JHD_TLS_CIPHER_ARIA_256_GCM, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_ARIA_256_CBC_SHA384, "TLS-RSA-WITH-ARIA-256-CBC-SHA384", JHD_TLS_CIPHER_ARIA_256_CBC, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},


        { JHD_TLS_TLS_RSA_WITH_ARIA_128_GCM_SHA256, "TLS-RSA-WITH-ARIA-128-GCM-SHA256", JHD_TLS_CIPHER_ARIA_128_GCM, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_RSA_WITH_ARIA_128_CBC_SHA256, "TLS-RSA-WITH-ARIA-128-CBC-SHA256", JHD_TLS_CIPHER_ARIA_128_CBC, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384, "TLS-ECDHE-RSA-WITH-ARIA-256-GCM-SHA384", JHD_TLS_CIPHER_ARIA_256_GCM, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384, "TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384", JHD_TLS_CIPHER_ARIA_256_CBC, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256, "TLS-ECDHE-RSA-WITH-ARIA-128-GCM-SHA256", JHD_TLS_CIPHER_ARIA_128_GCM, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256, "TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256", JHD_TLS_CIPHER_ARIA_128_CBC, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_ECDHE_RSA,&jhd_tls_rsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384, "TLS-ECDHE-ECDSA-WITH-ARIA-256-GCM-SHA384", JHD_TLS_CIPHER_ARIA_256_GCM, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384, "TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384", JHD_TLS_CIPHER_ARIA_256_CBC, &jhd_tls_sha384_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},


        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256, "TLS-ECDHE-ECDSA-WITH-ARIA-128-GCM-SHA256", JHD_TLS_CIPHER_ARIA_128_GCM, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},

        { JHD_TLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256, "TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256", JHD_TLS_CIPHER_ARIA_128_CBC, &jhd_tls_sha256_info,JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA,&jhd_tls_ecdsa_info,
                JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,JHD_TLS_SSL_MAJOR_VERSION_3, JHD_TLS_SSL_MINOR_VERSION_3,/*0*/},
        { 0, "", JHD_TLS_CIPHER_NONE, NULL, JHD_TLS_KEY_EXCHANGE_NONE, NULL,0, 0, 0, 0, /*0*/ }
};







#if !defined(JHD_TLS_INLINE)


const jhd_tls_pk_info_t* jhd_tls_ssl_get_ciphersuite_sig_pk_alg(const jhd_tls_ssl_ciphersuite_t *info) {
	return info->pk_info;
}

const jhd_tls_pk_info_t* jhd_tls_ssl_get_ciphersuite_sig_alg(const jhd_tls_ssl_ciphersuite_t *info) {
	return info->pk_info;
}

int jhd_tls_ssl_ciphersuite_uses_ec(const jhd_tls_ssl_ciphersuite_t *info) {
	return  (info->key_exchange)== JHD_TLS_KEY_EXCHANGE_ECDHE_RSA || (info->key_exchange)== JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA;
}
#endif
const jhd_tls_ssl_ciphersuite_t *jhd_tls_ssl_ciphersuite_from_string(const char *ciphersuite_name) {
	const jhd_tls_ssl_ciphersuite_t *cur = supported_ciphersuites;
	if ( NULL == ciphersuite_name)
		return ( NULL);

	while (cur->id != 0) {
		if (0 == strcmp(cur->name, ciphersuite_name))
			return (cur);
		cur++;
	}

	return ( NULL);
}

const jhd_tls_ssl_ciphersuite_t *jhd_tls_ssl_ciphersuite_from_id(int ciphersuite) {
	const jhd_tls_ssl_ciphersuite_t *cur = supported_ciphersuites;

	while (cur->id != 0) {
		if (cur->id == ciphersuite)
			return (cur);

		cur++;
	}

	return ( NULL);
}

const char *jhd_tls_ssl_get_ciphersuite_name(const int ciphersuite_id) {
	const jhd_tls_ssl_ciphersuite_t *cur;

	cur = jhd_tls_ssl_ciphersuite_from_id(ciphersuite_id);

	if (cur == NULL)
		return ("unknown");

	return (cur->name);
}

int jhd_tls_ssl_get_ciphersuite_id(const char *ciphersuite_name) {
	const jhd_tls_ssl_ciphersuite_t *cur;

	cur = jhd_tls_ssl_ciphersuite_from_string(ciphersuite_name);

	if (cur == NULL)
		return (0);

	return (cur->id);
}



