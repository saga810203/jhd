#ifndef JHD_TLS_CERTS_H
#define JHD_TLS_CERTS_H

#include <stddef.h>
#include <jhd_config.h>

#ifdef JHD_CONFIG_INCLUDE_TEST_CERTS
extern const char   jhd_tls_test_cas_pem[];
extern const size_t jhd_tls_test_cas_pem_len;


/* List of all CA certificates, terminated by NULL */
extern const char * jhd_tls_test_cas[];
extern const size_t jhd_tls_test_cas_len[];

/*
 * Convenience for users who just want a certificate:
 * RSA by default, or ECDSA if RSA is not available
 */
extern const char * jhd_tls_test_ca_crt;
extern const size_t jhd_tls_test_ca_crt_len;
extern const char * jhd_tls_test_ca_key;
extern const size_t jhd_tls_test_ca_key_len;
extern const char * jhd_tls_test_ca_pwd;
extern const size_t jhd_tls_test_ca_pwd_len;
extern const char * jhd_tls_test_srv_crt;
extern const size_t jhd_tls_test_srv_crt_len;
extern const char * jhd_tls_test_srv_key;
extern const size_t jhd_tls_test_srv_key_len;
extern const char * jhd_tls_test_cli_crt;
extern const size_t jhd_tls_test_cli_crt_len;
extern const char * jhd_tls_test_cli_key;
extern const size_t jhd_tls_test_cli_key_len;


extern const char   jhd_tls_test_ca_crt_ec[];
extern const size_t jhd_tls_test_ca_crt_ec_len;
extern const char   jhd_tls_test_ca_key_ec[];
extern const size_t jhd_tls_test_ca_key_ec_len;
extern const char   jhd_tls_test_ca_pwd_ec[];
extern const size_t jhd_tls_test_ca_pwd_ec_len;
extern const char   jhd_tls_test_srv_crt_ec[];
extern const size_t jhd_tls_test_srv_crt_ec_len;
extern const char   jhd_tls_test_srv_key_ec[];
extern const size_t jhd_tls_test_srv_key_ec_len;
extern const char   jhd_tls_test_cli_crt_ec[];
extern const size_t jhd_tls_test_cli_crt_ec_len;
extern const char   jhd_tls_test_cli_key_ec[];
extern const size_t jhd_tls_test_cli_key_ec_len;



extern const char   jhd_tls_test_ca_crt_rsa[];
extern const size_t jhd_tls_test_ca_crt_rsa_len;
extern const char   jhd_tls_test_ca_key_rsa[];
extern const size_t jhd_tls_test_ca_key_rsa_len;
extern const char   jhd_tls_test_ca_pwd_rsa[];
extern const size_t jhd_tls_test_ca_pwd_rsa_len;
extern const char   jhd_tls_test_srv_crt_rsa[];
extern const size_t jhd_tls_test_srv_crt_rsa_len;
extern const char   jhd_tls_test_srv_key_rsa[];
extern const size_t jhd_tls_test_srv_key_rsa_len;
extern const char   jhd_tls_test_cli_crt_rsa[];
extern const size_t jhd_tls_test_cli_crt_rsa_len;
extern const char   jhd_tls_test_cli_key_rsa[];
extern const size_t jhd_tls_test_cli_key_rsa_len;
#endif



#endif /* certs.h */
