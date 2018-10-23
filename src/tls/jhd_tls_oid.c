#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>

#include <tls/jhd_tls_oid.h>
#include <tls/jhd_tls_rsa.h>

#include <stdio.h>
#include <string.h>

#include <tls/jhd_tls_platform.h>

#include <tls/jhd_tls_x509.h>
#include <tls/jhd_tls_md_internal.h>
#include <tls/jhd_tls_pk_internal.h>

/*
 * Macro to automatically add the size of #define'd OIDs
 */
#define ADD_LEN(s)      s, JHD_TLS_OID_SIZE(s)


/*
#define FN_OID_TYPED_FROM_ASN1( TYPE_T, NAME, LIST )                        \
static const TYPE_T * oid_ ## NAME ## _from_asn1( const jhd_tls_asn1_buf *oid )     \
{                                                                           \
    const TYPE_T *p = LIST;                                                 \
    const jhd_tls_oid_descriptor_t *cur = (const jhd_tls_oid_descriptor_t *) p;             \
    if( p == NULL || oid == NULL ) return( NULL );                          \
    while( cur->asn1 != NULL ) {                                            \
        if( cur->asn1_len == oid->len &&                                    \
            memcmp( cur->asn1, oid->p, oid->len ) == 0 ) {                  \
            return( p );                                                    \
        }                                                                   \
        p++;                                                                \
        cur = (const jhd_tls_oid_descriptor_t *) p;                                 \
    }                                                                       \
    return( NULL );                                                         \
}

#define FN_OID_GET_DESCRIPTOR_ATTR1(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1) \
int FN_NAME( const jhd_tls_asn1_buf *oid, ATTR1_TYPE * ATTR1 )                  \
{                                                                       \
    const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1( oid );        \
    if( data == NULL ) return( JHD_TLS_ERR_OID_NOT_FOUND );            \
    *ATTR1 = data->descriptor.ATTR1;                                    \
    return( 0 );                                                        \
}

#define FN_OID_GET_ATTR1(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1) \
int FN_NAME( const jhd_tls_asn1_buf *oid, ATTR1_TYPE * ATTR1 )                  \
{                                                                       \
    const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1( oid );        \
    if( data == NULL ) return( JHD_TLS_ERR_OID_NOT_FOUND );            \
    *ATTR1 = data->ATTR1;                                               \
    return( 0 );                                                        \
}

#define FN_OID_GET_ATTR2(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1,     \
                         ATTR2_TYPE, ATTR2)                                 \
int FN_NAME( const jhd_tls_asn1_buf *oid, ATTR1_TYPE * ATTR1, ATTR2_TYPE * ATTR2 )  \
{                                                                           \
    const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1( oid );            \
    if( data == NULL ) return( JHD_TLS_ERR_OID_NOT_FOUND );                \
    *ATTR1 = data->ATTR1;                                                   \
    *ATTR2 = data->ATTR2;                                                   \
    return( 0 );                                                            \
}

#define FN_OID_GET_OID_BY_ATTR1(FN_NAME, TYPE_T, LIST, ATTR1_TYPE, ATTR1)   \
int FN_NAME(const ATTR1_TYPE ATTR1, const char **oid, size_t *olen )             \
{                                                                           \
    const TYPE_T *cur = LIST;                                               \
    while( cur->descriptor.asn1 != NULL ) {                                 \
        if( cur->ATTR1 == ATTR1 ) {                                         \
            *oid = cur->descriptor.asn1;                                    \
            *olen = cur->descriptor.asn1_len;                               \
            return( 0 );                                                    \
        }                                                                   \
        cur++;                                                              \
    }                                                                       \
    return( JHD_TLS_ERR_OID_NOT_FOUND );                                   \
}
#define FN_OID_GET_OID_BY_ATTR2(FN_NAME, TYPE_T, LIST, ATTR1_TYPE, ATTR1,   \
                                ATTR2_TYPE, ATTR2)                          \
int FN_NAME( ATTR1_TYPE ATTR1, ATTR2_TYPE ATTR2, const char **oid ,         \
             size_t *olen )                                                 \
{                                                                           \
    const TYPE_T *cur = LIST;                                               \
    while( cur->descriptor.asn1 != NULL ) {                                 \
        if( cur->ATTR1 == ATTR1 && cur->ATTR2 == ATTR2 ) {                  \
            *oid = cur->descriptor.asn1;                                    \
            *olen = cur->descriptor.asn1_len;                               \
            return( 0 );                                                    \
        }                                                                   \
        cur++;                                                              \
    }                                                                       \
    return( JHD_TLS_ERR_OID_NOT_FOUND );                                   \
}
*/

/*
 * For X520 attribute types
 */
typedef struct {
	jhd_tls_oid_descriptor_t descriptor;
	const char *short_name;
} oid_x520_attr_t;

static const oid_x520_attr_t oid_x520_attr_type[] = {
		{ { ADD_LEN(JHD_TLS_OID_AT_CN), "id-at-commonName", "Common Name" }, "CN", },
		{ { ADD_LEN(JHD_TLS_OID_AT_COUNTRY), "id-at-countryName", "Country" }, "C", },
		{ { ADD_LEN(JHD_TLS_OID_AT_LOCALITY), "id-at-locality", "Locality" }, "L", },
		{ { ADD_LEN(JHD_TLS_OID_AT_STATE), "id-at-state", "State" }, "ST", },
		{ { ADD_LEN(JHD_TLS_OID_AT_ORGANIZATION), "id-at-organizationName", "Organization" },"O", },
		{ { ADD_LEN(JHD_TLS_OID_AT_ORG_UNIT), "id-at-organizationalUnitName", "Org Unit" }, "OU", },
		{ { ADD_LEN(JHD_TLS_OID_PKCS9_EMAIL),"emailAddress", "E-mail address" }, "emailAddress", },
		{ { ADD_LEN(JHD_TLS_OID_AT_SERIAL_NUMBER), "id-at-serialNumber", "Serial number" },"serialNumber", },
		{ { ADD_LEN(JHD_TLS_OID_AT_POSTAL_ADDRESS), "id-at-postalAddress", "Postal address" }, "postalAddress", },
		{ { ADD_LEN(JHD_TLS_OID_AT_POSTAL_CODE), "id-at-postalCode", "Postal code" }, "postalCode", },
		{ { ADD_LEN(JHD_TLS_OID_AT_SUR_NAME), "id-at-surName", "Surname" },"SN", },
		{ { ADD_LEN(JHD_TLS_OID_AT_GIVEN_NAME), "id-at-givenName", "Given name" }, "GN", },
		{ { ADD_LEN(JHD_TLS_OID_AT_INITIALS), "id-at-initials","Initials" }, "initials", },
		{ { ADD_LEN(JHD_TLS_OID_AT_GENERATION_QUALIFIER), "id-at-generationQualifier", "Generation qualifier" },"generationQualifier", },
		{ { ADD_LEN(JHD_TLS_OID_AT_TITLE), "id-at-title", "Title" }, "title", },
		{ { ADD_LEN(JHD_TLS_OID_AT_DN_QUALIFIER),"id-at-dnQualifier", "Distinguished Name qualifier" }, "dnQualifier", },
		{ { ADD_LEN(JHD_TLS_OID_AT_PSEUDONYM), "id-at-pseudonym", "Pseudonym" },"pseudonym", },
		{ { ADD_LEN(JHD_TLS_OID_DOMAIN_COMPONENT), "id-domainComponent", "Domain component" }, "DC", },
		{ { ADD_LEN(JHD_TLS_OID_AT_UNIQUE_IDENTIFIER), "id-at-uniqueIdentifier", "Unique Identifier" }, "uniqueIdentifier", },
		{ { NULL, 0, NULL, NULL },NULL, }
};

/*FN_OID_TYPED_FROM_ASN1(oid_x520_attr_t, x520_attr, oid_x520_attr_type)*/

static const oid_x520_attr_t * oid_x520_attr_from_asn1(const jhd_tls_asn1_buf *oid) {
	const oid_x520_attr_t *p = oid_x520_attr_type;
	const jhd_tls_oid_descriptor_t *cur = (const jhd_tls_oid_descriptor_t *) &(p->descriptor);
	while (cur->asn1) {
		if (cur->asn1_len == oid->len && memcmp(cur->asn1, oid->p, oid->len) == 0) {
			return (p);
		}
		p++;
		cur =  (const jhd_tls_oid_descriptor_t *) &(p->descriptor);
	}
	return NULL;
}

/*FN_OID_GET_ATTR1(jhd_tls_oid_get_attr_short_name, oid_x520_attr_t, x520_attr, const char *, short_name)*/

int jhd_tls_oid_get_attr_short_name(const jhd_tls_asn1_buf *oid, const char ** short_name) {
	const oid_x520_attr_t *data = oid_x520_attr_from_asn1(oid);
	if (data == NULL)
		return JHD_ERROR;
	*short_name = data->short_name;
	return JHD_OK;
}

/*
 * For X509 extensions
 */
typedef struct {
	jhd_tls_oid_descriptor_t descriptor;
	int ext_type;
} oid_x509_ext_t;

static const oid_x509_ext_t oid_x509_ext[] = {
		{ { ADD_LEN(JHD_TLS_OID_BASIC_CONSTRAINTS), "id-ce-basicConstraints", "Basic Constraints" },JHD_TLS_X509_EXT_BASIC_CONSTRAINTS, },
		{ { ADD_LEN(JHD_TLS_OID_KEY_USAGE), "id-ce-keyUsage", "Key Usage" },JHD_TLS_X509_EXT_KEY_USAGE, },
		{ { ADD_LEN(JHD_TLS_OID_EXTENDED_KEY_USAGE), "id-ce-extKeyUsage", "Extended Key Usage" },JHD_TLS_X509_EXT_EXTENDED_KEY_USAGE, },
		{ { ADD_LEN(JHD_TLS_OID_SUBJECT_ALT_NAME), "id-ce-subjectAltName", "Subject Alt Name" },JHD_TLS_X509_EXT_SUBJECT_ALT_NAME, },
		{ { ADD_LEN(JHD_TLS_OID_NS_CERT_TYPE), "id-netscape-certtype", "Netscape Certificate Type" },JHD_TLS_X509_EXT_NS_CERT_TYPE, },
		{ { NULL, 0, NULL, NULL }, 0, },
};

/*FN_OID_TYPED_FROM_ASN1(oid_x509_ext_t, x509_ext, oid_x509_ext)*/
static const oid_x509_ext_t * oid_x509_ext_from_asn1(const jhd_tls_asn1_buf *oid) {
	const oid_x509_ext_t *p = oid_x509_ext;
	const jhd_tls_oid_descriptor_t *cur = (const jhd_tls_oid_descriptor_t *) &(p->descriptor);
	while (cur->asn1 != NULL) {
		if (cur->asn1_len == oid->len && memcmp(cur->asn1, oid->p, oid->len) == 0) {
			return (p);
		}
		p++;
		cur = (const jhd_tls_oid_descriptor_t *) &(p->descriptor);
	}
	return ( NULL);
}

/*FN_OID_GET_ATTR1(jhd_tls_oid_get_x509_ext_type, oid_x509_ext_t, x509_ext, int, ext_type)*/
void jhd_tls_oid_get_x509_ext_type(const jhd_tls_asn1_buf *oid, int * ext_type) {
	const oid_x509_ext_t *data = oid_x509_ext_from_asn1(oid);
	if(data){
		*ext_type = data->ext_type;
	}else{
		*ext_type = 0;
	}
}

static const jhd_tls_oid_descriptor_t oid_ext_key_usage[] = {
		{ ADD_LEN(JHD_TLS_OID_SERVER_AUTH), "id-kp-serverAuth", "TLS Web Server Authentication" },
		{ ADD_LEN(JHD_TLS_OID_CLIENT_AUTH), "id-kp-clientAuth", "TLS Web Client Authentication" },
		{ ADD_LEN(JHD_TLS_OID_CODE_SIGNING), "id-kp-codeSigning","Code Signing" },
		{ ADD_LEN(JHD_TLS_OID_EMAIL_PROTECTION), "id-kp-emailProtection", "E-mail Protection" },
		{ ADD_LEN(JHD_TLS_OID_TIME_STAMPING),  "id-kp-timeStamping", "Time Stamping" },
		{ ADD_LEN(JHD_TLS_OID_OCSP_SIGNING), "id-kp-OCSPSigning", "OCSP Signing" },
		{ NULL, 0, NULL, NULL },
};

/*FN_OID_TYPED_FROM_ASN1(jhd_tls_oid_descriptor_t, ext_key_usage, oid_ext_key_usage)*/

static const jhd_tls_oid_descriptor_t * oid_ext_key_usage_from_asn1(const jhd_tls_asn1_buf *oid) {
	const jhd_tls_oid_descriptor_t *cur = oid_ext_key_usage;
	while (cur->asn1 != NULL) {
		if (cur->asn1_len == oid->len && memcmp(cur->asn1, oid->p, oid->len) == 0) {
			return (cur);
		}
		cur++;
	}
	return ( NULL);
}

/*FN_OID_GET_ATTR1(jhd_tls_oid_get_extended_key_usage, jhd_tls_oid_descriptor_t, ext_key_usage, const char *, description)*/
void jhd_tls_oid_get_extended_key_usage(const jhd_tls_asn1_buf *oid,const char ** description) {
	const jhd_tls_oid_descriptor_t *data = oid_ext_key_usage_from_asn1(oid);
	if (data)
		*description = data->description;
	else
		*description = NULL;
}

/*
 * For SignatureAlgorithmIdentifier
 */
typedef struct {
	jhd_tls_oid_descriptor_t descriptor;
	const jhd_tls_md_info_t *md_info;
	const jhd_tls_pk_info_t *pk_info;
} oid_sig_alg_t;

static const oid_sig_alg_t oid_sig_alg[] = {
		{ { ADD_LEN(JHD_TLS_OID_PKCS1_MD5), "md5WithRSAEncryption", "RSA with MD5" }, &jhd_tls_md5_info, &jhd_tls_rsa_info, },
		{ { ADD_LEN(JHD_TLS_OID_PKCS1_SHA1), "sha-1WithRSAEncryption", "RSA with SHA1" }, &jhd_tls_sha1_info, &jhd_tls_rsa_info, },
		{ { ADD_LEN(JHD_TLS_OID_PKCS1_SHA224),"sha224WithRSAEncryption", "RSA with SHA-224" }, &jhd_tls_sha224_info, &jhd_tls_rsa_info, },
		{ { ADD_LEN(JHD_TLS_OID_PKCS1_SHA256),"sha256WithRSAEncryption", "RSA with SHA-256" }, &jhd_tls_sha256_info, &jhd_tls_rsa_info, },
		{ { ADD_LEN(JHD_TLS_OID_PKCS1_SHA384),"sha384WithRSAEncryption", "RSA with SHA-384" }, &jhd_tls_sha384_info, &jhd_tls_rsa_info, },
		{ { ADD_LEN(JHD_TLS_OID_PKCS1_SHA512),"sha512WithRSAEncryption", "RSA with SHA-512" }, &jhd_tls_sha512_info, &jhd_tls_rsa_info, },
		{ { ADD_LEN(JHD_TLS_OID_RSA_SHA_OBS),"sha-1WithRSAEncryption", "RSA with SHA1" }, &jhd_tls_sha1_info, &jhd_tls_rsa_info, },
		{ { ADD_LEN(JHD_TLS_OID_ECDSA_SHA1), "ecdsa-with-SHA1","ECDSA with SHA1" }, &jhd_tls_sha1_info, &jhd_tls_ecdsa_info, },
		{ { ADD_LEN(JHD_TLS_OID_ECDSA_SHA224), "ecdsa-with-SHA224", "ECDSA with SHA224" },&jhd_tls_sha224_info, &jhd_tls_ecdsa_info, },
		{ { ADD_LEN(JHD_TLS_OID_ECDSA_SHA256), "ecdsa-with-SHA256", "ECDSA with SHA256" }, &jhd_tls_sha256_info,&jhd_tls_ecdsa_info, },
		{ { ADD_LEN(JHD_TLS_OID_ECDSA_SHA384), "ecdsa-with-SHA384", "ECDSA with SHA384" }, &jhd_tls_sha384_info, &jhd_tls_ecdsa_info, },
		{ { ADD_LEN(JHD_TLS_OID_ECDSA_SHA512), "ecdsa-with-SHA512", "ECDSA with SHA512" }, &jhd_tls_sha512_info, &jhd_tls_ecdsa_info, },
		{ { NULL, 0, NULL, NULL },NULL, NULL, },
};

/*FN_OID_TYPED_FROM_ASN1(oid_sig_alg_t, sig_alg, oid_sig_alg)*/

static const oid_sig_alg_t * oid_sig_alg_from_asn1(const jhd_tls_asn1_buf *oid) {
	const oid_sig_alg_t *p = oid_sig_alg;
	const jhd_tls_oid_descriptor_t *cur = &p->descriptor;
	while (cur->asn1 != NULL) {
		if (cur->asn1_len == oid->len && memcmp(cur->asn1, oid->p, oid->len) == 0) {
			return (p);
		}
		p++;
		cur =  &p->descriptor;
	}
	return ( NULL);
}

/*FN_OID_GET_DESCRIPTOR_ATTR1(jhd_tls_oid_get_sig_alg_desc, oid_sig_alg_t, sig_alg, const char *, description)*/

void jhd_tls_oid_get_sig_alg_desc(const jhd_tls_asn1_buf *oid,const char ** description) {
	const oid_sig_alg_t *data = oid_sig_alg_from_asn1(oid);
	if (data)
		*description = data->descriptor.description;
	else
		*description = NULL;
}

/*FN_OID_GET_ATTR2(jhd_tls_oid_get_sig_alg, oid_sig_alg_t, sig_alg, jhd_tls_md_info_t *, md_info, jhd_tls_pk_type_t, pk_alg)*/

void jhd_tls_oid_get_sig_alg(const jhd_tls_asn1_buf *oid, const jhd_tls_md_info_t ** md_info,const jhd_tls_pk_info_t **pk_info) {
	const oid_sig_alg_t *data = oid_sig_alg_from_asn1(oid);
	if (data) {
		*md_info = data->md_info;
		*pk_info = data->pk_info;
	}else{
		*md_info = NULL;
		*pk_info = NULL;
	}
}

/*FN_OID_GET_OID_BY_ATTR2(jhd_tls_oid_get_oid_by_sig_alg, oid_sig_alg_t, oid_sig_alg, jhd_tls_pk_type_t, pk_alg, jhd_tls_md_info_t *, md_info)*/

int jhd_tls_oid_get_oid_by_sig_alg(const jhd_tls_pk_info_t *pk_info, jhd_tls_md_info_t * md_info, const char **oid, size_t *olen) {
	const oid_sig_alg_t *cur = oid_sig_alg;
	while (cur->descriptor.asn1) {
		if (cur->pk_info == pk_info && cur->md_info == md_info) {
			*oid = cur->descriptor.asn1;
			*olen = cur->descriptor.asn1_len;
			return JHD_OK;
		}
		cur++;
	}
	return JHD_ERROR;
}

/*
 * For PublicKeyInfo (PKCS1, RFC 5480)
 */
typedef struct {
	jhd_tls_oid_descriptor_t descriptor;
	const jhd_tls_pk_info_t *pk_info;
} oid_pk_alg_t;

//static const oid_pk_alg_t oid_pk_alg[] = {
//		{ { ADD_LEN(JHD_TLS_OID_PKCS1_RSA), "rsaEncryption", "RSA" }, &jhd_tls_rsa_info, },
//		{ { NULL, 0, NULL, NULL },NULL, },
//};

static const oid_pk_alg_t oid_pk_alg[]={
		{ { ADD_LEN(JHD_TLS_OID_PKCS1_RSA), "rsaEncryption", "RSA" }, &jhd_tls_rsa_info, },
		{ { ADD_LEN( JHD_TLS_OID_EC_ALG_UNRESTRICTED ),  "id-ecPublicKey",   "Generic EC key" },&jhd_tls_ecdsa_info,},
};


/*FN_OID_TYPED_FROM_ASN1(oid_pk_alg_t, pk_alg, oid_pk_alg)*/

static const oid_pk_alg_t * oid_pk_alg_from_asn1(const jhd_tls_asn1_buf *oid){
//	const oid_pk_alg_t *p = oid_pk_alg;
//	const jhd_tls_oid_descriptor_t *cur = (const jhd_tls_oid_descriptor_t *) p;
//	if (p == NULL || oid == NULL)
//		return ( NULL);
//	while (cur->asn1 != NULL) {
//		if (cur->asn1_len == oid->len && memcmp(cur->asn1, oid->p, oid->len) == 0) {
//			return (p);
//		}
//		p++;
//		cur = (const jhd_tls_oid_descriptor_t *) p;
//	}
//	return ( NULL);
	return ((oid_pk_alg[0].descriptor.asn1_len == oid->len) && (memcmp(oid_pk_alg[0].descriptor.asn1,oid->p,oid->len) == 0))?&oid_pk_alg[0]:
					(((oid_pk_alg[1].descriptor.asn1_len == oid->len) && (memcmp(oid_pk_alg[1].descriptor.asn1,oid->p,oid->len) == 0))?&oid_pk_alg[1]:NULL);
}

//JHD_TLS_ERR_OID_NOT_FOUND

/*FN_OID_GET_ATTR1(jhd_tls_oid_get_pk_alg, oid_pk_alg_t, pk_alg, jhd_tls_pk_type_t, pk_alg)*/
void jhd_tls_oid_get_pk_alg(const jhd_tls_asn1_buf *oid,const jhd_tls_pk_info_t **pk_info) {
	const oid_pk_alg_t *data = oid_pk_alg_from_asn1(oid);
	if (data == NULL){
		*pk_info = NULL;
	}else{
		*pk_info = data->pk_info;
	}
}

/*FN_OID_GET_OID_BY_ATTR1(jhd_tls_oid_get_oid_by_pk_alg, oid_pk_alg_t, oid_pk_alg, jhd_tls_pk_type_t, pk_alg)*/
void jhd_tls_oid_get_oid_by_pk_alg(const jhd_tls_pk_info_t *pk_info, const char **oid, size_t *olen) {
	if(oid_pk_alg[0].pk_info == pk_info){
					*oid = oid_pk_alg[0].descriptor.asn1;
					*olen = oid_pk_alg[0].descriptor.asn1_len;

	}else if(oid_pk_alg[1].pk_info == pk_info){
						*oid = oid_pk_alg[1].descriptor.asn1;
						*olen = oid_pk_alg[1].descriptor.asn1_len;

	}else{
		*oid = NULL;
		*olen = 0;
	}
}

/*
 * For namedCurve (RFC 5480)
 */
typedef struct {
	jhd_tls_oid_descriptor_t descriptor;
	jhd_tls_ecp_group_id grp_id;
} oid_ecp_grp_t;

static const oid_ecp_grp_t oid_ecp_grp[] = {
        { { ADD_LEN(JHD_TLS_OID_EC_GRP_SECP192R1), "secp192r1", "secp192r1" }, JHD_TLS_ECP_DP_SECP192R1, },
        { { ADD_LEN(JHD_TLS_OID_EC_GRP_SECP224R1), "secp224r1", "secp224r1" }, JHD_TLS_ECP_DP_SECP224R1, },
        { { ADD_LEN(JHD_TLS_OID_EC_GRP_SECP256R1), "secp256r1", "secp256r1" }, JHD_TLS_ECP_DP_SECP256R1, },
        { { ADD_LEN(JHD_TLS_OID_EC_GRP_SECP384R1), "secp384r1", "secp384r1" }, JHD_TLS_ECP_DP_SECP384R1, },
        { { ADD_LEN(JHD_TLS_OID_EC_GRP_SECP521R1), "secp521r1", "secp521r1" }, JHD_TLS_ECP_DP_SECP521R1, },
        { { ADD_LEN(JHD_TLS_OID_EC_GRP_SECP192K1), "secp192k1", "secp192k1" }, JHD_TLS_ECP_DP_SECP192K1, },
        { { ADD_LEN(JHD_TLS_OID_EC_GRP_SECP224K1), "secp224k1", "secp224k1" }, JHD_TLS_ECP_DP_SECP224K1, },
        { { ADD_LEN(JHD_TLS_OID_EC_GRP_SECP256K1), "secp256k1", "secp256k1" }, JHD_TLS_ECP_DP_SECP256K1, },
        { { ADD_LEN(JHD_TLS_OID_EC_GRP_BP256R1), "brainpoolP256r1", "brainpool256r1" }, JHD_TLS_ECP_DP_BP256R1, },
        { { ADD_LEN(JHD_TLS_OID_EC_GRP_BP384R1), "brainpoolP384r1", "brainpool384r1" }, JHD_TLS_ECP_DP_BP384R1, },
        { { ADD_LEN(JHD_TLS_OID_EC_GRP_BP512R1), "brainpoolP512r1", "brainpool512r1" }, JHD_TLS_ECP_DP_BP512R1, },
        { { NULL, 0, NULL, NULL }, JHD_TLS_ECP_DP_NONE, }, };

/*FN_OID_TYPED_FROM_ASN1(oid_ecp_grp_t, grp_id, oid_ecp_grp)*/
static const oid_ecp_grp_t * oid_grp_id_from_asn1(const jhd_tls_asn1_buf *oid) {
	const oid_ecp_grp_t *p = oid_ecp_grp;
	const jhd_tls_oid_descriptor_t *cur = &p->descriptor;
	while (cur->asn1 != NULL) {
		if (cur->asn1_len == oid->len && memcmp(cur->asn1, oid->p, oid->len) == 0) {
			return (p);
		}
		p++;
		cur = &p->descriptor;
	}
	return ( NULL);
}

/*FN_OID_GET_ATTR1(jhd_tls_oid_get_ec_grp, oid_ecp_grp_t, grp_id, jhd_tls_ecp_group_id, grp_id)*/

void jhd_tls_oid_get_ec_grp(const jhd_tls_asn1_buf *oid,jhd_tls_ecp_group_id * grp_id){
	const oid_ecp_grp_t *data = oid_grp_id_from_asn1(oid);
	if(data)
		*grp_id = data->grp_id;
	else
		*grp_id = JHD_TLS_ECP_DP_NONE;
}

/*FN_OID_GET_OID_BY_ATTR1(jhd_tls_oid_get_oid_by_ec_grp, oid_ecp_grp_t, oid_ecp_grp, jhd_tls_ecp_group_id, grp_id)*/
void jhd_tls_oid_get_oid_by_ec_grp(const jhd_tls_ecp_group_id grp_id, const char **oid, size_t *olen) {
	const oid_ecp_grp_t *cur = oid_ecp_grp;
	while (cur->descriptor.asn1 != NULL) {
		if (cur->grp_id == grp_id) {
			*oid = cur->descriptor.asn1;
			*olen = cur->descriptor.asn1_len;
			return ;
		}
		cur++;
	}
	*oid = NULL;
	*olen= 0;
}

/*
 * For PKCS#5 PBES2 encryption algorithm
 */
typedef struct {
	jhd_tls_oid_descriptor_t descriptor;
	jhd_tls_cipher_type_t cipher_alg;
} oid_cipher_alg_t;

static const oid_cipher_alg_t oid_cipher_alg[] = {
				{ { ADD_LEN(JHD_TLS_OID_DES_CBC), "desCBC", "DES-CBC" }, JHD_TLS_CIPHER_DES_CBC, },
				{ { ADD_LEN(JHD_TLS_OID_DES_EDE3_CBC), "des-ede3-cbc", "DES-EDE3-CBC" }, JHD_TLS_CIPHER_DES_EDE3_CBC, },
				{ { NULL, 0, NULL, NULL }, JHD_TLS_CIPHER_NONE, }, };

/*FN_OID_TYPED_FROM_ASN1(oid_cipher_alg_t, cipher_alg, oid_cipher_alg)*/

static const oid_cipher_alg_t * oid_cipher_alg_from_asn1(const jhd_tls_asn1_buf *oid) {
	const oid_cipher_alg_t *p = oid_cipher_alg;
	const jhd_tls_oid_descriptor_t *cur =&p->descriptor;
	while (cur->asn1 != NULL) {
		if (cur->asn1_len == oid->len && memcmp(cur->asn1, oid->p, oid->len) == 0) {
			return (p);
		}
		p++;
		cur = &p->descriptor;
	}
	return ( NULL);
}

/*FN_OID_GET_ATTR1(jhd_tls_oid_get_cipher_alg, oid_cipher_alg_t, cipher_alg, jhd_tls_cipher_type_t, cipher_alg)*/

void jhd_tls_oid_get_cipher_alg(const jhd_tls_asn1_buf *oid,jhd_tls_cipher_type_t * cipher_alg){
	const oid_cipher_alg_t *data = oid_cipher_alg_from_asn1(oid);
	if(data)
		*cipher_alg = data->cipher_alg;
	else
		*cipher_alg = JHD_TLS_CIPHER_NONE;
}

/*
 * For digestAlgorithm
 */
typedef struct {
	jhd_tls_oid_descriptor_t descriptor;
	const jhd_tls_md_info_t *md_info;
} oid_md_alg_t;

static const oid_md_alg_t oid_md_alg[] = {
				{ { ADD_LEN(JHD_TLS_OID_DIGEST_ALG_MD5), "id-md5", "MD5" }, &jhd_tls_md5_info, },
				{ { ADD_LEN(JHD_TLS_OID_DIGEST_ALG_SHA1), "id-sha1", "SHA-1" }, &jhd_tls_sha1_info, },
				{ { ADD_LEN(JHD_TLS_OID_DIGEST_ALG_SHA224), "id-sha224", "SHA-224" }, &jhd_tls_sha224_info, },
				{ { ADD_LEN(JHD_TLS_OID_DIGEST_ALG_SHA256), "id-sha256", "SHA-256" }, &jhd_tls_sha256_info, },
				{ { ADD_LEN(JHD_TLS_OID_DIGEST_ALG_SHA384), "id-sha384", "SHA-384" }, &jhd_tls_sha384_info, },
				{ { ADD_LEN(JHD_TLS_OID_DIGEST_ALG_SHA512), "id-sha512", "SHA-512" }, &jhd_tls_sha512_info, },
				{ { NULL, 0, NULL, NULL },NULL, }, };

/*FN_OID_TYPED_FROM_ASN1(oid_md_alg_t, md_alg, oid_md_alg)*/

static const oid_md_alg_t * oid_md_alg_from_asn1(const jhd_tls_asn1_buf *oid) {
	const oid_md_alg_t *p = oid_md_alg;
	const jhd_tls_oid_descriptor_t *cur = &p->descriptor;
	while (cur->asn1 != NULL) {
		if (cur->asn1_len == oid->len && memcmp(cur->asn1, oid->p, oid->len) == 0) {
			return (p);
		}
		p++;
		cur = &p->descriptor;
	}
	return ( NULL);
}

/*FN_OID_GET_ATTR1(jhd_tls_oid_get_md_info, oid_md_alg_t, md_alg, jhd_tls_md_info_t *, md_info)*/

void jhd_tls_oid_get_md_info(const jhd_tls_asn1_buf *oid,const jhd_tls_md_info_t ** md_info){
	const oid_md_alg_t *data = oid_md_alg_from_asn1(oid);
	if(data)
		*md_info = data->md_info;
	else
		*md_info = NULL;
}

/*FN_OID_GET_OID_BY_ATTR1(jhd_tls_oid_get_oid_by_md, oid_md_alg_t, oid_md_alg,jhd_tls_md_info_t *, md_info)*/

void jhd_tls_oid_get_oid_by_md(const jhd_tls_md_info_t * md_info, const char **oid, size_t *olen) {
	const oid_md_alg_t *cur = oid_md_alg;
	while (cur->descriptor.asn1 != NULL) {
		if (cur->md_info == md_info) {
			*oid = cur->descriptor.asn1;
			*olen = cur->descriptor.asn1_len;
			return;
		}
		cur++;
	}
	*oid = NULL;
	*olen = 0;
}

/*
 * For HMAC digestAlgorithm
 */
typedef struct {
	jhd_tls_oid_descriptor_t descriptor;
	const jhd_tls_md_info_t *md_hmac;
} oid_md_hmac_t;

static const oid_md_hmac_t oid_md_hmac[] = {
				{ { ADD_LEN(JHD_TLS_OID_HMAC_SHA1), "hmacSHA1", "HMAC-SHA-1" }, &jhd_tls_sha1_info, },
				{ { ADD_LEN(JHD_TLS_OID_HMAC_SHA224), "hmacSHA224", "HMAC-SHA-224" },&jhd_tls_sha224_info, },
				{ { ADD_LEN(JHD_TLS_OID_HMAC_SHA256), "hmacSHA256", "HMAC-SHA-256" }, &jhd_tls_sha256_info, },
				{ { ADD_LEN(JHD_TLS_OID_HMAC_SHA384), "hmacSHA384", "HMAC-SHA-384" }, &jhd_tls_sha384_info, },
				{ { ADD_LEN(JHD_TLS_OID_HMAC_SHA512), "hmacSHA512", "HMAC-SHA-512" }, &jhd_tls_sha512_info, },
				{ { NULL, 0, NULL, NULL },NULL, }, };

/*FN_OID_TYPED_FROM_ASN1(oid_md_hmac_t, md_hmac, oid_md_hmac)*/

static const oid_md_hmac_t * oid_md_hmac_from_asn1(const jhd_tls_asn1_buf *oid) {
	const oid_md_hmac_t *p = oid_md_hmac;
	const jhd_tls_oid_descriptor_t *cur = &p->descriptor;
	while (cur->asn1 != NULL) {
		if (cur->asn1_len == oid->len && memcmp(cur->asn1, oid->p, oid->len) == 0) {
			return (p);
		}
		p++;
		cur =  &p->descriptor;
	}
	return ( NULL);
}

/*FN_OID_GET_ATTR1(jhd_tls_oid_get_md_hmac, oid_md_hmac_t, md_hmac, jhd_tls_md_info_t *, md_hmac)*/

void jhd_tls_oid_get_md_hmac(const jhd_tls_asn1_buf *oid,const jhd_tls_md_info_t ** md_info){
	const oid_md_hmac_t *data = oid_md_hmac_from_asn1(oid);
	if(data){
		*md_info = data->md_hmac;
	}else{
		*md_info = NULL;
	}
}


#define OID_SAFE_SNPRINTF                               \
    do {                                                \
        if( ret < 0 || (size_t) ret >= n )              \
            return( JHD_ERROR );    \
                                                        \
        n -= (size_t) ret;                              \
        p += (size_t) ret;                              \
    } while( 0 )

/* Return the x.y.z.... style numeric string for the given OID */
int jhd_tls_oid_get_numeric_string(char *buf, size_t size, const jhd_tls_asn1_buf *oid) {
	int ret;
	size_t i, n;
	unsigned int value;
	char *p;

	p = buf;
	n = size;

	/* First byte contains first two dots */
	if (oid->len > 0) {
		ret = snprintf(p, n, "%d.%d", oid->p[0] / 40, oid->p[0] % 40);
		OID_SAFE_SNPRINTF;
	}

	value = 0;
	for (i = 1; i < oid->len; i++) {
		/* Prevent overflow in value. */
		if (((value << 7) >> 7) != value)
			return ( JHD_TLS_ERR_OID_BUF_TOO_SMALL);

		value <<= 7;
		value += oid->p[i] & 0x7F;

		if (!(oid->p[i] & 0x80)) {
			/* Last byte */
			ret = snprintf(p, n, ".%d", value);
			OID_SAFE_SNPRINTF;
			value = 0;
		}
	}

	return ((int) (size - n));
}

