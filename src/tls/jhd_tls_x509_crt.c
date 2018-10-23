#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_x509_crt.h>
#include <tls/jhd_tls_oid.h>
#include <tls/jhd_tls_md_internal.h>
#include <tls/jhd_tls_pk_internal.h>
#include <stdio.h>
#include <string.h>

#include <tls/jhd_tls_pem.h>

#include <tls/jhd_tls_platform.h>

#include <time.h>


/*
 * Item in a verification chain: cert and flags for it
 */
typedef struct {
	jhd_tls_x509_crt *crt;
	uint32_t flags;
} x509_crt_verify_chain_item;

/*
 * Max size of verification chain: end-entity + intermediates + trusted root
 */
#define X509_MAX_VERIFY_CHAIN_SIZE    ( JHD_TLS_X509_MAX_INTERMEDIATE_CA + 2 )

/*
 * Default profile
 */
const jhd_tls_x509_crt_profile jhd_tls_x509_crt_profile_default = {
#if defined(JHD_TLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES)
        /* Allow SHA-1 (weak, but still safe in controlled environments) */
		(1<<JHD_TLS_SSL_HASH_SHA1) |
#endif
        /* Only SHA-2 hashes */
        (1<<JHD_TLS_SSL_HASH_SHA224) | (1<<JHD_TLS_SSL_HASH_SHA256) | (1<<JHD_TLS_SSL_HASH_SHA384) | (1<<JHD_TLS_SSL_HASH_SHA512), 0xFFFFFFF, /* Any PK alg    */
        0xFFFFFFF, /* Any curve     */
        2048, };

/*
 * Next-default profile
 */
const jhd_tls_x509_crt_profile jhd_tls_x509_crt_profile_next = {
/* Hashes from SHA-256 and above */
		(1<<JHD_TLS_SSL_HASH_SHA256) | (1<<JHD_TLS_SSL_HASH_SHA384) | (1<<JHD_TLS_SSL_HASH_SHA512), 0xFFFFFFF, /* Any PK alg    */

/* Curves at or above 128-bit security level */
JHD_TLS_X509_ID_FLAG(JHD_TLS_ECP_DP_SECP256R1) |
JHD_TLS_X509_ID_FLAG( JHD_TLS_ECP_DP_SECP384R1 ) |
JHD_TLS_X509_ID_FLAG( JHD_TLS_ECP_DP_SECP521R1 ) |
JHD_TLS_X509_ID_FLAG( JHD_TLS_ECP_DP_BP256R1 ) |
JHD_TLS_X509_ID_FLAG( JHD_TLS_ECP_DP_BP384R1 ) |
JHD_TLS_X509_ID_FLAG( JHD_TLS_ECP_DP_BP512R1 ) |
JHD_TLS_X509_ID_FLAG( JHD_TLS_ECP_DP_SECP256K1 ), 2048, };

/*
 * NSA Suite B Profile
 */
const jhd_tls_x509_crt_profile jhd_tls_x509_crt_profile_suiteb = {
/* Only SHA-256 and 384 */
		(1<<JHD_TLS_SSL_HASH_SHA256) | (1<<JHD_TLS_SSL_HASH_SHA384),
/* Only ECDSA */
(1<<JHD_TLS_SSL_SIG_ECDSA),

/* Only NIST P-256 and P-384 */
JHD_TLS_X509_ID_FLAG( JHD_TLS_ECP_DP_SECP256R1 ) | JHD_TLS_X509_ID_FLAG(JHD_TLS_ECP_DP_SECP384R1), 0, };

///*
// * Check md_alg against profile
// * Return 0 if md_alg is acceptable for this profile, -1 otherwise
// */
//static int x509_profile_check_md_alg(const jhd_tls_x509_crt_profile *profile,const jhd_tls_md_info_t *md_info) {
//	if ((profile->allowed_mds & (1 << md_info->hash_flag)) != 0)
//		return (0);
//
//	return (-1);
//}
//
///*
// * Check pk_alg against profile
// * Return 0 if pk_alg is acceptable for this profile, -1 otherwise
// */
//static int x509_profile_check_pk_alg(const jhd_tls_x509_crt_profile *profile,const jhd_tls_pk_info_t *pk_info) {
//	if ((profile->allowed_pks & (1<< pk_info->pk_flag)) != 0)
//		return (0);
//
//	return (-1);
//}
//
///*
// * Check key against profile
// * Return 0 if pk is acceptable for this profile, -1 otherwise
// */
//static int x509_profile_check_key(const jhd_tls_x509_crt_profile *profile, const jhd_tls_pk_context *pk) {
//	if (pk->pk_info == &jhd_tls_rsa_info) {
//		return (jhd_tls_pk_get_bitlen(pk) >= profile->rsa_min_bitlen)? (0):(-1);
//	}else if (pk->pk_info == &jhd_tls_ecdsa_info) {
//		const jhd_tls_ecp_group_id gid = jhd_tls_pk_ec(*pk)->grp->id;
//
//		return ((profile->allowed_curves & JHD_TLS_X509_ID_FLAG(gid)) != 0)? (0): (-1);
//	}
//	return (-1);
//}

/*
 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
static int x509_get_version(unsigned char **p, const unsigned char *end, int *ver) {
	int ret;
	size_t len;

	if ((ret = jhd_tls_asn1_get_tag(p, end, &len,JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | 0)) != 0) {
		if (ret == JHD_UNEXPECTED) {
			*ver = 0;
			return JHD_OK;
		}
		return (ret);
	}
	end = *p + len;

	if ((ret = jhd_tls_asn1_get_int(p, end, ver)) != 0)
		return  ret;

	if (*p != end)
		return  JHD_ERROR;
	return JHD_OK;
}

/*
 *  Validity ::= SEQUENCE {
 *       notBefore      Time,
 *       notAfter       Time }
 */
static int x509_get_dates(unsigned char **p, const unsigned char *end, jhd_tls_x509_time *from, jhd_tls_x509_time *to) {
	int ret;
	size_t len;

	if ((ret = jhd_tls_asn1_get_tag(p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != 0)
		return JHD_ERROR;

	end = *p + len;

	if ((ret = jhd_tls_x509_get_time(p, end, from)) != 0)
		return (ret);

	if ((ret = jhd_tls_x509_get_time(p, end, to)) != 0)
		return (ret);

	if (*p != end)
		return JHD_ERROR;
	return JHD_OK;
}

/*
 * X.509 v2/v3 unique identifier (not parsed)
 */
static int x509_get_uid(unsigned char **p, const unsigned char *end, jhd_tls_x509_buf *uid, int n) {
	int ret;

	if (*p == end)
		return JHD_OK;

	uid->tag = **p;

	if ((ret = jhd_tls_asn1_get_tag(p, end, &uid->len,JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | n)) != 0) {
		if (ret == JHD_UNEXPECTED)
			return JHD_OK;
		return (ret);
	}

	uid->p = *p;
	*p += uid->len;

	return (0);
}

static int x509_get_basic_constraints(unsigned char **p, const unsigned char *end, int *ca_istrue, int *max_pathlen) {
	int ret;
	size_t len;

	/*
	 * BasicConstraints ::= SEQUENCE {
	 *      cA                      BOOLEAN DEFAULT FALSE,
	 *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
	 */
	*ca_istrue = 0; /* DEFAULT FALSE */
	*max_pathlen = 0; /* endless */

	if ((ret = jhd_tls_asn1_get_tag(p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != 0)
		return JHD_ERROR;

	if (*p == end)
		return (0);

	if ((ret = jhd_tls_asn1_get_bool(p, end, ca_istrue)) != 0) {
		if (ret == JHD_UNEXPECTED)
			ret = jhd_tls_asn1_get_int(p, end, ca_istrue);

		if (ret != 0)
			return JHD_ERROR;

		if (*ca_istrue != 0)
			*ca_istrue = 1;
	}

	if (*p == end)
		return (0);

	if ((ret = jhd_tls_asn1_get_int(p, end, max_pathlen)) != 0)
		return JHD_ERROR;

	if (*p != end)
		return JHD_ERROR;

	(*max_pathlen)++;

	return (0);
}

static int x509_get_ns_cert_type(unsigned char **p, const unsigned char *end, unsigned char *ns_cert_type) {
	int ret;
	jhd_tls_x509_bitstring bs = { 0, 0, NULL };

	if ((ret = jhd_tls_asn1_get_bitstring(p, end, &bs)) != 0)
		return JHD_ERROR;

	if (bs.len != 1)
		return JHD_ERROR;
	/* Get actual bitstring */
	*ns_cert_type = *bs.p;
	return JHD_OK;
}

static int x509_get_key_usage(unsigned char **p, const unsigned char *end, unsigned int *key_usage) {
	int ret;
	size_t i;
	jhd_tls_x509_bitstring bs = { 0, 0, NULL };

	if ((ret = jhd_tls_asn1_get_bitstring(p, end, &bs)) != 0)
		return JHD_ERROR;

	if (bs.len < 1)
		return JHD_ERROR;

	/* Get actual bitstring */
	*key_usage = 0;
	for (i = 0; i < bs.len && i < sizeof(unsigned int); i++) {
		*key_usage |= (unsigned int) bs.p[i] << (8 * i);
	}

	return (0);
}

/*
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 */
static int x509_get_ext_key_usage(unsigned char **p, const unsigned char *end, jhd_tls_x509_sequence *ext_key_usage,void *event) {
	int ret;
	ext_key_usage->buf.p = NULL;
	if ((ret = jhd_tls_asn1_get_sequence_of(p, end, ext_key_usage, JHD_TLS_ASN1_OID,event)) != 0)
		return ret;
	/* Sequence length must be >= 1 */
	if (ext_key_usage->buf.p == NULL)
		return JHD_ERROR;
	return (0);
}

static int x509_get_ext_key_usage_by_malloc(unsigned char **p, const unsigned char *end, jhd_tls_x509_sequence *ext_key_usage) {
	int ret;
	ext_key_usage->buf.p = NULL;
	if ((ret = jhd_tls_asn1_get_sequence_of_by_malloc(p, end, ext_key_usage, JHD_TLS_ASN1_OID)) != 0)
		return ret;
	if (ext_key_usage->buf.p == NULL)
		return JHD_ERROR;
	return (0);
}

/*
 * SubjectAltName ::= GeneralNames
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 * GeneralName ::= CHOICE {
 *      otherName                       [0]     OtherName,
 *      rfc822Name                      [1]     IA5String,
 *      dNSName                         [2]     IA5String,
 *      x400Address                     [3]     ORAddress,
 *      directoryName                   [4]     Name,
 *      ediPartyName                    [5]     EDIPartyName,
 *      uniformResourceIdentifier       [6]     IA5String,
 *      iPAddress                       [7]     OCTET STRING,
 *      registeredID                    [8]     OBJECT IDENTIFIER }
 *
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 * EDIPartyName ::= SEQUENCE {
 *      nameAssigner            [0]     DirectoryString OPTIONAL,
 *      partyName               [1]     DirectoryString }
 *
 * NOTE: we only parse and use dNSName at this point.
 */
static int x509_get_subject_alt_name(unsigned char **p, const unsigned char *end, jhd_tls_x509_sequence *subject_alt_name,void *event) {
	int ret;
	size_t len, tag_len;
	jhd_tls_asn1_buf *buf;
	unsigned char tag;
	jhd_tls_asn1_sequence *prev;
	jhd_tls_asn1_sequence *cur = subject_alt_name;

	/* Get main sequence tag */
	if ((ret = jhd_tls_asn1_get_tag(p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != 0)
		return JHD_ERROR;

	if (*p + len != end)
		return JHD_ERROR;
	if(*p<end){
		for(;;){
			if ((end - *p) < 1)
				return JHD_ERROR;
			tag = **p;
			(*p)++;
			if ((ret = jhd_tls_asn1_get_len(p, end, &tag_len)) != 0)
				return JHD_ERROR;
			if ((tag & JHD_TLS_ASN1_TAG_CLASS_MASK) != JHD_TLS_ASN1_CONTEXT_SPECIFIC) {
				return JHD_ERROR;
			}
			/* Skip everything but DNS name */
			if (tag != ( JHD_TLS_ASN1_CONTEXT_SPECIFIC | 2)) {
				*p += tag_len;
				continue;
			}
			buf = &(cur->buf);
			buf->tag = tag;
			buf->p = *p;
			buf->len = tag_len;
			*p += buf->len;

			if(*p<end){
				if(cur->next == NULL){
					cur->next  = jhd_tls_alloc(sizeof(jhd_tls_asn1_sequence));
					if(cur->next == NULL){
						if(event == NULL){
							return JHD_ERROR;
						}else{
							jhd_tls_wait_mem(event,sizeof(jhd_tls_asn1_sequence));
							//FIXME: add memory waitting queue
							return JHD_AGAIN;
						}
					}
					jhd_tls_platform_zeroize(cur->next,sizeof(jhd_tls_asn1_sequence));
				}
				cur = cur->next;
			}else{
				break;
			}
		}
	}
	if (*p != end)
		return JHD_ERROR;
	prev = cur ;
	cur = cur->next;
	prev->next = NULL;
	while(cur != NULL){
		prev = cur;
		cur = prev->next;
		jhd_tls_free_with_size(prev,sizeof(jhd_tls_asn1_sequence));
	}
	return (0);
}
static int x509_get_subject_alt_name_by_malloc(unsigned char **p, const unsigned char *end, jhd_tls_x509_sequence *subject_alt_name) {
	int ret;
	size_t len, tag_len;
	jhd_tls_asn1_buf *buf;
	unsigned char tag;
	jhd_tls_asn1_sequence *prev;
	jhd_tls_asn1_sequence *cur = subject_alt_name;
	if ((ret = jhd_tls_asn1_get_tag(p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != 0)
		return JHD_ERROR;
	if (*p + len != end)
		return JHD_ERROR;
	if(*p<end){
		for(;;){
			if (end <= *p) return JHD_ERROR;
			tag = **p;
			(*p)++;
			if ((ret = jhd_tls_asn1_get_len(p, end, &tag_len)) != 0) return JHD_ERROR;
			if ((tag & JHD_TLS_ASN1_TAG_CLASS_MASK) != JHD_TLS_ASN1_CONTEXT_SPECIFIC) {
				return JHD_ERROR;
			}
			if (tag != ( JHD_TLS_ASN1_CONTEXT_SPECIFIC | 2)) {
				*p += tag_len;
				continue;
			}
			buf = &(cur->buf);
			buf->tag = tag;
			buf->p = *p;
			buf->len = tag_len;
			*p += buf->len;
			if(*p<end){
				cur->next  = jhd_tls_alloc(sizeof(jhd_tls_asn1_sequence));
				if(cur->next == NULL){
					return JHD_ERROR;
				}
				jhd_tls_platform_zeroize(cur->next,sizeof(jhd_tls_asn1_sequence));
				cur = cur->next;
			}else{
				break;
			}
		}
	}
	if (*p != end)
		return JHD_ERROR;
	prev = cur ;
	cur = cur->next;
	prev->next = NULL;
	while(cur != NULL){
		prev = cur;
		cur = prev->next;
		free(prev);
	}
	return (0);
}
static int x509_get_crt_ext(unsigned char **p, const unsigned char *end, jhd_tls_x509_crt *crt,void *event) {
	int ret;
	size_t len;
	unsigned char *end_ext_data, *end_ext_octet;
	jhd_tls_x509_sequence *next,*prev;

	if ((ret = jhd_tls_x509_get_ext(p, end, &crt->v3_ext, 3)) != 0) {
		if (ret == JHD_UNEXPECTED)
			return JHD_OK;
		return (ret);
	}

	while (*p < end) {
		/*
		 * Extension  ::=  SEQUENCE  {
		 *      extnID      OBJECT IDENTIFIER,
		 *      critical    BOOLEAN DEFAULT FALSE,
		 *      extnValue   OCTET STRING  }
		 */
		jhd_tls_x509_buf extn_oid = { 0, 0, NULL };
		int is_critical = 0; /* DEFAULT FALSE */
		int ext_type = 0;

		if ((ret = jhd_tls_asn1_get_tag(p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != 0)
			return JHD_ERROR;

		end_ext_data = *p + len;

		/* Get extension ID */
		extn_oid.tag = **p;

		if ((ret = jhd_tls_asn1_get_tag(p, end, &extn_oid.len, JHD_TLS_ASN1_OID)) != 0)
			return JHD_ERROR;

		extn_oid.p = *p;
		*p += extn_oid.len;

		if ((end - *p) < 1)
			return JHD_ERROR;;

		/* Get optional critical */
		if ((ret = jhd_tls_asn1_get_bool(p, end_ext_data, &is_critical)) != 0 && (ret != JHD_UNEXPECTED))
			return JHD_ERROR;

		/* Data should be octet string type */
		if ((ret = jhd_tls_asn1_get_tag(p, end_ext_data, &len,JHD_TLS_ASN1_OCTET_STRING)) != 0)
			return JHD_ERROR;

		end_ext_octet = *p + len;

		if (end_ext_octet != end_ext_data)
			return JHD_ERROR;

		/*
		 * Detect supported extensions
		 */
		jhd_tls_oid_get_x509_ext_type(&extn_oid, &ext_type);

		if (ext_type == 0) {
			/* No parser found, skip extension */
			*p = end_ext_octet;
			if (is_critical) {
				/* Data is marked as critical: fail */
				return JHD_ERROR;
			}
			continue;
		}

		/* Forbid repeated extensions */
		if ((crt->ext_types & ext_type) != 0)
			return JHD_ERROR;

		crt->ext_types |= ext_type;

		switch (ext_type) {
			case JHD_TLS_X509_EXT_BASIC_CONSTRAINTS:
				/* Parse basic constraints */
				if ((ret = x509_get_basic_constraints(p, end_ext_octet, &crt->ca_istrue, &crt->max_pathlen)) != 0)
					return (ret);
				break;

			case JHD_TLS_X509_EXT_KEY_USAGE:
				/* Parse key usage */
				if ((ret = x509_get_key_usage(p, end_ext_octet, &crt->key_usage)) != 0)
					return (ret);
				break;

			case JHD_TLS_X509_EXT_EXTENDED_KEY_USAGE:
				/* Parse extended key usage */
				if ((ret = x509_get_ext_key_usage(p, end_ext_octet, &crt->ext_key_usage,event)) != 0){
					if(ret == JHD_AGAIN){
						crt->ext_key_usage.buf.p  = NULL;
						crt->ext_key_usage.buf.len = 0;
					}else{
						next = crt->ext_key_usage.next;
						crt->ext_key_usage.next = NULL;
						while(next != NULL){
							prev = next;
							next = next->next;
							jhd_tls_free_with_size(prev,sizeof(jhd_tls_x509_sequence));
						}
					}
					return (ret);
				}
				break;

			case JHD_TLS_X509_EXT_SUBJECT_ALT_NAME:
				/* Parse subject alt name */
				if ((ret = x509_get_subject_alt_name(p, end_ext_octet, &crt->subject_alt_names,event)) != 0){
					if(ret == JHD_AGAIN){
						crt->subject_alt_names.buf.p  = NULL;
						crt->subject_alt_names.buf.len = 0;
					}else{
						next = crt->subject_alt_names.next;
						crt->subject_alt_names.next = NULL;
						while(next != NULL){
							prev = next;
							next = next->next;
							jhd_tls_free_with_size(prev,sizeof(jhd_tls_x509_sequence));
						}

					}
					return (ret);
				}
				break;

			case JHD_TLS_X509_EXT_NS_CERT_TYPE:
				/* Parse netscape certificate type */
				if ((ret = x509_get_ns_cert_type(p, end_ext_octet, &crt->ns_cert_type)) != 0)
					return JHD_ERROR;
				break;

			default:
				return JHD_ERROR;
		}
	}
	if (*p != end)
		return JHD_ERROR;

	return JHD_OK;
}

/*
 * X.509 v3 extensions
 *
 */
static int x509_get_crt_ext_by_malloc(unsigned char **p, const unsigned char *end, jhd_tls_x509_crt *crt) {
	int ret;
	size_t len;
	unsigned char *end_ext_data, *end_ext_octet;
	jhd_tls_x509_sequence *next,*prev;

	if ((ret = jhd_tls_x509_get_ext(p, end, &crt->v3_ext, 3)) != 0) {
		if (ret == JHD_UNEXPECTED)
			return JHD_OK;
		return (ret);
	}

	while (*p < end) {
		jhd_tls_x509_buf extn_oid = { 0, 0, NULL };
		int is_critical = 0; /* DEFAULT FALSE */
		int ext_type = 0;

		if ((ret = jhd_tls_asn1_get_tag(p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)) != 0)
			return JHD_ERROR;
		end_ext_data = *p + len;
		extn_oid.tag = **p;
		if ((ret = jhd_tls_asn1_get_tag(p, end, &extn_oid.len, JHD_TLS_ASN1_OID)) != 0)
			return JHD_ERROR;
		extn_oid.p = *p;
		*p += extn_oid.len;
		if ((end - *p) < 1)
			return JHD_ERROR;;
		if ((ret = jhd_tls_asn1_get_bool(p, end_ext_data, &is_critical)) != 0 && (ret != JHD_UNEXPECTED))
			return JHD_ERROR;
		if ((ret = jhd_tls_asn1_get_tag(p, end_ext_data, &len,JHD_TLS_ASN1_OCTET_STRING)) != 0)
			return JHD_ERROR;
		end_ext_octet = *p + len;
		if (end_ext_octet != end_ext_data)
			return JHD_ERROR;
		jhd_tls_oid_get_x509_ext_type(&extn_oid, &ext_type);

		if (ext_type == 0) {
			*p = end_ext_octet;
			if (is_critical) {
				return JHD_ERROR;
			}
			continue;
		}
		if ((crt->ext_types & ext_type) != 0)
			return JHD_ERROR;
		crt->ext_types |= ext_type;
		switch (ext_type) {
			case JHD_TLS_X509_EXT_BASIC_CONSTRAINTS:
				if ((ret = x509_get_basic_constraints(p, end_ext_octet, &crt->ca_istrue, &crt->max_pathlen)) != 0)
					return (ret);
				break;
			case JHD_TLS_X509_EXT_KEY_USAGE:
				if ((ret = x509_get_key_usage(p, end_ext_octet, &crt->key_usage)) != 0)
					return (ret);
				break;
			case JHD_TLS_X509_EXT_EXTENDED_KEY_USAGE:
				/* Parse extended key usage */
				if ((ret = x509_get_ext_key_usage_by_malloc(p, end_ext_octet, &crt->ext_key_usage)) != 0){
						next = crt->ext_key_usage.next;
						crt->ext_key_usage.next = NULL;
						while(next != NULL){
							prev = next;
							next = next->next;
							free(prev);
						}
					return (ret);
				}
				break;

			case JHD_TLS_X509_EXT_SUBJECT_ALT_NAME:
				/* Parse subject alt name */
				if ((ret = x509_get_subject_alt_name_by_malloc(p, end_ext_octet, &crt->subject_alt_names)) != 0){
					next = crt->subject_alt_names.next;
					crt->subject_alt_names.next = NULL;
					while(next != NULL){
						prev = next;
						next = next->next;
						jhd_tls_free_with_size(prev,sizeof(jhd_tls_x509_sequence));
					}
					return (ret);
				}
				break;

			case JHD_TLS_X509_EXT_NS_CERT_TYPE:
				/* Parse netscape certificate type */
				if ((ret = x509_get_ns_cert_type(p, end_ext_octet, &crt->ns_cert_type)) != 0)
					return JHD_ERROR;
				break;

			default:
				return JHD_ERROR;
		}
	}
	if (*p != end)
		return JHD_ERROR;

	return JHD_OK;
}
int jhd_tls_x509_crt_parse_der_by_malloc(jhd_tls_x509_crt *crt, const unsigned char *buf, size_t buflen){
		int ret;
		size_t len,raw_len;
		unsigned char *p, *end, *crt_end;
		jhd_tls_x509_buf sig_params1, sig_params2, sig_oid2;
		memset(&sig_params1, 0, sizeof(jhd_tls_x509_buf));
		memset(&sig_params2, 0, sizeof(jhd_tls_x509_buf));
		memset(&sig_oid2, 0, sizeof(jhd_tls_x509_buf));
		// Use the original buffer until we figure out actual length
		p = (unsigned char*) buf;
		len = buflen;
		end = p + len;
		if ( jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)!= JHD_OK) {
			return JHD_ERROR;
		}
		if (len > (size_t) (end - p)) {
			return JHD_ERROR;
		}
		crt_end = p + len;
		raw_len = crt_end - buf;
		crt->raw.p = p = malloc(raw_len);
		if(NULL ==p){
			log_stderr("systemcall malloc error");
			return JHD_ERROR;
		}
		crt->raw.len = raw_len;
		memcpy(p, buf, raw_len);
		p += crt->raw.len - len;
		end = crt_end = p + len;
		crt->tbs.p = p;
		if (jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)!= JHD_OK) {
			return JHD_ERROR;
		}
		end = p + len;
		crt->tbs.len = end - crt->tbs.p;

		/*
		 * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
		 *
		 * CertificateSerialNumber  ::=  INTEGER
		 *
		 * signature            AlgorithmIdentifier
		 */
		if (x509_get_version(&p, end, &crt->version)!= JHD_OK || (jhd_tls_x509_get_serial(&p, end, &crt->serial)!= JHD_OK)
		        || (jhd_tls_x509_get_alg(&p, end, &crt->sig_oid, &sig_params1)!= JHD_OK)) {
			return JHD_ERROR;
		}
		if (crt->version < 0 || crt->version > 2) {
			return JHD_ERROR;
		}
		crt->version++;
		if ((ret = jhd_tls_x509_get_sig_alg(&crt->sig_oid, &sig_params1, &crt->sig_md, &crt->sig_pk)) != JHD_OK) {
			return (ret);
		}
		crt->issuer_raw.p = p;
		if (jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)!= JHD_OK) {
			return JHD_ERROR;
		}
		if ((ret = jhd_tls_x509_get_name_by_malloc(&p, p + len, &crt->issuer)) != 0) {
			return JHD_ERROR;
		}
		crt->issuer_raw.len = p - crt->issuer_raw.p;
		if (x509_get_dates(&p, end, &crt->valid_from, &crt->valid_to) != JHD_OK) {
			return JHD_ERROR;
		}
		crt->subject_raw.p = p;
		if (jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE) != JHD_OK) {
			return JHD_ERROR;
		}
		if (len && (ret = jhd_tls_x509_get_name_by_malloc(&p, p + len, &crt->subject)) != JHD_OK) {
			return JHD_ERROR;
		}
		crt->subject_raw.len = p - crt->subject_raw.p;
		if ((ret = jhd_tls_pk_parse_subpubkey_by_malloc(&p, end, &crt->pk)) != 0) {
			return (ret);
		}
		if (crt->version == 2 || crt->version == 3) {
			ret = x509_get_uid(&p, end, &crt->issuer_id, 1);
			if (ret != 0) {
				return JHD_ERROR;
			}
			ret = x509_get_uid(&p, end, &crt->subject_id, 2);
			if (ret != 0) {
				return JHD_ERROR;
			}
		}


		if (crt->version == 3)  {
			ret = x509_get_crt_ext_by_malloc(&p, end, crt);
			if (ret != 0) {
				return ret;
			}
		}
		if (p != end) {
			return JHD_ERROR;
		}
		end = crt_end;
		if ((ret = jhd_tls_x509_get_alg(&p, end, &sig_oid2, &sig_params2)) != 0) {
			return JHD_ERROR;
		}
		if (crt->sig_oid.len != sig_oid2.len || memcmp(crt->sig_oid.p, sig_oid2.p, crt->sig_oid.len) != 0 || sig_params1.len != sig_params2.len
		        || (sig_params1.len != 0 && memcmp(sig_params1.p, sig_params2.p, sig_params1.len) != 0)) {
			return JHD_ERROR;
		}

		if ((ret = jhd_tls_x509_get_sig(&p, end, &crt->sig)) != 0) {
			return JHD_ERROR;
		}

		if (p != end) {
			return JHD_ERROR;
		}
		return (0);

}
/*
 * Parse and fill a single X.509 certificate in DER format
 */
int jhd_tls_x509_crt_parse_der(jhd_tls_x509_crt *crt, const unsigned char *buf, size_t buflen,void *event) {
	int ret;
	size_t len,raw_len;
	unsigned char *p, *end, *crt_end;
	jhd_tls_x509_buf sig_params1, sig_params2, sig_oid2;
	memset(&sig_params1, 0, sizeof(jhd_tls_x509_buf));
	memset(&sig_params2, 0, sizeof(jhd_tls_x509_buf));
	memset(&sig_oid2, 0, sizeof(jhd_tls_x509_buf));
	// Use the original buffer until we figure out actual length
	p = (unsigned char*) buf;
	len = buflen;
	end = p + len;
	/*
	 * Certificate  ::=  SEQUENCE  {
	 *      tbsCertificate       TBSCertificate,
	 *      signatureAlgorithm   AlgorithmIdentifier,
	 *      signatureValue       BIT STRING  }
	 */
	if ( jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)!= JHD_OK) {
		return JHD_ERROR;
	}

	if (len > (size_t) (end - p)) {
		return JHD_ERROR;
	}
	crt_end = p + len;
	raw_len = crt_end - buf;
	if(crt->raw.p != NULL){
		if(raw_len != crt->raw.len){
			jhd_tls_free_with_size(crt->raw.p,crt->raw.len);
			crt->raw.p = NULL;
			crt->raw.len = 0;
		}else{
			p = crt->raw.p;
			goto label_memcpy;
		}
	}
	crt->raw.p = p = jhd_tls_alloc(raw_len);
	if(NULL ==p){
		if(event!=NULL){
			jhd_tls_wait_mem(event,raw_len);
			return JHD_AGAIN;
		}
		return JHD_ERROR;
	}
	crt->raw.len = raw_len;
	label_memcpy:
	memcpy(p, buf, raw_len);

	// Direct pointers to the new buffer
	p += crt->raw.len - len;
	end = crt_end = p + len;

	/*
	 * TBSCertificate  ::=  SEQUENCE  {
	 */
	crt->tbs.p = p;
	if (jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)!= JHD_OK) {
		return JHD_ERROR;
	}
	end = p + len;
	crt->tbs.len = end - crt->tbs.p;

	/*
	 * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	 *
	 * CertificateSerialNumber  ::=  INTEGER
	 *
	 * signature            AlgorithmIdentifier
	 */
	if (x509_get_version(&p, end, &crt->version)!= JHD_OK || (jhd_tls_x509_get_serial(&p, end, &crt->serial)!= JHD_OK)
	        || (jhd_tls_x509_get_alg(&p, end, &crt->sig_oid, &sig_params1)!= JHD_OK)) {
		return JHD_ERROR;
	}

	if (crt->version < 0 || crt->version > 2) {
		return JHD_ERROR;
	}

	crt->version++;

	if ((ret = jhd_tls_x509_get_sig_alg(&crt->sig_oid, &sig_params1, &crt->sig_md, &crt->sig_pk)) != JHD_OK) {
		return (ret);
	}

	/*
	 * issuer               Name
	 */
	crt->issuer_raw.p = p;

	if (jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE)!= JHD_OK) {
		return JHD_ERROR;
	}

	if ((ret = jhd_tls_x509_get_name(&p, p + len, &crt->issuer)) != 0) {
		if((event != NULL) && (JHD_AGAIN == ret)){
				jhd_tls_wait_mem(event,sizeof(jhd_tls_x509_name));
				return JHD_AGAIN;
		}
		return JHD_ERROR;
	}

	crt->issuer_raw.len = p - crt->issuer_raw.p;

	/*
	 * Validity ::= SEQUENCE {
	 *      notBefore      Time,
	 *      notAfter       Time }
	 *
	 */
	if (x509_get_dates(&p, end, &crt->valid_from, &crt->valid_to) != JHD_OK) {
		return JHD_ERROR;
	}

	/*
	 * subject              Name
	 */
	crt->subject_raw.p = p;

	if (jhd_tls_asn1_get_tag(&p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE) != JHD_OK) {
		return JHD_ERROR;
	}

	if (len && (ret = jhd_tls_x509_get_name(&p, p + len, &crt->subject)) != JHD_OK) {
		if((event != NULL) && (JHD_AGAIN == ret)){
				jhd_tls_wait_mem(event,sizeof(jhd_tls_x509_name));
				return JHD_AGAIN;
		}
		return JHD_ERROR;
	}

	crt->subject_raw.len = p - crt->subject_raw.p;

	/*
	 * SubjectPublicKeyInfo
	 */
	if ((ret = jhd_tls_pk_parse_subpubkey(&p, end, &crt->pk,event)) != 0) {
		return (ret);
	}

	/*
	 *  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
	 *                       -- If present, version shall be v2 or v3
	 *  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
	 *                       -- If present, version shall be v2 or v3
	 *  extensions      [3]  EXPLICIT Extensions OPTIONAL
	 *                       -- If present, version shall be v3
	 */
	if (crt->version == 2 || crt->version == 3) {
		ret = x509_get_uid(&p, end, &crt->issuer_id, 1);
		if (ret != 0) {
			return JHD_ERROR;
		}
		ret = x509_get_uid(&p, end, &crt->subject_id, 2);
		if (ret != 0) {
			return JHD_ERROR;
		}
	}


	if (crt->version == 3)  {
		ret = x509_get_crt_ext(&p, end, crt,event);
		if (ret != 0) {
			return ret;
		}
	}

	if (p != end) {
		return JHD_ERROR;
	}
	end = crt_end;

	/*
	 *  }
	 *  -- end of TBSCertificate
	 *
	 *  signatureAlgorithm   AlgorithmIdentifier,
	 *  signatureValue       BIT STRING
	 */
	if ((ret = jhd_tls_x509_get_alg(&p, end, &sig_oid2, &sig_params2)) != 0) {
		return JHD_ERROR;
	}
	if (crt->sig_oid.len != sig_oid2.len || memcmp(crt->sig_oid.p, sig_oid2.p, crt->sig_oid.len) != 0 || sig_params1.len != sig_params2.len
	        || (sig_params1.len != 0 && memcmp(sig_params1.p, sig_params2.p, sig_params1.len) != 0)) {
		return JHD_ERROR;
	}

	if ((ret = jhd_tls_x509_get_sig(&p, end, &crt->sig)) != 0) {
		return JHD_ERROR;
	}

	if (p != end) {
		return JHD_ERROR;
	}
	return (0);
}

jhd_tls_x509_crt* jhd_tls_x509_crt_parse(const unsigned char *buf, size_t buflen){
	    unsigned char tmp_buf[8192];
	    jhd_tls_x509_crt *cert;
		size_t tmp_buf_len;
		jhd_tls_x509_crt *tmp_cert,*curr_cert;
		cert = malloc(sizeof(jhd_tls_x509_crt));
		if(cert == NULL){
			log_stderr("systemcall malloc error");
			return NULL;
		}
		memset(cert,0,sizeof(jhd_tls_x509_crt));
		curr_cert = cert;
		if (buflen != 0 && buf[buflen - 1] == '\0' && strstr((const char *) buf, "-----BEGIN CERTIFICATE-----") != NULL) {
			int ret;
			for(;;){
				size_t use_len;
				tmp_buf_len = 8192;
				if(JHD_OK == jhd_tls_pem_read_buffer(tmp_buf,&tmp_buf_len, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", buf,&use_len)){
					buflen -= use_len;
					buf += use_len;
				} else {
					goto func_err;
				}
				if(JHD_OK != jhd_tls_x509_crt_parse_der_by_malloc(curr_cert,tmp_buf,tmp_buf_len)){
					goto func_err;
				}
				if(buflen >1){
					curr_cert->next = malloc(sizeof(jhd_tls_x509_crt));
					if(curr_cert->next == NULL){
						goto func_err;
					}
					curr_cert = cert->next;
					memset(curr_cert,0,sizeof(jhd_tls_x509_crt));
				}else{
					break;
				}
			}
			return cert;
		}
		if(JHD_OK != jhd_tls_x509_crt_parse_der_by_malloc(cert, buf, buflen,NULL)){
			goto func_err;
		}
		return cert;
func_err:
	if(cert != NULL){
		jhd_tls_x509_crt_free_by_malloc(cert);
		free(cert);
	}
	return NULL;
}



static int x509_info_subject_alt_name(char **buf, size_t *size, const jhd_tls_x509_sequence *subject_alt_name) {
	size_t i;
	size_t n = *size;
	char *p = *buf;
	const jhd_tls_x509_sequence *cur = subject_alt_name;
	const char *sep = "";
	size_t sep_len = 0;

	while (cur != NULL) {
		if (cur->buf.len + sep_len >= n) {
			*p = '\0';
			return JHD_ERROR;
		}

		n -= cur->buf.len + sep_len;
		for (i = 0; i < sep_len; i++)
			*p++ = sep[i];
		for (i = 0; i < cur->buf.len; i++)
			*p++ = cur->buf.p[i];

		sep = ", ";
		sep_len = 2;

		cur = cur->next;
	}

	*p = '\0';

	*size = n;
	*buf = p;

	return (0);
}

#define PRINT_ITEM(i)                           \
    {                                           \
        ret = snprintf( p, n, "%s" i, sep );    \
        JHD_TLS_X509_SAFE_SNPRINTF;                        \
        sep = ", ";                             \
    }

#define CERT_TYPE(type,name)                    \
    if( ns_cert_type & type )                   \
        PRINT_ITEM( name );

static int x509_info_cert_type(char **buf, size_t *size, unsigned char ns_cert_type) {
	int ret;
	size_t n = *size;
	char *p = *buf;
	const char *sep = "";

	CERT_TYPE(JHD_TLS_X509_NS_CERT_TYPE_SSL_CLIENT, "SSL Client");
	CERT_TYPE(JHD_TLS_X509_NS_CERT_TYPE_SSL_SERVER, "SSL Server");
	CERT_TYPE(JHD_TLS_X509_NS_CERT_TYPE_EMAIL, "Email");
	CERT_TYPE(JHD_TLS_X509_NS_CERT_TYPE_OBJECT_SIGNING, "Object Signing");
	CERT_TYPE(JHD_TLS_X509_NS_CERT_TYPE_RESERVED, "Reserved");
	CERT_TYPE(JHD_TLS_X509_NS_CERT_TYPE_SSL_CA, "SSL CA");
	CERT_TYPE(JHD_TLS_X509_NS_CERT_TYPE_EMAIL_CA, "Email CA");
	CERT_TYPE(JHD_TLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA, "Object Signing CA");

	*size = n;
	*buf = p;

	return (0);
}

#define KEY_USAGE(code,name)    \
    if( key_usage & code )      \
        PRINT_ITEM( name );

static int x509_info_key_usage(char **buf, size_t *size, unsigned int key_usage) {
	int ret;
	size_t n = *size;
	char *p = *buf;
	const char *sep = "";

	KEY_USAGE(JHD_TLS_X509_KU_DIGITAL_SIGNATURE, "Digital Signature");
	KEY_USAGE(JHD_TLS_X509_KU_NON_REPUDIATION, "Non Repudiation");
	KEY_USAGE(JHD_TLS_X509_KU_KEY_ENCIPHERMENT, "Key Encipherment");
	KEY_USAGE(JHD_TLS_X509_KU_DATA_ENCIPHERMENT, "Data Encipherment");
	KEY_USAGE(JHD_TLS_X509_KU_KEY_AGREEMENT, "Key Agreement");
	KEY_USAGE(JHD_TLS_X509_KU_KEY_CERT_SIGN, "Key Cert Sign");
	KEY_USAGE(JHD_TLS_X509_KU_CRL_SIGN, "CRL Sign");
	KEY_USAGE(JHD_TLS_X509_KU_ENCIPHER_ONLY, "Encipher Only");
	KEY_USAGE(JHD_TLS_X509_KU_DECIPHER_ONLY, "Decipher Only");

	*size = n;
	*buf = p;

	return (0);
}

static int x509_info_ext_key_usage(char **buf, size_t *size, const jhd_tls_x509_sequence *extended_key_usage) {
	int ret;
	const char *desc;
	size_t n = *size;
	char *p = *buf;
	const jhd_tls_x509_sequence *cur = extended_key_usage;
	const char *sep = "";

	while (cur != NULL) {
		jhd_tls_oid_get_extended_key_usage(&cur->buf, &desc);
		if(desc== NULL){
			desc = "???";
		}
		ret = snprintf(p, n, "%s%s", sep, desc);
		JHD_TLS_X509_SAFE_SNPRINTF;

		sep = ", ";

		cur = cur->next;
	}

	*size = n;
	*buf = p;

	return (0);
}

/*
 * Return an informational string about the certificate.
 */
#define BEFORE_COLON    18
#define BC              "18"
int jhd_tls_x509_crt_info(char *buf, size_t size, const char *prefix, const jhd_tls_x509_crt *crt) {
	int ret;
	size_t n;
	char *p;
	char key_size_str[BEFORE_COLON];

	p = buf;
	n = size;

	if ( NULL == crt) {
		ret = snprintf(p, n, "\nCertificate is uninitialised!\n");
		JHD_TLS_X509_SAFE_SNPRINTF;

		return ((int) (size - n));
	}

	ret = snprintf(p, n, "%scert. version     : %d\n", prefix, crt->version);
	JHD_TLS_X509_SAFE_SNPRINTF;
	ret = snprintf(p, n, "%sserial number     : ", prefix);
	JHD_TLS_X509_SAFE_SNPRINTF;

	ret = jhd_tls_x509_serial_gets(p, n, &crt->serial);
	JHD_TLS_X509_SAFE_SNPRINTF;

	ret = snprintf(p, n, "\n%sissuer name       : ", prefix);
	JHD_TLS_X509_SAFE_SNPRINTF;
	ret = jhd_tls_x509_dn_gets(p, n, &crt->issuer);
	JHD_TLS_X509_SAFE_SNPRINTF;

	ret = snprintf(p, n, "\n%ssubject name      : ", prefix);
	JHD_TLS_X509_SAFE_SNPRINTF;
	ret = jhd_tls_x509_dn_gets(p, n, &crt->subject);
	JHD_TLS_X509_SAFE_SNPRINTF;

	ret = snprintf(p, n, "\n%sissued  on        : "
			"%04d-%02d-%02d %02d:%02d:%02d", prefix, crt->valid_from.year, crt->valid_from.mon, crt->valid_from.day, crt->valid_from.hour, crt->valid_from.min,
	        crt->valid_from.sec);
	JHD_TLS_X509_SAFE_SNPRINTF;

	ret = snprintf(p, n, "\n%sexpires on        : "
			"%04d-%02d-%02d %02d:%02d:%02d", prefix, crt->valid_to.year, crt->valid_to.mon, crt->valid_to.day, crt->valid_to.hour, crt->valid_to.min,
	        crt->valid_to.sec);
	JHD_TLS_X509_SAFE_SNPRINTF;

	ret = snprintf(p, n, "\n%ssigned using      : ", prefix);
	JHD_TLS_X509_SAFE_SNPRINTF;

	ret = jhd_tls_x509_sig_alg_gets(p, n, &crt->sig_oid, crt->sig_pk, crt->sig_md);
	JHD_TLS_X509_SAFE_SNPRINTF;

	/* Key size */
	if ((ret = jhd_tls_x509_key_size_helper(key_size_str, BEFORE_COLON, jhd_tls_pk_get_name(&crt->pk))) != 0) {
		return (ret);
	}

	ret = snprintf(p, n, "\n%s%-" BC "s: %d bits", prefix, key_size_str, (int) jhd_tls_pk_get_bitlen(&crt->pk));
	JHD_TLS_X509_SAFE_SNPRINTF;

	/*
	 * Optional extensions
	 */

	if (crt->ext_types & JHD_TLS_X509_EXT_BASIC_CONSTRAINTS) {
		ret = snprintf(p, n, "\n%sbasic constraints : CA=%s", prefix, crt->ca_istrue ? "true" : "false");
		JHD_TLS_X509_SAFE_SNPRINTF;

		if (crt->max_pathlen > 0) {
			ret = snprintf(p, n, ", max_pathlen=%d", crt->max_pathlen - 1);
			JHD_TLS_X509_SAFE_SNPRINTF;
		}
	}

	if (crt->ext_types & JHD_TLS_X509_EXT_SUBJECT_ALT_NAME) {
		ret = snprintf(p, n, "\n%ssubject alt name  : ", prefix);
		JHD_TLS_X509_SAFE_SNPRINTF;

		if ((ret = x509_info_subject_alt_name(&p, &n, &crt->subject_alt_names)) != 0)
			return (ret);
	}

	if (crt->ext_types & JHD_TLS_X509_EXT_NS_CERT_TYPE) {
		ret = snprintf(p, n, "\n%scert. type        : ", prefix);
		JHD_TLS_X509_SAFE_SNPRINTF;

		if ((ret = x509_info_cert_type(&p, &n, crt->ns_cert_type)) != 0)
			return (ret);
	}

	if (crt->ext_types & JHD_TLS_X509_EXT_KEY_USAGE) {
		ret = snprintf(p, n, "\n%skey usage         : ", prefix);
		JHD_TLS_X509_SAFE_SNPRINTF;

		if ((ret = x509_info_key_usage(&p, &n, crt->key_usage)) != 0)
			return (ret);
	}

	if (crt->ext_types & JHD_TLS_X509_EXT_EXTENDED_KEY_USAGE) {
		ret = snprintf(p, n, "\n%sext key usage     : ", prefix);
		JHD_TLS_X509_SAFE_SNPRINTF;

		if ((ret = x509_info_ext_key_usage(&p, &n, &crt->ext_key_usage)) != 0)
			return (ret);
	}

	ret = snprintf(p, n, "\n");
	JHD_TLS_X509_SAFE_SNPRINTF;

	return ((int) (size - n));
}

struct x509_crt_verify_string {
	int code;
	const char *string;
};

static const struct x509_crt_verify_string x509_crt_verify_strings[] = { { JHD_TLS_X509_BADCERT_EXPIRED, "The certificate validity has expired" }, {
JHD_TLS_X509_BADCERT_REVOKED, "The certificate has been revoked (is on a CRL)" }, { JHD_TLS_X509_BADCERT_CN_MISMATCH,
        "The certificate Common Name (CN) does not match with the expected CN" }, { JHD_TLS_X509_BADCERT_NOT_TRUSTED,
        "The certificate is not correctly signed by the trusted CA" }, { JHD_TLS_X509_BADCRL_NOT_TRUSTED, "The CRL is not correctly signed by the trusted CA" },
        { JHD_TLS_X509_BADCRL_EXPIRED, "The CRL is expired" }, { JHD_TLS_X509_BADCERT_MISSING, "Certificate was missing" }, { JHD_TLS_X509_BADCERT_SKIP_VERIFY,
                "Certificate verification was skipped" }, { JHD_TLS_X509_BADCERT_OTHER, "Other reason (can be used by verify callback)" }, {
        JHD_TLS_X509_BADCERT_FUTURE, "The certificate validity starts in the future" }, { JHD_TLS_X509_BADCRL_FUTURE, "The CRL is from the future" }, {
        JHD_TLS_X509_BADCERT_KEY_USAGE, "Usage does not match the keyUsage extension" }, { JHD_TLS_X509_BADCERT_EXT_KEY_USAGE,
                "Usage does not match the extendedKeyUsage extension" }, { JHD_TLS_X509_BADCERT_NS_CERT_TYPE, "Usage does not match the nsCertType extension" },
        { JHD_TLS_X509_BADCERT_BAD_MD, "The certificate is signed with an unacceptable hash." }, { JHD_TLS_X509_BADCERT_BAD_PK,
                "The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA)." }, { JHD_TLS_X509_BADCERT_BAD_KEY,
                "The certificate is signed with an unacceptable key (eg bad curve, RSA too short)." }, { JHD_TLS_X509_BADCRL_BAD_MD,
                "The CRL is signed with an unacceptable hash." }, { JHD_TLS_X509_BADCRL_BAD_PK,
                "The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA)." }, { JHD_TLS_X509_BADCRL_BAD_KEY,
                "The CRL is signed with an unacceptable key (eg bad curve, RSA too short)." }, { 0, NULL } };

int jhd_tls_x509_crt_verify_info(char *buf, size_t size, const char *prefix, uint32_t flags) {
	int ret;
	const struct x509_crt_verify_string *cur;
	char *p = buf;
	size_t n = size;

	for (cur = x509_crt_verify_strings; cur->string != NULL; cur++) {
		if ((flags & cur->code) == 0)
			continue;

		ret = snprintf(p, n, "%s%s\n", prefix, cur->string);
		JHD_TLS_X509_SAFE_SNPRINTF;
		flags ^= cur->code;
	}

	if (flags != 0) {
		ret = snprintf(p, n, "%sUnknown reason "
				"(this should not happen)\n", prefix);
		JHD_TLS_X509_SAFE_SNPRINTF;
	}

	return ((int) (size - n));
}


int jhd_tls_x509_crt_check_key_usage(const jhd_tls_x509_crt *crt, unsigned int usage) {
	unsigned int usage_must, usage_may;
	unsigned int may_mask = JHD_TLS_X509_KU_ENCIPHER_ONLY | JHD_TLS_X509_KU_DECIPHER_ONLY;

	if ((crt->ext_types & JHD_TLS_X509_EXT_KEY_USAGE) == 0)
		return (0);

	usage_must = usage & ~may_mask;

	if (((crt->key_usage & ~may_mask) & usage_must) != usage_must)
		return JHD_ERROR;

	usage_may = usage & may_mask;

	if (((crt->key_usage & may_mask) | usage_may) != usage_may)
		return JHD_ERROR;

	return (0);
}



int jhd_tls_x509_crt_check_extended_key_usage(const jhd_tls_x509_crt *crt, const char *usage_oid, size_t usage_len) {
	const jhd_tls_x509_sequence *cur;

	/* Extension is not mandatory, absent means no restriction */
	if ((crt->ext_types & JHD_TLS_X509_EXT_EXTENDED_KEY_USAGE) == 0)
		return (0);

	/*
	 * Look for the requested usage (or wildcard ANY) in our list
	 */
	for (cur = &crt->ext_key_usage; cur != NULL; cur = cur->next) {
		const jhd_tls_x509_buf *cur_oid = &cur->buf;

		if (cur_oid->len == usage_len && memcmp(cur_oid->p, usage_oid, usage_len) == 0) {
			return (0);
		}

		if ( JHD_TLS_OID_CMP( JHD_TLS_OID_ANY_EXTENDED_KEY_USAGE, cur_oid ) == 0)
			return (0);
	}

	return JHD_ERROR;
}


//
/*
 * Like memcmp, but case-insensitive and always returns -1 if different
 */
static int x509_memcasecmp(const void *s1, const void *s2, size_t len) {
	size_t i;
	unsigned char diff;
	const unsigned char *n1 = s1, *n2 = s2;

	for (i = 0; i < len; i++) {
		diff = n1[i] ^ n2[i];

		if (diff == 0)
			continue;

		if (diff == 32 && ((n1[i] >= 'a' && n1[i] <= 'z') || (n1[i] >= 'A' && n1[i] <= 'Z'))) {
			continue;
		}

		return (-1);
	}

	return (0);
}

///*
// * Return 0 if name matches wildcard, -1 otherwise
// */
static int x509_check_wildcard(const unsigned char *hostname, const jhd_tls_x509_buf *name,size_t len) {
	size_t idx = 0;

	/* We can't have a match if there is no wildcard to match */
	if (name->len < 3 || name->p[0] != '*' || name->p[1] != '.')
		return (-1);


	idx = len - name->len;

	if(idx>0){
		if(hostname[idx] == '.'){
			if(x509_memcasecmp(name->p + 1, hostname + idx+1, name->len - 1) == 0){
				return 0;
			}
		}
	}
	return (-1);
}

///*
// * Compare two X.509 strings, case-insensitive, and allowing for some encoding
// * variations (but not all).
// *
// * Return 0 if equal, -1 otherwise.
// */
//static int x509_string_cmp(const jhd_tls_x509_buf *a, const jhd_tls_x509_buf *b) {
//	if (a->tag == b->tag && a->len == b->len && memcmp(a->p, b->p, b->len) == 0) {
//		return (0);
//	}
//
//	if ((a->tag == JHD_TLS_ASN1_UTF8_STRING || a->tag == JHD_TLS_ASN1_PRINTABLE_STRING)
//	        && (b->tag == JHD_TLS_ASN1_UTF8_STRING || b->tag == JHD_TLS_ASN1_PRINTABLE_STRING) && a->len == b->len
//	        && x509_memcasecmp(a->p, b->p, b->len) == 0) {
//		return (0);
//	}
//
//	return (-1);
//}

///*
// * Compare two X.509 Names (aka rdnSequence).
// *
// * See RFC 5280 section 7.1, though we don't implement the whole algorithm:
// * we sometimes return unequal when the full algorithm would return equal,
// * but never the other way. (In particular, we don't do Unicode normalisation
// * or space folding.)
// *
// * Return 0 if equal, -1 otherwise.
// */
//static int x509_name_cmp(const jhd_tls_x509_name *a, const jhd_tls_x509_name *b) {
//	/* Avoid recursion, it might not be optimised by the compiler */
//	while (a != NULL || b != NULL) {
//		if (a == NULL || b == NULL)
//			return (-1);
//
//		/* type */
//		if (a->oid.tag != b->oid.tag || a->oid.len != b->oid.len || memcmp(a->oid.p, b->oid.p, b->oid.len) != 0) {
//			return (-1);
//		}
//
//		/* value */
//		if (x509_string_cmp(&a->val, &b->val) != 0)
//			return (-1);
//
//		/* structure of the list of sets */
//		if (a->next_merged != b->next_merged)
//			return (-1);
//
//		a = a->next;
//		b = b->next;
//	}
//
//	/* a == NULL == b */
//	return (0);
//}

///*
// * Check the signature of a certificate by its parent
// */
//static int x509_crt_check_signature(const jhd_tls_x509_crt *child, jhd_tls_x509_crt *parent) {
//	const jhd_tls_md_info_t *md_info;
//	unsigned char hash[JHD_TLS_MD_MAX_SIZE];
//
//	md_info = child->sig_md;
//	jhd_tls_md(md_info, child->tbs.p, child->tbs.len, hash);
//
//	if (jhd_tls_pk_verify_ext(child->sig_pk, child->sig_opts, &parent->pk, child->sig_md, hash, jhd_tls_md_get_size(md_info), child->sig.p, child->sig.len)
//	        != 0) {
//		return (-1);
//	}
//
//	return (0);
//}

/*
 * Check if 'parent' is a suitable parent (signing CA) for 'child'.
 * Return 0 if yes, -1 if not.
 *
 * top means parent is a locally-trusted certificate
 */
//static int x509_crt_check_parent(const jhd_tls_x509_crt *child, const jhd_tls_x509_crt *parent, int top) {
//	int need_ca_bit;
//
//	/* Parent must be the issuer */
//	if (x509_name_cmp(&child->issuer, &parent->subject) != 0)
//		return (-1);
//
//	/* Parent must have the basicConstraints CA bit set as a general rule */
//	need_ca_bit = 1;
//
//	/* Exception: v1/v2 certificates that are locally trusted. */
//	if (top && parent->version < 3)
//		need_ca_bit = 0;
//
//	if (need_ca_bit && !parent->ca_istrue)
//		return (-1);
//
//
//	if (need_ca_bit && jhd_tls_x509_crt_check_key_usage(parent, JHD_TLS_X509_KU_KEY_CERT_SIGN) != 0) {
//		return (-1);
//	}
//
//
//	return (0);
//}

///*
// * Find a suitable parent for child in candidates, or return NULL.
// *
// * Here suitable is defined as:
// *  1. subject name matches child's issuer
// *  2. if necessary, the CA bit is set and key usage allows signing certs
// *  3. for trusted roots, the signature is correct
// *  4. pathlen constraints are satisfied
// *
// * If there's a suitable candidate which is also time-valid, return the first
// * such. Otherwise, return the first suitable candidate (or NULL if there is
// * none).
// *
// * The rationale for this rule is that someone could have a list of trusted
// * roots with two versions on the same root with different validity periods.
// * (At least one user reported having such a list and wanted it to just work.)
// * The reason we don't just require time-validity is that generally there is
// * only one version, and if it's expired we want the flags to state that
// * rather than NOT_TRUSTED, as would be the case if we required it here.
// *
// * The rationale for rule 3 (signature for trusted roots) is that users might
// * have two versions of the same CA with different keys in their list, and the
// * way we select the correct one is by checking the signature (as we don't
// * rely on key identifier extensions). (This is one way users might choose to
// * handle key rollover, another relies on self-issued certs, see [SIRO].)
// *
// * Arguments:
// *  - [in] child: certificate for which we're looking for a parent
// *  - [in] candidates: chained list of potential parents
// *  - [in] top: 1 if candidates consists of trusted roots, ie we're at the top
// *         of the chain, 0 otherwise
// *  - [in] path_cnt: number of intermediates seen so far
// *  - [in] self_cnt: number of self-signed intermediates seen so far
// *         (will never be greater than path_cnt)
// *
// * Return value:
// *  - the first suitable parent found (see above regarding time-validity)
// *  - NULL if no suitable parent was found
// */
//static jhd_tls_x509_crt *x509_crt_find_parent_in(jhd_tls_x509_crt *child, jhd_tls_x509_crt *candidates, int top, size_t path_cnt, size_t self_cnt) {
//	jhd_tls_x509_crt *parent, *badtime_parent = NULL;
//
//	for (parent = candidates; parent != NULL; parent = parent->next) {
//		/* basic parenting skills (name, CA bit, key usage) */
//		if (x509_crt_check_parent(child, parent, top) != 0)
//			continue;
//
//		/* +1 because stored max_pathlen is 1 higher that the actual value */
//		if (parent->max_pathlen > 0 && (size_t) parent->max_pathlen < 1 + path_cnt - self_cnt) {
//			continue;
//		}
//
//		/* Signature */
//		if (top && x509_crt_check_signature(child, parent) != 0) {
//			continue;
//		}
//
//		/* optional time check */
//		if (jhd_tls_x509_time_is_past(&parent->valid_to) || jhd_tls_x509_time_is_future(&parent->valid_from)) {
//			if (badtime_parent == NULL)
//				badtime_parent = parent;
//
//			continue;
//		}
//
//		break;
//	}
//
//	if (parent == NULL)
//		parent = badtime_parent;
//
//	return (parent);
//}

///*
// * Find a parent in trusted CAs or the provided chain, or return NULL.
// *
// * Searches in trusted CAs first, and return the first suitable parent found
// * (see find_parent_in() for definition of suitable).
// *
// * Arguments:
// *  - [in] child: certificate for which we're looking for a parent, followed
// *         by a chain of possible intermediates
// *  - [in] trust_ca: locally trusted CAs
// *  - [out] 1 if parent was found in trust_ca, 0 if found in provided chain
// *  - [in] path_cnt: number of intermediates seen so far
// *  - [in] self_cnt: number of self-signed intermediates seen so far
// *         (will always be no greater than path_cnt)
// *
// * Return value:
// *  - the first suitable parent found (see find_parent_in() for "suitable")
// *  - NULL if no suitable parent was found
// */
//static jhd_tls_x509_crt *x509_crt_find_parent(jhd_tls_x509_crt *child, jhd_tls_x509_crt *trust_ca, int *parent_is_trusted, size_t path_cnt, size_t self_cnt) {
//	jhd_tls_x509_crt *parent;
//
//	/* Look for a parent in trusted CAs */
//	*parent_is_trusted = 1;
//	parent = x509_crt_find_parent_in(child, trust_ca, 1, path_cnt, self_cnt);
//
//	if (parent != NULL)
//		return (parent);
//
//	/* Look for a parent upwards the chain */
//	*parent_is_trusted = 0;
//	return (x509_crt_find_parent_in(child, child->next, 0, path_cnt, self_cnt));
//}

/*
 * Check if an end-entity certificate is locally trusted
 *
 * Currently we require such certificates to be self-signed (actually only
 * check for self-issued as self-signatures are not checked)
 */
//static int x509_crt_check_ee_locally_trusted(jhd_tls_x509_crt *crt, jhd_tls_x509_crt *trust_ca) {
//	jhd_tls_x509_crt *cur;
//
//	/* must be self-issued */
//	if (x509_name_cmp(&crt->issuer, &crt->subject) != 0)
//		return (-1);
//
//	/* look for an exact match with trusted cert */
//	for (cur = trust_ca; cur != NULL; cur = cur->next) {
//		if (crt->raw.len == cur->raw.len && memcmp(crt->raw.p, cur->raw.p, crt->raw.len) == 0) {
//			return (0);
//		}
//	}
//
//	/* too bad */
//	return (-1);
//}

///*
// * Build and verify a certificate chain
// *
// * Given a peer-provided list of certificates EE, C1, ..., Cn and
// * a list of trusted certs R1, ... Rp, try to build and verify a chain
// *      EE, Ci1, ... Ciq [, Rj]
// * such that every cert in the chain is a child of the next one,
// * jumping to a trusted root as early as possible.
// *
// * Verify that chain and return it with flags for all issues found.
// *
// * Special cases:
// * - EE == Rj -> return a one-element list containing it
// * - EE, Ci1, ..., Ciq cannot be continued with a trusted root
// *   -> return that chain with NOT_TRUSTED set on Ciq
// *
// * Arguments:
// *  - [in] crt: the cert list EE, C1, ..., Cn
// *  - [in] trust_ca: the trusted list R1, ..., Rp
// *  - [in] ca_crl, profile: as in verify_with_profile()
// *  - [out] ver_chain, chain_len: the built and verified chain
// *
// * Return value:
// *  - non-zero if the chain could not be fully built and examined
// *  - 0 is the chain was successfully built and examined,
// *      even if it was found to be invalid
// */
//static int x509_crt_verify_chain(jhd_tls_x509_crt *crt, jhd_tls_x509_crt *trust_ca,const jhd_tls_x509_crt_profile *profile,
//        x509_crt_verify_chain_item ver_chain[X509_MAX_VERIFY_CHAIN_SIZE], size_t *chain_len) {
//	uint32_t *flags;
//	jhd_tls_x509_crt *child;
//	jhd_tls_x509_crt *parent;
//	int parent_is_trusted = 0;
//	int child_is_trusted = 0;
//	size_t self_cnt = 0;
//
//	child = crt;
//	*chain_len = 0;
//
//	while (1) {
//		/* Add certificate to the verification chain */
//		ver_chain[*chain_len].crt = child;
//		flags = &ver_chain[*chain_len].flags;
//		++*chain_len;
//
//		/* Check time-validity (all certificates) */
//		if (jhd_tls_x509_time_is_past(&child->valid_to))
//			*flags |= JHD_TLS_X509_BADCERT_EXPIRED;
//
//		if (jhd_tls_x509_time_is_future(&child->valid_from))
//			*flags |= JHD_TLS_X509_BADCERT_FUTURE;
//
//		/* Stop here for trusted roots (but not for trusted EE certs) */
//		if (child_is_trusted)
//			return (0);
//
//		/* Check signature algorithm: MD & PK algs */
//		if (x509_profile_check_md_alg(profile, child->sig_md) != 0)
//			*flags |= JHD_TLS_X509_BADCERT_BAD_MD;
//
//		if (x509_profile_check_pk_alg(profile, child->sig_pk) != 0)
//			*flags |= JHD_TLS_X509_BADCERT_BAD_PK;
//
//		/* Special case: EE certs that are locally trusted */
//		if (*chain_len == 1 && x509_crt_check_ee_locally_trusted(child, trust_ca) == 0) {
//			return (0);
//		}
//
//		/* Look for a parent in trusted CAs or up the chain */
//		parent = x509_crt_find_parent(child, trust_ca, &parent_is_trusted, *chain_len - 1, self_cnt);
//
//		/* No parent? We're done here */
//		if (parent == NULL) {
//			*flags |= JHD_TLS_X509_BADCERT_NOT_TRUSTED;
//			return (0);
//		}
//
//		/* Count intermediate self-issued (not necessarily self-signed) certs.
//		 * These can occur with some strategies for key rollover, see [SIRO],
//		 * and should be excluded from max_pathlen checks. */
//		if (*chain_len != 1 && x509_name_cmp(&child->issuer, &child->subject) == 0) {
//			self_cnt++;
//		}
//
//		/* path_cnt is 0 for the first intermediate CA,
//		 * and if parent is trusted it's not an intermediate CA */
//		if (!parent_is_trusted && *chain_len > JHD_TLS_X509_MAX_INTERMEDIATE_CA) {
//			/* return immediately to avoid overflow the chain array */
//			return ( JHD_TLS_ERR_X509_FATAL_ERROR);
//		}
//
//		/* if parent is trusted, the signature was checked by find_parent() */
//		if (!parent_is_trusted && x509_crt_check_signature(child, parent) != 0)
//			*flags |= JHD_TLS_X509_BADCERT_NOT_TRUSTED;
//
//		/* check size of signing key */
//		if (x509_profile_check_key(profile, &parent->pk) != 0)
//			*flags |= JHD_TLS_X509_BADCERT_BAD_KEY;
//
//
//		/* prepare for next iteration */
//		child = parent;
//		parent = NULL;
//		child_is_trusted = parent_is_trusted;
//	}
//}

/*
 * Check for CN match
 */
static int x509_crt_check_hostname(const jhd_tls_x509_buf *name, const unsigned char *hostname, size_t len) {
	/* try exact match */
	if (name->len == len && x509_memcasecmp(hostname, name->p,len) == 0) {
		return (0);
	}

	/* try wildcard match */
	return x509_check_wildcard(hostname, name,len) ;
}

///*
// * Verify the requested CN - only call this if cn is not NULL!
// */
int jhd_tls_x509_crt_verify_name(const jhd_tls_x509_crt *crt, const unsigned char *hostname,size_t len) {
	const jhd_tls_x509_name *name;
	const jhd_tls_x509_sequence *cur;

	if (crt->ext_types & JHD_TLS_X509_EXT_SUBJECT_ALT_NAME) {
		for (cur = &crt->subject_alt_names; cur != NULL; cur = cur->next) {
			if (x509_crt_check_hostname(&cur->buf, hostname, len) == 0)
				break;
		}
		return cur == NULL ? JHD_UNEXPECTED:JHD_OK;
	} else {
		for (name = &crt->subject; name != NULL; name = name->next) {
			if ( JHD_TLS_OID_CMP( JHD_TLS_OID_AT_CN, &name->oid ) == 0 && x509_crt_check_hostname(&name->val, hostname, len) == 0) {
				break;
			}
		}
		return name == NULL ? JHD_UNEXPECTED:JHD_OK;
	}
}

///*
// * Merge the flags for all certs in the chain, after calling callback
// */
//static int x509_crt_merge_flags_with_cb(uint32_t *flags, x509_crt_verify_chain_item ver_chain[X509_MAX_VERIFY_CHAIN_SIZE], size_t chain_len,
//        int (*f_vrfy)(void *, jhd_tls_x509_crt *, int, uint32_t *), void *p_vrfy) {
//	int ret;
//	size_t i;
//	uint32_t cur_flags;
//
//	for (i = chain_len; i != 0; --i) {
//		cur_flags = ver_chain[i - 1].flags;
//
//		if ( NULL != f_vrfy)
//			if ((ret = f_vrfy(p_vrfy, ver_chain[i - 1].crt, (int) i - 1, &cur_flags)) != 0)
//				return (ret);
//
//		*flags |= cur_flags;
//	}
//
//	return (0);
//}


///*
// * Verify the certificate validity, with profile
// *
// * This function:
// *  - checks the requested CN (if any)
// *  - checks the type and size of the EE cert's key,
// *    as that isn't done as part of chain building/verification currently
// *  - builds and verifies the chain
// *  - then calls the callback and merges the flags
// */
//int jhd_tls_x509_crt_verify_with_profile(jhd_tls_x509_crt *crt, jhd_tls_x509_crt *trust_ca, const jhd_tls_x509_crt_profile *profile,
//     uint32_t *flags) {
//	int ret;
//	x509_crt_verify_chain_item ver_chain[X509_MAX_VERIFY_CHAIN_SIZE];
//	size_t chain_len;
//	uint32_t *ee_flags = &ver_chain[0].flags;
//
//	*flags = 0;
//	memset(ver_chain, 0, sizeof(ver_chain));
//	chain_len = 0;
//	if (profile == NULL) {
//		ret = JHD_ERROR;
//		goto exit;
//	}
//	if (x509_profile_check_pk_alg(profile, crt->pk.pk_info) != 0)
//		*ee_flags |= JHD_TLS_X509_BADCERT_BAD_PK;
//
//	if (x509_profile_check_key(profile, &crt->pk) != 0)
//		*ee_flags |= JHD_TLS_X509_BADCERT_BAD_KEY;
//
//	/* Check the chain */
//	ret = x509_crt_verify_chain(crt, trust_ca, ca_crl, profile, ver_chain, &chain_len);
//	if (ret != 0)
//		goto exit;
//
//	/* Build final flags, calling callback on the way if any */
//	ret = x509_crt_merge_flags_with_cb(flags, ver_chain, chain_len, f_vrfy, p_vrfy);
//
//	exit:
//	/* prevent misuse of the vrfy callback - VERIFY_FAILED would be ignored by
//	 * the SSL module for authmode optional, but non-zero return from the
//	 * callback means a fatal error so it shouldn't be ignored */
//	if (ret == JHD_TLS_ERR_X509_CERT_VERIFY_FAILED)
//		ret = JHD_TLS_ERR_X509_FATAL_ERROR;
//
//	if (ret != 0) {
//		*flags = (uint32_t) -1;
//		return (ret);
//	}
//
//	if (*flags != 0)
//		return ( JHD_TLS_ERR_X509_CERT_VERIFY_FAILED);
//
//	return (0);
//}

#if !defined(JHD_TLS_INLINE)
/**
 * \brief          Initialize a certificate (chain)
 *
 * \param crt      Certificate chain to initialize
 */
void jhd_tls_x509_crt_init(jhd_tls_x509_crt *crt) {
	memset((void*) crt, 0, sizeof(jhd_tls_x509_crt));
}

#endif

/*
 * Unallocate all certificate data
 */

//FIXME: check free impl
void jhd_tls_x509_crt_free(jhd_tls_x509_crt *crt) {
	jhd_tls_x509_crt *cert_cur = crt;
	jhd_tls_x509_crt *cert_prv;
	jhd_tls_x509_name *name_cur;
	jhd_tls_x509_name *name_prv;
	jhd_tls_x509_sequence *seq_cur;
	jhd_tls_x509_sequence *seq_prv;

	do {
		if(cert_cur->pk.pk_ctx){
			jhd_tls_free_with_size(cert_cur->pk.pk_ctx,cert_cur->pk.pk_info->ctx_size);
			cert_cur->pk.pk_ctx = NULL;
		}
		name_cur = cert_cur->issuer.next;
		while (name_cur != NULL) {
			name_prv = name_cur;
			name_cur = name_cur->next;
			jhd_tls_free_with_size(name_prv,sizeof(jhd_tls_x509_name));
		}

		name_cur = cert_cur->subject.next;
		while (name_cur != NULL) {
			name_prv = name_cur;
			name_cur = name_cur->next;
			jhd_tls_free_with_size(name_prv,sizeof(jhd_tls_x509_name));
		}

		seq_cur = cert_cur->ext_key_usage.next;
		while (seq_cur != NULL) {
			seq_prv = seq_cur;
			seq_cur = seq_cur->next;
			jhd_tls_free_with_size(seq_prv,sizeof(jhd_tls_x509_sequence));
		}

		seq_cur = cert_cur->subject_alt_names.next;
		while (seq_cur != NULL) {
			seq_prv = seq_cur;
			seq_cur = seq_cur->next;
			jhd_tls_free_with_size(seq_prv,sizeof(jhd_tls_x509_sequence));
		}

		if (cert_cur->raw.p != NULL) {
			jhd_tls_free_with_size(cert_cur->raw.p,cert_cur->raw.len);
		}

		cert_cur = cert_cur->next;
	} while (cert_cur != NULL);

	cert_cur = crt;
	do {
		cert_prv = cert_cur;
		cert_cur = cert_cur->next;

		jhd_tls_platform_zeroize(cert_prv, sizeof(jhd_tls_x509_crt));
		if (cert_prv != crt){
			jhd_tls_free(cert_prv);
		}else{
			//FIXME:CHECK
			jhd_tls_platform_zeroize(cert_prv, sizeof(jhd_tls_x509_crt));
		}
	} while (cert_cur != NULL);
}


void jhd_tls_x509_crt_free_by_malloc(jhd_tls_x509_crt *crt) {
	jhd_tls_x509_crt *cert_cur = crt;
	jhd_tls_x509_crt *cert_prv;
	jhd_tls_x509_name *name_cur;
	jhd_tls_x509_name *name_prv;
	jhd_tls_x509_sequence *seq_cur;
	jhd_tls_x509_sequence *seq_prv;
	do {
		if(cert_cur->pk.pk_ctx){
			free(cert_cur->pk.pk_ctx);
			cert_cur->pk.pk_ctx = NULL;
		}
		name_cur = cert_cur->issuer.next;
		while (name_cur != NULL) {
			name_prv = name_cur;
			name_cur = name_cur->next;
			free(name_prv);
		}

		name_cur = cert_cur->subject.next;
		while (name_cur != NULL) {
			name_prv = name_cur;
			name_cur = name_cur->next;
			free(name_prv);
		}

		seq_cur = cert_cur->ext_key_usage.next;
		while (seq_cur != NULL) {
			seq_prv = seq_cur;
			seq_cur = seq_cur->next;
			free(seq_prv);
		}

		seq_cur = cert_cur->subject_alt_names.next;
		while (seq_cur != NULL) {
			seq_prv = seq_cur;
			seq_cur = seq_cur->next;
			free(seq_prv);
		}

		if (cert_cur->raw.p != NULL) {
			free(cert_cur->raw.p);
		}
		cert_cur = cert_cur->next;
	} while (cert_cur != NULL);
	cert_cur = crt;
	do {
		cert_prv = cert_cur;
		cert_cur = cert_cur->next;
		if (cert_prv != crt){
			free(cert_prv);
		}/*else{
			jhd_tls_platform_zeroize(cert_prv, sizeof(jhd_tls_x509_crt));
		}*/
	} while (cert_cur != NULL);
}

