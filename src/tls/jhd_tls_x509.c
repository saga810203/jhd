#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>


#include <tls/jhd_tls_x509.h>
#include <tls/jhd_tls_asn1.h>
#include <tls/jhd_tls_oid.h>

#include <stdio.h>
#include <string.h>
#include <tls/jhd_tls_pem.h>
#include <tls/jhd_tls_platform.h>
#include <tls/jhd_tls_md_internal.h>


#include <time.h>


#define CHECK(code) if( ( ret = code ) != 0 ){ return( ret ); }
#define CHECK_RANGE(min, max, val) if( val < min || val > max ){ return( ret ); }

/*
 *  CertificateSerialNumber  ::=  INTEGER
 */
int jhd_tls_x509_get_serial( unsigned char **p, const unsigned char *end,jhd_tls_x509_buf *serial )
{
    int ret;

    if( ( end - *p ) < 1 ){
        return JHD_ERROR;
    }
    if( **p != ( JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_PRIMITIVE | 2 ) && **p !=   JHD_TLS_ASN1_INTEGER )
        return JHD_ERROR;
    serial->tag = *(*p)++;
    if( ( ret = jhd_tls_asn1_get_len( p, end, &serial->len ) ) != 0 )
    	 return JHD_ERROR;

    serial->p = *p;
    *p += serial->len;
    return JHD_OK;
}


#if !defined(JHD_TLS_INLINE)
/* Get an algorithm identifier without parameters (eg for signatures)
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
int jhd_tls_x509_get_alg_null( unsigned char **p, const unsigned char *end,jhd_tls_x509_buf *alg )
{
   return  jhd_tls_asn1_get_alg_null( p, end, alg );
}

/*
 * Parse an algorithm identifier with (optional) paramaters
 */
int jhd_tls_x509_get_alg( unsigned char **p, const unsigned char *end,jhd_tls_x509_buf *alg, jhd_tls_x509_buf *params )
{
     return  jhd_tls_asn1_get_alg( p, end, alg, params );
}
#endif

/*
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
static int x509_get_attr_type_value( unsigned char **p,const unsigned char *end,jhd_tls_x509_name *cur )
{
    int ret;
    size_t len;
    jhd_tls_x509_buf *oid;
    jhd_tls_x509_buf *val;

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
        return JHD_ERROR;

    if( ( end - *p ) < 1 )
    	 return JHD_ERROR;

    oid = &cur->oid;
    oid->tag = **p;

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &oid->len, JHD_TLS_ASN1_OID ) ) != 0 )
    	 return JHD_ERROR;

    oid->p = *p;
    *p += oid->len;

    if( ( end - *p ) < 1 )
    	 return JHD_ERROR;

    if( **p != JHD_TLS_ASN1_BMP_STRING && **p != JHD_TLS_ASN1_UTF8_STRING      &&
        **p != JHD_TLS_ASN1_T61_STRING && **p != JHD_TLS_ASN1_PRINTABLE_STRING &&
        **p != JHD_TLS_ASN1_IA5_STRING && **p != JHD_TLS_ASN1_UNIVERSAL_STRING &&
        **p != JHD_TLS_ASN1_BIT_STRING )
    	 return JHD_ERROR;

    val = &cur->val;
    val->tag = *(*p)++;

    if( ( ret = jhd_tls_asn1_get_len( p, end, &val->len ) ) != 0 )
        return JHD_ERROR;

    val->p = *p;
    *p += val->len;
    return( 0 );
}

/*
 *  Name ::= CHOICE { -- only one possibility for now --
 *       rdnSequence  RDNSequence }
 *
 *  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 *
 * The data structure is optimized for the common case where each RDN has only
 * one element, which is represented as a list of AttributeTypeAndValue.
 * For the general case we still use a flat list, but we mark elements of the
 * same set so that they are "merged" together in the functions that consume
 * this list, eg jhd_tls_x509_dn_gets().
 */
int jhd_tls_x509_get_name( unsigned char **p,const unsigned char *end,jhd_tls_x509_name *cur )
{
    int ret;
    size_t set_len;
    const unsigned char *end_set;
    jhd_tls_x509_name *next=cur;
    do{
    	next->next_merged = 0;
    	next->oid.p= NULL;
    	next->val.p = NULL;
    	next = next->next;
    }while(next != NULL);
    while( 1 )
    {
       if( ( ret = jhd_tls_asn1_get_tag( p, end, &set_len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SET ) ) != 0 )
            return JHD_ERROR;
        end_set  = *p + set_len;
        while( 1 )
        {
            if( ( ret = x509_get_attr_type_value( p, end_set, cur ) ) != 0 )
                return( ret );
            if( *p == end_set )
                break;
            /* Mark this item as being no the only one in a set */
            cur->next_merged = 1;
            if(cur->next == NULL){
            	cur->next = jhd_tls_alloc(sizeof( jhd_tls_x509_name ) );
            	 if( cur->next == NULL ){
            	     return JHD_AGAIN;
            	 }
            	 jhd_tls_platform_zeroize(cur->next,sizeof( jhd_tls_x509_name));
            }
            cur = cur->next;
        }
		if (*p == end)
			return (0);
		if (cur->next == NULL) {
			cur->next = jhd_tls_alloc(sizeof(jhd_tls_x509_name));
			if (cur->next == NULL) {
				return JHD_AGAIN;
			}
			jhd_tls_platform_zeroize(cur->next, sizeof(jhd_tls_x509_name));
		}
		cur = cur->next;
    }
}


int jhd_tls_x509_get_name_by_malloc( unsigned char **p, const unsigned char *end,jhd_tls_x509_name *cur ){
	 int ret;
	    size_t set_len;
	    const unsigned char *end_set;
	    jhd_tls_x509_name *prev,*next=cur;
	    memset(next,0,sizeof(jhd_tls_x509_name));
	    for(;;){
	        if( ( ret = jhd_tls_asn1_get_tag( p, end, &set_len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SET ) ) != 0 ){
	            goto func_err;
	        }
	        end_set  = *p + set_len;
	        for(;;){
	            if( x509_get_attr_type_value( p, end_set, next)!= 0 ){
	               goto func_err;
	            }
	            if( *p == end_set ){
	                break;
	            }
	            next->next_merged = 1;
	            next->next = malloc(sizeof( jhd_tls_x509_name ) );
	            if(next->next == NULL){
	            	log_stderr("systemcall malloc error");
	            	return JHD_ERROR;
	            }
	            jhd_tls_platform_zeroize(next->next,sizeof( jhd_tls_x509_name));
	            next = next->next;
	        }
			if (*p == end)
				return (0);
			next->next = malloc(sizeof(jhd_tls_x509_name));
			if(cur->next == NULL){
				 log_stderr("systemcall malloc error");
				 return JHD_ERROR;
			}
			jhd_tls_platform_zeroize(next->next, sizeof(jhd_tls_x509_name));
			next = next->next;
	    }
	    return JHD_OK;
	func_err:
		prev = cur->next;
		if(prev){
			cur->next = NULL;
			for(;;){
				next = prev->next;
				free(prev);
				if(next){
					prev = next;
				}else{
					break;
				}
			}
		}
		return JHD_ERROR;
}



static int x509_parse_int( unsigned char **p, size_t n, int *res )
{
    *res = 0;

    for( ; n > 0; --n )
    {
        if( ( **p < '0') || ( **p > '9' ) )
            return JHD_ERROR;

        *res *= 10;
        *res += ( *(*p)++ - '0' );
    }

    return JHD_OK;
}

static int x509_date_is_valid(const jhd_tls_x509_time *t )
{
    int ret = JHD_ERROR;
    int month_len;

    CHECK_RANGE( 0, 9999, t->year );
    CHECK_RANGE( 0, 23,   t->hour );
    CHECK_RANGE( 0, 59,   t->min  );
    CHECK_RANGE( 0, 59,   t->sec  );

    switch( t->mon )
    {
        case 1: case 3: case 5: case 7: case 8: case 10: case 12:
            month_len = 31;
            break;
        case 4: case 6: case 9: case 11:
            month_len = 30;
            break;
        case 2:
            if( ( !( t->year % 4 ) && t->year % 100 ) ||
                !( t->year % 400 ) )
                month_len = 29;
            else
                month_len = 28;
            break;
        default:
            return( ret );
    }
    CHECK_RANGE( 1, month_len, t->day );

    return( 0 );
}

/*
 * Parse an ASN1_UTC_TIME (yearlen=2) or ASN1_GENERALIZED_TIME (yearlen=4)
 * field.
 */
static int x509_parse_time( unsigned char **p, size_t len, size_t yearlen,
                            jhd_tls_x509_time *tm )
{
    int ret;

    /*
     * Minimum length is 10 or 12 depending on yearlen
     */
    if ( len < yearlen + 8 )
        return JHD_ERROR;
    len -= yearlen + 8;

    /*
     * Parse year, month, day, hour, minute
     */
    CHECK( x509_parse_int( p, yearlen, &tm->year ) );
    if ( 2 == yearlen )
    {
        if ( tm->year < 50 )
            tm->year += 100;

        tm->year += 1900;
    }

    CHECK( x509_parse_int( p, 2, &tm->mon ) );
    CHECK( x509_parse_int( p, 2, &tm->day ) );
    CHECK( x509_parse_int( p, 2, &tm->hour ) );
    CHECK( x509_parse_int( p, 2, &tm->min ) );

    /*
     * Parse seconds if present
     */
    if ( len >= 2 )
    {
        CHECK( x509_parse_int( p, 2, &tm->sec ) );
        len -= 2;
    }
    else
        return JHD_ERROR;

    /*
     * Parse trailing 'Z' if present
     */
    if ( 1 == len && 'Z' == **p )
    {
        (*p)++;
        len--;
    }

    /*
     * We should have parsed all characters at this point
     */
    if ( 0 != len )
    	 return JHD_ERROR;
    CHECK( x509_date_is_valid( tm ) );

    return JHD_OK;
}

/*
 *  Time ::= CHOICE {
 *       utcTime        UTCTime,
 *       generalTime    GeneralizedTime }
 */
int jhd_tls_x509_get_time( unsigned char **p, const unsigned char *end,jhd_tls_x509_time *tm )
{
    int ret;
    size_t len, year_len;
    unsigned char tag;

    if( ( end - *p ) < 1 )
        return JHD_ERROR;

    tag = **p;

    if( tag == JHD_TLS_ASN1_UTC_TIME )
        year_len = 2;
    else if( tag == JHD_TLS_ASN1_GENERALIZED_TIME )
        year_len = 4;
    else
        return JHD_UNEXPECTED;

    (*p)++;
    ret = jhd_tls_asn1_get_len( p, end, &len );

    if( ret != 0 )
        return JHD_ERROR;

    return x509_parse_time( p, len, year_len, tm );
}

int jhd_tls_x509_get_sig( unsigned char **p, const unsigned char *end, jhd_tls_x509_buf *sig )
{
    int ret;
    size_t len;
    int tag_type;

    if( ( end - *p ) < 1 )
    	return JHD_ERROR;

    tag_type = **p;

    if( ( ret = jhd_tls_asn1_get_bitstring_null( p, end, &len ) ) != 0 )
    	return JHD_ERROR;

    sig->tag = tag_type;
    sig->len = len;
    sig->p = *p;

    *p += len;

    return( 0 );
}

/*
 * Get signature algorithm from alg OID and optional parameters
 */
int jhd_tls_x509_get_sig_alg( const jhd_tls_x509_buf *sig_oid, const jhd_tls_x509_buf *sig_params,const jhd_tls_md_info_t **md_info, const jhd_tls_pk_info_t **pk_info)
{
    jhd_tls_oid_get_sig_alg( sig_oid, md_info, pk_info );
    if(*md_info == NULL){
    	return JHD_UNSUPPORTED;
    }
    if( ( sig_params->tag != JHD_TLS_ASN1_NULL && sig_params->tag != 0 ) || sig_params->len != 0 )
        return JHD_ERROR;
    return JHD_OK;
}

/*
 * X.509 Extensions (No parsing of extensions, pointer should
 * be either manually updated or extensions should be parsed!)
 */
int jhd_tls_x509_get_ext( unsigned char **p, const unsigned char *end,
                  jhd_tls_x509_buf *ext, int tag )
{
    int ret;
    size_t len;

    if( *p == end )
        return( 0 );

    ext->tag = **p;

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &ext->len,JHD_TLS_ASN1_CONTEXT_SPECIFIC | JHD_TLS_ASN1_CONSTRUCTED | tag ) ) != 0 )
        return( ret );

    ext->p = *p;
    end = *p + ext->len;

    /*
     * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     *
     * Extension  ::=  SEQUENCE  {
     *      extnID      OBJECT IDENTIFIER,
     *      critical    BOOLEAN DEFAULT FALSE,
     *      extnValue   OCTET STRING  }
     */
    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
        return JHD_ERROR;

    if( end != *p + len )
        return JHD_ERROR;

    return JHD_OK;
}

/*
 * Store the name in printable form into buf; no more
 * than size characters will be written
 */
int jhd_tls_x509_dn_gets( char *buf, size_t size, const jhd_tls_x509_name *dn )
{
    int ret;
    size_t i, n;
    unsigned char c, merge = 0;
    const jhd_tls_x509_name *name;
    const char *short_name = NULL;
    char s[JHD_TLS_X509_MAX_DN_NAME_SIZE], *p;

    memset( s, 0, sizeof( s ) );

    name = dn;
    p = buf;
    n = size;

    while( name != NULL )
    {
        if( !name->oid.p )
        {
            name = name->next;
            continue;
        }

        if( name != dn )
        {
            ret = snprintf( p, n, merge ? " + " : ", " );
            JHD_TLS_X509_SAFE_SNPRINTF;
        }

        ret = jhd_tls_oid_get_attr_short_name( &name->oid, &short_name );

        if( ret == 0 )
            ret = snprintf( p, n, "%s=", short_name );
        else
            ret = snprintf( p, n, "\?\?=" );
        JHD_TLS_X509_SAFE_SNPRINTF;

        for( i = 0; i < name->val.len; i++ )
        {
            if( i >= sizeof( s ) - 1 )
                break;

            c = name->val.p[i];
            if( c < 32 || c == 127 || ( c > 128 && c < 160 ) )
                 s[i] = '?';
            else s[i] = c;
        }
        s[i] = '\0';
        ret = snprintf( p, n, "%s", s );
        JHD_TLS_X509_SAFE_SNPRINTF;

        merge = name->next_merged;
        name = name->next;
    }

    return( (int) ( size - n ) );
}

/*
 * Store the serial in printable form into buf; no more
 * than size characters will be written
 */
int jhd_tls_x509_serial_gets( char *buf, size_t size, const jhd_tls_x509_buf *serial )
{
    int ret;
    size_t i, n, nr;
    char *p;

    p = buf;
    n = size;

    nr = ( serial->len <= 32 )
        ? serial->len  : 28;

    for( i = 0; i < nr; i++ )
    {
        if( i == 0 && nr > 1 && serial->p[i] == 0x0 )
            continue;

        ret = snprintf( p, n, "%02X%s",
                serial->p[i], ( i < nr - 1 ) ? ":" : "" );
        JHD_TLS_X509_SAFE_SNPRINTF;
    }

    if( nr != serial->len )
    {
        ret = snprintf( p, n, "...." );
        JHD_TLS_X509_SAFE_SNPRINTF;
    }

    return( (int) ( size - n ) );
}

/*
 * Helper for writing signature algorithms
 */
int jhd_tls_x509_sig_alg_gets( char *buf, size_t size, const jhd_tls_x509_buf *sig_oid,const jhd_tls_pk_info_t *pk_info,const  jhd_tls_md_info_t *md_info )
{
    int ret;
    char *p = buf;
    size_t n = size;
    const char *desc = NULL;

    jhd_tls_oid_get_sig_alg_desc( sig_oid, &desc );
    if( desc == NULL )
        ret = snprintf( p, n, "???"  );
    else
        ret = snprintf( p, n, "%s", desc );
    JHD_TLS_X509_SAFE_SNPRINTF;

    return( (int)( size - n ) );
}

/*
 * Helper for writing "RSA key size", "EC key size", etc
 */
int jhd_tls_x509_key_size_helper( char *buf, size_t buf_size, const char *name )
{
    char *p = buf;
    size_t n = buf_size;
    int ret;

    ret = snprintf( p, n, "%s key size", name );
    JHD_TLS_X509_SAFE_SNPRINTF;

    return( 0 );
}

static int x509_get_current_time( jhd_tls_x509_time *now )
{
    struct tm *lt;
    time_t tt;
    int ret = 0;

    tt = time( NULL );
    lt = gmtime( &tt );

    if( lt == NULL )
        ret = -1;
    else
    {
        now->year = lt->tm_year + 1900;
        now->mon  = lt->tm_mon  + 1;
        now->day  = lt->tm_mday;
        now->hour = lt->tm_hour;
        now->min  = lt->tm_min;
        now->sec  = lt->tm_sec;
    }
    return( ret );
}
/*
 * Return 0 if before <= after, 1 otherwise
 */
static int x509_check_time( const jhd_tls_x509_time *before, const jhd_tls_x509_time *after )
{
    if( before->year  > after->year )
        return( 1 );

    if( before->year == after->year &&
        before->mon   > after->mon )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day   > after->day )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour  > after->hour )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour == after->hour &&
        before->min   > after->min  )
        return( 1 );

    if( before->year == after->year &&
        before->mon  == after->mon  &&
        before->day  == after->day  &&
        before->hour == after->hour &&
        before->min  == after->min  &&
        before->sec   > after->sec  )
        return( 1 );

    return( 0 );
}

int jhd_tls_x509_time_is_past( const jhd_tls_x509_time *to )
{
    jhd_tls_x509_time now;

    if( x509_get_current_time( &now ) != 0 )
        return( 1 );

    return( x509_check_time( &now, to ) );
}

int jhd_tls_x509_time_is_future( const jhd_tls_x509_time *from )
{
    jhd_tls_x509_time now;

    if( x509_get_current_time( &now ) != 0 )
        return( 1 );

    return( x509_check_time( from, &now ) );
}




