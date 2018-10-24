#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_asn1.h>
#include <string.h>
#include <tls/jhd_tls_bignum.h>
#include <tls/jhd_tls_platform.h>


/*
 * ASN.1 DER decoding routines
 */
int jhd_tls_asn1_get_len( unsigned char **p,const unsigned char *end,size_t *len )
{
	ssize_t plen = end - *p;
    if(plen < 1 ){
    	return JHD_ERROR;
    }
    if( ( **p & 0x80 ) == 0 )
        *len = *(*p)++;
    else
    {
        switch( **p & 0x7F )
        {
        case 1:
            if( plen < 2 ){
            	return JHD_ERROR;
            }
            *len = (*p)[1];
            (*p) += 2;
            break;
        case 2:
            if( plen < 3 ){
            	return JHD_ERROR;
            }
            *len = ( (size_t)(*p)[1] << 8 ) | (*p)[2];
            (*p) += 3;
            break;

        case 3:
            if( plen < 4 ){
            	return JHD_ERROR;
            }
            *len = ( (size_t)(*p)[1] << 16 ) |
                   ( (size_t)(*p)[2] << 8  ) | (*p)[3];
            (*p) += 4;
            break;

        case 4:
            if( plen < 5 ){
            	return JHD_ERROR;
            }
            *len = ( (size_t)(*p)[1] << 24 ) | ( (size_t)(*p)[2] << 16 ) |
                   ( (size_t)(*p)[3] << 8  ) |           (*p)[4];
            (*p) += 5;
            break;

        default:
            return JHD_ERROR;
        }
    }

    if( *len > (size_t) ( end - *p ) )
        return JHD_ERROR;

    return( 0 );
}

int jhd_tls_asn1_get_tag( unsigned char **p,const unsigned char *end,size_t *len, int tag )
{
    if( end <= *p ){
       return JHD_ERROR;
    }
    if( **p != tag )
        return JHD_UNEXPECTED;
    (*p)++;
    return( jhd_tls_asn1_get_len( p, end, len ) );
}

int jhd_tls_asn1_get_bool( unsigned char **p,const unsigned char *end,int *val )
{
    int ret;
    size_t len;
    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len, JHD_TLS_ASN1_BOOLEAN ) ) != 0 )
        return( ret );
    if( len != 1 )
        return JHD_ERROR;
    *val = ( **p != 0 ) ? 1 : 0;
    (*p)++;
    return JHD_OK;
}

int jhd_tls_asn1_get_int( unsigned char **p,const unsigned char *end,int *val )
{
    int ret;
    size_t len;
    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len, JHD_TLS_ASN1_INTEGER ) ) != 0 )
        return( ret );

    if( len == 0 || len > sizeof( int ) || ( **p & 0x80 ) != 0 )
        return JHD_ERROR;

    *val = 0;

    while( len-- > 0 )
    {
        *val = ( *val << 8 ) | **p;
        (*p)++;
    }

    return JHD_OK;
}


int jhd_tls_asn1_get_mpi( unsigned char **p,const unsigned char *end,jhd_tls_mpi *X )
{
    int ret;
    size_t len;
    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len, JHD_TLS_ASN1_INTEGER ) ) != 0 )
        return( ret );
    ret = jhd_tls_mpi_read_binary( X, *p, len );
    *p += len;
    return( ret );
}


int jhd_tls_asn1_get_bitstring( unsigned char **p, const unsigned char *end,jhd_tls_asn1_bitstring *bs)
{
    int ret;
    /* Certificate type is a single byte bitstring */
    if( ( ret = jhd_tls_asn1_get_tag( p, end, &bs->len, JHD_TLS_ASN1_BIT_STRING ) ) != 0 )
        return( ret );

    /* Check length, subtract one for actual bit string length */
    if( bs->len < 1 )
        return JHD_ERROR;
    bs->len -= 1;

    /* Get number of unused bits, ensure unused bits <= 7 */
    bs->unused_bits = **p;
    if( bs->unused_bits > 7 )
    	return JHD_ERROR;
    (*p)++;

    /* Get actual bitstring */
    bs->p = *p;
    *p += bs->len;

    if( *p != end )
    	return JHD_ERROR;

    return JHD_OK;
}

/*
 * Get a bit string without unused bits
 */
int jhd_tls_asn1_get_bitstring_null( unsigned char **p, const unsigned char *end,size_t *len )
{
    int ret;

    if( ( ret = jhd_tls_asn1_get_tag( p, end, len, JHD_TLS_ASN1_BIT_STRING ) ) != 0 )
        return( ret );

    if( (*len)-- < 2 || *(*p)++ != 0 )
        return JHD_ERROR;
    return( 0 );
}



/*
 *  Parses and splits an ASN.1 "SEQUENCE OF <tag>"
 */
int jhd_tls_asn1_get_sequence_of( unsigned char **p,const unsigned char *end,jhd_tls_asn1_sequence *cur,int tag,void *event)
{
    int ret;
    size_t len;
    jhd_tls_asn1_buf *buf;
	jhd_tls_asn1_sequence *prev,*next;
	log_assert_by_worker();
    if(  jhd_tls_asn1_get_tag( p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE )  != 0 )
        return JHD_ERROR;
    if( *p + len != end )
        return JHD_ERROR;
    next = cur;
    if(*p <end){
		for(;;){
			buf = &(next->buf);
			buf->tag = **p;
			if( ( ret = jhd_tls_asn1_get_tag( p, end, &buf->len, tag ) ) != 0 )
				return JHD_ERROR;
			buf->p = *p;
			*p += buf->len;
			/* Allocate and assign next pointer */
			if( *p < end )
			{
				if(next->next == NULL){
					next->next = (jhd_tls_asn1_sequence*)jhd_tls_alloc(sizeof( jhd_tls_asn1_sequence ) );
					if( next->next == NULL ){
						if(NULL == event)
							return JHD_ERROR;
						jhd_tls_wait_mem(event,sizeof( jhd_tls_asn1_sequence ));
						return JHD_AGAIN;
					}
					jhd_tls_platform_zeroize(next->next,sizeof(jhd_tls_asn1_sequence));
				}
				next = next->next;
			}else{
				break;
			}
		}
    }
    //TODO check memory leak
    if( *p != end )
            return JHD_ERROR;
    if(next->next != NULL){
    	prev = next;
    	next = next->next;
    	prev->next = NULL;
    	do{
    		prev = next;
    		next = next->next;
    		jhd_tls_free_with_size(prev,sizeof(jhd_tls_asn1_sequence));
    	}while(next != NULL);
    }
    return JHD_OK;
}

int jhd_tls_asn1_get_sequence_of_by_master( unsigned char **p,const unsigned char *end,jhd_tls_asn1_sequence *cur,int tag)
{
    int ret;
    size_t len;
    jhd_tls_asn1_buf *buf;
	jhd_tls_asn1_sequence *prev,*next;
	log_assert_master();
    if(  jhd_tls_asn1_get_tag( p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE )  != 0 )
        return JHD_ERROR;
    if( *p + len != end )
        return JHD_ERROR;
    next = cur;
    if(*p <end){
		for(;;){
			buf = &(next->buf);
			buf->tag = **p;
			if( ( ret = jhd_tls_asn1_get_tag( p, end, &buf->len, tag ) ) != 0 )
				return JHD_ERROR;
			buf->p = *p;
			*p += buf->len;
			/* Allocate and assign next pointer */
			if( *p < end ){
				next->next = (jhd_tls_asn1_sequence*)malloc(sizeof( jhd_tls_asn1_sequence ) );
				if( next->next == NULL ){
					log_stderr("systemcall malloc error");
					return JHD_ERROR;
				}
				jhd_tls_platform_zeroize(next->next,sizeof(jhd_tls_asn1_sequence));
				next = next->next;
			}else{
				break;
			}
		}
    }
    if( *p != end )
            return JHD_ERROR;
    return JHD_OK;
}

int jhd_tls_asn1_get_alg( unsigned char **p,const unsigned char *end,jhd_tls_asn1_buf *alg, jhd_tls_asn1_buf *params )
{
    int ret;
    size_t len;

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &len,JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
        return( ret );

    if( ( end - *p ) < 1 )
        return JHD_ERROR;

    alg->tag = **p;
    end = *p + len;

    if( ( ret = jhd_tls_asn1_get_tag( p, end, &alg->len, JHD_TLS_ASN1_OID ) ) != 0 )
        return( ret );

    alg->p = *p;
    *p += alg->len;

    if( *p == end )
    {
        jhd_tls_platform_zeroize( params, sizeof(jhd_tls_asn1_buf) );
        return( 0 );
    }

    params->tag = **p;
    (*p)++;

    if( ( ret = jhd_tls_asn1_get_len( p, end, &params->len ) ) != 0 )
        return( ret );

    params->p = *p;
    *p += params->len;

    if( *p != end )
        return JHD_ERROR;

    return( 0 );
}

int jhd_tls_asn1_get_alg_null( unsigned char **p,const unsigned char *end,jhd_tls_asn1_buf *alg )
{
    int ret;
    jhd_tls_asn1_buf params;

    memset( &params, 0, sizeof(jhd_tls_asn1_buf) );

    if( ( ret = jhd_tls_asn1_get_alg( p, end, alg, &params ) ) != 0 )
        return( ret );

    if( ( params.tag != JHD_TLS_ASN1_NULL && params.tag != 0 ) || params.len != 0 )
        return JHD_ERROR;

    return JHD_OK;
}

//void jhd_tls_asn1_free_named_data( jhd_tls_asn1_named_data *cur )
//{
//    jhd_tls_free( cur->oid.p );
//    jhd_tls_free( cur->val.p );
//    jhd_tls_platform_zeroize( cur, sizeof( jhd_tls_asn1_named_data ) );
//}
//void jhd_tls_asn1_free_named_data_list( jhd_tls_asn1_named_data **head )
//{
//    jhd_tls_asn1_named_data *cur;
//
//    while( ( cur = *head ) != NULL )
//    {
//        *head = cur->next;
//        jhd_tls_asn1_free_named_data( cur );
//        jhd_tls_free( cur );
//    }
//}

jhd_tls_asn1_named_data *jhd_tls_asn1_find_named_data( jhd_tls_asn1_named_data *list,const char *oid, size_t len )
{
    while( list != NULL )
    {
        if( list->oid.len == len && memcmp( list->oid.p, oid, len ) == 0 )
        {
            break;
        }

        list = list->next;
    }
    return( list );
}


