#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_asn1write.h>
#include <string.h>
#include <tls/jhd_tls_platform.h>

int jhd_tls_asn1_write_len( unsigned char **p, unsigned char *start, size_t len )
{
    if( len < 0x80 )
    {
       JHD_TLS_COMMON_CHECK_RETURN_ERROR( *p - start < 1 )

        *--(*p) = (unsigned char) len;
        return( 1 );
    }

    if( len <= 0xFF )
    {
    	JHD_TLS_COMMON_CHECK_RETURN_ERROR( *p - start < 2 )
        *--(*p) = (unsigned char) len;
        *--(*p) = 0x81;
        return( 2 );
    }

    if( len <= 0xFFFF )
    {
    	JHD_TLS_COMMON_CHECK_RETURN_ERROR( *p - start < 3 )
        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = 0x82;
        return( 3 );
    }

    if( len <= 0xFFFFFF )
    {
    	JHD_TLS_COMMON_CHECK_RETURN_ERROR( *p - start < 4 )
        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = ( len >> 16 ) & 0xFF;
        *--(*p) = 0x83;
        return( 4 );
    }

#if SIZE_MAX > 0xFFFFFFFF
    if( len <= 0xFFFFFFFF )
#endif
    {
    	JHD_TLS_COMMON_CHECK_RETURN_ERROR(*p - start < 5 )
        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = ( len >> 16 ) & 0xFF;
        *--(*p) = ( len >> 24 ) & 0xFF;
        *--(*p) = 0x84;
        return( 5 );
    }

#if SIZE_MAX > 0xFFFFFFFF
    return JHD_ERROR;
#endif
}

int jhd_tls_asn1_write_tag( unsigned char **p, unsigned char *start, unsigned char tag )
{
	JHD_TLS_COMMON_CHECK_RETURN_ERROR( *p - start < 1 )
    *--(*p) = tag;
    return ( 1 );
}


int jhd_tls_asn1_write_mpi( unsigned char **p, unsigned char *start, const jhd_tls_mpi *X )
{
    int ret;
    size_t len = 0;

    // Write the MPI
    //
    len = jhd_tls_mpi_size( X );
    JHD_TLS_COMMON_CHECK_RETURN_ERROR( (*p < start) || ((size_t)( *p - start ) < len) )
    (*p) -= len;
    JHD_TLS_MPI_CHK( jhd_tls_mpi_write_binary( X, *p, len ) );
    // DER format assumes 2s complement for numbers, so the leftmost bit
    // should be 0 for positive numbers and 1 for negative numbers.
    //
    if((X->s ==1) && (**p & 0x80) )
    {
    	JHD_TLS_COMMON_CHECK_RETURN_ERROR( *p - start < 1 )
        *--(*p) = 0x00;
        len += 1;
    }

    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( p, start, len ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( p, start, JHD_TLS_ASN1_INTEGER ) );

    ret = (int) len;
cleanup:
    return( ret );
}
