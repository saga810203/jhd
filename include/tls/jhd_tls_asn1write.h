#ifndef JHD_TLS_ASN1_WRITE_H
#define JHD_TLS_ASN1_WRITE_H

#include <tls/jhd_tls_asn1.h>

#define JHD_TLS_ASN1_CHK_ADD(g, f) if( ( ret = (f) ) < 0 ){return ret;}else{g+=ret;}


/**
 * \brief           Write a length field in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param len       the length to write
 *
 * \return          the length written or a negative error code
 */
int jhd_tls_asn1_write_len( unsigned char **p, unsigned char *start, size_t len );

/**
 * \brief           Write a ASN.1 tag in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param tag       the tag to write
 *
 * \return          the length written or a negative error code
 */
int jhd_tls_asn1_write_tag( unsigned char **p, unsigned char *start,
                    unsigned char tag );


/**
 * \brief           Write a big number (JHD_TLS_ASN1_INTEGER) in ASN.1 format
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param X         the MPI to write
 *
 * \return          the length written or a negative error code
 */
int jhd_tls_asn1_write_mpi( unsigned char **p, unsigned char *start, const jhd_tls_mpi *X );
#endif /* JHD_TLS_ASN1_WRITE_H */
