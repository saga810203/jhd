#include <jhd_config.h>
#include <tls/jhd_tls_config.h>
#include <string.h>
#include <tls/jhd_tls_aes.h>
#include <tls/jhd_tls_aesni.h>
#include <tls/jhd_tls_cipher_internal.h>

#if defined(JHD_TLS_SELF_TEST)
#include <tls/jhd_tls_platform.h>
#endif /* JHD_TLS_SELF_TEST */



/*
 * Forward S-box & tables
 */
static unsigned char FSb[256];
static uint32_t FT0[256];
#if !defined(JHD_TLS_AES_FEWER_TABLES)
static uint32_t FT1[256];
static uint32_t FT2[256];
static uint32_t FT3[256];
#endif /* !JHD_TLS_AES_FEWER_TABLES */

/*
 * Reverse S-box & tables
 */
static unsigned char RSb[256];
static uint32_t RT0[256];
#if !defined(JHD_TLS_AES_FEWER_TABLES)
static uint32_t RT1[256];
static uint32_t RT2[256];
static uint32_t RT3[256];
#endif /* !JHD_TLS_AES_FEWER_TABLES */

/*
 * Round constants
 */
static uint32_t RCON[10];

/*
 * Tables generation code
 */
#define ROTL8(x) ( ( x << 8 ) & 0xFFFFFFFF ) | ( x >> 24 )
#define XTIME(x) ( ( x << 1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( x && y ) ? pow[(log[x]+log[y]) % 255] : 0 )


static void aes_gen_tables(void) {
	int i, x, y, z;
	int pow[256];
	int log[256];

	/*
	 * compute pow and log tables over GF(2^8)
	 */
	for (i = 0, x = 1; i < 256; i++) {
		pow[i] = x;
		log[x] = i;
		x = (x ^ XTIME(x)) & 0xFF;
	}

	/*
	 * calculate the round constants
	 */
	for (i = 0, x = 1; i < 10; i++) {
		RCON[i] = (uint32_t) x;
		x = XTIME( x ) & 0xFF;
	}

	/*
	 * generate the forward and reverse S-boxes
	 */
	FSb[0x00] = 0x63;
	RSb[0x63] = 0x00;

	for (i = 1; i < 256; i++) {
		x = pow[255 - log[i]];

		y = x;
		y = ((y << 1) | (y >> 7)) & 0xFF;
		x ^= y;
		y = ((y << 1) | (y >> 7)) & 0xFF;
		x ^= y;
		y = ((y << 1) | (y >> 7)) & 0xFF;
		x ^= y;
		y = ((y << 1) | (y >> 7)) & 0xFF;
		x ^= y ^ 0x63;

		FSb[i] = (unsigned char) x;
		RSb[x] = (unsigned char) i;
	}

	/*
	 * generate the forward and reverse tables
	 */
	for (i = 0; i < 256; i++) {
		x = FSb[i];
		y = XTIME( x ) & 0xFF;
		z = (y ^ x) & 0xFF;

		FT0[i] = ((uint32_t) y) ^ ((uint32_t) x << 8) ^ ((uint32_t) x << 16) ^ ((uint32_t) z << 24);

#if !defined(JHD_TLS_AES_FEWER_TABLES)
		FT1[i] = ROTL8(FT0[i]);
		FT2[i] = ROTL8(FT1[i]);
		FT3[i] = ROTL8(FT2[i]);
#endif /* !JHD_TLS_AES_FEWER_TABLES */

		x = RSb[i];

		RT0[i] = ((uint32_t) MUL(0x0E, x)) ^ ((uint32_t) MUL(0x09, x) << 8) ^ ((uint32_t) MUL(0x0D, x) << 16) ^ ((uint32_t) MUL(0x0B, x) << 24);

#if !defined(JHD_TLS_AES_FEWER_TABLES)
		RT1[i] = ROTL8(RT0[i]);
		RT2[i] = ROTL8(RT1[i]);
		RT3[i] = ROTL8(RT2[i]);
#endif /* !JHD_TLS_AES_FEWER_TABLES */
	}
}

#undef ROTL8

#define AES_RT0(idx) RT0[idx]
#define AES_RT1(idx) RT1[idx]
#define AES_RT2(idx) RT2[idx]
#define AES_RT3(idx) RT3[idx]

#define AES_FT0(idx) FT0[idx]
#define AES_FT1(idx) FT1[idx]
#define AES_FT2(idx) FT2[idx]
#define AES_FT3(idx) FT3[idx]





void jhd_tls_aes_setkey_enc_auto(jhd_tls_aes_context *ctx, const unsigned char *key, unsigned int keybits){
	if(aesni_support_aes){
		jhd_tls_aes_setkey_enc_with_aesni(ctx,key,keybits);
	}else{
		jhd_tls_aes_setkey_enc_without_aesni(ctx,key,keybits);
	}
}


void jhd_tls_aes_setkey_dec_auto(jhd_tls_aes_context *ctx, const unsigned char *key, unsigned int keybits){
	if(aesni_support_aes){
		jhd_tls_aes_setkey_dec_with_aesni(ctx,key,keybits);
	}else{
		jhd_tls_aes_setkey_dec_without_aesni(ctx,key,keybits);
	}
}

void jhd_tls_aes_setkey_enc_with_aesni(jhd_tls_aes_context *ctx, const unsigned char *key, unsigned int keybits) {
	ctx->nr = keybits == 128 ? 10 : (keybits == 192 ? 12 :/*keybits==256*/14);
	ctx->rk = ctx->buf;
	jhd_tls_aesni_setkey_enc((unsigned char *) ctx->rk, key, keybits);
}

void jhd_tls_aes_setkey_enc_without_aesni(jhd_tls_aes_context *ctx,const unsigned char *key,unsigned int keybits){
	unsigned int i;
	uint32_t *RK;

	log_assert(keybits == 128 || keybits == 192 || keybits == 256);
	ctx->nr = keybits == 128?10:(keybits == 192?12:/*keybits==256*/14);
	ctx->rk = RK = ctx->buf;
	for(i = 0;i < (keybits >> 5);i++){
		GET_UINT32_LE(RK[i],key,i << 2);
	}
	if(ctx->nr == 10){
		for(i = 0;i < 10;i++,RK += 4){
			RK[4] = RK[0] ^ RCON[i] ^ ((uint32_t)FSb[(RK[3] >> 8) & 0xFF]) ^ ((uint32_t)FSb[(RK[3] >> 16) & 0xFF] << 8)
							^ ((uint32_t)FSb[(RK[3] >> 24) & 0xFF] << 16) ^ ((uint32_t)FSb[(RK[3]) & 0xFF] << 24);
			RK[5] = RK[1] ^ RK[4];
			RK[6] = RK[2] ^ RK[5];
			RK[7] = RK[3] ^ RK[6];
		}
	}else if(12 == ctx->nr){
		for(i = 0;i < 8;i++,RK += 6){
			RK[6] = RK[0] ^ RCON[i] ^ ((uint32_t)FSb[(RK[5] >> 8) & 0xFF]) ^ ((uint32_t)FSb[(RK[5] >> 16) & 0xFF] << 8)
							^ ((uint32_t)FSb[(RK[5] >> 24) & 0xFF] << 16) ^ ((uint32_t)FSb[(RK[5]) & 0xFF] << 24);
			RK[7] = RK[1] ^ RK[6];
			RK[8] = RK[2] ^ RK[7];
			RK[9] = RK[3] ^ RK[8];
			RK[10] = RK[4] ^ RK[9];
			RK[11] = RK[5] ^ RK[10];
		}
	}else{
		for(i = 0;i < 7;i++,RK += 8){
			RK[8] = RK[0] ^ RCON[i] ^ ((uint32_t)FSb[(RK[7] >> 8) & 0xFF]) ^ ((uint32_t)FSb[(RK[7] >> 16) & 0xFF] << 8)
							^ ((uint32_t)FSb[(RK[7] >> 24) & 0xFF] << 16) ^ ((uint32_t)FSb[(RK[7]) & 0xFF] << 24);
			RK[9] = RK[1] ^ RK[8];
			RK[10] = RK[2] ^ RK[9];
			RK[11] = RK[3] ^ RK[10];
			RK[12] = RK[4] ^ ((uint32_t)FSb[(RK[11]) & 0xFF]) ^ ((uint32_t)FSb[(RK[11] >> 8) & 0xFF] << 8) ^ ((uint32_t)FSb[(RK[11] >> 16) & 0xFF] << 16)
							^ ((uint32_t)FSb[(RK[11] >> 24) & 0xFF] << 24);
			RK[13] = RK[5] ^ RK[12];
			RK[14] = RK[6] ^ RK[13];
			RK[15] = RK[7] ^ RK[14];
		}
	}
}

void jhd_tls_aes_setkey_dec_with_aesni(jhd_tls_aes_context *ctx, const unsigned char *key, unsigned int keybits) {
	jhd_tls_aes_context cty;
	jhd_tls_platform_zeroize(&cty, sizeof(jhd_tls_aes_context));
	ctx->rk = ctx->buf;
	jhd_tls_aes_setkey_enc_with_aesni(&cty, key, keybits);
	ctx->nr = cty.nr;
	jhd_tls_aesni_inverse_key((unsigned char *) ctx->rk, (const unsigned char *) cty.rk, ctx->nr);
}
void jhd_tls_aes_setkey_dec_without_aesni(jhd_tls_aes_context *ctx, const unsigned char *key, unsigned int keybits) {
	int i, j;
	jhd_tls_aes_context cty;
	uint32_t *RK;
	uint32_t *SK;
	jhd_tls_platform_zeroize(&cty, sizeof(jhd_tls_aes_context));
	ctx->rk = RK = ctx->buf;
	jhd_tls_aes_setkey_enc_without_aesni(&cty, key, keybits);
	ctx->nr = cty.nr;
	SK = cty.rk + cty.nr * 4;
	*RK++ = *SK++;
	*RK++ = *SK++;
	*RK++ = *SK++;
	*RK++ = *SK++;
	for (i = ctx->nr - 1, SK -= 8; i > 0; i--, SK -= 8) {
		for (j = 0; j < 4; j++, SK++) {
			*RK++ = AES_RT0( FSb[ ( *SK ) & 0xFF ] )^
			AES_RT1( FSb[ ( *SK >> 8 ) & 0xFF ] ) ^
			AES_RT2( FSb[ ( *SK >> 16 ) & 0xFF ] ) ^
			AES_RT3( FSb[ ( *SK >> 24 ) & 0xFF ] );
		}
	}
	*RK++ = *SK++;
	*RK++ = *SK++;
	*RK++ = *SK++;
	*RK++ = *SK++;
}

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)         \
{                                                   \
    X0 = *RK++ ^ AES_FT0( ( Y0       ) & 0xFF ) ^   \
                 AES_FT1( ( Y1 >>  8 ) & 0xFF ) ^   \
                 AES_FT2( ( Y2 >> 16 ) & 0xFF ) ^   \
                 AES_FT3( ( Y3 >> 24 ) & 0xFF );    \
                                                    \
    X1 = *RK++ ^ AES_FT0( ( Y1       ) & 0xFF ) ^   \
                 AES_FT1( ( Y2 >>  8 ) & 0xFF ) ^   \
                 AES_FT2( ( Y3 >> 16 ) & 0xFF ) ^   \
                 AES_FT3( ( Y0 >> 24 ) & 0xFF );    \
                                                    \
    X2 = *RK++ ^ AES_FT0( ( Y2       ) & 0xFF ) ^   \
                 AES_FT1( ( Y3 >>  8 ) & 0xFF ) ^   \
                 AES_FT2( ( Y0 >> 16 ) & 0xFF ) ^   \
                 AES_FT3( ( Y1 >> 24 ) & 0xFF );    \
                                                    \
    X3 = *RK++ ^ AES_FT0( ( Y3       ) & 0xFF ) ^   \
                 AES_FT1( ( Y0 >>  8 ) & 0xFF ) ^   \
                 AES_FT2( ( Y1 >> 16 ) & 0xFF ) ^   \
                 AES_FT3( ( Y2 >> 24 ) & 0xFF );    \
}

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)         \
{                                                   \
    X0 = *RK++ ^ AES_RT0( ( Y0       ) & 0xFF ) ^   \
                 AES_RT1( ( Y3 >>  8 ) & 0xFF ) ^   \
                 AES_RT2( ( Y2 >> 16 ) & 0xFF ) ^   \
                 AES_RT3( ( Y1 >> 24 ) & 0xFF );    \
                                                    \
    X1 = *RK++ ^ AES_RT0( ( Y1       ) & 0xFF ) ^   \
                 AES_RT1( ( Y0 >>  8 ) & 0xFF ) ^   \
                 AES_RT2( ( Y3 >> 16 ) & 0xFF ) ^   \
                 AES_RT3( ( Y2 >> 24 ) & 0xFF );    \
                                                    \
    X2 = *RK++ ^ AES_RT0( ( Y2       ) & 0xFF ) ^   \
                 AES_RT1( ( Y1 >>  8 ) & 0xFF ) ^   \
                 AES_RT2( ( Y0 >> 16 ) & 0xFF ) ^   \
                 AES_RT3( ( Y3 >> 24 ) & 0xFF );    \
                                                    \
    X3 = *RK++ ^ AES_RT0( ( Y3       ) & 0xFF ) ^   \
                 AES_RT1( ( Y2 >>  8 ) & 0xFF ) ^   \
                 AES_RT2( ( Y1 >> 16 ) & 0xFF ) ^   \
                 AES_RT3( ( Y0 >> 24 ) & 0xFF );    \
}

/*
 * AES-ECB block encryption
 */

void jhd_tls_aes_ecb_encrypt_without_aesni(jhd_tls_aes_context *ctx, const unsigned char input[16], unsigned char output[16]) {
    int i;
    uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->rk;

    GET_UINT32_LE( X0, input,  0 ); X0 ^= *RK++;
    GET_UINT32_LE( X1, input,  4 ); X1 ^= *RK++;
    GET_UINT32_LE( X2, input,  8 ); X2 ^= *RK++;
    GET_UINT32_LE( X3, input, 12 ); X3 ^= *RK++;

    for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
    {
        AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
        AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
    }

    AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

    X0 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y0       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

    X1 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y1       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );

    X2 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y2       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

    X3 = *RK++ ^ \
            ( (uint32_t) FSb[ ( Y3       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );

    PUT_UINT32_LE( X0, output,  0 );
    PUT_UINT32_LE( X1, output,  4 );
    PUT_UINT32_LE( X2, output,  8 );
    PUT_UINT32_LE( X3, output, 12 );
}



void jhd_tls_aes_ecb_decrypt_without_aesni(jhd_tls_aes_context *ctx, const unsigned char input[16], unsigned char output[16]) {
	int i;
	uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

	RK = ctx->rk;

	GET_UINT32_LE(X0, input, 0);
	X0 ^= *RK++;
	GET_UINT32_LE(X1, input, 4);
	X1 ^= *RK++;
	GET_UINT32_LE(X2, input, 8);
	X2 ^= *RK++;
	GET_UINT32_LE(X3, input, 12);
	X3 ^= *RK++;

	for (i = (ctx->nr >> 1) - 1; i > 0; i--) {
		AES_RROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);
		AES_RROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);
	}

	AES_RROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);

	X0 = *RK++ ^ ((uint32_t) RSb[(Y0) & 0xFF]) ^ ((uint32_t) RSb[(Y3 >> 8) & 0xFF] << 8) ^ ((uint32_t) RSb[(Y2 >> 16) & 0xFF] << 16)
	        ^ ((uint32_t) RSb[(Y1 >> 24) & 0xFF] << 24);

	X1 = *RK++ ^ ((uint32_t) RSb[(Y1) & 0xFF]) ^ ((uint32_t) RSb[(Y0 >> 8) & 0xFF] << 8) ^ ((uint32_t) RSb[(Y3 >> 16) & 0xFF] << 16)
	        ^ ((uint32_t) RSb[(Y2 >> 24) & 0xFF] << 24);

	X2 = *RK++ ^ ((uint32_t) RSb[(Y2) & 0xFF]) ^ ((uint32_t) RSb[(Y1 >> 8) & 0xFF] << 8) ^ ((uint32_t) RSb[(Y0 >> 16) & 0xFF] << 16)
	        ^ ((uint32_t) RSb[(Y3 >> 24) & 0xFF] << 24);

	X3 = *RK++ ^ ((uint32_t) RSb[(Y3) & 0xFF]) ^ ((uint32_t) RSb[(Y2 >> 8) & 0xFF] << 8) ^ ((uint32_t) RSb[(Y1 >> 16) & 0xFF] << 16)
	        ^ ((uint32_t) RSb[(Y0 >> 24) & 0xFF] << 24);

	PUT_UINT32_LE(X0, output, 0);
	PUT_UINT32_LE(X1, output, 4);
	PUT_UINT32_LE(X2, output, 8);
	PUT_UINT32_LE(X3, output, 12);
}

/*
 * AES-ECB block encryption/decryption
 */
void jhd_tls_aes_crypt_ecb(jhd_tls_aes_context *ctx,jhd_tls_operation_t mode,const unsigned char input[16],unsigned char output[16]){
	if(aesni_support_aes){
		(jhd_tls_aesni_crypt_ecb(ctx,mode,input,output));
		return;
	}
	if(mode == JHD_TLS_ENCRYPT)
		(jhd_tls_aes_ecb_encrypt_without_aesni(ctx,input,output));
	else
		(jhd_tls_aes_ecb_decrypt_without_aesni(ctx,input,output));
}

/*
 * AES-CBC buffer encryption/decryption
 */
void jhd_tls_aes_crypt_cbc(jhd_tls_aes_context *ctx, jhd_tls_operation_t mode, size_t length, unsigned char iv[16], const unsigned char *input,unsigned char *output) {
	int i;
	unsigned char temp[16];
	log_assert(length % 16 ==0);
	if (mode == JHD_TLS_DECRYPT) {
		while (length > 0) {
			memcpy(temp, input, 16);
			jhd_tls_aes_crypt_ecb(ctx, mode, input, output);
			for (i = 0; i < 16; i++)
				output[i] = (unsigned char) (output[i] ^ iv[i]);
			memcpy(iv, temp, 16);
			input += 16;
			output += 16;
			length -= 16;
		}
	} else {
		while (length > 0) {
			for (i = 0; i < 16; i++){
				output[i] = (unsigned char) (input[i] ^ iv[i]);
			}
			jhd_tls_aes_crypt_ecb(ctx, mode, output, output);
			memcpy(iv, output, 16);

			input += 16;
			output += 16;
			length -= 16;
		}
	}
}

void jhd_tls_aes_cbc_encrypt_with_aesni(jhd_tls_aes_context *ctx,size_t length, unsigned char iv[16], const unsigned char *input,unsigned char *output) {
	log_assert(length % 16 ==0);
	while (length > 0) {
			p128_xor(output,input,iv);
			jhd_tls_aes_ecb_encrypt_with_aesni(ctx,output, output);
			memcpy_16(iv,output);
			input += 16;
			output += 16;
			length -= 16;
		}
}
void jhd_tls_aes_cbc_decrypt_with_aesni(jhd_tls_aes_context *ctx,size_t length,unsigned char iv[16],const unsigned char *input,unsigned char *output){
	uint64_t tmp1,tmp2;
	log_assert(length % 16 ==0);
	while(length > 0){
		tmp1 = *((uint64_t*)(input));
		tmp2 = *((uint64_t*)(input + 8));

		jhd_tls_aes_ecb_decrypt_with_aesni(ctx,input,output);

		p128_eq_xor(output,iv);
		*((uint64_t*)(iv)) = tmp1;
		*((uint64_t*)(iv + 8)) = tmp2;

		input += 16;
		output += 16;
		length -= 16;
	}
}


void jhd_tls_aes_cbc_encrypt_without_aesni(jhd_tls_aes_context *ctx,size_t length, unsigned char iv[16], const unsigned char *input,unsigned char *output) {
	log_assert(length % 16 ==0);
	while (length > 0) {
			p128_xor(output,input,iv);
			jhd_tls_aes_ecb_encrypt_without_aesni(ctx,output, output);
			memcpy_16(iv,output);
			input += 16;
			output += 16;
			length -= 16;
		}

}
void jhd_tls_aes_cbc_decrypt_without_aesni(jhd_tls_aes_context *ctx,size_t length,unsigned char iv[16],const unsigned char *input,unsigned char *output){
	uint64_t tmp1,tmp2;
	log_assert(length % 16 ==0);
	while(length > 0){
		tmp1 = *((uint64_t*)(input));
		tmp2 = *((uint64_t*)(input + 8));

		jhd_tls_aes_ecb_decrypt_without_aesni(ctx,input,output);

		p128_eq_xor(output,iv);

		*((uint64_t*)(iv)) = tmp1;
		*((uint64_t*)(iv + 8)) = tmp2;

		input += 16;
		output += 16;
		length -= 16;
	}
}




jhd_tls_cipher_base_t aes_info = {
		JHD_TLS_CIPHER_ID_AES,
		sizeof(jhd_tls_aes_context),
		jhd_tls_cipher_size_init,
//		(jhd_tls_cipher_ecb_pt) jhd_tls_aes_crypt_ecb,
//        (jhd_tls_cipher_cbc_pt) jhd_tls_aes_crypt_cbc,

		(jhd_tls_cipher_ecb_encrypt_pt)jhd_tls_aes_ecb_encrypt_without_aesni,
		(jhd_tls_cipher_ecb_decrypt_pt) jhd_tls_aes_ecb_decrypt_without_aesni,
		(jhd_tls_cipher_cbc_encrypt_pt) jhd_tls_aes_cbc_encrypt_without_aesni,
		(jhd_tls_cipher_cbc_encrypt_pt) jhd_tls_aes_cbc_decrypt_without_aesni,

		(jhd_tls_cipher_setkey_enc_pt) jhd_tls_aes_setkey_enc_without_aesni,
        (jhd_tls_cipher_setkey_dec_pt) jhd_tls_aes_setkey_dec_without_aesni,
};
void jhd_tls_aes_init(){



    jhd_tls_aesni_has_support();
    if(aesni_support_aes){
    	aes_info.ecb_encrypt_func=(jhd_tls_cipher_ecb_encrypt_pt) jhd_tls_aes_ecb_encrypt_with_aesni;
    	aes_info.ecb_decrypt_func= (jhd_tls_cipher_ecb_decrypt_pt) jhd_tls_aes_ecb_decrypt_with_aesni;
    	aes_info.cbc_encrypt_func=(jhd_tls_cipher_cbc_encrypt_pt) jhd_tls_aes_cbc_encrypt_with_aesni;
    	aes_info.cbc_decrypt_func=(jhd_tls_cipher_cbc_decrypt_pt) jhd_tls_aes_cbc_decrypt_with_aesni;
    	aes_info.setkey_enc_func =(jhd_tls_cipher_setkey_enc_pt) jhd_tls_aes_setkey_enc_with_aesni;
    	aes_info.setkey_dec_func= (jhd_tls_cipher_setkey_dec_pt)jhd_tls_aes_setkey_dec_with_aesni;
    }
	aes_gen_tables();
}



