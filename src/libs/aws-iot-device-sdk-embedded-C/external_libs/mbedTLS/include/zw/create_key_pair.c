#include "create_key_pair.h"
// #if !defined(MBEDTLS_CONFIG_FILE)
// #include "mbedtls/config.h"
// #else
// #include MBEDTLS_CONFIG_FILE
// #endif

// #if defined(MBEDTLS_PLATFORM_C)
// #include "mbedtls/platform.h"
// #else
// #include <stdio.h>
// #define mbedtls_printf     printf
// #endif

// #if defined(MBEDTLS_PK_WRITE_C) && defined(MBEDTLS_FS_IO) && \
//     defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
// #include "mbedtls/error.h"
// #include "mbedtls/pk.h"
// #include "mbedtls/ecdsa.h"
// #include "mbedtls/rsa.h"
// #include "mbedtls/error.h"
// #include "mbedtls/entropy.h"
// #include "mbedtls/ctr_drbg.h"

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>

// #if !defined(_WIN32)
// #include <unistd.h>

// #define DEV_RANDOM_THRESHOLD        32

// int dev_random_entropy_poll( void *data, unsigned char *output,
//                              size_t len, size_t *olen )
// {
//     FILE *file;
//     size_t ret, left = len;
//     unsigned char *p = output;
//     ((void) data);

//     *olen = 0;

//     file = fopen( "/dev/random", "rb" );
//     if( file == NULL )
//         return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

//     while( left > 0 )
//     {
//         /* /dev/random can return much less than requested. If so, try again */
//         ret = fread( p, 1, left, file );
//         if( ret == 0 && ferror( file ) )
//         {
//             fclose( file );
//             return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
//         }

//         p += ret;
//         left -= ret;
//         sleep( 1 );
//     }
//     fclose( file );
//     *olen = len;

//     return( 0 );
// }
// #endif /* !_WIN32 */
// #endif

#if defined(MBEDTLS_ECP_C)
#define DFL_EC_CURVE            mbedtls_ecp_curve_list()->grp_id
#else
#define DFL_EC_CURVE            0
#endif

#if !defined(_WIN32) && defined(MBEDTLS_FS_IO)
#define USAGE_DEV_RANDOM \
    "    use_dev_random=0|1    default: 0\n"
#else
#define USAGE_DEV_RANDOM ""
#endif /* !_WIN32 && MBEDTLS_FS_IO */

#define FORMAT_PEM              0
#define FORMAT_DER              1

#define DFL_PATH                "./"
#define DFL_TYPE                MBEDTLS_PK_RSA
#define DFL_RSA_KEYSIZE         2048
#define DFL_FILENAME            "keyfile.key"
#define DFL_FORMAT              FORMAT_PEM
#define DFL_USE_DEV_RANDOM      0

// int main (void)
// {
//     gen_key();
//     return(0);
// }

struct options
{
    int type;                   /* the type of key to generate          */
    int rsa_keysize;            /* length of key in bits                */
    int ec_curve;               /* curve identifier for EC keys         */
    const char *filename;       /* filename of the key file             */
    int format;                 /* the output format to use             */
    int use_dev_random;         /* use /dev/random as entropy source    */
} opt;

#define BUFSIZE 4096

static int write_private_key( mbedtls_pk_context *key, const char *output_file )
{
    int ret;
    FILE *f;
    unsigned char *output_buf=NULL;
    output_buf = malloc(BUFSIZE);
    output_file = filepath(DFL_PATH, output_file);

    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, BUFSIZE);
    
        if( ( ret = mbedtls_pk_write_key_pem( key, output_buf, BUFSIZE ) ) != 0 )
            return( ret );

        len = strlen( (char *) output_buf );


    if( ( f = fopen( output_file, "wb" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

int filepath(const char *folder_path, const char *file_name)
{
    char *fullpath = malloc(strlen(folder_path) + strlen(file_name) + 1);
    strcpy(fullpath, folder_path);
    strcat(fullpath, file_name);
    return fullpath;
}

int gen_key()
{
    int ret = 0;
    mbedtls_pk_context key;
    char buf[1024];

    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";

    /*
     * Set to sane values
     */

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    memset( buf, 0, sizeof( buf ) );

    opt.type                = DFL_TYPE;
    opt.rsa_keysize         = DFL_RSA_KEYSIZE;
    opt.ec_curve            = DFL_EC_CURVE;
    opt.filename            = filepath(DFL_PATH, DFL_FILENAME);
    opt.format              = DFL_FORMAT;
    opt.use_dev_random      = DFL_USE_DEV_RANDOM;

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
#if !defined(_WIN32) && defined(MBEDTLS_FS_IO)
    if( opt.use_dev_random )
    {
        if( ( ret = mbedtls_entropy_add_source( &entropy, dev_random_entropy_poll,
                                        NULL, DEV_RANDOM_THRESHOLD,
                                        MBEDTLS_ENTROPY_SOURCE_STRONG ) ) != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_entropy_add_source returned -0x%04x\n", -ret );
            goto exit;
        }

        mbedtls_printf("\n    Using /dev/random, so can take a long time! " );
        fflush( stdout );
    }
#endif /* !_WIN32 && MBEDTLS_FS_IO */

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                            strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * 1.1. Generate the key
     */
    mbedtls_printf( "\n  . Generating the private key ..." );
    fflush( stdout );

    if( ( ret = mbedtls_pk_setup( &key, mbedtls_pk_info_from_type( opt.type ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_setup returned -0x%04x", -ret );
        goto exit;
    }

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if( opt.type == MBEDTLS_PK_RSA )
    {
        ret = mbedtls_rsa_gen_key( mbedtls_pk_rsa( key ), mbedtls_ctr_drbg_random, &ctr_drbg,
                                opt.rsa_keysize, 65537 );
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_rsa_gen_key returned -0x%04x", -ret );
            goto exit;
        }
    }
    else
#endif /* MBEDTLS_RSA_C */
    {
        mbedtls_printf( " failed\n  !  key type not supported\n" );
        goto exit;
    }

    /*
     * 1.2 Print the key
     */
    mbedtls_printf( " ok\n  . Key information:\n" );

#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( &key ) == MBEDTLS_PK_RSA )
    {
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa( key );

        if( ( ret = mbedtls_rsa_export    ( rsa, &N, &P, &Q, &D, &E ) ) != 0 ||
            ( ret = mbedtls_rsa_export_crt( rsa, &DP, &DQ, &QP ) )      != 0 )
        {
            mbedtls_printf( " failed\n  ! could not export RSA parameters\n\n" );
            goto exit;
        }

        mbedtls_mpi_write_file( "N:  ",  &N,  16, NULL );
        mbedtls_mpi_write_file( "E:  ",  &E,  16, NULL );
        mbedtls_mpi_write_file( "D:  ",  &D,  16, NULL );
        mbedtls_mpi_write_file( "P:  ",  &P,  16, NULL );
        mbedtls_mpi_write_file( "Q:  ",  &Q,  16, NULL );
        mbedtls_mpi_write_file( "DP: ",  &DP, 16, NULL );
        mbedtls_mpi_write_file( "DQ:  ", &DQ, 16, NULL );
        mbedtls_mpi_write_file( "QP:  ", &QP, 16, NULL );
    }
    else
#endif
        mbedtls_printf("  ! key type not supported\n");

    /*
     * 1.3 Export key
     */
    mbedtls_printf( "  . Writing key to file..." );
    
    if( ( ret = write_private_key( &key, opt.filename ) ) != 0 )
    {
        mbedtls_printf( " failed\n" );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

exit:

    if( ret != 0 && ret != 1)
    {
#ifdef MBEDTLS_ERROR_C
        mbedtls_strerror( ret, buf, sizeof( buf ) );
        mbedtls_printf( " - %s\n", buf );
#else
        mbedtls_printf("\n");
#endif
    }

    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );

    mbedtls_pk_free( &key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return (ret);

}
//#endif /* MBEDTLS_PK_WRITE_C && MBEDTLS_PEM_WRITE_C && MBEDTLS_FS_IO &&  \
    // * MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
