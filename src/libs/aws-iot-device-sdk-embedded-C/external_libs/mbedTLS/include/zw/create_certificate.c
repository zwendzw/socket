#include "create_certificate.h"

#if !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_X509_CRT_PARSE_C) || \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_X509_CRL_PARSE_C)
int main( void )
{
    printf("MBEDTLS_RSA_C and/or MBEDTLS_X509_CRT_PARSE_C "
           "MBEDTLS_FS_IO and/or MBEDTLS_X509_CRL_PARSE_C "
           "not defined.\n");
    return( 0 );
}
#else

int write_certificate(char* issuer_crt_path, mbedtls_x509write_cert *crt, const char *output_file,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    FILE *f, *fp;
    char read_crt;
    unsigned char output_buf[4096];
    size_t len = 0;

    mbedtls_printf("  \n  !! Writing to %s ...", output_file);
    memset( output_buf, 0, 4096 );
    if( ( ret = mbedtls_x509write_crt_pem( crt, output_buf, 4096,
                                            f_rng, p_rng ) ) < 0 )
        return( ret );

    len = strlen( (char *) output_buf );

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( output_buf, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fp = fopen(issuer_crt_path, "r");
    
    while((read_crt = fgetc(fp)) != EOF){
        fputc(read_crt, f);
    }
    fclose( f );

    return( 0 );
}

int get_default_thing_name(const char *output_file)
{
    char *thing_name;
    FILE *fp = fopen(output_file, "r");
    char line[256];
    char pem[2500];
    while (fgets(line, sizeof(line), fp)) {
        if (strcmp(line, "-----BEGIN CERTIFICATE-----\n") == 0) {
        } else if (strcmp(line, "-----END CERTIFICATE-----\n") == 0) {
            break;
        } else {
            strncat(pem, line, strlen(line) - 1);
        }
    }
    fclose(fp);
    const size_t thing_name_size = 40;
    const size_t size = 2000;
    char base64_pem[size];
    size_t base64_pem_length = base64Decode(pem, base64_pem);
    char *hex_pem = bin2hex((unsigned char *)base64_pem, base64_pem_length);
    char *prefix = "301d0603551d0e04160414";
    char *find_prefix = strstr(hex_pem, prefix);
    if (find_prefix) {
        thing_name = malloc(thing_name_size);
        strncpy(thing_name, find_prefix + strlen(prefix), thing_name_size);
        thing_name[thing_name_size] = 0;
        mbedtls_printf("\n  Default thing name is: %s", thing_name);
    } else {
        return 1;
    }
    return 0;
}

char *bin2hex(const unsigned char *bin, size_t length) {
    char *output;
    size_t i;
    if (bin == NULL || length == 0) {
        return NULL;
    }
    output = malloc(length*2+1);
    for (i=0; i<length; i++) {
        output[i*2]   = "0123456789abcdef"[bin[i] >> 4];
        output[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
    }
    output[length*2] = '\0';
 
    return output;
}

size_t base64Decode(const char* input, char* output)
{
    base64_decodestate s;
    size_t cnt;
    
    base64_init_decodestate(&s);
    cnt = base64_decode_block(input, strlen(input), output, &s);
    output[cnt] = 0;

    return cnt;
}

int base64_decode_value(char value_in)
{
    static const char decoding[] = {62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
    static const char decoding_size = sizeof(decoding);
    value_in -= 43;
    if (value_in < 0 || value_in > decoding_size) {
        return -1;
    }
    return decoding[(int)value_in];
}

void base64_init_decodestate(base64_decodestate *state_in)
{
    state_in->step = step_a;
    state_in->plainchar = 0;
}

int base64_decode_block(const char *code_in, const int length_in, char *plaintext_out, base64_decodestate *state_in)
{
    const char* codechar = code_in;
    char* plainchar = plaintext_out;
    char fragment;
    *plainchar = state_in->plainchar;
    switch (state_in->step) {
        while (1){
            case step_a:
                do {
                    if (codechar == code_in+length_in) {
                        state_in->step = step_a;
                        state_in->plainchar = *plainchar;
                        return plainchar - plaintext_out;
                    }
                    fragment = (char)base64_decode_value(*codechar++);
                } while (fragment < 0);
                *plainchar = (fragment & 0x03f) << 2;
            case step_b:
                do {
                    if (codechar == code_in+length_in) {
                        state_in->step = step_b;
                        state_in->plainchar = *plainchar;
                        return plainchar - plaintext_out;
                    }
                    fragment = (char)base64_decode_value(*codechar++);
                } while (fragment < 0);
                *plainchar++ |= (fragment & 0x030) >> 4;
                *plainchar = (fragment & 0x00f) << 4;
            case step_c:
                do {
                    if (codechar == code_in+length_in) {
                        state_in->step = step_c;
                        state_in->plainchar = *plainchar;
                        return plainchar - plaintext_out;
                    }
                    fragment = (char)base64_decode_value(*codechar++);
                } while (fragment < 0);
                *plainchar++ |= (fragment & 0x03c) >> 2;
                *plainchar    = (fragment & 0x003) << 6;
            case step_d:
                do {
                    if (codechar == code_in + length_in) {
                    state_in->step = step_d;
                    state_in->plainchar = *plainchar;
                    return plainchar - plaintext_out;
                }
                fragment = (char)base64_decode_value(*codechar++);
        } while (fragment < 0);
            *plainchar++ |= (fragment & 0x03f);
        }
    }
    return plainchar - plaintext_out;
}

int satr_random_number_generator( mbedtls_ctr_drbg_context *crt_brbg,
                        void ( *function ),
                        mbedtls_entropy_context *entropy,
                        const char *pers,
                        size_t size )
{
    mbedtls_ctr_drbg_seed( crt_brbg, function, entropy,
                        ( const unsigned char * ) pers,
                        size );
    return ( 0 );
}

int check_custom_name(char *subject_name)
{
    char * Buffer1 = {0};
    bool custom_name = 0;
    Buffer1 = strtok(subject_name, "CN=");
    custom_name = strcmp(Buffer1, "sensor.live");
    return custom_name;
}

int read_serial_number(mbedtls_mpi *serial, int i, const char *s)
{
    mbedtls_mpi_read_string( serial, i, s );
    return ( 0 );
}

bool hasCertFile(char *file_name) {
    bool result;
    char file_path[50];
    strcpy(file_path, CERTS_PATH);
    strcat(file_path, file_name);
    FILE* fp = fopen(file_path, "r");
    if (fp) {
        result = true;
        fclose(fp);
    } else {
        result = false;
    }
    return result;
}

int main( void )
{
    mbedtls_printf("\n  . Check CSR file...");
    if (hasCertFile(ISSUER_CRT) == false) // CHECK ROOT_CA
    {
        mbedtls_printf( " failed\n  ! Your Root certificte not exist! Plase create first! And copy to your folder '%s'\n\n", CERTS_PATH);
        goto exit;
    }
    else if (hasCertFile(REQ_FILE) == false) // CHECK CSR
    {
        mbedtls_printf( " failed\n  ! CSR file not exist! Plase create CSR first!\n\n");
        goto exit;
    }
    else if (hasCertFile(SUBJECT_KEY) == false) // CHECK DEVICE PRIVATE KEY
    {
        mbedtls_printf( " failed\n  ! Private Key file not exist! Plase create Keyfile first!\n\n");
        goto exit;
    }
    else if (hasCertFile(ISSUER_KEY) == false) // CHECK ROOT PRIVATE KEY
    {
        mbedtls_printf( " failed\n  ! Root private key not exist! Plase create keyfile first!\n\n");
        goto exit;
    }
    
    else
    {
        mbedtls_printf( " done\n  !\n\n");
    }
    
    opt.issuer_crt              = ISSUER_CRT;
    opt.request_file            = REQ_FILE;
    opt.subject_key             = SUBJECT_KEY;
    opt.issuer_key              = ISSUER_KEY;
    opt.issuer_name             = DFL_ISSUER_NAME;
    opt.not_before              = DFL_NOT_BEFORE;
    opt.not_after               = DFL_NOT_AFTER;
    opt.serial                  = DFL_SER_NUMBER;
    opt.output_file             = DFL_OUTPUT_FILENAME;
    opt.key_usage               = DFL_KEY_USAGE;
    opt.ns_cert_type            = MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA;
    opt.selfsign                = DFL_SELFSIGN;
    opt.is_ca                   = DFL_IS_CA;
    opt.max_pathlen             = DFL_MAX_PATHLEN;
    opt.authority_identifier    = DFL_AUTH_IDENT;
    opt.subject_identifier      = DFL_SUBJ_IDENT;
    opt.basic_constraints       = DFL_CONSTRAINTS;
    opt.version                 = DFL_VERSION - 1;
    opt.md                      = DFL_DIGEST;

    mbedtls_x509write_cert crt;
    mbedtls_x509_crt issuer_crt;
    mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context *issuer_key = &loaded_issuer_key,
                *subject_key = &loaded_subject_key;
    mbedtls_mpi serial;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_x509write_crt_init( &crt );
    mbedtls_pk_init( &loaded_issuer_key );
    mbedtls_pk_init( &loaded_subject_key );
    mbedtls_mpi_init( &serial );

    #if defined(MBEDTLS_X509_CSR_PARSE_C)
        char subject_name[256];
        mbedtls_x509_csr csr;
    #endif

    mbedtls_x509_crt_init( &issuer_crt );
    memset( buf, 0, 1024 );

    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = satr_random_number_generator( &ctr_drbg, mbedtls_entropy_func,
                                        &entropy,
                                        pers,
                                        strlen( pers ) ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_ctr_drbg_seed returned %d - %s\n",
                        ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    mbedtls_printf( "  . Reading serial number..." );
    fflush( stdout );

    if( ( ret = read_serial_number( &serial, 10, opt.serial ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_mpi_read_string "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    #if defined(MBEDTLS_X509_CRT_PARSE_C)
    {
        mbedtls_printf( "\n  . Loading the CA root certificate ..." );
        fflush( stdout );

        if( ( ret = mbedtls_x509_crt_parse_file( &issuer_crt, opt.issuer_crt ) ) != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse_file "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        ret = mbedtls_x509_dn_gets( issuer_name, sizeof(issuer_name),
                                 &issuer_crt.subject );
        if( ret < 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509_dn_gets "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        opt.issuer_name = issuer_name;
        mbedtls_printf("\n  - issuer_name: %s", issuer_name);
    }
    #endif

    #if defined(MBEDTLS_X509_CSR_PARSE_C)
    {
        mbedtls_x509_csr_init( &csr );

        mbedtls_printf( "\n  . Loading the CSR ..." );
        fflush( stdout );

        ret = mbedtls_x509_csr_parse_file( &csr,  opt.request_file);
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret );
            goto exit;
        }

        mbedtls_printf( " ok\n" );

        mbedtls_x509_dn_gets( subject_name, sizeof(subject_name), &csr.subject );
        opt.subject_name = subject_name;
        subject_key = &csr.pk;
        mbedtls_printf("  - subject_name: %s\n", subject_name );
    }
    #endif

    mbedtls_printf( "  . Loading the subject key ..." );
    fflush( stdout );

    ret = mbedtls_pk_parse_keyfile( &loaded_subject_key, opt.subject_key, NULL);
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_keyfile ");
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    mbedtls_printf( "  . Loading the issuer key ..." );
    fflush( stdout );

    ret = mbedtls_pk_parse_keyfile( &loaded_issuer_key, opt.issuer_key, NULL );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_keyfile "
                        "returned -x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    if( strlen( opt.issuer_crt ) )
    {
        if( mbedtls_pk_check_pair( &issuer_crt.pk, issuer_key ) != 0 )
        {
            mbedtls_printf( " failed\n  !  issuer_key does not match "
                            "issuer certificate\n\n" );
            goto exit;
        }
    }

    mbedtls_printf( " ok\n" );

    mbedtls_x509write_crt_set_subject_key( &crt, subject_key );
    mbedtls_x509write_crt_set_issuer_key( &crt, issuer_key );

    if( ( ret = mbedtls_x509write_crt_set_subject_name( &crt, opt.subject_name ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_subject_name "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    if( ( ret = mbedtls_x509write_crt_set_issuer_name( &crt, opt.issuer_name ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_issuer_name "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( "  . Setting certificate values ..." );
    fflush( stdout );

    mbedtls_x509write_crt_set_version( &crt, opt.version );
    mbedtls_x509write_crt_set_md_alg( &crt, opt.md );

    ret = mbedtls_x509write_crt_set_serial( &crt, &serial );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_serial "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    ret = mbedtls_x509write_crt_set_validity( &crt, opt.not_before, opt.not_after );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_validity "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    if( opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.basic_constraints != 0 )
    {
        mbedtls_printf( "  . Adding the Basic Constraints extension ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_basic_constraints( &crt, opt.is_ca,
                                                           opt.max_pathlen );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  x509write_crt_set_basic_contraints "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

    if( opt.version ==MBEDTLS_X509_CRT_VERSION_3 &&
        opt.subject_identifier != 0 )
    {
        mbedtls_printf( "  . Adding the Subject Key Identifier ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_subject_key_identifier( &crt );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_subject"
                            "_key_identifier returned -0x%04x - %s\n\n",
                            -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

    if( opt.version == MBEDTLS_X509_CRT_VERSION_3 &&
        opt.ns_cert_type != 0 )
    {
        mbedtls_printf( "  . Adding the NS Cert Type extension ..." );
        fflush( stdout );

        ret = mbedtls_x509write_crt_set_ns_cert_type( &crt, opt.ns_cert_type );
        if( ret != 0 )
        {
            mbedtls_strerror( ret, buf, 1024 );
            mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_ns_cert_type "
                            "returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        mbedtls_printf( " ok\n" );
    }

    mbedtls_printf( "  . Writing the certificate..." );
    fflush( stdout );

    if( ( ret = write_certificate(opt.issuer_crt, &crt, opt.output_file,
                                mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_strerror( ret, buf, 1024 );
        mbedtls_printf( " failed\n  !  write_certificate -0x%04x - %s\n\n",
                        -ret, buf );
        goto exit;
    }

    mbedtls_printf( " ok\n" );
    mbedtls_printf( "  . Check custom thing name from certificate...\n\n" );
    fflush( stdout );
    
    if( ( ret = check_custom_name( subject_name ) ) !=0 )
    {
        mbedtls_printf(" thing name: %s", subject_name);
        fflush( stdout );
        goto exit;
    }
    else
    {
        mbedtls_printf( "  . Find the default thing name from certificate...\n\n" );
        fflush( stdout );
        if( ( get_default_thing_name(opt.output_file) ) != 0 )
        {
            mbedtls_printf(" failed\n ! Can not get thing name !\n");
            fflush( stdout );
        }
        mbedtls_printf( " ok\n" );
    }

exit:
    mbedtls_x509_crt_free( &issuer_crt );
    mbedtls_pk_free( &loaded_subject_key );
    mbedtls_pk_free( &loaded_issuer_key );
    mbedtls_mpi_free( &serial );

    return( 0 );
}
#endif