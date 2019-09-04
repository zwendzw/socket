#ifndef _CREATE_CERTIFICATE_H_
#define _CREATE_CERTIFICATE_H_
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_snprintf   snprintf
#define mbedtls_printf     printf
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

#define CERTS_PATH              "./"
#define ISSUER_CRT              "/Users/Cyan/Downloads/mbedtls-2.12.0/rootCA.pem"
#define REQ_FILE                "./deviceCert.csr"
#define SUBJECT_KEY             "./keyfile.key"
#define ISSUER_KEY              "/Users/Cyan/Downloads/mbedtls-2.12.0/rootCA.key"
#define DFL_ISSUER_NAME         "CN=CA,O=mbed TLS,C=UK"
#define DFL_SER_NUMBER          "1"
#define DFL_NOT_BEFORE          "20180101000000"
#define DFL_NOT_AFTER           "20201231235959"
#define DFL_OUTPUT_FILENAME     "./deviceCert.pem"
#define DFL_SELFSIGN            0
#define DFL_IS_CA               0
#define DFL_MAX_PATHLEN         -1
#define DFL_KEY_USAGE           0
#define DFL_NS_CERT_TYPE        0
#define DFL_VERSION             3
#define DFL_AUTH_IDENT          1
#define DFL_SUBJ_IDENT          1
#define DFL_CONSTRAINTS         1
#define DFL_DIGEST              MBEDTLS_MD_SHA256

const char *pers = "sensor.live";
int ret = 1;
char issuer_name[256];
char buf[1024];

struct options
{
    const char *issuer_crt;
    const char *request_file;
    const char *subject_key;
    const char *issuer_key;
    const char *issuer_name; 
    const char *not_before;
    const char *not_after;
    const char *serial;
    const char *output_file;
    unsigned char key_usage; 
    unsigned char ns_cert_type;
    int selfsign;
    int is_ca;
    int max_pathlen;
    int authority_identifier;
    int subject_identifier;
    int basic_constraints; 
    int version;
    mbedtls_md_type_t md;  
    const char *subject_name;
    const char *subject_pwd; 
    const char *issuer_pwd;
} opt;

char *bin2hex(const unsigned char *, size_t);

typedef enum
{
    step_a, step_b, step_c, step_d
} base64_decodestep;

typedef struct
{
    base64_decodestep step;
    char plainchar;
} base64_decodestate;

size_t base64Decode(const char *, char *);

void base64_init_decodestate(base64_decodestate *);

int base64_decode_value(char);

int base64_decode_block(const char *, const int, char *, base64_decodestate *);
#endif