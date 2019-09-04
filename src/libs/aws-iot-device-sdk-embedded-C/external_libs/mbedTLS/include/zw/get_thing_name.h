#if !defined(GET_THING_NAME_H)
#define GET_THING_NAME_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "mbedtls/certs.h"
#include "mbedtls/error.h"

char *bin2hex(const unsigned char *, size_t);

const char *output_file = "./deviceCert.pem";

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


#endif // GET_THING_NAME_H
