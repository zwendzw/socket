#if !defined(CREATE_CSR_H)
#define CREATE_CSR_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// ------------- MAC ADDRESS -------------

const char *custom_name = NULL;

// ---------------------------------------

int createCsr();

#define CERTS_PATH              "./"
#define DFL_FILENAME            "./keyfile.key"
#define DFL_DEBUG_LEVEL         0
#define DFL_OUTPUT_FILENAME     "./deviceCert.csr"
#define DFL_SUBJECT_NAME        "CN=sensor.live"
#define DFL_KEY_USAGE           0
#define DFL_NS_CERT_TYPE        0

#endif