#include "get_thing_name.h"

int main(void)
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
        printf("\n  Thing name is: %s", thing_name);
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