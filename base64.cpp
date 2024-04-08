#include "base64.hpp"

/***********************************************
decodes base64 format string into ASCCI string
@param plain encoded base64 format string
@return ASCII string to be encoded
***********************************************/

size_t decode_base64(unsigned char* cipher)
{
    int counts = 0;
    char buffer[4];
    int i = 0, p = 0;

    for (i = 0; cipher[i] != '\0'; i++) {
        unsigned char k;
        for (k = 0; k < 64 && base64_map[k] != cipher[i]; k++);
        buffer[counts++] = k;
        if (counts == 4) {
            cipher[p++] = (buffer[0] << 2) + (buffer[1] >> 4);
            if (buffer[2] != 64)
                cipher[p++] = (buffer[1] << 4) + (buffer[2] >> 2);
            if (buffer[3] != 64)
                cipher[p++] = (buffer[2] << 6) + buffer[3];
            counts = 0;
        }
    }
    return p;
}
