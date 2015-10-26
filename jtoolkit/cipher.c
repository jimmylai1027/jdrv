#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

typedef unsigned char BOOL;
#define TRUE    1
#define FALSE   0

#define TMPBUF_SIZE    (1024)
int cipher(BOOL bEncrypt, char civ[16], char cck[16])
{
    char default_civ[16] =
    {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    char default_cck[16] =
    {
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
    };
    char *buf;
    size_t bufsz;

    if (civ == NULL || cck == NULL)
    {
        civ = default_civ;
        cck = default_cck;
    }

    bufsz = 0;
    buf = malloc(TMPBUF_SIZE);

    if (buf == NULL)
    {
        fprintf(stderr, "Can't allocate memory.\n");
        return -1;
    }

    AES128CBC_Init(civ, cck);

    while (feof(stdin) == 0)
    {
        bufsz = fread(buf, 1, TMPBUF_SIZE, stdin);

        if (bEncrypt)
        {
            AES128CBC_CipherEncrypt(buf, bufsz);
        }
        else
        {
            AES128CBC_CipherDecrypt(buf, bufsz);
        }

        bufsz = fwrite(buf, 1, bufsz, stdout);
    }

    free(buf);
    return 0;
}
