#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char base64str[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int get_index(char c)
{
    switch (c)
    {
    case 'A' ... 'Z':
        return c - 'A';
    case 'a' ... 'z':
        return c - 'a' + 26;
    case '0' ... '9':
        return c - '0' + 52;
    case '+':
        return 62;
    case '/':
        return 63;
    default:
        break;
    }
    return -1;
}

static unsigned int obytecnt = 0;
static void output(unsigned char out)
{
    obytecnt = (obytecnt + 1) % 76;
    fprintf(stdout, "%c%s", base64str[(out) & 0x3f], (obytecnt == 0) ? "\n" : "");
}

void base64_encode(void)
{
    unsigned short word = 0;
    unsigned int obitcnt = 0;
    unsigned char *in = (unsigned char*)&word;
    unsigned char *out = in + 1;

    while (!feof(stdin))
    {
        if (!fread(in, 1, 1, stdin))
        {
            break;
        }

        word <<= (6 - obitcnt);
        output(*out);
        *out = 0;
        word <<= (2 + obitcnt);
        obitcnt = (2 + obitcnt);

        if (obitcnt == 6)
        {
            output(*out);
            *out = 0;
            obitcnt = 0;
        }
    }

    if (obitcnt)
    {
        word <<= (6 - obitcnt);
        output(*out);
        *out = 0;
        obitcnt = 0;
    }
}

void base64_decode(void)
{
    char c;
    unsigned short word = 0;
    unsigned int obitcnt = 0;
    unsigned char *in = (unsigned char*)&word;
    unsigned char *out = in + 1;

    while (!feof(stdin))
    {
        if (!fread(&c, 1, 1, stdin))
        {
            break;
        }

        if (c == '=')
        {
            break;
        }

        if (c == '\n')
        {
            continue;
        }

        *in = get_index(c);

        if (*in == -1)
        {
            continue;
        }

        *in = (*in << 2);

        if (obitcnt + 6 >= 8)
        {
            word <<= (8 - obitcnt);
            fwrite(out, 1, 1, stdout);
            *out = 0;
            obitcnt = (obitcnt - 2);
            word <<= obitcnt;
        }
        else
        {
            obitcnt += 6;
            word <<= 6;
        }
    }

    word = 0;
}

