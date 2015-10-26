#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG   0
#if DEBUG
#define dbg(fmt,args...) fprintf(stderr,fmt, ## args)
#else
#define dbg(fmt,args...)
#endif

typedef unsigned int BOOL;
#define TRUE    1
#define FALSE   0

#define dump(buf,bufsz) bufdump(stderr,FALSE,buf,bufsz)

static void bufdump(FILE *out, int option, char *buf, int bufsz)
{
    int i = 0, n = 0;
    char str[6 * 0x10 + 8];

    for (i = 0; i < bufsz ; i++)
    {
        if (n >= 0)
        {
            if (option == 2)
            {
                n += sprintf(&str[n], "0x%02x, ", (unsigned char)buf[i]);
            }
            else
            {
                n += sprintf(&str[n], "%02x ", (unsigned char)buf[i]);
            }
        }

        if ((i % 16) == 15  || i + 1 == bufsz)
        {
            if (option == 1)
            {
                fprintf(out, "0x%08x: %s\n", ((i + 1) - n / 3), str);
            }
            else
            {
                fprintf(out, "%s\n", str);
            }

            n = 0;
        }
    }
}

#define TMPBUF_SIZE (1024)
int printhex(int argc, char **argv)
{
    int option;
    char *buf;
    size_t bufsz;
    option = 0;
    bufsz = 0;
    buf = malloc(TMPBUF_SIZE);

    if (argc >= 2)
    {
        if (strcmp(argv[1], "-v") == 0)
        {
            option = 1;
        }
        else if (strcmp(argv[1], "-h") == 0)
        {
            option = 2;
        }
    }

    if (buf == NULL)
    {
        dbg("Can't allocate memory.\n");
        return -1;
    }

    if (option == 2)
    {
        fprintf(stdout, "static unsigned char buf[] = {\n");
    }

    while (!feof(stdin))
    {
        bufsz = fread(buf, 1, TMPBUF_SIZE, stdin);

        if (bufsz > 0)
        {
            bufdump(stdout, option, buf, bufsz);
        }
        else
        {
            break;
        }
    }

    if (option == 2)
    {
        fprintf(stdout, "}; /* end of buf[] */ \n");
    }

    free(buf);
    return 0;
}

