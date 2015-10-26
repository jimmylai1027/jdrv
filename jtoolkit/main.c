#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char BOOL;
#define TRUE    1
#define FALSE   0

int dump2bin(int argc, char **argv);
int printhex(int argc, char **argv);
int cipher(BOOL bEncrypt, char civ[16], char cck[16]);
int conv_dump_to_buf(char *str, char *buf, int bufsz);
void base64_encode(void);
void base64_decode(void);

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        if (strcmp(argv[1], "dump2bin") == 0)
        {
            dump2bin(argc - 1, argv + 1);
        }
        else if (strcmp(argv[1], "printhex") == 0)
        {
            printhex(argc - 1, argv + 1);
        }
        else if (strcmp(argv[1], "base64") == 0)
        {
            if (argc > 2)
            {
                if (strcmp(argv[2], "e") == 0)
                {
                    base64_encode();
                }
                else if (strcmp(argv[2], "d") == 0)
                {
                    base64_decode();
                }
            }
        }
    }

    return 0;
}

