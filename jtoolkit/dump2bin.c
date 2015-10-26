#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG   0
#if DEBUG
#define dbg(fmt,args...) fprintf(stderr,fmt, ## args)
#else
#define dbg(fmt,args...)
#endif

static void dump(char *ptr, int size)
{
    int i = 0, n = 0;
    char str[3 * 0x10 + 8];

    for (i = 0; i < size ; i++)
    {
        if (n >= 0)
        {
            n += sprintf(&str[n], "%02x ", (unsigned char)ptr[i]);
        }

        if (n >= 3 * 0x10 || i + 1 == size)
        {
            n = 0;
            dbg("%s\n", str);
        }
    }
}

typedef unsigned int BOOL;
#define TRUE    1
#define FALSE   0

#define LINE_BYTE_CNT   (1024)
#define TMPBUF_SIZE     (LINE_BYTE_CNT/2)


typedef enum __E_TOKEN_TYPE
{
    TTYPE_UNKNOW = 0,
    TTYPE_HEXSTRN,
    TTYPE_BYTE,      /* 1 byte  */
    TTYPE_WORD,      /* 2 bytes */
    TTYPE_DWORD,     /* 4 bytes */
    TTYPE_MASK = 0xff,       /* Don't use it */
    TTYPE_0X_BASE = 0x100,   /* Don't use it */
    TTYPE_0XBYTE = TTYPE_0X_BASE | TTYPE_BYTE,
    TTYPE_0XWORD = TTYPE_0X_BASE | TTYPE_WORD,
    TTYPE_0XDWORD = TTYPE_0X_BASE | TTYPE_DWORD,

    TTYPE_NUMBER,    /* Don't use it */
} E_TOKEN_TYPE;

typedef enum __E_LINE_TYPE
{
    LTYPE_EMPTY = 0,
    LTYPE_DWORDS,
    LTYPE_WORDS,
    LTYPE_BYTES,
    LTYPE_HEXSTRS,
    LTYPE_MASK = 0xff,          /* Don't use it. */
    LTYPE_ADDR_BASE = 0x100,    /* Don't use it. */
    LTYPE_ADDR_DWORDS = LTYPE_ADDR_BASE | LTYPE_DWORDS,
    LTYPE_ADDR_WORDS = LTYPE_ADDR_BASE | LTYPE_WORDS,
    LTYPE_ADDR_BYTES = LTYPE_ADDR_BASE | LTYPE_BYTES,
    LTYPE_ADDR_HEXSTRS = LTYPE_ADDR_BASE | LTYPE_HEXSTRS,

    LTYPE_NUMBER,   /* Don't use it */
} E_LINE_TYPE;

static BOOL ishex(char c)
{
    c = tolower(c);
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static BOOL ishexstr(char *str)
{
    if (str)
    {
        int i = strlen(str);

        if (i <= 0)
        {
            return FALSE;
        }

        while (i > 0)
        {
            i--;

            if (ishex(str[i]) == FALSE)
            {
                return FALSE;
            }
        }

        return TRUE;
    }

    return FALSE;
}

static E_TOKEN_TYPE get_token_type(char *token)
{
    E_TOKEN_TYPE tt;
    BOOL b0x;

    if (token == NULL)
    {
        tt = TTYPE_UNKNOW;
        goto end;
    }

    b0x = (strncasecmp(token, "0x", 2) == 0);

    if (b0x)
    {
        token += 2;
    }

    if (ishexstr(token) == FALSE)
    {
        tt = TTYPE_UNKNOW;
        goto end;
    }

    switch (strlen(token))
    {
    case 2:
        tt = b0x ? TTYPE_0XBYTE : TTYPE_BYTE ;
        break;

    case 4:
        tt = b0x ? TTYPE_0XWORD : TTYPE_WORD ;
        break;

    case 8:
        tt = b0x ? TTYPE_0XDWORD : TTYPE_DWORD ;
        break;

    default:
        tt = b0x ? TTYPE_UNKNOW : TTYPE_HEXSTRN;
        break;
    }

    dbg("token/type: '%s' / %s\n", token,    \
        tt == TTYPE_UNKNOW ? "TTYPE_UNKNOW" :   \
        tt == TTYPE_HEXSTRN ? "TTYPE_HEXSTRN" : \
        tt == TTYPE_0XBYTE ? "TTYPE_0XBYTE" :   \
        tt == TTYPE_0XWORD ? "TTYPE_0XWORD" :   \
        tt == TTYPE_0XDWORD ? "TTYPE_0XDWORD" : \
        tt == TTYPE_BYTE ? "TTYPE_BYTE" :       \
        tt == TTYPE_WORD ? "TTYPE_WORD" :       \
        tt == TTYPE_DWORD ? "TTYPE_DWORD" : ""  \
       );
end:
    return tt;
}

static E_LINE_TYPE get_line_type(char *line_str)
{
    char line[LINE_BYTE_CNT];
    E_TOKEN_TYPE tt0, tt1 , tt;
    char *t0, *t1, *t;
    int token_cnt;
    strcpy(line, line_str);
    t0 = NULL;
    t1 = NULL;
    token_cnt = 0;
    t0 = strtok(line, " ,:;\n");
    tt0 = get_token_type(t0);
    token_cnt = t0 ? (token_cnt + 1) : token_cnt;

    if (tt0 == TTYPE_UNKNOW)
    {
        return LTYPE_EMPTY;
    }

    t = t1 = strtok(NULL, " ,;\n");
    tt = tt1 = get_token_type(t1);
    token_cnt = t1 ? (token_cnt + 1) : token_cnt;

    if (t1 && tt1 != TTYPE_UNKNOW)
    {
        while (1)
        {
            t = strtok(NULL, " ,;\n");
            tt = get_token_type(t);

            if (t == NULL)
            {
                break;
            }
            else if (tt != tt1)
            {
                break;
            }

            token_cnt++;
        }
    }

    if (token_cnt == 0)
    {
        return LTYPE_EMPTY;
    }

    if (token_cnt == 1)
    {
        tt1 = tt0;
    }

    if (tt0 != tt1)
    {
        token_cnt -= 1;
    }

    switch (tt1)
    {
    case TTYPE_BYTE:
    case TTYPE_0XBYTE:
        return (tt0 != tt1) ? LTYPE_ADDR_BYTES : LTYPE_BYTES;

    case TTYPE_WORD:
    case TTYPE_0XWORD:
        return (tt0 != tt1) ? LTYPE_ADDR_WORDS : LTYPE_WORDS;

    case TTYPE_DWORD:
    case TTYPE_0XDWORD:
        return (tt0 != tt1) ? LTYPE_ADDR_DWORDS : LTYPE_DWORDS;

    default:
        return (tt0 != tt1) ? LTYPE_ADDR_HEXSTRS : LTYPE_HEXSTRS;
    }

    return LTYPE_EMPTY;
}

static int conv_hexstr(char *str, char *buf, int bufsz)
{
    char tmp[3];
    unsigned int i;
    int cnt, b;
    cnt = b = 0;
    tmp[2] = '\0';

    if (str)
    {
        for (i = 0; i < strlen(str); i++)
        {
            if (ishex(str[i]))
            {
                tmp[b] = str[i];
                b = (b + 1) % 2;

                if (b == 0)
                {
                    if (cnt < bufsz)
                    {
                        buf[cnt] = strtol(tmp, NULL, 16) & 0xff;
                        cnt++;
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }
    }

    return cnt;
}

int conv_dump_to_buf(char *line, char *buf, int bufsz)
{
    E_LINE_TYPE lt;
    char *t;
    int cnt;
    lt = get_line_type(line);
    dbg("-> %s\n", \
        lt == LTYPE_EMPTY ? "LTYPE_EMPTY" :                      \
        lt == LTYPE_ADDR_DWORDS ? "LTYPE_ADDR_DWORDS" :      \
        lt == LTYPE_ADDR_WORDS ? "LTYPE_ADDR_WORDS" :        \
        lt == LTYPE_ADDR_BYTES ? "LTYPE_ADDR_BYTES" :      \
        lt == LTYPE_DWORDS ? "LTYPE_DWORDS" :                \
        lt == LTYPE_WORDS ? "LTYPE_WORDS" :                  \
        lt == LTYPE_BYTES ? "LTYPE_BYTES" :                \
        lt == LTYPE_HEXSTRS ? "LTYPE_HEXSTRS" :                 \
        lt == LTYPE_ADDR_HEXSTRS ? "LTYPE_ADDR_HEXSTRS" : ""    \
       );

    if (lt == LTYPE_EMPTY)
    {
        return 0;
    }

    if (lt & LTYPE_ADDR_BASE)
    {
        t = strtok(line, " ,:;\n");
        t = strtok(NULL, " ,;\n");
    }
    else
    {
        t = strtok(line, " ,;\n");
    }

    cnt = 0;

    if ((lt & LTYPE_MASK) == LTYPE_DWORDS)
    {
        unsigned int *dwp = (unsigned int *)buf;

        while (t && cnt < 4)
        {
            dbg("t: %s\n", t);
            *dwp = (unsigned int)(strtoll(t, NULL, 16) & 0xffffffff);
            dwp++;
            t = strtok(NULL, " ,;\n");
            cnt++;
        }

        return cnt * 4;
    }
    else if ((lt & LTYPE_MASK) == LTYPE_WORDS)
    {
        unsigned short *wp = (unsigned short *)buf;

        while (t && cnt < 8)
        {
            *wp = strtol(t, NULL, 16) & 0xffff;
            wp++;
            t = strtok(NULL, " ,;\n");
            cnt++;
        }

        return cnt * 2;
    }
    else if ((lt & LTYPE_MASK) == LTYPE_BYTES)
    {
        unsigned char *bp = (unsigned char *)buf;

        while (t && cnt < 16)
        {
            *bp = strtol(t, NULL, 16) & 0xff;
            bp++;
            t = strtok(NULL, " ,;\n");
            cnt++;
        }

        return cnt;
    }
    else if ((lt & LTYPE_MASK) == LTYPE_HEXSTRS)
    {
        return conv_hexstr(t, buf, bufsz);
    }

    return 0;
}

static int dump2bin_multilines(void)
{
    char *buf;
    int bufsz;
    char line[LINE_BYTE_CNT];
    buf = malloc(TMPBUF_SIZE);

    if (buf == NULL)
    {
        return -1;
    }

    while (!feof(stdin))
    {
        /* get one line */
        if (NULL == fgets(line, LINE_BYTE_CNT, stdin))
        {
            continue;
        }

        dbg("Line: %s", line);
        /* convert dump to binary */
        bufsz = conv_dump_to_buf(line, buf, TMPBUF_SIZE);
        dump(buf, bufsz);
        dbg("\n\n");

        if (bufsz > 0)
        {
            bufsz = fwrite(buf, 1, bufsz, stdout);
        }
    }

    free(buf);
    return 0;
}

static int get_str_token(char *buf, int bufsz)
{
    BOOL bParsed, bParsing;
    int c, cnt;
    bParsed = bParsing = 0;
    c = cnt = 0;

    while (!feof(stdin) && cnt + 1 < bufsz)
    {
        c = fgetc(stdin);
        c = tolower(c);
        bParsing = (ishex(c) || c == 'x');

        if (bParsing)
        {
            buf[cnt] = c;
            cnt++;
        }

        if (bParsed && !bParsing)
        {
            break;
        }

        bParsed = bParsing;
    }

    buf[cnt] = '\0';
    return cnt;
}

static int dump2bin_oneline(void)
{
    char tmpbuf[0x10];
    unsigned char byte;

    while (get_str_token(tmpbuf, 0x10))
    {
        byte = (unsigned char)strtol(tmpbuf, NULL, 16) & 0xff;;
        fwrite(&byte, 1, 1, stdout);
    }

    return 0;
}

int dump2bin(int argc, char **argv)
{
    if (argc > 1 && 0 == strncasecmp(argv[1], "line", 4))
    {
        return dump2bin_oneline();
    }

    return dump2bin_multilines();
}

