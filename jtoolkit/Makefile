CC			= gcc -Os
RM			= rm -rf
MV			= mv -f
AR			= ar cur
RANLIB		= ranlib

SRCDIR		= .
INCDIR		= .
OBJDIR		= objs

CFLAGS      = \
    -Wall -Wundef -Wempty-body \
    -Wold-style-declaration -Wclobbered -Wignored-qualifiers -Wsign-compare

SRCS		= $(wildcard $(SRCDIR)/*.c)
OBJS_1		= $(patsubst %.c,%.o,$(SRCS))
OBJS		= $(patsubst $(SRCDIR)%,$(OBJDIR)%,$(OBJS_1))

TARGET		= jtk

all: clean MKDIR $(TARGET)

MKDIR:
	@mkdir -p $(OBJDIR)

$(TARGET): $(OBJS)
	@$(CROSS)$(CC) $(LDFLAGS) -o $@ $^

$(OBJDIR)/%.o:$(SRCDIR)/%.c
	@$(CROSS)$(CC) $(CFLAGS) -c $< -o $@

clean:
	@$(RM) $(OBJDIR) $(TARGET)


