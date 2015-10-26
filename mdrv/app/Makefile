CROSS   =
CC      = gcc

CFLAGS  = -Os -pthread
LDFLAGS = -lpthread
TARGET  = mapp
OBJS    = $(patsubst %.c, %.o, $(wildcard *.c))

$(TARGET): clean $(OBJS)
	$(CROSS)$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CROSS)$(CC) $(CFLAGS) -c $< -o $@
    
clean:
	rm -f $(OBJS) $(TARGET)

