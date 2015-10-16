CC	= gcc
OBJS	= jmain.o
TARGET	= japp
CFLAGS	= -Os -pthread
LDFLAGS	= -lpthread

$(TARGET): clean $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)

