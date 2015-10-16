CC	= gcc
OBJS	= mapp.o
TARGET	= mapp
CFLAGS	= -Os -pthread
LDFLAGS	= -lpthread

$(TARGET): clean $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)

