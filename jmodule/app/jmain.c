#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>


static int fd;

static void *my_task(void *dummy)
{
	unsigned char byte;
	byte = 0;
	while(1)
	{
		write(fd,&byte,1);
		sleep(1);
	}
}

int main()
{
	pthread_t th;
	int ret;
	unsigned char *buf;
	unsigned int sz;
	ret = 0;
	buf = NULL;
	sz = 100;
	fd = open("/dev/jdrv", O_RDWR);
	if (fd < 0)
	{
		ret = -1;
		goto end;
	}
	buf = malloc(sz);
	if(buf == NULL)
	{
		ret = -1;
		goto end;
	}

	/* create thread to write */
	pthread_create(&th, NULL, my_task, NULL);

	/* read and block until done */
	ret = read(fd, buf, sz);
	printf("ret %d\n",ret);	
end:
	free(buf);
	close(fd);
	return ret;
}
