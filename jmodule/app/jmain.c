#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>


static int fd;

static void *my_task(void *dummy)
{
	int ret, i;
	unsigned char c;
	i = 0;
	while(1)
	{
		c = i < 10 ? '0' + i : 'a' - 10 + i;
		ret = write(fd,&c,1);
		sleep(1);
		i = (i + 1)%16;
	}
}

int main()
{
	pthread_t th;
	int ret, n;
	unsigned char *buf;
	unsigned int sz;
	ret = 0;
	buf = NULL;
	sz = 100;
	srand(time(NULL));

	fd = open("/dev/jdrv", O_RDWR);
	if (fd < 0)
	{
		ret = -1;
		goto end;
	}
	buf = malloc(sz+1);
	if(buf == NULL)
	{
		ret = -1;
		goto end;
	}

	/* create thread to write */
	pthread_create(&th, NULL, my_task, NULL);
	/* read and block until done */
	while(1)
	{
		n = rand()%20;
		sleep(n);
		ret = read(fd, buf, sz);
		if (ret < 0)
		{
			break;
		}
	}
end:
	free(buf);
	close(fd);
	return ret;
}
