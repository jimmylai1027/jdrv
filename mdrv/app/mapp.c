#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>


static int fd = 0;

static void *my_task(void *dummy)
{
	int ret, i, n;
	unsigned char str[10+1];
	i = 0;
	while(1)
	{
        n = rand() % 10;
        str[n] = '\0';
        while (n--)
        {
            str[n] = i < 10 ? '0' + i : 'a' - 10 + i;
        }
		ret = write(fd,str,strlen(str));
		sleep( rand() % 10 );
		i = (i + 1)%16;
	}
}

int main(int argc, char **argv)
{
	pthread_t th;
	int ret = 0;
	unsigned char *buf = NULL;
	unsigned int sz = 100;

	srand(time(NULL));

	fd = open("/dev/mdrv", O_RDWR);
	buf = malloc(sz+1);

	if (fd < 0 || buf == NULL)
	{
		ret = -1;
		goto end;
	}

	/* create thread to write */
	pthread_create(&th, NULL, my_task, NULL);

	/* read and block until done */
	while(1)
	{
		sleep( rand() % 5 );
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
