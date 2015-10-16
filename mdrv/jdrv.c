#include <linux/init.h>		/* essentail header */
#include <linux/module.h>	
#include <linux/cdev.h>		/* cdev_init cdev_add cdev_del */
#include <linux/fs.h>		/* file operations */
#include <linux/slab.h>		/* kmalloc kfree */
#include <linux/wait.h>		/* wait event */
#include <linux/sched.h>	/* wait event */
#include <linux/string.h>

MODULE_LICENSE("Dual BSD/GPL");

#define dbg(fmt, args...) printk( KERN_EMERG "[jdrv] " fmt, ## args)

typedef struct __S_JDRV
{
	wait_queue_head_t wq;
#define JDRV_LOGBUF_SIZE	1024
	unsigned char logbuf[JDRV_LOGBUF_SIZE];
	unsigned int wp;
	unsigned int rp;
} S_JDRV;

static void dump(const char *buf, unsigned int sz)
{
	unsigned char *str;
	str = vmalloc(sz+1);
	if (str)
	{
		strncpy(str, buf, sz);
		str[sz] = '\0';
		dbg("%s\n",str);
		vfree(str);
	}
}


static unsigned int get_logbuf_size(S_JDRV *jd)
{
	if (jd->wp >= jd->rp)
	{
		return jd->wp - jd->rp;
	}
	return jd->wp + (JDRV_LOGBUF_SIZE - jd->rp);
}

static unsigned int get_avaliable_size(S_JDRV *jd)
{
	return JDRV_LOGBUF_SIZE - get_logbuf_size(jd) - 1;
}

static bool is_logbuf_full(S_JDRV *jd)
{
	return get_logbuf_size(jd) == (JDRV_LOGBUF_SIZE-1);
}

static ssize_t readbuf(S_JDRV *jd, char __user *buf, size_t size)
{
	unsigned int sz;
	unsigned int idx;
	sz = get_logbuf_size(jd);
	if (sz == 0)
	{
		return 0;
	}
	sz = sz < size ? sz : size;
	idx = (jd->rp + sz) % JDRV_LOGBUF_SIZE;
	if (idx < jd->rp)
	{
		unsigned int sz1, sz2;
		sz1 = JDRV_LOGBUF_SIZE - jd->rp;
		sz2 = idx;
		copy_to_user(buf, jd->logbuf+jd->rp, sz1);
		copy_to_user(buf+sz1, jd->logbuf, sz2);
	}
	else
	{
		copy_to_user(buf, jd->logbuf+jd->rp, sz);
	}
	jd->rp = idx;
	return sz;
}

static ssize_t writebuf(S_JDRV *jd, const char __user *buf, size_t size)
{
	unsigned int sz;
	unsigned int idx;
	if (is_logbuf_full(jd))
	{
		return 0;
	}
	sz = get_avaliable_size(jd);
	sz = sz < size ? sz : size;
	idx = (jd->wp + sz) % JDRV_LOGBUF_SIZE;
	if (idx < jd->wp)
	{
		unsigned int sz1,sz2;
		sz1 = JDRV_LOGBUF_SIZE - jd->wp;
		sz2 = idx;
		copy_from_user(jd->logbuf+jd->wp, buf, sz1);
		copy_from_user(jd->logbuf, buf+sz1, sz2);
	}
	else
	{
		copy_from_user(jd->logbuf+jd->wp, buf, sz);
	}
	jd->wp = idx;
	return sz;
}

static int drv_open(struct inode *i, struct file *filp)
{
	S_JDRV *jd;
	dbg("%s: '%s'(pid %i) open jdrv (major %d minor %d)\n",
		__FUNCTION__, current->comm, current->pid,
		imajor(i), iminor(i));
	filp->private_data = kmalloc(sizeof(S_JDRV),GFP_KERNEL);
	if(filp->private_data == NULL)
	{
		dbg("Fail to allocate memory\n");
		return -ENOMEM;
	}
	jd = (S_JDRV *)filp->private_data;
	init_waitqueue_head(&jd->wq);
	memset(jd->logbuf, 0, JDRV_LOGBUF_SIZE);
	jd->rp = jd->wp = 0;	/* buf empty */
	return 0;
}

static int drv_close(struct inode *i, struct file *filp)
{
	dbg("%s: '%s'(pid %i) close jdrv (major %d minor %d)\n",
		__FUNCTION__, current->comm, current->pid,
		imajor(i), iminor(i));
	kfree(filp->private_data);
	return 0;
}

static ssize_t drv_read(
	struct file *filp, char __user *buf, size_t size, loff_t *f_ops)
{
	ssize_t ret;
	S_JDRV *jd = (S_JDRV *)filp->private_data;
	dbg("%s: read %u byte%s\n", __FUNCTION__, size, size==1?"":"s");
	ret = wait_event_interruptible(jd->wq, get_logbuf_size(jd));
	if (ret == 0)
	{
		ret = readbuf(jd, buf, size);
		if (ret>0)
		{
			dump(buf,ret);
		}
	}
	else if (ret == -ERESTARTSYS)
	{
		dbg("wait_event_interruptible return -ERESTARTSYS\n");
	}
	else
	{
		dbg("wait_event_interruptible return %d\n", ret);
	}
	return ret;
}

static ssize_t drv_write(
	struct file *filp, const char __user *buf, size_t size, loff_t *f_ops)
{
	ssize_t ret;
	S_JDRV *jd = (S_JDRV *)filp->private_data;
	dbg("%s: write %u byte%s\n", __FUNCTION__, size, size==1?"":"s");
	ret = writebuf(jd, buf, size);
	if (ret>0)
	{
		dump(buf,ret);
	}
	wake_up_interruptible(&jd->wq);
	return ret;
}

static struct file_operations drv_fops = 
{
	.open = drv_open,
	.release = drv_close,
	.read = drv_read,
	.write = drv_write,
};



static struct cdev *chrdev;
#define JDRV_MAJOR	60
#define JDRV_MINOR	0

static int init_drv(void)
{
	int devno;
	dbg("%s\n",__FUNCTION__);
	chrdev = cdev_alloc();
	devno = MKDEV(JDRV_MAJOR, JDRV_MINOR);
	cdev_init(chrdev, &drv_fops);
	chrdev->owner = THIS_MODULE;
	chrdev->ops = &drv_fops;
	cdev_add(chrdev, devno, 1);
	return 0;
}

static void exit_drv(void)
{
	dbg("%s\n",__FUNCTION__);
	cdev_del(chrdev);
}

module_init(init_drv);
module_exit(exit_drv);
