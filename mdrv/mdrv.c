#include <linux/init.h>		/* essentail header, __init __exit */
#include <linux/module.h>	
#include <linux/cdev.h>		/* cdev_init cdev_add cdev_del */
#include <linux/fs.h>		/* file operations */
#include <linux/slab.h>		/* kmalloc kfree */
#include <linux/wait.h>		/* wait event */
#include <linux/sched.h>	/* wait event */
#include <linux/string.h>

MODULE_LICENSE("Dual BSD/GPL");

#define dbg(fmt, args...) printk( KERN_EMERG "[mdrv] " fmt, ## args)

typedef struct __S_MDRV
{
	wait_queue_head_t wq;
#define MDRV_LOGBUF_SIZE	1024
	char logbuf[MDRV_LOGBUF_SIZE];
	unsigned int wp;
	unsigned int rp;
} S_MDRV;

static void dump(const char *buf, unsigned int sz)
{
	char *str;
	str = (char*)vmalloc(sz+1);
	if (str)
	{
		strncpy(str, buf, sz);
		str[sz] = '\0';
		dbg("%s\n",str);
		vfree(str);
	}
}


static unsigned int get_logbuf_size(S_MDRV *jd)
{
	if (jd->wp >= jd->rp)
	{
		return jd->wp - jd->rp;
	}
	return jd->wp + (MDRV_LOGBUF_SIZE - jd->rp);
}

static unsigned int get_avaliable_size(S_MDRV *jd)
{
	return MDRV_LOGBUF_SIZE - get_logbuf_size(jd) - 1;
}

static bool is_logbuf_full(S_MDRV *jd)
{
	return get_logbuf_size(jd) == (MDRV_LOGBUF_SIZE-1);
}

static ssize_t readbuf(S_MDRV *jd, char __user *buf, size_t size)
{
	unsigned int sz;
	unsigned int idx;
	sz = get_logbuf_size(jd);
	if (sz == 0)
	{
		return 0;
	}
	sz = sz < size ? sz : size;
	idx = (jd->rp + sz) % MDRV_LOGBUF_SIZE;
	if (idx < jd->rp)
	{
		unsigned int sz1, sz2;
		sz1 = MDRV_LOGBUF_SIZE - jd->rp;
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

static ssize_t writebuf(S_MDRV *jd, const char __user *buf, size_t size)
{
	unsigned int sz;
	unsigned int idx;
	if (is_logbuf_full(jd))
	{
		return 0;
	}
	sz = get_avaliable_size(jd);
	sz = sz < size ? sz : size;
	idx = (jd->wp + sz) % MDRV_LOGBUF_SIZE;
	if (idx < jd->wp)
	{
		unsigned int sz1,sz2;
		sz1 = MDRV_LOGBUF_SIZE - jd->wp;
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
	S_MDRV *jd;
	dbg("%s: '%s'(pid %i) open mdrv (major %d minor %d)\n",
		__FUNCTION__, current->comm, current->pid,
		imajor(i), iminor(i));
	filp->private_data = kmalloc(sizeof(S_MDRV),GFP_KERNEL);
	if(filp->private_data == NULL)
	{
		dbg("Fail to allocate memory\n");
		return -ENOMEM;
	}
	jd = (S_MDRV *)filp->private_data;
	init_waitqueue_head(&jd->wq);
	memset(jd->logbuf, 0, MDRV_LOGBUF_SIZE);
	jd->rp = jd->wp = 0;	/* buf empty */
	return 0;
}

static int drv_close(struct inode *i, struct file *filp)
{
	dbg("%s: '%s'(pid %i) close mdrv (major %d minor %d)\n",
		__FUNCTION__, current->comm, current->pid,
		imajor(i), iminor(i));
	kfree(filp->private_data);
	return 0;
}

static ssize_t drv_read(
	struct file *filp, char __user *buf, size_t size, loff_t *f_ops)
{
	ssize_t ret;
	S_MDRV *jd = (S_MDRV *)filp->private_data;
	dbg("%s: read %zd byte%s\n", __FUNCTION__, size, size==1?"":"s");
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
		dbg("wait_event_interruptible return %zd\n", ret);
	}
	return ret;
}

static ssize_t drv_write(
	struct file *filp, const char __user *buf, size_t size, loff_t *f_ops)
{
	ssize_t ret;
	S_MDRV *jd = (S_MDRV *)filp->private_data;
	dbg("%s: write %zd byte%s\n", __FUNCTION__, size, size==1?"":"s");
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
#define MDRV_MAJOR	60
#define MDRV_MINOR	0

static __init int init_drv(void)
{
	int devno;
	dbg("%s\n",__FUNCTION__);
	chrdev = cdev_alloc();
	devno = MKDEV(MDRV_MAJOR, MDRV_MINOR);
	cdev_init(chrdev, &drv_fops);
	chrdev->owner = THIS_MODULE;
	chrdev->ops = &drv_fops;
	cdev_add(chrdev, devno, 1);
	return 0;
}

static __exit void exit_drv(void)
{
	dbg("%s\n",__FUNCTION__);
	cdev_del(chrdev);
}

module_init(init_drv);
module_exit(exit_drv);
