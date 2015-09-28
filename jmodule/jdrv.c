#include <linux/init.h>		/* essentail header */
#include <linux/module.h>	
#include <linux/cdev.h>		/* cdev_init cdev_add cdev_del */
#include <linux/fs.h>		/* file operations */
#include <linux/slab.h>		/* kmalloc kfree */
#include <linux/wait.h>		/* wait event */
#include <linux/sched.h>	/* wait event */

MODULE_LICENSE("Dual BSD/GPL");


typedef struct __S_JDRV
{
	wait_queue_head_t wq;
	ssize_t bufsz;
} S_JDRV;

static int drv_open(struct inode *i, struct file *filp)
{
	S_JDRV *jd;
	printk(KERN_INFO "%s\n",__FUNCTION__);
	filp->private_data = kmalloc(sizeof(S_JDRV),GFP_KERNEL);
	if(filp->private_data == NULL)
	{

		return -ENOMEM;
	}
	jd = (S_JDRV *)filp->private_data;
	init_waitqueue_head(&jd->wq);
	jd->bufsz = 0;
	return 0;
}

static int drv_close(struct inode *i, struct file *filp)
{
	printk(KERN_INFO "%s\n",__FUNCTION__);
	kfree(filp->private_data);
	return 0;
}

static ssize_t drv_read(struct file *filp, char *buf, size_t size, loff_t *f_ops)
{
	int ret;
	S_JDRV *jd = (S_JDRV *)filp->private_data;
	printk(KERN_INFO "%s size %u\n",__FUNCTION__, size);
	ret = wait_event_interruptible(jd->wq, jd->bufsz >= size);
	if (ret == 0)
	{
		jd->bufsz -= size;
	}
	else if (ret == -ERESTARTSYS)
	{
		printk(KERN_INFO "-ERESTARTSYS\n");
		return ret;
	}
	printk(KERN_INFO "ret = %d\n",ret);
	return size;
}

static ssize_t drv_write(struct file *filp, const char *buf, size_t size, loff_t *f_ops)
{
	S_JDRV *jd = (S_JDRV *)filp->private_data;
	printk(KERN_INFO "%s size %u\n",__FUNCTION__, size);
	wake_up_interruptible(&jd->wq);
	jd->bufsz += size;
	printk(KERN_INFO "bufsz %u\n",jd->bufsz);
	return size;
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
	int err, devno;

	printk(KERN_INFO "%s\n",__FUNCTION__);

	chrdev = cdev_alloc();

	devno = MKDEV(JDRV_MAJOR, JDRV_MINOR);
	cdev_init(chrdev, &drv_fops);
	chrdev->owner = THIS_MODULE;
	chrdev->ops = &drv_fops;
	err = cdev_add(chrdev, devno, 1);

	if (err)
	{
		printk(KERN_INFO "%s Fail to add cdev\n",__FUNCTION__);
	}

	return 0;
}

static void exit_drv(void)
{
	printk(KERN_INFO "%s\n",__FUNCTION__);
	cdev_del(chrdev);
}

module_init(init_drv);
module_exit(exit_drv);
