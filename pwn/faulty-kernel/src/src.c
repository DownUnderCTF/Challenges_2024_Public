#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string.h>

#define DEV_NAME "challenge"
#define FAIL (-1)
#define SUCCESS (0)

#define PAGECOUNT (128)

MODULE_AUTHOR("toasterpwn");
MODULE_DESCRIPTION("pwn me :)");
MODULE_LICENSE("GPL");

struct shared_buffer {
	pgoff_t pagecount;
	struct page** pages;
};

static struct miscdevice dev;

static int dev_mmap(struct file* filp, struct vm_area_struct* vma);
static vm_fault_t dev_vma_fault(struct vm_fault *vmf);
static int dev_open(struct inode* inodep, struct file* filp);

static struct file_operations dev_fops = {
	.owner = THIS_MODULE,
	.open = dev_open,
	.mmap = dev_mmap
};

static struct vm_operations_struct dev_vm_ops = {
	.fault = dev_vma_fault
};

static int dev_mmap(struct file* filp, struct vm_area_struct* vma) {
	struct shared_buffer* sbuf = filp->private_data;
	pgoff_t pages = vma_pages(vma);
	if (pages > sbuf->pagecount) {
		return -EINVAL;
	}

	vma->vm_ops = &dev_vm_ops;
    	vma->vm_private_data = sbuf;

	return SUCCESS;
}

static vm_fault_t dev_vma_fault(struct vm_fault *vmf) {
	struct vm_area_struct *vma = vmf->vma;
	struct shared_buffer *sbuf = vma->vm_private_data;

	pgoff_t pgoff = vmf->pgoff;

    	if (pgoff > sbuf->pagecount) {
        	return VM_FAULT_SIGBUS;
    	}

	get_page(sbuf->pages[pgoff]);
	vmf->page = sbuf->pages[pgoff];

	return SUCCESS;
}

static int dev_open(struct inode* inodep, struct file* filp) { 
	int i;
	struct shared_buffer* sbuf;

	sbuf = kzalloc(sizeof(*sbuf), GFP_KERNEL);
	if (!sbuf) {
		printk(KERN_INFO "[dev] Failed to initilise buffer.\n");
		goto fail;
	}

	sbuf->pagecount = PAGECOUNT;
	sbuf->pages = kmalloc_array(sbuf->pagecount, sizeof(*sbuf->pages), GFP_KERNEL);
	if (!sbuf->pages) {
		printk(KERN_INFO "[dev] Failed to initilise buffer.\n");
		goto fail_alloc_buf;
	}

	for (i = 0; i < sbuf->pagecount; i++) {
		sbuf->pages[i] = alloc_page(GFP_KERNEL);
		if (!sbuf->pages[i]) {
			printk(KERN_ERR "[dev] Failed to allocate page %d.\n", i);
			goto fail_alloc_pages;
		}
	}

	filp->private_data = sbuf;
	return SUCCESS;

fail_alloc_pages:
	while (i--) {
		if (sbuf->pages[i]) {
			__free_page(sbuf->pages[i]);
		}
	}

	kfree(sbuf->pages);
fail_alloc_buf:
	kfree(sbuf);
fail:
	return FAIL;
}

static int dev_init(void) {
	dev.minor = MISC_DYNAMIC_MINOR;
    	dev.name = DEV_NAME;
    	dev.fops = &dev_fops;
    	dev.mode = 0644;

	if (misc_register(&dev)) {
        	return FAIL;
    	}


	printk(KERN_INFO "[dev] It's mappin' time!\n");
	
	return SUCCESS;
}

static void dev_cleanup(void) {
	misc_deregister(&dev);

	printk(KERN_INFO "[dev] Shutting down.\n");
}


module_init(dev_init);
module_exit(dev_cleanup);
