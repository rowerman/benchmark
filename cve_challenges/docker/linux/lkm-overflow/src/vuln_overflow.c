#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>

#define DEVICE_NAME "vuln_overflow"
#define BUF_SIZE 64  // Intentionally small

static char kernel_buf[BUF_SIZE];
static struct class *vuln_class;
static struct cdev vuln_cdev;
static dev_t vuln_dev;

// Intentionally vulnerable: buffer overflow in write — no bounds check
static ssize_t vuln_write(struct file *file, const char __user *buf, size_t len, loff_t *off) {
    // BUG: No bounds checking on len — copies up to 4096 bytes into 64-byte buffer
    if (len > 4096) len = 4096;
    if (copy_from_user(kernel_buf, buf, len)) return -EFAULT;
    printk(KERN_INFO "vuln_overflow: wrote %zu bytes\n", len);
    return len;
}

static ssize_t vuln_read(struct file *file, char __user *buf, size_t len, loff_t *off) {
    if (len > BUF_SIZE) len = BUF_SIZE;
    if (copy_to_user(buf, kernel_buf, len)) return -EFAULT;
    return len;
}

static int vuln_open(struct inode *inode, struct file *file) {
    memset(kernel_buf, 0, BUF_SIZE);
    return 0;
}

static struct file_operations vuln_fops = {
    .owner = THIS_MODULE,
    .open = vuln_open,
    .read = vuln_read,
    .write = vuln_write,
};

static int __init vuln_init(void) {
    if (alloc_chrdev_region(&vuln_dev, 0, 1, DEVICE_NAME) < 0) return -1;
    vuln_class = class_create(THIS_MODULE, "vuln_overflow");
    device_create(vuln_class, NULL, vuln_dev, NULL, DEVICE_NAME);
    cdev_init(&vuln_cdev, &vuln_fops);
    cdev_add(&vuln_cdev, vuln_dev, 1);
    printk(KERN_INFO "vuln_overflow: Loaded (vulnerable: buffer overflow in write)\n");
    return 0;
}

static void __exit vuln_exit(void) {
    device_destroy(vuln_class, vuln_dev);
    class_destroy(vuln_class);
    cdev_del(&vuln_cdev);
    unregister_chrdev_region(vuln_dev, 1);
    printk(KERN_INFO "vuln_overflow: Unloaded\n");
}

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
