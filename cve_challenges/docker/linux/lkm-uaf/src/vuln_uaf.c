#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>

#define DEVICE_NAME "vuln_uaf"
#define CLASS_NAME "vuln_uaf"

static struct class *vuln_class;
static struct cdev vuln_cdev;
static dev_t vuln_dev;

// Vulnerable data structure
struct vuln_data {
    char buffer[256];
    void (*callback)(void);
};

static struct vuln_data *global_data = NULL;

// Intentionally vulnerable: use-after-free in release
static int vuln_open(struct inode *inode, struct file *file) {
    global_data = kmalloc(sizeof(struct vuln_data), GFP_KERNEL);
    if (!global_data) return -ENOMEM;
    memset(global_data, 0, sizeof(struct vuln_data));
    file->private_data = global_data;
    return 0;
}

// Intentionally vulnerable: frees data but doesn't NULL the pointer
static int vuln_release(struct inode *inode, struct file *file) {
    if (file->private_data) {
        kfree(file->private_data);
        // BUG: file->private_data is NOT set to NULL after free (UAF)
        // BUG: global_data is NOT set to NULL after free (UAF)
    }
    return 0;
}

// Read handler - reads the buffer content
static ssize_t vuln_read(struct file *file, char __user *buf, size_t len, loff_t *off) {
    struct vuln_data *data = (struct vuln_data *)file->private_data;
    if (!data) return -EINVAL;
    if (len > 256) len = 256;
    if (copy_to_user(buf, data->buffer, len)) return -EFAULT;
    return len;
}

// Write handler - writes to buffer, also writes flag address for exploitation demo
static ssize_t vuln_write(struct file *file, const char __user *buf, size_t len, loff_t *off) {
    struct vuln_data *data = (struct vuln_data *)file->private_data;
    if (!data) return -EINVAL;
    if (len > 256) len = 256;
    if (copy_from_user(data->buffer, buf, len)) return -EFAULT;
    return len;
}

static struct file_operations vuln_fops = {
    .owner = THIS_MODULE,
    .open = vuln_open,
    .release = vuln_release,
    .read = vuln_read,
    .write = vuln_write,
};

static int __init vuln_init(void) {
    if (alloc_chrdev_region(&vuln_dev, 0, 1, DEVICE_NAME) < 0) return -1;
    vuln_class = class_create(CLASS_NAME);
    device_create(vuln_class, NULL, vuln_dev, NULL, DEVICE_NAME);
    cdev_init(&vuln_cdev, &vuln_fops);
    cdev_add(&vuln_cdev, vuln_dev, 1);
    printk(KERN_INFO "vuln_uaf: Loaded (vulnerable: UAF in release)\n");
    return 0;
}

static void __exit vuln_exit(void) {
    device_destroy(vuln_class, vuln_dev);
    class_destroy(vuln_class);
    cdev_del(&vuln_cdev);
    unregister_chrdev_region(vuln_dev, 1);
    printk(KERN_INFO "vuln_uaf: Unloaded\n");
}

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Intentionally vulnerable kernel module with UAF");
