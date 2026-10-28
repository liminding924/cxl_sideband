/*************************************************************************
@File Name: mctp_bridge.c
@Desc: MCTP Bridge Kernel Module
@Author: Andy-wei.hou
@Mail: wei.hou@scaleflux.com
@Created Time: 2025-11-19 18:39:43
@Log: Fixed for Linux kernel 6.14+
      2026-10-28 multiple instances (nr_devs), one TX queue per instance
************************************************************************/
// mctp_bridge.c – Fixed for Linux kernel 6.14+
// Changes:
// 1. Added #include <linux/skbuff.h>
// 2. Removed dev->tx_queue usage
// 3. Correctly use struct sk_buff_head
// 4. Clean minimal bridge prototype
// 5. nr_devs instances, each with its own netdev, char device and TX queue,
//    so daemons serving different EIDs never take each other's frames
// 6. No sleeping lock in ndo_start_xmit; char device is single-open

#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/if_arp.h>
#include <net/mctp.h>

#include <linux/version.h>

/*
 * Kernel 6.4 removed class_create(THIS_MODULE, name),
 * replacing it with class_create(name).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
#define CLASS_CREATE(name) class_create(name)
#else
#define CLASS_CREATE(name) class_create(THIS_MODULE, name)
#endif


#define CHAR_DEV_BUF_MAX (64 * 1024)
#define MCTP_DEFAULT_EID 8  /* Default MCTP Endpoint ID */
#define MCTP_MTU 1024       /* MCTP Maximum Transmission Unit */
#define MBRIDGE_MAX_DEVS 8
#define MBRIDGE_TXQ_MAX 256 /* frames held for the daemon before dropping */

/*
 * One instance = one MCTP netdev + one char device + its own TX queue.
 * Route each remote EID to its own netdev (mctp route add <eid> via
 * mctp_bridgeN) and run one bridge daemon per char device.
 *
 * Index 0 keeps the original names: mctp_bridge0 and /dev/mctp_bridge.
 * Index N > 0 is mctp_bridgeN and /dev/mctp_bridgeN.
 */
static unsigned int nr_devs = 1;
module_param(nr_devs, uint, 0444);
MODULE_PARM_DESC(nr_devs, "Number of bridge instances (1-8, default 1)");

static unsigned int first_index;
module_param(first_index, uint, 0444);
MODULE_PARM_DESC(first_index, "Index of the first instance (default 0)");

static bool exclusive = true;
module_param(exclusive, bool, 0444);
MODULE_PARM_DESC(exclusive, "One opener per char device (default Y)");

struct mbridge {
    struct net_device *ndev;
    struct cdev cdev;
    dev_t devt;
    struct sk_buff_head tx_to_daemon;
    wait_queue_head_t tx_wq;
    atomic_t open_count;
};

static struct mbridge *mbridges[MBRIDGE_MAX_DEVS];
static dev_t mbridge_devnum;
static struct class *mbridge_class;

/* netdev ops */
static netdev_tx_t mbridge_start_xmit(struct sk_buff *skb, struct net_device *dev);
static int mbridge_open(struct net_device *dev);
static int mbridge_stop(struct net_device *dev);

static const struct net_device_ops mbridge_netdev_ops = {
    .ndo_open       = mbridge_open,
    .ndo_stop       = mbridge_stop,
    .ndo_start_xmit = mbridge_start_xmit,
};

static int mbridge_open(struct net_device *dev)
{
    netif_start_queue(dev);
    netif_carrier_on(dev);
    pr_info("%s: opened\n", dev->name);
    return 0;
}

static int mbridge_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    netif_carrier_off(dev);
    pr_info("%s: stopped\n", dev->name);
    return 0;
}

/*
 * Runs with BH disabled and must not sleep. sk_buff_head has its own
 * spinlock, so skb_queue_tail/skb_dequeue need no extra lock.
 */
static netdev_tx_t mbridge_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct mbridge *mb = *(struct mbridge **)netdev_priv(dev);

    /* No daemon reading: drop instead of growing without bound. */
    if (skb_queue_len(&mb->tx_to_daemon) >= MBRIDGE_TXQ_MAX) {
        dev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    /* Print SKB key information and first 5 bytes */
    dev_dbg(&dev->dev, "%s SKB info: len=%u, protocol=0x%04x, data=%*ph\n",
            __func__, skb->len, ntohs(skb->protocol), 5, skb->data);

    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;

    /* Queue for the char device reader */
    skb_orphan(skb);
    skb_queue_tail(&mb->tx_to_daemon, skb);
    wake_up_interruptible(&mb->tx_wq);

    return NETDEV_TX_OK;
}

/* char device open/release/read/write */
static int mbridge_chr_open(struct inode *inode, struct file *file)
{
    struct mbridge *mb = container_of(inode->i_cdev, struct mbridge, cdev);

    if (exclusive && atomic_inc_return(&mb->open_count) > 1) {
        atomic_dec(&mb->open_count);
        pr_warn("%s: char device busy, open by pid %d (%s) refused\n",
                mb->ndev->name, task_pid_nr(current), current->comm);
        return -EBUSY;
    }

    file->private_data = mb;
    return nonseekable_open(inode, file);
}

static int mbridge_chr_release(struct inode *inode, struct file *file)
{
    struct mbridge *mb = file->private_data;

    if (exclusive)
        atomic_dec(&mb->open_count);
    return 0;
}

static ssize_t mbridge_chr_read(struct file *file, char __user *buf,
                                size_t count, loff_t *ppos)
{
    struct mbridge *mb = file->private_data;
    struct sk_buff *skb;
    size_t to_copy;
    int ret;

    if (count == 0)
        return 0;

    /* Another reader (exclusive=N) may win the frame: wait again. */
    while (!(skb = skb_dequeue(&mb->tx_to_daemon))) {
        if (file->f_flags & O_NONBLOCK)
            return -EAGAIN;

        ret = wait_event_interruptible(mb->tx_wq,
                !skb_queue_empty(&mb->tx_to_daemon));
        if (ret)
            return ret;
    }

    /* Print SKB key information and first 5 bytes */
    dev_dbg(&mb->ndev->dev, "%s SKB info: len=%u, protocol=0x%04x, data=%*ph\n",
            __func__, skb->len, ntohs(skb->protocol), 5, skb->data);

    to_copy = min(count, (size_t)skb->len);

    if (copy_to_user(buf, skb->data, to_copy)) {
        kfree_skb(skb);
        return -EFAULT;
    }

    kfree_skb(skb);
    return to_copy;
}

static ssize_t mbridge_chr_write(struct file *file, const char __user *buf,
                                 size_t count, loff_t *ppos)
{
    struct mbridge *mb = file->private_data;
    struct net_device *ndev = mb->ndev;
    struct sk_buff *skb;
    void *data;

    if (count == 0)
        return 0;

    if (count > CHAR_DEV_BUF_MAX)
        return -E2BIG;

    skb = netdev_alloc_skb_ip_align(ndev, count + NET_IP_ALIGN);
    if (!skb)
        return -ENOMEM;

    data = skb_put(skb, count);

    if (copy_from_user(data, buf, count)) {
        kfree_skb(skb);
        return -EFAULT;
    }

    skb->dev = ndev;
    skb->protocol = htons(ETH_P_MCTP);  // Set to MCTP protocol
    /*init magic for mctp cb*/
    __mctp_cb(skb);


    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);

    ndev->stats.rx_packets++;
    ndev->stats.rx_bytes += count;


   /* Print SKB key information and first bytes */
    dev_dbg(&ndev->dev, "%s SKB info: len=%u, protocol=0x%04x, data=%*ph\n",
            __func__, skb->len, ntohs(skb->protocol), (int)count, skb->data);

    /* netif_rx() frees the skb itself when it drops it. */
    if (netif_rx(skb) != NET_RX_SUCCESS) {
        dev_err(&ndev->dev, "Failed to enqueue packet for processing\n");
        return -EIO;
    }

    return count;
}

static __poll_t mbridge_chr_poll(struct file *file, poll_table *wait)
{
    struct mbridge *mb = file->private_data;
    __poll_t mask = 0;

    poll_wait(file, &mb->tx_wq, wait);

    if (!skb_queue_empty(&mb->tx_to_daemon))
        mask |= EPOLLIN | EPOLLRDNORM;

    return mask;
}

static const struct file_operations mbridge_fops = {
    .owner   = THIS_MODULE,
    .open    = mbridge_chr_open,
    .release = mbridge_chr_release,
    .read    = mbridge_chr_read,
    .write   = mbridge_chr_write,
    .poll    = mbridge_chr_poll,
};

// Custom MCTP device setup function
static void mctp_setup(struct net_device *dev)
{
    dev->type = ARPHRD_MCTP;  // Use MCTP device type

    dev->mtu = MCTP_MTU;  // Set MCTP MTU
    dev->hard_header_len = 0;  // MCTP doesn't require hardware header
    dev->addr_len = 0;
    dev->flags = IFF_NOARP;  // MCTP doesn't require ARP

    // Set MCTP-specific parameters
    // Set endpoint ID in device address
    // memset(dev->dev_addr, 0, sizeof(dev->dev_addr));
    // dev->dev_addr[0] = MCTP_DEFAULT_EID;
    //
    dev->netdev_ops = &mbridge_netdev_ops;
}

static void mbridge_destroy(struct mbridge *mb)
{
    device_destroy(mbridge_class, mb->devt);
    cdev_del(&mb->cdev);
    unregister_netdev(mb->ndev);
    free_netdev(mb->ndev);
    skb_queue_purge(&mb->tx_to_daemon);
    kfree(mb);
}

static int mbridge_create(unsigned int slot)
{
    unsigned int index = first_index + slot;
    char ifname[IFNAMSIZ];
    struct device *chr;
    struct mbridge *mb;
    int ret;

    mb = kzalloc(sizeof(*mb), GFP_KERNEL);
    if (!mb)
        return -ENOMEM;

    mb->devt = MKDEV(MAJOR(mbridge_devnum), MINOR(mbridge_devnum) + slot);
    skb_queue_head_init(&mb->tx_to_daemon);
    init_waitqueue_head(&mb->tx_wq);
    atomic_set(&mb->open_count, 0);

    snprintf(ifname, sizeof(ifname), "mctp_bridge%u", index);
    mb->ndev = alloc_netdev(sizeof(struct mbridge *), ifname, NET_NAME_ENUM,
                            mctp_setup);
    if (!mb->ndev) {
        ret = -ENOMEM;
        goto err_free;
    }
    *(struct mbridge **)netdev_priv(mb->ndev) = mb;

    ret = register_netdev(mb->ndev);
    if (ret)
        goto err_free_netdev;

    /* char device for userspace read/write/poll */
    cdev_init(&mb->cdev, &mbridge_fops);
    mb->cdev.owner = THIS_MODULE;
    ret = cdev_add(&mb->cdev, mb->devt, 1);
    if (ret)
        goto err_unregister_netdev;

    if (index == 0)
        chr = device_create(mbridge_class, NULL, mb->devt, NULL, "mctp_bridge");
    else
        chr = device_create(mbridge_class, NULL, mb->devt, NULL,
                            "mctp_bridge%u", index);
    if (IS_ERR(chr)) {
        ret = PTR_ERR(chr);
        goto err_cdev_del;
    }

    mbridges[slot] = mb;
    pr_info("%s: %s <-> /dev/%s\n", KBUILD_MODNAME, ifname, dev_name(chr));
    return 0;

err_cdev_del:
    cdev_del(&mb->cdev);
err_unregister_netdev:
    unregister_netdev(mb->ndev);
err_free_netdev:
    free_netdev(mb->ndev);
err_free:
    kfree(mb);
    return ret;
}

/* init / exit */
static int __init mbridge_init(void)
{
    unsigned int i;
    int ret;

    if (nr_devs < 1 || nr_devs > MBRIDGE_MAX_DEVS) {
        pr_err("%s: nr_devs must be 1..%d\n", KBUILD_MODNAME, MBRIDGE_MAX_DEVS);
        return -EINVAL;
    }

    ret = alloc_chrdev_region(&mbridge_devnum, 0, nr_devs, KBUILD_MODNAME);
    if (ret)
        return ret;

    /* Named after the module, so a renamed build can load alongside. */
    mbridge_class = CLASS_CREATE(KBUILD_MODNAME "_class");
    if (IS_ERR(mbridge_class)) {
        ret = PTR_ERR(mbridge_class);
        pr_err("%s: failed to create class\n", KBUILD_MODNAME);
        goto err_unregister_chrdev;
    }

    for (i = 0; i < nr_devs; i++) {
        ret = mbridge_create(i);
        if (ret) {
            pr_err("%s: instance %u failed: %d\n", KBUILD_MODNAME,
                   first_index + i, ret);
            goto err_destroy;
        }
    }

    pr_info("%s: loaded OK, %u instance(s)\n", KBUILD_MODNAME, nr_devs);
    return 0;

err_destroy:
    while (i--)
        mbridge_destroy(mbridges[i]);
    class_destroy(mbridge_class);
err_unregister_chrdev:
    unregister_chrdev_region(mbridge_devnum, nr_devs);
    return ret;
}

static void __exit mbridge_exit(void)
{
    unsigned int i;

    for (i = 0; i < nr_devs; i++)
        if (mbridges[i])
            mbridge_destroy(mbridges[i]);

    class_destroy(mbridge_class);
    unregister_chrdev_region(mbridge_devnum, nr_devs);

    pr_info("%s: unloaded\n", KBUILD_MODNAME);
}

module_init(mbridge_init);
module_exit(mbridge_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mctp bridge");
MODULE_DESCRIPTION("mctp_bridge netdevs + char devices for BridgeDaemon, one per instance");
