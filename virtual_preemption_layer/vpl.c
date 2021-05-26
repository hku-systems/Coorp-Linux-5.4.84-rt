#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/semaphore.h>
#include<linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "../linux-5.4.84-rt/include/net/vpl.h"

// Load symbols for your driver.
#include "../linux-5.4.84-rt/drivers/net/wireless/mediatek/mt76/mt76.h"

// Length of sample queues for each EDCA category.
#define VPL_TIME_QUEUE_LENGTH 500

int prediction_transmission_accuracy_percent = 98;

extern struct ieee80211_hw* vpl_hw;

// Get your WNIC dev structure pointer
extern struct mt76_dev *vpl_mt76;
int vpl_control[IEEE80211_NUM_ACS];

//-------------------binary sort tree--------------------------------
typedef struct Node
{
	s64 t;
    int count;
	struct Node *lchild;
	struct Node *rchild;

	struct Node *lparent;
	struct Node *rparent;
}NODE,*BSTree;

int search_BSTree(BSTree pTree, s64 t, BSTree parent, BSTree *p)
{
	if(!pTree)
	{	
		*p = parent;
		return 0;
	}
	else
	{
		if(t == pTree->t)
		{
			*p = pTree;
			return 1;
		}
		else if(t < pTree->t)
			return search_BSTree(pTree->lchild, t, pTree, p);    
		else
			return search_BSTree(pTree->rchild, t, pTree, p);
    }
}

BSTree BST_insert(BSTree *pTree, s64 t)
{
	BSTree p;
	if(!search_BSTree(*pTree, t, NULL, &p))
	{
		BSTree pNew = (BSTree)kmalloc(sizeof(NODE), GFP_KERNEL);
		pNew->t = t;
		pNew->count = 1;
		pNew->lchild = pNew->rchild = NULL;
		pNew->lparent = pNew->rparent = NULL;
 
		if(!p)
		{
			*pTree = pNew;
		}
		else if(t < p->t)
		{
			p->lchild = pNew;
			pNew->rparent = p; 
		}
		else
		{
			p->rchild = pNew;
			pNew->lparent = p;
		}
		return pNew;
	}
	else
	{
		p->count++;
		return p;
	}
}


void delete_Node1(BSTree *p)
{ 
	BSTree q,s;
    if ((*p)->count > 1)
    {
        (*p)->count--;
    }
	if(!(*p)->lchild)	
	{
		q = (*p);
		(*p) = (*p)->rchild ;
		kfree(q);
	}
	else if(!(*p)->rchild)
	{
		q = (*p);
		(*p) = (*p)->lchild;
		kfree(q);
	}
	else
	{
		s = (*p)->lchild;
 
		while(s->rchild)
			s = s->rchild;
		s->rchild = (*p)->rchild;
		q = (*p);
		(*p) = (*p)->lchild;
		kfree(q);
	}
}

bool delete_BSTree(BSTree *pTree,int t)
{
	if(!*pTree)
		return false;
	else
	{	
		if(t == (*pTree)->t)
		{
			delete_Node1(pTree);
			return true;		
		}
		else if(t < (*pTree)->t)
			return delete_BSTree(&(*pTree)->lchild, t);
		else
			return delete_BSTree(&(*pTree)->rchild, t);
	}
}

BSTree create_BSTree(s64 *arr,int len)
{
	BSTree pTree = NULL;
	int i;
	for(i=0;i<len;i++)
		BST_insert(&pTree, arr[i]);
	return pTree;	
}

int descent_traverse_find(BSTree pTree, int *len, s64 *t)
{
	if (*len < 0)
		return 1;
	if(pTree)
	{
		if(pTree->rchild)
			if (descent_traverse_find(pTree->rchild, len, t))
				return 1;

		*len -= pTree->count;

		if (*len <= 0)
		{
			*t = pTree->t;
			return 1;
		}
		if(pTree->lchild)
			if (descent_traverse_find(pTree->lchild, len, t))
				return 1;	
	}
	return 0;
}

void destroy_BSTree(BSTree pTree)
{
	if(pTree)
	{
		if(pTree->lchild)
			destroy_BSTree(pTree->lchild);
		if(pTree->rchild)
			destroy_BSTree(pTree->rchild);
		kfree(pTree);
		pTree = NULL;
	}
}

//------------------maintain completion time table-----------------------------

time64_t protection_start = -1;
bool protection_flag = false;

// EDCA categories: 0 -> latency sensitive; 2 -> bandwidth hungry
int prioritized_qid = 0, nonprioritized_qid = 2;

// Sorted queue flushing time records to maintain the latest records
struct ac_queued_vs_flush_time
{
    time64_t time_in_sorted_ac[VPL_TIME_QUEUE_LENGTH];
    int head;
    int tail;
    int queued;
};

// Original queue flushing time records in a binary sort tree
struct queued_vs_flush_time
{
    struct ac_queued_vs_flush_time ac[IEEE80211_NUM_ACS][MT_NUM_TX_ENTRIES];
    BSTree sorted_ac[IEEE80211_NUM_ACS][MT_NUM_TX_ENTRIES];

    time64_t expected_transmission_time[IEEE80211_NUM_ACS][MT_NUM_TX_ENTRIES];

    void (*enqueue)(struct queued_vs_flush_time *q, time64_t t, int qid, int num_queued);

    time64_t (*find_n_percent)(struct queued_vs_flush_time *q, int qid, int n, int num_queued);

    time64_t (*get_expected_transmission_time)(struct queued_vs_flush_time *q, int qid, int num_queued);

};

struct queued_vs_flush_time vpl_queue;

time64_t find_n_percent(struct queued_vs_flush_time *q, int qid, int n, int num_queued)
{
    int descent_distance;
    time64_t result;  //ns

    struct ac_queued_vs_flush_time acq;
    BSTree sorted_acq;

    if (q->ac[qid][num_queued].queued < VPL_TIME_QUEUE_LENGTH / 2)
    {
        result = (int)30e6 / 256 * num_queued;
        return result;
    }


    sorted_acq = q->sorted_ac[qid][num_queued];
    acq = q->ac[qid][num_queued];

    descent_distance = (100 - n) * acq.queued / 100;

    descent_traverse_find(sorted_acq, &descent_distance, &result);

    return result;
}


void enqueue_spent_time(struct queued_vs_flush_time *q, time64_t t, int qid, int num_queued)
{
    struct ac_queued_vs_flush_time *acq;
    BSTree new, *sorted_acq;

    if (qid > 4 || qid < 0)
    {
        return;
    }

    acq = &q->ac[qid][num_queued];
    sorted_acq = &q->sorted_ac[qid][num_queued];


    new = BST_insert(sorted_acq, t);
    acq->queued++;

    if ((acq->head + 1) % VPL_TIME_QUEUE_LENGTH == acq->tail)
    {
        delete_BSTree(sorted_acq, acq->time_in_sorted_ac[acq->tail]);
        acq->queued--;
        acq->tail = (acq->tail + 1) % VPL_TIME_QUEUE_LENGTH;
    }

    acq->time_in_sorted_ac[acq->head] = t;
    acq->head = (acq->head + 1) % VPL_TIME_QUEUE_LENGTH;

    q->expected_transmission_time[qid][num_queued] = find_n_percent(q, qid, prediction_transmission_accuracy_percent, num_queued);
}

time64_t get_expected_transmission_time(struct queued_vs_flush_time *q, int qid, int num_queued)
{ 
    if (q->ac[qid][num_queued].queued < VPL_TIME_QUEUE_LENGTH / 2)
        return (int)30e6 / 256 * num_queued;
    else if (num_queued == 0)
	    return 0;
    // a trick to avoid dead upperbound
    else
        return q->expected_transmission_time[qid][num_queued-1];
}

void vpl_queue_init(struct queued_vs_flush_time *q)
{
    //Initialize vpl queue and its functions
    memset(q, 0, sizeof(struct queued_vs_flush_time));
    q->enqueue = enqueue_spent_time;
    q->find_n_percent = find_n_percent;
    q->get_expected_transmission_time = get_expected_transmission_time;
}

//------------------wrape mt76 ops---------------------------------------
const struct mt76_queue_ops *saved_queue_ops;
struct mt76_queue_ops wrapped_queue_ops;
const struct mt76_driver_ops *saved_driver_ops;
struct mt76_driver_ops wrapped_driver_ops;

struct sk_buff *(*saved_mt76_txq_dequeue)(struct mt76_dev *, struct mt76_txq *, bool);

struct sk_buff *last_skb = NULL;

struct sk_buff *wrapped_mt76_txq_dequeue(struct mt76_dev *dev, struct mt76_txq *mtxq, bool ps)
{

	struct ieee80211_txq *txq = mtxq_to_txq(mtxq);
	enum mt76_txq_id qid;
    struct sk_buff *ret;
    time64_t time_remaining, now, expected;
    if (!txq->sta)
		qid = MT_TXQ_BE;
	else 
        qid = txq->ac;
    //If queue 1 called tx complete skb, its queued number will be reduced right after. 
    //so for queue 2 the update of queue 1's queued number is timely. 
    if (qid == nonprioritized_qid && protection_flag == true)
    {
        if (dev->q_tx[prioritized_qid].q->queued > 0)
        {
            // printk(KERN_INFO "VPL: queue %d is not empty, stop queue %d\n", prioritized_qid, qid);
            ieee80211_stop_queue(vpl_hw, qid);
            return NULL;
        }
        else
        {
            now = ktime_get();
            time_remaining = protection_start - now;
            if (time_remaining >= 0)
            {   
                expected = vpl_queue.get_expected_transmission_time(
                    &vpl_queue, qid, dev->q_tx[qid].q->queued);
                if (expected >= time_remaining)
                {
                    // printk(KERN_INFO "VPL: now %lld time_remain %lld expected %lld Stop queue %d before %lld\n", now, time_remaining, expected, qid, protection_start);
                    ieee80211_stop_queue((struct ieee80211_hw*)vpl_hw, qid);
                    return NULL;
                }
            }
            // equal to if(time_remaining < 0), this happens when a protection is set and not
            // renewprotection is called, which means this protection is not ended
            else
            {
                // printk(KERN_INFO "VPL: now %lld stopping queue %d when it's already after %lld\n", now, qid, protection_start);
                ieee80211_stop_queue((struct ieee80211_hw*)vpl_hw, qid);
                return NULL;
            }
        }
    }
    //true mt76 dequeue
    ret = saved_mt76_txq_dequeue(dev, mtxq, ps);

    //if dequeue fails, last valid skb is the end
    // TODO
    if (qid == prioritized_qid){
        if (!ret && last_skb)
            last_skb->vpl_end = true;
        last_skb = ret;
    }
    return ret;
}

void wrapped_tx_complete_skb(struct mt76_dev *dev, enum mt76_txq_id qid,
				struct mt76_queue_entry *e)
{
    u64 time_spent = ktime_get() - e->skb->vpl_time_stamp;
    int previous_queued = e->skb->mt76_txq_queued;


    u64 max_ct_ns = 96614*previous_queued+1564387+10000000;
    time_spent = min(time_spent, max_ct_ns);
    vpl_queue.enqueue(&vpl_queue, time_spent, qid, previous_queued);

    //wake queue 2 upon queue 0's ending when it's outside protection time
    if (qid == prioritized_qid && e->skb->vpl_end == true && protection_flag == false)
    {
        ieee80211_wake_queue(vpl_hw, nonprioritized_qid);
        // make queue 2 starts functioning right after waking 
        tasklet_schedule(&vpl_mt76->tx_tasklet);
    }

    // true tx_complete_skb
    saved_driver_ops->tx_complete_skb(dev, qid, e);
}

int wrapped_tx_queue_skb(struct mt76_dev *dev, enum mt76_txq_id qid,
			    struct sk_buff *skb, struct mt76_wcid *wcid,
			    struct ieee80211_sta *sta)
{
    struct mt76_queue *q = dev->q_tx[qid].q;

    skb->mt76_txq_queued = q->queued;
    skb->vpl_time_stamp = ktime_get();
    skb->vpl_end = false;
    if (qid == prioritized_qid)
    {
        printk(KERN_INFO "queue_manager: queued in queue 0 %d queue 2 %d time %lld\n", q->queued, dev->q_tx[nonprioritized_qid].q->queued, ktime_get());
    }
    // true tx_queue_skb
    return saved_queue_ops->tx_queue_skb(dev, qid, skb, wcid, sta);
}

int wrapped_tx_queue_skb_raw(struct mt76_dev *dev, enum mt76_txq_id qid,
				struct sk_buff *skb, u32 tx_info)
{
    struct mt76_queue *q = dev->q_tx[qid].q;

    skb->mt76_txq_queued = q->queued;
    skb->vpl_time_stamp = ktime_get();
    skb->vpl_end = false;
    if (qid == prioritized_qid)
    {
        printk(KERN_INFO "queue_manager: queued in queue 1 %d queue 2 %d\n", q->queued, dev->q_tx[nonprioritized_qid].q->queued);
    }

    // true tx_queue_skb_raw
    return saved_queue_ops->tx_queue_skb_raw(dev, qid, skb, tx_info);
}

//------------------------vpl device with ioctl interface---------------------------------
#define IOC_MAGIC 'v'
#define IOCTL_SYNC _IOR(IOC_MAGIC,1, struct flow_tsf *) 
#define IOCTL_SETVPL _IOW(IOC_MAGIC, 2, int *)
#define VPL_STARTPROTECT _IOW(IOC_MAGIC, 3, time64_t *)
#define VPL_RENEWPROTECT _IOW(IOC_MAGIC, 4, time64_t *)
#define VPL_ENDPROTECT _IO(IOC_MAGIC, 5)


char message_buff[20000];

int open(struct inode *inode, struct file *filp)
{
    return 0;
}

// Read sample records
ssize_t read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
    int char_num = 0, j;
    if (*offset == 0)
    {
        memset(message_buff, 0, 20000 * sizeof(char));
        char_num = sprintf(message_buff, "Kernel time %lld\n", ktime_get());

        char_num += sprintf(message_buff + char_num, "AC: %d\n", 2);
        for (j = 0; j < MT_NUM_TX_ENTRIES; j++)
        {
            if (vpl_queue.ac[2][j].queued > 0)
                char_num += sprintf(message_buff + char_num, "num_q: %d, num_r: %d, 95: %lld, use: %lld\n", j, 
                    vpl_queue.ac[2][j].queued,
		    find_n_percent(&vpl_queue, 2, 95, j),
		    vpl_queue.expected_transmission_time[2][j]);
        }
    }

    if (*offset> 20000) 
    {
        return 0; // Returning 0 signs the end of message
    }
    if ((*offset + len) > 20000)
    {
        len = 20000 - *offset;
    }

    copy_to_user(buffer, message_buff + *offset, len);
    *offset = *offset + len;
    return len;
}

int release(struct inode *inode, struct file *filp) {
    return 0;
}

static long ioctl_funcs(struct file *filp,unsigned int cmd, unsigned long arg)
{
    int i;
    int temp[IEEE80211_NUM_ACS];

    switch(cmd) {
        case IOCTL_SYNC:
            printk(KERN_INFO "VPL: TSF is deprecated, no effect\n");
            break;
        case IOCTL_SETVPL:
            if((char *)arg == NULL)
            {
                printk(KERN_INFO "VPL: VPL value incorrect\n");
                return -EFAULT;
            }
            if(!vpl_hw)
            {
                printk(KERN_DEBUG "VPL: Unable to access vpl hw\n");
                return -EFAULT;
            }
            copy_from_user(temp, (int *)arg, IEEE80211_NUM_ACS * sizeof(int));
            for (i = 0; i < IEEE80211_NUM_ACS; i++)
            {
                if (temp[i] <= 0 && vpl_control[i] > 0)
                {
                    ieee80211_stop_queue((struct ieee80211_hw*)vpl_hw, i);
                }
                if (temp[i] > 0)
                {
                    ieee80211_wake_queue((struct ieee80211_hw*)vpl_hw, i);
                    // make queue 2 starts functioning right after waking 
                    tasklet_schedule(&vpl_mt76->tx_tasklet);
                }
            }
            copy_from_user(vpl_control, (int *)arg, IEEE80211_NUM_ACS * sizeof(int));
            break;
        case VPL_STARTPROTECT:
            // default make queue 2 under contorl by plan
            protection_flag = true;
            copy_from_user(&protection_start, (time64_t *)arg, sizeof(time64_t));
            printk(KERN_INFO "VPL: protection starts from %lld\n", protection_start);
            break;
        case VPL_RENEWPROTECT:
            protection_flag = true;
            copy_from_user(&protection_start, (time64_t *)arg, sizeof(time64_t));
            printk(KERN_INFO "VPL: end last protection and start new at %lld\n", protection_start);
            ieee80211_wake_queue((struct ieee80211_hw*)vpl_hw, 2);
            tasklet_schedule(&vpl_mt76->tx_tasklet);
            break;
        case VPL_ENDPROTECT:
            protection_flag = false;
            // make queue 2 starts functioning right after waking 
            ieee80211_wake_queue((struct ieee80211_hw*)vpl_hw, 2);
            tasklet_schedule(&vpl_mt76->tx_tasklet);
            break;
        default:
            return -EFAULT;                                                                        
    } 
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = open,
    .read = read,

    .unlocked_ioctl = ioctl_funcs,
    .compat_ioctl = ioctl_funcs,
    .release = release
};

static struct miscdevice flow_vpl = {
    .minor = MISC_DYNAMIC_MINOR,
    .name   = "flow_vpl",
    .fops   = &fops,
    .mode   = 0666
};


static int __init flow_vpl_init(void) {
    int error;
    printk(KERN_INFO "VPL: VPL device init\n");
    error = misc_register(&flow_vpl);
    if (error)
    {
        printk(KERN_ERR "VPL: failed to create flow_vpl\n");
        return -EINVAL;
    }

    if (!vpl_mt76)
    {
        printk(KERN_DEBUG "VPL: failed to connect mt76\n");
        return -EINVAL;
    }
    printk(KERN_INFO "VPL: IOCTL_SYNC %lu\n", IOCTL_SYNC);
    printk(KERN_INFO "VPL: IOCTL_SETVPL %lu\n", IOCTL_SETVPL);
    printk(KERN_INFO "VPL: VPL_STARTPROTECT %lu\n", VPL_STARTPROTECT);
    printk(KERN_INFO "VPL: VPL_RENEWPROTEC %lu\n", VPL_RENEWPROTECT);
    printk(KERN_INFO "VPL: VPL_ENDPROTECT %u\n", VPL_ENDPROTECT);

    memset(vpl_control, 1, sizeof(int) * IEEE80211_NUM_ACS);

    vpl_queue_init(&vpl_queue);

    //Wrap tx queue and tx complete with our own function
    saved_queue_ops = vpl_mt76->queue_ops;
    saved_driver_ops = vpl_mt76->drv;
    saved_mt76_txq_dequeue = vpl_mt76->mt76_txq_dequeue;

    memcpy(&wrapped_queue_ops, saved_queue_ops, sizeof(struct mt76_queue_ops));
    memcpy(&wrapped_driver_ops, saved_driver_ops, sizeof(struct mt76_driver_ops));
    
    wrapped_queue_ops.tx_queue_skb = wrapped_tx_queue_skb;
    wrapped_driver_ops.tx_complete_skb = wrapped_tx_complete_skb;

    vpl_mt76->queue_ops = &wrapped_queue_ops;
    vpl_mt76->drv = &wrapped_driver_ops;
    vpl_mt76->mt76_txq_dequeue = wrapped_mt76_txq_dequeue;


    return 0;
}

static void __exit flow_vpl_exit(void) {
    int i, j;

    printk(KERN_INFO "VPL: Flow vpl device exit\n");

    vpl_mt76->queue_ops = saved_queue_ops;
    vpl_mt76->drv = saved_driver_ops;
    vpl_mt76->mt76_txq_dequeue = saved_mt76_txq_dequeue;

    for (i = 0; i < IEEE80211_NUM_ACS; i++)
        for (j = 0; j < MT_NUM_TX_ENTRIES; j++)
        {
            if (vpl_queue.sorted_ac[i][j])
                destroy_BSTree(vpl_queue.sorted_ac[i][j]);
        }

    misc_deregister(&flow_vpl);
}

MODULE_LICENSE("GPL"); 
module_init(flow_vpl_init);
module_exit(flow_vpl_exit);
