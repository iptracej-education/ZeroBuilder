/*
 * Linux Kernel Race Condition Test Cases
 * Real kernel race vulnerabilities for ZeroBuilder GAT validation
 * Based on actual CVEs and kernel race condition patterns
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/mm.h>

// Simulated kernel structures for testing
struct file_context {
    atomic_t refcount;
    struct mutex lock;
    void *private_data;
    int flags;
    struct list_head list;
};

struct vm_area {
    unsigned long start;
    unsigned long end;
    struct file *file;
    struct mutex mmap_lock;
    atomic_t users;
};

// Global state (realistic for kernel modules)
static struct file_context *global_contexts[1024];
static DEFINE_MUTEX(context_mutex);
static DEFINE_SPINLOCK(vm_lock);
static struct vm_area *active_mappings[256];

/*
 * RACE PATTERN A: Use-After-Free via Reference Counting
 * Based on CVE-2019-19448 - Use-after-free in BTRFS
 */
int kernel_file_release_race(struct file *file) {
    struct file_context *ctx = file->private_data;
    
    // VULNERABLE: Race between refcount check and usage
    // GAT should flag: TOCTOU race in reference counting
    if (atomic_read(&ctx->refcount) > 1) {  // Check
        // ... another thread can decrement refcount here ...
        
        // VULNERABLE: Use without proper refcount protection
        if (ctx->private_data) {  // Use - ctx might be freed!
            kfree(ctx->private_data);
            ctx->private_data = NULL;
        }
        
        atomic_dec(&ctx->refcount);
        return 0;
    }
    
    // VULNERABLE: Double-free race condition
    // GAT should flag: potential double-free
    mutex_lock(&ctx->lock);
    if (ctx->private_data) {  // Check under lock
        kfree(ctx->private_data);
        ctx->private_data = NULL;  // Set to NULL
    }
    mutex_unlock(&ctx->lock);
    
    // VULNERABLE: Another thread can free ctx here
    // GAT should flag: use-after-free potential
    atomic_dec(&ctx->refcount);  // Last reference
    if (atomic_read(&ctx->refcount) == 0) {
        kfree(ctx);  // Free ctx
        // But file->private_data still points to freed memory!
    }
    
    return 0;
}

/*
 * RACE PATTERN B: TOCTOU in Filesystem Operations
 * Based on CVE-2020-29661 - TOCTOU in Linux TTY
 */
int kernel_path_resolution_race(const char __user *pathname, int flags) {
    struct path path;
    struct inode *inode;
    int error;
    
    // VULNERABLE: TOCTOU between path lookup and access
    // GAT should flag: TOCTOU race in filesystem operations
    error = user_path_lookup(pathname, 0, &path);  // Check - resolve path
    if (error)
        return error;
    
    inode = path.dentry->d_inode;
    
    // VULNERABLE: Check permissions without holding locks
    // GAT should flag: race between permission check and use
    if (!inode_permission(inode, MAY_READ)) {  // Check permissions
        path_put(&path);
        return -EACCES;
    }
    
    // ... Time gap where file permissions/ownership can change ...
    // ... or symlink target can be modified ...
    
    // VULNERABLE: Use the file based on stale permission check
    // GAT should flag: stale permission check usage
    if (flags & O_TRUNC) {
        // Truncate file without re-checking permissions
        error = do_truncate(&path, 0, 0, NULL);  // Use - permissions might have changed!
    }
    
    // VULNERABLE: Directory traversal race
    // GAT should flag: directory modification race
    struct dentry *parent = path.dentry->d_parent;
    if (parent && d_unhashed(parent)) {
        // Parent directory was unlinked after path resolution
        // But we're still using the resolved path
        error = vfs_open(&path, NULL, NULL);  // VULNERABLE: use of unlinked path
    }
    
    path_put(&path);
    return error;
}

/*
 * RACE PATTERN C: Memory Mapping Races  
 * Based on CVE-2018-17182 - vmacache race condition
 */
int kernel_mmap_race_condition(unsigned long addr, size_t length, struct file *file) {
    struct vm_area *vma;
    unsigned long flags;
    
    // VULNERABLE: Race in VMA lookup and modification
    // GAT should flag: unsynchronized VMA access
    vma = find_vma_by_addr(addr);  // Lookup without proper locking
    if (!vma) {
        return -ENOMEM;
    }
    
    // VULNERABLE: Race between VMA validation and modification
    // GAT should flag: TOCTOU in memory mapping
    if (vma->start <= addr && addr + length <= vma->end) {  // Check
        // ... Another thread can modify or unmap VMA here ...
        
        // VULNERABLE: Use VMA without revalidation
        if (vma->file != file) {  // Use - VMA might have changed!
            return -EINVAL;
        }
        
        // VULNERABLE: Modify VMA properties without proper locking
        spin_lock_irqsave(&vm_lock, flags);
        vma->start = addr;  // Modify
        vma->end = addr + length;
        spin_unlock_irqrestore(&vm_lock, flags);
        
        // VULNERABLE: Use atomic operations incorrectly
        // GAT should flag: incorrect atomic usage in race
        if (atomic_read(&vma->users) > 0) {  // Non-atomic check
            atomic_inc(&vma->users);  // Increment based on stale check
        }
    }
    
    // VULNERABLE: Memory mapping consistency race
    // GAT should flag: inconsistent memory mapping state
    for (int i = 0; i < 256; i++) {
        if (active_mappings[i] == vma) {
            // Found mapping, but no synchronization
            active_mappings[i]->file = file;  // Update without lock
            break;
        }
    }
    
    return 0;
}

/*
 * RACE PATTERN D: Signal Handling Races
 * Based on CVE-2019-18683 - Signal handling race
 */
int kernel_signal_delivery_race(int sig, struct task_struct *task) {
    struct sigpending *pending;
    struct sigqueue *queue;
    unsigned long flags;
    
    // VULNERABLE: Race in signal pending check and delivery
    // GAT should flag: signal delivery race condition
    pending = &task->pending;
    
    if (sigismember(&pending->signal, sig)) {  // Check if signal pending
        // ... Another thread can deliver/modify signals here ...
        
        // VULNERABLE: Signal queue manipulation without proper locking
        // GAT should flag: unsynchronized signal queue access
        queue = list_first_entry(&pending->list, struct sigqueue, list);
        if (queue && queue->info.si_signo == sig) {  // Use - queue might be freed!
            list_del(&queue->list);
            __sigqueue_free(queue);
        }
    }
    
    // VULNERABLE: Signal mask race condition
    // GAT should flag: signal mask TOCTOU
    spin_lock_irqsave(&task->sighand->siglock, flags);
    
    if (!sigismember(&task->blocked, sig)) {  // Check if signal blocked
        spin_unlock_irqrestore(&task->sighand->siglock, flags);
        
        // ... Signal mask can change here in another thread ...
        
        // VULNERABLE: Deliver signal based on stale mask check
        // GAT should flag: stale signal mask usage
        send_signal(sig, NULL, task, PIDTYPE_PID);  // Use - mask might have changed!
    } else {
        spin_unlock_irqrestore(&task->sighand->siglock, flags);
    }
    
    // VULNERABLE: Signal handler race condition
    // GAT should flag: signal handler modification race
    struct k_sigaction *ka = &task->sighand->action[sig-1];
    if (ka->sa.sa_handler != SIG_DFL) {  // Check handler
        // ... Signal handler can be modified here ...
        
        // VULNERABLE: Call handler without revalidation
        ka->sa.sa_handler(sig);  // Use - handler might have changed!
    }
    
    return 0;
}

/*
 * RACE PATTERN E: Device Driver Reference Counting
 * Based on CVE-2020-12352 - Reference counting in Bluetooth
 */
int kernel_device_reference_race(struct device *dev) {
    struct file_context *ctx;
    int ret = 0;
    
    // VULNERABLE: Device reference counting race
    // GAT should flag: improper device reference management
    if (atomic_read(&dev->refcount) == 0) {
        return -ENODEV;  // Device already released
    }
    
    // VULNERABLE: Get reference without atomic protection
    // GAT should flag: non-atomic reference increment
    int current_refs = atomic_read(&dev->refcount);  // Read
    if (current_refs > 0) {
        // ... Another thread can decrement to 0 here ...
        atomic_inc(&dev->refcount);  // Increment - might increment freed device!
    }
    
    // VULNERABLE: Device context allocation race
    // GAT should flag: allocation race in device context
    ctx = dev->driver_data;
    if (!ctx) {  // Check if context exists
        // ... Another thread can allocate context here ...
        
        ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);  // Allocate new context
        if (!ctx) {
            atomic_dec(&dev->refcount);
            return -ENOMEM;
        }
        
        // VULNERABLE: Race in setting device context
        // GAT should flag: race in context assignment
        if (!dev->driver_data) {  // Double-check
            dev->driver_data = ctx;  // Set context
        } else {
            // Another thread already set context
            kfree(ctx);  // Free our allocation
            ctx = dev->driver_data;  // Use the other thread's context
            // VULNERABLE: Use without validation that it's still valid
        }
    }
    
    // VULNERABLE: Use device context without proper synchronization
    // GAT should flag: unsynchronized device context usage
    if (ctx->flags & DEVICE_FLAG_READY) {  // Check flag
        // ... Context can be freed by another thread here ...
        
        ret = ctx->ops->operation(dev);  // Use - ctx might be freed!
    }
    
    atomic_dec(&dev->refcount);
    return ret;
}

/*
 * RACE PATTERN F: Network Socket State Races
 * Based on CVE-2020-12771 - Socket state race in BCM CAN
 */
int kernel_socket_state_race(struct socket *sock, int new_state) {
    struct sock *sk = sock->sk;
    int old_state;
    
    // VULNERABLE: Socket state transition race
    // GAT should flag: unsynchronized socket state transition
    old_state = sk->sk_state;  // Read current state
    
    // VULNERABLE: State validation without proper locking
    // GAT should flag: TOCTOU in socket state validation
    if (old_state == TCP_ESTABLISHED) {  // Check current state
        // ... Another thread can change socket state here ...
        
        // VULNERABLE: State change based on stale check
        sk->sk_state = new_state;  // Use - state might have changed!
        
        // VULNERABLE: Socket cleanup race
        // GAT should flag: cleanup race condition
        if (new_state == TCP_CLOSE) {
            if (sk->sk_socket) {  // Check if socket exists
                // ... Socket can be freed by another thread here ...
                
                sock_orphan(sk);  // Use - socket might be freed!
                sk->sk_socket = NULL;
            }
        }
    }
    
    // VULNERABLE: Socket buffer race condition
    // GAT should flag: socket buffer race
    struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);
    if (skb) {  // Check if buffer exists
        // ... Buffer can be dequeued/freed by another thread ...
        
        // VULNERABLE: Use buffer without proper reference
        int len = skb->len;  // Use - skb might be freed!
        if (len > 0) {
            __skb_unlink(skb, &sk->sk_receive_queue);
            kfree_skb(skb);
        }
    }
    
    // VULNERABLE: Socket option race condition  
    // GAT should flag: socket option modification race
    if (sock->ops && sock->ops->setsockopt) {  // Check ops exist
        // ... Socket ops can be changed/freed by another thread ...
        
        // VULNERABLE: Call ops without revalidation
        int ret = sock->ops->setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
                                       NULL, 0);  // Use - ops might be freed!
    }
    
    return 0;
}

/*
 * Main function to demonstrate kernel race patterns
 */
int test_kernel_races(void) {
    printk(KERN_INFO "Kernel Race Condition Test Cases\n");
    
    // These would be called in different kernel contexts
    // where race conditions can occur
    
    return 0;
}

/*
 * EXPECTED GAT ANALYSIS FOR KERNEL RACE PATTERNS:
 * 
 * CRITICAL KERNEL RACES (0.9-1.0):
 * - kernel_file_release_race(): Use-after-free via reference counting
 * - kernel_path_resolution_race(): TOCTOU in filesystem operations  
 * - kernel_signal_delivery_race(): Signal handling race conditions
 * 
 * HIGH KERNEL RACE RISK (0.7-0.8):
 * - kernel_mmap_race_condition(): Memory mapping consistency races
 * - kernel_device_reference_race(): Device driver reference counting
 * - kernel_socket_state_race(): Network socket state transitions
 * 
 * KERNEL RACE PATTERNS GAT SHOULD LEARN:
 * 1. Reference counting races (check vs use, double-free)
 * 2. TOCTOU in filesystem operations (permission, path resolution)
 * 3. Memory mapping races (VMA lookup, modification, validation)
 * 4. Signal handling races (delivery, mask, handler modification)
 * 5. Device context races (allocation, assignment, cleanup)
 * 6. Socket state races (transition, buffer, option modification)
 * 
 * HAPPENS-BEFORE VIOLATIONS GAT SHOULD DETECT:
 * - atomic_read() followed by non-atomic operation
 * - Check-then-use patterns without proper locking
 * - Resource cleanup races (free-then-use)
 * - State transition races (validate-then-modify)
 * - Cross-thread resource sharing without synchronization
 * 
 * These patterns have led to:
 * - Privilege escalation (reference counting bypasses)
 * - Information disclosure (use-after-free reads)
 * - Denial of service (double-free crashes)
 * - Memory corruption (race in memory mapping)
 */