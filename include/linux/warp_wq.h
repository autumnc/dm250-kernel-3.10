#ifndef _LINUX_WARP_WQ_H
#define _LINUX_WARP_WQ_H

/*
 * WARP-POLL wait-queue audit.
 *
 * bug5 is a socket wait-queue use-after-free: a wait queue keeps pointing at a
 * poll_table_entry (or its wait_queue_t) after the owner has returned from
 * poll() and the entry's storage is gone, so the next wake walks freed memory.
 * fs/select.c keeps a registry of the poll entries that are actually live and
 * warp_wq_audit() flags any pollwake entry in the queue that is not in it.
 *
 * Called with the queue's own lock held (remove/wake), where the list is
 * otherwise stable.  On an anomaly it dumps and BUG()s so the oops handler
 * saves the scene to pstore.
 */
#include <linux/wait.h>

#if defined(CONFIG_PM_WARP) && defined(CONFIG_WARP_DIAG)
extern void warp_wq_audit(wait_queue_head_t *q, const char *where);
#else
static inline void warp_wq_audit(wait_queue_head_t *q, const char *where) { }
#endif

#endif /* _LINUX_WARP_WQ_H */
