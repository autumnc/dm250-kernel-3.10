/*
 * Hardware write-watchpoint trap for the systemic-corruption hunt.
 *
 * The soak crashes share one fingerprint: 4-byte kernel heap pointers turn
 * up in freed or foreign slab objects -- biovec-64, fs_cache, nf_conntrack
 * -- and even in kernel stacks, and whoever next uses that memory branches
 * into the garbage.  Every other detector in this tree is retrospective:
 * poisoning marks the damage, redzones frame it, but nothing names the
 * store that wrote it.
 *
 * An ARM data watchpoint does.  It traps the exact store, and the faulting
 * pt_regs names the writer: pc is the store instruction, lr its caller,
 * alongside the current comm.  Arm one -- via /proc/warp_watch or the
 * warp_watch= cmdline -- on an address predicted from an earlier crash and
 * the next corruption names its author.
 *
 *   echo 0xd65b5ec4 > /proc/warp_watch    arm a 4-byte write window there
 *   echo 0 > /proc/warp_watch             disarm all
 *   cat  /proc/warp_watch                 state + the last writer seen
 *
 * The address must be 4-byte aligned for a length-4 window; the arch code
 * masks it down and shifts the byte-select if it is not.  Up to WATCH_MAX
 * windows may be armed at once, bounded by the WRP registers the core
 * actually implements.
 *
 * The trap handler runs in the debug-exception context, which on this part
 * is entered wherever the store happened -- kernel, IRQ, MMC completion,
 * spinlock held.  printk and dump_stack from there deadlocked the block
 * layer: an 8 MB dd to the rootfs trapped the target, the handler wedged
 * holding a lock the console path wanted, and the box soft-locked for 22 s
 * (watchdog reset, no hit line ever printed).  So the handler now does no
 * I/O at all -- it only copies pc/lr/val/cpu/pid/comm into a slot and
 * returns.  The housekeeping kthread, in plain process context, prints the
 * records a second later.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/hardirq.h>
#include <linux/ptrace.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/percpu.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define WATCH_MAX	4
#define WW_REC_ALL	8		/* first writes recorded, any value */
#define WW_REC_PTR	8		/* first kernel-pointer-valued writes */
#define WW_MAX_TRAPS	(1 << 20)	/* stop trapping a purely hot target */
/*
 * A kernel heap pointer, written over a length/offset field, is the
 * corruption signature.  Benign stores to the watched word are small
 * integers (a biovec bv_len), so gating the pointer log on this bound
 * filters them out and leaves only the stores that look like the bug.
 */
#define WW_PTR_MIN	0xc0000000UL

struct ww_hit {
	unsigned long pc;
	unsigned long lr;
	unsigned long val;
	int cpu;
	int pid;
	int irq;
	char comm[TASK_COMM_LEN];
};

struct ww_slot {
	unsigned long addr;			/* 0 == free */
	struct perf_event * __percpu *ev;
	int active;				/* trap currently installed */
	int dead;				/* tear down requested */
	int sticky;				/* static target; rolling may not evict */
	int ct;					/* creation-time ct watch; reconciler owns */
	atomic_t hits;				/* every store to the window */
	atomic_t ptr_hits;			/* stores of a kptr value */
	struct ww_hit rec_all[WW_REC_ALL];
	struct ww_hit rec_ptr[WW_REC_PTR];
	int reported_all;
	int reported_ptr;
};

static struct ww_slot ww_slot[WATCH_MAX];
static DEFINE_MUTEX(ww_mutex);
static unsigned long ww_boot_addr[WATCH_MAX];
static unsigned int ww_boot_delay = 30;
static int ww_boot_n;

/*
 * Auto-arming master switch.  The static and creation-time arms re-arm
 * themselves every tick, so a plain "echo 0" (disarm now) would be undone a
 * second later -- long before a flash read-modify-write of the rootfs, which
 * must not run with a watchpoint armed.  Clear this first for a quiet box.
 * /proc/warp_watch_auto: 0 == stop auto-arming, 1 == resume.
 */
static int ww_auto = 1;

/*
 * Rolling arm.  A victim address from a past crash does not survive a
 * reboot (slab layout shifts), so the watchpoint is instead pointed at the
 * address the SLUB corruption check just found -- live, same boot.  The
 * check runs in every context (alloc/free/scan), so this is a bare store
 * and a flag; the housekeeping kthread does the actual arming.
 */
static unsigned long ww_corrupt_addr;
static int ww_corrupt_pending;
static int ww_corrupt_live;	/* 1 == named by a live-object detector */

void warp_ww_note_corruption(unsigned long addr);
void warp_ww_note_corruption(unsigned long addr)
{
	ww_corrupt_addr = addr;
	ww_corrupt_live = 0;
	smp_wmb();
	ww_corrupt_pending = 1;
}

/*
 * Live-object detector hook: the SLUB poison check above only ever sees a
 * freed object, so a trap it arms never catches the writer (the word is gone
 * and stays gone).  The conntrack and timer-wheel guards instead fire on a
 * word that is still in use -- arm the trap on that exact word and the writer
 * coming back to it is caught.  Flagged live so the rolling arm may preempt a
 * sticky fixed target to make room; a freed-object hit may not.
 */
void warp_ww_note_corruption_live(unsigned long addr);
void warp_ww_note_corruption_live(unsigned long addr)
{
	ww_corrupt_addr = addr;
	ww_corrupt_live = 1;
	smp_wmb();
	ww_corrupt_pending = 1;
}

/*
 * Static per-cpu targets.  The systemic corruption keeps landing on the
 * per-cpu timer wheel base: the spinlock magic word (offset 4 inside the
 * raw_spinlock, never written once the lock is initialised) turns up holding
 * a kernel heap pointer, the next timer-softirq lock then spins on the bad
 * magic forever, and the box hard-locks into a watchdog reset.  Unlike a slab
 * victim this object is live and permanent, so arming the trap on it as soon
 * as it exists directly tests whether the writer revisits a live victim --
 * the gap the SLUB-triggered rolling arm could never close.  kernel/timer.c
 * names each base at init_timers_cpu(); the slots are sticky, so the rolling
 * arm must never evict them.
 */
#define WW_TMR_MAX		8
#define WW_TMR_MAGIC_OFF	4	/* raw_spinlock_t: magic just past raw_lock */
static unsigned long ww_tmr_base[WW_TMR_MAX];
static int ww_tmr_n;
static int ww_tmr_done[WW_TMR_MAX];

void warp_ww_note_timer_base(int cpu, unsigned long lock_addr);
void warp_ww_note_timer_base(int cpu, unsigned long lock_addr)
{
	if (cpu < 0 || cpu >= WW_TMR_MAX)
		return;
	ww_tmr_base[cpu] = lock_addr;
	smp_wmb();
	if (ACCESS_ONCE(ww_tmr_n) < cpu + 1)
		ACCESS_ONCE(ww_tmr_n) = cpu + 1;
}

/*
 * Creation-time arming (experiment #91).  Both arms tried so far failed for
 * the same reason: the writer stores to a victim once and never returns to it,
 * so arming the word *after* a detector flags it watches a store that never
 * comes.  This arm instead watches the write-once field of a live object from
 * the instant it is created: a new conntrack's timeout.function is set exactly
 * once (setup_timer) and never rewritten, so the only store the trap can ever
 * see is the writer's -- no trap storm, and the field is in use the whole time.
 * The ring keeps the newest WW_CT_MAX creations; the housekeeping kthread
 * reconciles the live watchpoints to it.
 */
#define WW_CT_MAX	WATCH_MAX
static unsigned long ww_ct_new[WW_CT_MAX];	/* oldest .. newest */
static int ww_ct_new_n;
static DEFINE_SPINLOCK(ww_ct_new_lock);

void warp_ww_note_new_ct(unsigned long addr);
void warp_ww_note_new_ct(unsigned long addr)
{
	unsigned long flags;
	int i;

	if (!addr)
		return;
	addr &= ~0x3UL;
	spin_lock_irqsave(&ww_ct_new_lock, flags);
	for (i = 0; i < ww_ct_new_n; i++)
		if (ww_ct_new[i] == addr) {
			spin_unlock_irqrestore(&ww_ct_new_lock, flags);
			return;
		}
	if (ww_ct_new_n < WW_CT_MAX) {
		ww_ct_new[ww_ct_new_n++] = addr;
	} else {
		memmove(&ww_ct_new[0], &ww_ct_new[1],
			(WW_CT_MAX - 1) * sizeof(unsigned long));
		ww_ct_new[WW_CT_MAX - 1] = addr;
	}
	spin_unlock_irqrestore(&ww_ct_new_lock, flags);
}

/* Trap context: no printk, no dump_stack, no locks -- record and return. */
static void ww_record(struct ww_hit *r, unsigned long pc, unsigned long lr,
		      unsigned long val)
{
	r->pc = pc;
	r->lr = lr;
	r->val = val;
	r->cpu = smp_processor_id();
	r->pid = current->pid;
	r->irq = in_interrupt();
	memcpy(r->comm, current->comm, TASK_COMM_LEN);
}

static void ww_triggered(struct perf_event *bp, struct perf_sample_data *data,
			 struct pt_regs *regs)
{
	unsigned long ea = bp->attr.bp_addr;
	unsigned long pc = instruction_pointer(regs);
	unsigned long lr = regs->ARM_lr;
	unsigned long val;
	struct ww_slot *s = NULL;
	int i, n;

	for (i = 0; i < WATCH_MAX; i++) {
		if (ww_slot[i].active && ww_slot[i].addr == ea) {
			s = &ww_slot[i];
			break;
		}
	}
	if (!s)
		return;

	val = virt_addr_valid(ea) ? *(u32 *)ea : 0;
	n = atomic_inc_return(&s->hits);

	if (n <= WW_REC_ALL)
		ww_record(&s->rec_all[n - 1], pc, lr, val);

	if (val >= WW_PTR_MIN) {
		int p = atomic_inc_return(&s->ptr_hits);

		if (p <= WW_REC_PTR)
			ww_record(&s->rec_ptr[p - 1], pc, lr, val);
	}

	if (n >= WW_MAX_TRAPS)
		s->dead = 1;
}

static int ww_arm_one_flags(unsigned long addr, int sticky, int ct)
{
	struct perf_event_attr attr;
	struct perf_event * __percpu *ev;
	struct ww_slot *s = NULL;
	int i, ret;

	addr &= ~0x3UL;
	if (!virt_addr_valid(addr))
		return -EINVAL;

	mutex_lock(&ww_mutex);
	for (i = 0; i < WATCH_MAX; i++)
		if (ww_slot[i].active && ww_slot[i].addr == addr) {
			mutex_unlock(&ww_mutex);
			return -EEXIST;
		}
	for (i = 0; i < WATCH_MAX; i++)
		if (!ww_slot[i].active) {
			s = &ww_slot[i];
			break;
		}
	if (!s) {
		mutex_unlock(&ww_mutex);
		return -ENOSPC;
	}

	hw_breakpoint_init(&attr);
	attr.bp_addr = addr;
	attr.bp_len  = HW_BREAKPOINT_LEN_4;
	attr.bp_type = HW_BREAKPOINT_W;

	/* Publish the slot before the event can fire. */
	s->addr = addr;
	s->dead = 0;
	s->sticky = sticky;
	s->ct = ct;
	atomic_set(&s->hits, 0);
	atomic_set(&s->ptr_hits, 0);
	memset(s->rec_all, 0, sizeof(s->rec_all));
	memset(s->rec_ptr, 0, sizeof(s->rec_ptr));
	s->reported_all = 0;
	s->reported_ptr = 0;

	ev = register_wide_hw_breakpoint(&attr, ww_triggered, NULL);
	if (IS_ERR(ev)) {
		ret = PTR_ERR(ev);
		s->addr = 0;
		mutex_unlock(&ww_mutex);
		return ret;
	}
	s->ev = ev;
	s->active = 1;
	mutex_unlock(&ww_mutex);

	pr_emerg("WARP-WW: armed W watch @%08lx len=4%s\n", addr,
		 sticky ? " (sticky)" : "");
	return 0;
}

static int ww_arm_one(unsigned long addr)
{
	return ww_arm_one_flags(addr, 0, 0);
}

/* Detach one slot's trap but keep its stats for /proc. */
static void ww_teardown(int i)
{
	struct perf_event * __percpu *ev;

	mutex_lock(&ww_mutex);
	ev = ww_slot[i].ev;
	ww_slot[i].ev = NULL;
	ww_slot[i].active = 0;
	mutex_unlock(&ww_mutex);

	if (!ev)
		return;
	unregister_wide_hw_breakpoint(ev);
	pr_emerg("WARP-WW: disarmed @%08lx (%d hits, %d kptr)\n",
		 ww_slot[i].addr, atomic_read(&ww_slot[i].hits),
		 atomic_read(&ww_slot[i].ptr_hits));
}

static void ww_disarm_all(void)
{
	int i;

	for (i = 0; i < WATCH_MAX; i++)
		if (ww_slot[i].active)
			ww_teardown(i);
}

static ssize_t ww_write(struct file *f, const char __user *ubuf,
			size_t len, loff_t *off)
{
	char kbuf[64];
	unsigned long addr;
	int ret;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = 0;

	if (strict_strtoul(kbuf, 0, &addr))
		return -EINVAL;

	if (addr == 0) {
		ww_disarm_all();
		return len;
	}

	ret = ww_arm_one(addr);
	if (ret)
		pr_emerg("WARP-WW: arm @%08lx failed: %d\n", addr, ret);
	return ret ? ret : len;
}

static ssize_t ww_auto_write(struct file *f, const char __user *ubuf,
			     size_t len, loff_t *off)
{
	char kbuf[16];
	unsigned long v;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = 0;
	if (strict_strtoul(kbuf, 0, &v))
		return -EINVAL;
	ww_auto = v ? 1 : 0;
	if (!ww_auto)
		ww_disarm_all();
	pr_emerg("WARP-WW: auto-arming %s\n", ww_auto ? "on" : "off");
	return len;
}

static ssize_t ww_auto_read(struct file *f, char __user *ubuf,
			    size_t len, loff_t *off)
{
	char b[4];
	int n = scnprintf(b, sizeof(b), "%d\n", ww_auto);

	return simple_read_from_buffer(ubuf, len, off, b, n);
}

static const struct file_operations ww_auto_fops = {
	.owner	= THIS_MODULE,
	.read	= ww_auto_read,
	.write	= ww_auto_write,
	.llseek	= no_llseek,
};

static void ww_dump_rec(char *p, int sz, int *n, struct ww_slot *s,
			struct ww_hit *rec, int cnt)
{
	int k;

	for (k = 0; k < cnt; k++) {
		struct ww_hit *r = &rec[k];

		*n += scnprintf(p + *n, sz - *n,
				"      [%d] val=%08lx pc=%pS lr=%pS irq=%d cpu=%d pid=%d comm=%s\n",
				k, r->val, (void *)r->pc, (void *)r->lr,
				r->irq, r->cpu, r->pid, r->comm);
	}
}

static ssize_t ww_read(struct file *f, char __user *ubuf,
		       size_t len, loff_t *off)
{
	char *p;
	int i, n = 0;
	const int sz = 4096;

	p = kzalloc(sz, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	mutex_lock(&ww_mutex);
	n += scnprintf(p + n, sz - n, "warp_watch: %s\n",
		       ww_boot_n ? "boot-armed" : "manual");
	for (i = 0; i < WATCH_MAX; i++) {
		struct ww_slot *s = &ww_slot[i];
		int ph, ah;

		if (!s->addr)
			continue;
		ph = atomic_read(&s->ptr_hits);
		ah = atomic_read(&s->hits);
		n += scnprintf(p + n, sz - n,
			       "  [%d] @%08lx %s hits=%d kptr=%d\n", i, s->addr,
			       s->active ? "armed" : "disarmed", ah, ph);
		if (ph)
			ww_dump_rec(p, sz, &n, s, s->rec_ptr,
				    ph < WW_REC_PTR ? ph : WW_REC_PTR);
		else if (ah)
			ww_dump_rec(p, sz, &n, s, s->rec_all,
				    ah < WW_REC_ALL ? ah : WW_REC_ALL);
	}
	if (ww_boot_n) {
		n += scnprintf(p + n, sz - n, "cmdline targets:");
		for (i = 0; i < ww_boot_n; i++)
			n += scnprintf(p + n, sz - n, " %08lx", ww_boot_addr[i]);
		n += scnprintf(p + n, sz - n, " (delay %us)\n", ww_boot_delay);
	}
	mutex_unlock(&ww_mutex);

	n = simple_read_from_buffer(ubuf, len, off, p, n);
	kfree(p);
	return n;
}

static const struct file_operations ww_fops = {
	.owner	= THIS_MODULE,
	.read	= ww_read,
	.write	= ww_write,
	.llseek	= no_llseek,
};

/*
 * Housekeeping: arm any cmdline targets once the boot has settled, then
 * report what the traps caught and reap finished slots.  This is where all
 * the printing happens -- the trap handler itself never touches the console.
 */
static void ww_report(int i)
{
	struct ww_slot *s = &ww_slot[i];
	int ph = atomic_read(&s->ptr_hits);
	int ah = atomic_read(&s->hits);
	int k, m;

	if (ph && !s->reported_ptr) {
		s->reported_ptr = 1;
		pr_emerg("WARP-WW: @%08lx KERNEL-POINTER store seen: %d kptr hit(s) of %d\n",
			 s->addr, ph, ah);
		m = ph < WW_REC_PTR ? ph : WW_REC_PTR;
		for (k = 0; k < m; k++) {
			struct ww_hit *r = &s->rec_ptr[k];

			pr_emerg("WARP-WW:   kptr[%d] val=%08lx pc=%pS lr=%pS irq=%d cpu=%d pid=%d comm=%s\n",
				 k, r->val, (void *)r->pc, (void *)r->lr,
				 r->irq, r->cpu, r->pid, r->comm);
		}
		/* Got the signature; keep the trap from firing forever. */
		s->dead = 1;
	}

	if (ah && !s->reported_all) {
		s->reported_all = 1;
		pr_emerg("WARP-WW: @%08lx first writes (%d total):\n", s->addr, ah);
		m = ah < WW_REC_ALL ? ah : WW_REC_ALL;
		for (k = 0; k < m; k++) {
			struct ww_hit *r = &s->rec_all[k];

			pr_emerg("WARP-WW:   w[%d] val=%08lx pc=%pS lr=%pS irq=%d cpu=%d pid=%d comm=%s\n",
				 k, r->val, (void *)r->pc, (void *)r->lr,
				 r->irq, r->cpu, r->pid, r->comm);
		}
	}
}

/*
 * Point the trap at a freshly corrupted word so a repeat store to it names
 * the writer.  `live` is set for a word named by the conntrack/timer guards
 * (still in use, so a repeat is plausible, and the arm may preempt a sticky
 * fixed target to make room); a freed-object (SLUB) hit may only take an idle
 * slot, since those words never recur.
 */
static void ww_rolling_arm(unsigned long addr, int live)
{
	int i;

	if (!addr)
		return;
	for (i = 0; i < WATCH_MAX; i++)
		if (ww_slot[i].active && ww_slot[i].addr == addr)
			return;			/* already watching it */
	for (i = 0; i < WATCH_MAX; i++)
		if (!ww_slot[i].active)
			break;
	if (i == WATCH_MAX) {			/* all busy: roll a non-sticky out */
		for (i = 0; i < WATCH_MAX; i++)
			if (ww_slot[i].active && !ww_slot[i].sticky)
				break;
		if (i == WATCH_MAX) {
			/*
			 * Only sticky fixed targets left.  A live-object hit is
			 * worth more than a target that has not fired, so let it
			 * preempt one; a freed-object hit must not -- those
			 * words never recur, so the trap would be wasted.
			 */
			if (!live)
				return;
			for (i = 0; i < WATCH_MAX; i++)
				if (ww_slot[i].active)
					break;
		}
		ww_teardown(i);
	}
	pr_emerg("WARP-WW: rolling onto %s word %08lx\n",
		 live ? "LIVE-corrupt" : "corrupted", addr);
	ww_arm_one(addr);
}

/*
 * Arm the static per-cpu timer-base magic words, one per cpu as each base is
 * announced (boot cpu first, APs as they come online).  Runs from the
 * housekeeping kthread so register_wide_hw_breakpoint is never called from
 * timer.c's early init or an atomic context.
 */
static void ww_arm_static_targets(void)
{
	int i, n = ACCESS_ONCE(ww_tmr_n);

	for (i = 0; i < n && i < WW_TMR_MAX; i++) {
		unsigned long a = ww_tmr_base[i] + WW_TMR_MAGIC_OFF;
		u32 probe;

		if (!ww_tmr_base[i] || ww_tmr_done[i])
			continue;
		ww_tmr_done[i] = 1;
		if (!virt_addr_valid(a)) {
			pr_emerg("WARP-WW: timer_base[%d] @%08lx not valid, skip\n",
				 i, a);
			continue;
		}
		/*
		 * Self-check the offset: the word we mean to watch must read
		 * SPINLOCK_MAGIC right now.  If it does not, the layout guess is
		 * wrong -- and arming a field the timer path writes every tick
		 * would trap-storm the box -- so skip it and say so instead.
		 */
		probe = *(u32 *)a;
		if (probe != 0xdead4ead) {
			pr_emerg("WARP-WW: timer_base[%d] @%08lx probe=%08x != magic, skip\n",
				 i, a, probe);
			continue;
		}
		if (ww_arm_one_flags(a, 1, 0) == 0)
			pr_emerg("WARP-WW: static arm timer_base[%d] magic @%08lx (probe ok)\n",
				 i, a);
		else
			pr_emerg("WARP-WW: static arm timer_base[%d] @%08lx FAILED\n",
				 i, a);
	}
}

/*
 * Reconcile the live watchpoints to the newest-WW_CT_MAX creation ring:
 * watch every ring entry, drop any ct watch that has aged out.  A ct watch
 * may preempt a sticky fixed target -- those have never fired, a live ct in
 * use is a better bet -- but never another ct watch that is still current.
 */
static void ww_reconcile_ct(void)
{
	unsigned long want[WW_CT_MAX];
	unsigned long flags;
	int want_n, i, j;

	spin_lock_irqsave(&ww_ct_new_lock, flags);
	want_n = ww_ct_new_n;
	for (i = 0; i < want_n; i++)
		want[i] = ww_ct_new[i];
	spin_unlock_irqrestore(&ww_ct_new_lock, flags);

	for (i = 0; i < WATCH_MAX; i++) {
		struct ww_slot *s = &ww_slot[i];
		int keep = 0;

		if (!s->active || !s->ct)
			continue;
		for (j = 0; j < want_n; j++)
			if (s->addr == want[j])
				keep = 1;
		if (!keep)
			ww_teardown(i);
	}

	for (j = 0; j < want_n; j++) {
		int have = 0, slot = -1;

		for (i = 0; i < WATCH_MAX; i++)
			if (ww_slot[i].active && ww_slot[i].addr == want[j])
				have = 1;
		if (have)
			continue;
		for (i = 0; i < WATCH_MAX; i++)
			if (!ww_slot[i].active) {
				slot = i;
				break;
			}
		if (slot < 0) {
			/*
			 * Evict a slot whose address is not in the current ring:
			 * a stale timer_base or aged ct.  Never evict a watch we
			 * are about to keep, or the ring can never fill.
			 */
			int k;

			for (i = 0; i < WATCH_MAX && slot < 0; i++) {
				int wanted = 0;

				if (!ww_slot[i].active)
					continue;
				for (k = 0; k < want_n; k++)
					if (ww_slot[i].addr == want[k])
						wanted = 1;
				if (!wanted)
					slot = i;
			}
		}
		if (slot < 0)
			continue;
		if (ww_slot[slot].active)
			ww_teardown(slot);
		if (ww_arm_one_flags(want[j], 0, 1) == 0)
			pr_emerg("WARP-WW: ct-watch arm @%08lx\n", want[j]);
	}
}

static int ww_thread(void *unused)
{
	int i;

	if (ww_boot_n) {
		ssleep(ww_boot_delay);
		for (i = 0; i < ww_boot_n; i++)
			ww_arm_one(ww_boot_addr[i]);
	}

	for (;;) {
		ssleep(1);
		if (ww_auto) {
			ww_arm_static_targets();
			ww_reconcile_ct();
		}
		if (ww_corrupt_pending) {
			unsigned long a = ww_corrupt_addr & ~0x3UL;
			int live = ww_corrupt_live;

			ww_corrupt_pending = 0;
			/*
			 * auto=0 must mean *no* watchpoint is armed, rolling arm
			 * included.  An armed wide hw breakpoint under load wedges
			 * this board (see #92), so a "quiet" soak has to be genuinely
			 * quiet or its result is uninterpretable.  The read-only
			 * detectors (CTREF/TMR) still print; they just don't arm.
			 */
			if (ww_auto)
				ww_rolling_arm(a, live);
		}
		for (i = 0; i < WATCH_MAX; i++) {
			if (!ww_slot[i].addr)
				continue;
			ww_report(i);
			if (ww_slot[i].dead && ww_slot[i].active)
				ww_teardown(i);
		}
	}
	return 0;
}

/*
 * warp_watch=0xd65b5e34[,0x...]   arm these after boot
 * warp_watch_delay=60             seconds to wait first (default 30)
 */
static int __init ww_setup_addr(char *str)
{
	char *tok, *save = NULL;

	for (tok = strsep(&str, ","); tok; tok = strsep(&str, ",")) {
		unsigned long a;
		if (ww_boot_n >= WATCH_MAX)
			break;
		if (strict_strtoul(tok, 0, &a))
			continue;
		if (a)
			ww_boot_addr[ww_boot_n++] = a & ~0x3UL;
	}
	return 1;
}
__setup("warp_watch=", ww_setup_addr);

static int __init ww_setup_delay(char *str)
{
	unsigned long v;

	if (!strict_strtoul(str, 0, &v) && v)
		ww_boot_delay = v;
	return 1;
}
__setup("warp_watch_delay=", ww_setup_delay);

static int __init warp_watch_init(void)
{
	struct proc_dir_entry *e;

	e = proc_create("warp_watch", 0600, NULL, &ww_fops);
	if (!e) {
		pr_emerg("WARP-WW: proc_create failed\n");
		return 0;
	}
	proc_create("warp_watch_auto", 0600, NULL, &ww_auto_fops);

	kthread_run(ww_thread, NULL, "warp-watch");

	pr_info("WARP-WW: ready (/proc/warp_watch), %d cmdline target(s)\n",
		ww_boot_n);
	return 0;
}
late_initcall(warp_watch_init);
