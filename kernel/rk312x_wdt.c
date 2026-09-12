/*
 * Minimal RK312x hardware watchdog (DW-compatible block at 0x2004c000).
 *
 * DT-less on purpose: the board's device tree lives in the resource
 * partition, which the safe flash path must not touch, so this driver
 * pokes the block directly and ships inside the kernel image instead.
 *
 * The driver is INERT at boot: it performs no watchdog register writes in
 * init(). Arm is explicit, through /proc/wdt. Earlier revisions briefly
 * armed the block at init() to measure its tick rate; on this SoC the
 * subsequent "disable" write does not reliably take, which left the block
 * running with no feeder and reset the board ~29s into every boot. Keep
 * boot free of register writes and that failure mode cannot occur.
 *
 * The period is pinned to the block's maximum (TORR=15). The counter is
 * fed every 500ms; at 74.25MHz that is a 28.8s timeout, a ~57x margin,
 * so a busy scheduler cannot accidentally trip it. The rate is measured
 * at arm time from CCVR (which counts down), NOT from clk_get_rate():
 * measuring the real tick avoids depending on the clock framework
 * agreeing with the block's actual input.
 *
 * Two notifiers make the reset cause trustworthy and keep crash evidence:
 *  - DIE_OOPS feeds the block, buying a fresh timeout window so the oops
 *    printout is not cut off and the panic() that follows can run kmsg_dump()
 *    into ramoops. panic() then emergency_restart()s -- a warm reset that
 *    preserves DRAM, so the records survive and the next boot reports
 *    "Boot mode: PANIC". A cold watchdog reset re-initialises DRAM, which is
 *    why the previous truncation lost everything.
 *  - The reboot notifier disarms on orderly shutdown, so a clean reboot does
 *    not read back as "Boot mode: WATCHDOG".
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/div64.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/suspend.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/notifier.h>
#include <linux/kdebug.h>
#include <linux/reboot.h>

#define WDT_PHYS	0x2004c000
#define WDT_CR		0x00
#define WDT_TORR	0x04
#define WDT_CCVR	0x08
#define WDT_CRR		0x0c

#define WDT_CR_STOP	0x0a
#define WDT_FEED	0x76

#define WDT_TORR_MAX	15		/* 2^(16+15) clk cycles == longest period */
#define WDT_PET_MS	500

static void __iomem *wdt_base;
static struct clk *wdt_clk;
static struct task_struct *wdt_kth;
static bool wdt_armed;
static bool wdt_want;

static u32 wdt_torr;
static unsigned long wdt_period_ms;
static unsigned int wdt_pets;
static unsigned int wdt_measured_hz;

static int petting = 1;

module_param(petting, int, 0644);
MODULE_PARM_DESC(petting, "0 stops feeding the watchdog (forces a reset once armed)");

static inline void wdt_w32(u32 v, u32 off)
{
	writel_relaxed(v, wdt_base + off);
	dsb();
}

static inline u32 wdt_r32(u32 off)
{
	u32 v = readl_relaxed(wdt_base + off);

	dsb();
	return v;
}

static void wdt_pet(void)
{
	wdt_w32(WDT_FEED, WDT_CRR);
}

static void __wdt_halt(void)
{
	/*
	 * EN=0 to stop. Do not rely on this to disarm: on some revisions the
	 * block keeps counting after the stop write, so callers must keep
	 * feeding or accept a reset.
	 */
	if (wdt_base)
		wdt_w32(0, WDT_CR);
	wdt_armed = false;
}

static void wdt_disarm(void)
{
	wdt_want = false;
	__wdt_halt();
}

static void wdt_arm(void)
{
	u32 c0, c1, delta;
	u64 tmp;

	wdt_torr = WDT_TORR_MAX;
	wdt_w32(wdt_torr, WDT_TORR);
	wdt_pet();

	/*
	 * Measure the real tick from CCVR (which counts down) the first time
	 * only. The window must be long enough that msleep's overshoot is a
	 * small fraction of it: at 20ms a couple of ms of overshoot skews the
	 * rate by >20%, so use 200ms. Caching keeps PM re-arm from sleeping.
	 */
	if (!wdt_measured_hz) {
		wdt_w32((1u << 0) | (0u << 1) | (4u << 2), WDT_CR);
		c0 = wdt_r32(WDT_CCVR);
		msleep(200);
		c1 = wdt_r32(WDT_CCVR);
		delta = c0 > c1 ? c0 - c1 : c1 - c0;
		if (delta) {
			tmp = (u64)delta * 1000;
			do_div(tmp, 200);
			wdt_measured_hz = (u32)tmp;
		}
	}

	tmp = (u64)1 << (16 + wdt_torr);
	tmp *= 1000;
	do_div(tmp, wdt_measured_hz ? wdt_measured_hz : 1);
	wdt_period_ms = (unsigned long)tmp;

	wdt_pet();
	/* EN=1, RMOD=00 (reset, no IRQ), RPL=0b10 */
	wdt_w32((1u << 0) | (0u << 1) | (4u << 2), WDT_CR);
	wdt_armed = true;
	wdt_want = true;
}

static int wdt_kthread(void *unused)
{
	while (!kthread_should_stop()) {
		if (petting && wdt_armed) {
			wdt_pet();
			wdt_pets++;
		}
		msleep(WDT_PET_MS);
	}
	return 0;
}

static int wdt_pm_notify(struct notifier_block *nb, unsigned long action,
			 void *data)
{
	switch (action) {
	case PM_HIBERNATION_PREPARE:
	case PM_SUSPEND_PREPARE:
		if (wdt_armed)
			__wdt_halt();
		break;
	case PM_POST_HIBERNATION:
	case PM_POST_SUSPEND:
		if (wdt_want)
			wdt_arm();
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block wdt_pm_nb = {
	.notifier_call = wdt_pm_notify,
};

/*
 * A fatal fault is starting. Feed the block instead of disarming it: the oops
 * printout can take seconds, and if it is cut off the reset is a cold watchdog
 * reset that does not preserve DRAM, so the backtrace never reaches ramoops
 * and the captured log stops mid-line. One feed restarts the full timeout
 * window -- comfortably longer than the oops, the panic() that follows, and
 * panic_timeout -- so the panic path wins and the reset is panic()'s warm
 * emergency_restart() (recorded as "Boot mode: PANIC"), which keeps DRAM and
 * therefore the ramoops records. The block is left armed, so a genuine hang is
 * still reset, just cold.
 */
static int wdt_die_notify(struct notifier_block *nb, unsigned long val,
			  void *data)
{
	if (val != DIE_OOPS || !wdt_armed)
		return NOTIFY_DONE;

	pr_emerg("rk312x_wdt: oops, feeding so the panic path can finish\n");
	wdt_pet();
	return NOTIFY_DONE;
}

static struct notifier_block wdt_die_nb = {
	.notifier_call = wdt_die_notify,
};

/*
 * Panic is underway (kmsg_dump() has already run by now). Feed again so the
 * panic_timeout delay plus the warm restart cannot run past the timeout and
 * turn into a cold watchdog reset that wipes the ramoops records just written.
 */
static int wdt_panic_notify(struct notifier_block *nb, unsigned long event,
			    void *ptr)
{
	if (wdt_armed) {
		pr_emerg("rk312x_wdt: panic, feeding so the warm reboot lands\n");
		wdt_pet();
	}
	return NOTIFY_DONE;
}

static struct notifier_block wdt_panic_nb = {
	.notifier_call = wdt_panic_notify,
};

/*
 * Orderly shutdown. Disarm so a clean reboot/halt does not read back as a
 * watchdog reset ("Boot mode: WATCHDOG"), which is otherwise indistinguishable
 * from a real crash.
 */
static int wdt_reboot_notify(struct notifier_block *nb, unsigned long code,
			     void *unused)
{
	switch (code) {
	case SYS_DOWN:		/* also SYS_RESTART */
	case SYS_HALT:
	case SYS_POWER_OFF:
		if (wdt_armed) {
			pr_emerg("rk312x_wdt: orderly shutdown, disarming\n");
			wdt_disarm();
		}
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block wdt_reboot_nb = {
	.notifier_call = wdt_reboot_notify,
};

static int wdt_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "armed=%d pets=%u clk_rate=%lu measured=%u torr=%u period=%lums\n",
		   wdt_armed, wdt_pets,
		   wdt_clk ? clk_get_rate(wdt_clk) : 0,
		   wdt_measured_hz, wdt_torr, wdt_period_ms);
	if (wdt_base)
		seq_printf(m, "regs cr=0x%08x torr=0x%08x ccvr=%u crr=0x%08x\n",
			   wdt_r32(WDT_CR), wdt_r32(WDT_TORR),
			   wdt_r32(WDT_CCVR), wdt_r32(WDT_CRR));
	return 0;
}

static int wdt_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, wdt_proc_show, NULL);
}

static ssize_t wdt_proc_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *ppos)
{
	char k[8];
	int v;

	if (len == 0 || len >= sizeof(k))
		return -EINVAL;
	if (copy_from_user(k, buf, len))
		return -EFAULT;
	k[len] = '\0';
	if (kstrtoint(k, 0, &v))
		return -EINVAL;

	if (v)
		wdt_arm();
	else
		wdt_disarm();
	return len;
}

static const struct file_operations wdt_proc_fops = {
	.owner	= THIS_MODULE,
	.open	= wdt_proc_open,
	.read	= seq_read,
	.write	= wdt_proc_write,
	.llseek	= seq_lseek,
	.release = single_release,
};

static int __init rk312x_wdt_init(void)
{
	wdt_clk = clk_get(NULL, "g_pclk_wdt");
	if (IS_ERR(wdt_clk)) {
		pr_err("rk312x_wdt: clk g_pclk_wdt missing (%ld)\n",
		       PTR_ERR(wdt_clk));
		return PTR_ERR(wdt_clk);
	}
	clk_prepare_enable(wdt_clk);

	wdt_base = ioremap(WDT_PHYS, 0x100);
	if (!wdt_base) {
		pr_err("rk312x_wdt: ioremap failed\n");
		clk_disable_unprepare(wdt_clk);
		return -ENOMEM;
	}

	proc_create("wdt", 0644, NULL, &wdt_proc_fops);
	register_pm_notifier(&wdt_pm_nb);
	register_die_notifier(&wdt_die_nb);
	register_reboot_notifier(&wdt_reboot_nb);
	atomic_notifier_chain_register(&panic_notifier_list, &wdt_panic_nb);

	wdt_kth = kthread_run(wdt_kthread, NULL, "wdt-pet");
	if (IS_ERR(wdt_kth)) {
		pr_err("rk312x_wdt: no petter thread (%ld)\n",
		       PTR_ERR(wdt_kth));
		return PTR_ERR(wdt_kth);
	}

	pr_emerg("rk312x_wdt: inert at boot, clk_rate=%lu Hz (echo 1 > /proc/wdt to arm)\n",
		 clk_get_rate(wdt_clk));
	return 0;
}
late_initcall(rk312x_wdt_init);

MODULE_LICENSE("GPL");
