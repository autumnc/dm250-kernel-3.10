/*
 * Controlled hard-lockup trigger, for validating the cross-CPU
 * (HARDLOCKUP_DETECTOR_OTHER_CPU) hardlockup detector on this platform.
 *
 * `echo <cpu> > /proc/hardlock` pins a kthread to that CPU and spins there
 * forever with interrupts disabled. If the detector works, a neighbouring
 * CPU notices the stalled hrtimer within ~12s and (since
 * BOOTPARAM_HARDLOCKUP_PANIC=y) panics with a backtrace.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>

static int hardlock_thread(void *arg)
{
	pr_emerg("hardlock_test: CPU%d spinning with IRQs off\n",
		 smp_processor_id());
	local_irq_disable();
	for (;;)
		cpu_relax();
	return 0;
}

static ssize_t hardlock_write(struct file *f, const char __user *buf,
			      size_t len, loff_t *off)
{
	char k[8];
	unsigned long cpu;
	struct task_struct *t;

	if (len == 0 || len >= sizeof(k))
		return -EINVAL;
	if (copy_from_user(k, buf, len))
		return -EFAULT;
	k[len] = '\0';
	if (kstrtoul(k, 0, &cpu) || cpu >= nr_cpu_ids || !cpu_online(cpu))
		return -EINVAL;

	pr_emerg("hardlock_test: wedging CPU%lu\n", cpu);
	t = kthread_create(hardlock_thread, NULL, "hardlock");
	if (IS_ERR(t))
		return PTR_ERR(t);
	kthread_bind(t, cpu);
	wake_up_process(t);
	return len;
}

static const struct file_operations hardlock_fops = {
	.owner = THIS_MODULE,
	.write = hardlock_write,
	.llseek = no_llseek,
};

static int __init hardlock_init(void)
{
	proc_create("hardlock", 0200, NULL, &hardlock_fops);
	return 0;
}
late_initcall(hardlock_init);

MODULE_LICENSE("GPL");
