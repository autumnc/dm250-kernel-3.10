/*
 * Kernel protected-region integrity monitor.
 *
 * The soak crashes land in unrelated subsystems (eMMC write completion,
 * dentry open, scheduler wakeup) and always with the same fingerprint: a
 * wild branch to a kernel-stack address.  That points at systemic kernel
 * memory corruption rather than any single driver bug.
 *
 * The whole [_stext, _etext) span -- .text, .rodata, the exception and
 * unwind tables and the notes -- is read-only after late_initcall.  The one
 * exception is jump-label patching, which writes exactly one 4-byte
 * instruction per enabled static branch.  So a periodic word-for-word
 * comparison of those sections against a boot-time snapshot either catches
 * the writer red-handed (which word, where, old -> new) or rules the
 * sections out as the corruption target.
 *
 * A word that changed is reported unless it sits on a jump-label site *and*
 * holds one of the two legitimate encodings (NOP, or a branch to that
 * entry's target); a corrupted value landing on a jump-label site matches
 * neither and is still reported.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/jump_label.h>

#define WARP_RI_MAX_REPORT 96

extern char _stext[], _etext[];
extern char __start_rodata[], __end_rodata[];

/*
 * arch/arm/mm/proc-v7.S keeps a 4*11-byte scratch stack inside .text that
 * __v7_setup spills its registers to on every CPU bring-up (boot, CPU hotplug,
 * and the warp's enable_nonboot_cpus()).  It is written at runtime, so a
 * word-for-word comparison will legitimately see it change; it is not part of
 * the read-only region this monitor is meant to police.  Report it, don't panic.
 */
extern char __v7_setup_stack[];
#define V7_SETUP_STACK_LEN (4 * 11)

static char *ri_mirror;			/* snapshot of [_stext, _etext) */
static int ri_total;			/* words reported this cycle */

#define RI_OFF(addr)	((unsigned long)(addr) - (unsigned long)_stext)

#ifdef CONFIG_JUMP_LABEL
/*
 * Return 1 if @val is a legitimate patched form for the jump-label
 * instruction at @addr, -1 if @addr is a jump-label site but @val is not a
 * valid encoding, 0 if @addr is not a jump-label site at all.
 */
static int ri_jump_label_site(unsigned long addr, u32 val)
{
	struct jump_entry *e = __start___jump_table;
	struct jump_entry *stop = __stop___jump_table;

	for (; e < stop; e++) {
		u32 nop, branch;
		long delta;

		if ((unsigned long)e->code != addr)
			continue;
		/* ARM encodings for a patched static branch */
		nop = 0xe1a00000U;
		delta = ((long)e->target - (long)(addr + 8)) >> 2;
		branch = 0xea000000U | (delta & 0x00ffffffU);
		if (val == nop || val == branch)
			return 1;
		return -1;
	}
	return 0;
}
#else
static int ri_jump_label_site(unsigned long addr, u32 val) { return 0; }
#endif

static void ri_report(const char *name, unsigned long addr, u32 old, u32 cur)
{
	if (ri_total >= WARP_RI_MAX_REPORT) {
		if (ri_total == WARP_RI_MAX_REPORT)
			pr_emerg("WARP-RI: ... more changes suppressed\n");
		ri_total++;
		return;
	}
	ri_total++;

	pr_emerg("WARP-RI: %s @%08lx changed: %08x -> %08x  site=%pS\n",
		 name, addr, old, cur, (void *)addr);
	if (cur >= (u32)(unsigned long)_stext && cur < (u32)(unsigned long)_etext)
		pr_emerg("WARP-RI:   new value is kernel text: %pS\n", (void *)cur);
	if (old >= (u32)(unsigned long)_stext && old < (u32)(unsigned long)_etext)
		pr_emerg("WARP-RI:   old value was kernel text: %pS\n", (void *)old);
}

static int ri_check(const char *name, unsigned long start, unsigned long end,
		    int flag_text)
{
	const u32 *mem = (const u32 *)start;
	const u32 *mir = (const u32 *)(ri_mirror + RI_OFF(start));
	unsigned long n = (end - start) >> 2;
	unsigned long i;
	int nbad = 0;

	for (i = 0; i < n; i++) {
		u32 old, cur;

		old = mir[i];
		cur = mem[i];
		if (old == cur)
			continue;
		if (flag_text && ri_jump_label_site((unsigned long)&mem[i], cur) > 0)
			continue;
		if ((unsigned long)&mem[i] >= (unsigned long)__v7_setup_stack &&
		    (unsigned long)&mem[i] <
			(unsigned long)__v7_setup_stack + V7_SETUP_STACK_LEN) {
			static u32 v7s_pold, v7s_pnew;
			static int v7s_have;

			if (!v7s_have || v7s_pold != old || v7s_pnew != cur) {
				pr_info("WARP-RI: __v7_setup_stack+%lu %08x -> %08x (spill scratch, not ro)\n",
					(unsigned long)&mem[i] -
						(unsigned long)__v7_setup_stack, old, cur);
				v7s_pold = old;
				v7s_pnew = cur;
				v7s_have = 1;
			}
			continue;
		}
		ri_report(name, (unsigned long)&mem[i], old, cur);
		nbad++;
	}
	return nbad;
}

static int warp_ri_thread(void *unused)
{
	ssleep(3);
	for (;;) {
		int n = 0;

		ri_total = 0;
		n += ri_check(".text", (unsigned long)_stext,
			      (unsigned long)__start_rodata, 1);
		n += ri_check(".rodata", (unsigned long)__start_rodata,
			      (unsigned long)__end_rodata, 0);
		n += ri_check(".ro-x", (unsigned long)__end_rodata,
			      (unsigned long)_etext, 0);
		if (n) {
			pr_emerg("WARP-RI: %d word(s) modified in read-only region\n",
				 n);
			dump_stack();
			panic("WARP-RI: kernel read-only region modified");
		}
		ssleep(5);
	}
	return 0;
}

static int __init warp_ri_init(void)
{
	unsigned long len = (unsigned long)_etext - (unsigned long)_stext;

	ri_mirror = vmalloc(len);
	if (!ri_mirror) {
		pr_emerg("WARP-RI: vmalloc(%lu) failed, monitor disabled\n", len);
		return 0;
	}
	memcpy(ri_mirror, _stext, len);

	pr_info("WARP-RI: monitoring [%p..%p) %lu bytes (.text/.rodata/ro)\n",
		_stext, _etext, len);
	pr_info("WARP-RI: __v7_setup_stack boot value @%p = %08x\n",
		__v7_setup_stack, *(u32 *)(__v7_setup_stack + 0x20));
	kthread_run(warp_ri_thread, NULL, "warp-ri");
	return 0;
}
late_initcall(warp_ri_init);
