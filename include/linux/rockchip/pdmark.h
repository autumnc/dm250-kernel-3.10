#ifndef __LINUX_ROCKCHIP_PDMARK_H
#define __LINUX_ROCKCHIP_PDMARK_H

/*
 * Breadcrumb for the cold-restore shutdown freeze.
 *
 * A poweroff can stop anywhere between reboot(RB_POWER_OFF) and the point
 * where the PMIC actually cuts, and nothing after reboot() can be recorded
 * from userspace: wifi is already off by stage 10, and device_shutdown()
 * takes the SD host down with it.  So each step leaves a code in the PMU
 * scratch register.  The PMU is in the always-on domain, so a CRU soft reset
 * (the watchdog included) keeps the value; a real power-off loses it -- and
 * the case being chased is exactly the one where the board stays powered and
 * the watchdog resets it.
 *
 * The value left by the last hung run is printed by rk312x_boot_mode_init()
 * on the next boot.  device_shutdown() writes a printable 4-char device-name
 * tag instead of a number, so the boot line can name the device too.
 *
 * Diagnostic build: this is not meant to stay in a shipping kernel.
 */
#include <linux/types.h>

#ifdef CONFIG_ARCH_ROCKCHIP

#include <asm/io.h>
#include <linux/rockchip/iomap.h>

#define RK_PD_MARK_REG	(RK_PMU_VIRT + 0x44)	/* RK312X_PMU_SYS_REG3 */

static inline void rk_pd_mark(u32 code)
{
	writel_relaxed(code, RK_PD_MARK_REG);
	dsb();
}

/* First four characters of a device name, big-endian, space padded. */
static inline u32 rk_pd_tag(const char *n)
{
	u32 v = 0;
	int i;

	for (i = 0; i < 4; i++)
		v = (v << 8) | (n[i] ? (u8)n[i] : ' ');
	return v;
}

#else

static inline void rk_pd_mark(u32 code) { }
static inline u32 rk_pd_tag(const char *n) { return 0; }

#endif

#endif
