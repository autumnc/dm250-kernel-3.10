#ifndef _LINUX_WARP_DIAG_H
#define _LINUX_WARP_DIAG_H

/*
 * Coarse per-cpu "where am I right now" marker for hard-lockup diagnosis.
 *
 * When a cpu stops taking interrupts it cannot be IPI'd for a backtrace, and a
 * raw scan of its kernel stack is dominated by pt_regs (user register file)
 * and stale values, so it cannot name the frame the cpu is spinning in.  A
 * locklessly written per-cpu phase id, timestamped so the reader can tell a
 * live marker from a stale one, does name it.
 */
#if defined(CONFIG_PM_WARP) && defined(CONFIG_WARP_DIAG)

enum {
	WARP_PH_NONE = 0,
	WARP_PH_RUN_TIMERS,
	WARP_PH_CASCADE,
	WARP_PH_NEXT_TIMER,
	WARP_PH_GET_NEXT,
	WARP_PH_MIGRATE,
	WARP_PH_CONSOLE_LOCK,
	WARP_PH_FB_BLANK,
};

extern void warp_phase_set(unsigned int ph);
extern const char *warp_phase_name(unsigned int ph);

#define WARP_PHASE(x)	warp_phase_set(x)

#else

#define WARP_PHASE(x)	do { } while (0)

#endif /* CONFIG_PM_WARP */

#endif /* _LINUX_WARP_DIAG_H */
