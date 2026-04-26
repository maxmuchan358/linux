/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CRASH_H
#define _ASM_X86_CRASH_H

struct kimage;
struct pt_regs;

int crash_load_segments(struct kimage *image);
int crash_setup_memmap_entries(struct kimage *image,
                struct boot_params *params);
void crash_smp_send_stop(void);

#ifdef CONFIG_CUSTOM_CRASHDUMP_NMI
void custom_crashdump_capture(struct pt_regs *regs);
void custom_vmcoreinfo_extra_append(void);
#endif

#endif /* _ASM_X86_CRASH_H */
