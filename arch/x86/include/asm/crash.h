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
enum custom_crashdump_context_source {
    CUSTOM_CONTEXT_SOURCE_TASK = 1,
    CUSTOM_CONTEXT_SOURCE_IRQ = 2,
    CUSTOM_CONTEXT_SOURCE_NMI = 3,
    CUSTOM_CONTEXT_SOURCE_IPI = 4,
    CUSTOM_CONTEXT_SOURCE_EXCEPTION = 5,
};

void custom_crashdump_save_cpu(struct pt_regs *regs, int cpu, u32 source);
void custom_crashdump_capture(void);
phys_addr_t custom_crash_note_paddr(void);
size_t custom_crash_note_reserved_size(void);
#endif

#endif /* _ASM_X86_CRASH_H */
