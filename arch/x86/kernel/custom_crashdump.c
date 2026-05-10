// SPDX-License-Identifier: GPL-2.0-only

/*
 * custom_crashdump.c - Custom crash metadata via standard vmcore
 *
 * This code stores custom device state plus selected panic CPU/system state in
 * an extra ELF PT_NOTE area that becomes part of the standard /proc/vmcore
 * output.
 */

#include <linux/crash_core.h>
#include <linux/crash_reserve.h>
#include <linux/crc32.h>
#include <linux/elf.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/smp.h>
#include <linux/swap.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmcore_info.h>
#include <uapi/linux/sysinfo.h>

#include <asm/apic.h>
#include <asm-generic/irq_regs.h>
#include <asm/crash.h>
#include <asm/cpuid/api.h>
#include <asm/debugreg.h>
#include <asm/desc.h>
#include <asm/fpu/sched.h>
#include <asm/fpu/types.h>
#include <asm/fpu/xcr.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/processor.h>
#include <asm/special_insns.h>
#include <asm/tsc.h>

#include "fpu/internal.h"

#define CUSTOM_TEST_VENDOR_ID        0x1d5f
#define CUSTOM_TEST_DEVICE_ID        0xcafe
#define CUSTOM_NMI_CFG_DWORD         0x40
#define CUSTOM_VMCOREDD_MAGIC        0x4344564d
#define CUSTOM_VMCOREDD_VERSION      7
#define CUSTOM_CRASH_NOTE_NAME       "X86CUSTOM"
#define CUSTOM_CRASH_NOTE_TYPE       0x58434e4d
#define CUSTOM_CFG_DWORD_COUNT       48
#define CUSTOM_MMIO_REG_COUNT        64
#define CUSTOM_PIO_REG_COUNT         16
#define CUSTOM_MMIO_INDEX_COUNT      32
#define CUSTOM_PIO_INDEX_COUNT       16
#define CUSTOM_MMIO_TABLE_COUNT      32
#define CUSTOM_QUEUE_REG_COUNT       8
#define CUSTOM_CPUID_LEAF_COUNT      4
#define CUSTOM_MAX_TEST_DEVICES      8
#define CUSTOM_MAX_CAPTURE_CPUS      NR_CPUS
#define CUSTOM_MAX_CONTEXTS_PER_CPU  5
#define CUSTOM_CONTEXT_STACK_BYTES   512
#define CUSTOM_MAX_XSAVE_AREA_SIZE   16384
#define CUSTOM_MSR_ENTRY_COUNT       24
#define CUSTOM_APIC_VECTOR_REGS      8

#define CUSTOM_MMIO_INDEX_SEL        0x100
#define CUSTOM_MMIO_INDEX_DATA       0x104
#define CUSTOM_MMIO_TABLE_BASE       0x200
#define CUSTOM_MMIO_QUEUE_BASE       0x300

#define CUSTOM_PIO_INDEX_SEL         0x40
#define CUSTOM_PIO_INDEX_DATA        0x44

#define CUSTOM_SECTION_DEVICE_STATE  1
#define CUSTOM_SECTION_CPU_STATE     2
#define CUSTOM_SECTION_SYSTEM_STATE  3
#define CUSTOM_SECTION_CONTEXT_STATE 4
#define CUSTOM_SECTION_FPU_STATE     5
#define CUSTOM_SECTION_MSR_STATE     6
#define CUSTOM_SECTION_APIC_STATE    7

#define CUSTOM_CRASH_NOTE_NAME_BYTES ALIGN(sizeof(CUSTOM_CRASH_NOTE_NAME), 4)
#define CUSTOM_CRASH_NOTE_BYTES      (1024 * 1024)

#define CUSTOM_CONTEXT_INDEX_TASK    0
#define CUSTOM_CONTEXT_INDEX_IRQ     1
#define CUSTOM_CONTEXT_INDEX_NMI     2
#define CUSTOM_CONTEXT_INDEX_IPI     3
#define CUSTOM_CONTEXT_INDEX_EXC     4

struct custom_vmcoredd_header {
	u32 magic;
	u32 version;
	u32 total_size;
	u32 payload_crc;
	u32 section_count;
	u32 flags;
	u32 reserved0;
	u32 reserved1;
};

struct custom_vmcoredd_section {
	u32 type;
	u32 size;
};

struct custom_vmcoredd_cpuid_leaf {
	u32 leaf;
	u32 subleaf;
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
};

struct custom_vmcoredd_device_state {
	u32 vendor_id;
	u32 device_id;
	u32 domain;
	u32 bus_devfn;
	u32 profile;
	u32 instance_id;
	u32 cfg_dword_count;
	u32 mmio_reg_count;
	u32 pio_reg_count;
	u32 mmio_index_count;
	u32 pio_index_count;
	u32 mmio_table_count;
	u32 queue_reg_count;
	u32 mmio_index;
	u32 pio_index;
	u32 class_revision;
	u32 pci_cfg_space[CUSTOM_CFG_DWORD_COUNT];
	u32 mmio_regs[CUSTOM_MMIO_REG_COUNT];
	u32 pio_regs[CUSTOM_PIO_REG_COUNT];
	u32 mmio_indexed[CUSTOM_MMIO_INDEX_COUNT];
	u32 pio_indexed[CUSTOM_PIO_INDEX_COUNT];
	u32 mmio_table[CUSTOM_MMIO_TABLE_COUNT];
	u32 queue_regs[CUSTOM_QUEUE_REG_COUNT];
};

struct custom_vmcoredd_cpu_state {
	u32 cpu_id;
	u32 valid;
	u64 tsc;
	u64 cr0;
	u64 cr2;
	u64 cr3;
	u64 cr4;
	u64 cr8;
	u64 dr0;
	u64 dr1;
	u64 dr2;
	u64 dr3;
	u64 dr6;
	u64 dr7;
	u64 efer;
	u64 pat;
	u64 fs_base;
	u64 gs_base;
	u64 kernel_gs_base;
	u64 tsc_aux;
	u64 apic_base;
	u64 xcr0;
	u64 xstate_in_use;
	struct desc_ptr gdt;
	struct desc_ptr idt;
	u16 ldtr;
	u16 tr;
	u32 pkru;
	u32 reserved1;
	struct custom_vmcoredd_cpuid_leaf cpuid[CUSTOM_CPUID_LEAF_COUNT];
};

struct custom_vmcoredd_system_state {
	u64 jiffies;
	u64 real_time_sec;
	u64 real_time_nsec;
	u64 totalram;
	u64 freeram;
	u64 sharedram;
	u64 bufferram;
	u64 totalswap;
	u64 freeswap;
	u64 totalhigh;
	u64 freehigh;
	u32 mem_unit;
	u32 procs;
	u64 loads[3];
	u64 uptime;
};

struct custom_vmcoredd_context_state {
	u32 cpu_id;
	u32 source;
	u32 valid;
	u32 stack_len;
	u32 stack_crc;
	u32 trap_nr;
	u32 signr;
	u64 ip;
	u64 sp;
	u64 flags;
	u64 cs;
	u64 ss;
	u64 ax;
	u64 bx;
	u64 cx;
	u64 dx;
	u64 si;
	u64 di;
	u64 bp;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 orig_ax;
	u8 stack_snapshot[CUSTOM_CONTEXT_STACK_BYTES];
} __packed;

struct custom_vmcoredd_fpu_state {
	u32 cpu_id;
	u32 valid;
	u32 area_size;
	u32 reserved0;
	u64 xfeatures_mask;
	u8 xsave_area[CUSTOM_MAX_XSAVE_AREA_SIZE] __aligned(64);
};

struct custom_vmcoredd_msr_entry {
	u32 msr;
	s32 status;
	u64 value;
};

struct custom_vmcoredd_msr_state {
	u32 cpu_id;
	u32 entry_count;
	struct custom_vmcoredd_msr_entry entries[CUSTOM_MSR_ENTRY_COUNT];
};

struct custom_vmcoredd_apic_state {
	u32 cpu_id;
	u32 valid;
	u32 x2apic_enabled;
	u32 id;
	u32 version;
	u32 tpr;
	u32 ppr;
	u32 ldr;
	u32 dfr;
	u32 spiv;
	u32 esr;
	u32 lvtt;
	u32 lvtpc;
	u32 lvt0;
	u32 lvt1;
	u32 lvterr;
	u32 tmict;
	u32 tmcct;
	u32 tdcr;
	u32 isr[CUSTOM_APIC_VECTOR_REGS];
	u32 tmr[CUSTOM_APIC_VECTOR_REGS];
	u32 irr[CUSTOM_APIC_VECTOR_REGS];
};

struct custom_bound_test_device {
	struct pci_dev *pdev;
	void __iomem *mmio;
	resource_size_t pio;
};

static const u32 custom_tracked_msrs[CUSTOM_MSR_ENTRY_COUNT] = {
	MSR_EFER,
	MSR_IA32_CR_PAT,
	MSR_FS_BASE,
	MSR_GS_BASE,
	MSR_KERNEL_GS_BASE,
	MSR_TSC_AUX,
	MSR_IA32_APICBASE,
	MSR_STAR,
	MSR_LSTAR,
	MSR_CSTAR,
	MSR_SYSCALL_MASK,
	MSR_IA32_SYSENTER_CS,
	MSR_IA32_SYSENTER_ESP,
	MSR_IA32_SYSENTER_EIP,
	MSR_IA32_FEAT_CTL,
	MSR_IA32_MISC_ENABLE,
	MSR_IA32_DEBUGCTLMSR,
	MSR_IA32_MCG_CAP,
	MSR_IA32_MCG_STATUS,
	MSR_IA32_TSC,
	MSR_IA32_SPEC_CTRL,
	MSR_IA32_ARCH_CAPABILITIES,
	MSR_IA32_TSX_CTRL,
	MSR_IA32_FLUSH_CMD,
};

static struct custom_bound_test_device custom_test_devices[CUSTOM_MAX_TEST_DEVICES];
static struct custom_vmcoredd_device_state custom_last_device_states[CUSTOM_MAX_TEST_DEVICES];
static unsigned int custom_bound_device_count;
static unsigned int custom_last_device_count;
static struct custom_vmcoredd_system_state custom_last_system_state;
static struct custom_vmcoredd_cpu_state custom_cpu_states[CUSTOM_MAX_CAPTURE_CPUS];
static struct custom_vmcoredd_fpu_state custom_fpu_states[CUSTOM_MAX_CAPTURE_CPUS];
static struct custom_vmcoredd_msr_state custom_msr_states[CUSTOM_MAX_CAPTURE_CPUS];
static struct custom_vmcoredd_apic_state custom_apic_states[CUSTOM_MAX_CAPTURE_CPUS];
static struct custom_vmcoredd_context_state
	custom_cpu_contexts[CUSTOM_MAX_CAPTURE_CPUS][CUSTOM_MAX_CONTEXTS_PER_CPU];
static void *custom_vmcore_note;
static phys_addr_t custom_vmcore_note_phys;
static size_t custom_vmcore_note_size;

static int __init custom_reserve_vmcore_note_buffer(void);
static void custom_vmcore_note_prepare(void);
void custom_crashdump_capture(void);
void custom_crashdump_save_cpu(struct pt_regs *regs, int cpu, u32 source);
static void custom_vmcoreinfo_extra_append(void);

static struct custom_vmcoredd_header *custom_vmcore_note_desc(void *note_buf)
{
	return (struct custom_vmcoredd_header *)((u8 *)note_buf +
		sizeof(struct elf_note) + CUSTOM_CRASH_NOTE_NAME_BYTES);
}

static bool __init custom_range_overlaps_resource(phys_addr_t start,
					 size_t size,
					 const struct resource *res)
{
	phys_addr_t end;

	if (res->end <= res->start)
		return false;

	end = start + size - 1;
	return start <= res->end && end >= res->start;
}

static int __init custom_reserve_vmcore_note_buffer(void)
{
	if (!crashk_res.end || crashk_res.end <= crashk_res.start)
		return 0;

	custom_vmcore_note = alloc_pages_exact(CUSTOM_CRASH_NOTE_BYTES,
					      GFP_KERNEL | __GFP_ZERO);
	if (!custom_vmcore_note) {
		pr_warn("custom crashdump: failed to allocate vmcore note buffer\n");
		return -ENOMEM;
	}

	custom_vmcore_note_phys = virt_to_phys(custom_vmcore_note);
	if (custom_range_overlaps_resource(custom_vmcore_note_phys,
					   CUSTOM_CRASH_NOTE_BYTES,
					   &crashk_res) ||
		    custom_range_overlaps_resource(custom_vmcore_note_phys,
					   CUSTOM_CRASH_NOTE_BYTES,
					   &crashk_low_res)) {
		pr_warn("custom crashdump: allocated vmcore note buffer overlaps crashkernel reservation\n");
		free_pages_exact(custom_vmcore_note, CUSTOM_CRASH_NOTE_BYTES);
		custom_vmcore_note = NULL;
		custom_vmcore_note_phys = 0;
		return -ENOMEM;
	}

	pr_info("custom crashdump: reserved vmcore note buffer at %pa size=%u\n",
		&custom_vmcore_note_phys, CUSTOM_CRASH_NOTE_BYTES);

	return 0;
}
early_initcall(custom_reserve_vmcore_note_buffer);

static __always_inline u64 custom_read_cr8(void)
{
	u64 value;

	asm volatile("mov %%cr8,%0" : "=r" (value));
	return value;
}

static __always_inline void custom_store_ldtr_tr(u16 *ldtr, u16 *tr)
{
	asm volatile("sldt %0" : "=rm" (*ldtr));
	asm volatile("str %0" : "=rm" (*tr));
}

static int custom_rdmsrl_capture(u32 msr, u64 *value)
{
	int ret;

	ret = rdmsrq_safe(msr, value);
	if (ret)
		*value = 0;
	return ret;
}

static void custom_capture_cpuid_leaf(struct custom_vmcoredd_cpuid_leaf *leaf,
				      u32 op, u32 subleaf)
{
	leaf->leaf = op;
	leaf->subleaf = subleaf;
	cpuid_count(op, subleaf, &leaf->eax, &leaf->ebx, &leaf->ecx, &leaf->edx);
}

static int custom_find_bound_device_slot(struct pci_dev *pdev)
{
	unsigned int index;

	for (index = 0; index < CUSTOM_MAX_TEST_DEVICES; index++) {
		if (custom_test_devices[index].pdev == pdev)
			return index;
	}

	return -1;
}

static int custom_alloc_bound_device_slot(void)
{
	unsigned int index;

	for (index = 0; index < CUSTOM_MAX_TEST_DEVICES; index++) {
		if (!custom_test_devices[index].pdev)
			return index;
	}

	return -1;
}

static void custom_init_device_state_defaults(struct custom_vmcoredd_device_state *state)
{
	memset(state, 0, sizeof(*state));
	state->vendor_id = CUSTOM_TEST_VENDOR_ID;
	state->device_id = CUSTOM_TEST_DEVICE_ID;
	state->cfg_dword_count = CUSTOM_CFG_DWORD_COUNT;
	state->mmio_reg_count = CUSTOM_MMIO_REG_COUNT;
	state->pio_reg_count = CUSTOM_PIO_REG_COUNT;
	state->mmio_index_count = CUSTOM_MMIO_INDEX_COUNT;
	state->pio_index_count = CUSTOM_PIO_INDEX_COUNT;
	state->mmio_table_count = CUSTOM_MMIO_TABLE_COUNT;
	state->queue_reg_count = CUSTOM_QUEUE_REG_COUNT;
	state->mmio_index = 0xffffffff;
	state->pio_index = 0xffffffff;
	memset(state->pci_cfg_space, 0xff, sizeof(state->pci_cfg_space));
	memset(state->mmio_regs, 0xff, sizeof(state->mmio_regs));
	memset(state->pio_regs, 0xff, sizeof(state->pio_regs));
	memset(state->mmio_indexed, 0xff, sizeof(state->mmio_indexed));
	memset(state->pio_indexed, 0xff, sizeof(state->pio_indexed));
	memset(state->mmio_table, 0xff, sizeof(state->mmio_table));
	memset(state->queue_regs, 0xff, sizeof(state->queue_regs));
}

static void custom_cache_pci_cfg_space(struct pci_dev *pdev,
				      struct custom_vmcoredd_device_state *state)
{
	unsigned int index;

	for (index = 0; index < CUSTOM_CFG_DWORD_COUNT; index++)
		pci_read_config_dword(pdev, CUSTOM_NMI_CFG_DWORD + (index * sizeof(u32)),
				      &state->pci_cfg_space[index]);
}

static void custom_cache_mmio_state(void __iomem *mmio,
				   struct custom_vmcoredd_device_state *state)
{
	unsigned int index;
	u32 selector;

	if (!mmio)
		return;

	for (index = 0; index < CUSTOM_MMIO_REG_COUNT; index++)
		state->mmio_regs[index] = ioread32(mmio + (index * sizeof(u32)));

	selector = ioread32(mmio + CUSTOM_MMIO_INDEX_SEL);
	state->mmio_index = selector;

	for (index = 0; index < CUSTOM_MMIO_INDEX_COUNT; index++) {
		iowrite32(index, mmio + CUSTOM_MMIO_INDEX_SEL);
		state->mmio_indexed[index] = ioread32(mmio + CUSTOM_MMIO_INDEX_DATA);
	}
	iowrite32(selector, mmio + CUSTOM_MMIO_INDEX_SEL);

	for (index = 0; index < CUSTOM_MMIO_TABLE_COUNT; index++) {
		state->mmio_table[index] =
			ioread32(mmio + CUSTOM_MMIO_TABLE_BASE + (index * sizeof(u32)));
	}

	for (index = 0; index < CUSTOM_QUEUE_REG_COUNT; index++) {
		state->queue_regs[index] =
			ioread32(mmio + CUSTOM_MMIO_QUEUE_BASE + (index * sizeof(u32)));
	}
}

static void custom_cache_pio_state(resource_size_t pio,
				  struct custom_vmcoredd_device_state *state)
{
	unsigned int index;
	u32 selector;

	if (!pio)
		return;

	for (index = 0; index < CUSTOM_PIO_REG_COUNT; index++)
		state->pio_regs[index] = inl(pio + (index * sizeof(u32)));

	selector = inl(pio + CUSTOM_PIO_INDEX_SEL);
	state->pio_index = selector;

	for (index = 0; index < CUSTOM_PIO_INDEX_COUNT; index++) {
		outl(index, pio + CUSTOM_PIO_INDEX_SEL);
		state->pio_indexed[index] = inl(pio + CUSTOM_PIO_INDEX_DATA);
	}
	outl(selector, pio + CUSTOM_PIO_INDEX_SEL);
}

#ifdef CONFIG_CUSTOM_CRASHDUMP_NMI_TEST_DEV
static int custom_crashdump_test_probe(struct pci_dev *pdev,
				      const struct pci_device_id *id)
{
	void __iomem *mmio;
	resource_size_t pio = 0;
	int slot;
	u16 vendor = 0;
	u16 device = 0;

	slot = custom_alloc_bound_device_slot();
	if (slot < 0)
		return -ENOSPC;

	if (pcim_enable_device(pdev))
		return -ENODEV;

	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM))
		return -ENODEV;

	mmio = pcim_iomap(pdev, 0, 0);
	if (!mmio)
		return -ENODEV;

	if (pci_resource_flags(pdev, 1) & IORESOURCE_IO)
		pio = pci_resource_start(pdev, 1);

	custom_test_devices[slot].pdev = pdev;
	custom_test_devices[slot].mmio = mmio;
	custom_test_devices[slot].pio = pio;

	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device);

	pr_info("custom crashdump pci test device[%d] bound %04x:%04x mmio=%pa pio=%pa\n",
		slot, vendor, device, &pdev->resource[0].start, &pio);

	return 0;
}

static void custom_crashdump_test_remove(struct pci_dev *pdev)
{
	int slot;

	slot = custom_find_bound_device_slot(pdev);
	if (slot < 0)
		return;

	memset(&custom_test_devices[slot], 0, sizeof(custom_test_devices[slot]));
}

static const struct pci_device_id custom_crashdump_test_ids[] = {
	{ PCI_DEVICE(CUSTOM_TEST_VENDOR_ID, CUSTOM_TEST_DEVICE_ID) },
	{ 0, }
};

static struct pci_driver custom_crashdump_test_driver = {
	.name = "custom_crashdump_test",
	.id_table = custom_crashdump_test_ids,
	.probe = custom_crashdump_test_probe,
	.remove = custom_crashdump_test_remove,
};

builtin_pci_driver(custom_crashdump_test_driver);
#endif /* CONFIG_CUSTOM_CRASHDUMP_NMI_TEST_DEV */

static void custom_collect_device_state(const struct custom_bound_test_device *bound,
				       struct custom_vmcoredd_device_state *state)
{
	custom_init_device_state_defaults(state);
	if (!bound->pdev)
		return;

	state->vendor_id = bound->pdev->vendor;
	state->device_id = bound->pdev->device;
	state->domain = pci_domain_nr(bound->pdev->bus);
	state->bus_devfn = ((u32)bound->pdev->bus->number << 8) | bound->pdev->devfn;
	state->class_revision = bound->pdev->class;
	pci_read_config_dword(bound->pdev, 0x44, &state->profile);
	pci_read_config_dword(bound->pdev, 0x48, &state->instance_id);

	custom_cache_pci_cfg_space(bound->pdev, state);
	custom_cache_mmio_state(bound->mmio, state);
	custom_cache_pio_state(bound->pio, state);
}

static void custom_collect_device_states(void)
{
	unsigned int index;

	custom_bound_device_count = 0;
	custom_last_device_count = 0;
	for (index = 0; index < CUSTOM_MAX_TEST_DEVICES; index++) {
		if (!custom_test_devices[index].pdev)
			continue;
		custom_bound_device_count++;
		custom_collect_device_state(&custom_test_devices[index],
					   &custom_last_device_states[custom_last_device_count]);
		custom_last_device_count++;
	}

	if (!custom_last_device_count) {
		struct custom_bound_test_device empty = { 0 };

		custom_collect_device_state(&empty, &custom_last_device_states[0]);
		custom_last_device_count = 1;
	}
}

static unsigned int custom_first_valid_cpu(void)
{
	unsigned int index;

	for (index = 0; index < CUSTOM_MAX_CAPTURE_CPUS; index++) {
		if (custom_cpu_states[index].valid)
			return index;
	}

	return CUSTOM_MAX_CAPTURE_CPUS;
}

static void custom_collect_cpu_state(struct custom_vmcoredd_cpu_state *state)
{
	u64 value;

	memset(state, 0, sizeof(*state));
	state->cpu_id = raw_smp_processor_id();
	state->valid = 1;
	state->tsc = rdtsc();
	state->cr0 = read_cr0();
	state->cr2 = read_cr2();
	state->cr3 = __read_cr3();
	state->cr4 = __read_cr4();
	state->cr8 = custom_read_cr8();
	get_debugreg(value, 0);
	state->dr0 = value;
	get_debugreg(value, 1);
	state->dr1 = value;
	get_debugreg(value, 2);
	state->dr2 = value;
	get_debugreg(value, 3);
	state->dr3 = value;
	get_debugreg(value, 6);
	state->dr6 = value;
	get_debugreg(value, 7);
	state->dr7 = value;

	custom_rdmsrl_capture(MSR_EFER, &state->efer);
	custom_rdmsrl_capture(MSR_IA32_CR_PAT, &state->pat);
	custom_rdmsrl_capture(MSR_FS_BASE, &state->fs_base);
	custom_rdmsrl_capture(MSR_GS_BASE, &state->gs_base);
	custom_rdmsrl_capture(MSR_KERNEL_GS_BASE, &state->kernel_gs_base);
	custom_rdmsrl_capture(MSR_TSC_AUX, &state->tsc_aux);
	custom_rdmsrl_capture(MSR_IA32_APICBASE, &state->apic_base);

	native_store_gdt(&state->gdt);
	store_idt(&state->idt);
	custom_store_ldtr_tr(&state->ldtr, &state->tr);
	if (boot_cpu_has(X86_FEATURE_OSPKE))
		state->pkru = rdpkru();

	if (boot_cpu_has(X86_FEATURE_OSXSAVE))
		state->xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
	if (boot_cpu_has(X86_FEATURE_XGETBV1))
		state->xstate_in_use = xfeatures_in_use();

	custom_capture_cpuid_leaf(&state->cpuid[0], 0x0, 0x0);
	custom_capture_cpuid_leaf(&state->cpuid[1], 0x1, 0x0);
	custom_capture_cpuid_leaf(&state->cpuid[2], 0x7, 0x0);
	custom_capture_cpuid_leaf(&state->cpuid[3], 0xd, 0x0);
}

static void custom_collect_system_state(struct custom_vmcoredd_system_state *state)
{
	struct sysinfo info = { 0 };
	struct timespec64 ts;

	memset(state, 0, sizeof(*state));
	si_meminfo(&info);
	si_swapinfo(&info);
	ktime_get_real_ts64(&ts);

	state->jiffies = get_jiffies_64();
	state->real_time_sec = ts.tv_sec;
	state->real_time_nsec = ts.tv_nsec;
	state->totalram = info.totalram;
	state->freeram = info.freeram;
	state->sharedram = info.sharedram;
	state->bufferram = info.bufferram;
	state->totalswap = info.totalswap;
	state->freeswap = info.freeswap;
	state->totalhigh = info.totalhigh;
	state->freehigh = info.freehigh;
	state->mem_unit = info.mem_unit;
	state->procs = info.procs;
	state->loads[0] = info.loads[0];
	state->loads[1] = info.loads[1];
	state->loads[2] = info.loads[2];
	state->uptime = info.uptime;
}

static void custom_capture_stack_snapshot(struct custom_vmcoredd_context_state *state,
					 const void *stack_ptr)
{
	unsigned int size = CUSTOM_CONTEXT_STACK_BYTES;

	state->stack_len = 0;
	state->stack_crc = 0;
	memset(state->stack_snapshot, 0, sizeof(state->stack_snapshot));
	if (!stack_ptr)
		return;
	if ((unsigned long)stack_ptr < TASK_SIZE_MAX)
		return;
	if (copy_from_kernel_nofault(state->stack_snapshot, stack_ptr, size))
		return;
	state->stack_len = size;
	state->stack_crc = crc32_le(0, state->stack_snapshot, size);
}

static void custom_fill_context_from_regs(struct custom_vmcoredd_context_state *state,
				     const struct pt_regs *regs, u32 source,
				     u32 trap_nr, u32 signr)
{
	memset(state, 0, sizeof(*state));
	state->cpu_id = raw_smp_processor_id();
	state->source = source;
	state->trap_nr = trap_nr;
	state->signr = signr;
	if (!regs)
		return;

	state->valid = 1;
	state->ip = regs->ip;
	state->sp = regs->sp;
	state->flags = regs->flags;
	state->cs = regs->cs;
	state->ss = regs->ss;
	state->ax = regs->ax;
	state->bx = regs->bx;
	state->cx = regs->cx;
	state->dx = regs->dx;
	state->si = regs->si;
	state->di = regs->di;
	state->bp = regs->bp;
	state->r8 = regs->r8;
	state->r9 = regs->r9;
	state->r10 = regs->r10;
	state->r11 = regs->r11;
	state->r12 = regs->r12;
	state->r13 = regs->r13;
	state->r14 = regs->r14;
	state->r15 = regs->r15;
	state->orig_ax = regs->orig_ax;
	custom_capture_stack_snapshot(state, (const void *)regs->sp);
}

static void custom_collect_fpu_state(struct custom_vmcoredd_fpu_state *state,
				 bool live)
{
	struct fpu *fpu = x86_task_fpu(current);
	const struct fpstate *fpstate;
	u32 area_size;

	memset(state, 0, sizeof(*state));
	state->cpu_id = raw_smp_processor_id();
	if (!fpu || !fpu->fpstate)
		fpstate = &init_fpstate;
	else
		fpstate = fpu->fpstate;

	state->valid = 1;
	if (live) {
		fpregs_lock();
		if (!test_thread_flag(TIF_NEED_FPU_LOAD))
			save_fpregs_to_fpstate(fpu);
	}
	area_size = min_t(u32, fpstate->size ?: fpu_kernel_cfg.default_size,
				 CUSTOM_MAX_XSAVE_AREA_SIZE);
	state->area_size = area_size;
	state->xfeatures_mask = fpstate->xfeatures;
	if (area_size)
		memcpy(state->xsave_area, &fpstate->regs, area_size);
	if (live)
		fpregs_unlock();
}

static void custom_collect_msr_state(struct custom_vmcoredd_msr_state *state)
{
	unsigned int index;

	memset(state, 0, sizeof(*state));
	state->cpu_id = raw_smp_processor_id();
	state->entry_count = CUSTOM_MSR_ENTRY_COUNT;
	for (index = 0; index < CUSTOM_MSR_ENTRY_COUNT; index++) {
		state->entries[index].msr = custom_tracked_msrs[index];
		state->entries[index].status =
			custom_rdmsrl_capture(custom_tracked_msrs[index],
					     &state->entries[index].value);
	}
}

static void custom_collect_apic_state(struct custom_vmcoredd_apic_state *state)
{
	unsigned int index;

	memset(state, 0, sizeof(*state));
	state->cpu_id = raw_smp_processor_id();
	if (!boot_cpu_has(X86_FEATURE_APIC))
		return;

	state->valid = 1;
	state->x2apic_enabled = x2apic_enabled();
	state->id = apic_read(APIC_ID);
	state->version = apic_read(APIC_LVR);
	state->tpr = apic_read(APIC_TASKPRI);
	state->ppr = apic_read(APIC_PROCPRI);
	state->ldr = apic_read(APIC_LDR);
	state->dfr = apic_read(APIC_DFR);
	state->spiv = apic_read(APIC_SPIV);
	state->esr = apic_read(APIC_ESR);
	state->lvtt = apic_read(APIC_LVTT);
	state->lvtpc = apic_read(APIC_LVTPC);
	state->lvt0 = apic_read(APIC_LVT0);
	state->lvt1 = apic_read(APIC_LVT1);
	state->lvterr = apic_read(APIC_LVTERR);
	state->tmict = apic_read(APIC_TMICT);
	state->tmcct = apic_read(APIC_TMCCT);
	state->tdcr = apic_read(APIC_TDCR);
	for (index = 0; index < CUSTOM_APIC_VECTOR_REGS; index++) {
		state->isr[index] = apic_read(APIC_ISR + (index * 0x10));
		state->tmr[index] = apic_read(APIC_TMR + (index * 0x10));
		state->irr[index] = apic_read(APIC_IRR + (index * 0x10));
	}
}

static void custom_collect_cpu_bundle(u32 cpu, bool live_fpu)
{
	if (cpu >= CUSTOM_MAX_CAPTURE_CPUS)
		return;

	custom_collect_cpu_state(&custom_cpu_states[cpu]);
	custom_collect_fpu_state(&custom_fpu_states[cpu], live_fpu);
	custom_collect_msr_state(&custom_msr_states[cpu]);
	custom_collect_apic_state(&custom_apic_states[cpu]);
}

static unsigned int custom_context_index(u32 source)
{
	switch (source) {
	case CUSTOM_CONTEXT_SOURCE_TASK:
		return CUSTOM_CONTEXT_INDEX_TASK;
	case CUSTOM_CONTEXT_SOURCE_IRQ:
		return CUSTOM_CONTEXT_INDEX_IRQ;
	case CUSTOM_CONTEXT_SOURCE_NMI:
		return CUSTOM_CONTEXT_INDEX_NMI;
	case CUSTOM_CONTEXT_SOURCE_IPI:
		return CUSTOM_CONTEXT_INDEX_IPI;
	case CUSTOM_CONTEXT_SOURCE_EXCEPTION:
		return CUSTOM_CONTEXT_INDEX_EXC;
	default:
		return CUSTOM_CONTEXT_INDEX_EXC;
	}
}

static unsigned int custom_count_valid_cpu_slots(void)
{
	unsigned int count = 0;
	unsigned int index;

	for (index = 0; index < CUSTOM_MAX_CAPTURE_CPUS; index++) {
		if (custom_cpu_states[index].valid)
			count++;
	}

	return count;
}

static unsigned int custom_count_context_valid(void)
{
	unsigned int count = 0;
	unsigned int cpu_index;
	unsigned int ctx_index;

	for (cpu_index = 0; cpu_index < CUSTOM_MAX_CAPTURE_CPUS; cpu_index++) {
		for (ctx_index = 0; ctx_index < CUSTOM_MAX_CONTEXTS_PER_CPU; ctx_index++) {
			if (custom_cpu_contexts[cpu_index][ctx_index].valid)
				count++;
		}
	}

	return count;
}

void custom_crashdump_save_cpu(struct pt_regs *regs, int cpu, u32 source)
{
	const struct pt_regs *irq_regs;
	struct custom_vmcoredd_context_state *contexts;
	bool live_fpu;
	unsigned int index;

	if (cpu < 0 || cpu >= CUSTOM_MAX_CAPTURE_CPUS)
		return;

	live_fpu = source != CUSTOM_CONTEXT_SOURCE_NMI &&
		   source != CUSTOM_CONTEXT_SOURCE_IPI;
	custom_collect_cpu_bundle(cpu, live_fpu);
	contexts = custom_cpu_contexts[cpu];

	custom_fill_context_from_regs(&contexts[CUSTOM_CONTEXT_INDEX_TASK],
				     task_pt_regs(current), CUSTOM_CONTEXT_SOURCE_TASK,
				     0, 0);

	irq_regs = get_irq_regs();
	custom_fill_context_from_regs(&contexts[CUSTOM_CONTEXT_INDEX_IRQ],
				     irq_regs, CUSTOM_CONTEXT_SOURCE_IRQ, 0, 0);

	index = custom_context_index(source);
	custom_fill_context_from_regs(&contexts[index], regs, source,
				     source == CUSTOM_CONTEXT_SOURCE_EXCEPTION ?
				     current->thread.trap_nr : 0,
				     0);
	if (source == CUSTOM_CONTEXT_SOURCE_NMI)
		custom_fill_context_from_regs(&contexts[CUSTOM_CONTEXT_INDEX_IPI], regs,
					     CUSTOM_CONTEXT_SOURCE_IPI, 0, 0);
	if (!regs && index == CUSTOM_CONTEXT_INDEX_EXC)
		contexts[index].cpu_id = cpu;
	if (cpu != raw_smp_processor_id()) {
		custom_cpu_states[cpu].cpu_id = cpu;
		custom_fpu_states[cpu].cpu_id = cpu;
		custom_msr_states[cpu].cpu_id = cpu;
		custom_apic_states[cpu].cpu_id = cpu;
		for (index = 0; index < CUSTOM_MAX_CONTEXTS_PER_CPU; index++)
			contexts[index].cpu_id = cpu;
	}
}

static u8 *custom_note_append_section(u8 *cursor, const u8 *limit, u32 type,
				      const void *data, u32 size, u32 *section_count)
{
	struct custom_vmcoredd_section *section = (struct custom_vmcoredd_section *)cursor;
	u32 aligned_size = ALIGN(size, 4);

	if (cursor + sizeof(*section) + aligned_size > limit)
		return NULL;

	section->type = type;
	section->size = size;
	cursor += sizeof(*section);
	memcpy(cursor, data, size);
	if (aligned_size > size)
		memset(cursor + size, 0, aligned_size - size);
	(*section_count)++;

	return cursor + aligned_size;
}

static u32 custom_context_section_size(const struct custom_vmcoredd_context_state *state)
{
	return offsetof(struct custom_vmcoredd_context_state, stack_snapshot) +
		state->stack_len;
}

static u32 custom_fpu_section_size(const struct custom_vmcoredd_fpu_state *state)
{
	return offsetof(struct custom_vmcoredd_fpu_state, xsave_area) +
		state->area_size;
}

void custom_crashdump_capture(void)
{
	if (!custom_cpu_states[raw_smp_processor_id()].valid)
		custom_crashdump_save_cpu(NULL, raw_smp_processor_id(),
					 CUSTOM_CONTEXT_SOURCE_EXCEPTION);

	if (!custom_vmcore_note)
		return;

	custom_collect_device_states();
	custom_collect_system_state(&custom_last_system_state);
	custom_vmcore_note_prepare();
}

static void custom_vmcoreinfo_extra_append(void)
{
	struct custom_vmcoredd_header *hdr;
	unsigned int cpu;

	if (!custom_vmcore_note_size)
		return;

	hdr = custom_vmcore_note_desc(custom_vmcore_note);

	vmcoreinfo_append_str("CUSTOM_NOTE_NAME=%s\n", CUSTOM_CRASH_NOTE_NAME);
	vmcoreinfo_append_str("CUSTOM_NOTE_TYPE=0x%x\n", CUSTOM_CRASH_NOTE_TYPE);
	vmcoreinfo_append_str("CUSTOM_NOTE_SIZE=%zu\n", custom_vmcore_note_size);
	vmcoreinfo_append_str("CUSTOM_SECTION_COUNT=%u\n", hdr->section_count);
	vmcoreinfo_append_str("CUSTOM_DEVICE_COUNT=%u\n", custom_bound_device_count);
	vmcoreinfo_append_str("CUSTOM_CPU_COUNT=%u\n", custom_count_valid_cpu_slots());
	vmcoreinfo_append_str("CUSTOM_CONTEXT_COUNT=%u\n", custom_count_context_valid());
	vmcoreinfo_append_str("CUSTOM_PCI_CFG40=0x%08x\n",
				 custom_last_device_states[0].pci_cfg_space[0]);
	vmcoreinfo_append_str("CUSTOM_MMIO32=0x%08x\n",
				 custom_last_device_states[0].mmio_regs[0]);
	vmcoreinfo_append_str("CUSTOM_IOPORT32=0x%08x\n",
				 custom_last_device_states[0].pio_regs[0]);
	cpu = custom_first_valid_cpu();
	if (cpu < CUSTOM_MAX_CAPTURE_CPUS) {
		vmcoreinfo_append_str("CUSTOM_CPU_ID=%u\n", custom_cpu_states[cpu].cpu_id);
		vmcoreinfo_append_str("CUSTOM_CPU_CR3=0x%llx\n", custom_cpu_states[cpu].cr3);
	}
	vmcoreinfo_append_str("CUSTOM_JIFFIES=0x%llx\n", custom_last_system_state.jiffies);
}

void arch_crash_save_vmcoreinfo_late(void)
{
	custom_vmcoreinfo_extra_append();
}

static void custom_vmcore_note_prepare(void)
{
	void *note_buf = custom_vmcore_note;
	struct elf_note *note = (struct elf_note *)note_buf;
	struct custom_vmcoredd_header *hdr = custom_vmcore_note_desc(note_buf);
	const u8 *limit = (u8 *)custom_vmcore_note + CUSTOM_CRASH_NOTE_BYTES -
		sizeof(struct elf_note);
	u8 *cursor = (u8 *)(hdr + 1);
	void *tail_note;
	unsigned int device_index;
	unsigned int cpu_index;
	unsigned int ctx_index;

	if (!note_buf) {
		custom_vmcore_note_size = 0;
		pr_warn_once("custom crashdump: vmcore note buffer is unavailable\n");
		return;
	}

	memset(note_buf, 0, CUSTOM_CRASH_NOTE_BYTES);

	hdr->magic = CUSTOM_VMCOREDD_MAGIC;
	hdr->version = CUSTOM_VMCOREDD_VERSION;
	hdr->section_count = 0;
	hdr->flags = 0;
	hdr->reserved0 = 0;
	hdr->reserved1 = 0;

	for (device_index = 0; device_index < custom_last_device_count; device_index++) {
		cursor = custom_note_append_section(cursor, limit,
					   CUSTOM_SECTION_DEVICE_STATE,
					   &custom_last_device_states[device_index],
					   sizeof(custom_last_device_states[device_index]),
					   &hdr->section_count);
		if (!cursor)
			goto overflow;
	}

	cursor = custom_note_append_section(cursor, limit, CUSTOM_SECTION_SYSTEM_STATE,
					   &custom_last_system_state,
					   sizeof(custom_last_system_state),
					   &hdr->section_count);
	if (!cursor)
		goto overflow;

	for (cpu_index = 0; cpu_index < CUSTOM_MAX_CAPTURE_CPUS; cpu_index++) {
		if (!custom_cpu_states[cpu_index].valid)
			continue;

		cursor = custom_note_append_section(cursor, limit, CUSTOM_SECTION_CPU_STATE,
					   &custom_cpu_states[cpu_index],
					   sizeof(custom_cpu_states[cpu_index]),
					   &hdr->section_count);
		if (!cursor)
			goto overflow;

		for (ctx_index = 0; ctx_index < CUSTOM_MAX_CONTEXTS_PER_CPU; ctx_index++) {
			if (!custom_cpu_contexts[cpu_index][ctx_index].valid)
				continue;
			cursor = custom_note_append_section(cursor, limit,
						   CUSTOM_SECTION_CONTEXT_STATE,
						   &custom_cpu_contexts[cpu_index][ctx_index],
					   custom_context_section_size(&custom_cpu_contexts[cpu_index][ctx_index]),
						   &hdr->section_count);
			if (!cursor)
				goto overflow;
		}

		if (custom_fpu_states[cpu_index].valid) {
			cursor = custom_note_append_section(cursor, limit,
						   CUSTOM_SECTION_FPU_STATE,
						   &custom_fpu_states[cpu_index],
					   custom_fpu_section_size(&custom_fpu_states[cpu_index]),
						   &hdr->section_count);
			if (!cursor)
				goto overflow;
		}

		cursor = custom_note_append_section(cursor, limit, CUSTOM_SECTION_MSR_STATE,
					   &custom_msr_states[cpu_index],
					   sizeof(custom_msr_states[cpu_index]),
					   &hdr->section_count);
		if (!cursor)
			goto overflow;

		if (custom_apic_states[cpu_index].valid) {
			cursor = custom_note_append_section(cursor, limit,
						   CUSTOM_SECTION_APIC_STATE,
						   &custom_apic_states[cpu_index],
						   sizeof(custom_apic_states[cpu_index]),
						   &hdr->section_count);
			if (!cursor)
				goto overflow;
		}
	}

	hdr->total_size = cursor - (u8 *)hdr;
	hdr->payload_crc = 0;
	hdr->payload_crc = crc32_le(0, (u8 *)(hdr + 1), hdr->total_size - sizeof(*hdr));

	note->n_namesz = sizeof(CUSTOM_CRASH_NOTE_NAME);
	note->n_descsz = hdr->total_size;
	note->n_type = CUSTOM_CRASH_NOTE_TYPE;
	memcpy((u8 *)note_buf + sizeof(*note), CUSTOM_CRASH_NOTE_NAME,
	       sizeof(CUSTOM_CRASH_NOTE_NAME));
	tail_note = (u8 *)hdr + ALIGN(hdr->total_size, 4);
	final_note(tail_note);
	custom_vmcore_note_size = (u8 *)tail_note + sizeof(struct elf_note) -
		(u8 *)note_buf;

	pr_info("custom crashdump: vmcore note prepared size=%zu devices=%u sections=%u\n",
		custom_vmcore_note_size, custom_last_device_count, hdr->section_count);
	return;

overflow:
	custom_vmcore_note_size = 0;
	pr_warn("custom crashdump: vmcore note buffer exhausted\n");
}

phys_addr_t custom_crash_note_paddr(void)
{
	return custom_vmcore_note_phys;
}

size_t custom_crash_note_reserved_size(void)
{
	return custom_vmcore_note ? CUSTOM_CRASH_NOTE_BYTES : 0;
}
