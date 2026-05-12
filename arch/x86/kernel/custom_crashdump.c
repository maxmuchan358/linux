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
#include <asm/pci_x86.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/processor.h>
#include <asm/special_insns.h>
#include <asm/tsc.h>

#include "fpu/internal.h"

#define CUSTOM_TEST_VENDOR_ID        0x1d5f
#define CUSTOM_TEST_DEVICE_ID        0xcafe
#define CUSTOM_VMCOREDD_MAGIC        0x4344564d
#define CUSTOM_VMCOREDD_VERSION      7
#define CUSTOM_CRASH_NOTE_NAME       "X86CUSTOM"
#define CUSTOM_CRASH_NOTE_TYPE       0x58434e4d
#define CUSTOM_MAX_TEST_DEVICES      8
#define CUSTOM_MAX_CAPTURE_CPUS      NR_CPUS
#define CUSTOM_MAX_CONTEXTS_PER_CPU  5
#define CUSTOM_CONTEXT_STACK_BYTES   512
#define CUSTOM_MAX_XSAVE_AREA_SIZE   16384
#define CUSTOM_MSR_ENTRY_COUNT       24
#define CUSTOM_APIC_VECTOR_REGS      8
#define CUSTOM_CPUID_LEAF_COUNT      4

/* Device region types for custom_region_desc.type */
#define CUSTOM_REGION_CFG            0  /* PCI config space (pci_read_config_dword) */
#define CUSTOM_REGION_MMIO           1  /* MMIO via cached BAR iomap */
#define CUSTOM_REGION_PIO            2  /* I/O port via BAR base + offset */
#define CUSTOM_REGION_FIXED_PIO      3  /* Fixed absolute I/O port (offset = port addr) */
#define CUSTOM_REGION_ECAM           4  /* ECAM via kernel MMCFG mapping (offset within 4KB) */

#define CUSTOM_BAR_NONE              0xff  /* bar_mmio/bar_pio sentinel: no BAR */

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
#define CUSTOM_CONTEXT_INDEX_EXC     3
#define CUSTOM_CONTEXT_INDEX_PANIC   4

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

/*
 * Compile-time region descriptor: one entry per memory/IO region to capture.
 * offset and size must be multiples of 4 (dword-aligned).
 */
struct custom_region_desc {
	u32 type;    /* CUSTOM_REGION_CFG / MMIO / PIO */
	u32 offset;  /* byte offset from BAR or config-space base */
	u32 size;    /* byte count to read */
};

/*
 * Compile-time device descriptor: identifies a PCI device and lists the
 * regions to capture.  Defined statically; never modified at runtime.
 */
struct custom_device_desc {
	u16 vendor_id;
	u16 device_id;
	u8  bar_mmio;   /* BAR index for MMIO, CUSTOM_BAR_NONE if absent */
	u8  bar_pio;    /* BAR index for PIO,  CUSTOM_BAR_NONE if absent */
	u8  reserved[2];
	const struct custom_region_desc *regions;
	u32 region_count;
};

/*
 * Per-instance runtime state populated at probe time.
 * Virtual addresses are cached here so that no ioremap is needed at panic.
 */
struct custom_device_runtime {
	const struct custom_device_desc *desc;
	struct pci_dev    *pdev;
	void __iomem      *mmio_base;  /* cached virtual base for MMIO regions */
	resource_size_t    pio_base;   /* cached I/O port base (BAR-based PIO) */
	void __iomem      *ecam_base;  /* cached 4KB ECAM config page (kernel MMCFG mapping) */
};

/* Dump format: device identification header inside a DEVICE_STATE section */
struct custom_vmcoredd_device_header {
	u32 vendor_id;
	u32 device_id;
	u32 domain;
	u32 bus_devfn;
	u32 class_revision;
	u32 region_count;
};

/* Dump format: per-region header, immediately followed by 'size' bytes of data */
struct custom_vmcoredd_region_header {
	u32 type;
	u32 offset;
	u32 size;
	u32 reserved;
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

static struct custom_device_runtime custom_runtime_devices[CUSTOM_MAX_TEST_DEVICES];
static unsigned int custom_runtime_device_count;
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

#ifdef CONFIG_CUSTOM_CRASHDUMP_NMI_TEST_DEV
/*
 * Static region capture table for the test device (vendor=0x1d5f, device=0xcafe).
 * offset and size must be multiples of 4.
 */
static const struct custom_region_desc custom_test_regions[] = {
	{ CUSTOM_REGION_CFG,       0x00, 48 * sizeof(u32) },  /* first 48 dwords of config space */
	{ CUSTOM_REGION_MMIO,      0x00, 64 * sizeof(u32) },  /* first 64 dwords of MMIO BAR0 */
	{ CUSTOM_REGION_PIO,       0x00, 16 * sizeof(u32) },  /* first 16 dwords of PIO BAR1 */
	{ CUSTOM_REGION_FIXED_PIO, 0x80,  1 * sizeof(u32) },  /* port 0x80: POST code register */
	{ CUSTOM_REGION_FIXED_PIO, 0x61,  1 * sizeof(u32) },  /* port 0x61: System Control Port B */
	{ CUSTOM_REGION_FIXED_PIO, 0x64,  1 * sizeof(u32) },  /* port 0x64: KBC status */
	{ CUSTOM_REGION_FIXED_PIO, 0x70,  1 * sizeof(u32) },  /* port 0x70: RTC index */
	{ CUSTOM_REGION_FIXED_PIO, 0x92,  1 * sizeof(u32) },  /* port 0x92: Port A (fast A20) */
	{ CUSTOM_REGION_ECAM,      0x00, 16 * sizeof(u32) },  /* first 64 bytes via ECAM */
};

static const struct custom_device_desc custom_test_device_desc = {
	.vendor_id    = CUSTOM_TEST_VENDOR_ID,
	.device_id    = CUSTOM_TEST_DEVICE_ID,
	.bar_mmio     = 0,
	.bar_pio      = 1,
	.regions      = custom_test_regions,
	.region_count = ARRAY_SIZE(custom_test_regions),
};
#endif /* CONFIG_CUSTOM_CRASHDUMP_NMI_TEST_DEV */

#ifdef CONFIG_CUSTOM_CRASHDUMP_NMI_NET_DEV
/*
 * NIC diagnostic device (vendor=0x1d5f, device=0xd001)
 *
 * BAR0 MMIO layout:
 *   0x000-0x06c  28 direct regs: MAC, link, Rx/Tx stats, error counters, ctrl, PHY
 *   0x100-0x104   2 regs: indirect index select + indirect data window
 * BAR1 PIO:
 *   0x00-0x3c   16 dwords: cmd, status, DMA address, descriptor pointers, misc
 */
#define CUSTOM_NET_VENDOR_ID    0x1d5f
#define CUSTOM_NET_DEVICE_ID    0xd001

static const struct custom_region_desc custom_net_regions[] = {
	{ CUSTOM_REGION_CFG,  0x00,  16 * sizeof(u32) },  /* config space header (64 bytes) */
	{ CUSTOM_REGION_MMIO, 0x00,  28 * sizeof(u32) },  /* 0x000-0x06c: direct registers */
	{ CUSTOM_REGION_MMIO, 0x100,  2 * sizeof(u32) },  /* 0x100-0x104: indirect index/data */
	{ CUSTOM_REGION_PIO,  0x00,  16 * sizeof(u32) },  /* 0x00-0x3c: all PIO registers */
};

static const struct custom_device_desc custom_net_device_desc = {
	.vendor_id    = CUSTOM_NET_VENDOR_ID,
	.device_id    = CUSTOM_NET_DEVICE_ID,
	.bar_mmio     = 0,
	.bar_pio      = 1,
	.regions      = custom_net_regions,
	.region_count = ARRAY_SIZE(custom_net_regions),
};
#endif /* CONFIG_CUSTOM_CRASHDUMP_NMI_NET_DEV */

#ifdef CONFIG_CUSTOM_CRASHDUMP_NMI_STOR_DEV
/*
 * Storage controller diagnostic device (vendor=0x1d5f, device=0xd002)
 *
 * BAR0 MMIO layout (NVMe-style):
 *   0x000-0x03c  16 dwords: CAP, VS, INTMS/INTMC, CC, CSTS, NSSR, AQA, ASQ, ACQ,
 *                           CMBLOC, CMBSZ, BPINFO
 *   0x040-0x07c  16 dwords: extended controller registers
 *   0x200-0x27c  32 dwords: queue doorbells / firmware scratchpad
 */
#define CUSTOM_STOR_VENDOR_ID   0x1d5f
#define CUSTOM_STOR_DEVICE_ID   0xd002

static const struct custom_region_desc custom_stor_regions[] = {
	{ CUSTOM_REGION_CFG,  0x00,  16 * sizeof(u32) },  /* config space header (64 bytes) */
	{ CUSTOM_REGION_MMIO, 0x00,  16 * sizeof(u32) },  /* 0x000-0x03c: NVMe-style main regs */
	{ CUSTOM_REGION_MMIO, 0x040, 16 * sizeof(u32) },  /* 0x040-0x07c: extended regs */
	{ CUSTOM_REGION_MMIO, 0x200, 32 * sizeof(u32) },  /* 0x200-0x27c: doorbells/scratchpad */
};

static const struct custom_device_desc custom_stor_device_desc = {
	.vendor_id    = CUSTOM_STOR_VENDOR_ID,
	.device_id    = CUSTOM_STOR_DEVICE_ID,
	.bar_mmio     = 0,
	.bar_pio      = CUSTOM_BAR_NONE,
	.regions      = custom_stor_regions,
	.region_count = ARRAY_SIZE(custom_stor_regions),
};
#endif /* CONFIG_CUSTOM_CRASHDUMP_NMI_STOR_DEV */

/*
 * Table of all device descriptors to cache at initcall time.
 * Add a pointer here for each device type that should be captured at panic.
 */
static const struct custom_device_desc * const custom_device_descs[] = {
#ifdef CONFIG_CUSTOM_CRASHDUMP_NMI_TEST_DEV
	&custom_test_device_desc,
#endif
#ifdef CONFIG_CUSTOM_CRASHDUMP_NMI_NET_DEV
	&custom_net_device_desc,
#endif
#ifdef CONFIG_CUSTOM_CRASHDUMP_NMI_STOR_DEV
	&custom_stor_device_desc,
#endif
};

/*
 * Scan custom_device_descs[], find matching PCI devices, and cache their
 * virtual addresses.  Runs once at device_initcall; no ioremap at panic.
 */
static int __init custom_crashdump_cache_devices(void)
{
	unsigned int d;

	for (d = 0; d < ARRAY_SIZE(custom_device_descs); d++) {
		const struct custom_device_desc *desc = custom_device_descs[d];
		struct pci_dev *pdev = NULL;

		while ((pdev = pci_get_device(desc->vendor_id, desc->device_id,
					      pdev)) != NULL) {
			void __iomem *mmio = NULL;
			void __iomem *ecam = NULL;
			resource_size_t pio = 0;
			unsigned int slot, r;
			bool needs_ecam = false;

			if (custom_runtime_device_count >= CUSTOM_MAX_TEST_DEVICES) {
				pr_warn("custom crashdump: device table full, skipping %04x:%04x\n",
					desc->vendor_id, desc->device_id);
				pci_dev_put(pdev);
				pdev = NULL;
				break;
			}
			slot = custom_runtime_device_count;

			if (pci_enable_device(pdev)) {
				pr_warn("custom crashdump: failed to enable %04x:%04x\n",
					desc->vendor_id, desc->device_id);
				continue;
			}

			if (desc->bar_mmio != CUSTOM_BAR_NONE &&
			    (pci_resource_flags(pdev, desc->bar_mmio) & IORESOURCE_MEM)) {
				mmio = pci_iomap(pdev, desc->bar_mmio, 0);
				if (!mmio)
					pr_warn("custom crashdump: iomap failed for %04x:%04x BAR%u\n",
						desc->vendor_id, desc->device_id, desc->bar_mmio);
			}

			if (desc->bar_pio != CUSTOM_BAR_NONE &&
			    (pci_resource_flags(pdev, desc->bar_pio) & IORESOURCE_IO))
				pio = pci_resource_start(pdev, desc->bar_pio);

			for (r = 0; r < desc->region_count; r++) {
				if (desc->regions[r].type == CUSTOM_REGION_ECAM) {
					needs_ecam = true;
					break;
				}
			}
			if (needs_ecam) {
				struct pci_mmcfg_region *cfg =
					pci_mmconfig_lookup(pci_domain_nr(pdev->bus),
							    pdev->bus->number);
				if (cfg && cfg->virt)
					ecam = (void __iomem *)(cfg->virt +
						PCI_MMCFG_BUS_OFFSET(pdev->bus->number) +
						((u32)pdev->devfn << 12));
				if (!ecam)
					pr_warn("custom crashdump: ECAM not available for %04x:%04x\n",
						desc->vendor_id, desc->device_id);
			}

			custom_runtime_devices[slot].desc      = desc;
			custom_runtime_devices[slot].pdev      = pci_dev_get(pdev);
			custom_runtime_devices[slot].mmio_base = mmio;
			custom_runtime_devices[slot].pio_base  = pio;
			custom_runtime_devices[slot].ecam_base = ecam;
			custom_runtime_device_count++;

			pr_info("custom crashdump: cached device[%u] %04x:%04x mmio=%px pio=%pa ecam=%px\n",
				slot, pdev->vendor, pdev->device, mmio, &pio, ecam);
		}
	}
	return 0;
}
device_initcall(custom_crashdump_cache_devices);

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
	case CUSTOM_CONTEXT_SOURCE_EXCEPTION:
		return CUSTOM_CONTEXT_INDEX_EXC;
	case CUSTOM_CONTEXT_SOURCE_PANIC:
		return CUSTOM_CONTEXT_INDEX_PANIC;
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

	live_fpu = source != CUSTOM_CONTEXT_SOURCE_NMI;
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

/*
 * Compute the byte size of the data payload for one DEVICE_STATE section.
 * All region sizes must be multiples of 4, so no padding is needed.
 */
static u32 custom_device_section_size(const struct custom_device_desc *desc)
{
	u32 size = sizeof(struct custom_vmcoredd_device_header);
	u32 i;

	for (i = 0; i < desc->region_count; i++)
		size += sizeof(struct custom_vmcoredd_region_header) +
			desc->regions[i].size;
	return size;
}

/*
 * Write one DEVICE_STATE section directly into the PT_NOTE buffer.
 * Reads are performed using cached virtual addresses; no ioremap at panic.
 */
static u8 *custom_note_append_device(u8 *cursor, const u8 *limit,
				     const struct custom_device_runtime *dev,
				     u32 *section_count)
{
	const struct custom_device_desc *desc = dev->desc;
	struct custom_vmcoredd_section *sec;
	struct custom_vmcoredd_device_header *dh;
	u32 data_size = custom_device_section_size(desc);
	u32 i, j;

	if (cursor + sizeof(*sec) + data_size > limit)
		return NULL;

	sec = (struct custom_vmcoredd_section *)cursor;
	sec->type = CUSTOM_SECTION_DEVICE_STATE;
	sec->size = data_size;
	cursor += sizeof(*sec);

	dh = (struct custom_vmcoredd_device_header *)cursor;
	dh->vendor_id      = dev->pdev ? dev->pdev->vendor : 0;
	dh->device_id      = dev->pdev ? dev->pdev->device : 0;
	dh->domain         = dev->pdev ? pci_domain_nr(dev->pdev->bus) : 0;
	dh->bus_devfn      = dev->pdev ? ((u32)dev->pdev->bus->number << 8 |
					   dev->pdev->devfn) : 0;
	dh->class_revision = dev->pdev ? dev->pdev->class : 0;
	dh->region_count   = desc->region_count;
	cursor += sizeof(*dh);

	for (i = 0; i < desc->region_count; i++) {
		const struct custom_region_desc *rd = &desc->regions[i];
		struct custom_vmcoredd_region_header *rh;
		u32 *data;
		u32 nwords = rd->size / sizeof(u32);

		rh = (struct custom_vmcoredd_region_header *)cursor;
		rh->type     = rd->type;
		rh->offset   = rd->offset;
		rh->size     = rd->size;
		rh->reserved = 0;
		cursor += sizeof(*rh);

		data = (u32 *)cursor;
		switch (rd->type) {
		case CUSTOM_REGION_CFG:
			if (dev->pdev) {
				for (j = 0; j < nwords; j++)
					pci_read_config_dword(dev->pdev,
							      rd->offset + j * sizeof(u32),
							      &data[j]);
			} else {
				memset(data, 0xff, rd->size);
			}
			break;
		case CUSTOM_REGION_MMIO:
			if (dev->mmio_base) {
				for (j = 0; j < nwords; j++)
					data[j] = ioread32(dev->mmio_base +
							   rd->offset + j * sizeof(u32));
			} else {
				memset(data, 0xff, rd->size);
			}
			break;
		case CUSTOM_REGION_PIO:
			if (dev->pio_base) {
				for (j = 0; j < nwords; j++)
					data[j] = inl(dev->pio_base +
						      rd->offset + j * sizeof(u32));
			} else {
				memset(data, 0xff, rd->size);
			}
			break;
		case CUSTOM_REGION_FIXED_PIO:
			/* rd->offset is the absolute I/O port base address */
			for (j = 0; j < nwords; j++)
				data[j] = inl(rd->offset + j * sizeof(u32));
			break;
		case CUSTOM_REGION_ECAM:
			/* rd->offset is byte offset within the 4KB ECAM config page */
			if (dev->ecam_base) {
				for (j = 0; j < nwords; j++)
					data[j] = ioread32(dev->ecam_base +
							   rd->offset + j * sizeof(u32));
			} else {
				memset(data, 0xff, rd->size);
			}
			break;
		default:
			memset(data, 0xff, rd->size);
			break;
		}
		cursor += rd->size;
	}

	(*section_count)++;
	return cursor;
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
	vmcoreinfo_append_str("CUSTOM_DEVICE_COUNT=%u\n", custom_runtime_device_count);
	vmcoreinfo_append_str("CUSTOM_CPU_COUNT=%u\n", custom_count_valid_cpu_slots());
	vmcoreinfo_append_str("CUSTOM_CONTEXT_COUNT=%u\n", custom_count_context_valid());
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

	for (device_index = 0; device_index < custom_runtime_device_count; device_index++) {
		cursor = custom_note_append_device(cursor, limit,
						   &custom_runtime_devices[device_index],
						   &hdr->section_count);
		if (!cursor)
			goto overflow;
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
		custom_vmcore_note_size, custom_runtime_device_count, hdr->section_count);
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
