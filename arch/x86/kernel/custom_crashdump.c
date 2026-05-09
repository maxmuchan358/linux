// SPDX-License-Identifier: GPL-2.0-only

#include <linux/crash_core.h>
#include <linux/crash_reserve.h>
#include <linux/ioport.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/kexec.h>
#include <linux/kmemleak.h>
#include <linux/memblock.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/vmcore_info.h>

#include <asm/apic.h>
#include <asm/cpufeature.h>
#include <asm/fpu/xcr.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/processor.h>
#include <asm/special_insns.h>
#include <asm/tsc.h>

#define CUSTOM_CRASH_NOTE_NAME            "X86CUSTOM"
#define CUSTOM_CRASH_NOTE_TYPE            0x58434e4d

#define CUSTOM_NOTE_MAGIC                 0x434e4f54
#define CUSTOM_NOTE_VERSION               3
#define CUSTOM_LOAD_MAGIC                 0x434c4f44
#define CUSTOM_LOAD_VERSION               3

#define CUSTOM_NOTE_BYTES                 PAGE_SIZE
#define CUSTOM_DEVICE_DUMP_BYTES          SZ_256K

#define CUSTOM_TEST_VENDOR_ID             0x1d5f
#define CUSTOM_TEST_DEVICE_ID             0xcafe
#define CUSTOM_MAX_DEVICES                8
#define CUSTOM_CFG_DUMP_BYTES             PCI_CFG_SPACE_EXP_SIZE
#define CUSTOM_BAR_DUMP_BYTES             SZ_16K
#define CUSTOM_LOAD_ALIGN                 64
#define CUSTOM_RESERVED_ALIGN             PAGE_SIZE

#define CUSTOM_FEATURE_NOTE               BIT(0)
#define CUSTOM_FEATURE_LOAD               BIT(1)
#define CUSTOM_FEATURE_APIC               BIT(2)
#define CUSTOM_FEATURE_MSRS               BIT(3)
#define CUSTOM_FEATURE_DEVICE_DUMP        BIT(4)
#define CUSTOM_FEATURE_BAR0_DUMP          BIT(5)

#define CUSTOM_CONTEXT_UNKNOWN            0
#define CUSTOM_CONTEXT_TASK               1
#define CUSTOM_CONTEXT_HARDIRQ            2
#define CUSTOM_CONTEXT_SOFTIRQ            3
#define CUSTOM_CONTEXT_NMI                4

#define CUSTOM_DEVICE_FLAG_CFG_SNAPSHOT   BIT(0)
#define CUSTOM_DEVICE_FLAG_BAR0_SNAPSHOT  BIT(1)

#define CUSTOM_APIC_VECTOR_REGS           8
#define CUSTOM_NOTE_MSR_COUNT             8

struct custom_note_msr_entry {
	u32 msr;
	s32 status;
	u64 value;
};

struct custom_note_apic_state {
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

struct custom_vmcore_note_desc {
	u32 magic;
	u32 version;
	u32 size;
	u32 feature_flags;
	u32 panic_cpu;
	u32 panic_context;
	u32 msr_count;
	u32 reserved0;
	u64 crash_time_sec;
	u64 crash_time_nsec;
	u64 jiffies;
	u64 tsc;
	u64 load_paddr;
	u64 load_size;
	u64 load_used_size;
	u64 cr0;
	u64 cr2;
	u64 cr3;
	u64 cr4;
	u64 cr8;
	u64 xcr0;
	u64 apic_base;
	u64 tsc_aux;
	u32 pkru;
	u32 x86_vendor;
	u32 x86;
	u32 x86_model;
	u32 x86_stepping;
	u32 x86_phys_bits;
	u32 x86_virt_bits;
	struct custom_note_msr_entry msrs[CUSTOM_NOTE_MSR_COUNT];
	struct custom_note_apic_state apic;
};

struct custom_device_dump_header {
	u32 magic;
	u32 version;
	u32 header_size;
	u32 feature_flags;
	u32 used_size;
	u32 device_count;
	u32 entry_size;
	u32 reserved0;
	u64 crash_time_sec;
	u64 crash_time_nsec;
	u64 jiffies;
	u64 tsc;
};

struct custom_device_dump_entry {
	u32 domain;
	u32 class_revision;
	u16 vendor_id;
	u16 device_id;
	u8 bus;
	u8 devfn;
	u8 hdr_type;
	u8 reserved0;
	u64 bar0_addr;
	u64 bar0_len;
	u32 cfg_offset;
	u32 cfg_size;
	u32 bar0_offset;
	u32 bar0_size;
	u32 flags;
	u32 reserved1;
};

struct custom_crashdump_state {
	void *note_buf;
	phys_addr_t note_phys;
	size_t note_size;
	void *load_buf;
	phys_addr_t load_phys;
	size_t load_size;
	size_t load_used_size;
	u32 feature_flags;
};

static const u32 custom_note_msrs[CUSTOM_NOTE_MSR_COUNT] = {
	MSR_EFER,
	MSR_IA32_CR_PAT,
	MSR_FS_BASE,
	MSR_GS_BASE,
	MSR_KERNEL_GS_BASE,
	MSR_TSC_AUX,
	MSR_IA32_APICBASE,
	MSR_STAR,
};

static struct custom_crashdump_state custom_state;
static u16 custom_filter_vendor;
static u16 custom_filter_device;
static u32 custom_filter_class;
static bool custom_filter_vendor_set;
static bool custom_filter_device_set;
static bool custom_filter_class_set;
static bool custom_capture_all_devices;
static struct resource custom_note_res = {
	.name = "Custom crash note",
	.flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM,
	.desc = IORES_DESC_RESERVED,
};
static struct resource custom_load_res = {
	.name = "Custom crash payload",
	.flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM,
	.desc = IORES_DESC_RESERVED,
};

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

static int __init custom_parse_vendor(char *arg)
{
	unsigned int value;

	if (kstrtouint(arg, 0, &value))
		return -EINVAL;
	custom_filter_vendor = value;
	custom_filter_vendor_set = true;
	return 0;
}
early_param("custom_crashdump.vendor", custom_parse_vendor);

static int __init custom_parse_device(char *arg)
{
	unsigned int value;

	if (kstrtouint(arg, 0, &value))
		return -EINVAL;
	custom_filter_device = value;
	custom_filter_device_set = true;
	return 0;
}
early_param("custom_crashdump.device", custom_parse_device);

static int __init custom_parse_class(char *arg)
{
	if (kstrtou32(arg, 0, &custom_filter_class))
		return -EINVAL;
	custom_filter_class &= 0x00ffffff;
	custom_filter_class_set = true;
	return 0;
}
early_param("custom_crashdump.class", custom_parse_class);

static int __init custom_parse_capture_all(char *arg)
{
	int value;

	if (kstrtoint(arg, 0, &value))
		return -EINVAL;
	custom_capture_all_devices = !!value;
	return 0;
}
early_param("custom_crashdump.capture_all", custom_parse_capture_all);

static phys_addr_t __init custom_reserved_alloc(size_t size)
{
	phys_addr_t start = 0;
	phys_addr_t phys;

	if (crashk_res.end > start)
		start = crashk_res.end + 1;
	if (crashk_low_res.end > start)
		start = crashk_low_res.end + 1;

	phys = memblock_phys_alloc_range(PAGE_ALIGN(size), CUSTOM_RESERVED_ALIGN,
					 start, MEMBLOCK_ALLOC_ANYWHERE);
	if (!phys)
		return 0;
	if (custom_range_overlaps_resource(phys, size, &crashk_res) ||
	    custom_range_overlaps_resource(phys, size, &crashk_low_res)) {
		memblock_phys_free(phys, PAGE_ALIGN(size));
		return 0;
	}

	return phys;
}

static int __init custom_insert_reserved_resource(struct resource *res,
					  phys_addr_t phys, size_t size)
{
	res->start = phys;
	res->end = phys + PAGE_ALIGN(size) - 1;
	if (insert_resource(&iomem_resource, res)) {
		pr_warn("custom crashdump: failed to register reserved range %pa-%pa\n",
			&res->start, &res->end);
		res->start = 0;
		res->end = 0;
		return -EBUSY;
	}
	return 0;
}

static __always_inline u64 custom_read_cr8(void)
{
	u64 value;

	asm volatile("mov %%cr8,%0" : "=r" (value));
	return value;
}

static int custom_rdmsrl_capture(u32 msr, u64 *value)
{
	int ret;

	ret = rdmsrq_safe(msr, value);
	if (ret)
		*value = 0;
	return ret;
}

static unsigned int custom_panic_context(void)
{
	if (in_nmi())
		return CUSTOM_CONTEXT_NMI;
	if (in_hardirq())
		return CUSTOM_CONTEXT_HARDIRQ;
	if (in_serving_softirq())
		return CUSTOM_CONTEXT_SOFTIRQ;
	return CUSTOM_CONTEXT_TASK;
}

static bool custom_match_device(const struct pci_dev *pdev)
{
	if (custom_capture_all_devices)
		return true;

	if (custom_filter_vendor_set && pdev->vendor != custom_filter_vendor)
		return false;
	if (custom_filter_device_set && pdev->device != custom_filter_device)
		return false;
	if (custom_filter_class_set && ((pdev->class >> 8) != custom_filter_class))
		return false;

	if (custom_filter_vendor_set || custom_filter_device_set ||
	    custom_filter_class_set)
		return true;

	return pdev->vendor == CUSTOM_TEST_VENDOR_ID &&
	       pdev->device == CUSTOM_TEST_DEVICE_ID;
}

static void custom_capture_apic_state(struct custom_note_apic_state *apic_state)
{
	unsigned int index;

	memset(apic_state, 0, sizeof(*apic_state));
	if (!boot_cpu_has(X86_FEATURE_APIC))
		return;

	apic_state->valid = 1;
	apic_state->x2apic_enabled = x2apic_enabled();
	apic_state->id = apic_read(APIC_ID);
	apic_state->version = apic_read(APIC_LVR);
	apic_state->tpr = apic_read(APIC_TASKPRI);
	apic_state->ppr = apic_read(APIC_PROCPRI);
	apic_state->ldr = apic_read(APIC_LDR);
	apic_state->dfr = apic_read(APIC_DFR);
	apic_state->spiv = apic_read(APIC_SPIV);
	apic_state->esr = apic_read(APIC_ESR);
	apic_state->lvtt = apic_read(APIC_LVTT);
	apic_state->lvtpc = apic_read(APIC_LVTPC);
	apic_state->lvt0 = apic_read(APIC_LVT0);
	apic_state->lvt1 = apic_read(APIC_LVT1);
	apic_state->lvterr = apic_read(APIC_LVTERR);
	apic_state->tmict = apic_read(APIC_TMICT);
	apic_state->tmcct = apic_read(APIC_TMCCT);
	apic_state->tdcr = apic_read(APIC_TDCR);
	for (index = 0; index < CUSTOM_APIC_VECTOR_REGS; index++) {
		apic_state->isr[index] = apic_read(APIC_ISR + (index * 0x10));
		apic_state->tmr[index] = apic_read(APIC_TMR + (index * 0x10));
		apic_state->irr[index] = apic_read(APIC_IRR + (index * 0x10));
	}
}

static size_t custom_align_size(size_t size)
{
	return ALIGN(size, CUSTOM_LOAD_ALIGN);
}

static void custom_prepare_empty_note(void)
{
	Elf_Word *cursor;
	struct custom_vmcore_note_desc desc;

	if (!custom_state.note_buf)
		return;

	memset(&desc, 0, sizeof(desc));
	desc.magic = CUSTOM_NOTE_MAGIC;
	desc.version = CUSTOM_NOTE_VERSION;
	desc.size = sizeof(desc);
	desc.feature_flags = custom_state.feature_flags;
	desc.load_paddr = custom_state.load_phys;
	desc.load_size = custom_state.load_size;

	memset(custom_state.note_buf, 0, custom_state.note_size);
	cursor = append_elf_note(custom_state.note_buf, (char *)CUSTOM_CRASH_NOTE_NAME,
				 CUSTOM_CRASH_NOTE_TYPE, &desc, sizeof(desc));
	final_note(cursor);
}

static void custom_init_load_header(void)
{
	struct custom_device_dump_header *hdr;

	if (!custom_state.load_buf)
		return;

	memset(custom_state.load_buf, 0, custom_state.load_size);
	hdr = custom_state.load_buf;
	hdr->magic = CUSTOM_LOAD_MAGIC;
	hdr->version = CUSTOM_LOAD_VERSION;
	hdr->header_size = sizeof(*hdr) +
				   CUSTOM_MAX_DEVICES * sizeof(struct custom_device_dump_entry);
	hdr->feature_flags = custom_state.feature_flags;
	hdr->entry_size = sizeof(struct custom_device_dump_entry);
	hdr->used_size = custom_align_size(hdr->header_size);
	custom_state.load_used_size = hdr->used_size;
}

static void custom_capture_note(void)
{
	Elf_Word *cursor;
	struct custom_vmcore_note_desc desc;
	struct timespec64 ts;
	unsigned int index;
	u64 xcr0 = 0;

	if (!custom_state.note_buf)
		return;

	memset(&desc, 0, sizeof(desc));
	ktime_get_real_ts64(&ts);
	desc.magic = CUSTOM_NOTE_MAGIC;
	desc.version = CUSTOM_NOTE_VERSION;
	desc.size = sizeof(desc);
	desc.feature_flags = custom_state.feature_flags;
	desc.panic_cpu = smp_processor_id();
	desc.panic_context = custom_panic_context();
	desc.msr_count = CUSTOM_NOTE_MSR_COUNT;
	desc.crash_time_sec = ts.tv_sec;
	desc.crash_time_nsec = ts.tv_nsec;
	desc.jiffies = get_jiffies_64();
	desc.tsc = rdtsc();
	desc.load_paddr = custom_state.load_phys;
	desc.load_size = custom_state.load_size;
	desc.load_used_size = custom_state.load_used_size;
	desc.cr0 = read_cr0();
	desc.cr2 = read_cr2();
	desc.cr3 = __read_cr3();
	desc.cr4 = __read_cr4();
	desc.cr8 = custom_read_cr8();
	if (boot_cpu_has(X86_FEATURE_OSXSAVE))
		xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
	desc.xcr0 = xcr0;
	if (boot_cpu_has(X86_FEATURE_OSPKE))
		desc.pkru = rdpkru();
	desc.x86_vendor = boot_cpu_data.x86_vendor;
	desc.x86 = boot_cpu_data.x86;
	desc.x86_model = boot_cpu_data.x86_model;
	desc.x86_stepping = boot_cpu_data.x86_stepping;
	desc.x86_phys_bits = boot_cpu_data.x86_phys_bits;
	desc.x86_virt_bits = boot_cpu_data.x86_virt_bits;
	custom_rdmsrl_capture(MSR_IA32_APICBASE, &desc.apic_base);
	custom_rdmsrl_capture(MSR_TSC_AUX, &desc.tsc_aux);
	for (index = 0; index < CUSTOM_NOTE_MSR_COUNT; index++) {
		desc.msrs[index].msr = custom_note_msrs[index];
		desc.msrs[index].status =
			custom_rdmsrl_capture(custom_note_msrs[index],
					     &desc.msrs[index].value);
	}
	custom_capture_apic_state(&desc.apic);

	memset(custom_state.note_buf, 0, custom_state.note_size);
	cursor = append_elf_note(custom_state.note_buf, (char *)CUSTOM_CRASH_NOTE_NAME,
				 CUSTOM_CRASH_NOTE_TYPE, &desc, sizeof(desc));
	final_note(cursor);
}

static void custom_capture_device_dumps(void)
{
	struct custom_device_dump_header *hdr;
	struct custom_device_dump_entry *entries;
	struct timespec64 ts;
	struct pci_dev *pdev = NULL;
	u8 *payload;
	size_t offset;
	unsigned int count = 0;

	if (!custom_state.load_buf)
		return;

	custom_state.feature_flags &= ~(CUSTOM_FEATURE_DEVICE_DUMP |
					 CUSTOM_FEATURE_BAR0_DUMP);
	custom_init_load_header();
	hdr = custom_state.load_buf;
	entries = (struct custom_device_dump_entry *)(hdr + 1);
	payload = custom_state.load_buf;
	offset = custom_align_size(hdr->header_size);
	ktime_get_real_ts64(&ts);
	hdr->crash_time_sec = ts.tv_sec;
	hdr->crash_time_nsec = ts.tv_nsec;
	hdr->jiffies = get_jiffies_64();
	hdr->tsc = rdtsc();

	for_each_pci_dev(pdev) {
		struct custom_device_dump_entry *entry;
		void __iomem *mmio;
		resource_size_t mmio_start;
		resource_size_t mmio_len;
		size_t cfg_size = CUSTOM_CFG_DUMP_BYTES;
		size_t bar_size = 0;
		unsigned int dword;

		if (count >= CUSTOM_MAX_DEVICES)
			break;
		if (!custom_match_device(pdev))
			continue;

		entry = &entries[count];
		entry->domain = pci_domain_nr(pdev->bus);
		entry->class_revision = pdev->class;
		entry->vendor_id = pdev->vendor;
		entry->device_id = pdev->device;
		entry->bus = pdev->bus->number;
		entry->devfn = pdev->devfn;
		pci_read_config_byte(pdev, PCI_HEADER_TYPE, &entry->hdr_type);

		if (offset + cfg_size > custom_state.load_size)
			break;
		entry->cfg_offset = offset;
		entry->cfg_size = cfg_size;
		entry->flags |= CUSTOM_DEVICE_FLAG_CFG_SNAPSHOT;
		for (dword = 0; dword < cfg_size / sizeof(u32); dword++)
			pci_read_config_dword(pdev, dword * sizeof(u32),
					      (u32 *)(payload + offset +
					      dword * sizeof(u32)));
		offset += custom_align_size(cfg_size);

		mmio_start = pci_resource_start(pdev, 0);
		mmio_len = pci_resource_len(pdev, 0);
		entry->bar0_addr = mmio_start;
		entry->bar0_len = mmio_len;
		if ((pci_resource_flags(pdev, 0) & IORESOURCE_MEM) &&
		    mmio_start && mmio_len) {
			bar_size = min_t(size_t, (size_t)mmio_len, CUSTOM_BAR_DUMP_BYTES);
			if (offset + bar_size <= custom_state.load_size) {
				mmio = ioremap(mmio_start, bar_size);
				if (mmio) {
					entry->bar0_offset = offset;
					entry->bar0_size = bar_size;
					entry->flags |= CUSTOM_DEVICE_FLAG_BAR0_SNAPSHOT;
					memcpy_fromio(payload + offset, mmio, bar_size);
					iounmap(mmio);
					offset += custom_align_size(bar_size);
					custom_state.feature_flags |= CUSTOM_FEATURE_BAR0_DUMP;
				}
			}
		}

		count++;
	}

	if (count)
		custom_state.feature_flags |= CUSTOM_FEATURE_DEVICE_DUMP;
	hdr->feature_flags = custom_state.feature_flags;
	hdr->device_count = count;
	hdr->used_size = offset;
	custom_state.load_used_size = offset;
}

int arch_crash_exclude_extra_ranges(struct crash_mem *mem)
{
	int ret;

	if (custom_state.note_phys) {
		ret = crash_exclude_mem_range(mem, custom_state.note_phys,
					     custom_state.note_phys + custom_state.note_size - 1);
		if (ret)
			return ret;
	}

	if (custom_state.load_phys) {
		ret = crash_exclude_mem_range(mem, custom_state.load_phys,
					     custom_state.load_phys + custom_state.load_size - 1);
		if (ret)
			return ret;
	}

	return 0;
}

unsigned int arch_crash_extra_vmcore_notes(void)
{
	return custom_state.note_phys ? 1 : 0;
}

unsigned int arch_crash_extra_vmcore_loads(void)
{
	return custom_state.load_phys ? 1 : 0;
}

unsigned int arch_crash_append_vmcore_notes(Elf64_Phdr *phdr,
					    unsigned int max_phdrs)
{
	if (!custom_state.note_phys || !max_phdrs)
		return 0;

	phdr->p_type = PT_NOTE;
	phdr->p_offset = custom_state.note_phys;
	phdr->p_paddr = custom_state.note_phys;
	phdr->p_filesz = custom_state.note_size;
	phdr->p_memsz = custom_state.note_size;
	phdr->p_align = 0;

	return 1;
}

unsigned int arch_crash_append_vmcore_loads(Elf64_Phdr *phdr,
					    unsigned int max_phdrs)
{
	if (!custom_state.load_phys || !max_phdrs)
		return 0;

	phdr->p_type = PT_LOAD;
	phdr->p_flags = PF_R;
	phdr->p_offset = custom_state.load_phys;
	phdr->p_paddr = custom_state.load_phys;
	phdr->p_vaddr = 0;
	phdr->p_filesz = custom_state.load_size;
	phdr->p_memsz = custom_state.load_size;
	phdr->p_align = PAGE_SIZE;

	return 1;
}

void arch_crash_save_vmcoreinfo_late(void)
{
	if (!custom_state.note_buf || !custom_state.load_buf)
		return;

	custom_capture_device_dumps();
	custom_capture_note();

	vmcoreinfo_append_str("CUSTOM_VMCORE_NOTE_NAME=%s\n",
				 CUSTOM_CRASH_NOTE_NAME);
	vmcoreinfo_append_str("CUSTOM_VMCORE_NOTE_TYPE=0x%x\n",
				 CUSTOM_CRASH_NOTE_TYPE);
	vmcoreinfo_append_str("CUSTOM_VMCORE_NOTE_PADDR=0x%llx\n",
				 (unsigned long long)custom_state.note_phys);
	vmcoreinfo_append_str("CUSTOM_VMCORE_NOTE_BYTES=%zu\n",
				 custom_state.note_size);
	vmcoreinfo_append_str("CUSTOM_VMCORE_LOAD_PADDR=0x%llx\n",
				 (unsigned long long)custom_state.load_phys);
	vmcoreinfo_append_str("CUSTOM_VMCORE_LOAD_BYTES=%zu\n",
				 custom_state.load_size);
	vmcoreinfo_append_str("CUSTOM_VMCORE_LOAD_USED=%zu\n",
				 custom_state.load_used_size);
	vmcoreinfo_append_str("CUSTOM_VMCORE_FEATURES=0x%x\n",
				 custom_state.feature_flags);
	if (custom_capture_all_devices)
		vmcoreinfo_append_str("CUSTOM_VMCORE_CAPTURE_ALL=1\n");
	if (custom_filter_vendor_set)
		vmcoreinfo_append_str("CUSTOM_VMCORE_FILTER_VENDOR=0x%04x\n",
				 custom_filter_vendor);
	if (custom_filter_device_set)
		vmcoreinfo_append_str("CUSTOM_VMCORE_FILTER_DEVICE=0x%04x\n",
				 custom_filter_device);
	if (custom_filter_class_set)
		vmcoreinfo_append_str("CUSTOM_VMCORE_FILTER_CLASS=0x%06x\n",
				 custom_filter_class);
}

static int __init custom_reserve_buffers(void)
{
	phys_addr_t phys;
	int ret;

	if (!IS_ENABLED(CONFIG_CRASH_DUMP) || !crashk_res.end)
		return 0;

	custom_state.feature_flags = CUSTOM_FEATURE_NOTE |
					   CUSTOM_FEATURE_LOAD |
					   CUSTOM_FEATURE_APIC |
					   CUSTOM_FEATURE_MSRS;

	phys = custom_reserved_alloc(CUSTOM_NOTE_BYTES);
	if (!phys)
		return -ENOMEM;
	ret = custom_insert_reserved_resource(&custom_note_res, phys,
					     CUSTOM_NOTE_BYTES);
	if (ret) {
		memblock_phys_free(phys, PAGE_ALIGN(CUSTOM_NOTE_BYTES));
		return ret;
	}
	custom_state.note_phys = phys;
	custom_state.note_size = PAGE_ALIGN(CUSTOM_NOTE_BYTES);
	custom_state.note_buf = phys_to_virt(phys);
	memset(custom_state.note_buf, 0, custom_state.note_size);
	kmemleak_ignore_phys(phys);

	phys = custom_reserved_alloc(CUSTOM_DEVICE_DUMP_BYTES);
	if (!phys)
		goto free_note;
	ret = custom_insert_reserved_resource(&custom_load_res, phys,
					     CUSTOM_DEVICE_DUMP_BYTES);
	if (ret) {
		memblock_phys_free(phys, PAGE_ALIGN(CUSTOM_DEVICE_DUMP_BYTES));
		goto free_note;
	}
	custom_state.load_phys = phys;
	custom_state.load_size = PAGE_ALIGN(CUSTOM_DEVICE_DUMP_BYTES);
	custom_state.load_buf = phys_to_virt(phys);
	memset(custom_state.load_buf, 0, custom_state.load_size);
	kmemleak_ignore_phys(phys);

	custom_prepare_empty_note();
	custom_init_load_header();

	pr_info("custom crashdump: reserved note=%pa/%zu load=%pa/%zu\n",
		&custom_state.note_phys, custom_state.note_size,
		&custom_state.load_phys, custom_state.load_size);
	if (custom_capture_all_devices) {
		pr_info("custom crashdump: capturing all PCI devices with BAR snapshots\n");
	} else if (custom_filter_vendor_set || custom_filter_device_set ||
		   custom_filter_class_set) {
		pr_info("custom crashdump: PCI filter vendor=%s0x%04x device=%s0x%04x class=%s0x%06x\n",
			custom_filter_vendor_set ? "" : "<any>",
			custom_filter_vendor,
			custom_filter_device_set ? "" : "<any>",
			custom_filter_device,
			custom_filter_class_set ? "" : "<any>",
			custom_filter_class);
	} else {
		pr_info("custom crashdump: default PCI filter vendor=0x%04x device=0x%04x\n",
			CUSTOM_TEST_VENDOR_ID, CUSTOM_TEST_DEVICE_ID);
	}

	return 0;

free_note:
	release_resource(&custom_note_res);
	custom_note_res.start = 0;
	custom_note_res.end = 0;
	memblock_phys_free(custom_state.note_phys, custom_state.note_size);
	custom_state.note_buf = NULL;
	custom_state.note_phys = 0;
	custom_state.note_size = 0;
	return ret ? ret : -ENOMEM;
}
early_initcall(custom_reserve_buffers);