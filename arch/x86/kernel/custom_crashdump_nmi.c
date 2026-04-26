// SPDX-License-Identifier: GPL-2.0-only

/*
 * custom_crashdump_nmi.c - Custom crash dump via NMI, panic notifier, and vmcoredd
 *
 * This driver captures per-CPU register state and printk tail at panic time and
 * embeds the result as a device dump (vmcoredd) blob in /proc/vmcore, where the
 * capture tool (show_vmcoredd.py) can extract and decode it from the 2nd kernel.
 *
 * Flow (1st kernel):
 *   NMI                -> custom_nmi_handler()           : per-CPU register snapshot
 *   crash_kexec()      -> custom_crashdump_capture()     : collect all CPUs + printk tail
 *   crash_save_vmcoreinfo() -> custom_vmcoreinfo_extra_append() : write keys to ELF note
 *
 * Flow (2nd / kdump kernel):
 *   late_initcall      -> custom_vmcoredd_late_init()    : read vmcoreinfo from old mem,
 *                         custom_vmcoredd_register()       register blob with vmcore layer
 *   /proc/vmcore read  -> custom_vmcoredd_copy_from_oldmem() : stream blob to user space
 */

#include <linux/atomic.h>
#include <linux/cc_platform.h>
#include <linux/cpu.h>
#include <linux/crash_dump.h>
#include <linux/crc32.h>
#include <linux/elf.h>
#include <linux/init.h>
#include <linux/kmsg_dump.h>
#include <linux/moduleparam.h>
#include <linux/nmi.h>
#include <linux/notifier.h>
#include <linux/panic_notifier.h>
#include <linux/pci.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/sched/task_stack.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/vmcore_info.h>

#include <asm/asm.h>
#include <asm/debugreg.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/nmi.h>
#include <asm/paravirt.h>
#include <asm/ptrace.h>

#define CUSTOM_TEST_VENDOR_ID       0x1d5f
#define CUSTOM_TEST_DEVICE_ID       0xcafe
#define CUSTOM_NMI_CFG_DWORD        0x40
#define CUSTOM_STACK_SNAPSHOT_BYTES 512
#define CUSTOM_PRINTK_TAIL_BYTES    4096
#define CUSTOM_VMCOREDD_MAGIC       0x4344564d
#define CUSTOM_VMCOREDD_VERSION     3
#define CUSTOM_VMCOREDD_MAX_CPUS    256
#define CUSTOM_VMCOREDD_BLOB_BYTES  (512 * 1024)

/*
 * Per-CPU register and stack snapshot captured on NMI / panic.
 * Stored in a per-CPU variable; copied into the vmcoredd blob by
 * custom_vmcoredd_prepare_blob() after all CPUs have responded.
 *
 * Wire-format note: bool valid occupies 1 byte followed by 1 byte of implicit
 * compiler padding before u16 cs.  The layout is fixed; a BUILD_BUG_ON below
 * verifies the offsets so that the Python parser stays in sync.
 */
struct custom_nmi_cpu_state {
	bool valid;
	/* 1-byte implicit padding here; verified by BUILD_BUG_ON in nmi_init */
	u16 cs;
	u16 ss;
	u64 ip;
	u64 sp;
	u64 flags;
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
	u64 cr0;
	u64 cr2;
	u64 cr3;
	u64 cr4;
	u64 dr6;
	u64 dr7;
	u64 apic_base;
	/* Kernel stack snapshot (kept in legacy fields for parser compatibility). */
	u32 stack_len;
	u32 stack_crc;
	u8 stack_snapshot[CUSTOM_STACK_SNAPSHOT_BYTES];
	/* Optional user stack snapshot (captured only on user-mode entries). */
	u32 user_stack_len;
	u32 user_stack_crc;
	u8 user_stack_snapshot[CUSTOM_STACK_SNAPSHOT_BYTES];
	/*
	 * Generation tag: must match custom_capture_generation at assembly time
	 * to be counted as a valid panic capture.  Prevents a spurious NMI that
	 * fires between custom_reset_capture_valid_bits() and
	 * trigger_all_cpu_backtrace() from being mistaken for a panic snapshot.
	 */
	u32 capture_gen;
};

/*
 * Header placed at the start of the vmcoredd blob (custom_vmcoredd_blob[0]).
 * Followed by record_count × custom_vmcoredd_cpu_record, then printk_tail bytes.
 * payload_crc covers everything after the header.
 */
struct custom_vmcoredd_header {
	u32 magic;
	u32 version;
	u32 total_size;
	u32 payload_crc;
	u32 captured_cpus;
	u32 online_cpus;
	u32 record_count;
	u32 record_size;
	u32 printk_tail_len;
	u32 printk_tail_crc;
	u32 pci_cfg40;
	u32 mmio32;
	u32 ioport32;
};

/* One record per captured CPU, appended after the header in the blob. */
struct custom_vmcoredd_cpu_record {
	u32 cpu;
	u32 reserved;
	struct custom_nmi_cpu_state state;
};

static DEFINE_PER_CPU(struct custom_nmi_cpu_state, custom_nmi_cpu_state);

/* Whether to register NMI handlers (can be disabled via kernel cmdline). */
static bool custom_nmi_handlers = true;
/* Read-only: handler registration happens once at arch_initcall; runtime
 * changes have no effect on the already-registered (or not) handlers.
 */
module_param_named(custom_crashdump_nmi_handlers, custom_nmi_handlers, bool, 0444);

/* Number of stack bytes to snapshot per CPU (capped at CUSTOM_STACK_SNAPSHOT_BYTES). */
static unsigned int custom_stack_copy_bytes = CUSTOM_STACK_SNAPSHOT_BYTES;
module_param_named(custom_crashdump_stack_copy_bytes,
		   custom_stack_copy_bytes, uint, 0644);

/*
 * Monotonically increasing capture generation.  Incremented once at the start
 * of each panic capture round (before valid bits are reset).  Per-CPU NMI
 * captures tag their slot with the current generation so that any NMI that
 * fires in the window between the valid-bit reset and trigger_all_cpu_backtrace
 * can be distinguished from the authoritative panic snapshot.
 */
static unsigned int custom_capture_generation;

static char custom_printk_tail[CUSTOM_PRINTK_TAIL_BYTES];
static size_t custom_printk_tail_len;
static u32 custom_printk_tail_crc;

static struct pci_dev *custom_test_pdev;
static void __iomem *custom_test_mmio;
static resource_size_t custom_test_pio;
static u32 custom_test_cfg40_cached;
static u32 custom_test_mmio_cached = 0xffffffff;
static u32 custom_test_io_cached = 0xffffffff;
/*
 * Static BSS blob for the vmcoredd payload assembled at panic time.
 * Worst-case size calculation:
 *   CUSTOM_VMCOREDD_MAX_CPUS (256) × sizeof(custom_vmcoredd_cpu_record)
 *   + sizeof(custom_vmcoredd_header) + CUSTOM_PRINTK_TAIL_BYTES
 *   ≈ 256 × 1264 + 52 + 4096 ≈ 328 KB
 * 512 KB provides comfortable headroom without wasting BSS space.
 */
static u8 custom_vmcoredd_blob[CUSTOM_VMCOREDD_BLOB_BYTES];
static size_t custom_vmcoredd_blob_size;
static u64 custom_vmcoredd_oldmem_paddr;
static unsigned int custom_vmcoredd_oldmem_size;
static char custom_vmcoreinfo_scratch[VMCOREINFO_BYTES + 1];

static void custom_vmcoredd_prepare_blob(u32 cfg40, u32 mmio_val, u32 io_val);

static int custom_vmcoredd_copy_from_oldmem(struct vmcoredd_data *data, void *buf);

static struct vmcoredd_data custom_vmcoredd_data = {
	.dump_name = "custom_panic_capture",
	.vmcoredd_callback = custom_vmcoredd_copy_from_oldmem,
};

/* Returns the number of online CPUs that have set valid=true in their state. */
static unsigned int custom_count_captured_cpus(void)
{
	unsigned int seen = 0;
	int cpu;

	for_each_online_cpu(cpu) {
		struct custom_nmi_cpu_state *s = &per_cpu(custom_nmi_cpu_state, cpu);

		/*
		 * The acquire on valid pairs with the release in custom_nmi_capture().
		 * Once valid=true is visible, capture_gen is also visible (written
		 * before the store-release), so a plain read is sufficient.
		 */
		if (smp_load_acquire(&s->valid) &&
		    s->capture_gen == custom_capture_generation)
			seen++;
	}

	return seen;
}

/* Clear per-CPU capture valid bits before starting a new panic capture round. */
static void custom_reset_capture_valid_bits(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		WRITE_ONCE(per_cpu(custom_nmi_cpu_state, cpu).valid, false);
}

/*
 * PCI driver probe for the QEMU test device (vendor=0x1d5f, device=0xcafe).
 * Maps BAR0 (MMIO) and records BAR1 (I/O port base) so they can be read
 * during crash capture without going through config space re-probing.
 *
 * Compiled only when CONFIG_CUSTOM_CRASHDUMP_NMI_TEST_DEV=y.
 */
#ifdef CONFIG_CUSTOM_CRASHDUMP_NMI_TEST_DEV
static int custom_crashdump_test_probe(struct pci_dev *pdev,
				      const struct pci_device_id *id)
{
	u16 vendor = 0;
	u16 device = 0;
	u32 cfg40;

	if (pcim_enable_device(pdev))
		return -ENODEV;

	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM))
		return -ENODEV;

	custom_test_mmio = pcim_iomap(pdev, 0, 0);
	if (!custom_test_mmio)
		return -ENODEV;

	if (pci_resource_flags(pdev, 1) & IORESOURCE_IO)
		custom_test_pio = pci_resource_start(pdev, 1);
	else
		custom_test_pio = 0;

	pci_read_config_dword(pdev, CUSTOM_NMI_CFG_DWORD, &cfg40);
	WRITE_ONCE(custom_test_cfg40_cached, cfg40);

	if (custom_test_mmio)
		WRITE_ONCE(custom_test_mmio_cached, ioread32(custom_test_mmio));
	else
		WRITE_ONCE(custom_test_mmio_cached, 0xffffffff);

	if (custom_test_pio)
		WRITE_ONCE(custom_test_io_cached, inl(custom_test_pio));
	else
		WRITE_ONCE(custom_test_io_cached, 0xffffffff);

	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device);

	custom_test_pdev = pdev;
	pr_info("custom crashdump pci test device bound %04x:%04x mmio=%pa pio=%pa\n",
		vendor, device, &pdev->resource[0].start, &custom_test_pio);

	return 0;
}

static void custom_crashdump_test_remove(struct pci_dev *pdev)
{
	if (custom_test_pdev == pdev) {
		custom_test_pdev = NULL;
		custom_test_mmio = NULL;
		custom_test_pio = 0;
		WRITE_ONCE(custom_test_cfg40_cached, 0);
		WRITE_ONCE(custom_test_mmio_cached, 0xffffffff);
		WRITE_ONCE(custom_test_io_cached, 0xffffffff);
	}
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

/*
 * Collect current register values from the test PCI device.
 * Prefers the live MMIO/PIO mappings when the driver is bound; falls back to
 * direct config-space + ioremap reads when called before probe() or in NMI
 * context where the driver structures may not be fully initialised.
 */
static void custom_collect_device_values(u32 *cfg40, u32 *mmio_val, u32 *io_val)
{
	/*
	 * Panic path: avoid PCI config transactions and dynamic ioremap.
	 * Use values cached during normal operation and only perform direct
	 * MMIO/PIO reads when existing mappings are already available.
	 */
	*cfg40 = READ_ONCE(custom_test_cfg40_cached);
	*mmio_val = READ_ONCE(custom_test_mmio_cached);
	*io_val = READ_ONCE(custom_test_io_cached);

	if (READ_ONCE(custom_test_mmio)) {
		u32 v = ioread32(custom_test_mmio);

		*mmio_val = v;
		WRITE_ONCE(custom_test_mmio_cached, v);
	}

	if (READ_ONCE(custom_test_pio)) {
		u32 v = inl(custom_test_pio);

		*io_val = v;
		WRITE_ONCE(custom_test_io_cached, v);
	}
}

/*
 * Capture the register state of the current CPU into its per-CPU slot.
 * Reads all general-purpose registers, segment selectors, control registers,
 * debug registers, APIC base MSR, and a snapshot of the current kernel stack.
 * Safe to call from NMI context.
 */
static void custom_nmi_capture(struct pt_regs *regs)
{
	struct custom_nmi_cpu_state *state = this_cpu_ptr(&custom_nmi_cpu_state);
	unsigned long stack_base = (unsigned long)task_stack_page(current);
	unsigned long stack_end = stack_base + THREAD_SIZE;
	unsigned long kernel_sp = current_stack_pointer;
	unsigned long user_sp = 0;
	unsigned int kernel_copy_len = min(custom_stack_copy_bytes,
					   (unsigned int)CUSTOM_STACK_SNAPSHOT_BYTES);
	unsigned int user_copy_len = kernel_copy_len;
	u64 apic_base = 0;
	unsigned long dr6 = 0;
	unsigned long dr7 = 0;

	rdmsrq_safe(MSR_IA32_APICBASE, &apic_base);
	get_debugreg(dr6, 6);
	get_debugreg(dr7, 7);

	if (regs && !user_mode(regs))
		kernel_sp = kernel_stack_pointer(regs);
	if (regs && user_mode(regs))
		user_sp = user_stack_pointer(regs);

	WRITE_ONCE(state->valid, false);
	state->ip = regs ? instruction_pointer(regs) : 0;
	state->sp = regs ? regs->sp : 0;
	state->flags = regs ? regs->flags : 0;
	state->cs = regs ? regs->cs : 0;
	state->ss = regs ? regs->ss : 0;
	state->ax = regs ? regs->ax : 0;
	state->bx = regs ? regs->bx : 0;
	state->cx = regs ? regs->cx : 0;
	state->dx = regs ? regs->dx : 0;
	state->si = regs ? regs->si : 0;
	state->di = regs ? regs->di : 0;
	state->bp = regs ? regs->bp : 0;
	state->r8 = regs ? regs->r8 : 0;
	state->r9 = regs ? regs->r9 : 0;
	state->r10 = regs ? regs->r10 : 0;
	state->r11 = regs ? regs->r11 : 0;
	state->r12 = regs ? regs->r12 : 0;
	state->r13 = regs ? regs->r13 : 0;
	state->r14 = regs ? regs->r14 : 0;
	state->r15 = regs ? regs->r15 : 0;
	state->cr0 = read_cr0();
	state->cr2 = read_cr2();
	state->cr3 = __read_cr3();
	state->cr4 = __read_cr4();
	state->dr6 = dr6;
	state->dr7 = dr7;
	state->apic_base = apic_base;
	state->stack_len = 0;
	state->stack_crc = 0;
	state->user_stack_len = 0;
	state->user_stack_crc = 0;

	if (kernel_sp >= stack_base && kernel_sp < stack_end) {
		unsigned long avail = stack_end - kernel_sp;

		if (kernel_copy_len > avail)
			kernel_copy_len = avail;
		if (kernel_copy_len) {
			memcpy(state->stack_snapshot, (void *)kernel_sp, kernel_copy_len);
			state->stack_len = kernel_copy_len;
			state->stack_crc = crc32_le(0, state->stack_snapshot,
						 kernel_copy_len);
		}
	}

	if (user_sp && user_copy_len) {
		unsigned long left;
		unsigned int copied;

		left = copy_from_user_nmi(state->user_stack_snapshot,
					 (const void __user *)user_sp, user_copy_len);
		copied = user_copy_len - left;
		if (copied) {
			state->user_stack_len = copied;
			state->user_stack_crc = crc32_le(0,
						 state->user_stack_snapshot,
						 copied);
		}
	}

	/*
	 * Tag with the current capture generation before publishing.  The
	 * store-release on valid ensures capture_gen is visible to any CPU
	 * that subsequently loads valid with an acquire.
	 */
	state->capture_gen = READ_ONCE(custom_capture_generation);
	/* Publish this CPU slot only after all fields are fully populated. */
	smp_store_release(&state->valid, true);
}

/*
 * Main panic-time entry point, exported for crash.c / machine_kexec.c.
 *
 * Called from crash_kexec() before kexec starts.
 * Responsibilities:
 *   1. Capture the panicking CPU's registers via custom_nmi_capture().
 *   2. Capture the printk tail before triggering NMI on other CPUs (see
 *      comment in function body for why order matters).
 *   3. Trigger NMI on all other CPUs and wait for them to respond.
 *      nmi_trigger_cpumask_backtrace() blocks until all CPUs have cleared
 *      their backtrace_mask bit or a 10-second timeout expires.
 *   4. Read device registers and assemble the vmcoredd blob.
 */
void custom_crashdump_capture(struct pt_regs *regs)
{
	u32 cfg40;
	u32 mmio_val;
	u32 io_val;
	unsigned int seen;
	unsigned int target_cpus = num_online_cpus();
	struct kmsg_dump_iter iter;
	size_t out_len = 0;

	/*
	 * Advance the capture generation before resetting valid bits.  Any NMI
	 * that fires after this point will tag its slot with the new generation,
	 * while slots written before the reset still carry the old generation and
	 * will be excluded by custom_count_captured_cpus() / prepare_blob().
	 */
	WRITE_ONCE(custom_capture_generation, READ_ONCE(custom_capture_generation) + 1);
	custom_reset_capture_valid_bits();
	custom_nmi_capture(regs);

	/*
	 * Capture the printk tail BEFORE trigger_all_cpu_backtrace().
	 * trigger_all_cpu_backtrace() causes nmi_cpu_backtrace_handler() to call
	 * show_regs()/dump_stack() on every CPU, writing N × show_regs() worth
	 * of data into the printk ring buffer.  If we collect the tail after that,
	 * the panic message and oops backtrace may have been pushed out of the
	 * ring buffer on systems with many CPUs.
	 *
	 * panic() may call __crash_kexec() before notifiers and kmsg_dump(), so
	 * this is the only place that reliably captures the full panic context.
	 */
	kmsg_dump_rewind(&iter);
	if (kmsg_dump_get_buffer(&iter, true, custom_printk_tail,
				 sizeof(custom_printk_tail), &out_len)) {
		custom_printk_tail_len = out_len;
		custom_printk_tail_crc = crc32_le(0, custom_printk_tail, out_len);
	} else {
		custom_printk_tail_len = 0;
		custom_printk_tail_crc = 0;
	}

	/*
	 * Send NMI IPI to all other online CPUs so they populate their per-CPU
	 * slots via custom_nmi_handler().
	 *
	 * nmi_trigger_cpumask_backtrace() (called internally) blocks until all
	 * target CPUs clear their backtrace_mask bit (via nmi_cpu_backtrace_handler)
	 * or a 10-second timeout expires.  By the time this returns, custom_nmi_capture()
	 * has already run on every responding CPU, so no additional polling is needed.
	 *
	 * If NMI IPI is unavailable on this arch the function returns false and only
	 * the panic CPU's snapshot will be present in the blob.
	 */
	if (!trigger_all_cpu_backtrace())
		pr_warn("custom crashdump: NMI backtrace unavailable, only panic CPU captured\n");

	custom_collect_device_values(&cfg40, &mmio_val, &io_val);
	seen = custom_count_captured_cpus();
	if (seen < target_cpus)
		pr_warn("custom crashdump: captured cpus=%u/%u (some NMI snapshots missing)\n",
			seen, target_cpus);
	custom_vmcoredd_prepare_blob(cfg40, mmio_val, io_val);
	/*
	 * vmcoreinfo keys are appended later by custom_vmcoreinfo_extra_append(),
	 * which is called from crash_save_vmcoreinfo() after vmcoreinfo_data has
	 * been switched to the safe copy.  This ensures the keys survive into the
	 * ELF note that the 2nd (kdump) kernel reads via elfcorehdr.
	 */
}

/*
 * Override the weak stub in kernel/vmcore_info.c.
 * Called from crash_save_vmcoreinfo() after the vmcoreinfo buffer has been
 * switched to the crash-safe copy.  Appends key=value pairs describing the
 * vmcoredd blob location so the 2nd (kdump) kernel can locate it from the
 * ELF PT_NOTE segment in /proc/vmcore.
 *
 * The prototype is declared here (rather than in a header) because this is
 * a __weak override and no shared header includes it.  The declaration
 * satisfies -Wmissing-prototypes; the __weak stub lives in kernel/vmcore_info.c.
 */
void custom_vmcoreinfo_extra_append(void); /* satisfies -Wmissing-prototypes */
void custom_vmcoreinfo_extra_append(void)
{
	struct custom_vmcoredd_header *hdr;

	if (!custom_vmcoredd_blob_size)
		return;

	hdr = (struct custom_vmcoredd_header *)custom_vmcoredd_blob;

	vmcoreinfo_append_str("CUSTOM_NMI_CPUS=%u/%u\n",
			      hdr->captured_cpus, hdr->online_cpus);
	vmcoreinfo_append_str("CUSTOM_VMCOREDD_PADDR=0x%llx\n",
			      (u64)__pa_symbol(custom_vmcoredd_blob));
	vmcoreinfo_append_str("CUSTOM_VMCOREDD_SIZE=%zu\n", custom_vmcoredd_blob_size);
	vmcoreinfo_append_str("CUSTOM_PRINTK_TAIL_LEN=%zu\n", custom_printk_tail_len);
	vmcoreinfo_append_str("CUSTOM_PRINTK_TAIL_CRC=0x%08x\n", custom_printk_tail_crc);
	vmcoreinfo_append_str("CUSTOM_PCI_CFG40=0x%08x\n", hdr->pci_cfg40);
	vmcoreinfo_append_str("CUSTOM_MMIO32=0x%08x\n", hdr->mmio32);
	vmcoreinfo_append_str("CUSTOM_IOPORT32=0x%08x\n", hdr->ioport32);
}

/*
 * Assemble the vmcoredd blob in custom_vmcoredd_blob[].
 *
 * Layout:
 *   [0]                  custom_vmcoredd_header
 *   [sizeof(header)]     record_count × custom_vmcoredd_cpu_record  (CPU states)
 *   [header + records]   printk tail bytes  (up to CUSTOM_PRINTK_TAIL_BYTES)
 *
 * payload_crc covers everything after the header (records + tail).
 * Updates custom_vmcoredd_blob_size so the 2nd kernel knows how many bytes
 * to copy via custom_vmcoredd_copy_from_oldmem().
 */
static void custom_vmcoredd_prepare_blob(u32 cfg40, u32 mmio_val, u32 io_val)
{
	struct custom_vmcoredd_header *hdr;
	size_t off = sizeof(*hdr);
	size_t tail_len;
	u32 record_count = 0;
	int cpu;

	hdr = (struct custom_vmcoredd_header *)custom_vmcoredd_blob;

	for_each_online_cpu(cpu) {
		struct custom_vmcoredd_cpu_record *rec;
		struct custom_nmi_cpu_state *s;

		s = &per_cpu(custom_nmi_cpu_state, cpu);
		/* Exclude slots from pre-panic or spurious NMIs (wrong generation). */
		if (!smp_load_acquire(&s->valid) ||
		    s->capture_gen != custom_capture_generation)
			continue;

		if (record_count >= CUSTOM_VMCOREDD_MAX_CPUS)
			break;
		if (off + sizeof(*rec) > sizeof(custom_vmcoredd_blob))
			break;

		rec = (struct custom_vmcoredd_cpu_record *)(custom_vmcoredd_blob + off);
		rec->cpu = cpu;
		rec->reserved = 0;
		rec->state = *s;
		off += sizeof(*rec);
		record_count++;
	}

	tail_len = min(custom_printk_tail_len, sizeof(custom_printk_tail));
	if (off + tail_len > sizeof(custom_vmcoredd_blob))
		tail_len = sizeof(custom_vmcoredd_blob) - off;
	if (tail_len)
		memcpy(custom_vmcoredd_blob + off, custom_printk_tail, tail_len);

	hdr->magic = CUSTOM_VMCOREDD_MAGIC;
	hdr->version = CUSTOM_VMCOREDD_VERSION;
	hdr->total_size = off + tail_len;
	/* Use record_count (the loop result) as the authoritative captured count.
	 * This avoids a race where custom_count_captured_cpus() and the loop
	 * below observe a different number of valid slots.
	 */
	hdr->captured_cpus = record_count;
	hdr->online_cpus = num_online_cpus();
	hdr->record_count = record_count;
	hdr->record_size = sizeof(struct custom_vmcoredd_cpu_record);
	hdr->printk_tail_len = tail_len;
	hdr->printk_tail_crc = crc32_le(0, custom_vmcoredd_blob + off, tail_len);
	hdr->pci_cfg40 = cfg40;
	hdr->mmio32 = mmio_val;
	hdr->ioport32 = io_val;
	hdr->payload_crc = crc32_le(0, custom_vmcoredd_blob + sizeof(*hdr),
				    hdr->total_size - sizeof(*hdr));

	/* Keep vmcoreinfo-exported values aligned with the blob payload. */
	custom_printk_tail_len = tail_len;
	custom_printk_tail_crc = hdr->printk_tail_crc;

	custom_vmcoredd_blob_size = hdr->total_size;
}

/* Parse a "KEY=value\n" line from a vmcoreinfo string into a u64. */
static bool custom_vmcoreinfo_get_u64(const char *vmcoreinfo, const char *key,
				      u64 *value)
{
	const char *line;
	const char *end;
	char tmp[32];
	size_t len;

	line = strstr(vmcoreinfo, key);
	if (!line)
		return false;

	line += strlen(key);
	end = strchr(line, '\n');
	if (!end)
		end = line + strlen(line);

	len = min_t(size_t, end - line, sizeof(tmp) - 1);
	memcpy(tmp, line, len);
	tmp[len] = '\0';

	return !kstrtoull(tmp, 0, value);
}

/*
 * Walk a raw ELF PT_NOTE region and locate the VMCOREINFO note.
 * Returns true and copies the note descriptor into *out on success.
 */
static bool custom_find_vmcoreinfo_in_notes(void *notes, size_t notes_size,
					    char *out, size_t out_sz)
{
	size_t off = 0;

	while (off + sizeof(struct elf_note) <= notes_size) {
		struct elf_note *note = (struct elf_note *)(notes + off);
		size_t name_off;
		size_t desc_off;
		size_t next_off;

		if (!note->n_namesz)
			break;

		name_off = off + sizeof(*note);
		desc_off = name_off + ALIGN(note->n_namesz, 4);
		next_off = desc_off + ALIGN(note->n_descsz, 4);
		if (next_off > notes_size)
			break;

		if (note->n_type == 0 &&
		    note->n_namesz == sizeof(VMCOREINFO_NOTE_NAME) &&
		    !memcmp(notes + name_off, VMCOREINFO_NOTE_NAME,
			    sizeof(VMCOREINFO_NOTE_NAME))) {
			size_t copy_len = min_t(size_t, note->n_descsz, out_sz - 1);

			memcpy(out, notes + desc_off, copy_len);
			out[copy_len] = '\0';
			return true;
		}

		off = next_off;
	}

	return false;
}

/*
 * Read the vmcoreinfo ELF note from the 1st kernel's ELF core header
 * (accessible via elfcorehdr_addr in the 2nd kernel).
 * Only ELF64 format is supported; returns -EINVAL for ELF32.
 */
static int custom_read_vmcoreinfo_from_oldmem(char *out, size_t out_sz)
{
	unsigned char ident[EI_NIDENT];
	u64 pos = elfcorehdr_addr;
	int ret;

	ret = elfcorehdr_read(ident, sizeof(ident), &pos);
	if (ret < 0)
		return ret;
	if (memcmp(ident, ELFMAG, SELFMAG))
		return -EINVAL;

	if (ident[EI_CLASS] == ELFCLASS64) {
		Elf64_Ehdr ehdr;
		Elf64_Phdr *phdrs;
		int i;

		pos = elfcorehdr_addr;
		ret = elfcorehdr_read((char *)&ehdr, sizeof(ehdr), &pos);
		if (ret < 0)
			return ret;

		phdrs = vmalloc(array_size(ehdr.e_phnum, sizeof(*phdrs)));
		if (!phdrs)
			return -ENOMEM;

		pos = elfcorehdr_addr + ehdr.e_phoff;
		ret = elfcorehdr_read((char *)phdrs,
				     ehdr.e_phnum * sizeof(*phdrs), &pos);
		if (ret < 0)
			goto out_free_64;

		for (i = 0; i < ehdr.e_phnum; i++) {
			void *notes;
			u64 note_pos;

			if (phdrs[i].p_type != PT_NOTE || !phdrs[i].p_memsz)
				continue;

			notes = vmalloc(phdrs[i].p_memsz);
			if (!notes) {
				ret = -ENOMEM;
				goto out_free_64;
			}

			note_pos = phdrs[i].p_offset;
			ret = elfcorehdr_read_notes(notes, phdrs[i].p_memsz, &note_pos);
			if (ret < 0) {
				vfree(notes);
				goto out_free_64;
			}

			if (custom_find_vmcoreinfo_in_notes(notes, phdrs[i].p_memsz,
							   out, out_sz)) {
				vfree(notes);
				ret = 0;
				goto out_free_64;
			}

			vfree(notes);
		}

		ret = -ENOENT;
out_free_64:
		vfree(phdrs);
		return ret;
	}

	return -EINVAL;
}

/*
 * vmcoredd callback invoked by the vmcore layer when user space reads the
 * device dump region from /proc/vmcore.  Streams custom_vmcoredd_blob_size
 * bytes of old memory (physical address custom_vmcoredd_oldmem_paddr) into
 * the caller-supplied buffer page by page.
 */
static int custom_vmcoredd_copy_from_oldmem(struct vmcoredd_data *data, void *buf)
{
	u64 pos = custom_vmcoredd_oldmem_paddr;
	char *dst = buf;
	size_t left = data->size;

	while (left) {
		size_t chunk = min_t(size_t, left,
				     PAGE_SIZE - (size_t)(pos & (PAGE_SIZE - 1)));
		struct kvec kvec = {
			.iov_base = dst,
			.iov_len = chunk,
		};
		struct iov_iter iter;
		ssize_t n;

		iov_iter_kvec(&iter, ITER_DEST, &kvec, 1, chunk);
		n = read_from_oldmem(&iter, chunk, &pos,
				    cc_platform_has(CC_ATTR_MEM_ENCRYPT));
		if (n != chunk)
			return -EIO;

		dst += chunk;
		left -= chunk;
	}

	return 0;
}

/*
 * Register the vmcoredd device dump with the vmcore layer (2nd kernel only).
 *
 * Reads CUSTOM_VMCOREDD_PADDR and CUSTOM_VMCOREDD_SIZE from the vmcoreinfo
 * ELF note that the 1st kernel embedded in elfcorehdr.  Those values point
 * to the blob assembled by custom_vmcoredd_prepare_blob() in the 1st kernel.
 *
 * Note: is_kdump_kernel() is used instead of is_vmcore_usable() because
 * vmcore_init() (fs_initcall) sets elfcorehdr_addr = ELFCORE_ADDR_ERR on
 * success, which makes is_vmcore_usable() return false at late_initcall time.
 * is_kdump_kernel() only checks that elfcorehdr_addr != ELFCORE_ADDR_MAX and
 * is therefore correct here.
 */
static int __init custom_vmcoredd_register(void)
{
	u64 paddr;
	u64 size;
	int ret;

	if (!is_kdump_kernel())
		return 0;

	ret = custom_read_vmcoreinfo_from_oldmem(custom_vmcoreinfo_scratch,
					 sizeof(custom_vmcoreinfo_scratch));
	if (ret) {
		pr_info("custom vmcoredd: vmcoreinfo metadata not found (%d)\n", ret);
		return ret;
	}

	if (!custom_vmcoreinfo_get_u64(custom_vmcoreinfo_scratch,
				      "CUSTOM_VMCOREDD_PADDR=", &paddr) ||
	    !custom_vmcoreinfo_get_u64(custom_vmcoreinfo_scratch,
				      "CUSTOM_VMCOREDD_SIZE=", &size)) {
		pr_info("custom vmcoredd: custom metadata missing\n");
		return -ENOENT;
	}

	if (!size || size > UINT_MAX) {
		pr_warn("custom vmcoredd: invalid metadata size=%llu\n", size);
		return -EINVAL;
	}

	custom_vmcoredd_oldmem_paddr = paddr;
	custom_vmcoredd_oldmem_size = size;
	custom_vmcoredd_data.size = custom_vmcoredd_oldmem_size;

	ret = vmcore_add_device_dump(&custom_vmcoredd_data);
	if (ret) {
		pr_warn("custom vmcoredd: add device dump failed (%d)\n", ret);
		return ret;
	}

	pr_info("custom vmcoredd: registered paddr=%#llx size=%u\n",
		custom_vmcoredd_oldmem_paddr, custom_vmcoredd_oldmem_size);
	return 0;
}

/*
 * NMI handler registered for both NMI_UNKNOWN and NMI_LOCAL.
 * Captures the current CPU's register state so it is available when
 * the panic CPU assembles the vmcoredd blob.
 */
static int custom_nmi_handler(unsigned int val, struct pt_regs *regs)
{
	custom_nmi_capture(regs);
	/*
	 * Return NMI_DONE (not NMI_HANDLED) so that the "arch_bt" handler
	 * (nmi_cpu_backtrace_handler, registered by hw_nmi.c) can also run and
	 * clear this CPU's bit in backtrace_mask.  If we returned NMI_HANDLED,
	 * the backtrace_mask bit would never be cleared and
	 * nmi_trigger_cpumask_backtrace() would always time out after 10 seconds.
	 */
	return NMI_DONE;
}

/*
 * Panic notifier: logs that panic has been observed.
 *
 * Note: this notifier runs at priority INT_MAX-1, before __crash_kexec()
 * calls custom_crashdump_capture().  At this point no NMI capture round
 * has been started yet (custom_capture_generation has not been incremented),
 * so meaningful per-CPU counts are not available.  The log entry serves only
 * as a breadcrumb that the notifier chain was reached.
 */
static int custom_panic_notifier(struct notifier_block *nb,
					unsigned long action, void *data)
{
	pr_info("custom crashdump: panic observed, NMI capture pending\n");
	return NOTIFY_DONE;
}

static struct notifier_block custom_panic_nb = {
	.notifier_call = custom_panic_notifier,
	.priority = INT_MAX - 1,
};

/*
 * arch_initcall: register NMI handlers and panic notifier.
 *
 * Runs during early boot (before PCI probe / device_initcall).  Registers:
 *   - NMI_UNKNOWN + NMI_LOCAL handlers for per-CPU register capture
 *   - panic notifier as a breadcrumb that the panic chain was reached
 */
static int __init custom_crashdump_nmi_init(void)
{
	int rc;
	bool nmi_registered = false;

	/*
	 * Verify the wire-format layout of custom_nmi_cpu_state.
	 * bool valid (1 byte) is followed by 1 byte of implicit padding before
	 * u16 cs.  If the compiler or ABI ever changes this, the Python parser
	 * (show_vmcoredd.py) will silently misparse every field.
	 */
	BUILD_BUG_ON(offsetof(struct custom_nmi_cpu_state, cs) != 2);
	BUILD_BUG_ON(offsetof(struct custom_nmi_cpu_state, stack_len) !=
		     offsetof(struct custom_nmi_cpu_state, apic_base) + sizeof(u64));

	if (custom_nmi_handlers) {
		rc = register_nmi_handler(NMI_UNKNOWN, custom_nmi_handler,
					  NMI_FLAG_FIRST,
					  "custom-crashdump-nmi-unknown");
		if (rc)
			return rc;

		rc = register_nmi_handler(NMI_LOCAL, custom_nmi_handler,
					  NMI_FLAG_FIRST,
					  "custom-crashdump-nmi-local");
		if (rc) {
			unregister_nmi_handler(NMI_UNKNOWN,
						"custom-crashdump-nmi-unknown");
			return rc;
		}

		nmi_registered = true;
	}

	rc = atomic_notifier_chain_register(&panic_notifier_list, &custom_panic_nb);
	if (rc) {
		if (nmi_registered) {
			unregister_nmi_handler(NMI_LOCAL,
						"custom-crashdump-nmi-local");
			unregister_nmi_handler(NMI_UNKNOWN,
						"custom-crashdump-nmi-unknown");
		}
		return rc;
	}

	pr_info("custom crashdump NMI+panic notifier enabled\n");
	return 0;
}
arch_initcall(custom_crashdump_nmi_init);

/*
 * late_initcall: attempt to register the vmcoredd blob in the 2nd kernel.
 * Runs after vmcore_init() has completed so /proc/vmcore is almost ready.
 * Ignores -ENOENT (not a kdump kernel or metadata not present).
 */
static int __init custom_vmcoredd_late_init(void)
{
	int rc;

	rc = custom_vmcoredd_register();
	if (rc && rc != -ENOENT)
		pr_warn("custom vmcoredd: registration skipped (%d)\n", rc);
	return 0;
}
late_initcall(custom_vmcoredd_late_init);