# Trace Linux boot
-- OSH lab01
## ENVIRONMENT
- Archlinux with kernel 4.15.13-1-ARCH
- qemu 2.11.1-2
- gdb 8.1
- gcc 7.3.1
## establish of lab environment
- clone the kernel source: [https://github.com/torvalds/linux](https://github.com/torvalds/linux)
```sh
git clone https://github.com/torvalds/linux.git
```
- compile
```sh
make menuconfig
make -j8 bzImage
```
during make menuconfig, select Kernel hacking->Compile-time->checks and compiler options->Compile the kernel with debug info, which can guarantee the debug info included in the kernel
- create virtual disk and format
```sh
qemu-img create disk.img 1g
mkfs.ext4 disk.img
```
- create Archlinux bootstrap
```sh
mkdir root.x86_64
mount -o loop disk.img root.x86_64
aria2c https://mirrors.ustc.edu.cn/archlinux/iso/latest/archlinux-bootstrap-2018.04.01-x86_64.tar.gz
tar xzf <path-to-bootstrap-image>/archlilnux-bootstrap-2018.04.01-x86_64.tar.gz
cp /usr/bin/init root.x86_64/usr/bin/
cp /usr/bin/shutdown root.x86_64/usr/bin
umount root.x86_64
```
there is the tutor in archwiki: [Install from existing Linux](https://wiki.archlinux.org/index.php/Install_from_existing_Linux#Creating_the_chroot)
, and the bootstrap didn't have init and command, to make the bootstrap can init, I copy the init binary in local system to the disk image.

Then I use `qemu-system-x86_64 -kernel arch/x86/boot/bzImage -hda disk.img -append "root=/dev/sda console=ttyS0 nokaslr " -s -S --nographic` to boot qemu, and type `./gdb.sh` to boot gdb and break at function start_kernel()

I had grub bootloader installed, so kernel can boot directly

After start_kernel called:
- set_task_stack_end_magic() -- kernel/fork.c
```c
void set_task_stack_end_magic(struct task_struct *tsk)
{
  unsigned long *stackend;

  stackend = end_of_stack(tsk);
  *stackend = STACK_END_MAGIC;  /* for overflow detection */
}
```
- cgroup_init_early() --kernel/cgroup/cgroup.c
    - cgroup initialization at system boot, and initialize any subsystems that request early init
```c
int __init cgroup_init_early(void)
{
  static struct cgroup_sb_opts __initdata opts;
  struct cgroup_subsys *ss; 
  int i;

  init_cgroup_root(&cgrp_dfl_root, &opts);
  cgrp_dfl_root.cgrp.self.flags |= CSS_NO_REF;

  RCU_INIT_POINTER(init_task.cgroups, &init_css_set);

  for_each_subsys(ss, i) { 
    WARN(!ss->css_alloc || !ss->css_free || ss->name || ss->id,
         "invalid cgroup_subsys %d:%s css_alloc=%p css_free=%p id:name=%d:%s\n",
         i, cgroup_subsys_name[i], ss->css_alloc, ss->css_free,
         ss->id, ss->name);
    WARN(strlen(cgroup_subsys_name[i]) > MAX_CGROUP_TYPE_NAMELEN,
         "cgroup_subsys_name %s too long\n", cgroup_subsys_name[i]);

    ss->id = i; 
    ss->name = cgroup_subsys_name[i];
    if (!ss->legacy_name)
      ss->legacy_name = cgroup_subsys_name[i];

    if (ss->early_init)
      cgroup_init_subsys(ss, true);
  }
  return 0;
}
```
---

#enable interrupts

---
- boot_cpu_init() -- kernel/cpu.c
    - Activate the first processor
```c
void __init boot_cpu_init(void)
{
  int cpu = smp_processor_id();

  /* Mark the boot cpu "present", "online" etc for SMP and UP case */
  set_cpu_online(cpu, true);
  set_cpu_active(cpu, true);
  set_cpu_present(cpu, true);
  set_cpu_possible(cpu, true);

#ifdef CONFIG_SMP
  __boot_cpu_id = cpu;
#endif
}
```
- setup_arch() -- arch/x86/kernel/setup.c
    - architecture-specific boot-time initializations
```c
void __init setup_arch(char **cmdline_p)
{
	memblock_reserve(__pa_symbol(_text),
			 (unsigned long)__bss_stop - (unsigned long)_text);

	early_reserve_initrd();

	/*
	 * At this point everything still needed from the boot loader
	 * or BIOS or kernel text should be early reserved or marked not
	 * RAM in e820. All other memory is free game.
	 */

#ifdef CONFIG_X86_32
	memcpy(&boot_cpu_data, &new_cpu_data, sizeof(new_cpu_data));

	/*
	 * copy kernel address range established so far and switch
	 * to the proper swapper page table
	 */
	clone_pgd_range(swapper_pg_dir     + KERNEL_PGD_BOUNDARY,
			initial_page_table + KERNEL_PGD_BOUNDARY,
			KERNEL_PGD_PTRS);

	load_cr3(swapper_pg_dir);
	/*
	 * Note: Quark X1000 CPUs advertise PGE incorrectly and require
	 * a cr3 based tlb flush, so the following __flush_tlb_all()
	 * will not flush anything because the cpu quirk which clears
	 * X86_FEATURE_PGE has not been invoked yet. Though due to the
	 * load_cr3() above the TLB has been flushed already. The
	 * quirk is invoked before subsequent calls to __flush_tlb_all()
	 * so proper operation is guaranteed.
	 */
	__flush_tlb_all();
#else
	printk(KERN_INFO "Command line: %s\n", boot_command_line);
#endif

	/*
	 * If we have OLPC OFW, we might end up relocating the fixmap due to
	 * reserve_top(), so do this before touching the ioremap area.
	 */
	olpc_ofw_detect();

	idt_setup_early_traps();
	early_cpu_init();
	early_ioremap_init();

	setup_olpc_ofw_pgd();

	ROOT_DEV = old_decode_dev(boot_params.hdr.root_dev);
	screen_info = boot_params.screen_info;
	edid_info = boot_params.edid_info;
#ifdef CONFIG_X86_32
	apm_info.bios = boot_params.apm_bios_info;
	ist_info = boot_params.ist_info;
#endif
	saved_video_mode = boot_params.hdr.vid_mode;
	bootloader_type = boot_params.hdr.type_of_loader;
	if ((bootloader_type >> 4) == 0xe) {
		bootloader_type &= 0xf;
		bootloader_type |= (boot_params.hdr.ext_loader_type+0x10) << 4;
	}
	bootloader_version  = bootloader_type & 0xf;
	bootloader_version |= boot_params.hdr.ext_loader_ver << 4;

#ifdef CONFIG_BLK_DEV_RAM
	rd_image_start = boot_params.hdr.ram_size & RAMDISK_IMAGE_START_MASK;
	rd_prompt = ((boot_params.hdr.ram_size & RAMDISK_PROMPT_FLAG) != 0);
	rd_doload = ((boot_params.hdr.ram_size & RAMDISK_LOAD_FLAG) != 0);
#endif
#ifdef CONFIG_EFI
	if (!strncmp((char *)&boot_params.efi_info.efi_loader_signature,
		     EFI32_LOADER_SIGNATURE, 4)) {
		set_bit(EFI_BOOT, &efi.flags);
	} else if (!strncmp((char *)&boot_params.efi_info.efi_loader_signature,
		     EFI64_LOADER_SIGNATURE, 4)) {
		set_bit(EFI_BOOT, &efi.flags);
		set_bit(EFI_64BIT, &efi.flags);
	}
#endif

	x86_init.oem.arch_setup();

	iomem_resource.end = (1ULL << boot_cpu_data.x86_phys_bits) - 1;
	e820__memory_setup();
	parse_setup_data();

	copy_edd();

	if (!boot_params.hdr.root_flags)
		root_mountflags &= ~MS_RDONLY;
	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code = (unsigned long) _etext;
	init_mm.end_data = (unsigned long) _edata;
	init_mm.brk = _brk_end;

	mpx_mm_init(&init_mm);

	code_resource.start = __pa_symbol(_text);
	code_resource.end = __pa_symbol(_etext)-1;
	data_resource.start = __pa_symbol(_etext);
	data_resource.end = __pa_symbol(_edata)-1;
	bss_resource.start = __pa_symbol(__bss_start);
	bss_resource.end = __pa_symbol(__bss_stop)-1;

#ifdef CONFIG_CMDLINE_BOOL
#ifdef CONFIG_CMDLINE_OVERRIDE
	strlcpy(boot_command_line, builtin_cmdline, COMMAND_LINE_SIZE);
#else
	if (builtin_cmdline[0]) {
		/* append boot loader cmdline to builtin */
		strlcat(builtin_cmdline, " ", COMMAND_LINE_SIZE);
		strlcat(builtin_cmdline, boot_command_line, COMMAND_LINE_SIZE);
		strlcpy(boot_command_line, builtin_cmdline, COMMAND_LINE_SIZE);
	}
#endif
#endif

	strlcpy(command_line, boot_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = command_line;

	/*
	 * x86_configure_nx() is called before parse_early_param() to detect
	 * whether hardware doesn't support NX (so that the early EHCI debug
	 * console setup can safely call set_fixmap()). It may then be called
	 * again from within noexec_setup() during parsing early parameters
	 * to honor the respective command line option.
	 */
	x86_configure_nx();

	parse_early_param();

	if (efi_enabled(EFI_BOOT))
		efi_memblock_x86_reserve_range();
#ifdef CONFIG_MEMORY_HOTPLUG
	/*
	 * Memory used by the kernel cannot be hot-removed because Linux
	 * cannot migrate the kernel pages. When memory hotplug is
	 * enabled, we should prevent memblock from allocating memory
	 * for the kernel.
	 *
	 * ACPI SRAT records all hotpluggable memory ranges. But before
	 * SRAT is parsed, we don't know about it.
	 *
	 * The kernel image is loaded into memory at very early time. We
	 * cannot prevent this anyway. So on NUMA system, we set any
	 * node the kernel resides in as un-hotpluggable.
	 *
	 * Since on modern servers, one node could have double-digit
	 * gigabytes memory, we can assume the memory around the kernel
	 * image is also un-hotpluggable. So before SRAT is parsed, just
	 * allocate memory near the kernel image to try the best to keep
	 * the kernel away from hotpluggable memory.
	 */
	if (movable_node_is_enabled())
		memblock_set_bottom_up(true);
#endif

	x86_report_nx();

	/* after early param, so could get panic from serial */
	memblock_x86_reserve_range_setup_data();

	if (acpi_mps_check()) {
#ifdef CONFIG_X86_LOCAL_APIC
		disable_apic = 1;
#endif
		setup_clear_cpu_cap(X86_FEATURE_APIC);
	}

#ifdef CONFIG_PCI
	if (pci_early_dump_regs)
		early_dump_pci_devices();
#endif

	e820__reserve_setup_data();
	e820__finish_early_params();

	if (efi_enabled(EFI_BOOT))
		efi_init();

	dmi_scan_machine();
	dmi_memdev_walk();
	dmi_set_dump_stack_arch_desc();

	/*
	 * VMware detection requires dmi to be available, so this
	 * needs to be done after dmi_scan_machine(), for the boot CPU.
	 */
	init_hypervisor_platform();

	x86_init.resources.probe_roms();

	/* after parse_early_param, so could debug it */
	insert_resource(&iomem_resource, &code_resource);
	insert_resource(&iomem_resource, &data_resource);
	insert_resource(&iomem_resource, &bss_resource);

	e820_add_kernel_range();
	trim_bios_range();
#ifdef CONFIG_X86_32
	if (ppro_with_ram_bug()) {
		e820__range_update(0x70000000ULL, 0x40000ULL, E820_TYPE_RAM,
				  E820_TYPE_RESERVED);
		e820__update_table(e820_table);
		printk(KERN_INFO "fixed physical RAM map:\n");
		e820__print_table("bad_ppro");
	}
#else
	early_gart_iommu_check();
#endif

	/*
	 * partially used pages are not usable - thus
	 * we are rounding upwards:
	 */
	max_pfn = e820__end_of_ram_pfn();

	/* update e820 for memory not covered by WB MTRRs */
	mtrr_bp_init();
	if (mtrr_trim_uncached_memory(max_pfn))
		max_pfn = e820__end_of_ram_pfn();

	max_possible_pfn = max_pfn;

	/*
	 * This call is required when the CPU does not support PAT. If
	 * mtrr_bp_init() invoked it already via pat_init() the call has no
	 * effect.
	 */
	init_cache_modes();

	/*
	 * Define random base addresses for memory sections after max_pfn is
	 * defined and before each memory section base is used.
	 */
	kernel_randomize_memory();

#ifdef CONFIG_X86_32
	/* max_low_pfn get updated here */
	find_low_pfn_range();
#else
	check_x2apic();

	/* How many end-of-memory variables you have, grandma! */
	/* need this before calling reserve_initrd */
	if (max_pfn > (1UL<<(32 - PAGE_SHIFT)))
		max_low_pfn = e820__end_of_low_ram_pfn();
	else
		max_low_pfn = max_pfn;

	high_memory = (void *)__va(max_pfn * PAGE_SIZE - 1) + 1;
#endif

	/*
	 * Find and reserve possible boot-time SMP configuration:
	 */
	find_smp_config();

	reserve_ibft_region();

	early_alloc_pgt_buf();

	/*
	 * Need to conclude brk, before e820__memblock_setup()
	 *  it could use memblock_find_in_range, could overlap with
	 *  brk area.
	 */
	reserve_brk();

	cleanup_highmap();

	memblock_set_current_limit(ISA_END_ADDRESS);
	e820__memblock_setup();

	reserve_bios_regions();

	if (efi_enabled(EFI_MEMMAP)) {
		efi_fake_memmap();
		efi_find_mirror();
		efi_esrt_init();

		/*
		 * The EFI specification says that boot service code won't be
		 * called after ExitBootServices(). This is, in fact, a lie.
		 */
		efi_reserve_boot_services();
	}

	/* preallocate 4k for mptable mpc */
	e820__memblock_alloc_reserved_mpc_new();

#ifdef CONFIG_X86_CHECK_BIOS_CORRUPTION
	setup_bios_corruption_check();
#endif

#ifdef CONFIG_X86_32
	printk(KERN_DEBUG "initial memory mapped: [mem 0x00000000-%#010lx]\n",
			(max_pfn_mapped<<PAGE_SHIFT) - 1);
#endif

	reserve_real_mode();

	trim_platform_memory_ranges();
	trim_low_memory_range();

	init_mem_mapping();

	idt_setup_early_pf();

	/*
	 * Update mmu_cr4_features (and, indirectly, trampoline_cr4_features)
	 * with the current CR4 value.  This may not be necessary, but
	 * auditing all the early-boot CR4 manipulation would be needed to
	 * rule it out.
	 *
	 * Mask off features that don't work outside long mode (just
	 * PCIDE for now).
	 */
	mmu_cr4_features = __read_cr4() & ~X86_CR4_PCIDE;

	memblock_set_current_limit(get_max_mapped());

	/*
	 * NOTE: On x86-32, only from this point on, fixmaps are ready for use.
	 */

#ifdef CONFIG_PROVIDE_OHCI1394_DMA_INIT
	if (init_ohci1394_dma_early)
		init_ohci1394_dma_on_all_controllers();
#endif
	/* Allocate bigger log buffer */
	setup_log_buf(1);

	if (efi_enabled(EFI_BOOT)) {
		switch (boot_params.secure_boot) {
		case efi_secureboot_mode_disabled:
			pr_info("Secure boot disabled\n");
			break;
		case efi_secureboot_mode_enabled:
			pr_info("Secure boot enabled\n");
			break;
		default:
			pr_info("Secure boot could not be determined\n");
			break;
		}
	}

	reserve_initrd();

	acpi_table_upgrade();

	vsmp_init();

	io_delay_init();

	early_platform_quirks();

	/*
	 * Parse the ACPI tables for possible boot-time SMP configuration.
	 */
	acpi_boot_table_init();

	early_acpi_boot_init();

	initmem_init();
	dma_contiguous_reserve(max_pfn_mapped << PAGE_SHIFT);

	/*
	 * Reserve memory for crash kernel after SRAT is parsed so that it
	 * won't consume hotpluggable memory.
	 */
	reserve_crashkernel();

	memblock_find_dma_reserve();

#ifdef CONFIG_KVM_GUEST
	kvmclock_init();
#endif

	tsc_early_delay_calibrate();
	if (!early_xdbc_setup_hardware())
		early_xdbc_register_console();

	x86_init.paging.pagetable_init();

	kasan_init();

	/*
	 * Sync back kernel address range.
	 *
	 * FIXME: Can the later sync in setup_cpu_entry_areas() replace
	 * this call?
	 */
	sync_initial_page_table();

	tboot_probe();

	map_vsyscall();

	generic_apic_probe();

	early_quirks();

	/*
	 * Read APIC and some other early information from ACPI tables.
	 */
	acpi_boot_init();
	sfi_init();
	x86_dtb_init();

	/*
	 * get boot-time SMP configuration:
	 */
	get_smp_config();

	/*
	 * Systems w/o ACPI and mptables might not have it mapped the local
	 * APIC yet, but prefill_possible_map() might need to access it.
	 */
	init_apic_mappings();

	prefill_possible_map();

	init_cpu_to_node();

	io_apic_init_mappings();

	x86_init.hyper.guest_late_init();

	e820__reserve_resources();
	e820__register_nosave_regions(max_low_pfn);

	x86_init.resources.reserve_resources();

	e820__setup_pci_gap();

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	if (!efi_enabled(EFI_BOOT) || (efi_mem_type(0xa0000) != EFI_CONVENTIONAL_MEMORY))
		conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)
	conswitchp = &dummy_con;
#endif
#endif
	x86_init.oem.banner();

	x86_init.timers.wallclock_init();

	mcheck_init();

	arch_init_ideal_nops();

	register_refined_jiffies(CLOCK_TICK_RATE);

#ifdef CONFIG_EFI
	if (efi_enabled(EFI_BOOT))
		efi_apply_memmap_quirks();
#endif

	unwind_init();
}
```
---

#set up the initial canary and entropy after arch and after adding latent and command line entropy

---
- boot_init_stack_canary() -- arch/x86/include/asm/stackprotector.h
    - initialize the stackprotector canary value
```c
static __always_inline void boot_init_stack_canary(void)
{
	u64 canary;
	u64 tsc;

#ifdef CONFIG_X86_64
	BUILD_BUG_ON(offsetof(union irq_stack_union, stack_canary) != 40);
#endif
	/*
	 * We both use the random pool and the current TSC as a source
	 * of randomness. The TSC only matters for very early init,
	 * there it already has some randomness on most systems. Later
	 * on during the bootup the random pool has true entropy too.
	 */
	get_random_bytes(&canary, sizeof(canary));
	tsc = rdtsc();
	canary += tsc + (tsc << 32UL);
	canary &= CANARY_MASK;

	current->stack_canary = canary;
#ifdef CONFIG_X86_64
	this_cpu_write(irq_stack_union.stack_canary, canary);
#else
	this_cpu_write(stack_canary.canary, canary);
#endif
}
```
- setup_command_line -- init/main.c
    - store the untouched command line and touched command line, and a component for future reference
- build_all_zonelists() -- mm/page_alloc.c
- jump_label_init()
- setup_log_buf()
- ...
## consolusion
I met many problems when establishing the environment, especisally there are no direct command to create Archlinux bootstrap, but I finish it at the end, and learned the process of kernel booting and how to debug kernel, I did gain much.