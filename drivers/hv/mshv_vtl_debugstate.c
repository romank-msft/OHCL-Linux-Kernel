// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025, Microsoft Corporation.
 *
 * Authors:
 *   Roman Kisel <romank@microsoft.com>
 */

#include <linux/capability.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/mshv.h>
#include <linux/smp.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>

#include <asm/desc.h>
#include <asm/sev.h>
#include <asm/mshyperv.h>
#include <asm/set_memory.h>

#include "mshv.h"
#include "mshv_vtl.h"
#include "mshv_vtl_local_maps.h"

MODULE_AUTHOR("Microsoft");
MODULE_LICENSE("GPL");

/*
 * TODO: Duplicating defintions. Including hyperv-tlfs.h and svm.h breaks the build.
 */
#define HV_REGISTER_GUEST_OS_ID		0x00090002

#define V_GUEST_BUSY_SHIFT 63
#define V_GUEST_BUSY_MASK (1ULL << V_GUEST_BUSY_SHIFT)
#define SVM_EXIT_INTR          0x060

#define GHCB_USAGE_HYPERV_CALL	1

union sev_event_inject {
	struct {
		u64 vector: 8;
		u64 interruption_type: 3;
		u64 deliver_error_code: 1;
		u64 _rsvd1: 19;
		u64 valid: 1;
		u64 error_code: 32;
	} e;
	u64 as_u64;
};

struct ghcb_save_area {
	u8 reserved_0x0[203];
	u8 cpl;
	u8 reserved_0xcc[116];
	u64 xss;
	u8 reserved_0x148[24];
	u64 dr7;
	u8 reserved_0x168[16];
	u64 rip;
	u8 reserved_0x180[88];
	u64 rsp;
	u8 reserved_0x1e0[24];
	u64 rax;
	u8 reserved_0x200[264];
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u8 reserved_0x320[8];
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u8 reserved_0x380[16];
	u64 sw_exit_code;
	u64 sw_exit_info_1;
	u64 sw_exit_info_2;
	u64 sw_scratch;
	u8 reserved_0x3b0[56];
	u64 xcr0;
	u8 valid_bitmap[16];
	u64 x87_state_gpa;
} __packed;

#define GHCB_SHARED_BUF_SIZE	2032

struct ghcb {
	struct ghcb_save_area save;
	u8 reserved_save[2048 - sizeof(struct ghcb_save_area)];

	u8 shared_buffer[GHCB_SHARED_BUF_SIZE];

	u8 reserved_0xff0[10];
	u16 protocol_version;	/* negotiated SEV-ES/GHCB protocol version */
	u32 ghcb_usage;
} __packed;

union hv_ghcb {
	struct ghcb ghcb;
	struct {
		u64 hypercalldata[509];
		u64 outputgpa;
		union {
			union {
				struct {
					u32 callcode        : 16;
					u32 isfast          : 1;
					u32 reserved1       : 14;
					u32 isnested        : 1;
					u32 countofelements : 12;
					u32 reserved2       : 4;
					u32 repstartindex   : 12;
					u32 reserved3       : 4;
				};
				u64 asuint64;
			} hypercallinput;
			union {
				struct {
					u16 callstatus;
					u16 reserved1;
					u32 elementsprocessed : 12;
					u32 reserved2         : 20;
				};
				u64 asunit64;
			} hypercalloutput;
		};
		u64 reserved2;
	} hypercall;
} __packed __aligned(HV_HYP_PAGE_SIZE);

struct vmcb_seg {
	u16 selector;
	u16 attrib;
	u32 limit;
	u64 base;
} __packed;

struct sev_es_save_area {
	struct vmcb_seg es;
	struct vmcb_seg cs;
	struct vmcb_seg ss;
	struct vmcb_seg ds;
	struct vmcb_seg fs;
	struct vmcb_seg gs;
	struct vmcb_seg gdtr;
	struct vmcb_seg ldtr;
	struct vmcb_seg idtr;
	struct vmcb_seg tr;
	u64 pl0_ssp;
	u64 pl1_ssp;
	u64 pl2_ssp;
	u64 pl3_ssp;
	u64 u_cet;
	u8 reserved_0xc8[2];
	u8 vmpl;
	u8 cpl;
	u8 reserved_0xcc[4];
	u64 efer;
	u8 reserved_0xd8[104];
	u64 xss;
	u64 cr4;
	u64 cr3;
	u64 cr0;
	u64 dr7;
	u64 dr6;
	u64 rflags;
	u64 rip;
	u64 dr0;
	u64 dr1;
	u64 dr2;
	u64 dr3;
	u64 dr0_addr_mask;
	u64 dr1_addr_mask;
	u64 dr2_addr_mask;
	u64 dr3_addr_mask;
	u8 reserved_0x1c0[24];
	u64 rsp;
	u64 s_cet;
	u64 ssp;
	u64 isst_addr;
	u64 rax;
	u64 star;
	u64 lstar;
	u64 cstar;
	u64 sfmask;
	u64 kernel_gs_base;
	u64 sysenter_cs;
	u64 sysenter_esp;
	u64 sysenter_eip;
	u64 cr2;
	u8 reserved_0x248[32];
	u64 g_pat;
	u64 dbgctl;
	u64 br_from;
	u64 br_to;
	u64 last_excp_from;
	u64 last_excp_to;
	u8 reserved_0x298[80];
	u32 pkru;
	u32 tsc_aux;
	u8 reserved_0x2f0[24];
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 reserved_0x320;	/* rsp already available at 0x01d8 */
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u8 reserved_0x380[16];
	u64 guest_exit_info_1;
	u64 guest_exit_info_2;
	u64 guest_exit_int_info;
	u64 guest_nrip;
	u64 sev_features;
	u64 vintr_ctrl;
	u64 guest_exit_code;
	u64 virtual_tom;
	u64 tlb_id;
	u64 pcpu_id;
	u64 event_inj;
	u64 xcr0;
	u8 reserved_0x3f0[16];

	/* Floating point area */
	u64 x87_dp;
	u32 mxcsr;
	u16 x87_ftw;
	u16 x87_fsw;
	u16 x87_fcw;
	u16 x87_fop;
	u16 x87_ds;
	u16 x87_cs;
	u64 x87_rip;
	u8 fpreg_x87[80];
	u8 fpreg_xmm[256];
	u8 fpreg_ymm[256];
} __packed;

static struct page* __percpu *mshv_vtl_dbg_snp_probe_vmsa;
static struct page* mshv_vtl_dbg_snp_probe_code_page;
static struct page* mshv_vtl_dbg_snp_probe_pml4;
static struct page* mshv_vtl_dbg_snp_probe_pdp;
static struct page* mshv_vtl_dbg_snp_probe_gdtr; /* Doesn't really need a page */
static u64 mshv_vtl_dbg_snp_probe_gdtr_size;

extern struct mshv_vtl_run *mshv_vtl_this_run(void);
extern struct sev_es_save_area *mshv_vtl_this_vmsa(void);

struct hv_input_qphv_single
{
	u64 partition_id;
	u64 gpn;
} __packed;

static u64 mshv_vtl_dbg_qphv(u64 gpn, u64 *host_vis)
{
	union hv_ghcb *hv_ghcb;
	void **ghcb_base;
	unsigned long flags;
	u64 status;
	struct hv_input_qphv_single qphv = { .gpn = gpn, .partition_id = HV_PARTITION_ID_SELF };

	if (!hv_ghcb_pg) {
		pr_err("%s: no hv_ghcb_pg\n", __func__);
		return -EFAULT;
	}

	local_irq_save(flags);
	ghcb_base = (void **)this_cpu_ptr(hv_ghcb_pg);
	hv_ghcb = (union hv_ghcb *)*ghcb_base;
	if (!hv_ghcb) {
		pr_err("%s: no hv_ghcb\n", __func__);
		local_irq_restore(flags);
		return -EFAULT;
	}

	hv_ghcb->ghcb.protocol_version = GHCB_PROTOCOL_MAX;
	hv_ghcb->ghcb.ghcb_usage = GHCB_USAGE_HYPERV_CALL;

	hv_ghcb->hypercall.hypercalldata[442] = 0;
	hv_ghcb->hypercall.outputgpa = (u64)&(hv_ghcb->hypercall.hypercalldata[442]);
	hv_ghcb->hypercall.hypercallinput.asuint64 = 0;
	hv_ghcb->hypercall.hypercallinput.callcode = 0x011c;
	hv_ghcb->hypercall.hypercallinput.countofelements = 1;
	memcpy(hv_ghcb->hypercall.hypercalldata, &qphv, sizeof(qphv));

	VMGEXIT();
	*host_vis = hv_ghcb->hypercall.hypercalldata[442];

	hv_ghcb->ghcb.ghcb_usage = 0xffffffff;
	memset(hv_ghcb->ghcb.save.valid_bitmap, 0,
		   sizeof(hv_ghcb->ghcb.save.valid_bitmap));

	status = hv_ghcb->hypercall.hypercalloutput.callstatus;

	local_irq_restore(flags);

	return status;
}

struct mshv_vtl_dbg_vp_vtl0 {
	u64 vp_count;
	u64 reg_count;
	u64 vp_success;
	u64 reg_list_size_bytes;
	struct hv_register_assoc __user *user_reg_list; /* `reg_count` registers for each `vp_count` VPs */
} __packed;

struct mshv_vtl_dbg_read_page {
	u64 pfn;
	void __user *dst;
} __packed;

#define MSHV_DBG_STATE_IOCTL 0xB9

#define MSHV_DBG_VP_VTL0_STATE _IOWR(MSHV_DBG_STATE_IOCTL, 0xEE, struct mshv_vtl_dbg_vp_vtl0)
#define MSHV_DBG_READ_PAGE     _IOWR(MSHV_DBG_STATE_IOCTL, 0xEF, struct mshv_vtl_dbg_read_page)

static void mshv_vtl_dbgstate_init_ghcb(void* arg)
{
	u64 ghcb_gpa;
	void *ghcb_va;
	void **ghcb_base;

	pr_info("%s: initializing GHCB on CPU %d\n", __func__, smp_processor_id());

	ghcb_base = (void **)this_cpu_ptr(hv_ghcb_pg);
	if (*ghcb_base) {
		pr_info("%s: already initialized GHCB on CPU %d\n", __func__, smp_processor_id());
		return;
	}

	rdmsrl(MSR_AMD64_SEV_ES_GHCB, ghcb_gpa);

	ghcb_va = (void *)ioremap_cache(ghcb_gpa, HV_HYP_PAGE_SIZE);
	if (!ghcb_va) {
		pr_err("%s: OOM, CPU %d\n", __func__, smp_processor_id());
		return;
	}

	*ghcb_base = ghcb_va;
	pr_info("%s: initialized GHCB on CPU %d\n", __func__, smp_processor_id());
}

static void mshv_vtl_dbgstate_setup_vmsa(struct sev_es_save_area* vmsa)
{
	/* Running in the identical mapping */

	vmsa->gdtr.base = page_to_phys(mshv_vtl_dbg_snp_probe_gdtr);
	vmsa->gdtr.limit = mshv_vtl_dbg_snp_probe_gdtr_size;

	__asm __volatile("movl %%es, %%eax;" : "=a" (vmsa->es.selector));
	__asm __volatile("movl %%cs, %%eax;" : "=a" (vmsa->cs.selector));
	__asm __volatile("movl %%ss, %%eax;" : "=a" (vmsa->ss.selector));
	__asm __volatile("movl %%ds, %%eax;" : "=a" (vmsa->ds.selector));

	vmsa->efer = native_read_msr(MSR_EFER);

	vmsa->cr4 = native_read_cr4();
	vmsa->cr3 = page_to_phys(mshv_vtl_dbg_snp_probe_pml4); /* Not exatcly precise */
	vmsa->cr0 = native_read_cr0();

	vmsa->xcr0 = 1;
	vmsa->g_pat = HV_AP_INIT_GPAT_DEFAULT;
	vmsa->rip = page_to_phys(mshv_vtl_dbg_snp_probe_code_page);

	vmsa->vmpl = 2;
	vmsa->sev_features = sev_status >> 2;

	vmsa->pcpu_id = smp_processor_id();

	/* Something benign so the VP can run */
	vmsa->guest_exit_code = SVM_EXIT_INTR;
	/* Don't allow it to run just yet */
	vmsa->vintr_ctrl |= V_GUEST_BUSY_MASK;
}

static void mshv_vtl_dbgstate_init_probe_vmsa(void* arg)
{
	int ret;
	struct page** vmsa_page_ptr;
	union hv_input_vtl vtl = {};
	struct hv_register_assoc reg_assoc = {};
	struct sev_es_save_area *vmsa;
	union sev_event_inject event_inj;

	pr_info("%s: initializing probe VMSA on CPU %d\n", __func__, smp_processor_id());

	vmsa_page_ptr = this_cpu_ptr(mshv_vtl_dbg_snp_probe_vmsa);
	if (*vmsa_page_ptr) {
		pr_info("%s: already initialized probe VMSA on CPU %d\n", __func__, smp_processor_id());
		return;
	}

	*vmsa_page_ptr = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!*vmsa_page_ptr) {
		pr_err("%s: could not allocate probe VMSA on CPU %d\n", __func__, smp_processor_id());
		return;
	}
	vmsa = (struct sev_es_save_area *)page_address(*vmsa_page_ptr);
	mshv_vtl_dbgstate_setup_vmsa(vmsa);

	pr_info("%s: RMP adjust the current VMSA on CPU %d\n", __func__, smp_processor_id());

	/* Make the current VMSA can't run to an NMI and is not runnable */

	event_inj.as_u64 = 0;
	event_inj.e.vector = 2;
	event_inj.e.interruption_type = 2;
	event_inj.e.valid = 1;
	mshv_vtl_this_vmsa()->event_inj = event_inj.as_u64;
	mshv_vtl_this_vmsa()->vintr_ctrl |= V_GUEST_BUSY_MASK;

	/*
	 * Unregister the current VMSA page.
	 * Should the hardware save the current state to it?
	 */
	ret = rmpadjust((unsigned long)mshv_vtl_this_vmsa(),
				RMP_PG_SIZE_4K, 1);
	if (ret) {
		pr_err("failed unregister the VMSA page: %d\n", ret);
		return;
	}

	pr_info("%s: registering the new VMSA with the hypervisor, CPU %d\n", __func__, smp_processor_id());

	/* Register the VMSA with the hypeervisor */

	reg_assoc.name = HV_X64_REGISTER_SEV_CONTROL;
	reg_assoc.value.reg64 = page_to_phys(*vmsa_page_ptr) | 1;
	vtl.use_target_vtl = 1;
	vtl.target_vtl = 0;
	ret = hv_call_set_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
					1, vtl, &reg_assoc);
	if (ret) {
		pr_err("failed to set VMSA page in hypervisor: %d\n", ret);
		return;
	}

	pr_info("%s: RMP adjust the new VMSA on CPU %d\n", __func__, smp_processor_id());

	/*
	 * Use VMPL1 as the target VMPL when setting a page bit, as
	 * required by AMD: have to use a numerically higher VMPL
	 */
	ret = rmpadjust((unsigned long)vmsa,
				RMP_PG_SIZE_4K, 1 | RMPADJUST_VMSA_PAGE_BIT);
	if (ret) {
		pr_err("failed to adjust RMP permissions: %d\n", ret);
		return;
	}

	/*
	 * Run the new VMSA, that should exit right away as the code page is filled with int3.
	 */
	pr_info("%s: Run the new VMSA on CPU %d, rip %#llx\n", __func__, smp_processor_id(), vmsa->rip);
	vmsa->vintr_ctrl &= !V_GUEST_BUSY_MASK;
	snp_mshv_vtl_return(0);
	pr_info("%s: SEV exit from the new VMSA on CPU %d, rip %#llx, SEV exit code %#llx, next rip %#llx, vintr_ctrl %#llx\n",
		__func__, smp_processor_id(), vmsa->rip, vmsa->guest_exit_code, vmsa->guest_nrip, vmsa->vintr_ctrl);

	pr_info("%s: initialized probe VMSA on CPU %d\n", __func__, smp_processor_id());
}

static int mshv_vtl_dbgstate_open(struct inode *node, struct file *f)
{
	int ret, i;
	struct desc_ptr gdtr;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

#ifndef CONFIG_X86_64
	return -EINVAL;
#endif

	if (hv_isolation_type_tdx())
		return -EINVAL;

	if (!hv_isolation_type_snp())
		return 0;

	if (!hv_ghcb_pg)
		hv_ghcb_pg = alloc_percpu(union hv_ghcb *);
	if (!hv_ghcb_pg)
		return -ENOMEM;
	on_each_cpu(mshv_vtl_dbgstate_init_ghcb, NULL, 1);

	mshv_vtl_dbg_snp_probe_code_page = alloc_page(GFP_KERNEL);
	if (!mshv_vtl_dbg_snp_probe_code_page)
		return -ENOMEM;
	mshv_vtl_dbg_snp_probe_pml4 = alloc_page(GFP_KERNEL);
	if (!mshv_vtl_dbg_snp_probe_pml4)
		return -ENOMEM;
	mshv_vtl_dbg_snp_probe_pdp = alloc_page(GFP_KERNEL);
	if (!mshv_vtl_dbg_snp_probe_pdp)
		return -ENOMEM;
	mshv_vtl_dbg_snp_probe_gdtr = alloc_page(GFP_KERNEL);
	if (!mshv_vtl_dbg_snp_probe_gdtr)
		return -ENOMEM;

	ret = set_memory_decrypted((unsigned long)page_address(mshv_vtl_dbg_snp_probe_code_page), 1);
	if (ret)
		return ret;
	ret = set_memory_decrypted((unsigned long)page_address(mshv_vtl_dbg_snp_probe_pml4), 1);
	if (ret)
		return ret;
	ret = set_memory_decrypted((unsigned long)page_address(mshv_vtl_dbg_snp_probe_pdp), 1);
	if (ret)
		return ret;
	ret = set_memory_decrypted((unsigned long)page_address(mshv_vtl_dbg_snp_probe_gdtr), 1);
	if (ret)
		return ret;

	/* Fill out the code probe page with int3 */
	memset(page_address(mshv_vtl_dbg_snp_probe_code_page), 0xcc, PAGE_SIZE);

	/*
	 * Build the page table with 1 GiB pages mapping the first 512 GiB identically.
	 * Not setting the encrypted bit so the probe will be able to access only unencrypted
	 * memory.
	 */
	memset(page_address(mshv_vtl_dbg_snp_probe_pml4), 0, PAGE_SIZE);
	memset(page_address(mshv_vtl_dbg_snp_probe_pdp), 0, PAGE_SIZE);

	/* Using just one PML 4 entry, read-only & execute permissions */
	*((u64*)page_address(mshv_vtl_dbg_snp_probe_pml4)) =
		(page_to_pfn(mshv_vtl_dbg_snp_probe_pdp) << PAGE_SHIFT) | _PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_DIRTY;

	/* Fill out the PDP entries with 1 GiB pages, read-only & execute permissions */
	for (i = 0; i < 512; ++i)
		*((u64*)page_address(mshv_vtl_dbg_snp_probe_pdp) + i) =
			(i << 30) | _PAGE_PSE | _PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_DIRTY;

	/* Copy out the current GDTR into the allocated space */
	native_store_gdt(&gdtr);
	memset(page_address(mshv_vtl_dbg_snp_probe_gdtr), 0, PAGE_SIZE);
	memcpy(page_address(mshv_vtl_dbg_snp_probe_gdtr), (void*)gdtr.address, gdtr.size);
	mshv_vtl_dbg_snp_probe_gdtr_size = gdtr.size;

	// /* Allow VMPL 2 access the pages if the pages are encrypted */
	// ret = rmpadjust((unsigned long)page_address(mshv_vtl_dbg_snp_probe_code_page), RMP_PG_SIZE_4K, 0xf02);
	// if (ret)
	// 	return -EFAULT;
	// ret = rmpadjust((unsigned long)page_address(mshv_vtl_dbg_snp_probe_pml4), RMP_PG_SIZE_4K, 0xf02);
	// if (ret)
	// 	return -EFAULT;
	// ret = rmpadjust((unsigned long)page_address(mshv_vtl_dbg_snp_probe_pdp), RMP_PG_SIZE_4K, 0xf02);
	// if (ret)
	// 	return -EFAULT;

	if (!mshv_vtl_dbg_snp_probe_vmsa)
		mshv_vtl_dbg_snp_probe_vmsa = alloc_percpu(struct page *);
	if (!mshv_vtl_dbg_snp_probe_vmsa)
		return -ENOMEM;
	on_each_cpu(mshv_vtl_dbgstate_init_probe_vmsa, NULL, 1);

	return 0;
}

static int mshv_vtl_dbgstate_release(struct inode *node, struct file *f)
{
	// TODO: release the resources, restore the VMSA
	return 0;
}

#define NON_ISOL_REG_COUNT 	56
#define SNP_REG_COUNT		24

static int mshv_vtl_dbgstate_this_vp_state_snp(u64 reg_count, struct hv_register_assoc *reg_list)
{
	struct sev_es_save_area *vmsa = mshv_vtl_this_vmsa();

	if (reg_count != SNP_REG_COUNT)
		return -EINVAL;

	reg_list[0].name = HV_X64_REGISTER_RAX;
	reg_list[0].value.reg64 = vmsa->rax;
	reg_list[1].name = HV_X64_REGISTER_RCX;
	reg_list[1].value.reg64 = vmsa->rcx;
	reg_list[2].name = HV_X64_REGISTER_RDX;
	reg_list[2].value.reg64 = vmsa->rdx;
	reg_list[3].name = HV_X64_REGISTER_RBX;
	reg_list[3].value.reg64 = vmsa->rbx;
	reg_list[4].name = HV_X64_REGISTER_RBP;
	reg_list[4].value.reg64 = vmsa->rbp;
	reg_list[5].name = HV_X64_REGISTER_RSI;
	reg_list[5].value.reg64 = vmsa->rsi;
	reg_list[6].name = HV_X64_REGISTER_RDI;
	reg_list[6].value.reg64 = vmsa->rdi;
	reg_list[7].name = HV_X64_REGISTER_R8;
	reg_list[7].value.reg64 = vmsa->r8;
	reg_list[8].name = HV_X64_REGISTER_R9;
	reg_list[8].value.reg64 = vmsa->r9;
	reg_list[9].name = HV_X64_REGISTER_R10;
	reg_list[9].value.reg64 = vmsa->r10;
	reg_list[10].name = HV_X64_REGISTER_R11;
	reg_list[10].value.reg64 = vmsa->r11;
	reg_list[11].name = HV_X64_REGISTER_R12;
	reg_list[11].value.reg64 = vmsa->r12;
	reg_list[12].name = HV_X64_REGISTER_R13;
	reg_list[12].value.reg64 = vmsa->r13;
	reg_list[13].name = HV_X64_REGISTER_R14;
	reg_list[13].value.reg64 = vmsa->r14;
	reg_list[14].name = HV_X64_REGISTER_R15;
	reg_list[14].value.reg64 = vmsa->r15;
	reg_list[15].name = HV_X64_REGISTER_CR2;
	reg_list[15].value.reg64 = vmsa->cr2;

	reg_list[16].name = HV_X64_REGISTER_RSP;
	reg_list[16].value.reg64 = vmsa->rsp;
	reg_list[17].name = HV_X64_REGISTER_RFLAGS;
	reg_list[17].value.reg64 = vmsa->rflags;
	reg_list[18].name = HV_X64_REGISTER_RIP;
	reg_list[18].value.reg64 = vmsa->rip;
	reg_list[19].name = HV_X64_REGISTER_CR0;
	reg_list[19].value.reg64 = vmsa->cr0;
	reg_list[20].name = HV_X64_REGISTER_CR3;
	reg_list[20].value.reg64 = vmsa->cr3;
	reg_list[21].name = HV_X64_REGISTER_CR4;
	reg_list[21].value.reg64 = vmsa->cr4;
	reg_list[22].name = HV_X64_REGISTER_CR8;
	reg_list[22].value.reg64 = vmsa->vintr_ctrl & 0xff;
	reg_list[23].name = HV_X64_REGISTER_EFER;
	reg_list[23].value.reg64 = vmsa->efer;

	return 0;
}

static int mshv_vtl_dbgstate_this_vp_state_plain(u64 reg_count, struct hv_register_assoc *reg_list)
{
	int ret, i;
	union hv_input_vtl input_vtl = {};
	struct hv_vtl_cpu_context *shared_ctx = &(mshv_vtl_this_run()->cpu_context);

	if (reg_count != NON_ISOL_REG_COUNT)
		return -EINVAL;

	/* Shared registers. */
	reg_list[0].name = HV_X64_REGISTER_RAX;
	reg_list[0].value.reg64 = shared_ctx->rax;
	reg_list[1].name = HV_X64_REGISTER_RCX;
	reg_list[1].value.reg64 = shared_ctx->rcx;
	reg_list[2].name = HV_X64_REGISTER_RDX;
	reg_list[2].value.reg64 = shared_ctx->rdx;
	reg_list[3].name = HV_X64_REGISTER_RBX;
	reg_list[3].value.reg64 = shared_ctx->rbx;
	reg_list[4].name = HV_X64_REGISTER_RBP;
	reg_list[4].value.reg64 = shared_ctx->rbp;
	reg_list[5].name = HV_X64_REGISTER_RSI;
	reg_list[5].value.reg64 = shared_ctx->rsi;
	reg_list[6].name = HV_X64_REGISTER_RDI;
	reg_list[6].value.reg64 = shared_ctx->rdi;
	reg_list[7].name = HV_X64_REGISTER_R8;
	reg_list[7].value.reg64 = shared_ctx->r8;
	reg_list[8].name = HV_X64_REGISTER_R9;
	reg_list[8].value.reg64 = shared_ctx->r9;
	reg_list[9].name = HV_X64_REGISTER_R10;
	reg_list[9].value.reg64 = shared_ctx->r10;
	reg_list[10].name = HV_X64_REGISTER_R11;
	reg_list[10].value.reg64 = shared_ctx->r11;
	reg_list[11].name = HV_X64_REGISTER_R12;
	reg_list[11].value.reg64 = shared_ctx->r12;
	reg_list[12].name = HV_X64_REGISTER_R13;
	reg_list[12].value.reg64 = shared_ctx->r13;
	reg_list[13].name = HV_X64_REGISTER_R14;
	reg_list[13].value.reg64 = shared_ctx->r14;
	reg_list[14].name = HV_X64_REGISTER_R15;
	reg_list[14].value.reg64 = shared_ctx->r15;
	reg_list[15].name = HV_X64_REGISTER_CR2;
	reg_list[15].value.reg64 = shared_ctx->cr2;

	/* Private registers. */
	reg_list[16].name = HV_X64_REGISTER_RSP;
	reg_list[17].name = HV_X64_REGISTER_RFLAGS;
	reg_list[18].name = HV_X64_REGISTER_RIP;
	reg_list[19].name = HV_X64_REGISTER_CR0;
	reg_list[20].name = HV_X64_REGISTER_CR3;
	reg_list[21].name = HV_X64_REGISTER_CR4;
	reg_list[22].name = HV_X64_REGISTER_CR8;
	reg_list[23].name = HV_X64_REGISTER_XFEM;
	reg_list[24].name = HV_X64_REGISTER_INTERMEDIATE_CR0;
	reg_list[25].name = HV_X64_REGISTER_INTERMEDIATE_CR4;
	reg_list[26].name = HV_X64_REGISTER_INTERMEDIATE_CR8;
	reg_list[27].name = HV_X64_REGISTER_DR0;
	reg_list[28].name = HV_X64_REGISTER_DR1;
	reg_list[29].name = HV_X64_REGISTER_DR2;
	reg_list[30].name = HV_X64_REGISTER_DR3;
	reg_list[31].name = HV_X64_REGISTER_DR6;
	reg_list[32].name = HV_X64_REGISTER_DR7;
	reg_list[33].name = HV_X64_REGISTER_ES;
	reg_list[34].name = HV_X64_REGISTER_CS;
	reg_list[35].name = HV_X64_REGISTER_SS;
	reg_list[36].name = HV_X64_REGISTER_DS;
	reg_list[37].name = HV_X64_REGISTER_FS;
	reg_list[38].name = HV_X64_REGISTER_GS;
	reg_list[39].name = HV_X64_REGISTER_LDTR;
	reg_list[40].name = HV_X64_REGISTER_TR;
	reg_list[41].name = HV_X64_REGISTER_IDTR;
	reg_list[42].name = HV_X64_REGISTER_GDTR;
	reg_list[43].name = HV_X64_REGISTER_TSC;
	reg_list[44].name = HV_X64_REGISTER_EFER;
	reg_list[45].name = HV_X64_REGISTER_KERNEL_GS_BASE;
	reg_list[46].name = HV_X64_REGISTER_APIC_BASE;
	reg_list[47].name = HV_X64_REGISTER_PAT;
	reg_list[48].name = HV_X64_REGISTER_SYSENTER_CS;
	reg_list[49].name = HV_X64_REGISTER_SYSENTER_EIP;
	reg_list[50].name = HV_X64_REGISTER_SYSENTER_ESP;
	reg_list[51].name = HV_X64_REGISTER_STAR;
	reg_list[52].name = HV_X64_REGISTER_LSTAR;
	reg_list[53].name = HV_X64_REGISTER_CSTAR;
	reg_list[54].name = HV_X64_REGISTER_SFMASK;
	reg_list[55].name = HV_REGISTER_GUEST_OS_ID;

	input_vtl.use_target_vtl = 1;
	for (i = 16; i < NON_ISOL_REG_COUNT; ++i) {
		/* TODO: Getting the registers one at a time to ignore errors */
		ret = hv_call_get_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
						1, input_vtl, reg_list + i);
		if (ret)
			pr_err("%s: CPU %d, hypercall failed for register %#x: %d\n", __func__, smp_processor_id(), reg_list[i].name, ret);
	}

	return 0;
}

struct mshv_vtl_get_vtl0_state_arg {
	u64 reg_count;
	struct mshv_vtl_dbg_vp_vtl0 state;
	struct hv_register_assoc *reg_list; /* `reg_count` registers for each `vp_count` VPs */
} __packed;

static void mshv_vtl_dbgstate_this_vp_state(void *arg)
{
	int ret = 0;
	struct mshv_vtl_get_vtl0_state_arg *info = arg;
	struct hv_register_assoc *reg_list = NULL;

	pr_info("%s: getting state from CPU %d, ret %d\n", __func__, smp_processor_id(), ret);

	atomic_inc((atomic_t*)&(info->state.vp_count));
	if (!info->reg_list)
		return;

	if (info->state.reg_count != info->reg_count) {
		ret = -EINVAL;
		goto exit;
	}

	reg_list = info->reg_list + smp_processor_id()*info->reg_count;

	if (hv_isolation_type_tdx())
		ret = -EINVAL;
	else if (hv_isolation_type_snp())
		ret = mshv_vtl_dbgstate_this_vp_state_snp(info->reg_count, reg_list);
	else
		ret = mshv_vtl_dbgstate_this_vp_state_plain(info->reg_count, reg_list);
	if (ret)
		goto exit;

	pr_info("%s: got state from CPU %d\n", __func__, smp_processor_id());
	atomic_inc((atomic_t*)&(info->state.vp_success));

exit:
	if (ret)
		pr_err("%s: error %d when getting state from CPU %d\n", __func__, ret, smp_processor_id());
}

static long mshv_vtl_dbgstate_ioctl_vp_vtl0_state(struct mshv_vtl_dbg_vp_vtl0 __user *user_vtl0_state)
{
	int ret;
	bool success;
	u64 vp_count;
	struct mshv_vtl_get_vtl0_state_arg vtl0;
	u64 vp_reg_list_size_bytes;

	ret = copy_from_user(&vtl0.state, user_vtl0_state,
		sizeof(struct mshv_vtl_dbg_vp_vtl0));
	if (ret)
		return -EFAULT;

	if (hv_isolation_type_snp())
		vtl0.reg_count = SNP_REG_COUNT;
	else if (hv_isolation_type_tdx())
		return -EINVAL;
	else
		vtl0.reg_count = NON_ISOL_REG_COUNT;
	vp_reg_list_size_bytes = sizeof(struct hv_register_assoc) * vtl0.reg_count;

	vp_count = vtl0.state.vp_count;
	if (vp_count) {
		if (vtl0.state.reg_list_size_bytes != vtl0.state.vp_count * vp_reg_list_size_bytes)
			return -EINVAL;
		vtl0.reg_list = kzalloc(vtl0.state.reg_list_size_bytes, GFP_KERNEL);
		if (ret)
			return -ENOMEM;
	} else {
		vtl0.reg_list = NULL;
	}

	vtl0.state.vp_count = 0;
	vtl0.state.vp_success = 0;
	vtl0.state.reg_count = vtl0.reg_count;

	on_each_cpu(mshv_vtl_dbgstate_this_vp_state, &vtl0, 1);
	vtl0.state.reg_list_size_bytes = vtl0.state.vp_count * vp_reg_list_size_bytes;

	pr_info("%s: VTL0 CPU state, VP count %lld, VP success %lld, reg count %lld\n",
		__func__, vtl0.state.vp_count, vtl0.state.vp_success, vtl0.state.reg_count);

	ret = copy_to_user(user_vtl0_state, &vtl0.state,
		sizeof(struct mshv_vtl_dbg_vp_vtl0));
	if (ret)
		return -EFAULT;

	if (vp_count) {
		ret = copy_to_user(vtl0.state.user_reg_list, vtl0.reg_list,
			vtl0.state.reg_list_size_bytes);
		kfree(vtl0.reg_list);
		vtl0.reg_list = NULL;
		if (ret)
			return -EFAULT;
	}

	success = (vtl0.state.vp_success != 0 && vtl0.state.vp_count == vtl0.state.vp_success) || (!vtl0.state.user_reg_list) || (!vtl0.reg_list);
	return success ? 0 : -EINVAL;
}

static ssize_t __mshv_vtl_dbgstate_ioctl_read_page(void *vaddr, void *param)
{
	memcpy(param, vaddr, PAGE_SIZE);
	return 0;
}

struct rmp_query_data {
	u64 flags;
	u64 page_size;
};

static ssize_t __mshv_vtl_dbgstate_ioctl_rmp_query(void *vaddr, void *param)
{
	struct rmp_query_data *data = param;
	return rmpquery((u64)vaddr, &(data->page_size), &(data->flags));
}

static long mshv_vtl_dbgstate_ioctl_read_page(struct mshv_vtl_dbg_read_page __user *user_read_page)
{
	long ret = 0;
	u64 failed_pfn;
	bool encrypt = true;
	void *page = NULL;
	struct mshv_vtl_dbg_read_page read_page = {};

#ifndef CONFIG_X86_64
	ret = -EINVAL;
	goto exit;
#endif

	if (hv_isolation_type_tdx()) {
		ret = -EINVAL;
		goto exit;
	}

	ret = copy_from_user(&read_page, user_read_page,
		sizeof(struct mshv_vtl_dbg_read_page));
	if (ret) {
		ret = -EFAULT;
		goto exit;
	}

	page = (void*)__get_free_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto exit;
	}

	pr_info("%s: reading PFN %#llx\n", __func__, read_page.pfn);

	if (hv_isolation_type_snp()) {
		bool use_large_page = false;
		struct rmp_query_data query = { .flags = 2 /* VMPL 2 */, .page_size = RMP_PG_SIZE_4K };

		ret = mshv_use_local_page(read_page.pfn, use_large_page, encrypt, /*page_count = */ 1,
			&failed_pfn, __mshv_vtl_dbgstate_ioctl_rmp_query, &query);
		// pr_info("%s: reading PFN %#llx ret %ld, flags %#llx, page_size %#llx\n", __func__, read_page.pfn, ret, query.flags, query.page_size);

		if (!ret && ((query.flags >> 8) == 0 || (query.flags & 0xff) != 2)) {
			/* don't read the memory VMPL2/VTL0 can't access */
			ret = -EFAULT;
			goto exit;
		}

		if (ret) {
			encrypt = false;
			ret = mshv_use_local_page(read_page.pfn, use_large_page, encrypt, /*page_count = */ 1,
				&failed_pfn, __mshv_vtl_dbgstate_ioctl_rmp_query, &query);
			// pr_info("%s: reading PFN %#llx ret %ld, flags %#llx, page_size %#llx\n", __func__, read_page.pfn, ret, query.flags, query.page_size);

			if (ret) {
				ret = -EFAULT;
				goto exit;
			}
		}
	}

	ret = mshv_use_local_page(read_page.pfn, /* use_large_page = */ false, encrypt, /* page_count = */ 1,
		&failed_pfn, __mshv_vtl_dbgstate_ioctl_read_page, page);
	if (ret) {
		ret = -EFAULT;
		goto exit;
	}

	// pr_info("%s: copying PFN %#llx\n", __func__, read_page.pfn);

	ret = copy_to_user(read_page.dst, page, PAGE_SIZE);
	if (ret) {
		ret = -EFAULT;
		goto exit;
	}

exit:
	if (ret)
		pr_err("%s: error %ld\n", __func__, ret);

	if (page)
		free_page((unsigned long)page);
	return ret;
}

static long mshv_vtl_dbgstate_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case MSHV_DBG_VP_VTL0_STATE:
		return mshv_vtl_dbgstate_ioctl_vp_vtl0_state((struct mshv_vtl_dbg_vp_vtl0 __user *)arg);
	case MSHV_DBG_READ_PAGE:
		return mshv_vtl_dbgstate_ioctl_read_page((struct mshv_vtl_dbg_read_page __user *)arg);
	default:
		break;
	}

	return -ENOIOCTLCMD;
}

static const struct file_operations mshv_vtl_dbgstate_file_ops = {
	.owner = THIS_MODULE,
	.open = mshv_vtl_dbgstate_open,
	.release = mshv_vtl_dbgstate_release,
	.unlocked_ioctl = mshv_vtl_dbgstate_ioctl,
};

static struct miscdevice mshv_vtl_dbgstate = {
	.name = "mshv_dbgstate",
	.nodename = "mshv_dbgstate",
	.fops = &mshv_vtl_dbgstate_file_ops,
	.mode = 0600,
	.minor = MISC_DYNAMIC_MINOR,
};

static int __init mshv_vtl_dbgstate_init(void)
{
	return misc_register(&mshv_vtl_dbgstate);
}

static void __exit mshv_vtl_dbgstate_exit(void)
{
	misc_deregister(&mshv_vtl_dbgstate);
}

module_init(mshv_vtl_dbgstate_init);
module_exit(mshv_vtl_dbgstate_exit);
