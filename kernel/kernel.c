/*-----------------------------------------------------------------------------
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2008-2012 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 * The full GNU General Public License is included in this distribution
 * in the file called LICENSE.GPL.
 *
 * Contact Information:
 *      Intel Corporation
 *      2200 Mission College Blvd.
 *      Santa Clara, CA  97052
 *
 * BSD LICENSE
 *
 * Copyright(c) 2008-2012 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   - Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *---------------------------------------------------------------------------*/

#include <linux/autoconf.h>
#include <asm/cache.h>

/* syscalls.h has the function prototypes for sys_open,
   sys_read, sys_write, sys_close and others. */
#include <linux/syscalls.h>

#include <stdbool.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/delay.h> 
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/time.h>
#include <linux/spinlock_types.h>
#include <linux/spinlock.h>
#include <asm/page.h>
#include <asm/uaccess.h>
#include <stdarg.h>
#include <linux/pci.h>
#include <linux/rwsem.h>
#include <linux/completion.h>

#include "clock_control.h"
#include "sec_hal.h"
#include "x86_cache.h"
#include "sec_kernel.h"
#include "sec_tracker.h"

#include "sec_kernel_dma.h"
#include "sec_dma_tracker.h"

#include "sec_fw.h"
#include "sec_pci.h"
#include "sec_pm.h"
#include "sec_tdp.h"
#include "sec_tdp_peri_fw.h"
#include "sec_fw_context_manager.h"
#include "sec_kernel_multipart.h"

//SEC registers
//RX and TX are from the SEC HW point of view
#define SEC_HCU_RX_DATA 0xffC86404

#define SEC_AES_RX_DATA 0xFFC85400

#define SEC_AES_RX_FIFO 0xFFC85600
#define SEC_AES_TX_FIFO 0xFFC85700

#define SEC_CSS_RX_FIFO 0xFFC85E00
#define SEC_CSS_TX_FIFO 0xFFC85F00

#define SEC_C2_RX_FIFO  0xFFC85A00
#define SEC_C2_TX_FIFO  0xFFC85B00

#define SEC_DES_RX_FIFO 0xFFC86200
#define SEC_DES_TX_FIFO 0xFFC86300

#define  SEC_IPC_54_MODULE_ID       0x00002000ul
#define  SEC_IPC_54_MODULE_ID_MASK  0x7FFFFFFFul

#define SEC_IPC_CIPLUS_MODULE_ID 0x00005010ul

unsigned int shmem_in_use=0;

// Information about a sec operation in progress in the firmware.
typedef struct
{
    uint32_t          job_id;
    uint16_t          opl_size; //Size of output payload
    uint16_t          osh_size; //Size of output shared memory
    uint16_t          osh_size_copied; //Size of output shared memory already copied 
    opl_t            *opl;
    ipc_shmem_t      *osh_pl;
    sec_ipc_return_t  ipc_rc;
    os_event_t        event_done;
} sec_fw_op_t;

// This spinlock is required for access to the SEC Functional Unit Block (FUB)
// in a hyperthreaded multi-core system.
static spinlock_t  sec_hw_unit_lock;
//semaphore to exclusively update global data related to bulk mode
struct semaphore bulk_ipc_lock;

/* This data structure is used to track the usage of various
 * context_ids.
 *
 * The spinlock guards access to the array.
 *
 * The semaphore is initialized so that it can be down()ed
 * SEC_NUM_CONTEXTS times and then is held by the process for the life
 * of the context_id. When there is contention for context_ids, the
 * waiting processes will block on trying to down() the semaphore. */
struct context_id_tracker {
    bool in_use[SEC_NUM_CONTEXTS];
    spinlock_t lock;
    struct semaphore sema;
};

spinlock_t fcm_kernel_context_lock;
fcm_kernel_context klist;
DEFINE_MUTEX(odp_rw_ipc_mutex);
static struct context_id_tracker context_trackers[SEC_NUM_CONTEXT_TYPES];

// This semaphore is required to keep sec_eau_modular_exp atomic
struct semaphore sec_eau_sema;
// Fast path mode will be used when TDP is enabled
int g_fast_path=0;

// Kernel scoreboard manager to track resource allocation, operations in progess
typedef struct
{
    struct semaphore res_semas [SEC_RESOURCE_COUNT];
    sec_fw_op_t      ops [SEC_MAX_OPERATION_COUNT];
    spinlock_t       board_lock;
    unsigned long    flags;
} sec_kernel_scoreboard_t;

static sec_kernel_scoreboard_t  score_board;
//global Data structure to keep information of Bulkmode. 
//Assumed that SEC_MAX_BULK_OPERATION_COUNT applications may run in bulk mode simultaneously.
typedef struct
{
    uint32_t     tgid;
    uint32_t     bulk_counter;
    uint8_t      bulk_mode;
    uint8_t      status;
    uint32_t     write_ptr;
    uint32_t     cmd_buff_ptr;
    uint32_t     cmd_data_ptr;
    uint32_t     counter;
    uint32_t     start_job_id;
    struct semaphore write_ptr_lock;
    struct completion host_compl_signal;
    struct completion fw_compl_signal;
} bulk_status;
bulk_status  g_bulk_stat[SEC_MAX_BULK_OPERATION_COUNT];
static int g_bulk_counter=0;

static int           dev_number;
static unsigned long g_sec_max_ipc_wait;
sec_hal_t     sec_hal_handle;

// Blocks sending new ipc commands until Sec is ready for input
static os_event_t ready_for_input;

static struct semaphore jobid_semaphore;// Make 'job_id' increments atomic

// Temporary semaphore to serialize all API calls
static struct semaphore sec_api_semaphore;

//----------------------------------------------------------------------------
//  Handling of functional differences between SEC revisions
//----------------------------------------------------------------------------

// PCI revision ID of SEC core in host SOC
static sec_pci_rev_t    SEC_revision;
//static unsigned long   *pSEC_scratch_pad;

//Host and SEC core {vendor, device, revision} PCI IDs
sec_chip_info_t gchip_info;


//----------------------------------------------------------------------------
//  The CE4200 SEC needs extra system memory.
//  When this SEC Linux kernel is running on a CE4200 it allocates
//  system memory and sends the physical pointer to the SEC HW.
//----------------------------------------------------------------------------
static sec_contig_mem_t gregsysmem_rom;

//----------------------------------------------------------------------------
//  FW Pager mechanism requires 2MB of memory.
//  This memory will be registered to 1200 module after its been loaded.
//----------------------------------------------------------------------------
static sec_contig_mem_t gregsysmem_pager;


//----------------------------------------------------------------------------
// Prototypes of all kernel functions that have different
// implementations for different revisions of the SEC core.
//----------------------------------------------------------------------------
typedef struct
{
    ; // Currently empty
} kernel_function_vector_t;

kernel_function_vector_t rev0 = { };

// Once a difference appears, there must be at least a rev0 vector and
// a revN vector, and function f() will be invoked as kfv->f(args);
kernel_function_vector_t *kfv = NULL;


//----------------------------------------------------------------------------
// __sec_get_tgid
//
// Gets a task's TGID as seen in kernel space using SEC_GET_TGID ioctl
//----------------------------------------------------------------------------
static sec_result_t __sec_get_tgid(uint32_t arg)
{
    unsigned int this_tgid;
    sec_result_t     rc;

    rc = SEC_SUCCESS;
    if (copy_from_user(&this_tgid, (unsigned int*)arg, sizeof(unsigned int)))
    {
        printk(KERN_INFO "\n __sec_get_tgid: failed copying unsigned int from user\n");
        rc = SEC_FAIL;
        goto exit;
    }

    this_tgid = (unsigned int)(current->tgid);

    if (copy_to_user((void*)arg, &this_tgid, sizeof(unsigned int)))
    {
        printk(KERN_INFO "\n __sec_get_tgid: failed copying tgid in unsigned int to user\n");
        rc = SEC_FAIL;
        goto exit;
    }

exit:
    return rc;
} //ENDPROC __sec_get_tgid


//----------------------------------------------------------------------------
// __sec_munmap
//
// Finds the memory in the tracker system and verifies ownership
// If this associated thread group ID owns the memory and the
// memory is still mapped this routine unmapps the memory.
// It does not free the memory.
//----------------------------------------------------------------------------
static sec_result_t __sec_munmap(sec_contig_mem_t *mem)
{
    //mm_struct is defined in include/linux/sched.h
    struct mm_struct *mm;
    struct vm_area_struct *pvma;
    sec_contig_mem_t *ptrmem;
    unsigned int this_tgid;
    unsigned int offset;
    unsigned int size;
    unsigned int pg_size;
    unsigned int pg_aligned_base;
    unsigned long vaddr;
    sec_result_t rc;
    int iret;

    iret = 0;
    rc = SEC_SUCCESS;
    mm = current->mm;
    pvma = mm->mmap;
    ptrmem = NULL;
    this_tgid = (unsigned int)(current->tgid);

    // Verify that SEC owns the passed in tgid and physical memory
    ptrmem = tracker_verify_mem(mem);
    if(ptrmem == NULL)
    {
        printk(KERN_INFO "__sec_munmap: current tgid %d cannot unmap memory at 0x%08x for tgid %d\n",
               this_tgid, mem->paddr, mem->tgid);
        rc = SEC_MMAP_INVALID_TGID;
        goto exit;
    }

    // Unlock this memory's lock flag
    down_write(&mm->mmap_sem);
    for(pvma = mm->mmap; pvma != NULL; pvma = pvma->vm_next)
    {
        if( ((unsigned long)ptrmem->user_vaddr >= pvma->vm_start)
         && ((unsigned long)ptrmem->user_vaddr <= pvma->vm_end))
        {
            if(pvma->vm_flags & VM_LOCKED)
            {
                // We locked this vma in SEC_MMAP so unlock it.
                pvma->vm_flags = pvma->vm_flags ^ VM_LOCKED;
            }
        }
    }
    up_write(&mm->mmap_sem);


    // Verify that this memory hasn't already been unmapped
    if(ptrmem->mmap_count > 0)
    {
        size = ptrmem->size;
        vaddr = (unsigned long)ptrmem->user_vaddr;
        pg_size = PAGE_SIZE;
        pg_aligned_base = (vaddr/pg_size)*pg_size;

        //This is because munmap works only on pages
        offset = vaddr - pg_aligned_base;
        size = size + offset;
        down_write(&mm->mmap_sem);
        iret = do_munmap(mm, (unsigned long)pg_aligned_base, size);
        up_write(&mm->mmap_sem);
        if( iret != 0)
        {
            rc = SEC_MMAP_PHYSMEM_STILL_MAPPED;
            goto exit;
        } //ENDIF do_munmap failed
        if(ptrmem->mmap_count > 0) ptrmem->mmap_count = ptrmem->mmap_count - 1;
        mem->mmap_count = ptrmem->mmap_count;
    } //ENDIF the memory was still mapped

exit:
    return rc;
} //ENDPROC __sec_munmap


//----------------------------------------------------------------------------
// __sec_munmap_call
//
// Call that implements SEC_MUNMAP_CALL ioctl call.
//
// Finds the memory in the tracker system and verifies ownership
// If this associated thread group ID owns the memory and the
// memory is still mapped this routine unmapps the memory.
// It does not free the memory.
//----------------------------------------------------------------------------
static sec_result_t __sec_munmap_call(uint32_t arg)
{
    sec_contig_mem_t mem;
    sec_result_t     rc;

    rc = SEC_SUCCESS;
    if (copy_from_user(&mem, (sec_contig_mem_t*)arg, sizeof(sec_contig_mem_t)))
    {
        printk(KERN_INFO "\n __sec_munmap_call: failed copying sec_contig_mem_t from user\n");
        rc = SEC_FAIL;
        goto exit;
    }

    VERIFY(mem.kernel_vaddr != NULL, exit, rc, SEC_FAIL);

    rc = __sec_munmap(&mem);
    if(rc != SEC_SUCCESS) goto exit;

#ifdef DEBUG_SEC_MUNMAP_CALL
    printk(KERN_INFO "\n __sec_munmap_call: After unmapping\n");
    printk(KERN_INFO "    mem.paddr       =0x%08x\n", mem.paddr);
    printk(KERN_INFO "    mem.kernel_vaddr=0x%p\n", mem.kernel_vaddr);
    printk(KERN_INFO "    mem.user_vaddr  =0x%p\n", mem.user_vaddr);
    printk(KERN_INFO "    mem.mmap_count  =%d\n", mem.mmap_count);
    printk(KERN_INFO "    mem.size  =%d bytes\n", mem.size);
    printk(KERN_INFO "    mem.tgid  =%d\n", mem.tgid);
    printk(KERN_INFO "    mem.smpool=%d\n", mem.smpool);
#endif

    // Must copy mem back to user because the count was modified in __sec_munmap
    if (copy_to_user((void*)arg, &mem, sizeof(sec_contig_mem_t)))
    {
        printk(KERN_INFO "\n __sec_munmap_call: failed copying sec_contig_mem_t to user\n");
        rc = SEC_FAIL;
        goto exit;
    }

exit:
    return rc;
}


//----------------------------------------------------------------------------
// __sec_alloc_pages
//
// Allocates contiguous, page aligned memory for things like FW module loads.
// Using __get_free_pages should guarantee page-aligned, contiguous memory
// areas, regardless of what Linux memory allocater may be selected.
//----------------------------------------------------------------------------
static sec_result_t __sec_alloc_pages(uint32_t arg)
{
    void             * buffer = NULL;
    sec_contig_mem_t   mem;
    sec_result_t       rc = SEC_SUCCESS;

    /* Verify that our argument looks reasonable */
    VERIFY(arg != 0, exit_now, rc, SEC_NULL_POINTER);

    /* Retrieve and verify the contents of our received contig_mem_t */
    if (copy_from_user(&mem, (sec_contig_mem_t*)arg, sizeof(sec_contig_mem_t)))
    {
        SEC_PRINT_ERROR("failed to copy sec_contig_mem_t from user\n");
        rc = SEC_FAIL;
        goto exit_now;
    }
    /* Verify the allocation request is valid */
    VERIFY(mem.size > 0, exit_now, rc, SEC_INVALID_INPUT);

    /* Allocate the memory, and check that we succeeded */
    buffer = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
            get_order(mem.size));
    VERIFY(buffer != NULL, exit, rc, SEC_OUT_OF_MEMORY);
    if(g_fast_path)
    {
        set_pages_uc(virt_to_page((unsigned long)buffer), (1 << (get_order(mem.size))));
    }
    memset(buffer, 0x00, get_order(mem.size) * PAGE_SIZE);

    /* Setup our received contig_mem_t structure */
    mem.paddr        = (unsigned int)OS_VIRT_TO_PHYS(buffer);
    mem.kernel_vaddr = buffer;
    mem.user_vaddr   = 0x0; // This will be setup in mmap
    mem.mmap_count   = 0;
    mem.tgid = (unsigned int)(current->tgid);
    mem.smpool = 0;
    mem.flags |= SEC_CONTIG_FLAG_PAGE_ALLOC; 

#ifdef DEBUG_SEC_ALLOC_PAGES
    printk(KERN_INFO "\n __sec_alloc_pages: \n");
    printk(KERN_INFO "    mem.paddr       =0x%08x\n", mem.paddr);
    printk(KERN_INFO "    mem.kernel_vaddr=0x%p\n", mem.kernel_vaddr);
    printk(KERN_INFO "    mem.user_vaddr  =0x%p\n", mem.user_vaddr);
    printk(KERN_INFO "    mem.mmap_count  = %d\n", mem.mmap_count);
    printk(KERN_INFO "    mem.size  =%d bytes\n", mem.size);
    printk(KERN_INFO "    mem.tgid  =%d\n", mem.tgid);
    printk(KERN_INFO "    mem.smpool=%d\n", mem.smpool);
    printk(KERN_INFO "    mem.flags=%d\n", mem.flags);
#endif

    VERIFY(copy_to_user((void*)arg, &mem, sizeof(sec_contig_mem_t)) == 0,
            exit, rc, SEC_FAIL);

    rc = tracker_add_mem(mem.tgid, &mem);
    VERIFY_QUICK(rc == SEC_SUCCESS, exit);

exit:
    if (rc != SEC_SUCCESS && buffer != NULL)
        free_pages((unsigned long)buffer, get_order(mem.size));

exit_now:
    return rc;
} // ENDPROC __sec_alloc_pages

//----------------------------------------------------------------------------
// __sec_do_free_pages
//
// Performs the actual page free. This section is needed by portions of the
// kernel driver which don't need the rest of __sec_free_pages
//----------------------------------------------------------------------------
sec_result_t __sec_do_free_pages (void * kernel_vaddr, unsigned int size_bytes)
{
    sec_result_t    rc = SEC_SUCCESS;
    int             int_rc = 0;

    VERIFY(kernel_vaddr != NULL, exit, rc, SEC_FAIL);

    if(g_fast_path)
    {
        int_rc = set_pages_wb(
                virt_to_page((unsigned long) kernel_vaddr),
                     (size_bytes >>PAGE_SHIFT));
        VERIFY(int_rc == 0, exit, rc, SEC_FAIL);
    }
    free_pages((unsigned long)kernel_vaddr, get_order(size_bytes));

exit:
    return rc;
}

//----------------------------------------------------------------------------
// __sec_free_pages
//
// Frees pages allocated by __sec_alloc_pages.
//----------------------------------------------------------------------------
static sec_result_t __sec_free_pages(uint32_t arg)
{
    sec_contig_mem_t mem;
    sec_contig_mem_t *ptrmem = NULL;
    unsigned int size = 0;
    unsigned int pg_aligned_base = 0;
    unsigned long vaddr = 0;
    sec_result_t     rc = SEC_SUCCESS;
    int memunmap_ret = 0;

    if (copy_from_user(&mem, (sec_contig_mem_t*)arg, sizeof(sec_contig_mem_t)))
    {
        SEC_PRINT_ERROR("failed copying sec_contig_mem_t from user\n");
        rc = SEC_FAIL;
        goto exit;
    }
    VERIFY(mem.kernel_vaddr != NULL, exit, rc, SEC_FAIL);

    // Verify that SEC owns the passed in tgid and physical memory
    ptrmem = tracker_verify_mem(&mem);
    VERIFY(ptrmem != NULL, exit, rc, SEC_FAIL);

#ifdef DEBUG_SEC_FREE_PAGES
    printk(KERN_INFO "\n__sec_free_pages:\n");
    printk(KERN_INFO "    ptrmem->paddr       =0x%08x\n", ptrmem->paddr);
    printk(KERN_INFO "    ptrmem->kernel_vaddr=0x%p\n", ptrmem->kernel_vaddr);
    printk(KERN_INFO "    ptrmem->user_vaddr  =0x%p\n", ptrmem->user_vaddr);
    printk(KERN_INFO "    ptrmem->mmap_count  =%d\n", ptrmem->mmap_count);
    printk(KERN_INFO "    ptrmem->size  =%d bytes\n", ptrmem->size);
    printk(KERN_INFO "    ptrmem->tgid  =%d\n", ptrmem->tgid);
    printk(KERN_INFO "    ptrmem->smpool=%d\n", ptrmem->smpool);
#endif

    /* If the memory has been mmap'ed, unmap it */
    if(ptrmem->mmap_count > 0)
    {
        size = ptrmem->size;
        vaddr = (unsigned long)(ptrmem->user_vaddr);
        pg_aligned_base = (vaddr / PAGE_SIZE) * PAGE_SIZE;

        //This is because munmap works only on pages
        size = size + (vaddr - pg_aligned_base);
        down_write(&current->mm->mmap_sem);
        memunmap_ret = do_munmap(current->mm, (unsigned long)pg_aligned_base,
                                size);
        up_write(&current->mm->mmap_sem);
        /* If memunmap succeeded decrement the counter */
        if( memunmap_ret == 0)
        {
            if(ptrmem->mmap_count > 0)
                ptrmem->mmap_count = ptrmem->mmap_count - 1;
        }
        else
        {
            switch (memunmap_ret)
            {
            case -EINVAL:
                SEC_PRINT_ERROR("Received an invalid parameter for do_munmap\n"
                                "\tptrmem->user_vaddr = 0x%08x\n"
                                "\tptrmem->size = %d bytes\n",
                                (unsigned int)ptrmem->user_vaddr, ptrmem->size);
                break;
            case -ENOMEM:
                SEC_PRINT_ERROR("do_munmap had a vm_area split problem\n");
                break;
            default:
                SEC_PRINT_ERROR("do_munmap error=%d\n", memunmap_ret);
                break;
            }
            rc = SEC_MMAP_PHYSMEM_STILL_MAPPED;
            goto exit;
        }
    }

    /* If nothing else has this memory mapped, clean it up */
    if(ptrmem->mmap_count == 0)
    {
        /* If PM is going to free the memory don't free it here */
        if ((mem.flags & SEC_CONTIG_FLAG_PM_FREED) == 0)
        {
            rc = __sec_do_free_pages(ptrmem->kernel_vaddr, ptrmem->size);
            VERIFY_QUICK(rc == SEC_SUCCESS, exit);
        }
        /* Remove the memory from the tracker */
        if (tracker_remove_mem(ptrmem->tgid, ptrmem) != SEC_SUCCESS)
        {
            // The address was bound to other tgid, search for
            // it within the existing clients and remove it.
            rc = tracker_remove_mem_from_client_list(ptrmem);
        }
    }
    else
    {
#ifdef DEBUG_SEC_FREE_PAGES_ERR
        printk(KERN_INFO "\n%s "
                "Physical Memory Still Mapped ptrmem->mmap_count=%d\n",
                __func__, (int)ptrmem->mmap_count);
#endif
       rc = SEC_MMAP_PHYSMEM_STILL_MAPPED;
    }

exit:
    return rc;
} // ENDPROC __sec_free_pages


//----------------------------------------------------------------------------
// __sec_alloc_mem
//
// Call that implements SEC_ALLOC_MEM_CALL ioctl call.
//
// Allocates memory of a passed size in kernel (gets kernel virtual address),
// converts kernel virt address to physical address, adds new memory block
// to client memory tracker and returns memory information.
//----------------------------------------------------------------------------
static sec_result_t __sec_alloc_mem(uint32_t arg)
{
    void             * buffer = NULL;
    sec_contig_mem_t   mem;
    sec_result_t       rc = SEC_SUCCESS;
    int                order;

    if (copy_from_user(&mem, (sec_contig_mem_t*)arg, sizeof(sec_contig_mem_t)))
    {
        printk(KERN_INFO "\n __sec_alloc_mem: failed copying sec_contig_mem_t from user\n");
        rc = SEC_FAIL;
        goto exit_now;
    }

    if(mem.size == 0)
    {
        printk(KERN_INFO "\n __sec_alloc_mem: size in sec_contig_mem_t from user is zero\n");
        rc = SEC_INVALID_INPUT;
        goto exit_now;
    }
    if(g_fast_path)
    {
        order = get_order(mem.size);
        mem.size = PAGE_SIZE << order;

        buffer= (void *)__get_free_pages(GFP_KERNEL, order);
        if(buffer == NULL)
        {
            printk(KERN_INFO "\n __sec_alloc_mem: OS_ALLOC failed allocating %d bytes of memory\n", mem.size);
            rc = SEC_FAIL;
            goto exit_now;
        }
        set_pages_uc(virt_to_page((unsigned long)buffer), (1 << order));
        mem.flags |= SEC_CONTIG_FLAG_PAGE_ALLOC;
    }
    else
    {
        buffer = OS_ALLOC(mem.size);
        if(buffer == NULL)
        {
            printk(KERN_INFO "\n __sec_alloc_mem: OS_ALLOC failed allocating %d bytes of memory\n", mem.size);
            rc = SEC_FAIL;
            goto exit_now;
        }
        mem.flags |= SEC_CONTIG_FLAG_OS_ALLOC;
    }
    mem.paddr        = (unsigned int)OS_VIRT_TO_PHYS(buffer);
    mem.kernel_vaddr = buffer;
    mem.user_vaddr   = 0x0;
    mem.mmap_count   = 0;
    mem.tgid = (unsigned int)(current->tgid);
    mem.smpool = 0;

#ifdef DEBUG_SEC_ALLOC_MEM
    printk(KERN_INFO "\n __sec_alloc_mem: \n");
    printk(KERN_INFO "    mem.paddr       =0x%08x\n", mem.paddr);
    printk(KERN_INFO "    mem.kernel_vaddr=0x%p\n", mem.kernel_vaddr);
    printk(KERN_INFO "    mem.user_vaddr  =0x%p\n", mem.user_vaddr);
    printk(KERN_INFO "    mem.mmap_count  = %d\n", mem.mmap_count);
    printk(KERN_INFO "    mem.size  =%d bytes\n", mem.size);
    printk(KERN_INFO "    mem.tgid  =%d\n", mem.tgid);
    printk(KERN_INFO "    mem.smpool=%d\n", mem.smpool);
#endif

    if (copy_to_user((void*)arg, &mem, sizeof(sec_contig_mem_t)))
    {
        printk(KERN_INFO "\n __sec_alloc_mem: failed copying sec_contig_mem_t to user\n");
        rc = SEC_FAIL;
        goto exit;
    }

    rc = tracker_add_mem(mem.tgid, &mem);
    if(rc != SEC_SUCCESS)
    {
        printk(KERN_INFO "\n __sec_alloc_mem: failed adding this sec_contig_mem_t to tracker\n");
    }

exit:
    if (rc != SEC_SUCCESS)
    {
        if (buffer != NULL)
        {
            OS_FREE(buffer);
        }
    }
exit_now:
    return rc;
} // ENDPROC __sec_alloc_mem

//----------------------------------------------------------------------------
// sec_get_tdp_handler
//
// Checks whether TDP is enabled and FW module 40000 is loaded
//----------------------------------------------------------------------------
static sec_result_t sec_get_tdp_handler(uint32_t arg)
{
    sec_result_t     rc = SEC_SUCCESS;
    int  status;
    status = sec_check_tdp_fw();
    if (copy_to_user((void*)arg, &status, sizeof(unsigned int)))
    {
        printk(KERN_INFO "\n __sec_get_tgid: failed copying tgid in unsigned int to user\n");
        rc = SEC_FAIL;
        goto exit;
    }
exit:
    return rc;
}// ENDPROC sec_get_tdp_handler


//----------------------------------------------------------------------------
// __sec_free_mem
//
// Call that implements SEC_FREE_MEM_CALL ioctl call.
//
// Free's kernel space virtual address for the block and removes address
// from sec client memory tracker.
//----------------------------------------------------------------------------
static sec_result_t __sec_free_mem(uint32_t arg)
{
    struct mm_struct *mm;
    sec_contig_mem_t mem;
    sec_contig_mem_t *ptrmem;
    unsigned int this_tgid;
    unsigned int offset;
    unsigned int size;
    unsigned int pg_size;
    unsigned int pg_aligned_base;
    unsigned long vaddr;
    sec_result_t     rc = SEC_SUCCESS;
    sec_result_t    trc = SEC_SUCCESS;
    int iret;

    iret = 0;
    mm = current->mm;
    this_tgid = (unsigned int)(current->tgid);

    if (copy_from_user(&mem, (sec_contig_mem_t*)arg, sizeof(sec_contig_mem_t)))
    {
        printk(KERN_INFO "\n __sec_free_mem: failed copying sec_contig_mem_t from user\n");
        rc = SEC_FAIL;
        goto exit;
    }

    VERIFY(mem.kernel_vaddr != NULL, exit, rc, SEC_FAIL);

    // Verify that SEC owns the passed in tgid and physical memory
    ptrmem = tracker_verify_mem(&mem);
    VERIFY(ptrmem != NULL, exit, rc, SEC_FAIL);

#ifdef DEBUG_SEC_FREE_MEM
    printk(KERN_INFO "\n__sec_free_mem:\n");
    printk(KERN_INFO "    ptrmem->paddr       =0x%08x\n", ptrmem->paddr);
    printk(KERN_INFO "    ptrmem->kernel_vaddr=0x%p\n", ptrmem->kernel_vaddr);
    printk(KERN_INFO "    ptrmem->user_vaddr  =0x%p\n", ptrmem->user_vaddr);
    printk(KERN_INFO "    ptrmem->mmap_count  =%d\n", ptrmem->mmap_count);
    printk(KERN_INFO "    ptrmem->size  =%d bytes\n", ptrmem->size);
    printk(KERN_INFO "    ptrmem->tgid  =%d\n", ptrmem->tgid);
    printk(KERN_INFO "       this_tgid  =%d\n", this_tgid);
    printk(KERN_INFO "    ptrmem->smpool=%d\n", ptrmem->smpool);
#endif

    if(ptrmem->mmap_count > 0)
    {
        size = ptrmem->size;
        vaddr = (unsigned long)(ptrmem->user_vaddr);
        pg_size = PAGE_SIZE;
        pg_aligned_base = (vaddr/pg_size)*pg_size;

        //This is because munmap works only on pages
        offset = vaddr - pg_aligned_base;
        size = size + offset;
        down_write(&mm->mmap_sem);
        iret = do_munmap(mm, (unsigned long)pg_aligned_base, size);
        up_write(&mm->mmap_sem);
        if( iret == 0)
        {
            if(ptrmem->mmap_count > 0) ptrmem->mmap_count = ptrmem->mmap_count - 1;
        }
        else
        {
            if(iret == -EINVAL)
            {
                printk(KERN_INFO "__sec_free_mem: received an invalid parameter for do_munmap\n");
                printk(KERN_INFO "    ptrmem->user_vaddr  =0x%p\n", ptrmem->user_vaddr);
                printk(KERN_INFO "    ptrmem->size  =%d bytes\n", ptrmem->size);
            }
            else if(iret == -ENOMEM)
            {
                printk(KERN_INFO "__sec_free_mem: do_munmap had a vm_area split problem\n");
            }
            else
            {
                printk(KERN_INFO "__sec_free_mem: do_munmap error=%d\n", iret);
            }
            rc = SEC_MMAP_PHYSMEM_STILL_MAPPED;
            goto exit;
        }
    }

    if(ptrmem->mmap_count == 0)
    {
        /* If PM is going to free the memory don't free it here */
        if ((mem.flags & SEC_CONTIG_FLAG_PM_FREED) == 0)
        {
            if(g_fast_path)
            {
                set_pages_wb(virt_to_page((unsigned long)ptrmem->kernel_vaddr), (ptrmem->size >>PAGE_SHIFT));
                free_pages((unsigned long)ptrmem->kernel_vaddr, get_order(ptrmem->size));
            }
            else
            {
                OS_FREE(ptrmem->kernel_vaddr);
            }
        }
        trc = tracker_remove_mem(ptrmem->tgid, ptrmem);
        // The address was bound to other tgid, search for
        // it within the existing clients and remove it.
        if (trc != SEC_SUCCESS)
        {
            rc = tracker_remove_mem_from_client_list(ptrmem);
        }
    }
    else
    {
#ifdef DEBUG_SEC_FREE_MEM_ERR
        printk(KERN_INFO "\n __sec_free_mem: Physical Memory Still Mapped ptrmem->mmap_count=%d\n",
               (int)ptrmem->mmap_count);
#endif
       rc = SEC_MMAP_PHYSMEM_STILL_MAPPED;
    }

exit:
    return rc;
} // ENDPROC __sec_free_mem


//-----------------------------------------------------------------------------
// sec_kernel_open
//-----------------------------------------------------------------------------
static int sec_kernel_open(struct inode *inode, struct file *fd)
{
    tracker_client_add((unsigned int)(current->tgid));
    return 0;
}


//-----------------------------------------------------------------------------
// sec_kernel_close
//
// This function will be called in 2 cases -- either if application performed
// close on a device, or if application died and system performed close
// on its own.
//
// Possible concern: if firmware is executing a command for which it needs
// physical memory, what happens when we deallocate that memory?
//
// This will not happen though, since once a command to firmware is sent,
// ioctl call ends up waiting for a result in non-interruptible manner.
//
// Therefore firmware will have to complete its operation before ioctl
// returns and 'device close' is executed.
//-----------------------------------------------------------------------------
static int sec_kernel_close(struct inode *inode, struct file *fd)
{
    dma_tracker_garbage_collect(current->tgid);
    fcm_internal_session_garbage_collect(current->tgid);
    tracker_garbage_collect(current->tgid);
    return 0;
}


//-----------------------------------------------------------------------------
// sec_kernel_mmap
//
// Memory map handler for sec.
//-----------------------------------------------------------------------------
static int sec_kernel_mmap(struct file *f, struct vm_area_struct *vma)
{
    sec_contig_mem_t * ptrmem;
    unsigned int tgid;
    unsigned int size;

    size = vma->vm_end - vma->vm_start;
    tgid = (unsigned int)current->tgid;

    ptrmem = tracker_verify_page(tgid, vma->vm_pgoff, size);
    if(ptrmem == NULL)
    {
        printk(KERN_INFO "\nsec_kernel_mmap: this thread group id %d does not own the memory to map\n", tgid);
        return -EINVAL;
    }
    vma->vm_flags |= VM_LOCKED;

    if ((f->f_flags & O_SYNC) ||(g_fast_path==1))
    {
        vma->vm_page_prot  = pgprot_noncached(vma->vm_page_prot);
    }

    if (remap_pfn_range(vma,
                        vma->vm_start,
                        vma->vm_pgoff,
                        vma->vm_end - vma->vm_start,
                        vma->vm_page_prot))
    {
        return -EAGAIN;
    }
    ptrmem->user_vaddr = (void*)vma->vm_start;
    ptrmem->mmap_count = ptrmem->mmap_count + 1;

#ifdef DEBUG_SEC_KERNEL_MMAP
    printk(KERN_INFO "\n sec_kernel_mmap:\n");
    printk(KERN_INFO "    ptrmem->paddr       =0x%08x\n", ptrmem->paddr);
    printk(KERN_INFO "    ptrmem->kernel_vaddr=0x%p\n", ptrmem->kernel_vaddr);
    printk(KERN_INFO "    ptrmem->user_vaddr  =0x%p\n", ptrmem->user_vaddr);
    printk(KERN_INFO "    ptrmem->size  =%d bytes\n", ptrmem->size);
    printk(KERN_INFO "    ptrmem->mmap_count  =%d\n", ptrmem->mmap_count);
    printk(KERN_INFO "    ptrmem->tgid  =%d\n", ptrmem->tgid);
    printk(KERN_INFO "    ptrmem->smpool=%d\n", ptrmem->smpool);
#endif

    return 0;
}

//-----------------------------------------------------------------------------
// File operations
//-----------------------------------------------------------------------------

// Forward reference
static
long sec_kernel_unlocked_ioctl(struct file *    fd,
                               unsigned int     command,
                               unsigned long    arg);
static
struct file_operations sec_fops =
{
    .owner           = THIS_MODULE,
    .unlocked_ioctl  = sec_kernel_unlocked_ioctl,
    .open            = sec_kernel_open,
    .release         = sec_kernel_close,
    .mmap            = sec_kernel_mmap
};


//-----------------------------------------------------------------------------
// Translate an IPC return type to a sec driver return type.
//-----------------------------------------------------------------------------
sec_result_t ipc2sec(sec_ipc_return_t ipc_ret)
{
    sec_result_t result;

    SEC_DEBUG( "IPC return code: 0x%08lx\n", (unsigned long)ipc_ret );

    // trap for module 0x5040 (link protection) errors
    // MS bit is 1 for FW errors
    // This is a work-around pending more extensive error handling
    // TODO replace with module id defines and a macro to be leveraged by
    // other modules
    if ((ipc_ret & 0xFFFF0000) == 0xD0400000)
    {
      result = ipc_ret;
      return result;
    }

    switch (ipc_ret)
    {
    case IPC_RET_SUCCESS:
    case IPC_RET_COMMAND_COMPLETE:
        result = SEC_SUCCESS;
        break;

    case IPC_RET_DEVICE_BUSY:
    case IPC_RET_KERNEL_MEMORY_FULL_ERROR:
        result = SEC_DEVICE_BUSY;
        break;

    case IPC_RET_BAD_HOST_REQUEST:
        result = SEC_INVALID_HOST_REQUEST;
        break;

    case IPC_FW_RET_DUPLICATE:
        result = SEC_EXT_FW_DUPLICATE_KEY_ID;
        break;

    case IPC_RET_FW_INVALID_LOAD_TYPE:
        result = SEC_FW_INVALID_LOAD_TYPE;
        break;

    case IPC_RET_FW_MODULE_NOT_FOUND:
        result = SEC_FW_MODULE_NOT_FOUND;
        break;

    case IPC_RET_FW_MODULE_ALREADY_LOADED:
        result = SEC_FW_MODULE_ALREADY_LOADED;
        break;

    case IPC_RET_FW_HKEY_OPERATION_ERROR:
        result = SEC_FW_HKEY_OPERATION_ERROR;
        break;

    case IPC_RET_FW_SYMBOL_TABLE_MISMATCH:
        result = SEC_FW_SYMBOL_TABLE_MISMATCH;
        break;

    case IPC_RET_FW_NO_MANIFEST_ENTRY:
        result = SEC_FW_NO_MANIFEST_ENTRY;
        break;

    case IPC_RET_FW_ELF_LOAD_FAILED:
        result = SEC_FW_FS_ELF_LOAD_FAILED;
        break;

    case IPC_RET_FW_FS_SEEK_OUT_OF_BOUNDS:
        result = SEC_FW_FS_SEEK_OUT_OF_BOUNDS;
        break;

    case IPC_RET_FW_FS_INVALID_SEEK_TYPE:
        result = SEC_FW_FS_INVALID_SEEK_TYPE;
        break;

    case IPC_RET_FW_FS_REOPEN_FILE_ERROR:
        result = SEC_FW_FS_REOPEN_FILE_ERROR;
        break;

    case IPC_RET_FW_FS_PAGE_NOT_FOUND:
        result = SEC_FW_FS_PAGE_NOT_FOUND;
        break;

    case IPC_RET_FW_FS_HEADER_LENGTH_MISMATCH:
        result = SEC_FW_FS_HEADER_LENGTH_MISMATCH;
        break;

    case IPC_RET_INVALID_PAGE_ADDRESS:
        result = SEC_FW_INVALID_PAGE_ADDRESS;
        break;

    case IPC_RET_FW_FS_FILE_NOT_OPENED:
        result = SEC_FW_FS_FILE_NOT_OPENED;
        break;

    case IPC_RET_SYSTEM_MEMORY_FULL:
        result = SEC_FW_SYSTEM_MEMORY_FULL;
        break;

    case IPC_RET_INVALID_SYSTEM_ADDRESS:
        result = SEC_FW_INVALID_SYSTEM_ADDRESS;
        break;

    case IPC_RET_INVALID_MODE:
        result = SEC_FW_INVALID_MODE;
        break;

    case IPC_RET_INVALID_NONCE:
        result = SEC_FW_INVALID_NONCE;
        break;

    case IPC_RET_INVALID_STEP:
        result = SEC_FW_INVALID_STEP;
        break;

    case IPC_RET_INVALID_KEY_ATTRIBUTES:
        result = SEC_FW_INVALID_KEY_ATTRIBUTES;
        break;

    case IPC_RET_TTB_KEY_INVALID:
        result = SEC_FW_TTB_KEY_INVALID;
        break;

    case IPC_RET_INVALID_KEY_TYPE:
        result = SEC_FW_INVALID_KEY_TYPE;
        break;

    case IPC_RET_INVALID_KEY_ID:
        result = SEC_INVALID_KEY_ID;
        break;

    case IPC_RET_INVALID_KEY_LOCATION:
    case IPC_RET_INVALID_DEST_PARAM:
        result = SEC_INVALID_KEY_LOCATION;
        break;

    case IPC_RET_INVALID_KEY_SELECT:
        result = SEC_FW_INVALID_KEY_SELECT;
        break;

    case IPC_RET_NO_KEY_SLOTS_AVAILABLE:
        result = SEC_FW_NO_KEY_SLOTS_AVAILABLE;
        break;

    case IPC_RET_DRBG_NOT_INITIALIZED:
        result = SEC_FW_DRBG_NOT_INITIALIZED;
        break;

    case IPC_RET_INVALID_HW_COMMAND:
        result = SEC_FW_INVALID_HW_COMMAND;
        break;

    case IPC_RET_EAU_PARITY_ERROR:
        result = SEC_FW_EAU_PARITY_ERROR;
        break;

    case IPC_RET_MOD_EXP_WITHOUT_EXPONENT:
        result = SEC_FW_MOD_EXP_WITHOUT_EXPONENT;
        break;

    case IPC_RET_INVALID_AES_CTR_MODE:
        result = SEC_FW_INVALID_AES_CTR_MODE;
        break;

    case IPC_RET_INVALID_CHAIN_MODE:
        result = SEC_FW_INVALID_CHAIN_MODE;
        break;

    case IPC_RET_CRYPT_FAILED:
    case IPC_RET_SIGN_FAILED:
    case IPC_RET_DRBG_FAILED:
    case IPC_RET_MOD_REDUCE_FAIL:
    case IPC_RET_SCALAR_MULT_FAIL:
    case IPC_RET_SHA_FAIL:
    case IPC_RET_SIGNATURE_VERIFICATION_FAILED:
        result = SEC_FW_CRYPT_OP_FAILED;
        break;

    case IPC_RET_NO_CONTEXT_AVAILABLE:
        result = SEC_FW_DRM_CONTEXT_NOT_AVAILABLE;
        break;

    case IPC_RET_INVALID_CONTEXT:
        result = SEC_FW_DRM_CONTEXT_INVALID;
        break;

    case IPC_RET_FEATURE_UNSUPPORTED:
    case IPC_RET_COMMAND_NOT_SUPPORTED_YET:
        result = SEC_NOT_SUPPORTED;
        break;

    case IPC_RET_INVALID_MSG:
        result = SEC_FW_DRM_INVALID_MSG;
        break;

    case IPC_RET_BAD_SINK_DEVICE:
        result = SEC_FW_DRM_BAD_SINK_DEVICE;
        break;

    case IPC_RET_DRM_NO_MEM:
        result = SEC_FW_DRM_NO_MEM;
        break;

    case IPC_RET_CONTEXT_BLACKLIST:
        result = SEC_FW_DRM_CONTEXT_BLACKLIST;
        break;

    case IPC_RET_INVALID_PROTOCOL_STATE:
        result = SEC_FW_DRM_INVALID_PROTOCOL_STATE;
        break;

    case IPC_RET_SRM_FAIL:
        result = SEC_FW_DRM_SRM_FAIL;
        break;

    case IPC_RET_TDP_PMR_NOT_LOCKED:
    case IPC_RET_TDP_PMR_INVALID_DRAM_ADDR:
    case IPC_RET_TDP_PMR_INVALID_BOUNDS:
    case IPC_RET_TDP_PMR_OVERLAPPING:
    case IPC_RET_TDP_MEM_CLASS_NOT_LOCKED:
    case IPC_RET_TDP_MEM_CLASS_PMR_MISMATCH:
    case IPC_RET_TDP_MEM_CLASS_INVALID_TYPE:
    case IPC_RET_TDP_ATTRIB_MATRIX_NOT_LOCKED:
    case IPC_RET_TDP_ATTRIB_MATRIX_INVALID:
    case IPC_RET_TDP_VT_BASE_NOT_LOCKED:
    case IPC_RET_TDP_VT_BASE_INVALID:
    case IPC_RET_TDP_INVALID_VENDOR_ID:
    case IPC_RET_TDP_INVALID_SERIAL_NUM:
    case IPC_RET_TDP_INVALID_UNIT_FLAGS:
    case IPC_RET_TDP_INVALID_MODULE_SIZE:
    case IPC_RET_TDP_INVALID_GATHER_ENTRY_SIZE:
    case IPC_RET_TDP_INVALID_DESTINATION_TYPE:
    case IPC_RET_TDP_INVALID_SEC_ATTRIB_TYPE:
    case IPC_RET_TDP_INVALID_SNOOP_SETTING:
    case IPC_RET_TDP_SNOOP_NOT_LOCKED:
    case IPC_RET_TDP_INVALID_DEST_ALIGNMENT:
    case IPC_RET_TDP_MODULE_OVERLAPPING:
    case IPC_RET_TDP_TOO_MANY_BSP_IMAGES:
    case IPC_RET_TDP_NO_STR_REGIONS:
    case IPC_RET_TDP_CORRUPT_STR_REGIONS:
    case IPC_RET_TDP_INVALID_CONFIG_FILE:
    case IPC_RET_TDP_INVALID_FW_VERSION:
    case IPC_RET_TDP_INVALID_MEU_CONFIG:
    case IPC_RET_TDP_INVALID_VDC_WB_TTR:
    case IPC_RET_TDP_INVALID_HDVCAP_TTR:
    case IPC_RET_TDP_INVALID_AUDIO_TTR:
    case IPC_RET_TDP_INVALID_SKU_ID:
    case IPC_RET_TDP_MODULE_NOT_LOADED:
        result = SEC_TDP_INIT_FAILED;
        break;

    case IPC_RET_INVALID_KEY_SIZE:
        result = SEC_INVALID_KEY_LENGTH;
        break;

    case IPC_RET_HDCP2R_INVALID_STATE:
        result = SEC_HDCP2R_INVALID_STATE;
        break;

    case IPC_RET_HDCP2R_CALCULATION_FAILED:
        result = SEC_HDCP2R_CALCULATION_FAILED;
        break;

    case IPC_RET_HDCP2R_OUT_OF_RESOURCES:
        result = SEC_HDCP2R_OUT_OF_RESOURCES;
        break;

    case IPC_RET_HDCP2R_OUT_OF_SESSIONS:
        result = SEC_HDCP2R_OUT_OF_SESSIONS;
        break;

    case IPC_RET_HDCP2R_BAD_SESSION_TYPE:
        result = SEC_HDCP2R_BAD_SESSION_TYPE;
        break;

    case IPC_RET_HDCP2R_INVALID_SESSION:
        result = SEC_HDCP2R_INVALID_SESSION;
        break;

    case IPC_RET_HDCP2R_UNPERMITTED_SESSION_TYPE:
        result = SEC_HDCP2R_UNPERMITTED_SESSION_TYPE;
        break;

    case IPC_RET_HDCP2R_KEYBLOB_NOT_LOADED_YET:
        result = SEC_HDCP2R_KEYBLOB_NOT_LOADED_YET;
        break;

    case IPC_RET_HDCP2R_KEYBLOB_ALREADY_LOADED:
        result = SEC_HDCP2R_KEYBLOB_ALREADY_LOADED;
        break;

    case IPC_RET_HDCP2R_KEYBLOB_NOT_GKEKED:
        result = SEC_HDCP2R_KEYBLOB_NOT_GKEKED;
        break;

    case IPC_RET_HDCP2R_KEYBLOB_ALREADY_WRAPPED:
        result = SEC_HDCP2R_KEYBLOB_ALREADY_WRAPPED;
        break;

    default:
        result = IPC_RET_OK(ipc_ret) ? SEC_SUCCESS : SEC_FAIL;
        break;
    }
    return result;
}

//-----------------------------------------------------------------------------
// print_data
//-----------------------------------------------------------------------------
static
void print_data (char *label, uint32_t *data, int size)
{
    int i;

    for (i=0; i < size; i++ )
    {
        SEC_DEBUG("%s[%d]=0x%08x\n", label, i, data[i]);
    }
    SEC_DEBUG("\n");
}


//-----------------------------------------------------------------------------
// sec_hal_get_pci_device_id
//
// Returns this SoC's PCI Vendor ID, Device ID, and revision number for
// a device within the SoC, given the PCI bus, device, and function numbers.
//-----------------------------------------------------------------------------
sec_result_t sec_hal_get_pci_device_id(
    unsigned char bus, unsigned char dev, unsigned char func,
    uint16_t *pvendor, uint16_t *pdevice, uint16_t *prevision)
{
    unsigned char rev;
    uint16_t vendor, device, revision;
    os_pci_dev_t  pci_dev, pdev;
    osal_result   ores, ores2, ores3, ores4;
    unsigned int  vendor_device_id = 0;
    unsigned int offset;
    sec_result_t   rc = SEC_SUCCESS;

    VERIFY(pvendor   != NULL, exit, rc, SEC_NULL_POINTER);
    VERIFY(pdevice   != NULL, exit, rc, SEC_NULL_POINTER);
    VERIFY(prevision != NULL, exit, rc, SEC_NULL_POINTER);

    vendor = 0;
    device = 0;
    revision = 0;

    offset = 8;
    ores = os_pci_device_from_address(&pci_dev, bus, dev, func);
    if(ores == OSAL_SUCCESS)
    {
        ores2 = os_pci_read_config_32(pci_dev, 0, &vendor_device_id);
        if (ores2 == OSAL_SUCCESS)
        {
            device = (vendor_device_id & 0xffff0000) >> 16;
            vendor = (vendor_device_id & 0x0000ffff);
            ores3 = os_pci_find_first_device((unsigned int)vendor,
                                             (unsigned int)device, &pdev);
            if (ores3 == OSAL_SUCCESS)
            {
                ores4 = os_pci_read_config_8(pdev,offset,&rev);
                if (ores4 == OSAL_SUCCESS)
                {
                    revision =  (uint16_t)rev;
                }
                else
                {
                    revision = 0;
                    switch(ores4)
                    {
                        case OSAL_ERROR: rc=SEC_PCI_DEVICE_ACCESS_ERROR; break;
                        case OSAL_INVALID_HANDLE: rc=SEC_NULL_POINTER; break;
                        case OSAL_INVALID_PARAM: rc=SEC_NULL_POINTER; break;
                        case OSAL_NOT_FOUND: rc=SEC_PCI_DEVICE_NOT_FOUND; break;
                        default: rc = SEC_FAIL;
                    }
                }
            }
            else
            {
                revision = 0;
                if(ores3 == OSAL_NOT_FOUND)
                {
                    rc = SEC_PCI_DEVICE_NOT_FOUND;
                }
                else
                {
                    rc = SEC_FAIL;
                }
            }
            os_pci_free_device( pdev );
        }
        else
        {
            vendor = 0;
            device = 0;
            revision = 0;
            switch(ores2)
            {
                case OSAL_ERROR: rc=SEC_PCI_DEVICE_ACCESS_ERROR; break;
                case OSAL_INVALID_HANDLE: rc=SEC_NULL_POINTER; break;
                case OSAL_INVALID_PARAM: rc=SEC_NULL_POINTER; break;
                case OSAL_NOT_FOUND: rc=SEC_PCI_DEVICE_NOT_FOUND; break;
                default: rc = SEC_FAIL;
            }
        }
        os_pci_free_device( pci_dev );
    }
    else
    {
        switch(ores)
        {
        /* OSAL_ERROR means the "/proc/bus/pci/%2.2x/%2.2x.%1.1x"
           was not the correct length so invalid parameter */
        case OSAL_ERROR: rc=SEC_INVALID_INPUT; break;
        /* OSAL_NOT_FOUND means could not find the device at
           "/proc/bus/pci/%2.2x/%2.2x.%1.1x" */
        case OSAL_NOT_FOUND: rc=SEC_PCI_DEVICE_NOT_FOUND; break;
        /* OSAL_INSUFFICIENT_MEMORY means could not allocate memory
           for pci_dev_t */
        case OSAL_INSUFFICIENT_MEMORY: rc=SEC_OUT_OF_MEMORY; break;
        default: rc = SEC_FAIL;
        }
    }

    *pdevice  = device;
    *pvendor  = vendor;
    *prevision= revision;
exit:
    return rc;
}


//-----------------------------------------------------------------------------
// sec_hal_get_iahost_chip_info
//
// This sec_hal_get_iahost_chip_info function returns the PCI host vendor,
// device, and revision numbers in the structure at the address that the
// passed parameter sec_chip_info points to.
//-----------------------------------------------------------------------------
sec_result_t
sec_hal_get_iahost_chip_info(sec_chip_info_t *sec_chip_info )
{
    uint16_t          host_vendor, host_device, host_revision;
    sec_result_t      rc;
    sec_result_t      eres;
    unsigned char     bus, dev, func;

    //check input parameters
    VERIFY(sec_chip_info != NULL, exit_now, rc, SEC_NULL_POINTER);

    rc = SEC_SUCCESS;
    host_vendor= 0;
    host_device= 0;
    host_revision= 0;
    sec_chip_info->host_vendor = host_vendor;
    sec_chip_info->host_device = host_device;
    sec_chip_info->host_revision = host_revision;

    /*The Host is on PCI bus 0 device 0 function 0*/
    bus = PCI_BUS_HOST;
    dev = PCI_DEV_HOST;
    func= PCI_FUNC_HOST;

    /* Get the SoC's Intel Host vendor, device, and revision information */
    eres = sec_hal_get_pci_device_id(bus, dev, func,
               &host_vendor, &host_device, &host_revision);
#ifdef DEBUG_SEC_HAL_GET_PCI_CHIP_INFO
    printk(KERN_INFO "\n sec_hal_get_pci_device_id returned=%d\n", (int)eres);
    printk(KERN_INFO " The SoC's Host's PCI VendorID=0x%04X\n", host_vendor);
    printk(KERN_INFO " DeviceID=0x%04X RevisionID=0x%04X\n\n", host_device, host_revision);
#endif
    if(eres == SEC_SUCCESS)
    {
        sec_chip_info->host_vendor = host_vendor;
        sec_chip_info->host_device = host_device;
        sec_chip_info->host_revision = host_revision;
    }
    else
    {
        rc = eres;
        goto exit_now;
    }

    /* Verify the SoC host is Intel */
    if(host_vendor != PCI_VENDOR_INTEL)
    {
       rc = SEC_NOT_AN_INTEL_SOC;
       goto exit_now;
    }

    /* Verify this Intel Host is a supported SoC */
    switch(host_device)
    {
        case PCI_DEVICE_CE2600: break;
        case PCI_DEVICE_CE3100: break;
        case PCI_DEVICE_CE4100: break;
        case PCI_DEVICE_CE4200: break;
        case PCI_DEVICE_CE5300: break;
        default:
            rc = SEC_NOT_A_SUPPORTED_INTEL_SOC;
    }

exit_now:
    return rc;
} // ENDPROC sec_hal_get_iahost_chip_info


//-----------------------------------------------------------------------------
// sec_hal_get_sec_chip_info
//
// This sec_get_chip_info function returns the PCI security hardware vendor,
// device, and revision numbers in the structure at the address that the
// passed parameter sec_chip_info points to.
//-----------------------------------------------------------------------------
sec_result_t
sec_hal_get_sec_chip_info(sec_chip_info_t *sec_chip_info )
{
    uint16_t          sec_vendor, sec_device, sec_revision;
    sec_result_t      rc;
    sec_result_t      eres;
    unsigned char     bus, dev, func;

    //check input parameters
    VERIFY(sec_chip_info != NULL, exit_now, rc, SEC_NULL_POINTER);

    rc = SEC_SUCCESS;
    sec_vendor= 0;
    sec_device= 0;
    sec_revision = 0;
    sec_chip_info->sec_vendor = sec_vendor;
    sec_chip_info->sec_device = sec_device;
    sec_chip_info->sec_revision = sec_revision;

    /*The SEC HW is on PCI bus 1 device 9 function 0*/
    bus = PCI_BUS_SEC;
    dev = PCI_DEV_SEC;
    func= PCI_FUNC_SEC;

    /* Get the SoC's SEC HW vendor, device, and revision information */
    eres = sec_hal_get_pci_device_id(bus, dev, func,
               &sec_vendor, &sec_device, &sec_revision);
#ifdef DEBUG_SEC_HAL_GET_PCI_CHIP_INFO
    printk(KERN_INFO "\n sec_hal_get_pci_device_id returned=%d\n", (int)eres);
    printk(KERN_INFO " The SoC's Security HW Unit's PCI VendorID=0x%04X\n", sec_vendor);
    printk(KERN_INFO " DeviceID=0x%04X RevisionID=0x%04X\n", sec_device, sec_revision);
#endif

    if(eres == SEC_SUCCESS)
    {
        sec_chip_info->sec_vendor = sec_vendor;
        sec_chip_info->sec_device = sec_device;
        sec_chip_info->sec_revision = sec_revision;
    }
    else
    {
        rc = eres;
        goto exit_now;
    }
    /* Verify the SoC's SEC HW is Intel */
    if(sec_device != PCI_DEVICE_SEC)
    {
       rc = SEC_HW_PCI_ID_UNKNOWN;
    }

exit_now:
    return rc;
} // ENDPROC sec_hal_get_sec_chip_info

//-----------------------------------------------------------------------------
// sec_get_job_id
//
// Function returns unique job id back to a caller. job id is used to
// differentiate between SEC unit jobs
//-----------------------------------------------------------------------------
uint32_t sec_get_job_id(void)
{
    static uint32_t job_id = 0;

    down(&jobid_semaphore);
    job_id++;
    up(&jobid_semaphore);

    return job_id;
}


//-----------------------------------------------------------------------------
// sec_hal_intr_func
//
// When the security hardware firmware rings the output doorbell then an
// interrupt is generated and linux calls this function. Thus this is the
// interrupt handler.
//-----------------------------------------------------------------------------
void sec_hal_intr_func(void * data)
{
    sec_hal_t *      sec_hal = (sec_hal_t *) data;
    sec_ipc_return_t ipc_rc  = 0;
    uint32_t         job_id  = 0;
    uint32_t         opl_size;
    uint32_t        *opl_u32ptr;
    void            *opl_ptr;
    int              i;
    bool             found   = false;
    int              index   = -1;
    //Check if the SEC is ready to receive the input
    if (sec_hal_devh_ReadReg32(sec_hal,SEC_HAL_IPC_HOST_INT_STATUS) & 0x2)
    {
        // Clear input ready interrupt
        sec_hal_devh_WriteReg32(sec_hal , SEC_HAL_IPC_HOST_INT_STATUS, 0x2);

        // Allow new input to SEC
        os_event_set(&ready_for_input);
    }
    //Check to see if the SEC completes any command
    if (sec_hal_devh_ReadReg32(sec_hal,SEC_HAL_IPC_HOST_INT_STATUS) & 0x1)
    {
        //Retrieve the process id from the output payload
        job_id = sec_hal_devh_ReadReg32(sec_hal, SEC_HAL_IPC_OUTPUT_PAYLOAD);

        //Retrieve the output status
        ipc_rc = sec_hal_devh_ReadReg32(sec_hal, SEC_HAL_IPC_OUTPUT_DOORBELL);

        if (ipc_rc == IPC_RET_MONOTONIC_TIME_BASE_PULSE) //ignore for now
        {
            goto done;
        }

        spin_lock_irqsave(&score_board.board_lock, score_board.flags);
        for (i=0; i < 32; i++)
        {
            if (score_board.ops[i].job_id == job_id)
            {
                if (ipc_rc == IPC_RET_COMMAND_COMPLETE)
                {
                    //Read the SEC HW output payload 64 bytes max
                    if ((score_board.ops[i].opl) && (score_board.ops[i].opl_size > 4))
                    {
                        //Cannot dereference a void pointer.
                        opl_u32ptr = (uint32_t*)score_board.ops[i].opl;
                        *opl_u32ptr = job_id;

                        //Increment the output payload pointer by 4 bytes
                        //because we already read the job id, so why read
                        //it twice.
                        opl_ptr = ((void*)score_board.ops[i].opl) + 4;

                        //So, now we can copy 4 less bytes from sec
                        opl_size = (uint32_t)score_board.ops[i].opl_size - 4;

                        //Read output payload starting after job_id
                        sec_hal_read_pl(sec_hal, opl_ptr, 4, opl_size);
                    } /* ENDIF there was output payload to copy */

                    //Read the SEC HW shared memory 256 Bytes at a time. shared memory can be > 256 Bytes
                    if ((score_board.ops[i].osh_pl) && (score_board.ops[i].osh_size > 0))
                    {
                        if(score_board.ops[i].osh_size - score_board.ops[i].osh_size_copied > 256)
                        {
                            sec_hal_read_sh_ram(sec_hal,
                                            (void*)score_board.ops[i].osh_pl + score_board.ops[i].osh_size_copied,
                                            0,
                                            256);
                           score_board.ops[i].osh_size_copied +=256;
                        }
                        else
                        {
                            sec_hal_read_sh_ram(sec_hal,
                                            (void*)score_board.ops[i].osh_pl + score_board.ops[i].osh_size_copied,
                                            0,
                                            (uint32_t)score_board.ops[i].osh_size-score_board.ops[i].osh_size_copied);
                           score_board.ops[i].osh_size_copied += (score_board.ops[i].osh_size-score_board.ops[i].osh_size_copied);
                        }
                    } /* ENDIF there was PCI mapped shared memory to copy */
                } /* ENDIF ipc_rc == IPC_RET_COMMAND_COMPLETE */
                //if(score_board.ops[i].osh_size == score_board.ops[i].osh_size_copied)
                if ( ((ipc_rc == IPC_RET_COMMAND_COMPLETE) && (score_board.ops[i].osh_size == score_board.ops[i].osh_size_copied)) ||
                     (ipc_rc != IPC_RET_COMMAND_COMPLETE))
                {
                    score_board.ops[i].ipc_rc = ipc_rc;
                    index = i;
                    found = true;
                }
                break;
            } /* ENDIF score_board.ops[i].job_id == job_id */
        } /* ENDFOR all the score_boards*/
        spin_unlock_irqrestore(&score_board.board_lock, score_board.flags);

        //Wake up the calling process
        if (found == true)
        {
            os_event_set(&(score_board.ops[index].event_done));
        }

done:
        //Clear any pending output interrupts
        sec_hal_devh_WriteReg32(sec_hal , SEC_HAL_IPC_HOST_INT_STATUS, 0x1);
        // Re-enable SEC to Output Payload for next cmd
        sec_hal_devh_WriteReg32(sec_hal , SEC_HAL_IPC_OUTPUT_STATUS, 0x1);
    } /* ENDIF the SEC completed a command */
} /* ENDPROC sec_hal_intr_func */


//-----------------------------------------------------------------------------
// sec_lock_resources
//
// Lock a set of SEC resources to protect them from reuse for the duration of a
// sec operation.
//
// resources - An OR'd combination of 0 or more bit flags from the
//             sec_fw_resource_t enumeration.
//-----------------------------------------------------------------------------
void sec_lock_resources(uint32_t resources)
{
    int i;

    // TODO: useage of sec_api_semaphore is temporary till issues with
    // parallel execution are solved
    // Lock out all other commands before semaphore is released
 //   down(&sec_api_semaphore);

    for (i=0; resources && (i < SEC_RESOURCE_COUNT); i++, resources >>= 1)
    {
        if (resources & 1)
        {
            down(&score_board.res_semas[i]);
        }
    }
}


//-----------------------------------------------------------------------------
// sec_unlock_resources
//
// Release a set of SEC resources for reuse in future SEC operations.
//
// resources - An OR'd combination of 0 or more bit flags from the
//             sec_fw_resource_t enumeration.
//-----------------------------------------------------------------------------
void sec_unlock_resources(uint32_t resources)
{
    int i;

    // TODO: useage of sec_api_semaphore is temporary till issues with
    // parallel execution are solved
    // Release global semaphore so that other APIs can execute
    //up(&sec_api_semaphore);

    for (i=0; resources && (i < SEC_RESOURCE_COUNT); i++, resources >>= 1)
    {
        if (resources & 1)
        {
            up(&score_board.res_semas[i]);
        }
    }
}


//----------------------------------------------------------------------------
// sec_get_eau_lock
//
// Call that implements SEC_GET_EAU_LOCK ioctl call. The down_interruptible
// allows a user-space process that is waiting on this semaphore to be
// interrupted by the user.
//----------------------------------------------------------------------------
static sec_result_t sec_get_eau_lock(uint32_t arg)
{
    sec_result_t  rc = SEC_SUCCESS;
    int nret = 0;

    nret = down_interruptible(&sec_eau_sema);
#ifdef DEBUG_EAU_LOCKING
    printk(KERN_INFO "down_interruptible returned %d for tgid %d\n",
           nret, (int)(current->tgid) );
#endif
    if(nret != 0)
    {
        if(nret == 4)
        {
            rc = SEC_EAU_LOCK_INTERRUPTED;
            goto exit;
        }
        else
        {
            rc = SEC_EAU_LOCK_FAILED;
        }
    }
    if(rc == SEC_SUCCESS)
    {
        rc=tracker_add_eau_lock(current->tgid);
        if(rc!=SEC_SUCCESS)
        {
            up(&sec_eau_sema);
            goto exit;
        }
    }

exit:
    return rc;
}


//----------------------------------------------------------------------------
// sec_release_eau_lock
//
// Call that implements SEC_RELEASE_EAU_LOCK ioctl call.
//----------------------------------------------------------------------------
static
sec_result_t sec_release_eau_lock(uint32_t arg)
{
    sec_result_t  rc = SEC_SUCCESS;
    up(&sec_eau_sema);

#ifdef DEBUG_EAU_LOCKING
    printk(KERN_INFO "called up for sec_eau_sema tgid %d\n",
           (int)(current->tgid));
#endif
    rc = tracker_remove_eau_lock(current->tgid);
    return rc;
}

void free_eau_lock()
{
    up(&sec_eau_sema);
}

//-----------------------------------------------------------------------------
// wait_for_input_ready
//
// Function to wait for SEC be ready to receive input
//-----------------------------------------------------------------------------
static
sec_ipc_return_t wait_for_input_ready(void)
{
    osal_result ores;
    sec_ipc_return_t ipcret;

    ipcret = IPC_RET_SUCCESS;

    ores = os_event_hardwait(&ready_for_input, g_sec_max_ipc_wait);
    switch (ores)
    {
        case OSAL_SUCCESS:
            ipcret = IPC_RET_SUCCESS;
            break;
        case OSAL_TIMEOUT:
            printk(KERN_WARNING "SEC timed out waiting on FW.\n");
            ipcret = IPC_RET_WAIT_TIMEOUT;
            break;
        default:
            ipcret = IPC_RET_ERROR;
            break;
    }
    return ipcret;
}


//-----------------------------------------------------------------------------
// sec_get_scoreboard_slot
// This function initializes the score_board's sec_fw_op_t structure for the
// given job_id. This includes saving the returned payload and shared memory
// sizes that the Interrupt Service Routine (ISR) will use to only get the
// needed bytes.
//-----------------------------------------------------------------------------
static
sec_fw_op_t *
sec_get_scoreboard_slot(uint32_t job_id, uint16_t opl_size, uint16_t osh_size, opl_t *opl, ipc_shmem_t *osh_pl)
{
    int          i;
    sec_fw_op_t *op;

    spin_lock(&score_board.board_lock);

    for (op=score_board.ops, i=0; i < SEC_MAX_OPERATION_COUNT; i++, op++)
    {
        if (op->job_id == 0)
        {
            op->job_id  = job_id;
            op->opl_size = opl_size;
            op->osh_size = osh_size;
            op->opl     = opl;
            op->osh_pl  = osh_pl;
            op->osh_size_copied  = 0;
            op->ipc_rc  = 0;
            break;
        }
    }

    spin_unlock(&score_board.board_lock);
    if (i >= SEC_MAX_OPERATION_COUNT)
    {
        op = NULL;
    }

    return op;
}


//-----------------------------------------------------------------------------
// sec_release_scoreboard_slot
//
// Function to free a SEC driver resource
//-----------------------------------------------------------------------------
static
void sec_release_scoreboard_slot(sec_fw_op_t *  op)
{
    spin_lock(&score_board.board_lock);
    op->job_id = 0;
    spin_unlock(&score_board.board_lock);
}


//-----------------------------------------------------------------------------
// sec_kernel_free_descriptor_list
//
// Marks the descriptors in the descriptor list as available for reuse
//
// Parameters:
//      head - first entry in linked list of descriptors to free
//-----------------------------------------------------------------------------
void sec_kernel_free_descriptor_list( sec_dma_descriptor_t * head )
{
    while (head != NULL)
    {
        sec_dma_descriptor_t * tmp = head;
        head = head->next ? phys_to_virt(head->next) : NULL;
        OS_FREE(tmp);
    }
}


//-----------------------------------------------------------------------------
// sec_request_shram_access
// This function requests access to the SEC FW controlled IPC Shared RAM.
// It must be called before initiating any crypto requests that use the
// IPC Shared RAM or data corruption may occur. This Linux host side driver
// should wait for a return of SEC_FW_RET_IPC_SHARED_RAM_ACCESS_GRANTED.
//-----------------------------------------------------------------------------
static
sec_ipc_return_t sec_request_shram_access(void)
{
    sec_fw_op_t *    op;
    sec_ipc_return_t rc;
    osal_result    ores;
    ipl_t ipl;
    opl_t opl;

    rc = wait_for_input_ready();
    if( IPC_RET_OK(rc) )
    {
        ipl.data[0] = sec_get_job_id();
        op = sec_get_scoreboard_slot(ipl.data[0], REQ_IPC_SHARED_RAM_OPL_SIZE,
                                     REQ_IPC_SHARED_RAM_OSH_size, &opl, NULL);
        VERIFY(op != NULL, exit, rc, IPC_RET_ERROR);

        spin_lock(&sec_hw_unit_lock);
        sec_hal_ipc_call(&sec_hal_handle,
                         IPC_REQUEST_IPC_SHARED_RAM,
                         (uint32_t *) &ipl,
                         sizeof(ipl_t),
                         NULL,
                         0);
        spin_unlock(&sec_hw_unit_lock);

        ores = os_event_hardwait(&(op->event_done), g_sec_max_ipc_wait);
        switch (ores)
        {
            case OSAL_SUCCESS:
                rc = (sec_ipc_return_t) op->ipc_rc;
                break;
            case OSAL_TIMEOUT:
                rc = IPC_RET_WAIT_TIMEOUT;
                printk(KERN_WARNING
                    "SEC timed out waiting on FW IPC %d to complete.\n",
                    (int)IPC_REQUEST_IPC_SHARED_RAM);
                break;
            default:
                rc = IPC_RET_ERROR;
                break;
        }
        sec_release_scoreboard_slot(op);
    }

exit:
    return rc;
}


//-----------------------------------------------------------------------------
// sec_kernel_ipc
//
// Function sends IPC command to the firmware and waits for its completion.
// Function assumes that proper serialization (if needed) is done outside of
// it. Synchronization for hyperthreaded multi-core systems is done through
// the spinlock sec_hw_unit_lock.
//-----------------------------------------------------------------------------
sec_ipc_return_t sec_kernel_ipc(sec_fw_cmd_t    ipc_cmnd,
                                sec_fw_subcmd_t sub_cmd,
                                sec_ipc_sizes_t io_sizes,
                                ipl_t *         ipl,
                                opl_t *         opl,
                                ipc_shmem_t *   ish_pl,
                                ipc_shmem_t *   osh_pl)
{
    osal_result       ores=OSAL_SUCCESS;
    sec_ipc_return_t  rc;
    sec_fw_op_t      *op;
    uint32_t          outstatus;
    uint32_t          outdoorbell;
    unsigned int      tgid = (unsigned int) current->tgid;
    uint32_t          status=0;
    uint32_t          offset=0;
    uint32_t          pending_entry=0;
    uint32_t          wait_addr;
    uint32_t          cleanup_addr;
    uint32_t          compl=0;
    uint32_t          b_thr_offset=0;
    uint32_t          bulk_mode =0;
    //for each IPC command, it is checked if application is in BULK mode. 
    //if application has already send BULK IPC start command for this tgid, global data will have the information.
    for( b_thr_offset=0; b_thr_offset < g_bulk_counter ;b_thr_offset++)
    {
        if((tgid==g_bulk_stat[b_thr_offset].tgid) && g_bulk_stat[b_thr_offset].bulk_mode)
        {
            bulk_mode = 1;
            break;
        }
    }
    VERIFY(ipl != NULL, exit, rc, SEC_FAIL);

    //if application is in bulkmode, instead of sending IPC in normal fashion, 
    //input payload will be written in circular data buffer. 
    //and IPC command will be written to command buffer and status is written as zero in command buffer. 
    //when command is complete, status will be non-zero    
    if(bulk_mode == 1)
    {
        while(1)
       {
            //checks if there is any empty node in circular buffer.
            //locked this region to calculate the offset and write ipl/opl exclusively. 
            //it is required so that 2 IPC commands cant overwrite each other on same offset.
            down(&g_bulk_stat[b_thr_offset].write_ptr_lock);
            pending_entry = (g_bulk_stat[b_thr_offset].write_ptr - g_bulk_stat[b_thr_offset].cmd_buff_ptr) /8;
            if(pending_entry == (g_bulk_stat[b_thr_offset].counter) )
            {
                up(&g_bulk_stat[b_thr_offset].write_ptr_lock);
            }
            else
            {
                if ( ( ipc_cmnd != IPC_54 &&
                    ( ipc_cmnd != IPC_EXTERNAL_MODULE_CMD ||
                    (ipl->external_module_ipc.module_id & SEC_IPC_54_MODULE_ID_MASK) !=
                    SEC_IPC_54_MODULE_ID ) )
                   ||  (sub_cmd.sc_54 != IPC_SC_54_12))
                {
                    ipl->data[0] = sec_get_job_id();
                }
               break;
            }
        }
        //if command is not bulk_mode_stop command(0xffffffff).
        if(ipc_cmnd != 0xFFFFFFFF)
        {
            //calculates next offset in the circular buffer to write the input payload.
            offset=((g_bulk_stat[b_thr_offset].write_ptr - g_bulk_stat[b_thr_offset].cmd_buff_ptr)/8) % g_bulk_stat[b_thr_offset].counter;
            //In circular data buffer, each offset takes total 320 bytes. 
            //top 64 bytes for ipl/opl and rest 256 bytes for input/output shared RAM. 
            memcpy((void *) (g_bulk_stat[b_thr_offset].cmd_data_ptr + offset*SEC_HW_MAX_IPCMEM), ipl, SEC_HW_MAX_PAYLOAD);
            //if shared RAM is not null, most significant bit of ipc command should be set.
            if(ish_pl != NULL)
            {
                memcpy((void *) (g_bulk_stat[b_thr_offset].cmd_data_ptr + offset*SEC_HW_MAX_IPCMEM +SEC_HW_MAX_PAYLOAD ), ish_pl, SEC_HW_MAX_SHAREDMEM);
                ipc_cmnd = ipc_cmnd | 0x80000000;
            }
            memcpy((void *) (g_bulk_stat[b_thr_offset].cmd_buff_ptr + offset*8 + 4 ), &status, 4);
            memcpy((void *) (g_bulk_stat[b_thr_offset].cmd_buff_ptr + offset*8), &ipc_cmnd, 4);
            //wait_addr is the address where IPC command was written. 
            //In circular command buffer, each nodes takes 8bytes, top 4 bytes is for ipc_cmnd and last 4 byte is for return status.
            wait_addr =  g_bulk_stat[b_thr_offset].write_ptr;
            cleanup_addr = g_bulk_stat[b_thr_offset].cmd_data_ptr + offset*SEC_HW_MAX_IPCMEM;
            g_bulk_stat[b_thr_offset].write_ptr = g_bulk_stat[b_thr_offset].write_ptr + 8;
            if(g_bulk_stat[b_thr_offset].write_ptr == g_bulk_stat[b_thr_offset].cmd_buff_ptr + 8 * g_bulk_stat[b_thr_offset].counter)
                g_bulk_stat[b_thr_offset].write_ptr = g_bulk_stat[b_thr_offset].cmd_buff_ptr;
            //Once Input payload is copied to appropriate offset, writer thread sends complete signal to polling bulk_poll thread.
            complete(&g_bulk_stat[b_thr_offset].host_compl_signal);
            //Now IPC writer thread waits for polling thread's signal.
            wait_for_completion(&g_bulk_stat[b_thr_offset].fw_compl_signal);
            INIT_COMPLETION(g_bulk_stat[b_thr_offset].fw_compl_signal);
            up(&g_bulk_stat[b_thr_offset].write_ptr_lock);
            //reads the return status of ipc_command
            memcpy(&compl, (void *)(wait_addr+4), 4);
            memset((void *)(wait_addr),0,8);
            memset((void *)(cleanup_addr),0,SEC_HW_MAX_IPCMEM);
            if(compl!= IPC_RET_COMMAND_COMPLETE)
            {
                return compl;
            }
            else
            {
                if(opl != NULL)
                {
                    memcpy(opl, (void *) (g_bulk_stat[b_thr_offset].cmd_data_ptr + offset*SEC_HW_MAX_IPCMEM), SEC_HW_MAX_PAYLOAD);
                }
                if(osh_pl != NULL)
                {
                    memcpy(osh_pl, (void *) (g_bulk_stat[b_thr_offset].cmd_data_ptr + (offset*SEC_HW_MAX_IPCMEM) +SEC_HW_MAX_PAYLOAD ), SEC_HW_MAX_SHAREDMEM);
                }
                return compl;
            }
        }
        else
        {
            //In bulk_mode_stop
            offset=((g_bulk_stat[b_thr_offset].write_ptr - g_bulk_stat[b_thr_offset].cmd_buff_ptr)/8) % g_bulk_stat[b_thr_offset].counter;
            memcpy((void *) (g_bulk_stat[b_thr_offset].cmd_buff_ptr + offset*8 + 4 ), &status, 4);
            up(&g_bulk_stat[b_thr_offset].write_ptr_lock);
            memcpy((void *) (g_bulk_stat[b_thr_offset].cmd_buff_ptr + offset*8), &ipc_cmnd, 4);
            //polling thread polls the command buffer unless g_bulk_stat[b_thr_offset].status is zero
            memset(&g_bulk_stat[b_thr_offset].status, 0, 4);
            //to stop the bulk IPC, ipc_command=0xffffffff is sent and this IPC command returns the event on BULKIPC start's job ID
            op = sec_get_scoreboard_slot(g_bulk_stat[b_thr_offset].start_job_id,
                                 io_sizes.opl_size,
                                 io_sizes.osh_size,
                                 opl,
                                 osh_pl);
            VERIFY(op != NULL, exit, rc, IPC_RET_ERROR);
            ores = os_event_hardwait(&(op->event_done), g_sec_max_ipc_wait);
            switch (ores)
            {
                case OSAL_SUCCESS:
                    rc = (sec_ipc_return_t) op->ipc_rc;
                break;
                case OSAL_TIMEOUT:
                    rc = IPC_RET_WAIT_TIMEOUT;
                    printk(KERN_WARNING  "sec_kernel_ipc: SEC timed out waiting on FW IPC command= %lu (subcmd=%lu) to complete.\n",
                     (unsigned long)ipc_cmnd, (unsigned long)sub_cmd.sc );
                    //Read the SEC HW/FW IPC Output Status
                    outstatus = sec_hal_devh_ReadReg32(&sec_hal_handle,
                                       SEC_HAL_IPC_HOST_INT_STATUS);
                    printk(KERN_INFO
                     "sec_kernel_ipc: SEC HW/FW IPC Output status at timeout = 0x%08x\n",
                     outstatus);

                    //Read the SEC HW/FW IPC Output Doorbell
                    outdoorbell = sec_hal_devh_ReadReg32(&sec_hal_handle,
                                         SEC_HAL_IPC_OUTPUT_DOORBELL);
                    printk(KERN_INFO
                     "sec_kernel_ipc: SEC HW/FW IPC Output Doorbell at timeout = 0x%08x\n",
                     outdoorbell);
                break;
                default:
                    rc = IPC_RET_ERROR;
                break;
            }

            // Free scoreboard slot and SEC resources
            sec_release_scoreboard_slot(op);
            //once the bulk mode is stopped, writer thread sends the ipc command complete signal to polling thread. 
            //but now g_bulk_stat[b_thr_offset].status is zero and polling thread comes out of polling and exit
            complete(&g_bulk_stat[b_thr_offset].host_compl_signal);
            //added a signal to make sure that bulk_poll thread exit before bulk_ipc_stop exits
            wait_for_completion(&g_bulk_stat[b_thr_offset].fw_compl_signal);
            INIT_COMPLETION(g_bulk_stat[b_thr_offset].fw_compl_signal);
            memset(&g_bulk_stat[b_thr_offset],0,(30*sizeof(uint8_t)));
            return rc;
        }
    }//end of bulkmode


    if (ish_pl != NULL)
    {
        rc = sec_request_shram_access();
        if( IPC_RET_FAILED(rc) ) goto exit;
    }

    // Process_id for this sub-command is set in
    // Wait for SEC to complete processing current request
    rc = wait_for_input_ready();
    if( IPC_RET_OK(rc) )
    {
        // sec_kernel_process_aacs_op()
        if ( ( ipc_cmnd != IPC_54 &&
               ( ipc_cmnd != IPC_EXTERNAL_MODULE_CMD ||
                 (ipl->external_module_ipc.module_id & SEC_IPC_54_MODULE_ID_MASK) !=
                 SEC_IPC_54_MODULE_ID ) )
        ||  sub_cmd.sc_54 != IPC_SC_54_12 )
        {
            ipl->data[0] = sec_get_job_id();
            if(ipc_cmnd == IPC_60)
            {
                down(&bulk_ipc_lock);
                //we need to store the bulk_ipc(IPC_60) job id, 
                //because when bulk stop command is issued, event from FW is retrieved on the same job ID.
                g_bulk_stat[g_bulk_counter].start_job_id=ipl->data[0];
                up(&bulk_ipc_lock);
            }
        }
        op = sec_get_scoreboard_slot(ipl->data[0],
                                 io_sizes.opl_size,
                                 io_sizes.osh_size,
                                 opl,
                                 osh_pl);
        VERIFY(op != NULL, exit, rc, IPC_RET_ERROR);

        SEC_DEBUG( "IPC command 0x%08lx:0x%08lx:\n", (unsigned long)ipc_cmnd, (unsigned long)sub_cmd.sc );
        print_data("input_payload",ipl->data,sizeof(ipl->data)/sizeof(ipl->data[0]));

        spin_lock(&sec_hw_unit_lock);
        sec_hal_ipc_call(&sec_hal_handle,
                         (uint32_t)ipc_cmnd,
                         ipl->data,
                         (uint32_t)io_sizes.ipl_size,
                         (ish_pl == 0) ? 0 : ish_pl->data,
                         (uint32_t)io_sizes.ish_size);
        spin_unlock(&sec_hw_unit_lock);

        if (ish_pl) {
            memset((void*)ish_pl, 0, sizeof(ipc_shmem_t));
        }

        //Wait a maximum time on IPC command to finish
        if(ipc_cmnd == IPC_60)
            goto release_score;
        ores = os_event_hardwait(&(op->event_done), g_sec_max_ipc_wait);
        switch (ores)
        {
            case OSAL_SUCCESS:
                rc = (sec_ipc_return_t) op->ipc_rc;
                break;
            case OSAL_TIMEOUT:
                rc = IPC_RET_WAIT_TIMEOUT;
                printk(KERN_WARNING
                    "sec_kernel_ipc: SEC timed out waiting on FW IPC command= %lu (subcmd=%lu) to complete.\n",
                    (unsigned long)ipc_cmnd, (unsigned long)sub_cmd.sc );
                //Read the SEC HW/FW IPC Output Status
                outstatus = sec_hal_devh_ReadReg32(&sec_hal_handle,
                                       SEC_HAL_IPC_HOST_INT_STATUS);
                printk(KERN_INFO
                    "sec_kernel_ipc: SEC HW/FW IPC Output status at timeout = 0x%08x\n",
                    outstatus);

                //Read the SEC HW/FW IPC Output Doorbell
                outdoorbell = sec_hal_devh_ReadReg32(&sec_hal_handle,
                                         SEC_HAL_IPC_OUTPUT_DOORBELL);
                printk(KERN_INFO
                    "sec_kernel_ipc: SEC HW/FW IPC Output Doorbell at timeout = 0x%08x\n",
                    outdoorbell);
                break;
            default:
                rc = IPC_RET_ERROR;
                break;
        }

release_score:
        // Free scoreboard slot and SEC resources
        sec_release_scoreboard_slot(op);
        if ( opl )
        {
            print_data("output_payload",(uint32_t *)opl,sizeof(*opl)/sizeof(uint32_t));
        }
    }

exit:
    return rc;
}


//-----------------------------------------------------------------------------
// add_dma_desc
//
// Create and add a DMA descriptor to the end of a linked list
//
// Parameters:
//  head    Pointer to pointer to head of list.
//  tail    Pointer to pointer to tail of list.
//  size    Number of bytes in transfer.
//  src     Physical address of source of transfer.
//  dst     Physical address of destination of transfer.
//  flags   DMA flags to be used in operation.
//-----------------------------------------------------------------------------
sec_result_t add_dma_desc(  sec_dma_descriptor_t ** head,
                            sec_dma_descriptor_t ** tail,
                            uint32_t                size,
                            uint32_t                src,
                            uint32_t                dst,
                            uint32_t                flags)
{
    sec_result_t            rc = SEC_SUCCESS;
    sec_dma_descriptor_t *  desc;

    desc = (sec_dma_descriptor_t *) OS_ALLOC(sizeof(sec_dma_descriptor_t));
    VERIFY( desc != NULL, exit, rc, SEC_OUT_OF_MEMORY);

    desc->next        = 0;
    desc->size        = size;
    desc->src         = src;
    desc->dst         = dst;
    desc->dma_flags   = flags;

    if (*head == NULL)
    {
        // This is first descriptor on list
        *head = desc;
    }
    else
    {
        // Add to end of descriptor list
        (*tail)->next = OS_VIRT_TO_PHYS(desc);
    }
    *tail = desc;
exit:
    return rc;
}


//-----------------------------------------------------------------------------
// dump_dma_list
//
// Debuggging routine to dump contains of a DMA descriptor list.
//-----------------------------------------------------------------------------
void dump_dma_list(sec_dma_descriptor_t *list)
{
    int i;

    for (i=0; list; i++)
    {
        SEC_DEBUG("DMA descriptor[%d]=0x%08lx\n", i, (unsigned long int)OS_VIRT_TO_PHYS(list));
        SEC_DEBUG(". next       = 0x%08x\n", list->next);
        SEC_DEBUG(". size       = 0x%08x\n", list->size);
        SEC_DEBUG(". src        = 0x%08x\n", list->src);
        SEC_DEBUG(". dst        = 0x%08x\n", list->dst);
        SEC_DEBUG(". dma_flags  = 0x%08x\n", list->dma_flags);

        list = list->next ? phys_to_virt(list->next) : 0;
    }
}


//-----------------------------------------------------------------------------
// sec_kernel_user_buf_unlock
//
// De-initialize a user_buf_t structure by unlocking the pages it represents
// and freeing the pointer array allocated for them.
//
// Parameters:
//  buf        Structure to be de-initialized
//-----------------------------------------------------------------------------
void sec_kernel_user_buf_unlock( user_buf_t *buf )
{
    int i;

    if (buf && buf->pages)
    {
        for(i = 0; i < buf->num_pages; i++)
        {
            if(buf->pages[i] != NULL) page_cache_release(buf->pages[i]);
        }
        OS_FREE(buf->pages);
    }
}


//-----------------------------------------------------------------------------
// sec_kernel_user_buf_lock
//
// Initialize a user-space (virtual memory) buffer descriptor:
// - lock the pages associated with the buffer into memory,
//   and get pointers to them back from the kernel.
// - initialize the descriptor's pointers and counters
//   to represent the beginning of the buffer.
//
// Parameters:
//  buf        Structure to be initialized
//  vaddr      User-space (virtual memory) address of buffer via IPC arg
//  size       Length of buffer, in bytes via IPC arg
//  write      1 => buffer is writable, 0=> buffer is read-only
//-----------------------------------------------------------------------------
sec_result_t sec_kernel_user_buf_lock( user_buf_t  *buf,
                                    sec_address_t   vaddr,
                                         uint32_t   size,
                                              int   write)
{
    int             n,i;
    uint32_t        start;
    uint32_t        end;
    void           *pbuf;
    sec_result_t    rc = SEC_SUCCESS;

    // Check passed parameters
    VERIFY(buf != NULL, exit, rc, SEC_NULL_POINTER);
    VERIFY(vaddr != 0, exit, rc, SEC_NULL_POINTER);
    VERIFY(size != 0, exit, rc, SEC_INVALID_INPUT);

    // Calculate the total number of pages spanned by the buffer.
    end             = ((uint32_t)vaddr + size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    start           = vaddr >> PAGE_SHIFT;
    buf->num_pages  = end-start;

    // Allocate an array of pointers to page structures for them.
    buf->pages= (struct page**) OS_ALLOC(sizeof(struct page*) * buf->num_pages);
    memset(buf->pages, 0, sizeof(struct page*) * buf->num_pages);
    VERIFY(buf->pages != NULL, exit, rc, SEC_OUT_OF_MEMORY);

    // Perform system call to retrieve the page structures
    // and lock the pages into memory.
    down_read( &current->mm->mmap_sem );
    n = get_user_pages( current,
                        current->mm,
                        vaddr & PAGE_MASK,  // page-aligned address
                        buf->num_pages,
                        write,
                        0,
                        buf->pages,
                        NULL);
    up_read( &current->mm->mmap_sem );

    // Check if get_user_pages returned a system error
    if(n < 0)
    {
        rc = SEC_FAIL;
        goto exit;
    }


    if (n < buf->num_pages)
    {
        rc = SEC_FAIL;
        SEC_ERROR("get_user_pages() returned fewer pages(%d) than expected(%d)\n",
                  n, buf->num_pages);
        sec_kernel_user_buf_unlock(buf);
        goto exit;
    }

    // Initialize remaining fields of user_buf_t structure,
    // to point to beginning of buffer.
    buf->vaddr       = vaddr;       // VM address of buffer
    buf->size        = size;        // Byte length of buffer
    buf->page_index  = 0;           // Start on first page
    buf->offset      = buf->vaddr % PAGE_SIZE;
                                    // Offset into page of start of buffer
    buf->page_bytes  = PAGE_SIZE - buf->offset;
                                    // Number of bytes of buffer remaining
                                    // on first page.
    buf->page_addr   = page_to_phys(buf->pages[0]);
                                    // Physical address of first page
    if(g_fast_path)
    {
        for(i=0; i<n; i++)
        {
            //pbuf = phys_to_virt(page_to_phys(buf->pages[i]));
            pbuf = kmap(buf->pages[i]);
            if (pbuf)
            {
                cache_flush_buffer(pbuf, PAGE_SIZE);
            }
            kunmap(buf->pages[i]);
        }
    }

exit:
    return rc;
}


//-----------------------------------------------------------------------------
// user_buf_advance
//
// Advance pointers and counters in a user-space buffer descriptor.
//
// Parameters:
//  buf     Pointer to a user-space buffer descriptor.
//  n       Number of bytes by which to advance.  MUST BE <= NUMBER OF BYTES
//              REMAINING ON CURRENT PAGE. If equal to the number of remaining
//              bytes, the buffer position will be modified to the beginning of
//              the next page.
//-----------------------------------------------------------------------------
sec_result_t user_buf_advance( user_buf_t *buf, unsigned long n )
{
    sec_result_t  rc = SEC_SUCCESS;

    if (n > buf->page_bytes)
    {
        rc = SEC_FAIL;
        SEC_ERROR("user_buf_advance(): advance would cross page boundary\n");
        goto exit;
    }

    buf->offset      += n;
    buf->page_bytes  -= n;
    buf->size        -= n;

    if (buf->page_bytes == 0)
    {
        // Reached end of page -- advance to next one
        buf->page_index++;
        buf->page_addr   = page_to_phys(buf->pages[buf->page_index]);
        buf->offset      = 0;
        buf->page_bytes  = PWU_MIN(buf->size, PAGE_SIZE);
    }
exit:
    return rc;
}


//-----------------------------------------------------------------------------
// map_vm_for_dma_r
//
// Create a linked list of SEC DMA descriptors for a buffer in user space
// (allocated in virtual memory).  The descriptors must use physical addresses;
// since the physical pages associated with the virtual memory may not be
// contiguous, no descriptor can specify a transfer that will cross a page
// boundary.
//
// This version of the function assumes there will be only one (source) buffer
// for the crypto operation, such as a hash or signing operation.  All
// descriptors in the list will be for read operations.
//
// Because SEC will only be sucking on a FIFO it will not need to buffer data,
// and there is no limit (other than the page boundary restriction) to the size
// of the transfer.
//
// Parameters:
//  src             User-space source buffer description.
//  block_size      Cipher block size.
//  dst_rx_reg      FIFO register to be used as destination.
//
// Return value:    Pointer to DMA descriptor list (NULL on failure).
//-----------------------------------------------------------------------------
static
sec_dma_descriptor_t * map_vm_for_dma_r(user_buf_t *    src,
                                        int             block_size,
                                        unsigned long   dst_rx_reg,
                                        sec_fw_subcmd_t ipc_sub_cmd)
{
    sec_result_t            rc;
    sec_dma_descriptor_t *  head = NULL;    // Head of descriptor linked list
    sec_dma_descriptor_t *  tail = NULL;    // Tail of descriptor linked list
    unsigned long           xfer_size;
    uint32_t                flags, final_flag;

    flags = SEC_DMA_READ_FLAGS
          | SEC_DMA_FLAG_DST_MODE_FIX_CONT
          | SEC_DMA_FLAG_SRC_LL;

    final_flag = SEC_DMA_FLAG_TERM;

    if (ipc_sub_cmd.sc_54 == IPC_SC_54_20)
    {
        final_flag |= SEC_DMA_FLAG_SRC_INT;
    }

    // Each iteration of this loop will generate the DMA descriptors for one
    // physical page of the buffer.
    while (src->size > 0)
    {
        // Make sure next descriptor doesn't cross page boundary
        xfer_size = PWU_MIN(src->page_bytes, src->size);

        // Add DMA descriptor to list
        rc = add_dma_desc(  &head,
                            &tail,
                            xfer_size,
                            src->page_addr + src->offset,
                            dst_rx_reg,
                            flags
                            );

        VERIFY_QUICK(rc == SEC_SUCCESS, fail);
        rc = user_buf_advance( src, xfer_size );
        VERIFY_QUICK(rc == SEC_SUCCESS, fail);
    }

    if (head != NULL)
    {
        tail->dma_flags |= final_flag;
        dump_dma_list(head);
        return head;
    }

fail:
    if (head)
    {
        sec_kernel_free_descriptor_list(head);
    }
    return NULL;
}


//-----------------------------------------------------------------------------
// sec_kernel_map_vm_for_dma_rw
//
// Create a linked list of SEC DMA descriptors for two buffers in user space
// (allocated in virtual memory).  The descriptors must use physical addresses;
// since the physical pages associated with the virtual memory may not be
// contiguous, no descriptor can specify a transfer that will cross a page
// boundary.
//
// This version of the function assumes there will be source and destination
// buffers as in encryption/decryption operations.
//
// Because only full blocks can be operated on by the encryption/decryption
// ciphers, SEC must buffer input and output data internally.
//
// On store-and-forward transfers of multiple blocks (total size an even
// multiple of the block size), SEC can regulate the buffering itself.
//
// When a block spans a page boundary (in either the source or the destination
// buffer) it must be transferred with multiple read operations followed by
// multiple write operations.  In these cases only a single block is transferred
// (before resuming store-and-forward) to be sure SEC buffers don't overflow.
//
// Parameters:
//  src             User-space source buffer description.
//  dst             User-space destination buffer description.
//  block_size      Cipher block size.
//  src_rx_reg      Source FIFO register for WRITE-only DMA descriptors.
//  dst_rx_reg      Dest FIFO register for READ-only DMA descriptors.
//
// Return value:    Pointer to DMA descriptor list (NULL on failure).
//-----------------------------------------------------------------------------
sec_dma_descriptor_t * sec_kernel_map_vm_for_dma_rw(   user_buf_t *    src,
                                            user_buf_t *    dst,
                                            int             block_size,
                                            unsigned long   src_rx_reg,
                                            unsigned long   dst_rx_reg,
                                            sec_fw_cmd_t    fw_cmd)
{
    sec_result_t            rc;
    sec_dma_descriptor_t *  head = NULL;    // Head of descriptor linked list
    sec_dma_descriptor_t *  tail = NULL;    // Tail of descriptor linked list
    unsigned long           xfer_size;
    unsigned long           partial_block_size;
    uint32_t                dma_stf_flags;

    if (fw_cmd == IPC_ARC4_ENCRYPT_DECRYPT_DATA)
    {
        dma_stf_flags = SEC_DMA_STF_FLAGS_ARC4
                        | SEC_DMA_FLAG_DST_LL
                        | SEC_DMA_FLAG_SRC_LL;
    }
    else
    {
        dma_stf_flags = SEC_DMA_STF_FLAGS
                        | SEC_DMA_FLAG_DST_LL
                        | SEC_DMA_FLAG_SRC_LL;
    }


    // Each iteration of this loop will generate the DMA descriptors for one
    // physical page of the buffer. If the page ends with a partial block,
    // descriptors will be generated for both that partial block and for the
    // for the other half of the block in the next page.
    while (src->size > 0)
    {
        // Make sure next descriptor doesn't cross page boundary in either
        // the source buffer or the destination buffer.
        xfer_size = PWU_MIN(src->page_bytes, dst->page_bytes);
        xfer_size = PWU_MIN(xfer_size, src->size);

        // If this is a command that supports partial blocks (AES-CBC-CTS), and
        // the residual block is still on the same page, send as a
        // store-and-forward.
        if ((fw_cmd == IPC_AES_DECRYPT_DATA || fw_cmd == IPC_AES_ENCRYPT_DATA)
             && src->page_bytes >= src->size
             && dst->page_bytes >= src->size
             && src->size >= block_size)
            partial_block_size = 0;
        else
            partial_block_size = xfer_size % block_size;

        // If there are one or more full blocks in both source and dest pages,
        // set up descriptor for as many full blocks as possible.
        if (xfer_size >= block_size)
        {
            // Round down to block multiple, transfer partial block later.
            // (No-op if partial_block_size == 0)
            xfer_size -= partial_block_size;

            // Add STORE-AND-FORWARD DMA descriptor to list
            rc = add_dma_desc(  &head,
                                &tail,
                                xfer_size,
                                src->page_addr + src->offset,
                                dst->page_addr + dst->offset,
                                dma_stf_flags);
            VERIFY_QUICK(rc == SEC_SUCCESS, fail);
            rc = user_buf_advance( src, xfer_size );
            VERIFY_QUICK(rc == SEC_SUCCESS, fail);
            rc = user_buf_advance( dst, xfer_size );
            VERIFY_QUICK(rc == SEC_SUCCESS, fail);
        }

        // Set up READ and WRITE descriptors for block that is split across
        // pages in one or both buffers.
        if (partial_block_size != 0)
        {
            unsigned long remaining;  // # of bytes left in block

            if (head == NULL)
            {
                // First block must be in store-and-forward mode. Partial
                // block can't be in STF mode.  If first block is partial
                // block, set up dummy STF DMA descriptor (length 0).
                rc = add_dma_desc(  &head,
                                    &tail,
                                    0,
                                    0,
                                    0,
                                    dma_stf_flags
                                    );
                VERIFY_QUICK(rc == SEC_SUCCESS, fail);
            }

            // Add multiple READ descriptors (if necessary) for next block
            for (remaining = PWU_MIN(src->size, block_size); remaining > 0;
                 remaining -= xfer_size)
            {
                xfer_size = PWU_MIN(src->page_bytes, remaining);

                rc = add_dma_desc(  &head,
                                    &tail,
                                    xfer_size,
                                    src->page_addr + src->offset,
                                    dst_rx_reg,
                                    SEC_DMA_READ_FLAGS
                                        | SEC_DMA_FLAG_SRC_LL
                                        | SEC_DMA_FLAG_DST_LL
                                        | SEC_DMA_FLAG_DST_MODE_FIX);
                VERIFY_QUICK(rc == SEC_SUCCESS, fail);
                rc = user_buf_advance( src, xfer_size );
                VERIFY_QUICK(rc == SEC_SUCCESS, fail);
            }

            // Add multiple WRITE descriptors (if necessary) for next block
            for (remaining = PWU_MIN(dst->size, block_size); remaining > 0;
                 remaining -= xfer_size)
            {
                xfer_size = PWU_MIN(dst->page_bytes, remaining);

                rc = add_dma_desc(  &head,
                                    &tail,
                                    xfer_size,
                                    src_rx_reg,
                                    dst->page_addr + dst->offset,
                                    SEC_DMA_WRITE_FLAGS
                                        | SEC_DMA_FLAG_SRC_LL
                                        | SEC_DMA_FLAG_DST_LL);

                VERIFY_QUICK(rc == SEC_SUCCESS, fail);
                rc = user_buf_advance( dst, xfer_size );
                VERIFY_QUICK(rc == SEC_SUCCESS, fail);
            }
        }
    }

    if (head != NULL)
    {
        tail->dma_flags |= SEC_DMA_FLAG_TERM |  SEC_DMA_FLAG_DST_INT;
        dump_dma_list(head);
        return head;
    }

fail:
    if (head)
    {
        sec_kernel_free_descriptor_list(head);
    }
    return NULL;
}


//-----------------------------------------------------------------------------
// sec_kernel_copy_to_user
//
// Function to copy output payload from kernel space at "opl" to user space
// at arg->opl and shared payload from kernel space at "osh_pl" to user
// space at arg->osh_pl. Thus this function is counting on the user space
// pointers to be preserved.
//-----------------------------------------------------------------------------
int sec_kernel_copy_to_user(sec_kernel_ipc_t *arg,
                            opl_t            *opl,
                            ipc_shmem_t      *osh_pl)
{
    int status = 0;

    VERIFY(arg != NULL, exit, status, -1);
    if( (arg->opl && opl) && (arg->io_sizes.opl_size > 0) )
    {
        status = copy_to_user(arg->opl, opl, arg->io_sizes.opl_size);
        if (status)
        {
            SEC_ERROR("Couldn't copy output payload to user-space");
            return status;
        }
    }

    if( (arg->osh_pl && osh_pl) && (arg->io_sizes.osh_size > 0) )
    {
        status = copy_to_user(arg->osh_pl, osh_pl, arg->io_sizes.osh_size);
        if (status)
        {
            SEC_ERROR("Couldn't copy shared output payload to user-space");
            return status;
        }
    }

exit:
    return status;
}


//----------------------------------------------------------------------------
// sec_kernel_free_sysmem
//
// Frees memory previously allocated for the SEC HW/FW
//----------------------------------------------------------------------------
sec_result_t sec_kernel_free_sysmem(bool is_rom_mem)
{
    sec_result_t     rc = SEC_SUCCESS;
    sec_contig_mem_t* mem_ptr = NULL;
    

    if(is_rom_mem)
    {
        mem_ptr = &gregsysmem_rom;
    }
    else
    {
        mem_ptr = &gregsysmem_pager;
    }
    

    // If the device doesn't use sysmem, or nothing was allocated, skip this
    if ((gchip_info.host_device != PCI_DEVICE_CE4200 && 
            is_rom_mem) || mem_ptr->kernel_vaddr == NULL )
    {
        goto exit;
    }

#ifdef DEBUG_REG_SYS_MEM
    printk(KERN_INFO "%s: virtual  memory address =0x%p\n", __func__,
            mem_ptr->kernel_vaddr);
    printk(KERN_INFO "%s: physical memory address =0x%08x\n", __func__,
            mem_ptr->paddr);
    printk(KERN_INFO "%s: physical memory size =%d bytes\n", __func__,
            (int)mem_ptr->size);
#endif
    if(g_fast_path || enable_tdp >0)
    {
        set_pages_wb(virt_to_page((unsigned long)mem_ptr->kernel_vaddr), (mem_ptr->size >>PAGE_SHIFT));
        free_pages((unsigned long)mem_ptr->kernel_vaddr, get_order(mem_ptr->size));
    }
    else
    {
        OS_FREE(mem_ptr->kernel_vaddr);
    }
    mem_ptr->paddr = 0;
    mem_ptr->user_vaddr = NULL;
    mem_ptr->size = 0;
/*
    rc = tracker_remove_mem((unsigned int)(current->tgid), mem_ptr);
    if (rc == SEC_FAIL)
    {
        rc = tracker_remove_mem_from_client_list(mem_ptr);
    }
*/

exit:
    return rc;
} //ENDPROC sec_kernel_free_sysmem


//----------------------------------------------------------------------------
// sec_kernel_alloc_sysmem
//
// Allocate Linux managed system memory for the SEC HW/FW
//----------------------------------------------------------------------------
sec_result_t sec_kernel_alloc_sysmem (bool is_rom_memory)
{
    void             * buffer = NULL;
    sec_result_t       rc = SEC_SUCCESS;
    int                order;
    sec_contig_mem_t * memptr = NULL;

    if(is_rom_memory)
    {
        //Verify if the memory is not allocated before
        VERIFY(gregsysmem_rom.size == 0, exit, rc, SEC_SUCCESS);
        memptr = &gregsysmem_rom;
        memptr->size = SEC_REG_SYS_MEM_SIZE;
    }
    else
    {
        //Verify if the memory is not allocated before
        VERIFY(gregsysmem_pager.size == 0, exit, rc, SEC_SUCCESS);
        memptr = &gregsysmem_pager;
        memptr->size = SEC_REG_SYS_MEM_PAGER_SIZE;
    }

    if(enable_tdp>0)
    {
        SEC_DEBUG("Inside TDP sec_kernel_alloc_sysmem\n");
        order = get_order(memptr->size);
        buffer= (void *)__get_free_pages(GFP_KERNEL, order);
        VERIFY(buffer != NULL, exit, rc , SEC_FAIL);
        set_pages_uc(virt_to_page((unsigned long)buffer), (1 << order));
    }
    else
    {
        SEC_DEBUG("Inside non-TDP sec_kernel_alloc_sysmem\n");
        buffer = OS_ALLOC(memptr->size);
        VERIFY(buffer != NULL, exit, rc , SEC_FAIL);
    }
    
    memptr->paddr        = (unsigned int)OS_VIRT_TO_PHYS(buffer);
    memptr->kernel_vaddr = buffer;
    memptr->user_vaddr   = 0x0;
    memptr->mmap_count   = 0;
    memptr->tgid = (unsigned int)(current->tgid);
    memptr->smpool = 0;

#ifdef DEBUG_REG_SYS_MEM
    printk(KERN_INFO "sec_kernel_alloc_sysmem: virtual  memory address =0x%p\n", memptr->kernel_vaddr);
    printk(KERN_INFO "sec_kernel_alloc_sysmem: physical memory address =0x%08x\n", memptr->paddr);
    printk(KERN_INFO "sec_kernel_alloc_sysmem: physical memory size =%d bytes\n", (int)memptr->size);
    printk(KERN_INFO "sec_kernel_alloc_sysmem: thread group ID =%d\n", (int)memptr->tgid);
    printk(KERN_INFO "sec_kernel_alloc_sysmem: small pool flag =%d\n", memptr->smpool);
#endif

/*
    rc = tracker_add_mem((unsigned int)(current->tgid), memptr);
    VERIFY_QUICK(rc == SEC_SUCCESS, exit);
*/
exit:

    return rc;
} //ENDPROC sec_kernel_alloc_sysmem


//----------------------------------------------------------------------------
// sec_kernel_reg_sysmem
//
// Calls the sec_kernel_alloc_sysmem funtion above and if successful it
// then sends the allocated memory physical address to the SEC HW/FW.
//----------------------------------------------------------------------------
sec_result_t sec_kernel_reg_sysmem(bool is_rom_memory)
{
    ipl_t ipl;
    opl_t opl;
    sec_ipc_sizes_t io_sizes;
    sec_result_t rc = SEC_SUCCESS;
    sec_ipc_return_t  ipc_ret = IPC_RET_COMMAND_COMPLETE;
    const sec_fw_subcmd_t  sub_cmd = {.sc = IPC_SC_NOT_USED};

    /* If this is kernel initialization and not a CE4200, we don't need 
       to register system mem to ROM*/
    if(is_rom_memory && gchip_info.host_device != PCI_DEVICE_CE4200)
    {
        rc = SEC_SUCCESS;
        goto exit;
    }

    rc = sec_kernel_alloc_sysmem(is_rom_memory); 
#ifdef DEBUG_REG_SYS_MEM
    printk(KERN_INFO "%s: sec_kernel_alloc_sysmem return=%d\n",
            __func__, (int)rc);
#endif

    if(rc != SEC_SUCCESS) return rc;

    ipl.data[0] = sec_get_job_id();
    ipl.data[1] = 0;
    ipl.data[2] = 0;
    if(is_rom_memory)
    {
        ipl.data[3] = gregsysmem_rom.paddr;
        ipl.data[4] = gregsysmem_rom.size;
    }
    else
    {
        ipl.data[3] = gregsysmem_pager.paddr;
        ipl.data[4] = gregsysmem_pager.size;
    }

#ifdef DEBUG_REG_SYS_MEM
    printk(KERN_INFO "%s: sending physical memory address =0x%08x to SEC HW\n",
           __func__, ipl.data[3]);
    printk(KERN_INFO "%s: sending physical memory %d byte size info to"
           " SEC HW\n", __func__, (int)ipl.data[4]);
#endif

    io_sizes.ipl_size = 20;
    io_sizes.ish_size = 0;
    io_sizes.opl_size = 4;
    io_sizes.osh_size = 0;

    ipc_ret = sec_kernel_ipc( IPC_REGISTER_SYSTEM_MEMORY, sub_cmd, io_sizes,
                              &ipl, &opl, NULL, NULL);
#ifdef DEBUG_REG_SYS_MEM
    printk(KERN_INFO "%s: FW IPC return code=0x%08x\n", __func__,
        (uint32_t)ipc_ret);
#endif
    //Translate an IPC return type to a sec driver return type.
    rc = ipc2sec(ipc_ret);

exit:
    return rc;
} //ENDPROC sec_kernel_reg_sysmem


//-----------------------------------------------------------------------------
// sec_disable_output_interrupt
//
// Masks HW interrupts, and un-registers the sec interrupt handler
//-----------------------------------------------------------------------------
void sec_disable_output_interrupt(void)
{
    // Disable interrupts from the HW and release our handler
    sec_hal_devh_WriteReg32(&sec_hal_handle,SEC_HAL_IPC_HOST_INT_MASK,0);
    sec_hal_release_irq(&sec_hal_handle);

    return;
}

//-----------------------------------------------------------------------------
// sec_kernel_exit
//
// Sec module exit routine. deintializes structures and deallocates required
// resources (memory).
//-----------------------------------------------------------------------------
static
void sec_kernel_exit (void)
{
    int i;

    SEC_DEBUG ("sec_kernel_module: exiting...\n");

    //destory pulling thread here os_thread_destory
    unregister_chrdev(dev_number, "sec");

    sec_unregister_pci_dev();
    sec_fw_exit_handler();
    if(g_fast_path)
    {
        sec_peri_fw_cleanup_list();
    }

    // Disable interrupts
    sec_disable_output_interrupt();

    // De-init HAL
    sec_hal_delete_handle(&sec_hal_handle);

    // Free the Linux system memory that was allocated
    // and registered for the SEC HW/FW.
    sec_kernel_free_sysmem(SEC_ROM_MEM); 
    sec_kernel_free_sysmem(SEC_FW_PAGER_MEM); 

    //de-initialize the device.
    for (i=0; i < SEC_MAX_OPERATION_COUNT; i++)
    {
        os_event_destroy(&(score_board.ops[i].event_done));
    }

    os_event_destroy(&ready_for_input);

    //free AACS resource
    sec_kernel_aacs_deinit();

    //free DTCPIP resource
    sec_kernel_dtcpip_deinit();

    tracker_deinit();
}

//-----------------------------------------------------------------------------
// sec_kernel_check_device
//
// This function checks the current state of the sec HW. If it is being held
// in reset, we attempt to bring it out of reset.
//-----------------------------------------------------------------------------
int sec_kernel_check_device(void)
{
    int                     rc = 0;
    clock_control_ret_t     ccret;
    uint32_t                SEC_Clock;

    /* Check that the SEC HW and FW is present if not return failure */
    ccret = clock_control_read(CLOCK_SEC_RST, &SEC_Clock, CLOCK_TRUE);
    if (ccret != CLOCK_RET_OK)
    {
        SEC_ERROR("clock_control_read reports error = %d for "
                  "CLOCK_SEC_RST %d\n",
                  (int)ccret, (int)CLOCK_SEC_RST);
        rc = -ENODEV;
        goto exit;
    }

    /* If SEC_Clock is 1 the SEC FW/HW are not being held in reset */
    if (SEC_Clock == 1)
    {
        SEC_DEBUG("CLOCK_SEC_RST reports a 1 so SEC FW/HW are not being held "
                "in reset\n");
        goto exit;
    }

    SEC_DEBUG("CLOCK_SEC_RST %d is being held in reset\n"
            "sec_kernel_check_device will try to bring it out of reset\n",
            (int)CLOCK_SEC_RST);

    /* Bring the unit out of reset (set it to 1) */
    ccret = clock_control_write(CLOCK_SEC_RST, 1, CLOCK_TRUE);
    if (ccret != CLOCK_RET_OK)
    {
        SEC_ERROR("clock_control_write won't allow writing to "
                  "CLOCK_SEC_RST=%d\n"
                  "clock_control_write returned error %d\n",
                  (int)ccret, (int)CLOCK_SEC_RST);
        rc = -ENODEV;
        goto exit;
    }
    SEC_DEBUG("Successfully wrote to the SEC CLOCK Reset bit\n");

    /* Read the bit to make sure it 'took' */
    ccret = clock_control_read(CLOCK_SEC_RST, &SEC_Clock, CLOCK_TRUE);
    if (ccret != CLOCK_RET_OK)
    {
        SEC_ERROR("\nSecond call to clock_control_read reports error=%d "
                  "for CLOCK_SEC_RST %d\n",
                  (int)ccret, (int)CLOCK_SEC_RST);
        rc = -ENODEV;
        goto exit;
    }
    if (SEC_Clock == 0)
    {
        SEC_ERROR("Could not bring SEC out of reset\n");
        rc = -ENODEV;
        goto exit;
    }

    /* If we got here everything succeeded */
    SEC_DEBUG("Successfully enabled SEC CLOCK\n");

exit:
    return rc;
}


//-----------------------------------------------------------------------------
// sec_enable_output_interrupt
//
// Enables the sec interrupt handler, and notifies the HW to begin sending
// interrupts.
//-----------------------------------------------------------------------------
sec_result_t sec_enable_output_interrupt(void)
{
    sec_result_t rc = SEC_SUCCESS;

    /* Register our interrupt handler */
    if (sec_hal_set_irq(&sec_hal_handle) != SEC_HAL_SUCCESS)
    {
        rc = SEC_FAIL;
        goto exit;
    }

    //Enable input ready and output interrupts
    sec_hal_devh_WriteReg32 (&sec_hal_handle, SEC_HAL_IPC_HOST_INT_MASK, 3);

    //clear any pending output interrupts
    sec_hal_devh_WriteReg32(&sec_hal_handle,SEC_HAL_IPC_HOST_INT_STATUS, 1);

    //Enable SEC to output payload for next cmd
    sec_hal_devh_WriteReg32 (&sec_hal_handle, SEC_HAL_IPC_OUTPUT_STATUS, 1);

exit:
    return rc;
}

/* Initializes a struct context_id_tracker */
static void context_id_tracker_init(struct context_id_tracker *t)
{
    int i;

    for (i = 0; i < SEC_NUM_CONTEXTS; i++)
        t->in_use[i] = false;
    spin_lock_init(&t->lock);
    sema_init(&t->sema, SEC_NUM_CONTEXTS);
}

//-----------------------------------------------------------------------------
// sec_kernel_init
//
// Sec module entry routine. registers driver, intializes structures and
// allocates required resources (memory)
//-----------------------------------------------------------------------------
static
int sec_kernel_init (void)
{
    int i  = 0;
    int rc = -1;
    sec_result_t eres=SEC_SUCCESS;

    // Get the Host PCI vendor, device, and revision ids.
    memset((void*)(&gchip_info), 0, sizeof(sec_chip_info_t));
    eres = sec_hal_get_iahost_chip_info(&gchip_info);
    if(eres != SEC_SUCCESS)
    {
        SEC_ERROR("Could not retrieve Host PCI IDs\n");
        return -1;
    }

    /* Check/Attempt to reactivate our device */
    if(gchip_info.host_device != PCI_DEVICE_CE2600)
    {
        if ((rc = sec_kernel_check_device()) != 0)
            return -1;
    }
    SEC_DEBUG ("sec_kernel_module: initializing...\n");

    // Get the SEC PCI vendor, device, and revision ids.
    eres = sec_hal_get_sec_chip_info(&gchip_info);
    if(eres != SEC_SUCCESS)
    {
        SEC_ERROR("Could not retrieve SEC core PCI IDs\n");
        return -1;
    }

    // Set the maximum wait time out for SEC HW/FW
    if((gchip_info.host_device == PCI_DEVICE_CE3100)
    || (gchip_info.host_device == PCI_DEVICE_CE4100))
    {
        g_sec_max_ipc_wait = SEC_MAX_FW_WAIT;
    }
    else
    {
        g_sec_max_ipc_wait = SEC_CE4200_MAX_FW_WAIT;
    }

    // Stash the PCI revision id for future use.
    SEC_revision = gchip_info.sec_revision;
#ifdef DEBUG_SEC_KERNEL_INIT
    printk(KERN_INFO "sec_kernel_init: SEC_revision=%d\n", (int)SEC_revision);
#endif
    // Use it to select correct vector table for version-dependent functions.
    switch( SEC_revision )
    {
    case SEC_PCI_REV_0:
    case SEC_PCI_REV_1:
    case SEC_PCI_REV_2:
    case SEC_PCI_REV_3:
    case SEC_PCI_REV_4:
    case SEC_PCI_REV_6:
    case SEC_PCI_REV_7:
    case SEC_PCI_REV_8:
    case SEC_PCI_REV_10:
    case SEC_PCI_REV_11:
        kfv = &rev0;
        break;
    default:
        SEC_ERROR("Unknown SEC core. PCI revision ID=%d\n",(int)SEC_revision);
        return -1;
    }

    //register sec device with the kernel
    dev_number = register_chrdev (0, "sec", &sec_fops);
    if (dev_number < 0)
    {
        SEC_ERROR("Registering the char dev failed (rc=%d)\n",dev_number);
        return -1;
    }

    SEC_DEBUG("Registering the character device with %d\n", dev_number);

    //semaphores to protect SEC resources
    for (i=0; i < SEC_RESOURCE_COUNT; i++)
    {
        sema_init(&score_board.res_semas [i], 1);
    }

    //create events for SEC operations
    for (i=0; i < SEC_MAX_OPERATION_COUNT; i++)
    {
        if (OSAL_SUCCESS != os_event_create(&(score_board.ops[i].event_done), 0))
        {
            SEC_ERROR("Failed to create event\n");
            goto cleanup;
        }
    }

    // Create a "manual event" for SEC to FW operations.  if the second
    // parameter is a zero then "auto event", which means the
    // ready_for_input->signaled is set back to false right after
    // it is set to true.  The wait_for_input_ready will take care of this.
    if (OSAL_SUCCESS != os_event_create(&ready_for_input, 0))
    {
        SEC_ERROR("Failed to create FW IPC ready event\n");
        goto cleanup;
    }

    spin_lock_init(&score_board.board_lock);
    spin_lock_init(&sec_hw_unit_lock);
    spin_lock_init(&fcm_kernel_context_lock);
    INIT_LIST_HEAD(&klist.khead);
    //initialize bulk mode specific data
    sema_init(&bulk_ipc_lock,1);
    for(i=0; i<(sizeof(g_bulk_stat)/sizeof(g_bulk_stat[0])); i++)
    {   
        memset(&g_bulk_stat[i], 0, sizeof(bulk_status));
        sema_init(&g_bulk_stat[i].write_ptr_lock,1);
    }   


    context_id_tracker_init(&context_trackers[SEC_MAC_CONTEXT]);
    context_id_tracker_init(&context_trackers[SEC_DH_CONTEXT]);
    context_id_tracker_init(&context_trackers[SEC_HASH_CONTEXT]);

    sema_init(&sec_api_semaphore, 1);
    sema_init(&jobid_semaphore, 1);
    sema_init(&sec_eau_sema, 1);

    // Initialize DMA Tracker
    dma_tracker_init();

    // Create SEC hal handle
    if(sec_hal_create_handle(&sec_hal_handle))
    {
        SEC_ERROR("Failed to initialize sec hal\n");
        return 1;
    }

    if (sec_enable_output_interrupt() != SEC_SUCCESS)
    {
        SEC_ERROR("Failed to initialize sec interrupts\n");
        rc = -1;
        goto cleanup;
    }

    // Initialize client tracker
    tracker_init();

    //initialize aacs structures and allocate required resource
    rc = sec_kernel_aacs_init();

    //initialize dtcpip structures and allocate required resource
    rc = sec_kernel_dtcpip_init();

    os_event_set(&ready_for_input);
  
    sec_get_pmr();

    eres = sec_kernel_reg_sysmem(SEC_ROM_MEM); 
    if(eres != SEC_SUCCESS)
    {
        SEC_ERROR("Could not allocate and register Linux system memory for "
                  "the SEC HW\n");
        rc = -1;
        goto cleanup;
    }

    /* Initialize the FW module list for pre-loaded modules */
    SEC_RESULT_TRY(sec_fw_init_handler(), cleanup);

    /* Setup the PCI device for firmware re-loading and power management */
    SEC_RESULT_TRY(sec_register_pci_dev(), cleanup);

    rc = 0;
    if(gchip_info.host_device == PCI_DEVICE_CE4100 ||(gchip_info.host_device == PCI_DEVICE_CE4200) ||(gchip_info.host_device == PCI_DEVICE_CE5300))
    {
        if(enable_tdp >0)
        {
            SEC_RESULT_TRY(sec_tdp_configuration(), cleanup);
            g_fast_path=1;
        }
    }

cleanup:
    if (rc != 0)
    {
        if (rc > 0)
            rc = -1;
        sec_kernel_exit();
    }
    return rc;
} /* ENDPROC sec_kernel_init */

//-----------------------------------------------------------------------------
// crypt_dma_op_prepare
//
// Encrypt/decrypt using DMA to transfer data to/from firmware
//-----------------------------------------------------------------------------
static
sec_result_t crypt_dma_op_prepare( sec_kernel_ipc_t *  ipc_arg,
                                   ipl_t *             ipl,
                                   uint32_t *          block_size,
                                   uint32_t *          TX,
                                   uint32_t *          RX,
                                   dma_info_t **       dma_info )
{
    sec_result_t           rc = SEC_SUCCESS;

    switch (ipc_arg->cmd)
    {
    case IPC_C2_ENCRYPT_DATA:
    case IPC_C2_DECRYPT_DATA:
        *block_size = C2_BLOCK_SIZE;
        *TX         = SEC_C2_TX_FIFO;
        *RX         = SEC_C2_RX_FIFO;
        *dma_info   = &ipl->c2_crypt.dma_info;
        break;
    case IPC_AES_ENCRYPT_DATA:
    case IPC_AES_DECRYPT_DATA:
        *block_size = AES_BLOCK_SIZE;
        *TX         = SEC_AES_TX_FIFO;
        *RX         = SEC_AES_RX_FIFO;
        *dma_info   = &ipl->aes_crypt.dma_info;
        break;
    case IPC_AES128_ENCRYPT_DECRYPT_DATA:
        /* Because this is part of the CSS block, use the CSS FIFOs.
         * AES block size and DMA info remain the same */
        *block_size = AES_BLOCK_SIZE;
        *TX         = SEC_CSS_TX_FIFO;
        *RX         = SEC_CSS_RX_FIFO;
        *dma_info   = &ipl->aes_crypt.dma_info;
        break;
    case IPC_CSS_DECRYPT_DATA:
        *block_size = CSS_BLOCK_SIZE;
        *TX         = SEC_CSS_TX_FIFO;
        *RX         = SEC_CSS_RX_FIFO;
        *dma_info   = &ipl->css_crypt.dma_info;
        break;
    case IPC_DES_ENCRYPT_DATA:
    case IPC_DES_DECRYPT_DATA:
        *block_size = DES_BLOCK_SIZE;
        *TX         = SEC_DES_TX_FIFO;
        *RX         = SEC_DES_RX_FIFO;
        *dma_info   = &ipl->des_crypt.dma_info;
        break;
    case IPC_ARC4_ENCRYPT_DECRYPT_DATA:
        *block_size = ARC4_BLOCK_SIZE;
        *TX         = SEC_C2_TX_FIFO;
        *RX         = SEC_C2_RX_FIFO;
        *dma_info   = &ipl->arc4_crypt.dma_info;
        break;
    case IPC_EXTERNAL_MODULE_CMD:
        if(((ipc_arg->module_id & SEC_IPC_MODULE_ID_MASK) == SEC_IPC_CIPLUS_MODULE_ID) &&
                (ipc_arg->sub_cmd.sc == IPC_SC_2  || ipc_arg->sub_cmd.sc == IPC_SC_3))
        {
            *block_size     = AES_BLOCK_SIZE;
            *TX             = (uint32_t)NULL;
            *RX             = (uint32_t)NULL;
        }
        break;
    default:
        rc = SEC_FAIL;
        break;
    }

    return rc;
}


// -------------------------------------------------------------------
//          printVector
// -------------------------------------------------------------------

void printVector (uint8_t * vector, int size)
{
  int i;
  printk ("-----------------------------------------\n");
  for (i=0; i<size; i++)
  {
    printk (" 0x%02x", vector[i]);
    if (i%8 == 7)
    {
      printk ("\n");
    }
  }
  printk ("\n");
  printk ("-----------------------------------------\n");
}

sec_result_t external_mod_ipc_dma_setup(sec_kernel_ipc_t     *ipc_arg,
                                        ipl_t *               ipl,
                                        user_buf_t           *src,
                                        user_buf_t           *dst,
                                        sec_dma_descriptor_t **phys_src_desc)
{
    sec_result_t           rc = SEC_FAIL;
    sec_dma_descriptor_t * list = NULL;
    uint32_t               block_size;
    uint32_t               TX;
    uint32_t               RX;

    VERIFY(ipc_arg != NULL, exit, rc, SEC_FAIL);
    VERIFY(ipl != NULL, exit, rc, SEC_FAIL);
    VERIFY(src != NULL, exit, rc, SEC_FAIL);
    VERIFY(dst != NULL, exit, rc, SEC_FAIL);
    VERIFY(phys_src_desc != NULL, exit, rc, SEC_FAIL);

    if(ipc_arg->cmd == IPC_EXTERNAL_MODULE_CMD)
    {
        uint32_t module_id = ipc_arg->module_id & SEC_IPC_MODULE_ID_MASK;
        SEC_TRACE( ":%d\n", __LINE__);
        switch(module_id)
        {
            case SEC_IPC_CIPLUS_MODULE_ID:
                if(ipc_arg->sub_cmd.sc == IPC_SC_2  || ipc_arg->sub_cmd.sc == IPC_SC_3)
                {
                    block_size     = AES_BLOCK_SIZE;
                    TX             = (uint32_t)NULL;
                    RX             = (uint32_t)NULL;
                }
                else
                {
                    SEC_ERROR("Should not be here - kernel.c:%d\n", __LINE__);
                    goto exit;
                }

                if ((((uint32_t)ipc_arg->src & 0x3) == 0)
                        &&  (((uint32_t)ipc_arg->dst & 0x3) == 0))
                {
                    rc = sec_kernel_user_buf_lock(src,
                                                  (sec_address_t) ipc_arg->src,
                                                  ipc_arg->src_size,
                                                  USER_BUF_RO);

                    VERIFY_QUICK(rc == SEC_SUCCESS, exit);

                    if(ipc_arg->sub_cmd.sc == IPC_SC_2)
                    {
                        //make a linked list of message for CIPlus Authenticate IPC
                        *phys_src_desc = map_vm_for_dma_r(src, block_size, RX ,ipc_arg->sub_cmd);
                    }
                    else
                    {
                        rc = sec_kernel_user_buf_lock(dst,
                                                      (sec_address_t) ipc_arg->dst,
                                                      ipc_arg->dst_size,
                                                      USER_BUF_RW);
                        if (rc != SEC_SUCCESS)
                        {
                            sec_kernel_user_buf_unlock(src);
                            goto exit;
                        }

                        // Create DMA descriptors to perform the operation.
                        *phys_src_desc = sec_kernel_map_vm_for_dma_rw(src, dst, block_size, TX, RX, ipc_arg->cmd);
                    }

                    if ((*phys_src_desc) != NULL)
                    {
                        ipl->data[3] = (uint32_t)OS_VIRT_TO_PHYS(*phys_src_desc);
                    }
                }
                break;

            case SEC_IPC_DTCPIP_MODULE_ID:
                SEC_TRACE( ":%d\n", __LINE__);
                if(ipc_arg->sub_cmd.sc_dtcpip == IPC_SC_DTCPIP_PROCESS_PKT)
                {
                    block_size     = AES_BLOCK_SIZE;
                    TX             = (uint32_t)NULL;
                    RX             = (uint32_t)NULL;
                }
                else
                {
                    SEC_ERROR("Should not be here - kernel.c:%d\n", __LINE__);
                    rc = SEC_FAIL;
                    goto exit;
                }

                if ((((uint32_t)ipc_arg->src & 0x3) == 0)
                        &&  (((uint32_t)ipc_arg->dst & 0x3) == 0))
                {
                    SEC_TRACE( ":%d\n", __LINE__);
                    rc = sec_kernel_user_buf_lock(src,
                                                  (sec_address_t) ipc_arg->src,
                                                  ipc_arg->src_size,
                                                  USER_BUF_RO);

                    VERIFY_QUICK(rc == SEC_SUCCESS, exit);
                    SEC_TRACE( ":%d\n", __LINE__);

                    rc = sec_kernel_user_buf_lock(dst,
                                                  (sec_address_t) ipc_arg->dst,
                                                  ipc_arg->dst_size,
                                                  USER_BUF_RW);
                    if (rc != SEC_SUCCESS)
                    {
                        sec_kernel_user_buf_unlock(src);
                        rc = SEC_FAIL;
                        goto exit;
                    }

                    // Create DMA descriptors to perform the operation.
                    *phys_src_desc = sec_kernel_map_vm_for_dma_rw(src, dst, block_size, TX, RX, ipc_arg->cmd);

                    if (*phys_src_desc != NULL)
                    {
                        SEC_TRACE( ":%d\n", __LINE__);
                        //printVector((uint8_t*)ipl, sizeof(ipl_t));
                        ipl->dtcpip_process_pkt.next_desc = (uint32_t)OS_VIRT_TO_PHYS(*phys_src_desc);
                        //printVector((uint8_t*)ipl, sizeof(ipl_t));
                    }
                }
                break;
            default:
                SEC_ERROR("Invalid module ID\n");
                rc = SEC_FAIL;
                goto exit;
        }

        if(g_fast_path)
        {
            SEC_TRACE( ":%d\n", __LINE__);
            list = *phys_src_desc;
            while(list!=NULL)
            {
                cache_flush_buffer((void*)list, sizeof(sec_dma_descriptor_t));
                list = list->next ? phys_to_virt(list->next) : NULL;
            }
        }
    }
    else
    {
        SEC_ERROR("To be used only with external module IPC\n");
    }

exit:
    return rc;
}

sec_result_t external_mod_ipc_dma_teardown(sec_kernel_ipc_t     *ipc_arg,
                                           user_buf_t           *src,
                                           user_buf_t           *dst,
                                           sec_dma_descriptor_t *phys_src_desc)
{
    sec_result_t rc = SEC_INVALID_INPUT;
    VERIFY(ipc_arg != NULL, exit, rc, SEC_FAIL);
    SEC_TRACE( ":%d\n", __LINE__);
    if(ipc_arg->cmd == IPC_EXTERNAL_MODULE_CMD)
    {
        uint32_t module_id = ipc_arg->module_id & SEC_IPC_MODULE_ID_MASK;

        SEC_TRACE( ":%d\n", __LINE__);
        VERIFY(phys_src_desc != NULL, exit, rc, SEC_FAIL);
        sec_kernel_free_descriptor_list(phys_src_desc);

        VERIFY(src != NULL, exit, rc, SEC_FAIL);
        sec_kernel_user_buf_unlock(src);

        VERIFY(dst != NULL, exit, rc, SEC_FAIL);
        switch(module_id)
        {
            SEC_TRACE( ":%d\n", __LINE__);
            case SEC_IPC_CIPLUS_MODULE_ID:
                if(ipc_arg->sub_cmd.sc == IPC_SC_2)
                {
                    sec_kernel_user_buf_unlock(dst);
                    rc = SEC_SUCCESS;
                }
                else
                {
                    SEC_ERROR("Invalid mode for sub command\n");
                    rc = SEC_INVALID_INPUT;
                }
                break;

            case SEC_IPC_DTCPIP_MODULE_ID:
                sec_kernel_user_buf_unlock(dst);
                rc = SEC_SUCCESS;
                break;
        }
    }
exit:
    return rc;
}

//-----------------------------------------------------------------------------
// crypt_dma_op
//
// Encrypt/decrypt using DMA to transfer data to/from firmware
//-----------------------------------------------------------------------------

static
sec_result_t crypt_dma_op(sec_kernel_ipc_t *  ipc_arg,
                          ipl_t *             ipl,
                          opl_t *             opl,
                          ipc_shmem_t *       ish_pl)
{
    sec_result_t           rc;
    sec_ipc_return_t       ipc_ret       = IPC_RET_COMMAND_COMPLETE;
    sec_dma_descriptor_t * phys_src_desc = NULL;
    sec_dma_descriptor_t * list = NULL;
    void *                 src_data      = NULL;
    void *                 dst_data      = NULL;
    uint32_t               block_size;
    uint32_t               TX;
    uint32_t               RX;
    dma_info_t           * dma_info;
    uint32_t               dma_stf_flag;
    unsigned long *        swapped_iv;
    int                    i;

    VERIFY(ipl != NULL, exit, rc, SEC_FAIL);

    rc = crypt_dma_op_prepare( ipc_arg, ipl, &block_size, &TX, &RX, &dma_info );
    if ( rc != SEC_SUCCESS )
    {
        goto exit;
    }

    // If both src and dst buffers are DWORD aligned, use direct I/O to
    // process the data.  Otherwise, use buffered I/O.
    if ((((uint32_t)ipc_arg->src & 0x3) == 0)
    &&  (((uint32_t)ipc_arg->dst & 0x3) == 0))
    {
        user_buf_t  src;
        user_buf_t  dst;

        rc = sec_kernel_user_buf_lock( &src,
                            (sec_address_t) ipc_arg->src,
                            ipc_arg->src_size,
                            USER_BUF_RO);
        VERIFY_QUICK(rc == SEC_SUCCESS, exit);

        if(
             (ipc_arg->cmd == IPC_EXTERNAL_MODULE_CMD) &&
             ((ipc_arg->module_id & SEC_IPC_MODULE_ID_MASK) == SEC_IPC_CIPLUS_MODULE_ID) &&
             (ipc_arg->sub_cmd.sc == IPC_SC_2)
          )
        //make a linked list of message for CIPlus Authenticate IPC
        {
            phys_src_desc = map_vm_for_dma_r(&src,block_size, RX ,ipc_arg->sub_cmd);
        }
        else
        {
            rc = sec_kernel_user_buf_lock( &dst,
                            (sec_address_t) ipc_arg->dst,
                            ipc_arg->dst_size,
                            USER_BUF_RW);
            if (rc != SEC_SUCCESS)
            {
                sec_kernel_user_buf_unlock( &src );
                goto exit;
            }

            // Create DMA descriptors to perform the operation.
            phys_src_desc = sec_kernel_map_vm_for_dma_rw(&src, &dst, block_size, TX, RX, ipc_arg->cmd);
        }

        if (phys_src_desc != NULL)
        {
            if(ipc_arg->cmd == IPC_EXTERNAL_MODULE_CMD)
            {
                uint32_t module_id = ipc_arg->module_id & SEC_IPC_MODULE_ID_MASK;
                switch(module_id)
                {
                    case SEC_IPC_CIPLUS_MODULE_ID:
                        if(ipc_arg->sub_cmd.sc == IPC_SC_2  || ipc_arg->sub_cmd.sc == IPC_SC_3)
                        {
                            ipl->data[3] = (uint32_t)OS_VIRT_TO_PHYS(phys_src_desc);
                        }
                    break;

                    case SEC_IPC_DTCPIP_MODULE_ID:
                        if(ipc_arg->sub_cmd.sc_dtcpip == IPC_SC_DTCPIP_PROCESS_PKT)
                        {
                            ipl->dtcpip_process_pkt.next_desc = (uint32_t)OS_VIRT_TO_PHYS(phys_src_desc);
                        }
                        else
                        {
                            SEC_ERROR("Should not be here - kernel.c:%d\n", __LINE__);
                        }
                    break;
                }
            }
            else
            {
                dma_info->dma_flags       = phys_src_desc->dma_flags;
                dma_info->next_descriptor = phys_src_desc->next;
                dma_info->src_start       = phys_src_desc->src;
                dma_info->dst_start       = phys_src_desc->dst;
                dma_info->src_size        = phys_src_desc->size;
                dma_info->dst_size        = phys_src_desc->size;
            }

            if(g_fast_path)
            {
                list=phys_src_desc;
                while(list!=NULL)
                {
                    cache_flush_buffer((void*)list, sizeof(sec_dma_descriptor_t));
                    list = list->next ? phys_to_virt(list->next) : NULL;
                }
            }

            ipc_ret = sec_kernel_ipc( ipc_arg->cmd,
                                      ipc_arg->sub_cmd,
                                      ipc_arg->io_sizes,
                                      ipl,
                                      opl,
                                      ish_pl,
                                      NULL);
            sec_kernel_free_descriptor_list(phys_src_desc);
        }

        sec_kernel_user_buf_unlock( &src );
        //Unlock dst if the command is not (CI+:Authenticate)
        if( !(
             (ipc_arg->cmd == IPC_EXTERNAL_MODULE_CMD) &&
             ((ipc_arg->module_id & SEC_IPC_MODULE_ID_MASK) == SEC_IPC_CIPLUS_MODULE_ID) &&
             (ipc_arg->sub_cmd.sc == IPC_SC_2)
          )  )
        //CIPlus Authenticate IPC does not lock dst 
        {
            sec_kernel_user_buf_unlock( &dst );
        }

        VERIFY(phys_src_desc != NULL, exit, rc, SEC_FAIL);
    }
    else
    {
        // The source and destination buffers are not both DWORD-aligned.
        // We need to copy each page of data to an aligned buffer
        uint32_t       src = (uint32_t) ipc_arg->src;
        uint32_t       dst = (uint32_t) ipc_arg->dst;
        int            remaining;
        uint32_t       data_size;

        uint8_t *      last_block;
        ipc_shmem_t    tmp_key_buffer;

        if ( ish_pl )
        {
            OS_MEMCPY (&tmp_key_buffer, ish_pl, sizeof(ipc_shmem_t));
        }

        src_data = (void *)OS_ALLOC(PAGE_SIZE);
        dst_data = (void *)OS_ALLOC(PAGE_SIZE);

        VERIFY(src_data != NULL, exit, rc, SEC_OUT_OF_MEMORY);
        VERIFY(dst_data != NULL, exit, rc, SEC_OUT_OF_MEMORY);

        for (remaining=ipc_arg->src_size; remaining; remaining -= data_size)
        {
            data_size = (remaining >= PAGE_SIZE) ? PAGE_SIZE : remaining;
            copy_from_user(src_data, (void*)src, data_size);
            if(ipc_arg->cmd == IPC_ARC4_ENCRYPT_DECRYPT_DATA)
            {
               dma_stf_flag = SEC_DMA_STF_FLAGS_ARC4 | SEC_DMA_FLAG_DST_INT;
            }
            else
            {
               dma_stf_flag = SEC_DMA_STF_FLAGS | SEC_DMA_FLAG_DST_INT;
            }

            dma_info->dma_flags       = dma_stf_flag;
            dma_info->next_descriptor = 0;
            dma_info->src_start       = OS_VIRT_TO_PHYS(src_data);
            dma_info->dst_start       = OS_VIRT_TO_PHYS(dst_data);
            dma_info->src_size        = data_size;
            dma_info->dst_size        = data_size;
            if(g_fast_path)
            {
                cache_flush_buffer((void*)dma_info, sizeof(dma_info_t));
                cache_flush_buffer((void*)src_data, data_size);
                cache_flush_buffer((void*)dst_data, data_size);
            }

            // this fixes HSD 228671 - shared memory is wiped for
            // added robustness
            // TODO: Customize the copy for key size.
            if ( ish_pl )
            {
                OS_MEMCPY (ish_pl, &tmp_key_buffer, sizeof(ipc_shmem_t));
            }

            ipc_ret = sec_kernel_ipc( ipc_arg->cmd,
                                      ipc_arg->sub_cmd,
                                      ipc_arg->io_sizes,
                                      ipl,
                                      opl,
                                      ish_pl,
                                      NULL);
            if (ipc_ret != IPC_RET_COMMAND_COMPLETE)
            {
                break;
            }

            // printVector ((uint8_t*)(ipl), 64);

            if (((ipc_arg->cmd == IPC_AES_ENCRYPT_DATA) ||(ipc_arg->cmd == IPC_AES_DECRYPT_DATA))  &&
                ipc_arg->ipl->aes_crypt.chain_mode == SEC_CBC)
            {
               //printk ("+++++ AES  SEC_CBC +++++\n");
               if (remaining > data_size)
               {
                 // copy last encrypted aes block into the ipl's iv for the next call
                 if (ipc_arg->cmd == IPC_AES_ENCRYPT_DATA)
                 {
                   last_block = (uint8_t*)dst_data + data_size - AES_BLOCK_SIZE;
                 }
                 else
                 {
                   last_block = (uint8_t*)src_data + data_size - AES_BLOCK_SIZE;
                 }
                 OS_MEMCPY((&(ipl->aes_crypt.iv)), last_block, AES_BLOCK_SIZE);

                 // iv  endian swap
                 swapped_iv = (unsigned long *)&(ipl->aes_crypt.iv);
                 for (i = 0; i<4; i++)
                 {
                   swapped_iv[i] = bswap(swapped_iv[i]);
                 }
               }
            }
            //printVector ((uint8_t*)(ipl), 64);

            //copy output data back to user buffer
            copy_to_user((void *)dst, dst_data, data_size);
            src += data_size;
            dst += data_size;
        }
    }

    if (ipc_ret == IPC_RET_COMMAND_COMPLETE)
    {
        sec_kernel_copy_to_user(ipc_arg, opl, NULL);
    }
    rc = ipc2sec(ipc_ret);

exit:

    if (src_data) { OS_FREE(src_data); }
    if (dst_data) { OS_FREE(dst_data); }
    return rc;
}


//-----------------------------------------------------------------------------
// lastbytes_copy to OPL
//
// This mechanism copies the last bytes of the fragmented buffer operation to
// a field in the OPL.  This is to return the encrypted block to save/restore
// the CBC chaining state.
//-----------------------------------------------------------------------------
static
sec_result_t lastbytes_copy( sec_kernel_fb_t *  fb_arg,
                             void *             bfr,
                             void *             bfr_virtual,
                             opl_t *            opl )
{
    sec_result_t            rc = SEC_SUCCESS;

    if ( fb_arg->fragment_count > 0ul
    && fb_arg->lastbytes_len_bytes <= fb_arg->fragment_length_bytes
    && fb_arg->lastbytes_opl_ofs+fb_arg->lastbytes_len_bytes <= fb_arg->ipc.io_sizes.opl_size )
    {
        unsigned long   bfr_ofs = ( (fb_arg->fragment_count - 1ul) *
                                    fb_arg->fragment_period_bytes ) +
                                  fb_arg->fragment_length_bytes -
                                  fb_arg->lastbytes_len_bytes;
        if ( bfr_virtual )
        {
            OS_MEMCPY( &((uint8_t *)opl)[fb_arg->lastbytes_opl_ofs],
                       &((uint8_t *)bfr_virtual)[bfr_ofs],
                       fb_arg->lastbytes_len_bytes );
        }
        else
        {
            void __iomem *  bfr_io = ioremap( (unsigned long)&((uint8_t *)bfr)[bfr_ofs],
                                             fb_arg->lastbytes_len_bytes );
            VERIFY( bfr_io != NULL, exit, rc, SEC_FAIL);
            memcpy_fromio( &((uint8_t *)opl)[fb_arg->lastbytes_opl_ofs],
                           bfr_io,
                           fb_arg->lastbytes_len_bytes );
            iounmap( bfr_io );
        }
    }

exit:
    return rc;
}


//-----------------------------------------------------------------------------
// fragment_copy
//
// This mechanism copies the last bytes of the fragmented buffer operation to
// a field in the OPL.  This is to return the encrypted block to save/restore
// the CBC chaining state.
//-----------------------------------------------------------------------------
static
sec_result_t fragment_copy( size_t             length_bytes,
                            unsigned long      bfr_ofs,
                            void *             bfr_src,
                            void *             bfr_virtual_src,
                            void *             bfr_dst,
                            void *             bfr_virtual_dst )
{
    sec_result_t            rc = SEC_SUCCESS;

    if ( bfr_virtual_src )
    {
        if ( bfr_virtual_dst )
        {
            OS_MEMCPY( &((uint8_t *)bfr_virtual_dst)[bfr_ofs],
                       &((uint8_t *)bfr_virtual_src)[bfr_ofs],
                       length_bytes );
        }
        else
        {
            void __iomem *  bfr_io = ioremap( (unsigned long)&((uint8_t *)bfr_dst)[bfr_ofs],
                                              (unsigned long)length_bytes );
            memcpy_toio( bfr_io,
                         &((uint8_t *)bfr_virtual_src)[bfr_ofs],
                         (long)length_bytes );
            iounmap( bfr_io );
        }
    }
    else
    {
        if ( bfr_virtual_dst )
        {
            void __iomem *  bfr_io = ioremap( (unsigned long)&((uint8_t *)bfr_src)[bfr_ofs],
                                              (unsigned long)length_bytes );
            memcpy_fromio( &((uint8_t *)bfr_virtual_dst)[bfr_ofs],
                           bfr_io,
                           (long)length_bytes );
            iounmap( bfr_io );
        }
        else
        {
            /*  Here we are doing a phys-to-phys memcpy.  This is going to be
             *  dirt slow no matter how we deal with it.  It will be too slow
             *  to be effectively useful.  So we are not going to even bother
             *  to try to speed it up.  We will do a byte-per-byte copy for
             *  the sake of simplicity.
             */
            while ( length_bytes )
            {
                void __iomem *  bfr_io_src = ioremap( (unsigned long)&((uint8_t *)bfr_src)[bfr_ofs],
                                                      1 );
                void __iomem *  bfr_io_dst = ioremap( (unsigned long)&((uint8_t *)bfr_dst)[bfr_ofs],
                                                      1 );
                iowrite8( (u8)ioread8( bfr_io_src ), bfr_io_dst );
                iounmap( bfr_io_dst );
                iounmap( bfr_io_src );
            }
        }
    }

    return rc;
}


//-----------------------------------------------------------------------------
// crypt_dma_op_fb_phys
//
// Encrypt/decrypt using DMA to transfer data to/from firmware.  This version
// is for the fragmented buffer case and only handles physical memory
// addresses.
//-----------------------------------------------------------------------------
static
sec_result_t crypt_dma_op_fb_phys( sec_kernel_fb_t *  fb_arg,
                                   ipl_t *            ipl,
                                   opl_t *            opl,
                                   ipc_shmem_t *      ish_pl,
                                   void *             bfr_virtual_src,
                                   void *             bfr_virtual_dst )
{
    sec_result_t            rc;
    sec_ipc_return_t        ipc_ret       = IPC_RET_COMMAND_COMPLETE;
    uint32_t                block_size;
    uint32_t                TX;
    uint32_t                RX;
    dma_info_t *            dma_info;
    uint32_t                dma_stf_flags;
    uint32_t                bfr_src;
    uint32_t                bfr_dst;
    uint32_t                remaining_fragments;
    uint32_t                fragment_space_bytes = 0;
    sec_dma_descriptor_t *  dmad_head = NULL;
    sec_dma_descriptor_t *  dmad_tail = NULL;
    uint16_t                saved_opl_size = 0;
    bool                    not_in_place;
    sec_dma_descriptor_t *  list;

    VERIFY( ipl != NULL,
            exit, rc, SEC_FAIL);
    VERIFY( fb_arg->bfr_type_src == SEC_KERNEL_ADDR_PHYSCONTIG,
            exit, rc, SEC_FAIL );
    VERIFY( fb_arg->bfr_type_dst == SEC_KERNEL_ADDR_PHYSCONTIG,
            exit, rc, SEC_FAIL );

    rc = crypt_dma_op_prepare( &fb_arg->ipc, ipl, &block_size, &TX, &RX, &dma_info );
    VERIFY_QUICK( rc == SEC_SUCCESS, exit );

    not_in_place = (fb_arg->ipc.src != fb_arg->ipc.dst) ? true : false;

    /*  deal with copying the first encrypted block, if applicable:  */
    if ( fb_arg->lastbytes_copy_mode == SEC_KERNEL_LB_COPY_BEFORE )
    {
        rc = lastbytes_copy( fb_arg, fb_arg->ipc.src, bfr_virtual_src, opl );
        VERIFY_QUICK( rc == SEC_SUCCESS, exit );
    }

    switch ( fb_arg->ipc.cmd )
    {
    case IPC_ARC4_ENCRYPT_DECRYPT_DATA:
        dma_stf_flags = SEC_DMA_STF_FLAGS_ARC4 |
                        SEC_DMA_FLAG_DST_LL | SEC_DMA_FLAG_SRC_LL;
        break;
    default:
        dma_stf_flags = SEC_DMA_STF_FLAGS |
                        SEC_DMA_FLAG_DST_LL | SEC_DMA_FLAG_SRC_LL;
        break;
    }

    if ( fb_arg->fragment_period_bytes > fb_arg->fragment_length_bytes )
    {
        fragment_space_bytes = fb_arg->fragment_period_bytes -
                               fb_arg->fragment_length_bytes;
    }

    /*  loop through the fragments adding a DMA descriptor to the list for
     *  each one:
     */
    for ( remaining_fragments = fb_arg->fragment_count,
              bfr_src = (uint32_t)fb_arg->ipc.src,
              bfr_dst = (uint32_t)fb_arg->ipc.dst;
          remaining_fragments;
          remaining_fragments--,
              bfr_src += fb_arg->fragment_period_bytes,
              bfr_dst += fb_arg->fragment_period_bytes )
    {
        rc = add_dma_desc( &dmad_head, &dmad_tail,
                           fb_arg->fragment_length_bytes,
                           bfr_src, bfr_dst,
                           dma_stf_flags );
        VERIFY_QUICK( rc == SEC_SUCCESS, cleanup_dmad );
        if ( not_in_place && remaining_fragments>1u && fragment_space_bytes )
        {
            rc = fragment_copy( fragment_space_bytes,
                                fb_arg->fragment_length_bytes,
                                fb_arg->ipc.src, bfr_virtual_src,
                                fb_arg->ipc.dst, bfr_virtual_dst );
        }
    }
    VERIFY_QUICK( dmad_head, cleanup_dmad_done );
    dmad_tail->dma_flags |= SEC_DMA_FLAG_TERM | SEC_DMA_FLAG_DST_INT;
    dump_dma_list( dmad_head );  /*  this just debug prints the list  */

    dma_info->dma_flags = dmad_head->dma_flags;
    dma_info->next_descriptor = dmad_head->next;
    dma_info->src_start = dmad_head->src;
    dma_info->dst_start = dmad_head->dst;
    dma_info->src_size  = dmad_head->size;
    dma_info->dst_size  = dmad_head->size;

    if(g_fast_path)
    {
        list=dmad_head;
        while(list!=NULL)
        {
            cache_flush_buffer((void*)list, sizeof(sec_dma_descriptor_t));
            cache_flush_buffer(phys_to_virt(list->src), list->size);
            cache_flush_buffer(phys_to_virt(list->dst), list->size);
            list = list->next ? phys_to_virt(list->next) : NULL;
        }
    }

    /*  We have an ugly little problem to workaround here.  If we copied the
     *  lastbytes into the OPL already, then sec_kernel_ipc() will overwrite
     *  it unless fb_arg->ipc.io_sizes.opl_size is reduced accordingly.  I
     *  could add another parameter to sec_kernel_ipc() but then other code
     *  would need to change also.  So, until we come up with a cleaner soln,
     *  we are just going to temporarily set io_sizes.opl_size down to what
     *  the firmware returns and then restore it when we return.  Ultimately,
     *  the problem is that we are abusing opl_size a bit here by using it
     *  for two similar but different meanings:  (1) the OPL size returned to
     *  user space, and (2) the OPL size returned from FW (which is different
     *  in this case since we are adding our own OPL parameter).
     */
    if ( fb_arg->lastbytes_copy_mode == SEC_KERNEL_LB_COPY_BEFORE )
    {
        saved_opl_size = fb_arg->ipc.io_sizes.opl_size;
        fb_arg->ipc.io_sizes.opl_size = (uint16_t)fb_arg->lastbytes_opl_ofs;
    }

    ipc_ret = sec_kernel_ipc( fb_arg->ipc.cmd,
                              fb_arg->ipc.sub_cmd,
                              fb_arg->ipc.io_sizes,
                              ipl,
                              opl,
                              ish_pl,
                              NULL );

    /*  Restore the saved fb_arg->ipc.io_sizes.opl_size back.
     */
    if ( fb_arg->lastbytes_copy_mode == SEC_KERNEL_LB_COPY_BEFORE )
    {
        fb_arg->ipc.io_sizes.opl_size = saved_opl_size;
    }

    rc = ipc2sec(ipc_ret);
    VERIFY_QUICK( ipc_ret==IPC_RET_COMMAND_COMPLETE,  cleanup_dmad );

    /*  deal with copying the last encrypted block, if applicable:  */
    if ( fb_arg->lastbytes_copy_mode == SEC_KERNEL_LB_COPY_AFTER )
    {
        rc = lastbytes_copy( fb_arg, fb_arg->ipc.dst, bfr_virtual_dst, opl );
        VERIFY_QUICK( rc == SEC_SUCCESS, cleanup_dmad );
    }

    sec_kernel_copy_to_user( &fb_arg->ipc, opl, NULL );

cleanup_dmad:
    sec_kernel_free_descriptor_list( dmad_head );
cleanup_dmad_done:

exit:
    return rc;
}

static int bulk_poll(void *offset)
{
    int b_thr_offset, read_ptr=0, compl=0;
    int rc=0;
    read_ptr=0;
    memcpy(&b_thr_offset,(int *)offset, sizeof(int));
    //signal to notify sec_process_bulk_ipc to exit
    complete(&g_bulk_stat[b_thr_offset].fw_compl_signal);
    //polling thread, which reads the return status of IPC command. 
    //once writer thread post the command, it sends complete signal to polling thread . 
    //now polling threads polls the status by reading the value of command buffer node. 
    //if status is non zero, polling thread sends signal to writer thread. 
    //polling thread runs in while loop until bulk mode status (g_bulk_stat[b_thr_offset].status)is zero. 
    //bulk_stop IPC command sets g_bulk_stat[b_thr_offset].status to zero and polling thread exits
    while(g_bulk_stat[b_thr_offset].status!=0)
    {
        compl=0;
        wait_for_completion(&g_bulk_stat[b_thr_offset].host_compl_signal);
        if(*((uint32_t *)(g_bulk_stat[b_thr_offset].cmd_buff_ptr+read_ptr*8)) !=0xFFFFFFFF)
        {
            while(1)
            {
                memcpy(&compl, (void *)(g_bulk_stat[b_thr_offset].cmd_buff_ptr + read_ptr*8 + 4), 4);
                if(compl!=0)
                {
                    if(g_bulk_stat[b_thr_offset].status!=0)
                    {
                        INIT_COMPLETION(g_bulk_stat[b_thr_offset].host_compl_signal);
                        complete(&g_bulk_stat[b_thr_offset].fw_compl_signal);
                    }
                    else
                    {
                        INIT_COMPLETION(g_bulk_stat[b_thr_offset].host_compl_signal);
                        goto exit;
                    }
                    read_ptr=(read_ptr+1)%g_bulk_stat[b_thr_offset].counter;
                        break;
                }
            }
        }
    }

exit:
    //signal to bulk stop IPC writer thread to notify that bulk_poll thread is exiting
    complete(&g_bulk_stat[b_thr_offset].fw_compl_signal);
    return rc;
}

//**************************************
// BULK IPC
//IPC_60 handler function. 
//This function initializes or sets the parameter and starts polling thread by creating a kernel thread
//**************************************

static
sec_result_t sec_process_bulk_ipc(sec_kernel_ipc_t *ipc_arg,
                                  ipl_t *           ipl,
                                  opl_t *           opl,
                                  ipc_shmem_t *     ish_pl,
                                  ipc_shmem_t *     osh_pl)
{
    sec_result_t            rc              = SEC_SUCCESS;
    sec_ipc_return_t        ipc_ret         = IPC_RET_COMMAND_COMPLETE;
    uint32_t                cmd_buff_ptr;
    uint32_t                cmd_data_ptr;
    int b_thr_offset;

    cmd_buff_ptr = ipl->bulk_ipc.cmd_buff_ptr;
    cmd_data_ptr = ipl->bulk_ipc.cmd_data_ptr;
    ipl->bulk_ipc.cmd_buff_ptr = OS_VIRT_TO_PHYS((void *) ipl->bulk_ipc.cmd_buff_ptr );
    ipl->bulk_ipc.cmd_data_ptr = OS_VIRT_TO_PHYS((void *) ipl->bulk_ipc.cmd_data_ptr );

    memset((void *) cmd_data_ptr,0, 328*ipl->bulk_ipc.cmd_count);
    //this section will return error if more than SEC_MAX_BULK_COUNT application is running simultaneously
    down(&bulk_ipc_lock);
    if(g_bulk_counter == (sizeof(g_bulk_stat)/sizeof(g_bulk_stat[0])))
    {
        if(g_bulk_stat[0].status==0)
            g_bulk_counter =0;
        else
            return SEC_EXCEED_MAX_BULK_OPERATION_COUNT;
    }
    up(&bulk_ipc_lock);

    init_completion(&g_bulk_stat[g_bulk_counter].host_compl_signal);
    init_completion(&g_bulk_stat[g_bulk_counter].fw_compl_signal);
    ipc_ret = sec_kernel_ipc(ipc_arg->cmd, ipc_arg->sub_cmd, ipc_arg->io_sizes, ipl, opl, ish_pl, osh_pl);

    rc = ipc2sec(ipc_ret);
    if(rc == SEC_SUCCESS)
    {
        if(g_bulk_stat[g_bulk_counter].status==0)
        {
            down(&bulk_ipc_lock);
            g_bulk_stat[g_bulk_counter].tgid = current->tgid;
            g_bulk_stat[g_bulk_counter].bulk_mode=1;
            g_bulk_stat[g_bulk_counter].status=1;
            g_bulk_stat[g_bulk_counter].write_ptr=cmd_buff_ptr;
            g_bulk_stat[g_bulk_counter].cmd_buff_ptr=cmd_buff_ptr;
            g_bulk_stat[g_bulk_counter].cmd_data_ptr=cmd_data_ptr;
            g_bulk_stat[g_bulk_counter].counter=ipl->bulk_ipc.cmd_count;
            g_bulk_stat[g_bulk_counter].bulk_counter=g_bulk_counter;
            b_thr_offset=g_bulk_stat[g_bulk_counter].bulk_counter;
            g_bulk_counter++;
            up(&bulk_ipc_lock);

        }
        else
        {
            rc = SEC_FAIL;
            return rc;
         }
    }
    //  a kernel thread is created for polling
    kthread_run(bulk_poll, &b_thr_offset,"bulk_poll_0x%x",b_thr_offset);
    // waits for a signal from bulk_poll thread to make sure that bulk_poll thread is created
    wait_for_completion(&g_bulk_stat[b_thr_offset].fw_compl_signal);
    return rc;
}

 

//-----------------------------------------------------------------------------
// sec_hash
//
// Used by MD5, SHA*, and AACS AES hashes.
//-----------------------------------------------------------------------------
static
sec_result_t sec_hash(sec_kernel_ipc_t *ipc_arg,
                      ipl_t *           ipl,
                      opl_t *           opl,
                      ipc_shmem_t *     ish_pl,
                      ipc_shmem_t *     osh_pl,
                      int               hash_block_size,
                      int               chaining_var_size,
                      int               length_field_size)
{
    sec_dma_descriptor_t *  phys_src_desc;
    sec_dma_descriptor_t *  list;
    sec_result_t            result              = SEC_SUCCESS;
    sec_ipc_return_t        ipc_ret             = IPC_RET_COMMAND_COMPLETE;
    uint32_t      *         chaining_var_ptr    = NULL;
    unsigned char *         length_field        = NULL;
    void *                  src_data            = NULL;
    unsigned long           dst_rx_reg;

    VERIFY(ipl != NULL, exit, result, SEC_FAIL);

    if (ipc_arg->src_size == 0)
    {
        // This is a no-op.  The user space library should just return
        // success when it sees a zero-length source, instead of calling us.
        // The code below assumes a non-zero length.
        result = SEC_INVALID_INPUT;
        SEC_ERROR("zero-length source passed for hashing\n");
        goto exit;
    }

    if(ipc_arg->sub_cmd.sc_54 == IPC_SC_54_20)
    {
        dst_rx_reg = SEC_AES_RX_FIFO;
    }
    else
    {
        dst_rx_reg = SEC_HCU_RX_DATA;
    }

    if (ipl->hash_fw_based.storage_mode == 0) {
        chaining_var_ptr = (uint32_t *)OS_ALLOC(chaining_var_size);
        VERIFY(chaining_var_ptr != NULL, exit, result, SEC_OUT_OF_MEMORY);

        /* The ipc_arg->ipl pointer is pointing to the passed user
           space ipl_t structure. So get the chaining_variable_pointer
           from user space and convert it to kernel space and put it
           in ipl.
        */
        if (ipl->hash_data.allow_user_entered_chaining_variables == 1)
        {
            copy_from_user(chaining_var_ptr,
                           (void*) ipl->hash_data.chaining_variable_pointer,
                           chaining_var_size);
            ipl->hash_data.chaining_variable_pointer =
                (uint32_t) OS_VIRT_TO_PHYS(chaining_var_ptr);
            if(g_fast_path)
            {
                cache_flush_buffer((uint32_t *)chaining_var_ptr, chaining_var_size);
            }
            print_data("chaining variable", (uint32_t *)chaining_var_ptr, 5);
        }

        //copy user specified total length to a temporary kernel-space buffer
        if (ipl->hash_data.total_length_in_bits != 0)
        {
            length_field = (unsigned char *)OS_ALLOC(length_field_size);
            VERIFY(length_field != NULL, exit, result, SEC_OUT_OF_MEMORY);

            copy_from_user(length_field,
                           (void *)ipl->hash_data.total_length_in_bits,
                           length_field_size);

            ipl->hash_data.total_length_in_bits = (uint32_t)OS_VIRT_TO_PHYS(length_field);
            if(g_fast_path)
            {
                cache_flush_buffer((unsigned char *)length_field, length_field_size);
            }
            print_data("total_length_in_bits var", (uint32_t *)length_field,2);
        }
    }

    // In order to use direct I/O src address must be 32-bit aligned and
    // source size must be multiple of 'hash_block_size'
    if ((((uint32_t)ipc_arg->src & 0x3) == 0)
        && ((ipl->hash_fw_based.storage_mode == 0 &&
             ipc_arg->src_size % hash_block_size == 0)
            || ipc_arg->src_size % 0x03 == 0))
    {
        user_buf_t      src;
        sec_result_t    rc;

        rc = sec_kernel_user_buf_lock( &src,
                            (sec_address_t) ipc_arg->src,
                            ipc_arg->src_size,
                            USER_BUF_RO);
        VERIFY_QUICK(rc == SEC_SUCCESS, exit);

        phys_src_desc = map_vm_for_dma_r(&src,hash_block_size,dst_rx_reg, ipc_arg->sub_cmd);
        if (phys_src_desc != NULL)
        {
            ipl->hash_data.dma_info.dma_flags       = phys_src_desc->dma_flags;
            ipl->hash_data.dma_info.next_descriptor = phys_src_desc->next;
            ipl->hash_data.dma_info.src_start       = phys_src_desc->src;
            ipl->hash_data.dma_info.dst_start       = phys_src_desc->dst;
            ipl->hash_data.dma_info.src_size        = phys_src_desc->size;
            ipl->hash_data.dma_info.dst_size        = 0;

            if(g_fast_path)
            {
                list=phys_src_desc;
                while(list!=NULL)
                {
                    cache_flush_buffer((void*)list, sizeof(sec_dma_descriptor_t));
                    list = list->next ? phys_to_virt(list->next) : NULL;
                }
            }
            ipc_ret = sec_kernel_ipc( ipc_arg->cmd,
                                      ipc_arg->sub_cmd,
                                      ipc_arg->io_sizes,
                                      ipl,
                                      opl,
                                      ish_pl,
                                      osh_pl);

            sec_kernel_free_descriptor_list(phys_src_desc);
        }
        // Free pages locked by user_buf_lock()
        sec_kernel_user_buf_unlock( &src );

        VERIFY(phys_src_desc != NULL, exit, result, SEC_FAIL);
    }
    else
    {
        // We need to copy each page of data to a physically contigous buffer
        uint32_t data_size;
        uint32_t remain_size;
        uint32_t src;
        src_data = (void *)OS_ALLOC(PAGE_SIZE);
        VERIFY(src_data != NULL, exit, result, SEC_OUT_OF_MEMORY);

        src         = (uint32_t)ipc_arg->src;
        remain_size = ipc_arg->src_size;

        while (remain_size)
        {
            data_size = (remain_size >= PAGE_SIZE) ? PAGE_SIZE : remain_size;
            remain_size -= data_size;

            if (copy_from_user(src_data, (void*)src, data_size))
            {
                SEC_ERROR("Copy from user failed\n");
                result = SEC_FAIL;
                goto exit;
            }

            ipl->hash_data.dma_info.dma_flags  = SEC_DMA_READ_FLAGS
                                               | SEC_DMA_FLAG_DST_MODE_FIX_CONT;

            ipl->hash_data.dma_info.next_descriptor  = 0;
            ipl->hash_data.dma_info.src_start        = OS_VIRT_TO_PHYS(src_data);
            ipl->hash_data.dma_info.dst_start        = 0;
            ipl->hash_data.dma_info.src_size         = data_size;
            ipl->hash_data.dma_info.dst_size         = 0;

            if(g_fast_path)
            {
                cache_flush_buffer((void*)src_data, data_size);
            }
            ipc_ret = sec_kernel_ipc( ipc_arg->cmd,
                                      ipc_arg->sub_cmd,
                                      ipc_arg->io_sizes,
                                      ipl,
                                      opl,
                                      ish_pl,
                                      osh_pl);
            VERIFY_QUICK(ipc_ret == IPC_RET_COMMAND_COMPLETE, exit);

            //more data to be processed
            if (remain_size && ipl->hash_fw_based.storage_mode == 0)
            {
                ipl->hash_data.allow_user_entered_chaining_variables = 1;
                OS_MEMCPY(chaining_var_ptr, osh_pl, chaining_var_size);
                ipl->hash_data.chaining_variable_pointer =
                                (uint32_t) OS_VIRT_TO_PHYS(chaining_var_ptr);
                if(g_fast_path)
                {
                    cache_flush_buffer((uint32_t *)chaining_var_ptr, chaining_var_size);
                }
            }
            src += data_size;
        }
    }

    if (ipc_ret == IPC_RET_COMMAND_COMPLETE)
    {
        sec_kernel_copy_to_user(ipc_arg, opl, osh_pl);
    }

    result = ipc2sec(ipc_ret);

exit:
    if (src_data        ) { OS_FREE(src_data);          }
    if (chaining_var_ptr) { OS_FREE(chaining_var_ptr);  }
    if (length_field    ) { OS_FREE(length_field);      }

    return result;
} //ENDPROC sec_hash


//-----------------------------------------------------------------------------
// sha_hash
//-----------------------------------------------------------------------------
static
sec_result_t sha_hash(sec_kernel_ipc_t * ipc_arg,
                      ipl_t *            ipl,
                      opl_t *            opl,
                      ipc_shmem_t *      ish_pl,
                      ipc_shmem_t *      osh_pl)
{
    sec_result_t    rc                  = SEC_SUCCESS;
    int             chaining_var_size   = 0;
    int             hash_block_size     = 0;
    int             length_field_size   = 0;

    switch (ipl->hash_data.mode)
    {
    case SHA_1:
        hash_block_size     = SHA_1_BLOCK_SIZE;
        chaining_var_size   = SHA_1_STATE_SIZE;
        length_field_size   = 8;
        break;
    case SHA_224:
        hash_block_size     = SHA_224_BLOCK_SIZE;
        chaining_var_size   = SHA_224_STATE_SIZE;
        length_field_size   = 8;
        break;
    case SHA_256:
        hash_block_size     = SHA_256_BLOCK_SIZE;
        chaining_var_size   = SHA_256_STATE_SIZE;
        length_field_size   = 8;
        break;
    case SHA_384:
        hash_block_size     = SHA_384_BLOCK_SIZE;
        chaining_var_size   = SHA_384_STATE_SIZE;
        length_field_size   = 16;
        break;
    case SHA_512:
        hash_block_size     = SHA_512_BLOCK_SIZE;
        chaining_var_size   = SHA_512_STATE_SIZE;
        length_field_size   = 16;
        break;
    default:
        rc = SEC_INVALID_HASH;
        goto end;
        break;
    }

    rc = sec_hash(ipc_arg,
                  ipl,
                  opl,
                  ish_pl,
                  osh_pl,
                  hash_block_size,
                  chaining_var_size,
                  length_field_size);

end:
    return rc;
}

//-----------------------------------------------------------------------------
// __workaround_2754133
//
// CE3100 firmware workaround of 2754133.
// After N times random data is read from fw RNG has to be reseeded.
//-----------------------------------------------------------------------------
static void __workaround_2754133(void)
{
    static int                      get_rnd_data_called=0;
    sec_ipc_sizes_t io_sizes;

    if (get_rnd_data_called++ > 50000)
    {
        ipl_t tmp_ipl;
        const sec_fw_subcmd_t  sub_cmd = {.sc = IPC_SC_NOT_USED};

        //Reseed with 0 entropy.
        memset(&tmp_ipl, 0, sizeof(tmp_ipl));
        memset(&io_sizes, 0, sizeof(io_sizes));
        io_sizes.ipl_size = (uint16_t)sizeof(tmp_ipl);
        sec_kernel_ipc(IPC_CTR_DRBG_RESEED, sub_cmd, io_sizes, &tmp_ipl, NULL, NULL, NULL);
        get_rnd_data_called = 0;
    }
}

/* acquire_context_interruptible
 *
 * Acquire a context of the specified type.  Can be interrupted.
 * Returns a negative value in the case of an error, otherwise returns
 * the acquired context_id. */
static int acquire_context_interruptible(enum context_type type,
					 uint32_t resources,
					 bool *locked) {
    int i, context = -ENOENT;

    if (down_trylock(&context_trackers[type].sema)) {
        /* Couldn't acquire a context immediately, drop resources from
         * the tracker and wait. */
        sec_unlock_resources(resources);
        tracker_remove_resources(current->tgid, resources);
        *locked = false;

        if (down_interruptible(&context_trackers[type].sema))
            return -EINTR;

        sec_lock_resources(resources);
        tracker_add_resources(current->tgid, resources);
        *locked = true;
    }

    spin_lock(&context_trackers[type].lock);
    for(i = 0; i < SEC_NUM_CONTEXTS; i++)
    {
        if(!context_trackers[type].in_use[i])
        {
            context_trackers[type].in_use[i] = true;
            context = i;
            break;
        }
    }
    spin_unlock(&context_trackers[type].lock);

    if (context >= 0)
        tracker_add_context(type, current->tgid, context);

    return context;
}

/* sec_release_context_for_client
 *
 * Releases a context that's currently in use. */
void sec_release_context(enum context_type type, uint32_t context_id)
{
    if (context_id >= SEC_NUM_CONTEXTS)
        return;

    spin_lock(&context_trackers[type].lock);
    if (context_trackers[type].in_use[context_id])
    {
        context_trackers[type].in_use[context_id] = false;
        up(&context_trackers[type].sema);
    }
    spin_unlock(&context_trackers[type].lock);
}

/* sec_release_context_for_client
 *
 * Checks to see if the current process actually owns a specified
 * context.  If so the calls sec_release_context().
 */
static void sec_release_context_for_client(enum context_type type,
                                           uint32_t context_id)
{
    if (context_id >= SEC_NUM_CONTEXTS)
        return;

    if (!tracker_has_context(type, current->tgid, context_id))
        return;

    tracker_remove_context(type, current->tgid, context_id);

    sec_release_context(type, context_id);
}

/*
---------------------------------------------------------------------
uint32 Link List implementation
---------------------------------------------------------------------
*/
/*
NOTE:
Because of the way the structure uint32_list is defined in sec_kernel_types.h
The list data item, which is a struct list_head, comes first.
Since struct list_head, defined in kernel-2.6.35/linux-2.6.35/include/linux/list.h,
is two pointers next and prev, tmp pointer is the same value as tmp->list.next.
So, when list_add_tail, defined in list.h, is called the tmp address is actually
saved in "l->list" thus it is not lost when this function returns.
So, the klocwork bug that this is a possible memory leak is NOT a bug!
*/
bool uint32_list_add_tail_node(uint32_t value, uint32_list* l)
{
    uint32_list *tmp = OS_ALLOC(sizeof(uint32_list));
    bool ret = false;
    if(l && tmp)
    {
        INIT_LIST_HEAD(&(tmp->list));
        tmp->value = value;
        list_add_tail(&(tmp->list), &(l->list));
        ret = true;
    }
    return ret;
}

bool uint32_list_remove_node(uint32_t value, uint32_list* l)
{
    bool ret = false;
	struct list_head *j = NULL;
    struct list_head *q = NULL;
    uint32_list *le = NULL;

    // Proceed only is list is non empty
    if(l && (0 == list_empty_careful(&l->list)))
    {
        list_for_each_safe(j, q, &(l->list))
        {
            le = list_entry(j, uint32_list, list);
            if(le->value == value)
            {
                list_del(j);
                OS_FREE(le);
                ret = true;
                break;
            }
        }
    }
    return ret;
}

void uint32_list_clear_list(uint32_list* l)
{
    struct list_head* j = NULL;
    struct list_head* q = NULL;
    uint32_list *le = NULL;

    // Proceed only is list is non empty
    if(l && (0 == list_empty_careful(&l->list)))
    {
        list_for_each_safe(j, q, &(l->list))
        {
            le = list_entry(j, uint32_list, list);
            list_del(j);
            OS_FREE(le);
        }
    }
}

//-----------------------------------------------------------------------------
// sec_kernel_ioctl_ipc_call:
//
// Handler for IPC ioctl calls
//
// This function secures access to the resources required for performing the
// requested sec operation and uses the hal interface to command the hardware
// to initiate the op the sec_kernel_ioctl_ipc_call routine also manages the
// scoreboard to make sure operations, resource, and sensitive function calls
// don't collide.
//
// Parameter:
//      arg - a structure holding all required input for sec op.
//-----------------------------------------------------------------------------
static sec_result_t sec_kernel_ioctl_ipc_call(uint32_t arg)
{
    sec_result_t        rc;
    sec_ipc_return_t    ipc_ret = IPC_RET_ERROR;
    sec_kernel_ipc_t    ipc_arg;
    ipl_t               ipl_data;
    opl_t               opl_data;
    uint32_t            num_osh_block=0;
    ipc_shmem_t         ish_pl_data;
    ipl_t              *ipl         = NULL;
    opl_t              *opl         = NULL;
    ipc_shmem_t        *osh_pl      = NULL;
    ipc_shmem_t        *ish_pl      = NULL;
    //uint32_t            public_key_return_ptr;
    //void                * return_key = NULL;
    bool                resources_locked = false;

    if (!arg)
    {
        SEC_ERROR("Invalid argument passed\n");
        rc = -EFAULT;
        goto exit;
    }

    rc = SEC_SUCCESS;

    SAFE_COPY_FROM_USER(&ipc_arg, (void*)arg, sizeof(ipc_arg));

    /* We always need an IPL */
    if (ipc_arg.ipl == NULL)
    {
        rc = SEC_INTERNAL_ERROR;
        goto exit;
    }
    else
    {
        if ( ( ipc_arg.cmd == IPC_54 ||
               ( ipc_arg.cmd == IPC_EXTERNAL_MODULE_CMD &&
                 (ipc_arg.module_id & SEC_IPC_54_MODULE_ID_MASK) ==
                 SEC_IPC_54_MODULE_ID ) )
        &&  ipc_arg.sub_cmd.sc_54 == IPC_SC_54_12 )
        {
           // For this command only, 'ipl' is a pointer to sec_contig_mem_t.
           // Note:  This is ugly.  We are assuming that:
           //        sizeof(sec_contig_mem_t) <= sizeof(ipl_t).  We will add
           //        a check for that here to be safe.
           if ( sizeof(sec_contig_mem_t) > (sizeof ipl_data) )
           {
               printk( KERN_ERR "sizeof(sec_contig_mem_t) > (sizeof ipl_data)" );
               rc = SEC_INTERNAL_ERROR;
               goto exit;
           }
           SAFE_COPY_FROM_USER(&ipl_data, ipc_arg.ipl, sizeof(sec_contig_mem_t));
        }
        else
        {
           SAFE_COPY_FROM_USER(&ipl_data, ipc_arg.ipl, sizeof(ipl_data));
        }
        ipl = &ipl_data;
    }

    if (ipc_arg.opl)
    {
        SAFE_COPY_FROM_USER(&opl_data, ipc_arg.opl, sizeof(opl_data));
        opl = &opl_data;
    }

    if (ipc_arg.ish_pl)
    {
        SAFE_COPY_FROM_USER(&ish_pl_data, ipc_arg.ish_pl, sizeof(ish_pl_data));
        ish_pl = &ish_pl_data;
    }

    if (ipc_arg.osh_pl)
    {
        num_osh_block= ipc_arg.io_sizes.osh_size/SEC_HW_MAX_SHAREDMEM;
        if(ipc_arg.io_sizes.osh_size % SEC_HW_MAX_SHAREDMEM)
          num_osh_block +=1;
        osh_pl = (ipc_shmem_t *) OS_ALLOC (num_osh_block*sizeof(ipc_shmem_t));
        VERIFY( osh_pl !=NULL ,exit, rc, SEC_OUT_OF_MEMORY);
    }

    sec_lock_resources(ipc_arg.resources);
    rc = tracker_add_resources(current->tgid, ipc_arg.resources);
    resources_locked = true;

    // Process SEC requests
    if ( ipc_arg.cmd == IPC_54 ||
         ( ipc_arg.cmd == IPC_EXTERNAL_MODULE_CMD &&
           (ipc_arg.module_id & SEC_IPC_54_MODULE_ID_MASK) ==
           SEC_IPC_54_MODULE_ID ) )
    {
        rc = sec_kernel_process_aacs_op(&ipc_arg, ipl, opl, ish_pl);
    } 
    else if (ipc_arg.cmd == IPC_EXTERNAL_MODULE_CMD &&
            (ipc_arg.module_id & SEC_IPC_MODULE_ID_MASK) == SEC_IPC_DTCPIP_MODULE_ID) 
    {
        rc = sec_kernel_process_dtcpip_op(&ipc_arg, ipl, opl, ish_pl);
    } 
    else 
    {
        switch (ipc_arg.cmd)
        {
        case IPC_60:
            if(gchip_info.host_device == PCI_DEVICE_CE5300)
            {
                rc = sec_process_bulk_ipc(&ipc_arg, ipl, opl, ish_pl,osh_pl);
                break;
            }
            else
            {
                rc = sec_kernel_process_3000_op(&ipc_arg, ipl, opl, ish_pl);
                break;  
            }

        case IPC_AES_ENCRYPT_DATA:
        case IPC_AES_DECRYPT_DATA:
        case IPC_AES128_ENCRYPT_DECRYPT_DATA:
        case IPC_CSS_DECRYPT_DATA:
        case IPC_C2_ENCRYPT_DATA:
        case IPC_C2_DECRYPT_DATA:
        case IPC_DES_ENCRYPT_DATA:
        case IPC_DES_DECRYPT_DATA:
        case IPC_ARC4_ENCRYPT_DECRYPT_DATA:
            rc = crypt_dma_op( &ipc_arg, ipl, opl, ish_pl );
            memset((void*)&ish_pl_data, 0, sizeof(ipc_shmem_t));
            break;

        case IPC_MD5_HASH_DATA:
            rc = sec_hash( &ipc_arg,
                            ipl,
                            opl,
                            ish_pl,
                            osh_pl,
                            MD5_BLOCK_SIZE,
                            MD5_DIGEST_SIZE,
                            8);
            break;

        case IPC_SHA_HASH_DATA:
            if (ipl->hash_fw_based.storage_mode == 1 
                && ipl->hash_fw_based.operation == 0)
            {
                /* FW Based INIT */
                VERIFY(opl, exit, rc, SEC_FAIL);

                ipl->hash_fw_based.context =
                    acquire_context_interruptible(SEC_HASH_CONTEXT,
                                                  ipc_arg.resources,
                                                  &resources_locked);

                VERIFY( ipl->hash_fw_based.context < SEC_NUM_CONTEXTS,
                       exit, rc, SEC_FAIL);

                ipc_ret = sec_kernel_ipc(ipc_arg.cmd, ipc_arg.sub_cmd,
                                         ipc_arg.io_sizes, ipl, opl, ish_pl,
                                         osh_pl);
                rc = ipc2sec(ipc_ret);
                
                opl->context_id = ipl->hash_fw_based.context;
            }
            else if (ipl->hash_fw_based.storage_mode == 1
                     && ((ipl->hash_fw_based.operation & 0x01
                          && ipl->hash_fw_based.data_source == 1)
                         || (ipl->hash_fw_based.operation == 2)))
            {
                /* FW Based update w/ key */
                ipc_ret = sec_kernel_ipc(ipc_arg.cmd, ipc_arg.sub_cmd,
                                         ipc_arg.io_sizes, ipl, opl, ish_pl,
                                         osh_pl);
                rc = ipc2sec(ipc_ret);
            }
            else
            {
                rc = sha_hash(&ipc_arg, ipl, opl, ish_pl, osh_pl);
            }
            sec_kernel_copy_to_user(&ipc_arg, opl, osh_pl);
            break;

        case IPC_DH_KEY_EXCHANGE:
            if (ipl->dh_key_exchange.subcommand == 0)
            {
                ipl->dh_key_exchange.context =
                    acquire_context_interruptible(SEC_DH_CONTEXT, ipc_arg.resources,
                                                  &resources_locked);

                VERIFY( ipl->dh_key_exchange.context < SEC_NUM_CONTEXTS,
                       exit, rc, SEC_FAIL);
            }
            /* Fallthrough */

        case IPC_GET_HW_FW_VERSION:
        case IPC_GET_SERIAL_NUMBER:
        case IPC_RSA_ENCRYPT_DATA:
        case IPC_RSA_DECRYPT_DATA:
        case IPC_RSA_SIGN_DATA:
        case IPC_RSA_VERIFY:
        case IPC_LOAD_LARGE_EXPONENT:
        case IPC_CTR_DRBG_RESEED:
        case IPC_CTR_DRBG_GET_RANDOM_DATA:
        case IPC_SET_CLEAR_KEY:
        case IPC_INVALIDATE_KEY:
        case IPC_ECDSA_SIGN:
        case IPC_ECDSA_VERIFY:
        case IPC_EC_ADD_POINT:
        case IPC_EC_SCALAR_MULTIPLY:
        case IPC_PERFORM_EAU_OPERATION:
        case IPC_DES_ENCRYPT_AND_STORE_KEY:
        case IPC_DES_DECRYPT_AND_STORE_KEY:
        case IPC_AES_ENCRYPT_AND_STORE_KEY:
        case IPC_AES_DECRYPT_AND_STORE_KEY:
        case IPC_REWRAP_MODULE_KEYS:
        case IPC_DECRYPT_LOAD_HDCP_KEYS:
        case IPC_HASH_VERIFY_KSV:
        case IPC_WRAP_FLASH_KEY:
        case IPC_55:
        case IPC_56:
        case IPC_57:
        case IPC_58:
        case IPC_GENERATE_KEY:
        case IPC_61:
        case IPC_EXTERNAL_MODULE_CMD_CE4100:
        case IPC_KEY_STORE_PROVISION_WV_ECM:
        case IPC_KEY_STORE_PROVISION_COMPONENT:
        case IPC_KEY_STORE_COPY_TO_REG:
        case IPC_LOAD_MANIFEST:
//        case IPC_LOAD_LARGE_NUMBER:

        //  Trusted Time Base
        case  IPC_INIT_TTB_TYPE1:
        case  IPC_INIT_TTB_TYPE2:
        case  IPC_READ_TTB      :
        case  IPC_UPDATE_TTB    :

        case IPC_EXTERNAL_MODULE_CMD:
        case IPC_85:
        case IPC_87:
            if (ipc_arg.cmd== IPC_CTR_DRBG_GET_RANDOM_DATA)
            {
                __workaround_2754133();
            }
            //Code specific to CIPLUS crypt and autheticate ipc
            if(((ipc_arg.module_id & SEC_IPC_MODULE_ID_MASK) == 
                        SEC_IPC_CIPLUS_MODULE_ID)
                && (ipc_arg.sub_cmd.sc == IPC_SC_2
                    || ipc_arg.sub_cmd.sc == IPC_SC_3))
            {
                rc = crypt_dma_op( &ipc_arg, ipl, opl, ish_pl );
            } 
            //Code specific to multi-part handler
            else if(((ipc_arg.module_id & SEC_IPC_MODULE_ID_MASK) == 
                        SEC_MV_MODULE_ID)
                && (ipc_arg.sub_cmd.sc_multipart == IPC_AES_MULTIPART_ENCRYPT_DATA
                    || ipc_arg.sub_cmd.sc_multipart == IPC_AES_MULTIPART_DECRYPT_DATA))
            {
                rc = aes_multipart_op( &ipc_arg, ipl, opl, ish_pl );
            }
            else if(((ipc_arg.module_id & SEC_IPC_MODULE_ID_MASK) ==
                        SEC_PR2_MODULE_ID))
            {
                if(ipc_arg.sub_cmd.sc_pr2 == IPC_SC_PR2_HASH_VALUE
                        || ipc_arg.sub_cmd.sc_pr2 == IPC_SC_PR2_CALCULATE_OMAC)
                {
                    rc = pr2_multipart_op( &ipc_arg, ipl, opl, ish_pl );
                }
                else if(ipc_arg.sub_cmd.sc_pr2 == IPC_SC_PR2_MULTIPART_DECRYPT)
                {
                    rc = aes_multipart_op( &ipc_arg, ipl, opl, ish_pl );
                }
                else
                {
                
                    ipc_ret = sec_kernel_ipc(ipc_arg.cmd,
                                             ipc_arg.sub_cmd,
                                             ipc_arg.io_sizes, ipl, opl, ish_pl,
                                             osh_pl);
                    rc = ipc2sec(ipc_ret);   
                }                            
            }       
            else if(((ipc_arg.module_id & SEC_IPC_MODULE_ID_MASK) ==
                        SEC_TDP_MODULE_ID) && 
                        (ipc_arg.sub_cmd.sc_tdp == IPC_SC_TDP_LOADCNFG))
            {
                void * config_file_virt_ptr;
                ipl_tdp_load_config_t * ipl_config;
                ipl_config = (ipl_tdp_load_config_t *)ipl;
                config_file_virt_ptr = phys_to_virt(ipl_config->config_file_ptr);
                rc = sec_tdp_conf_semi_trusted_unit(config_file_virt_ptr);
                VERIFY_QUICK(rc == SEC_SUCCESS,exit);
                ipc_ret = sec_kernel_ipc(ipc_arg.cmd, ipc_arg.sub_cmd,
                                         ipc_arg.io_sizes, ipl, opl, ish_pl,
                                         osh_pl);
                rc = ipc2sec(ipc_ret);
            } 
            else
            {
                ipc_ret = sec_kernel_ipc(ipc_arg.cmd, ipc_arg.sub_cmd,
                                         ipc_arg.io_sizes, ipl, opl, ish_pl,
                                         osh_pl);
                rc = ipc2sec(ipc_ret);
            }

            // special case for extended sec fw
            if (ipc_arg.cmd == IPC_58 &&
                ipc_ret == IPC_RET_INVALID_SRC_KEY_PARAM)
            {
                rc = SEC_EXT_FW_INVALID_KEY_ID;
            }
            VERIFY_QUICK(rc == SEC_SUCCESS, exit);

            memset((void*)&ish_pl_data, 0, sizeof(ipc_shmem_t));

            if ((ipc_arg.cmd == IPC_DH_KEY_EXCHANGE)
             && (opl != NULL)
             && (ipl->dh_key_exchange.subcommand == 0))
            {
                 opl->dh_context_id = ipl->dh_key_exchange.context;
            }
            sec_kernel_copy_to_user(&ipc_arg, opl, osh_pl);
            break;

        case IPC_GENERATE_MAC:
            if (ipl->mac_data.mac_flag == 1) //mac_init call
            {
                ipl->mac_data.mac_context_id =
                    acquire_context_interruptible(SEC_MAC_CONTEXT,
                                                  ipc_arg.resources,
                                                  &resources_locked);

                VERIFY( ipl->mac_data.mac_context_id < SEC_NUM_CONTEXTS,
                       exit, rc, SEC_FAIL);
            } //ENDIF initializing MAC
            ipc_ret = sec_kernel_ipc(ipc_arg.cmd, ipc_arg.sub_cmd, ipc_arg.io_sizes, ipl, opl, ish_pl, osh_pl);
            rc = ipc2sec(ipc_ret);
            VERIFY_QUICK(rc == SEC_SUCCESS, exit);
            memset((void*)&ish_pl_data, 0, sizeof(ipc_shmem_t));
            if (ipl->mac_data.mac_flag == 1)
            {
                VERIFY(opl, exit, rc, SEC_FAIL);
                opl->context_id = ipl->mac_data.mac_context_id;
            }
            sec_kernel_copy_to_user(&ipc_arg, opl, osh_pl);
            break;

        case IPC_BULK_STOP:
            ipc_ret = sec_kernel_ipc(0xFFFFFFFF, ipc_arg.sub_cmd, ipc_arg.io_sizes, ipl, opl, ish_pl, osh_pl);
            rc = ipc2sec(ipc_ret);
            VERIFY_QUICK(rc == SEC_SUCCESS, exit);
            sec_kernel_copy_to_user(&ipc_arg, opl, osh_pl);
        break;

        case IPC_AUTH_AND_LOAD_FW_MODULE:
            SEC_ERROR( "IPC_AUTH_AND_LOAD_FW_MODULE has been removed; "
                       "See new FW IOCTL\n");
            rc = SEC_NOT_SUPPORTED;
            break;

        case IPC_ODP_READ_WRITE:
            mutex_lock(&odp_rw_ipc_mutex);
            ipc_ret = sec_kernel_ipc(ipc_arg.cmd, ipc_arg.sub_cmd, ipc_arg.io_sizes, ipl, opl, ish_pl, osh_pl);
            mutex_unlock(&odp_rw_ipc_mutex);
            rc = ipc2sec(ipc_ret);
            VERIFY_QUICK(rc == SEC_SUCCESS, exit);
            sec_kernel_copy_to_user(&ipc_arg, opl, osh_pl);
           break;

        default:
            SEC_ERROR("Unknown IPC command %d\n", ipc_arg.cmd);
            rc = SEC_INTERNAL_ERROR;
            break;
        }
    }

exit:
    //It is possible that the code got here because arg is zero
    if( (arg != 0) && resources_locked)
    {
        sec_unlock_resources(ipc_arg.resources);
        tracker_remove_resources(current->tgid, ipc_arg.resources);
        resources_locked = false;
    }

    /* Release allocated contexts if appropriate. */
    /* NOTE: it is possible to get here from the top where the passed
       in ipl is NULL or arg is zero.  Thus it is necessary to check ipl here */
    if( (arg != 0) && (ipl != NULL) )
    {
        switch (ipc_arg.cmd)
        {
        case IPC_GENERATE_MAC:
            if((ipl->mac_data.mac_flag == 2) || (rc != SEC_SUCCESS))
            {
                sec_release_context_for_client(SEC_MAC_CONTEXT,
                                               ipl->mac_data.mac_context_id);
            }
            break;

        case IPC_DH_KEY_EXCHANGE:
            if (ipl->dh_key_exchange.subcommand != 0 ||
                rc != SEC_SUCCESS)
            {
                sec_release_context_for_client(SEC_DH_CONTEXT,
                                               ipl->dh_key_exchange.context);
            }
            break;

        case IPC_SHA_HASH_DATA:
            if (ipl->hash_fw_based.storage_mode == 1 &&
               (ipl->hash_fw_based.operation == 2 ||
                ipl->hash_fw_based.operation == 3 ||
                rc != SEC_SUCCESS))
            {
                sec_release_context_for_client(SEC_HASH_CONTEXT,
                                               ipl->hash_fw_based.context);
            }
            break;

        default: break;
        } //ENDSWITCH on IPC command
    } //ENDIF ipl is NOT NULL

    if (rc == SEC_OUT_OF_MEMORY)
    {
        SEC_ERROR("SEC ran out of memory\n");
    }
    if(osh_pl)
      OS_FREE(osh_pl);
    return rc;
} /* ENDPROC sec_kernel_ioctl_ipc_call */


//-----------------------------------------------------------------------------
// sec_kernel_ioctl_ipc_call_fb:
//
// Handler for IPC ioctl calls that have fragmented buffers
//
// This function is a variation on sec_kernel_ipc_call() for handling functions
// that use fragmented buffers. It is provided an expanded argument containing
// information about the fragmented buffers so we can build the descriptors.
//
// This function also performs other duties that are also associated with
// sec_kernel_ipc_call(), such as managing the resources, performing the
// requested SEC operation, scoreboard, etc.
//
// Parameter:
//      arg - a structure holding all required input for sec op.
//-----------------------------------------------------------------------------
static sec_result_t sec_kernel_ioctl_ipc_call_fb( uint32_t arg )
{
    sec_result_t        rc = SEC_SUCCESS;
    sec_result_t        rc2= SEC_SUCCESS;
    sec_kernel_fb_t     fb_arg;
    ipl_t               ipl_data;
    opl_t               opl_data;
    ipc_shmem_t         osh_pl_data;
    ipc_shmem_t         ish_pl_data;
    ipl_t       *       ipl         = NULL;
    opl_t       *       opl         = NULL;
    ipc_shmem_t *       osh_pl      = NULL;
    ipc_shmem_t *       ish_pl      = NULL;
    unsigned long       truncate;

    if (!arg)
    {
        SEC_ERROR("Invalid argument passed\n");
        return -EFAULT;
    }

    SAFE_COPY_FROM_USER(&fb_arg, (void*)arg, sizeof(fb_arg));

    if (fb_arg.ipc.ipl)
    {
        SAFE_COPY_FROM_USER(&ipl_data, fb_arg.ipc.ipl, sizeof(ipl_data));
        ipl = &ipl_data;
    }

    if (fb_arg.ipc.opl)
    {
        SAFE_COPY_FROM_USER(&opl_data, fb_arg.ipc.opl, sizeof(opl_data));
        opl = &opl_data;
    }

    if (fb_arg.ipc.ish_pl)
    {
        SAFE_COPY_FROM_USER(&ish_pl_data, fb_arg.ipc.ish_pl, sizeof(ish_pl_data));
        ish_pl = &ish_pl_data;
    }

    if (fb_arg.ipc.osh_pl)
    {
        osh_pl = &osh_pl_data;
    }

    sec_lock_resources(fb_arg.ipc.resources);
    rc = tracker_add_resources(current->tgid, fb_arg.ipc.resources);

    //process SEC requests
    switch ( fb_arg.ipc.cmd )
    {
    case IPC_AES_ENCRYPT_DATA:
    case IPC_AES_DECRYPT_DATA:
    case IPC_CSS_DECRYPT_DATA:
    case IPC_C2_ENCRYPT_DATA:
    case IPC_C2_DECRYPT_DATA:
    case IPC_DES_ENCRYPT_DATA:
    case IPC_DES_DECRYPT_DATA:
    case IPC_ARC4_ENCRYPT_DECRYPT_DATA:
        {
            sec_kernel_addr_t  bfr_type_src = fb_arg.bfr_type_src;
            sec_kernel_addr_t  bfr_type_dst = fb_arg.bfr_type_dst;
            void *             bfr_caller_src = fb_arg.ipc.src;
            void *             bfr_caller_dst = fb_arg.ipc.dst;
            void *             bfr_kernel_src = NULL;
            void *             bfr_kernel_dst = NULL;
            bool               in_place     = false;
            const uint32_t     bfr_size_bytes = ( fb_arg.fragment_count - 1 ) *
                                                fb_arg.fragment_period_bytes +
                                                fb_arg.fragment_length_bytes;

            /* If the types and pointers are the same, we are processing this
             * data in-place */
            if ( bfr_type_src==bfr_type_dst && bfr_caller_src==bfr_caller_dst )
            {
                in_place = true;
            }

            /* If the source buffer is virtual, allocate a contiguous memory
             * space and retrieve its physical address */
            if ( bfr_caller_src && bfr_type_src==SEC_KERNEL_ADDR_VIRTUAL )
            {
                bfr_kernel_src = (void *)OS_ALLOC(bfr_size_bytes);
                if ( bfr_kernel_src == NULL)
                {
                    rc = SEC_OUT_OF_MEMORY;
                }
                else
                {
                    if ( copy_from_user( bfr_kernel_src, bfr_caller_src,
                                         bfr_size_bytes ) )
                    {
                        rc = SEC_FAIL;
                    }
                    else
                    {
                        // TODO - with kernel 2.6.35 physical address pointers
                        // are 64 bits which resulted in a pointer cast problem.
                        // The top 32 bits are not used. As a temporary fix the
                        // address is truncated to 32 bits. The driver needs
                        // to be brought into compliance.
                        //fb_arg.ipc.src = (void *)OS_VIRT_TO_PHYS(
                        //      bfr_kernel_src);
                        truncate = (unsigned long)OS_VIRT_TO_PHYS(
                                bfr_kernel_src);
                        fb_arg.ipc.src = (void *)truncate;
                        fb_arg.bfr_type_src = SEC_KERNEL_ADDR_PHYSCONTIG;
                        /* If we are processing this data in-place, we will be
                         * using the memory we just allocated */
                        if ( in_place )
                        {
                            fb_arg.ipc.dst = fb_arg.ipc.src;
                            fb_arg.bfr_type_dst = SEC_KERNEL_ADDR_PHYSCONTIG;
                            bfr_kernel_dst = bfr_kernel_src;
                        }
                    }
                }
            }

            /* If we are modifying this buffer in place we don't need to
             * allocate a destination; otherwise, allocate a destination */
            if ( rc==SEC_SUCCESS
            &&   bfr_caller_dst && bfr_type_dst==SEC_KERNEL_ADDR_VIRTUAL
            &&   !in_place )
            {
                bfr_kernel_dst = (void *)OS_ALLOC(bfr_size_bytes);
                if ( bfr_kernel_dst )
                {
                    truncate = (unsigned long)OS_VIRT_TO_PHYS(bfr_kernel_dst);
                    fb_arg.ipc.dst = (void *)truncate;
                    fb_arg.bfr_type_dst = SEC_KERNEL_ADDR_PHYSCONTIG;
                }
                else
                {
                    rc = SEC_OUT_OF_MEMORY;
                }
            }

            /* If everything above succeeded, perform the requested operation */
            if ( rc == SEC_SUCCESS )
            {
                rc = crypt_dma_op_fb_phys( &fb_arg, ipl, opl, ish_pl,
                                           bfr_kernel_src, bfr_kernel_dst );
            }
            /* If the caller passed in a non-virtual destination, bfr_kernel_dst
             * will not have been set; otherwise, if we succeeded, copy the
             * processed data in to the original caller's address */
            if ( rc==SEC_SUCCESS && bfr_caller_dst && bfr_kernel_dst )
            {
                if ( copy_to_user( bfr_caller_dst, bfr_kernel_dst, bfr_size_bytes ) )
                {
                    rc = SEC_FAIL;
                }
            }

            /* If we are processing in-place, we only need to free once;
             * Do this by freeing the src (which is where we allocated to) */
            if ( bfr_kernel_dst && bfr_kernel_dst != bfr_kernel_src)
            {
                OS_FREE( bfr_kernel_dst );
            }

            if ( bfr_kernel_src )
            {
                OS_FREE( bfr_kernel_src );
            }
        }
        break;

    default:
        rc = sec_kernel_ioctl_ipc_call( (uint32_t)&((sec_kernel_fb_t *)arg)->ipc );
        break;
    }

//exit:
    sec_unlock_resources(fb_arg.ipc.resources);
    rc2 = tracker_remove_resources(current->tgid, fb_arg.ipc.resources);

    if (rc == SEC_OUT_OF_MEMORY)
    {
        SEC_ERROR("SEC ran out of memory\n");
    }

    return rc;
} /* ENDPROC sec_kernel_ioctl_ipc_call_fb */


//----------------------------------------------------------------------------
// __get_job_id
//
// Wrapper function for SEC_GET_JOB_ID ioctl call
//----------------------------------------------------------------------------
static sec_result_t __get_job_id(uint32_t arg)
{
    uint32_t     jobid;
    sec_result_t rc = SEC_SUCCESS;

    jobid = sec_get_job_id();

    if (copy_to_user((uint32_t*)arg, &jobid, sizeof(uint32_t)))
    {
        rc = SEC_FAIL;
    }

    return rc;
}

//----------------------------------------------------------------------------
// sec_kernel_get_chip_info
//
// Handler for SEC_GET_CHIP_INFO ioctl call
//----------------------------------------------------------------------------
static sec_result_t sec_kernel_get_chip_info(uint32_t arg)
{
    ipl_t ipl;
    opl_t opl;
    sec_ipc_sizes_t io_sizes;
    const sec_fw_subcmd_t  sub_cmd = {.sc = IPC_SC_NOT_USED};
    sec_result_t rc = SEC_SUCCESS;
    sec_ipc_return_t ipcret = IPC_RET_SUCCESS;

    if (!arg)
    {
        SEC_ERROR("Invalid argument passed\n");
        rc = -EFAULT;
        goto exit;
    }

    if(gchip_info.sec_rom_version == 0)
    {
        memset((void*)(&ipl), 0, sizeof(ipl_t));
        memset((void*)(&opl), 0, sizeof(opl_t));
        /* Trim the data transaction sizes between Host and SEC HW to minimum */
        io_sizes.ipl_size = SEC_HW_JUST_IPL_HEADER;
        io_sizes.ish_size = SEC_HW_NO_SHAREDMEM;
        io_sizes.opl_size = SEC_HW_OPL_FW_VERSION;
        io_sizes.osh_size = SEC_HW_NO_SHAREDMEM;
        ipcret = sec_kernel_ipc(IPC_GET_HW_FW_VERSION, sub_cmd, io_sizes, &ipl, &opl, NULL, NULL);
        rc = ipc2sec(ipcret);
        if(rc == SEC_SUCCESS)
        {
            gchip_info.sec_rom_version = opl.filler0[0];
            printk(KERN_INFO "SEC ROM version 0x%08lx\n", gchip_info.sec_rom_version);
        }
        else
        {
            rc = SEC_HW_ROM_VERSION_GET_FAILED;
            printk(KERN_ERR "Failed getting SEC ROM version. SEC HW IPC error=0x%08x\n",ipcret);
        }
    }

    if (copy_to_user((uint32_t*)arg, &gchip_info, sizeof(sec_chip_info_t)))
    {
        rc = SEC_FAIL;
    }
exit:
    return rc;
}
// ---------------------------------------------------------------------------
//                      BEGIN CW Management Infrastructor
// ---------------------------------------------------------------------------

#define CW_TABLE_SIZE 12
#define CW_FREE       -1
#define CW_OFFSET      4

static int   g_cw_enabled = 0;
static pid_t g_primary_cw_table[CW_TABLE_SIZE];  
static pid_t g_secondary_cw_table[CW_TABLE_SIZE];  

/*
//----------------------------------------------------------------------------
// _print_table
//
// For debugging
//----------------------------------------------------------------------------
static void _print_table(int* table)
{
    int i;
    for (i=0; i<CW_TABLE_SIZE; i++)
    {
        printk("%4d %8d\n", i, table[i]);
    }
}
*/

//----------------------------------------------------------------------------
// sec_enable_cw_reservations
//
// Set the global CW checking flag and initize the CW reservation table.
//----------------------------------------------------------------------------
static sec_result_t sec_enable_cw_reservations(uint32_t arg)
{
    int i = 0;
    sec_result_t rc = SEC_SUCCESS;

    sec_lock_resources(SEC_CW_RES);
    if (!g_cw_enabled)
    {
        //printk ("+++ Initialize CM Management +++\n");
        for (i=0; i<CW_TABLE_SIZE; i++)
        {
            g_primary_cw_table[i]   = CW_FREE;
            g_secondary_cw_table[i] = CW_FREE;
        }
        g_cw_enabled = 1;
    }
    sec_unlock_resources(SEC_CW_RES);
    return rc;
}

//----------------------------------------------------------------------------
// _reserve_cw_in_range
//
// Helper function. Reserve a control word if it is open within a range. 
// Return error if not.
//----------------------------------------------------------------------------
static sec_result_t _reserve_cw_in_range(pid_t* table, 
                                         pid_t  thread_id, 
                                         int    index_start,
                                         int    index_end,
                                         int*   assigned)
{
    int             i  = 0;
    sec_result_t    rc = SEC_SUCCESS;

    *assigned = CW_FREE;
    for (i=index_start; i<=index_end; i++)
    {
        // Found a free slot
        if (table[i] == CW_FREE)
        {
            table[i] = thread_id;
            if (i < CW_OFFSET)        // Its a CCW
            {
                *assigned = SEC_CCW1 + i;
            }
            else                      // Its a CW
            {
               *assigned = SEC_CW1 + i - CW_OFFSET;
            }
            break;
        }
    }

    // No free slot found
    if (*assigned == CW_FREE)
    {
        rc = SEC_OUT_RESOURCES;
    }
    return rc;
}

//----------------------------------------------------------------------------
// _reserve_cw
//
// Helper function. Reserve a control word if it is open. Return error if not.
//----------------------------------------------------------------------------
static sec_result_t _reserve_cw(pid_t* table, 
                                pid_t  thread_id, 
                                int    requested,
                                int*   assigned)
{
  //    int             i  = 0;
    sec_result_t    rc = SEC_SUCCESS;

    // Reserve a specific CCW
    if (requested >= SEC_CCW1 && requested <= SEC_CCW4)
    {
        rc = _reserve_cw_in_range (table, 
                                   thread_id, 
                                   requested - SEC_CCW1, 
                                   requested - SEC_CCW1,
                                   assigned);
    }

    // Reserve a specific CW
    else if (requested >= SEC_CW1 && requested <= SEC_CW8)
    {
        rc = _reserve_cw_in_range (table, 
                                   thread_id, 
                                   requested - SEC_CW1 + CW_OFFSET, 
                                   requested - SEC_CW1 + CW_OFFSET,
                                   assigned);
    }

    // Reserve any in a range
    else
    {
        switch (requested)
        {
            case SEC_CCW_ANY:
                rc = _reserve_cw_in_range 
                     (table, thread_id, 0, CW_OFFSET - 1, assigned);
                break;
            case SEC_CW_ANY:
                rc = _reserve_cw_in_range 
                     (table, thread_id, CW_OFFSET, CW_TABLE_SIZE - 1, assigned);
                break;
             case SEC_CCW_CW_ANY:
                rc = _reserve_cw_in_range 
                         (table, thread_id, 0, CW_OFFSET - 1, assigned);
                if (rc == SEC_OUT_RESOURCES)
                {
                    rc = _reserve_cw_in_range 
                             (table, thread_id, CW_OFFSET, CW_TABLE_SIZE - 1, 
                              assigned);
                }
                break;
        default:
            rc = SEC_INVALID_KEY_ID;
            goto exit;
        }
    }
 
 exit:
    return rc;
}

//----------------------------------------------------------------------------
// _garbage_collect_cw
//
// Helper function. Release any CWs from inactive threads.
//----------------------------------------------------------------------------
static sec_result_t _garbage_collect_cw(pid_t* table)
{
    int                i         = 0;
    sec_result_t       rc        = SEC_SUCCESS;

    for (i=0; i<CW_TABLE_SIZE; i++)
    {
        if (!find_task_by_vpid (table[i]))
        {
            table[i] = CW_FREE;
        }
    }


    return rc;
}

//----------------------------------------------------------------------------
// sec_reserve_cw
//
// Reserve a control word if it is open. First garbage collect if not.
// If still not open, return error.
//----------------------------------------------------------------------------
static sec_result_t sec_reserve_cw(uint32_t arg)
{
    sec_kernel_cw_request_t payload;
    pid_t*                  table = NULL;
    sec_result_t            rc = SEC_SUCCESS;
 
    sec_lock_resources(SEC_CW_RES);
    SAFE_COPY_FROM_USER(&payload, (void*)arg, sizeof(payload));

    // Get the CW table for the given key ladder
    switch (payload.key_ladder_id)
    {
        case SEC_PRIMARY_KEY_LADDER:
            table = g_primary_cw_table;
            break;
        case SEC_SECONDARY_KEY_LADDER:
            table = g_secondary_cw_table;
            break;
        default:
            rc = SEC_INVALID_KEY_LADDER;
            goto exit;
    }

    // Reserve a CW in the given table
    rc = _reserve_cw(table, 
                     current->tgid, 
                     payload.requested, 
                     &(payload.assigned));
    
    // If the CW isn't available, garbage collect and try again
    if (rc == SEC_OUT_RESOURCES)
    {
        rc = _garbage_collect_cw(table);
        rc = _reserve_cw(table, 
                         current->tgid,
                         payload.requested, 
                         &(payload.assigned));
    }

    if (rc != SEC_SUCCESS)
    {
        goto exit;
    }


    SAFE_COPY_TO_USER((void*)arg, &payload, sizeof(payload));
    /*
    printk ("+++ Requested 0x%x on keyladder %d - assigned 0x%x +++\n", 
            payload.requested, payload.key_ladder_id, payload.assigned);
    _print_table(table);
    */

 exit:
    sec_unlock_resources(SEC_CW_RES);
    return rc;
}

//----------------------------------------------------------------------------
// sec_release_cw
//
// Release a control word if reserved on this thread. Return error if not.
//----------------------------------------------------------------------------
static sec_result_t sec_release_cw(uint32_t arg)
{
    sec_kernel_cw_request_t payload;
    pid_t*                  table = NULL;
    int                     index = 0;
    sec_result_t            rc = SEC_SUCCESS;
 
    sec_lock_resources(SEC_CW_RES);
    SAFE_COPY_FROM_USER(&payload, (void*)arg, sizeof(payload));

    // map from key ladder id to key ladder table
    switch (payload.key_ladder_id)
    {
        case SEC_PRIMARY_KEY_LADDER:
            table = g_primary_cw_table;
            break;
        case SEC_SECONDARY_KEY_LADDER:
            table = g_secondary_cw_table;
            break;
        default:
            rc = SEC_INVALID_KEY_LADDER;
            goto exit;
    }

    // map from CW enumeration to table index
    if (payload.requested >= SEC_CCW1 && payload.requested <= SEC_CCW4)
    {
        index = payload.requested - SEC_CCW1;
    }
    else if (payload.requested >= SEC_CW1 && payload.requested <= SEC_CW8)
    {
        index = payload.requested - SEC_CW1 + CW_OFFSET;
    }
    else
    {
        rc = SEC_INVALID_KEY_ID;
        goto exit;
    }
    
    // free the table entry
    if (table[index] == current->tgid)
    {
        table[index] = CW_FREE;
    }
    else
    {
        rc = SEC_INVALID_KEY_ID;
        goto exit;
    }

    /*
    printk ("+++ Release CW 0x%x on key ladder %d at  index %d +++\n", 
            payload.requested, payload.key_ladder_id, index);
    _print_table(table);
    */

 exit:
    sec_unlock_resources(SEC_CW_RES);
    return rc;
}

//----------------------------------------------------------------------------
// sec_do_i_own_cw
//
// Return true if this thread own the control word. If control word checking
// isn't enabled return true for backward compatibility.
//----------------------------------------------------------------------------
static sec_result_t sec_do_i_own_cw(uint32_t arg)
{
    sec_kernel_cw_request_t payload;
    pid_t*                  table = NULL;
    int                     index = 0;
    sec_result_t            rc = SEC_SUCCESS;

    sec_lock_resources(SEC_CW_RES);
    SAFE_COPY_FROM_USER(&payload, (void*)arg, sizeof(payload));

    // if cw checking is not enabled, just return true 
    if (!g_cw_enabled)
    {
        payload.owned = 1;
        // printk("+++ CW Managment is not enabled so return true. +++\n");
    }

    // checking is enabled, so check the reservation table for ownership
    else
    {
        switch (payload.key_ladder_id)
        {
            case SEC_PRIMARY_KEY_LADDER:
                table = g_primary_cw_table;
                break;
            case SEC_SECONDARY_KEY_LADDER:
                table = g_secondary_cw_table;
                break;
            default:
                rc = SEC_INVALID_KEY_LADDER;
                goto exit;
        }

        // map from CW enumeration to table index
        if (payload.requested >= SEC_CCW1 && payload.requested <= SEC_CCW4)
        {
            index = payload.requested - SEC_CCW1;
        }
        else if (payload.requested >= SEC_CW1 && payload.requested <= SEC_CW8)
        {
            index = payload.requested - SEC_CW1 + CW_OFFSET;
        }
        else
        {
            rc = SEC_INVALID_KEY_ID;
            goto exit;
        }
    
        // check table entry
        payload.owned = table[index] == current->tgid;

        // printk ("+++ Do I own 0x%x?   %d +++\n", 
        //        payload.requested, payload.owned);
    }

    SAFE_COPY_TO_USER((void*)arg, &payload, sizeof(payload));

 exit:
    sec_unlock_resources(SEC_CW_RES);
    return rc;
}

// ---------------------------------------------------------------------------
//                      END CW Management Infrastructor
// ---------------------------------------------------------------------------

// Structure used to bind an ioctl command to a function
typedef struct
{
    unsigned int command;
    sec_result_t (*fn)(uint32_t arg);
} sec_ioctl_cmd_t;


// Table of ioctl commands with corresponding function names
static sec_ioctl_cmd_t sec_ioctls[] =
{
    { SEC_IOCSIPCCALL     , sec_kernel_ioctl_ipc_call    },
    { SEC_IPC_FRAGMENTED  , sec_kernel_ioctl_ipc_call_fb },
    { SEC_MUNMAP_CALL     , __sec_munmap_call            },
    { SEC_ALLOC_MEM_CALL  , __sec_alloc_mem              },
    { SEC_FREE_MEM_CALL   , __sec_free_mem               },
    { SEC_GET_JOB_ID,       __get_job_id                 },
    { SEC_GET_TGID,         __sec_get_tgid               },
    { SEC_GET_CHIP_INFO,    sec_kernel_get_chip_info     },
    { SEC_FW,               sec_fw_ioctl_handler         },
    { SEC_GET_TDP_INFO,     sec_get_tdp_handler          },
    { SEC_GET_EAU_LOCK,     sec_get_eau_lock             },
    { SEC_RELEASE_EAU_LOCK, sec_release_eau_lock         },
    { SEC_ALLOC_PAGES_CALL, __sec_alloc_pages            },
    { SEC_FREE_PAGES_CALL,  __sec_free_pages             },
    { SEC_CREATE_DMA_DESC,  sec_kernel_create_dma_desc   },
    { SEC_FREE_DMA_DESC,    sec_kernel_free_dma_desc     },
    { SEC_AES_SMD_TO_DMA,   sec_kernel_smd_to_dma        },
    { SEC_DMA_CLEANUP,      sec_kernel_dma_cleanup       },
    { SEC_ENABLE_CW_RESER,  sec_enable_cw_reservations   },
    { SEC_RESERVE_CW,       sec_reserve_cw               },
    { SEC_RELEASE_CW,       sec_release_cw               },
    { SEC_DO_I_OWN_CW,      sec_do_i_own_cw              },
    {0, NULL}, // NULL terminated list
};


//-----------------------------------------------------------------------------
// sec_kernel_unlocked_ioctl
//
// Sec driver ioctl routine.
//-----------------------------------------------------------------------------
static
long sec_kernel_unlocked_ioctl(struct file *    fd,
                               unsigned int     command,
                               unsigned long    arg)
{
    int rc = SEC_FAIL;
    sec_ioctl_cmd_t * entry = &sec_ioctls[0];
    int got_ioctl = 0;

    /* Make sure the ioctl isn't locked by power management */
    if (sec_pm_get_ioctl() != SEC_SUCCESS)
    {
        /* The IOCTL is locked by power management */
        if (entry->command == SEC_FW)
        {
             /* If this is a FW command it may be a load to RAM
              * request; allow it through. The FW IOCTL handler
              * will limit/reject other  transactions */
              got_ioctl = 0;
        }
        else
        {
            rc = SEC_PM_INVALID_STATE;
            goto exit;
        }
    }
    else
        got_ioctl = 1;

    // Go through list of all known commands and find needed function
    while (entry->fn)
    {
        if(entry->command == command)
        {
            rc = entry->fn(arg);
            break;
        }
        entry++;
    }

    /* Return the ioctl ref count; because this IOCTL could have
     * come from the suspend handler, we may not actually have the lock */
    if (got_ioctl)
        sec_pm_put_ioctl();

exit:
    return rc;
}

MODULE_AUTHOR ("Intel Corporation, (C) 2008-2012 - All Rights Reserved");
MODULE_LICENSE ("Dual BSD/GPL");
module_init (sec_kernel_init);
module_exit (sec_kernel_exit);
