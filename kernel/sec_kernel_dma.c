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
#include <linux/delay.h> /* This has the define for ssleep */
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/time.h>
#include <linux/spinlock_types.h>
#include <linux/spinlock.h>
#include <asm/page.h>
#include <asm/uaccess.h>
#include <stdarg.h>
#include <linux/pci.h>

#include "clock_control.h"
#include "sec_hal.h"
#include "x86_cache.h"
#include "sec_kernel.h"
#include "sec_types.h"
#include "sec_common_types.h"
#include "sec_kernel_share_types.h"
#include "sec_dma_tracker.h"

typedef struct
{
    sec_fw_cmd_t    cmd;
    sec_fw_subcmd_t sub_cmd;
    uint32_t        resources;
    sec_dma_chain_t dma_chain;
    sec_ipc_sizes_t io_sizes;
    ipl_t          *ipl;
    ipc_shmem_t    *ish_pl;
    opl_t          *opl;
    ipc_shmem_t    *osh_pl;
    sec_buffer_t   *src;
    sec_buffer_t   *dst;
} sec_kernel_smd_dma_ipc_t;


//-----------------------------------------------------------------------------
// sec_kernel_dma_cleanup
//
// This function handles the SEC_DMA_CLEANUP ioctl.
// It is called by the user library's sec_dev_close function 
//
//-----------------------------------------------------------------------------
sec_result_t sec_kernel_dma_cleanup(uint32_t arg)
{
    unsigned int   tgid;

    tgid = (unsigned int)current->tgid;
    dma_tracker_garbage_collect(tgid);
    return SEC_SUCCESS;
}

//-----------------------------------------------------------------------------
// sec_kernel_create_dma_desc
//
// This function handles the SEC_CREATE_DMA_DESC ioctl.  This function creates
// a sec_dma_descriptor_t for a given user space virtual address. 
//
//-----------------------------------------------------------------------------
sec_result_t sec_kernel_create_dma_desc(uint32_t arg)
{
    sec_result_t   rc = SEC_SUCCESS;
    unsigned int   tgid;
    sec_dma_mem_t  dma_mem;

    if (!arg)
    {
        SEC_ERROR("Invalid argument passed\n");
        return -EFAULT;
    }

    SAFE_COPY_FROM_USER(&dma_mem, (void*)arg, sizeof(dma_mem));
    tgid = (unsigned int)current->tgid;

#ifdef DEBUG_CREATE_DMA_DESC
    printk(KERN_INFO "\n====== Input sec_dma_mem_t structure to sec_kernel_create_dma_desc  ======\n");
    show_dma_mem(&dma_mem);
    printk(KERN_INFO "\n==========================================================================\n");
#endif

    rc=dma_tracker_add_node(tgid, &dma_mem);

#ifdef DEBUG_CREATE_DMA_DESC
    printk(KERN_INFO "sec_kernel_create_dma_desc: dma_tracker_add_node returned 0x%04x\n\n",(unsigned short)rc);
#endif

    return rc;
}


//-----------------------------------------------------------------------------
// sec_kernel_free_dma_desc
//
// This function handles the SEC_FREE_DMA_DESC ioctl.  This function frees the
// DMA descriptor and associated locks for a given sec_dma_descriptor for a
// given user space virtual address.
//-----------------------------------------------------------------------------
sec_result_t sec_kernel_free_dma_desc(uint32_t arg)
{
    sec_result_t          rc;
    sec_dma_mem_t         dma_mem;

    if (!arg)
    {
        SEC_ERROR("Invalid argument passed\n");
        return -EFAULT;
    }

    rc = SEC_SUCCESS;

    SAFE_COPY_FROM_USER(&dma_mem, (void*)arg, sizeof(dma_mem));
    rc=dma_tracker_remove_node((unsigned int)current->tgid, &dma_mem);

    return rc;
}


//---------------------------------------------------------------------
// sec_kernel_smd_to_dma
//
// Processes the SEC_AES_SMD_TO_DMA ioctl. 
// The "arg" is a pointer to a sec_kernel_smd_dma_ipc_t structure 
// defined in sec/kernel/sec_kernel_share_types.h. It has pointers
// to a source and a destination sec_buffer_t. The sec_buffer_t
// structure is defined in sec/include/sec_types.h. 
//---------------------------------------------------------------------
sec_result_t sec_kernel_smd_to_dma(uint32_t arg)
{
    sec_result_t   rc = SEC_SUCCESS;
    sec_result_t  rc2 = SEC_SUCCESS;
    sec_kernel_smd_dma_ipc_t  smd_dma;
    sec_buffer_t        src;
    sec_buffer_t        dst;
    ipl_t               ipl_data;
    opl_t               opl_data;
    ipc_shmem_t         osh_pl_data;
    ipc_shmem_t         ish_pl_data;
    ipl_t              *ipl    = NULL;
    opl_t              *opl    = NULL;
    ipc_shmem_t        *osh_pl = NULL;
    ipc_shmem_t        *ish_pl = NULL;
    sec_dma_descriptor_t *pdesc= NULL;
    sec_dma_descriptor_t *list = NULL;
    sec_dma_mem_t      *pdmamem= NULL;
    sec_dma_mem_t       dmamem;
    sec_ipc_return_t    ipc_ret= IPC_RET_SUCCESS;
    uint32_t    src_size= 0;
    uint32_t    dst_size= 0;

    if (!arg)
    {
        SEC_ERROR("Invalid argument passed\n");
        return -EFAULT;
    }

    SAFE_COPY_FROM_USER(&smd_dma, (void*)arg, sizeof(smd_dma));

    if(smd_dma.src == NULL)
    {
        return SEC_DMA_SRC_NULL_POINTER;
    }

    if(smd_dma.dst == NULL)
    {
        return SEC_DMA_DST_NULL_POINTER;
    }

    if(smd_dma.ipl == NULL)
    {
        return SEC_DMA_DST_NULL_POINTER;
    }

    SAFE_COPY_FROM_USER(&src, smd_dma.src, sizeof(src));
    SAFE_COPY_FROM_USER(&dst, smd_dma.dst, sizeof(dst));

    OS_MEMSET( (void*)(&dmamem), 0, sizeof(dmamem));

    if (smd_dma.ipl)
    {
        SAFE_COPY_FROM_USER(&ipl_data, smd_dma.ipl, sizeof(ipl_data));

        dst_size = ipl_data.aes_crypt.dma_info.dst_size;
        src_size = ipl_data.aes_crypt.dma_info.src_size;

        if((src.addr_type == SEC_ADDR_PHYSCONTIG)
        && (dst.addr_type == SEC_ADDR_VIRTUAL))
        {
            dmamem.dma_type = SEC_SMD_TO_DMA;
        }
        else if((src.addr_type == SEC_ADDR_VIRTUAL)
             && (dst.addr_type == SEC_ADDR_PHYSCONTIG))
        {
            dmamem.dma_type = SEC_DMA_TO_SMD;
        }
        else if((src.addr_type == SEC_ADDR_VIRTUAL)
             && (dst.addr_type == SEC_ADDR_VIRTUAL))
        {
            dmamem.dma_type = SEC_DMA_TO_DMA;
        }
        else if((src.addr_type == SEC_ADDR_PHYSCONTIG)
             && (dst.addr_type == SEC_ADDR_PHYSCONTIG))
        {
            dmamem.dma_type = SEC_SMD_TO_SMD;
        }
        else
        {
            SEC_ERROR("Invalid source or destination memory type argument passed\n");
            return -EFAULT;
        }

        dmamem.cmd = smd_dma.cmd;
        // Assume Long Term chain until sec_dma_node_t is found
        dmamem.dma_chain = SEC_DMA_DESC_LT;

        switch(dmamem.dma_type)
        {
          case SEC_SMD_TO_DMA:
            //Set start of the source physical buffer and size
            ipl_data.aes_crypt.dma_info.src_start = (smd_dma.src)->addr.phys;
            ipl_data.aes_crypt.dma_info.src_size = src_size;

            dmamem.dma_size = dst_size;
            dmamem.dma_src_addr = (void*)((smd_dma.src)->addr.phys);
            dmamem.dma_dst_addr = (smd_dma.dst)->addr.virt;
            pdmamem = dma_tracker_verify(&dmamem);
            if(pdmamem == NULL)
            {
                return SEC_DMA_NO_NODES_FOR_TGID;
            }
            else
            {
                //ELSE get to use exiting DMA descriptors and pages
                pdesc = (pdmamem->dma_info.dma_desc);
                if(pdesc != NULL)
                {
                    ipl_data.aes_crypt.dma_info.dma_flags = pdesc->dma_flags;
                    ipl_data.aes_crypt.dma_info.next_descriptor = pdesc->next;
                    ipl_data.aes_crypt.dma_info.dst_start = pdesc->dst;
                    ipl_data.aes_crypt.dma_info.dst_size = pdesc->size;
                }
            }
            break;
          case SEC_DMA_TO_SMD:
            //Set start of the destination physical buffer and size
            ipl_data.aes_crypt.dma_info.dst_start = (smd_dma.dst)->addr.phys;
            ipl_data.aes_crypt.dma_info.dst_size = dst_size;

            dmamem.dma_size = src_size;
            dmamem.dma_src_addr = (smd_dma.src)->addr.virt;
            dmamem.dma_dst_addr = (void*)((smd_dma.dst)->addr.phys);
            pdmamem = dma_tracker_verify(&dmamem);
            if(pdmamem == NULL)
            {
                return SEC_DMA_NO_NODES_FOR_TGID;
            }
            else
            {
                //ELSE get to use exiting DMA descriptors and pages
                ipl_data.aes_crypt.dma_info.next_descriptor = (uint32_t)(pdmamem->dma_info.dma_desc);
                pdesc = (pdmamem->dma_info.dma_desc);
                if(pdesc != NULL)
                {
                    ipl_data.aes_crypt.dma_info.dma_flags = pdesc->dma_flags;
                    ipl_data.aes_crypt.dma_info.next_descriptor = pdesc->next;
                    ipl_data.aes_crypt.dma_info.src_start = pdesc->src;
                    ipl_data.aes_crypt.dma_info.src_size = pdesc->size;
                }
            }
            break;
          case SEC_DMA_TO_DMA:
            dmamem.dma_size = src_size;
            dmamem.dma_src_addr = (smd_dma.src)->addr.virt;
            dmamem.dma_dst_addr = (smd_dma.dst)->addr.virt;
            pdmamem = dma_tracker_verify(&dmamem);
            if(pdmamem == NULL)
            {
                return SEC_DMA_NO_NODES_FOR_TGID;
            }
            else
            {
                //ELSE get to use exiting DMA descriptors and pages
                pdesc = (pdmamem->dma_info.dma_desc);
                if(pdesc != NULL)
                {
                    ipl_data.aes_crypt.dma_info.dma_flags = pdesc->dma_flags;
                    ipl_data.aes_crypt.dma_info.next_descriptor = pdesc->next;
                    ipl_data.aes_crypt.dma_info.src_start = pdesc->src;
                    ipl_data.aes_crypt.dma_info.dst_start = pdesc->dst;
                    ipl_data.aes_crypt.dma_info.src_size = pdesc->size;
                    ipl_data.aes_crypt.dma_info.dst_size = pdesc->size;
                }
            }
            break;
          case SEC_SMD_TO_SMD:
            //Set start of the source physical buffer and size
            ipl_data.aes_crypt.dma_info.src_start = (smd_dma.src)->addr.phys;
            ipl_data.aes_crypt.dma_info.src_size = src_size;

            //Set start of the destination physical buffer and size
            ipl_data.aes_crypt.dma_info.dst_start = (smd_dma.dst)->addr.phys;
            ipl_data.aes_crypt.dma_info.dst_size = dst_size;

            // Both buffers are physical addresses
            dmamem.dma_size = ipl_data.aes_crypt.dma_info.src_size;
            dmamem.dma_src_addr = (void*)((smd_dma.src)->addr.phys);
            dmamem.dma_dst_addr = (void*)((smd_dma.dst)->addr.phys);
            pdmamem = dma_tracker_verify(&dmamem);
            if(pdmamem == NULL)
            {
                return SEC_DMA_NO_NODES_FOR_TGID;
            }
            else
            {
                //ELSE get to use exiting DMA descriptors and pages
                pdesc = (pdmamem->dma_info.dma_desc);
                if(pdesc != NULL)
                {
                    ipl_data.aes_crypt.dma_info.dma_flags = pdesc->dma_flags;
                    ipl_data.aes_crypt.dma_info.next_descriptor = pdesc->next;
                }
            }
            break;
          default:
            SEC_ERROR("Invalid source-destination memory type combination\n");
            return -EFAULT;
        } //ENDSWITCH on DMA type

        if(g_fast_path)
        {
            list=pdesc;
            while(list!=NULL)
            {
                cache_flush_buffer(phys_to_virt(list->src), list->size);
                cache_flush_buffer(phys_to_virt(list->dst), list->size);
                cache_flush_buffer((void*)list, sizeof(sec_dma_descriptor_t));
                list = list->next ? phys_to_virt(list->next) : NULL;
            }
        } 

#ifdef DEBUG_SMD_TO_DMA
        printk(KERN_INFO "\n======sec_kernel_smd_to_dma===I=N=P=U=T===P=A=Y=L=O=A=D======\n");
        printk(KERN_INFO "ipl_data.aes_crypt.dma_info.dma_flags=0x%08x\n",
                   ipl_data.aes_crypt.dma_info.dma_flags);
        printk(KERN_INFO "ipl_data.aes_crypt.dma_info.next_descriptor=0x%08x\n",
                   ipl_data.aes_crypt.dma_info.next_descriptor);
        printk(KERN_INFO "ipl_data.aes_crypt.dma_info.src_start= 0x%08x\n",
                   ipl_data.aes_crypt.dma_info.src_start);
        printk(KERN_INFO "ipl_data.aes_crypt.dma_info.dst_start= 0x%08x\n",
                   ipl_data.aes_crypt.dma_info.dst_start);
        printk(KERN_INFO "ipl_data.aes_crypt.dma_info.src_size = 0x%08x\n",
                   ipl_data.aes_crypt.dma_info.src_size);
        printk(KERN_INFO "ipl_data.aes_crypt.dma_info.dst_size = 0x%08x\n",
                   ipl_data.aes_crypt.dma_info.dst_size);
        printk(KERN_INFO "======sec_kernel_smd_to_dma===I=N=P=U=T===P=A=Y=L=O=A=D======\n\n");
#endif

        ipl = &ipl_data;
    }
    else
    {
        SEC_ERROR("Command input payload is NULL\n");
        return -EFAULT;
    }

    if (smd_dma.opl)
    {
        SAFE_COPY_FROM_USER(&opl_data, smd_dma.opl, sizeof(opl_data));
        opl = &opl_data;
    }

    if (smd_dma.ish_pl)
    {
        SAFE_COPY_FROM_USER(&ish_pl_data, smd_dma.ish_pl, sizeof(ish_pl_data));
        ish_pl = &ish_pl_data;
    }

    if (smd_dma.osh_pl)
    {
        osh_pl = &osh_pl_data;
    }

    sec_lock_resources(smd_dma.resources);
    rc = dma_tracker_add_resources(current->tgid, smd_dma.resources);

#ifdef DEBUG_SMD_TO_DMA
    printk(KERN_INFO "sec_kernel_smd_to_dma: sending command to SEC HW\n");
    printk(KERN_INFO "=======================================================================\n\n");
#endif
    ipc_ret = sec_kernel_ipc( smd_dma.cmd, smd_dma.sub_cmd, smd_dma.io_sizes,
                              ipl, opl, ish_pl, NULL);
    rc = ipc2sec(ipc_ret);
    sec_unlock_resources(smd_dma.resources);
    rc2 = dma_tracker_remove_resources(current->tgid, smd_dma.resources);

    return rc;
} //ENDPROC sec_kernel_smd_to_dma

