/*-----------------------------------------------------------------------------
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2012 Intel Corporation. All rights reserved.
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
 * Copyright(c) 2012 Intel Corporation. All rights reserved.
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
#include <linux/types.h>
#include <linux/kernel.h>

#include "x86_cache.h"
#include "sec_kernel.h"
#include "sec_kernel_types.h"
#include "sec_kernel_multipart.h"

#define PMR_TYPE_CMP_VIDEO 7

//-----------------------------------------------------------------------------
// form_sfaf_sg_list
//
// This method forms the scatter-gather list understood by SEC firmware.
// This is the sequence of steps:
//      1. Lock physical pages corresponding to virtual memory by using
//         get_user_pages Linux Kernel API.
//      2. Alloc memory for a scatter-gather element
//      3. Set physical start address, length and various parameters in the 
//         scatter-gather element.
//      4. get_user_pages returns a reference to every page found in 
//         vir_buffer - vir+buffer+vir_buffer_size range. Whereas, SEC needs
//         a SG list with elements which are contiguous, irrespective of page 
//         boundaries. Therefore, we need additional manipulation for this.
//      5. Loop 2(by expanding memory for SG list) & 3 until all the physical
//         pages are covered.
//-----------------------------------------------------------------------------
static 
sec_result_t form_sfaf_sg_list(user_buf_t * user_buffer,
                                sec_address_t vir_buffer, 
                                unsigned long vir_buffer_size,
                                int write,
                                sfaf_mem_ptr_t **sg_list,
                                unsigned int    *sg_count )
{
    sec_result_t rc = SEC_SUCCESS;
    int xfer_size = 0;
    int num_pages_processed = 0;  //to keep track of pages returned by get_user_pages API
    bool need_another_sg_entry = true; //to keep track of elements in SG list provided to SEC

    sfaf_mem_ptr_t * new_sg_list = NULL;
    int new_sg_count = 0;
    unsigned long* sg_args = NULL;

    VERIFY( sg_list != NULL, exit, rc, SEC_NULL_POINTER);
    VERIFY( sg_count != NULL, exit, rc, SEC_NULL_POINTER);
    
    //Step 1 : get_user_pages API call
    rc = sec_kernel_user_buf_lock( user_buffer, 
            (sec_address_t) vir_buffer,
            vir_buffer_size,
            write);
    VERIFY_QUICK(rc == SEC_SUCCESS, exit);

    //We traverse the 'user_buffer' list returned by get_user_pages kernel API,
    while (need_another_sg_entry)
    {
        //Step 2: realloc memory for a additional sfaf_const_mem_ptr data structure and 
        //update it's variables
        new_sg_count = (*sg_count) + 1;
        new_sg_list = (sfaf_mem_ptr_t*) OS_ALLOC(sizeof(sfaf_mem_ptr_t) * (new_sg_count));
        VERIFY( new_sg_list != NULL, exit, rc, SEC_OUT_OF_MEMORY);

        if (*sg_list)
        {
            memcpy(new_sg_list, *sg_list, sizeof(sfaf_mem_ptr_t) * (new_sg_count -1));
            OS_FREE(*sg_list);
        }
        //Update the method output pointers
        *sg_count = new_sg_count;
        *sg_list = new_sg_list;

        //Step 3: Set SG elements
        xfer_size = PWU_MIN(user_buffer->page_bytes, user_buffer->size);
        new_sg_list[new_sg_count - 1].address = (void*)(user_buffer->page_addr + user_buffer->offset);
        new_sg_list[new_sg_count - 1].length  = xfer_size;
        new_sg_list[new_sg_count - 1].external = 1;  
        new_sg_list[new_sg_count - 1].swap = 1;      
        new_sg_list[new_sg_count - 1].pmr_type = 0;     
        new_sg_list[new_sg_count - 1].rsvd = 0;

        //swap the endianness for SEC
        sg_args = (unsigned long *)&(new_sg_list[new_sg_count - 1].external);
        sg_args[0] = bswap(sg_args[0]); 

        need_another_sg_entry = false;
        num_pages_processed++;

        if (num_pages_processed == user_buffer->num_pages)
        {
            //we are done processing the buffer...get out now
            goto exit;
        }

        //Step 4: get_user_pages returns a reference to every page found in 
        //vir_buffer - vir+buffer+vir_buffer_size range. Whereas, SEC needs
        //a SG list with elements which are contiguous, irrespective of page 
        //boundaries. Therefore, we need additional manipulation for this.
        rc = user_buf_advance( user_buffer, xfer_size);
        VERIFY_QUICK(rc == SEC_SUCCESS , exit);
        xfer_size = PWU_MIN(user_buffer->page_bytes, user_buffer->size);
        while ((num_pages_processed < user_buffer->num_pages) && (!need_another_sg_entry))
        {
            //navigate through for every page in user_buf_t
            if ((void*)(user_buffer->page_addr + user_buffer->offset) != 
                    (new_sg_list[new_sg_count - 1].address + new_sg_list[new_sg_count - 1].length))
            {
                //until you finish the list or the page's start address is not next to previous page's end address
                //generate another sfaf_const_mem_ptr data structure and follow the process
                need_another_sg_entry = true;
            }
            else
            {
                new_sg_list[new_sg_count - 1].length += xfer_size;
                num_pages_processed++;

                if (num_pages_processed == user_buffer->num_pages)
                {
                    //we are done processing the buffer...get out now
                    goto exit;
                }

                rc = user_buf_advance( user_buffer, xfer_size);
                VERIFY_QUICK(rc == SEC_SUCCESS , exit);
                xfer_size = PWU_MIN(user_buffer->page_bytes, user_buffer->size);
            }
        }
    }

exit:
    return rc;
}


//-----------------------------------------------------------------------------
// find_pa_of_smd_memory
//
// This method traverses the current process's VMA list and search for the VMA 
// in which the SMD virtual address falls. It then calculate the physical address
// corresponding to that virtual address and returns that address.
//-----------------------------------------------------------------------------
static 
uint32_t find_pa_of_smd_memory(uint32_t smd_vaddr)
{
    struct mm_struct *mm;
    struct vm_area_struct *pvma;
    uint32_t    smd_paddr = 0;

    mm = current->mm;
    pvma = mm->mmap;

    // Unlock this memory's lock flag
    down_write(&mm->mmap_sem);
    pvma = find_vma(mm, smd_vaddr);
    if (pvma)
    {
        //TODO : Do we also need to verify the length of the buffer provided by host??
        if ((smd_vaddr >= pvma->vm_start) && (smd_vaddr < pvma->vm_end))
        {
            //printk("using kernel method: vm_pgoff 0x%lx, start 0x%lx, end 0x%lx, vm_flags 0x%lx\n",
            //         pvma->vm_pgoff, pvma->vm_start, pvma->vm_end, pvma->vm_flags);
            smd_paddr = ((pvma->vm_pgoff) << PAGE_SHIFT) + (smd_vaddr - pvma->vm_start);
        }
    }
    up_write(&mm->mmap_sem);

    return smd_paddr;
}

//-----------------------------------------------------------------------------
// get_aes_sg_list_from_smd_contig_memory
//
// Utility method for forming the scatter-gather list for multipart AES 
// buffers from SMD memory which is contiguous in DRAM.
//-----------------------------------------------------------------------------
static 
sec_result_t get_aes_sg_list_from_smd_contig_memory(sec_multipart_buff_list_t *buff_list, 
                                          int read_write,
                                          int encrypted_parts,
                                          sfaf_mem_ptr_t **sg_list,
                                          unsigned int   *sg_count )
{
    sec_result_t rc = SEC_SUCCESS;
    int i = 0;      //index for a part in multipart list
    int j = 0;
    unsigned long* sg_args = NULL;
    sec_addr_t  vir_addr = 0;
    sec_addr_t  phy_addr = 0;
   
    *sg_count = 0;
    *sg_list = NULL;

    if (!buff_list)
        goto exit;

    *sg_count = encrypted_parts;
    *sg_list = (sfaf_mem_ptr_t*) OS_ALLOC(sizeof(sfaf_mem_ptr_t) * (*sg_count));
    VERIFY( *sg_list != NULL, exit, rc, SEC_OUT_OF_MEMORY);
    memset(*sg_list, 0, sizeof(sfaf_mem_ptr_t) * (*sg_count));

    for(i =0, j = 0; i < buff_list->nParts; i++)
    {
        if ( buff_list->part[i].copyonly == 0)      //deals with AES parts only
        {
            vir_addr = (sec_address_t)(read_write == USER_BUF_RO ?
                        buff_list->part[i].src_buffer : buff_list->part[i].dst_buffer);

            phy_addr = find_pa_of_smd_memory(vir_addr);
            VERIFY( phy_addr != 0, exit, rc, SEC_FAIL);
    
            (*sg_list)[j].address = (void*)(phy_addr);
            (*sg_list)[j].length  = buff_list->part[i].size_bytes;
            (*sg_list)[j].external = 1;  
            (*sg_list)[j].swap = 1;      
            (*sg_list)[j].pmr_type = (read_write == USER_BUF_RO) ? 0 : PMR_TYPE_CMP_VIDEO;     
            (*sg_list)[j].rsvd = 0;

            //swap the endianness for SEC
            sg_args = (unsigned long *)&((*sg_list)[j].external);
            sg_args[0] = bswap(sg_args[0]); 

            j++;
        }
    }

exit: 
    return rc;
}


//-----------------------------------------------------------------------------
// get_aes_sg_list_from_non_contig_memory
//
// Utility method for forming the scatter-gather list for multipart AES 
// buffers which are non-contiguous in DRAM.
//-----------------------------------------------------------------------------
static 
sec_result_t get_aes_sg_list_from_non_contig_memory(sec_multipart_buff_list_t *buff_list, 
                                   int read_write,
                                   int encrypted_parts,
                                   user_buf_t     **user_buf_list,
                                   sfaf_mem_ptr_t **sg_list,
                                   unsigned int   *sg_count )
{
    sec_result_t rc = SEC_SUCCESS;
    user_buf_t  * user_buff = NULL;
    int i = 0;      //index for a part in multipart list
    int j = 0;      //index for a user_buf_t in user_buf_list
    sec_address_t vir_addr;
   
    *sg_count = 0;
    *sg_list = NULL;

    if (!encrypted_parts)
        goto exit;

    *user_buf_list = (user_buf_t*)OS_ALLOC (sizeof(user_buf_t) * encrypted_parts);
    VERIFY( *user_buf_list != NULL, exit, rc, SEC_OUT_OF_MEMORY);
    memset(*user_buf_list, 0, (sizeof(user_buf_t) * encrypted_parts));

    for(i =0; i < buff_list->nParts; i++)
    {
        if ( buff_list->part[i].copyonly == 0)      //deals with AES parts
        {
            user_buff = ((user_buf_t*)(*user_buf_list) + j);
            j++;
            vir_addr = (sec_address_t)(read_write == USER_BUF_RO ?
                        buff_list->part[i].src_buffer : buff_list->part[i].dst_buffer);
            rc = form_sfaf_sg_list( user_buff,
                    vir_addr,
                    buff_list->part[i].size_bytes,
                    read_write,
                    sg_list,
                    sg_count );
            VERIFY_QUICK( rc == SEC_SUCCESS, exit);
        }
    }

exit: 
    return rc;
}

//-----------------------------------------------------------------------------
// get_copy_sg_list_from_non_contig_memory
//
// Utility method for forming the scatter-gather list for multipart copy 
// buffers which are non-contiguous in DRAM.
//-----------------------------------------------------------------------------
static 
sec_result_t get_copy_sg_list_from_non_contig_memory(sec_multipart_buff_list_t *buff_list, 
                                    int read_write,
                                    int copy_parts,
                                    user_buf_t     **user_buf_list,
                                    sfaf_mem_ptr_t **sg_list,
                                    unsigned int   *sg_count )
{
    sec_result_t rc = SEC_SUCCESS;
    user_buf_t  * user_buff = NULL;
    int i = 0;      //index for a part in multipart list
    int j = 0;      //index for a user_buf_t in user_buf_list
    sec_address_t vir_addr;

    *sg_count = 0;
    *sg_list = NULL;

    if (!copy_parts)
        goto exit; 

    *user_buf_list = (user_buf_t*)OS_ALLOC (sizeof(user_buf_t) * copy_parts);
    VERIFY( *user_buf_list != NULL, exit, rc, SEC_OUT_OF_MEMORY);
    memset(*user_buf_list, 0, (sizeof(user_buf_t) * copy_parts));

    for(i =0; i < buff_list->nParts; i++)
    {
        if ( buff_list->part[i].copyonly == 1)      //deals with ONLY copy parts
        {
            user_buff = ((user_buf_t*)(*user_buf_list) + j);
            j++;
            vir_addr = (sec_address_t)(read_write == USER_BUF_RO ?
                        buff_list->part[i].src_buffer : buff_list->part[i].dst_buffer);
            rc = form_sfaf_sg_list( user_buff,
                    vir_addr,
                    buff_list->part[i].size_bytes,
                    read_write,
                    sg_list,
                    sg_count );
            VERIFY_QUICK( rc == SEC_SUCCESS, exit);
        }
    }

exit:
    return rc;
}


//-----------------------------------------------------------------------------
// get_copy_sg_list_from_smd_contig_memory
//
// Utility method for forming the scatter-gather list for multipart copy 
// buffers from SMD memory which is contiguous in DRAM.
//-----------------------------------------------------------------------------
static 
sec_result_t get_copy_sg_list_from_smd_contig_memory(sec_multipart_buff_list_t *buff_list, 
                                          int read_write,
                                          int copy_parts,
                                          sfaf_mem_ptr_t **sg_list,
                                          unsigned int   *sg_count )
{
    sec_result_t rc = SEC_SUCCESS;
    int i = 0;      //index for a part in multipart list
    int j = 0;
    unsigned long* sg_args = NULL;
    sec_addr_t  phy_addr = 0;
    sec_addr_t  vir_addr = 0;
   
    *sg_count = 0;
    *sg_list = NULL;

    if (!buff_list)
        goto exit;

    *sg_count = copy_parts;
    *sg_list = (sfaf_mem_ptr_t*) OS_ALLOC(sizeof(sfaf_mem_ptr_t) * (*sg_count));
    VERIFY( *sg_list != NULL, exit, rc, SEC_OUT_OF_MEMORY);
    memset(*sg_list, 0, sizeof(sfaf_mem_ptr_t) * (*sg_count));

    for(i =0, j = 0; i < buff_list->nParts; i++)
    {
        if ( buff_list->part[i].copyonly == 1)      //deals with COPY parts only
        {
            vir_addr = (sec_address_t)(read_write == USER_BUF_RO ?
                        buff_list->part[i].src_buffer : buff_list->part[i].dst_buffer);

            phy_addr = find_pa_of_smd_memory(vir_addr);
            VERIFY( phy_addr != 0, exit, rc, SEC_FAIL);
    
            (*sg_list)[j].address = (void*)(phy_addr);
            (*sg_list)[j].length  = buff_list->part[i].size_bytes;
            (*sg_list)[j].external = 1;  
            (*sg_list)[j].swap = 1;     
            (*sg_list)[j].pmr_type = (read_write == USER_BUF_RO) ? 0 : PMR_TYPE_CMP_VIDEO;     
            (*sg_list)[j].rsvd = 0;

            //swap the endianness for SEC
            sg_args = (unsigned long *)&((*sg_list)[j].external);
            sg_args[0] = bswap(sg_args[0]); 

            j++;
        }
    }

exit: 
    return rc;
}


//-----------------------------------------------------------------------------
// get_copy_sg_list_from_smd_contig_memory
//
// Utility method for calling the respective methods for forming the 
// scatter-gather list.
//-----------------------------------------------------------------------------
static
sec_result_t  get_sg_list(sec_multipart_buff_list_t * multipart_list,
                     bool aes_part,
                     bool read_write,
                     uint32_t   nParts,
                     user_buf_t   **user_buf_list,
                     sfaf_mem_ptr_t **sg_list,
                     unsigned int   *sg_count )
{
    sec_result_t        rc = SEC_FAIL;
    sec_buffer_type_t   buffer_type;

    buffer_type = (read_write == USER_BUF_RO) ? multipart_list->src_buffer_type :
                    multipart_list->dst_buffer_type;
    
    if (aes_part)
    {
        if (buffer_type == SEC_BUFFER_NONCONTIG)
        {
            rc = get_aes_sg_list_from_non_contig_memory(multipart_list, read_write, nParts, 
                    user_buf_list, sg_list,  sg_count);
        }
        else
        {
            rc = get_aes_sg_list_from_smd_contig_memory(multipart_list, read_write, nParts, 
                    sg_list,  sg_count);
        }
    }
    else
    {
        if (buffer_type == SEC_BUFFER_NONCONTIG)
        {
            rc = get_copy_sg_list_from_non_contig_memory(multipart_list, read_write, nParts, 
                    user_buf_list, sg_list,  sg_count);
        }
        else
        {
            rc = get_copy_sg_list_from_smd_contig_memory(multipart_list, read_write, nParts, 
                    sg_list,  sg_count);
        }

    }
    VERIFY_QUICK( rc == SEC_SUCCESS, exit);

    //Handle TDP mode by flushing the SG list buffers
    if(g_fast_path)
    {
        if ((*sg_list) && (*sg_count))
        {
            cache_flush_buffer(*sg_list, (*sg_count) * sizeof(sfaf_mem_ptr_t));
        }
    }

exit:
    return rc;
}

//-----------------------------------------------------------------------------
// get_copy_sg_list_from_smd_contig_memory
//
// Utility method for freeing the user_buf_t memory
//-----------------------------------------------------------------------------
static
void  free_user_buffer_list( user_buf_t * user_buf_list, uint32_t nParts)
{
    uint32_t    i = 0;

    if (user_buf_list)
    {
        for(i =0; i < nParts; i++)
        {
            sec_kernel_user_buf_unlock( (user_buf_t*)(user_buf_list + i));
        }
        OS_FREE(user_buf_list); 
    }
}
 
//-----------------------------------------------------------------------------
// aes_multipart_op
//
// This method forms the payload for Multipart AES CTR decryption IPC.
// There are 4 scatter-gather lists provided to SEC firmware for processing:
//      1. aes_src_sg_list -- List of physical buffers which contain AES-CTR
//         encrypted media content.
//      2. aes_dst_sg_list -- List of physical PMR buffers where SEC will put 
//         AES-CTR decrypted media content.
//      3. copy_src_sg_list -- List of physical buffers which contain plaintext
//         media headers.
//      4. copy_dst_sg_list -- List of physical buffers where SEC will copy
//         plaintext media headers.
//-----------------------------------------------------------------------------
sec_result_t aes_multipart_op(sec_kernel_ipc_t * ipc_arg,
                              ipl_t *            ipl,
                              opl_t *            opl,
                              ipc_shmem_t *      ish_pl )
{
    sec_result_t        rc      = SEC_INVALID_INPUT;
    sec_ipc_return_t    ipc_ret = IPC_RET_COMMAND_COMPLETE;

    sfaf_mem_ptr_t * aes_src_sg_list = NULL;
    unsigned int     aes_src_sg_list_count = 0;
    user_buf_t     * aes_src_user_buf_list = NULL;

    sfaf_mem_ptr_t * aes_dst_sg_list = NULL;
    unsigned int     aes_dst_sg_list_count = 0;
    user_buf_t     * aes_dst_user_buf_list = NULL;

    sfaf_mem_ptr_t * copy_src_sg_list = NULL;
    unsigned int     copy_src_sg_list_count = 0;
    user_buf_t     * copy_src_user_buf_list = NULL;

    sfaf_mem_ptr_t * copy_dst_sg_list = NULL;
    unsigned int     copy_dst_sg_list_count = 0;
    user_buf_t     * copy_dst_user_buf_list = NULL;

    int encrypted_parts = 0;
    int i = 0;

    sec_multipart_buff_list_t * multipart_list = (sec_multipart_buff_list_t *)
        (phys_to_virt(ipl->aes_crypt_multipart.multipart_data.multipart_list));

    if (!multipart_list)
        goto exit;

    for(i =0; i < multipart_list->nParts; i++)
    {
        if (multipart_list->part[i].copyonly == false)
            encrypted_parts++;
    }

    if (!encrypted_parts)
        goto exit;


    //Form AES content source scatter-gather list
    rc =  get_sg_list( multipart_list, true, USER_BUF_RO, encrypted_parts,
                &aes_src_user_buf_list, &aes_src_sg_list,  &aes_src_sg_list_count);
    VERIFY_QUICK( rc == SEC_SUCCESS, exit);
    ipl->aes_crypt_multipart.sg_data.aes_src_sg = 
        (aes_src_sg_list_count != 0) ? (uint32_t)OS_VIRT_TO_PHYS(aes_src_sg_list) : 0;
    ipl->aes_crypt_multipart.sg_data.aes_src_sg_count = aes_src_sg_list_count;

    //Form AES content destination scatter-gather list
    rc =  get_sg_list( multipart_list, true, USER_BUF_RW, encrypted_parts,
                &aes_dst_user_buf_list, &aes_dst_sg_list,  &aes_dst_sg_list_count);
    VERIFY_QUICK( rc == SEC_SUCCESS, exit);
    ipl->aes_crypt_multipart.sg_data.aes_dst_sg = 
        (aes_dst_sg_list_count != 0) ?  (uint32_t)OS_VIRT_TO_PHYS(aes_dst_sg_list) : 0;
    ipl->aes_crypt_multipart.sg_data.aes_dst_sg_count = aes_dst_sg_list_count;

    //Form COPY content source scatter-gather list
    rc =  get_sg_list( multipart_list, false, USER_BUF_RO, multipart_list->nParts - encrypted_parts,
                &copy_src_user_buf_list, &copy_src_sg_list,  &copy_src_sg_list_count);
    VERIFY_QUICK( rc == SEC_SUCCESS, exit);
    ipl->aes_crypt_multipart.sg_data.copy_src_sg = 
        (copy_src_sg_list_count != 0) ?  (uint32_t)OS_VIRT_TO_PHYS(copy_src_sg_list) : 0;
    ipl->aes_crypt_multipart.sg_data.copy_src_sg_count = copy_src_sg_list_count;

    //Form COPY content destination scatter-gather list
    rc =  get_sg_list( multipart_list, false, USER_BUF_RW, multipart_list->nParts - encrypted_parts,
                &copy_dst_user_buf_list, &copy_dst_sg_list,  &copy_dst_sg_list_count);
    VERIFY_QUICK( rc == SEC_SUCCESS, exit);
    ipl->aes_crypt_multipart.sg_data.copy_dst_sg = 
        (copy_dst_sg_list_count != 0) ?  (uint32_t)OS_VIRT_TO_PHYS(copy_dst_sg_list) : 0;
    ipl->aes_crypt_multipart.sg_data.copy_dst_sg_count = copy_dst_sg_list_count;

    //provide the SG list to FW
    ipc_ret = sec_kernel_ipc( ipc_arg->cmd,
            ipc_arg->sub_cmd,
            ipc_arg->io_sizes,
            ipl,
            opl,
            ish_pl,
            NULL);

    if (ipc_ret == IPC_RET_COMMAND_COMPLETE)
    {
        sec_kernel_copy_to_user(ipc_arg, opl, NULL);
    }
    rc = ipc2sec(ipc_ret);

exit:
    //Free up all the resources allocated above
    free_user_buffer_list( aes_src_user_buf_list, encrypted_parts);
    free_user_buffer_list( aes_dst_user_buf_list, encrypted_parts);
    free_user_buffer_list( copy_src_user_buf_list, multipart_list->nParts - encrypted_parts);
    free_user_buffer_list( copy_dst_user_buf_list, multipart_list->nParts - encrypted_parts);

    OS_FREE(aes_src_sg_list); 
    OS_FREE(aes_dst_sg_list); 
    OS_FREE(copy_src_sg_list); 
    OS_FREE(copy_dst_sg_list); 

    return rc;
}

/* FIXME: This should probably moved to a better place */


sec_result_t pr2_multipart_op(sec_kernel_ipc_t * ipc_arg,
                              ipl_t *            ipl,
                              opl_t *            opl,
                              ipc_shmem_t *      ish_pl )
{
    sec_ipc_return_t    ipc_ret = IPC_RET_COMMAND_COMPLETE;
    sec_result_t rc = SEC_SUCCESS;
    sec_address_t buf_addr;
    uint32_t buf_size = 0;

    uint32_t sg_count = 0;
    user_buf_t *user_buf_list = NULL;
    sfaf_mem_ptr_t *sg_list = NULL;

    buf_addr = (sec_address_t) ipc_arg->src;
    buf_size = ipc_arg->src_size;

    if(buf_addr && buf_size)
    {
        /* Enter here only if we have to do scatter gather */
        user_buf_list = (user_buf_t*)OS_ALLOC (sizeof(user_buf_t));
        VERIFY( user_buf_list != NULL, exit, rc, SEC_OUT_OF_MEMORY);
        memset(user_buf_list, 0, (sizeof(user_buf_t)));

        rc = form_sfaf_sg_list( user_buf_list,
                buf_addr,
                buf_size,
                USER_BUF_RO,
                &sg_list,
                &sg_count );
        
        VERIFY_QUICK( rc == SEC_SUCCESS, exit);
#if 0        
        {
            int i;
            sfaf_mem_ptr_t *temp = sg_list;
            for(i=0; i<sg_count; i++)
            {
                pv(temp[i].address, temp[i].length);
            }
        }
#endif
        // Put the scatter gather list in the ipl
        if(ipc_arg->sub_cmd.sc_pr2 == IPC_SC_PR2_CALCULATE_OMAC)
        {
            ipl->pr2_sg_op.pr2_calc_omac.pr2_sg_data_start = (uint32_t) OS_VIRT_TO_PHYS(sg_list);
            ipl->pr2_sg_op.pr2_calc_omac.pr2_sg_data_count = sg_count;
        }
        else if(ipc_arg->sub_cmd.sc_pr2 == IPC_SC_PR2_HASH_VALUE)
        {
            ipl->pr2_sg_op.pr2_hash_value.pr2_sg_data_start = (uint32_t) OS_VIRT_TO_PHYS(sg_list);
            ipl->pr2_sg_op.pr2_hash_value.pr2_sg_data_count = sg_count;
        }
    }

    ipc_ret = sec_kernel_ipc(ipc_arg->cmd,
                             ipc_arg->sub_cmd,
                             ipc_arg->io_sizes,
                             ipl,
                             opl,
                             ish_pl,
                             NULL);
    rc = ipc2sec(ipc_ret);

exit: 
    free_user_buffer_list( user_buf_list, 1);
    OS_FREE(sg_list);
    return rc;
}
