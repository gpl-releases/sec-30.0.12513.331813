/*-----------------------------------------------------------------------------
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2010-2012 Intel Corporation. All rights reserved.
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
#include "x86_cache.h"
#include "osal.h"
#include "sec_kernel.h"
#include "sec_kernel_types.h"
#include "sec_hal.h"






//-----------------------------------------------------------------------------
// Translate an IPC return type to a sec driver return type.
//-----------------------------------------------------------------------------
sec_result_t ipc2sec_3000(sec_ipc_return_t ipc_ret)
{
    sec_result_t result;

    result = ipc2sec(ipc_ret);
  
    return result;
}


//-----------------------------------------------------------------------------
// crypt_dma_op
//
// Encrypt/decrypt using DMA to transfer data to/from firmware
//-----------------------------------------------------------------------------
//static
sec_result_t crypt_dma_op_3000(sec_kernel_ipc_t *  ipc_arg,
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
    uint32_t               dma_stf_flag;
    sec_dma_descriptor_t * desc        = NULL;
    sec_dma_descriptor_t * temp_desc = NULL;
    uint32_t               residual_size;
    void *                 residual_block = NULL;

    VERIFY(ipl != NULL, exit, rc, SEC_FAIL);

    block_size = AES_BLOCK_SIZE;
    TX         = SEC_AES_TX_FIFO;
    RX         = SEC_AES_RX_FIFO;

    
    switch(ipc_arg->src_dst_buf_type )
    {
        case SEC_KERNEL_ADDR_PHYSCONTIG:

            desc = (sec_dma_descriptor_t *) OS_ALLOC(sizeof(sec_dma_descriptor_t));
            VERIFY( desc != NULL, exit, rc, SEC_OUT_OF_MEMORY);

            dma_stf_flag = SEC_DMA_STF_FLAGS
                            | SEC_DMA_FLAG_DST_LL 
                            | SEC_DMA_FLAG_SRC_LL;

            desc->next        = 0;
            desc->size        = ipc_arg->src_size;
            desc->src         = (uint32_t)ipc_arg->src;
            desc->dst         = (uint32_t)ipc_arg->dst;
            desc->dma_flags   = dma_stf_flag;

            if(g_fast_path)
            {
                cache_flush_buffer((void*)desc, sizeof(sec_dma_descriptor_t));
                cache_flush_buffer((void*)phys_to_virt((uint32_t)ipc_arg->src), sizeof(ipc_arg->src_size));
                cache_flush_buffer((void*)phys_to_virt((uint32_t)ipc_arg->dst), sizeof(ipc_arg->dst_size));
            }

            ipl->ipc_sc_60_13.dma_descriptor = OS_VIRT_TO_PHYS(desc);
            ipl->ipc_sc_60_13.sub_cmd = ipc_arg->sub_cmd.sc_60;

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
            break;
            
        case SEC_KERNEL_ADDR_VIRTUAL:

            residual_size = ipc_arg->src_size % AES_BLOCK_SIZE;

            residual_block = (sec_dma_descriptor_t *) OS_ALLOC(AES_BLOCK_SIZE);
            VERIFY( residual_block != NULL, exit, rc, SEC_OUT_OF_MEMORY);

            OS_MEMSET(residual_block, 0, AES_BLOCK_SIZE);
            OS_MEMCPY(residual_block, (void*)ipc_arg->src+ipc_arg->src_size-residual_size, residual_size);

            dma_stf_flag = SEC_DMA_STF_FLAGS
                            | SEC_DMA_FLAG_DST_LL 
                            | SEC_DMA_FLAG_SRC_LL;

            // If both src and dst buffers are DWORD aligned, use direct I/O to
            // process the data.  Otherwise, use buffered I/O.
            if ((((uint32_t)ipc_arg->src & 0x3) == 0)
            &&  (((uint32_t)ipc_arg->dst & 0x3) == 0))
            {
                user_buf_t  src;
                user_buf_t  dst;
        
                desc = (sec_dma_descriptor_t *) OS_ALLOC(
                        sizeof(sec_dma_descriptor_t));
                VERIFY( desc != NULL, exit, rc, SEC_OUT_OF_MEMORY);
                desc->next        = 0;
                desc->size        = residual_size;
                desc->src         = OS_VIRT_TO_PHYS(residual_block);
                desc->dst         = OS_VIRT_TO_PHYS(residual_block);
                desc->dma_flags   = dma_stf_flag;

                if(g_fast_path)
                {
                    cache_flush_buffer((void*)desc, sizeof(sec_dma_descriptor_t));
                    cache_flush_buffer((void*)residual_block, AES_BLOCK_SIZE);
                }

                rc = sec_kernel_user_buf_lock( &src,
                                    (sec_address_t) ipc_arg->src,
                                    ipc_arg->src_size-residual_size,
                                    USER_BUF_RO);
                VERIFY_QUICK(rc == SEC_SUCCESS, exit);
        
                rc = sec_kernel_user_buf_lock( &dst,
                                    (sec_address_t) ipc_arg->dst,
                                    ipc_arg->dst_size-residual_size,
                                    USER_BUF_RW);
                if (rc != SEC_SUCCESS)
                {
                    sec_kernel_user_buf_unlock( &src );
                    goto exit;
                }
        
                // Create DMA descriptors to perform the operation.
                phys_src_desc = sec_kernel_map_vm_for_dma_rw(&src, &dst, block_size, TX, RX, ipc_arg->cmd);
                if (phys_src_desc != NULL)
                {
                    if (desc)
                    {
                        temp_desc = phys_src_desc;

                        while (temp_desc != NULL)
                        {
                           if (temp_desc->next == 0)
                           {
                                temp_desc->next= OS_VIRT_TO_PHYS(desc);
                                break;
                           }
                           else
                            temp_desc = phys_to_virt(temp_desc->next);
                        }
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

                    ipl->ipc_sc_60_13.dma_descriptor = OS_VIRT_TO_PHYS(phys_src_desc);
                    ipl->ipc_sc_60_13.sub_cmd = ipc_arg->sub_cmd.sc_60;

                    ipc_ret = sec_kernel_ipc( ipc_arg->cmd,
                                              ipc_arg->sub_cmd,
                                              ipc_arg->io_sizes,
                                              ipl,
                                              opl,
                                              ish_pl,
                                              NULL);
                    sec_kernel_free_descriptor_list(phys_src_desc);
                }
        
                if (desc)
                {
                    OS_MEMCPY ((void*)ipc_arg->src+ipc_arg->src_size-residual_size, residual_block, residual_size);
                }
                sec_kernel_user_buf_unlock( &src );
                sec_kernel_user_buf_unlock( &dst );
        
                VERIFY(phys_src_desc != NULL, exit, rc, SEC_FAIL);
            }
            else
            {
                // The source and destination buffers are not both DWORD-aligned.
                // We need to copy each page of data to an aligned buffer
                uint32_t src = (uint32_t) ipc_arg->src;
                uint32_t dst = (uint32_t) ipc_arg->dst;
                int      remaining;
                uint32_t data_size;
        
                src_data = (void *)OS_ALLOC(PAGE_SIZE);
                dst_data = (void *)OS_ALLOC(PAGE_SIZE);
                desc = (sec_dma_descriptor_t *) OS_ALLOC(sizeof(sec_dma_descriptor_t));
                VERIFY(src_data != NULL, exit, rc, SEC_OUT_OF_MEMORY);
                VERIFY(dst_data != NULL, exit, rc, SEC_OUT_OF_MEMORY);
                VERIFY( desc != NULL, exit, rc, SEC_OUT_OF_MEMORY);
        
                for (remaining=ipc_arg->src_size; remaining; remaining -= data_size)
                {
                    OS_MEMSET(src_data, 0, PAGE_SIZE);
                    data_size = (remaining >= PAGE_SIZE) ? PAGE_SIZE : remaining;
                    copy_from_user(src_data, (void*)src, data_size);
                    dma_stf_flag = SEC_DMA_STF_FLAGS | SEC_DMA_FLAG_DST_INT;
        
                    residual_size = data_size % AES_BLOCK_SIZE;
                    if (residual_size != 0)
                        desc->size = data_size + AES_BLOCK_SIZE - residual_size;
                    else 
                        desc->size        = data_size;

                    desc->next        = 0;
                    desc->src         = OS_VIRT_TO_PHYS(src_data);;
                    desc->dst         = OS_VIRT_TO_PHYS(dst_data);
                    desc->dma_flags   = dma_stf_flag;
                    if(g_fast_path)
                    {
                        cache_flush_buffer((void*)desc, sizeof(sec_dma_descriptor_t));
                        cache_flush_buffer((void*)src_data, sizeof(data_size));
                        cache_flush_buffer((void*)dst_data, sizeof(data_size));
                    }
        
                    ipl->ipc_sc_60_13.dma_descriptor = OS_VIRT_TO_PHYS(desc);
                    ipl->ipc_sc_60_13.sub_cmd = ipc_arg->sub_cmd.sc_60;

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
        
                    //copy output data back to user buffer
                    copy_to_user((void *)dst, dst_data, data_size);

                    
                    src += data_size;
                    dst += data_size;
                }
            }//else

            if (ipc_ret == IPC_RET_COMMAND_COMPLETE)
            {
                sec_kernel_copy_to_user(ipc_arg, opl, NULL);
            }
            rc = ipc2sec(ipc_ret);
            break;
        default: 
           rc = SEC_FAIL;
           break;
    } //case
    

exit:

    if (desc) { OS_FREE(desc); }
    if (src_data) { OS_FREE(src_data); }
    if (dst_data) { OS_FREE(dst_data); }
    if (residual_block) { OS_FREE(residual_block); }

    return rc;
}



//-----------------------------------------------------------------------------
// sec_kernel_process_aacs_op
//
// Function to process AACS operations.
//-----------------------------------------------------------------------------
sec_result_t
sec_kernel_process_3000_op(sec_kernel_ipc_t *  ipc_arg,
                           ipl_t *             ipl,
                           opl_t *             opl,
                           ipc_shmem_t *       ish_pl)
{
    sec_ipc_return_t  ipc_result;
    sec_result_t      result;

    VERIFY(ipl != NULL, exit, result, SEC_FAIL);

    if (ipc_arg->cmd != IPC_60)
    {
        SEC_ERROR("Invalid IPC command\n");
        result = SEC_INTERNAL_ERROR;
        goto exit;
    }

    switch (ipc_arg->sub_cmd.sc_60)
    {

        case IPC_SC_60_13:
            result = crypt_dma_op_3000(ipc_arg, ipl, opl, ish_pl );
            return result;

        default:
            ipc_result = sec_kernel_ipc(ipc_arg->cmd,
                                    ipc_arg->sub_cmd,
                                    ipc_arg->io_sizes,
                                    ipl,
                                    opl,
                                    NULL,
                                    NULL);
            if (ipc_result == IPC_RET_COMMAND_COMPLETE)
            {
                sec_kernel_copy_to_user(ipc_arg, opl, NULL);
            }
            break;

    }

    result = ipc2sec_3000(ipc_result);
exit:
    return result;
}
