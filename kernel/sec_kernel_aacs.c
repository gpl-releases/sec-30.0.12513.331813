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
#include "osal.h"
#include "sec_kernel.h"
#include "sec_kernel_types.h"
#include "sec_hal.h"
#include "sec_fw_context_manager.h"

#define SEC_AACS_MODULE_ID  0x00002000ul
fcm_kernel_context* aacs_context = NULL;


//TODO: move allocation of contexts into library. add needed ioctls. keep only
//pointer here. With current implementation, what if app dies without deleting
//aacs context?
// AACS contexts

//-----------------------------------------------------------------------------
// sec_kernel_aacs_deinit
//
// Function to free AACS resources
//-----------------------------------------------------------------------------
void sec_kernel_aacs_deinit()
{
    fcm_free_kernel_context(aacs_context);
}


//-----------------------------------------------------------------------------
// sec_kernel_aacs_init
//
// Function to allocate and initialize AACS resources
//-----------------------------------------------------------------------------
int sec_kernel_aacs_init()
{
    int i = 0;
    aacs_context = fcm_create_kernel_context(SEC_AACS_MODULE_ID,
                                             IPC_SC_54_2,
                                             SEC_MAX_AACS_CONTEXT);
    if(NULL == aacs_context)
    {
        SEC_ERROR("Could not allocate AACS kernel context\n");
        i = 1;
    }

    return i;
}

//-----------------------------------------------------------------------------
// Translate an IPC return type to a sec driver return type.
//-----------------------------------------------------------------------------
sec_result_t ipc2sec_aacs(sec_ipc_return_t ipc_ret)
{
    sec_result_t result;

    switch (ipc_ret)
    {

    /*  This IPC_RET_* is returned by AACSProcessCCVDRecordHeader if the failure
     *  is a result of the record does not apply (i.e. decryption does not yield
     *  0xDEADBEEF).  We want to capture this special case so we can set the
     *  corresponding flag in the API function accordingly.  */
    case IPC_RET_54_INVALID_INPUT:
        SEC_DEBUG( "IPC return code: 0x%08lx\n", (unsigned long)ipc_ret );
        result = SEC_INVALID_INPUT;
        break;

    case IPC_RET_54_INVALID_VARIANT:
        SEC_DEBUG( "IPC return code: 0x%08lx\n", (unsigned long)ipc_ret );
        result = SEC_INVALID_VARIANT;

    /*  All others are processed by the generic IPC return codes:  */
    default:
        result = ipc2sec(ipc_ret);
        break;
    }
    return result;
}


//-----------------------------------------------------------------------------
// sec_kernel_process_aacs_op
//
// Function to process AACS operations.
//-----------------------------------------------------------------------------
sec_result_t
sec_kernel_process_aacs_op(sec_kernel_ipc_t *  ipc_arg,
                           ipl_t *             ipl,
                           opl_t *             opl,
                           ipc_shmem_t *       ish_pl)
{
    sec_ipc_return_t  ipc_result;
    sec_result_t      result;
    ipl_t *           ipl_list  = NULL;
    unsigned char *   data = NULL;

    VERIFY(ipl != NULL, exit, result, SEC_FAIL);

    if ( ipc_arg->cmd != IPC_54 && ipc_arg->cmd != IPC_EXTERNAL_MODULE_CMD )
    {
        SEC_ERROR("Invalid IPC command\n");
        result = SEC_INTERNAL_ERROR;
        goto exit;
    }

    switch (ipc_arg->sub_cmd.sc_54)
    {
    case IPC_SC_54_1:
        if(aacs_context->internal_session_sema.count > 0)
        {
            data = (unsigned char *)OS_ALLOC(AACS_CONTEXT_SIZE);
            VERIFY(data != NULL, exit, result, SEC_OUT_OF_MEMORY);
            ipl->aacs_create_ctx.context_memory_pointer =
                                        OS_VIRT_TO_PHYS(data);

            //create a SEC AACS context
            ipc_result = sec_kernel_ipc(ipc_arg->cmd,
                                        ipc_arg->sub_cmd,
                                        ipc_arg->io_sizes,
                                        ipl,
                                        opl,
                                        NULL,
                                        NULL);
            if (ipc_result == IPC_RET_COMMAND_COMPLETE)
            {
                //copy the SEC output payload to the user specified buffer
                sec_kernel_copy_to_user(ipc_arg, opl, NULL);
                if(fcm_create_internal_session(aacs_context,
                                               opl->context_id,
                                               false,
                                               data) == NULL)
                {
                    result = SEC_NO_AACS_CONTEXT_AVAILABLE;
                }
                else
                    result = SEC_SUCCESS;
                if(result != SEC_SUCCESS)
                {
                    SEC_DEBUG(":%d - Failed to create context in kernel\n", __LINE__);
                    ipc_result = IPC_RET_INVALID_CONTEXT;
                    OS_FREE(data);
                }
    
            }
            else
            {
                if(data)
                {
                    OS_FREE(data);
                    data = NULL;
                }
            }
        }
        else
        {
            result = SEC_NO_AACS_CONTEXT_AVAILABLE;
            goto exit;
        }
        break;

    case IPC_SC_54_2:
        result = fcm_free_internal_session(aacs_context, ipl->aacs_destroy_ctx.context_id);
        if(result != SEC_SUCCESS)
        {
            SEC_DEBUG(":%d - Failed to destroy context ID %x\n", __LINE__,
                      ipl->aacs_destroy_ctx.context_id);
            ipc_result = IPC_RET_INVALID_CONTEXT;
        }
        else
            ipc_result = IPC_RET_SUCCESS;
        break;

    case IPC_SC_54_0:
    case IPC_SC_54_3:
    case IPC_SC_54_4:
    case IPC_SC_54_5:
    case IPC_SC_54_6:
    case IPC_SC_54_7:
    case IPC_SC_54_8:
    case IPC_SC_54_9:
    case IPC_SC_54_10:
    case IPC_SC_54_11:
    case IPC_SC_54_13:
    case IPC_SC_54_14:
    case IPC_SC_54_15:
    case IPC_SC_54_16:
    case IPC_SC_54_17:
    case IPC_SC_54_18:
    case IPC_SC_54_19:
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

    // For this command only, 'ipl' is a pointer to sec_contig_mem_t.
    // kernel_vaddr of sec_contig_mem_t points to an array of ipl_t structs.
    case IPC_SC_54_12:
        ipl_list   = (ipl_t*)(((sec_contig_mem_t*)ipl)->kernel_vaddr);
        ipc_result = sec_kernel_ipc(ipc_arg->cmd,
                                    ipc_arg->sub_cmd,
                                    ipc_arg->io_sizes,
                                    (ipl_t*)ipl_list,
                                    opl,
                                    0,
                                    0);
        break;

    case IPC_SC_54_36:
    case IPC_SC_54_37:
    case IPC_SC_54_38:
    case IPC_SC_54_39:
    case IPC_SC_54_41:
        SEC_ERROR( "Unsupported IPC_54 subcommand (0x%08lx, %lu)\n",
                   (unsigned long)ipc_arg->sub_cmd.sc_54,
                   (unsigned long)ipc_arg->sub_cmd.sc_54 );
        ipc_result = IPC_RET_COMMAND_NOT_SUPPORTED_YET;
        break;

    default:
        SEC_ERROR( "Unknown IPC_54 subcommand (0x%08lx, %lu)\n",
                   (unsigned long)ipc_arg->sub_cmd.sc_54,
                   (unsigned long)ipc_arg->sub_cmd.sc_54 );
        ipc_result = IPC_RET_INVALID_CRYPTO_ENGINE_SELECT;
        break;
    }

    result = ipc2sec_aacs(ipc_result);
exit:
    return result;
}
