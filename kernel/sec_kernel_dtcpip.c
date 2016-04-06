/*-----------------------------------------------------------------------------
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2011-2012 Intel Corporation. All rights reserved.
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
 * Copyright(c) 2011-2012 Intel Corporation. All rights reserved.
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
#include "sec_fw.h"
#include "sec_fw_context_manager.h"

fcm_kernel_context* dtcpip_context = NULL;
DEFINE_MUTEX(dtcpip_ipc_mutex);
#define SEC_DTCPIP_MAX_SESSIONS 8

//-----------------------------------------------------------------------------
// sec_create_dtcpip_context
//
// Function to get a free DTCPIP context resource
//-----------------------------------------------------------------------------
static
sec_result_t sec_create_dtcpip_context (int context_id)
{
    sec_result_t rc = SEC_NO_DTCPIP_CONTEXT_AVAILABLE;

    if(NULL != fcm_create_internal_session(dtcpip_context, context_id, false, NULL))
    {
        rc = SEC_SUCCESS;
    }
    return rc;
}

//-----------------------------------------------------------------------------
// sec_clone_dtcpip_context
//
// Function to get a free DTCPIP context resource
//-----------------------------------------------------------------------------
static
sec_result_t sec_clone_dtcpip_context (int context_id)
{
    sec_result_t rc = SEC_NO_DTCPIP_CONTEXT_AVAILABLE;
    SEC_DEBUG(":%d\n", __LINE__);

    if(NULL != fcm_create_internal_session(dtcpip_context, context_id, true, NULL))
    {
        rc = SEC_SUCCESS;
    }
    return rc;
}

//-----------------------------------------------------------------------------
//
// Function to free a DTCPIP context resource
//-----------------------------------------------------------------------------
static
sec_result_t sec_destroy_dtcpip_context (uint32_t context_id)
{
    return fcm_free_internal_session(dtcpip_context, context_id);
}

//-----------------------------------------------------------------------------
// sec_kernel_dtcpip_deinit
//
// Function to free DTCPIP resources
//-----------------------------------------------------------------------------
void sec_kernel_dtcpip_deinit()
{
    fcm_free_kernel_context(dtcpip_context);
}

//-----------------------------------------------------------------------------
// sec_kernel_dtcpip_init
//
// Function to allocate and initialize DTCPIP resources
//-----------------------------------------------------------------------------
int sec_kernel_dtcpip_init()
{
    int rc = 0;
    SEC_DEBUG(":%d - Registering module ID %lx\n", __LINE__, SEC_IPC_DTCPIP_MODULE_ID);
    dtcpip_context = fcm_create_kernel_context(SEC_IPC_DTCPIP_MODULE_ID,
                                               IPC_SC_DTCPIP_DESTROY_CTX,
                                               SEC_DTCPIP_MAX_SESSIONS);
    if(NULL == dtcpip_context)
    {
        SEC_ERROR("Could not allocate DTCP-IP kernel context\n");
        rc = -1;
    }

    return rc;
}

//-----------------------------------------------------------------------------
// Translate an IPC return type to a sec driver return type.
//-----------------------------------------------------------------------------
sec_result_t ipc2sec_dtcpip(sec_ipc_return_t ipc_ret)
{
    sec_result_t result;

    switch (ipc_ret)
    {
    //  Handle any specific error cases here. Generic
    //  errors are handled below
    default:
        result = ipc2sec(ipc_ret);
        break;
    }
    return result;
}

//-----------------------------------------------------------------------------
// sec_kernel_process_dtcpip_op
//
// Function to process DTCPIP operations.
//-----------------------------------------------------------------------------
sec_result_t
sec_kernel_process_dtcpip_op(sec_kernel_ipc_t *  ipc_arg,
                             ipl_t *             ipl,
                             opl_t *             opl,
                             ipc_shmem_t *       ish_pl)
{
    sec_ipc_return_t  ipc_result = IPC_RET_BAD_HOST_REQUEST;
    sec_result_t      result = SEC_FAIL;

    VERIFY(ipl != NULL, exit, result, SEC_FAIL);

    switch (ipc_arg->sub_cmd.sc_dtcpip)
    {
    case IPC_SC_DTCPIP_CREATE_CTX:
        mutex_lock(&dtcpip_ipc_mutex);
        ipc_result = sec_kernel_ipc(ipc_arg->cmd,
                                    ipc_arg->sub_cmd,
                                    ipc_arg->io_sizes,
                                    ipl,
                                    opl,
                                    NULL,
                                    NULL);
        mutex_unlock(&dtcpip_ipc_mutex);
        if (IPC_RET_OK(ipc_result))
        {
            sec_kernel_copy_to_user(ipc_arg, opl, NULL);
            result = sec_create_dtcpip_context(opl->context_id);
            if(SEC_SUCCESS != result)
            {
                SEC_DEBUG(":%d - Failed to create context in kernel\n", __LINE__);
                ipc_result = IPC_RET_INVALID_CONTEXT;
            }
        }
    break;

    case IPC_SC_DTCPIP_DESTROY_CTX:
    {
        // Get the context id to be destroyed
        int temp_id = ((ipl_fcm_context_id_t*)ipl)->context_id;
        SEC_DEBUG(":%d - Destroy Context: context ID = %x\n", __LINE__, temp_id);
        if(SEC_SUCCESS != sec_destroy_dtcpip_context(temp_id))
        {
            SEC_DEBUG(":%d - Failed to destroy context ID %x\n", __LINE__, temp_id);
            ipc_result = IPC_RET_INVALID_CONTEXT;
        }
        else
        {
            ipc_result = IPC_RET_SUCCESS;
        }
    }
    break;

    case IPC_SC_DTCPIP_CLONE_CONTEXT:
    {
        // Increment ref count for the context ID
        int temp_id = ((ipl_fcm_context_id_t*)ipl)->context_id;
        SEC_DEBUG(":%d - Clone Context: context ID: %x\n", __LINE__, temp_id);
        if(SEC_SUCCESS != sec_clone_dtcpip_context(temp_id))
        {
            SEC_DEBUG(":%d - Mismatch in kernel context map", __LINE__);
            ipc_result = IPC_RET_INVALID_CONTEXT;
        }
        else
        {
            ipc_result = IPC_RET_SUCCESS;
        }
    }
    break;

    case IPC_SC_DTCPIP_PROCESS_PKT:
    {
        user_buf_t src;
        user_buf_t dst;
        sec_dma_descriptor_t *desc = NULL;
        uint8_t do_dma = ((ipl->dtcpip_process_pkt.data_buffer_masks &
                             SEC_DTCPIP_USE_DMA_SRC) &&
                         (ipl->dtcpip_process_pkt.data_buffer_masks &
                             SEC_DTCPIP_USE_DMA_DST));
        if(do_dma)
        {
            if(SEC_SUCCESS != external_mod_ipc_dma_setup(ipc_arg, ipl, &src, &dst, &desc))
            {
                SEC_ERROR("DTCP-IP packet data DMA setup failed\n");
                ipc_result = IPC_RET_BAD_HOST_REQUEST;
                break;
            }
        }
        mutex_lock(&dtcpip_ipc_mutex);
        ipc_result = sec_kernel_ipc(ipc_arg->cmd,
                                    ipc_arg->sub_cmd,
                                    ipc_arg->io_sizes,
                                    ipl,
                                    opl,
                                    NULL,
                                    NULL);
        mutex_unlock(&dtcpip_ipc_mutex);
        if(do_dma)
        {
            if(SEC_SUCCESS != external_mod_ipc_dma_teardown(ipc_arg, &src, &dst, desc))
            {
                SEC_ERROR("DTCP-IP packet data DMA teardown failed\n");
            }
        }

        if (IPC_RET_OK(ipc_result))
        {
            sec_kernel_copy_to_user(ipc_arg, opl, NULL);
        }
    }
    break;

    case IPC_SC_DTCPIP_INIT:
    case IPC_SC_DTCPIP_INIT_SRM:
    case IPC_SC_DTCPIP_UPDATE_SRM:
    case IPC_SC_DTCPIP_WRAP_KEY:
    case IPC_SC_DTCPIP_ECDSA_SIGN:
    case IPC_SC_DTCPIP_ECDSA_VERIFY:
    case IPC_SC_DTCPIP_GEN_HK_HV:
    case IPC_SC_DTCPIP_GEN_KX_KSX:
    case IPC_SC_DTCPIP_GET_CMD_DATA:
    case IPC_SC_DTCPIP_GEN_KXM_KXSM:
    case IPC_SC_DTCPIP_EXPIRE_KX:
    case IPC_SC_DTCPIP_NEW_KX_KSX:
    case IPC_SC_DTCPIP_GEN_NONCE:
    case IPC_SC_DTCPIP_PROCESS_MSG:
    case IPC_SC_DTCPIP_TEST_IPC:

        mutex_lock(&dtcpip_ipc_mutex);
        ipc_result = sec_kernel_ipc(ipc_arg->cmd,
                                    ipc_arg->sub_cmd,
                                    ipc_arg->io_sizes,
                                    ipl,
                                    opl,
                                    NULL,
                                    NULL);
        mutex_unlock(&dtcpip_ipc_mutex);
        if (IPC_RET_OK(ipc_result))
        {
            sec_kernel_copy_to_user(ipc_arg, opl, NULL);
        }
    break;

    default:
        SEC_ERROR( "Unknown DTCPIP subcommand (0x%08lx, %lu)\n",
                   (unsigned long)ipc_arg->sub_cmd.sc_dtcpip,
                   (unsigned long)ipc_arg->sub_cmd.sc_dtcpip );
        ipc_result = IPC_RET_INVALID_CRYPTO_ENGINE_SELECT;
    break;
    }

    result = ipc2sec_dtcpip(ipc_result);
exit:
    return result;
}



