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
#include "sec_hal.h"
#include "sec_fw.h"
#include "sec_common_types.h"
#include "sec_fw_context_manager.h"

/*
---------------------------------------------------------------------
        Generic Firmware Context Management implementation
---------------------------------------------------------------------
*/


static sec_result_t fcm_get_module_id(sec_module_list_t *mod_list,
                                      uint32_t* mod_count,
                                      uint32_t* rom_ver,
                                      uint32_t* module_id);

static struct list_head* fcm_find_kernel_context(int module_id);
static struct list_head* fcm_find_internal_session(fcm_kernel_context *context, int context_id);
static sec_result_t fcm_free_fw_session(fcm_kernel_context *context, uint32_t context_id);
static void fcm_free_all_internal_sessions(fcm_kernel_context *context);
static void fcm_free_internal_session_tgid(fcm_kernel_context *context, uint32_t tgid);

#ifdef ENABLE_SEC_DEBUG 
static void fcm_dump_contexts(void);
#endif





static
sec_result_t fcm_get_module_id(sec_module_list_t *mod_list,
                               uint32_t* mod_count,
                               uint32_t* rom_ver,
                               uint32_t* module_id)
{

    int i;
    sec_result_t rc = SEC_FAIL;
    rc = sec_fw_get_ver_info(mod_list, mod_count, rom_ver);
    if (SEC_SUCCESS == rc)
    {
        for(i=0; i<SEC_MAX_LOADED_FW_MODULES; i++)
        {
            if(*module_id == (mod_list[i].module_id & 0x7FFFFFFFul))
            {
                *module_id = mod_list[i].module_id;
                break;
            }
        }
    }
    else
    {
        SEC_ERROR("Failed to get the FW ver info\n");
    }
    return rc;
}

static
struct list_head* fcm_find_kernel_context(int module_id)
{
    fcm_kernel_context *c = NULL;
    struct list_head *i = NULL;
    bool found = false;
    list_for_each(i, &klist.khead)
    {
        c = list_entry(i, fcm_kernel_context, khead);
        if(c && c->module_id == module_id)
        {
            found = true;
            break;
        }
    }
    if(found)
        return i;
    else
        return NULL;
}

static
struct list_head* fcm_find_internal_session(fcm_kernel_context *context, int context_id)
{
    fcm_internal_session *s = NULL;
    struct list_head *i = NULL;
    bool found = false;
    list_for_each(i, &context->dlist.dhead)
    {
        s = list_entry(i, fcm_internal_session, dhead);
        if(s && s->context_id == context_id)
        {
            found = true;
            break;
        }
    }
    if(found)
        return i;
    else
        return NULL;
}

static
sec_result_t fcm_free_fw_session(fcm_kernel_context *context, uint32_t context_id)
{
    sec_result_t rc = SEC_FAIL;
    sec_ipc_return_t    ipc_ret;

    ipl_t ipl;
    opl_t opl;
    sec_ipc_sizes_t sizes;
    sec_fw_cmd_t cmd;
    ipc_shmem_t *   ish_pl = NULL;
    ipc_shmem_t *   osh_pl = NULL;
    sec_fw_subcmd_t sub_cmd ={.sc = context->destroy_ipc};
    uint32_t rom_ver = 0;
    uint32_t mod_count = 0;
    sec_module_list_t mod_list[SEC_MAX_LOADED_FW_MODULES];
    OS_MEMSET(&ipl,0x0, sizeof(ipl));
    if(gchip_info.host_device == PCI_DEVICE_CE4100 && context->module_id == 0x2000)
    {
        cmd = IPC_54;
        ipl.aacs_destroy_ctx.filler1[1] = context->destroy_ipc;
        ipl.aacs_destroy_ctx.context_id = context_id;
    }
    else
    {
        cmd = IPC_EXTERNAL_MODULE_CMD;
        SEC_DEBUG( ":%d - destroy_ipc = %x\n", __LINE__,(uint32_t)sub_cmd.sc);
        ipl.fcm_ctx_id.context_id = context_id;
        fcm_get_module_id(mod_list, &mod_count, &rom_ver, &context->module_id);
        ipl.fcm_ctx_id.filler2 = context->module_id;
        ipl.fcm_ctx_id.filler3 = (uint32_t)sub_cmd.sc;
    }
    sizes.ipl_size =  SEC_DRM_DESTROY_CTX_PAYLOAD_SIZE;
    sizes.ish_size =  SEC_HW_NO_SHAREDMEM;
    sizes.opl_size =  SEC_HW_PAYLOAD_JUST_JOBID;
    sizes.osh_size =  SEC_HW_NO_SHAREDMEM;
    SEC_TRACE( ":%d\n", __LINE__);
    ipc_ret = sec_kernel_ipc(cmd,
                             sub_cmd,
                             sizes,
                             &ipl,
                             &opl,
                             ish_pl,
                             osh_pl);
    if (IPC_RET_OK(ipc_ret))
    {
        up(&context->internal_session_sema);
        rc = SEC_SUCCESS;
    }
    return rc;
}


static
void fcm_free_all_internal_sessions(fcm_kernel_context *context)
{
    struct list_head* i = NULL;
    struct list_head* p = NULL;

    list_for_each_safe(i, p, &(context->dlist.dhead))
    {
        fcm_internal_session *s= NULL;
        s = list_entry(i, fcm_internal_session, dhead);
        if(s)
        {
            // Deallocate the internal tgid list first
            uint32_list_clear_list(&s->tgid_list);

            // Delete from session list and deallocate memory
            list_del(i);
            if(s->data)
            {
                OS_FREE(s->data);
                s->data = NULL;
            }
            OS_FREE(s);
        }
    }
}

static
void fcm_free_internal_session_tgid(fcm_kernel_context *context, uint32_t tgid)
{
    uint32_list fw_kill_list;
    INIT_LIST_HEAD(&(fw_kill_list.list));
    SEC_TRACE( ":%d\n", __LINE__);
    if(context)
    {
        fcm_internal_session *s = NULL;
        struct list_head *i = NULL;
        struct list_head *q = NULL;

        SEC_TRACE( ":%d\n", __LINE__);
        //spin_lock(&(context->internal_session_lock));
        if(0 == list_empty_careful(&(context->dlist.dhead))) // 1 is empty, 0 is non empty
        {
            list_for_each_safe(i, q, &(context->dlist.dhead))
            {
                s = list_entry(i, fcm_internal_session, dhead);
                if(true == uint32_list_remove_node(tgid, &s->tgid_list))
                {
                    s->ref_counter--;
                    SEC_TRACE( ":%d\n", __LINE__);

                    if(s->ref_counter == 0)
                    {
                        // Add the context ID to the firmware kill list
                        uint32_list_add_tail_node(s->context_id, &fw_kill_list);

                        uint32_list_clear_list(&s->tgid_list);
                        list_del(i);
                        if(s->data)
                        {
                            OS_FREE(s->data);
                            s->data = NULL;
                        }
                        OS_FREE(s);
                        s = NULL;
                    }
                }
            }
        }
        //spin_unlock(&context->internal_session_lock);

        // Kill all contexts collected in fw_kill_list
        if(0 == list_empty_careful(&(fw_kill_list.list))) // 1 is empty, 0 is non empty
        {
            list_for_each_safe(i, q, &(fw_kill_list.list))
            {
                uint32_list *l = list_entry(i, uint32_list, list);
                sec_result_t rc = fcm_free_fw_session(context, l->value);
                if (SEC_SUCCESS != rc)
                {
                    SEC_ERROR( ":%d: Failed to free FW context %x\n", __LINE__, l->value);
                }
                list_del(i);
                OS_FREE(l);
            }
        }
    }
}


#ifdef ENABLE_SEC_DEBUG 
static void fcm_dump_contexts(void)
{
    fcm_kernel_context *c = NULL;
    struct list_head *i = NULL;
    struct list_head *j = NULL;
    struct list_head *p = NULL;
    struct list_head *q = NULL;

    list_for_each_safe(i, p, &(klist.khead))
    {
        c = list_entry(i, fcm_kernel_context, khead);
        //printk(KERN_INFO "Module ID = %x\n", c->module_id);
        list_for_each_safe(j, q, &(c->dlist.dhead))
        {
            fcm_internal_session *s = NULL;
            s = list_entry(j, fcm_internal_session, dhead);
            printk(KERN_INFO "s->context_id = %x\n", s->context_id);
        }
    }

}
#endif


fcm_kernel_context* fcm_create_kernel_context(int module_id,
                                              int destroy_ipc, 
                                              int max_sessions)
{
    fcm_kernel_context *c = NULL;
    struct list_head *lh = NULL;

    spin_lock(&fcm_kernel_context_lock);
    lh = fcm_find_kernel_context(module_id);

    if(NULL == lh)
    {
        c = OS_ALLOC_NONBLOCK(sizeof(fcm_kernel_context));
        if(c)
        {
            c->module_id = module_id;
            c->destroy_ipc = destroy_ipc;
            spin_lock_init(&c->internal_session_lock);
            sema_init(&c->internal_session_sema, max_sessions);
            INIT_LIST_HEAD(&(c->dlist.dhead)); // Initialize the internal DRM list
            list_add_tail(&(c->khead), &(klist.khead)); // Add this to outer kernel list 
        }
        else
        {
            SEC_DEBUG( "OS_ALLOC_NONBLOCK failed at %s:%d\n", __FILE__, __LINE__);
            c = NULL;
        }
    }
    else
    {
        c = list_entry(lh, fcm_kernel_context, khead);
    }
    spin_unlock(&fcm_kernel_context_lock);

    return c;
}

sec_result_t fcm_free_kernel_context(fcm_kernel_context* in_context)
{
    fcm_kernel_context *c = NULL;
    sec_result_t status = SEC_FAIL;
	struct list_head *i = NULL;
    struct list_head *p = NULL;

    spin_lock(&fcm_kernel_context_lock);
    if(0 == list_empty_careful(&(klist.khead)))
    {
        list_for_each_safe(i, p, &(klist.khead))
        {
            c = list_entry(i, fcm_kernel_context, khead);
            if(c->module_id == in_context->module_id)
            {
                fcm_free_all_internal_sessions(c);
                list_del(i);
                OS_FREE(c);
                status = SEC_SUCCESS;
                break;
            }
        }
    }
    else
    {
        SEC_ERROR("Kernel context doesn't exist\n");
        status = SEC_FAIL;
    }
    spin_unlock(&fcm_kernel_context_lock);
    return status;
}



fcm_internal_session* fcm_create_internal_session(fcm_kernel_context *context,
                                                  uint32_t context_id,
                                                  bool clone,
                                                  unsigned char * data)
{
    struct list_head *lh;
    fcm_internal_session *s = NULL;
    spin_lock(&context->internal_session_lock);

    if(clone == true)
    {
        if(0 == list_empty_careful(&(context->dlist.dhead)))
        {
            lh = fcm_find_internal_session(context, context_id);
            if(NULL != lh)
            {
                SEC_TRACE( ":%d\n", __LINE__);
                s = list_entry(lh, fcm_internal_session, dhead);
                s->ref_counter++;
                uint32_list_add_tail_node(current->tgid, &s->tgid_list);
            }
        }
    }
    else
    {
        if(1 == list_empty_careful(&(context->dlist.dhead))) // 1 is empty, 0 is non empty
        {
            // No DRM sessions. Create one
            s = OS_ALLOC_NONBLOCK(sizeof(fcm_internal_session));
            if(s)
            {
                s->context_id = context_id;
                s->ref_counter = 1;
                s->data = data;
                INIT_LIST_HEAD(&(s->tgid_list.list));
                uint32_list_add_tail_node(current->tgid, &s->tgid_list);
                list_add_tail(&(s->dhead), &(context->dlist.dhead));
                down_interruptible(&context->internal_session_sema);
            }
            else
            {
                SEC_DEBUG( "OS_ALLOC_NONBLOCK failed at %s:%d\n", __FILE__, __LINE__);
                s = NULL;
            }
        }
        else
        {
            // See if we already have an entry for the context_id mentioned
            lh = fcm_find_internal_session(context, context_id);
            if(NULL == lh)
            {
                s = OS_ALLOC_NONBLOCK(sizeof(fcm_internal_session));
                if(s)
                {
                    s->context_id = context_id;
                    s->ref_counter = 1;
                    s->data = data;
                    INIT_LIST_HEAD(&(s->tgid_list.list));
                    uint32_list_add_tail_node(current->tgid, &s->tgid_list);
                    list_add_tail(&(s->dhead), &(context->dlist.dhead));
                    down_interruptible(&context->internal_session_sema);
                }
                else
                {
                    SEC_DEBUG( "OS_ALLOC failed at %s:%d\n", __FILE__, __LINE__);
                    s = NULL;
                }
            }
            else
            {
                SEC_DEBUG( "Context already exists at %s:%d\n", __FILE__, __LINE__);
                s = NULL;
            }
        }
    }
    spin_unlock(&context->internal_session_lock);
    return s;
}

sec_result_t fcm_free_internal_session(fcm_kernel_context *context, int kill_context_id)
{
    sec_result_t status = SEC_FAIL;
    struct list_head *lh = NULL;
    fcm_internal_session *s = NULL;
    bool to_kill = false;

    SEC_TRACE( ":%d\n", __LINE__);
    spin_lock(&context->internal_session_lock);

    lh = fcm_find_internal_session(context, kill_context_id);
    if(lh)
    {
        SEC_TRACE( ":%d\n", __LINE__);
        s = list_entry(lh, fcm_internal_session, dhead);
        s->ref_counter--;
        if(s->ref_counter == 0)
        {
            SEC_TRACE( ":%d\n", __LINE__);
            uint32_list_clear_list(&s->tgid_list);
            list_del(lh);
            if(s->data)
            {
                OS_FREE(s->data);   
                s->data = NULL;
            }
            OS_FREE(s);
            s = NULL;
            to_kill = true;
        }
        else
        {
            status = SEC_SUCCESS;
        }
    }
    else
    {
        status = SEC_FAIL;
        SEC_DEBUG( ":%d - Did not find context\n", __LINE__);
    }

    spin_unlock(&context->internal_session_lock);

    if(to_kill)
    {
        // Kill in the FW as well using the registered destroy IPC
        if (SEC_SUCCESS == fcm_free_fw_session(context, kill_context_id))
        {
            SEC_TRACE( ":%d\n", __LINE__);
            status = SEC_SUCCESS;
        }
        else
        {
            SEC_DEBUG( ":%d: Failed to free FW context\n", __LINE__);
            status = SEC_FAIL;
        }
    }

    return status;
}

void fcm_internal_session_garbage_collect(uint32_t tgid)
{
    struct list_head *i = NULL;
    struct list_head *p = NULL;

    SEC_DEBUG("fcm_internal_session_garbage_collect: Process %d Terminated. \n", tgid );
#ifdef ENABLE_SEC_DEBUG 
    fcm_dump_contexts();
#endif

    if(0 == list_empty_careful(&(klist.khead))) // 1 is empty, 0 is non empty
    {
        list_for_each_safe(i, p, &(klist.khead))
        {
            fcm_kernel_context *c = list_entry(i, fcm_kernel_context, khead);
            if(c)
            {
                SEC_TRACE( ":%d\n", __LINE__);
                fcm_free_internal_session_tgid(c, tgid);
            }
            else
            {
                SEC_TRACE( ":%d\n", __LINE__);
            }
        }
    }
}
