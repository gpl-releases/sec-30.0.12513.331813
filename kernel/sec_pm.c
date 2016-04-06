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

#include <linux/list.h>
#include <linux/pci.h>
#include <linux/firmware.h>
#include <linux/kobject.h>
#include <linux/types.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include "osal.h"
#include "sec_types.h"
#include "sec_kernel.h"
#include "sec_tracker.h"
#include "sec_kernel_types.h"
#include "sec_common_types.h"

#include "sec_fw.h"
#include "sec_pm.h"
#include "sec_pci.h"
#include "sec_tdp.h"

//-----------------------------------------------------------------------------
// D E B U G G I N G
//-----------------------------------------------------------------------------
/* Debugging related macros */
//#define SEC_PM_DEBUG
#ifdef SEC_PM_DEBUG
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

#define SEC_PM_DPRINT(str, ...)                                             \
    printk(KERN_INFO "DEBUG (%s:%d) " str, __func__, __LINE__,             \
           ##__VA_ARGS__);

#define SEC_PM_TRACE() SEC_PM_DPRINT("TRACE\n") 

#define SEC_PM_LOAD_INFO_DPRINT(load_info_ptr)                              \
    SEC_PM_DPRINT("Load Info: id: 0x%08x -- Path: %s\n",                    \
            load_info_ptr->module_id, load_info_ptr->image_path)

#define SEC_PM_RET_TRACE() SEC_PM_DPRINT("Returning %d\n", rc)

/* This hashes the contig mem areas to for debugging purposes */
static inline void SEC_PM_HASH_DPRINT(void * ptr, size_t size)
{
    int i = 0;
    struct scatterlist sg_list[1];
    struct crypto_hash * md5;
    struct hash_desc desc;
    uint8_t result[16];

    OS_MEMSET(result, 0x00, 16);

    sg_init_one(sg_list, ptr, size);
    md5 = crypto_alloc_hash("md5", 0, 0);
    if (IS_ERR(md5))
    {
        SEC_ERROR("Couldn't setup md5 transform\n");
        return;
    }

    desc.tfm = md5;
    desc.flags = 0;

    crypto_hash_digest(&desc, sg_list, 1, result);
    SEC_PM_DPRINT("Hash for %p was: ", ptr);
    for (i = 0; i < 16; i++)
    {
        if (i % 4 == 0 && i != 0)
            printk(" ");
        printk("%02x", result[i]);
    }
    crypto_free_hash(md5);
    printk("\n\n");
    return;
}
#else /* SEC_PM_DEBUG */
#define SEC_PM_DPRINT(str, ...)
#define SEC_PM_TRACE()
#define SEC_PM_LOAD_INFO_DPRINT(load_info_ptr)
#define SEC_PM_RET_TRACE()
#define SEC_PM_HASH_DPRINT(ptr, size)
#endif /* SEC_PM_DEBUG */

//-----------------------------------------------------------------------------
// D A T A   T Y P E   D E F I N I T I O N S
//-----------------------------------------------------------------------------
typedef union {
    sec_fw_info_t       unload_check;     // Used for 'unload' & 'check' actions
    struct {
        sec_fw_load_t       load_info;
        ipl_t               ipl;        // Input payload
        opl_t               opl;        // Output payload
        ipc_shmem_t         ish_pl;     // Input shared mem
        ipc_shmem_t         osh_pl;     // Output shared mem
        void *              contig_mem_areas[SEC_MAX_FW_CONTIG_COUNT];
                                        // Contig mem areas we'll need to free
        size_t              contig_mem_sizes[SEC_MAX_FW_CONTIG_COUNT];
    }                   load;       // Used for 'load' actions
} sec_pm_action_info_t;


typedef struct {
    os_list_head_t          list;       // Kernel list handler
    sec_fw_action_t         action;     // Load or unload
    sec_pm_action_info_t    action_info;// Info about the load/unload/check
} sec_pm_action_node_t;

//-----------------------------------------------------------------------------
// G L O B A L S
//-----------------------------------------------------------------------------
static sec_tdp_config_info_t tdp_config_struct;        /* TDP config info tracker*/
sec_pm_state_t sec_pm_state = SEC_PM_RUNNING;   /* Power state tracking */
static DEFINE_MUTEX(sec_pm_action_list_mutex);  /* Controls access to FW list */
static LIST_HEAD(sec_pm_action_list);           /* FW info list */
int sec_ioctl_ref_count;                        /* Boolean for whether we are PM
                                                   locked or not */
DEFINE_SPINLOCK(sec_ioctl_state_lock);          /* Gates IOCTL for PM */

//-----------------------------------------------------------------------------
// M A C R O S   /   I N L I N E S
//-----------------------------------------------------------------------------

static inline int sec_pm_disable_ioctl(void)
{
    spin_lock(&sec_ioctl_state_lock);
    if (sec_ioctl_ref_count != 0)
    {
        spin_unlock(&sec_ioctl_state_lock);
        SEC_ERROR("Could not suspend; active IOCTL was present\n");
        return -1;
    }
    sec_ioctl_ref_count = -1;
    spin_unlock(&sec_ioctl_state_lock);
    return 0;
}

#define sec_pm_enable_ioctl()                                               \
    do {                                                                    \
        spin_lock(&sec_ioctl_state_lock);                                   \
        sec_ioctl_ref_count = 0;                                            \
        spin_unlock(&sec_ioctl_state_lock);                                 \
    } while (0)

//-----------------------------------------------------------------------------
// sec_pm_cleanup_node
//
// This function handles any necessary cleanup functionality for a PM action
// node.
//-----------------------------------------------------------------------------
static void sec_pm_cleanup_node(sec_pm_action_node_t * node)
{
    int i = 0;

    if (node == NULL)
        goto exit;
    
    if (node->action == SEC_FW_ACTION_LOAD_FW ||
        node->action == SEC_FW_ACTION_LOAD_MANIFEST)
    {
        /* Clean up any memory which user-space allocated */
        for (i = 0; i < SEC_MAX_FW_CONTIG_COUNT; i++)
        {
            if (node->action_info.load.contig_mem_areas[i] == NULL)
                break;
            /* Free the pages properly; this does return a status, but there
             * isn't much we can do if it fails so ignore it */
            __sec_do_free_pages(node->action_info.load.contig_mem_areas[i],
                                node->action_info.load.contig_mem_sizes[i]);
        }
    }

    OS_FREE(node);

exit:
    return;
}

//-----------------------------------------------------------------------------
// sec_pm_cleanup_action_list
//
// This function removes all items from the action list, and frees any
// associated memory
//-----------------------------------------------------------------------------
void sec_pm_cleanup_action_list(void)
{
    sec_pm_action_node_t *  cur_node = NULL;
    sec_pm_action_node_t *  next_node = NULL;

    mutex_lock(&sec_pm_action_list_mutex);
    list_for_each_entry_safe(cur_node, next_node, &sec_pm_action_list, list)
    {
        list_del(&cur_node->list);
        sec_pm_cleanup_node(cur_node);
    }
    mutex_unlock(&sec_pm_action_list_mutex);
    if((g_fast_path >0)&&(tdp_config_struct.tdp_config_mem_ptr != NULL))
    {
        __sec_do_free_pages(tdp_config_struct.tdp_config_mem_ptr,tdp_config_struct.tdp_config_mem_size);
        tdp_config_struct.tdp_config_mem_ptr = NULL;
        tdp_config_struct.tdp_config_mem_size = 0;
    }
}

//-----------------------------------------------------------------------------
// sec_pm_store_fw_image
//
// The following function takes the info from a load request, received during
// 'suspend' and stores it in the list of images to re-load during the
// resume handler.
//
// IMPORTANT ASSUMPTIONS:
// - This function should only be called when in a suspend state; because of
//   this, the list lock should be held around the request firmware call.
//-----------------------------------------------------------------------------
sec_result_t sec_pm_store_fw_image(sec_fw_load_t * fw_load)
{
    sec_result_t            rc = SEC_SUCCESS;
    sec_pm_action_node_t *  cur_node = NULL;
    int                     node_found = 0;
    int                     opl_result = 2;
    int                     i = 0;
    sec_contig_mem_t        this_contig;

    SEC_PM_TRACE();
    SEC_PM_LOAD_INFO_DPRINT(fw_load);

    /* Find the list image */
    list_for_each_entry(cur_node, &sec_pm_action_list, list)
    {
        /* Save time; if it isn't a load action it can't be our image */
        if (cur_node->action != SEC_FW_ACTION_LOAD_FW &&
            cur_node->action != SEC_FW_ACTION_LOAD_MANIFEST)
            continue;
        if (strncmp(cur_node->action_info.load.load_info.image_path,
                    fw_load->image_path,
                    SEC_FW_MAX_PATH_LEN) == 0)
        {
            node_found = 1;
            break;
        }
    }

    if (node_found == 0)
    {
        SEC_ERROR("Couldn't find an entry for %s in our action list!\n",
                fw_load->image_path);
        rc = SEC_FAIL;
        goto exit;
    }

    /* Copy the load info in to the action node; it was brought in to kernel
     * space by the IOCTL handler */
    OS_MEMCPY(&(cur_node->action_info.load.load_info),
              fw_load,
              sizeof(sec_fw_load_t));
    VERIFY_AND_COPY_FROM_USER(&(cur_node->action_info.load.ipl),
                              fw_load->ipc_call.ipl,
                              sizeof(ipl_t), VERIFY_READ);
    /* For OPL check write ability; we need to write to it later */
    VERIFY_AND_COPY_FROM_USER(&(cur_node->action_info.load.opl),
                              fw_load->ipc_call.opl,
                              sizeof(opl_t), VERIFY_WRITE);
    VERIFY_AND_COPY_FROM_USER(&(cur_node->action_info.load.ish_pl),
                              fw_load->ipc_call.ish_pl,
                              sizeof(ipc_shmem_t), VERIFY_READ);
    VERIFY_AND_COPY_FROM_USER(&(cur_node->action_info.load.osh_pl),
                              fw_load->ipc_call.osh_pl,
                              sizeof(ipc_shmem_t), VERIFY_READ);

    /* For each of our contiguous memory areas we need to:
     *    1. Inform the kernel to not free the actually allocated memory when
     *       the user-space program asks
     *    2. Log the kernel virtual address so we can free it on resume
     */
    for (i = 0; i < SEC_MAX_FW_CONTIG_COUNT; i++)
    {
        SEC_PM_DPRINT("Contig mem at %p\n", fw_load->contig_mem[i]);
        /* Once we hit a NULL that is the end of the list */
        if (fw_load->contig_mem[i] == NULL)
        {
            // Set the un-used mem areas to NULL so we known not to use them
            for ( ; i < SEC_MAX_FW_CONTIG_COUNT; i++)
            {
                cur_node->action_info.load.contig_mem_areas[i] = NULL;
            }
            break;
        }

        /* Copy the contig mem info from user space */
        VERIFY_AND_COPY_FROM_USER(&this_contig, fw_load->contig_mem[i],
                            sizeof(sec_contig_mem_t), VERIFY_WRITE);

        /* Save the kernel address to the memory we will need to free later */
        cur_node->action_info.load.contig_mem_areas[i] = 
            this_contig.kernel_vaddr;
        cur_node->action_info.load.contig_mem_sizes[i] = this_contig.size;
#ifdef SEC_PM_DEBUG
        /* If in DEBUG mode perform a preliminary hash */
        SEC_PM_HASH_DPRINT(this_contig.kernel_vaddr, this_contig.size);
#endif /* SEC_PM_DEBUG */

        SEC_PM_DPRINT("Added address 0x%p (size: %d) for cleanup later\n",
                this_contig.kernel_vaddr, this_contig.size);
        /* Set the flag to indicate that this mem should not be freed */
        this_contig.flags |= SEC_CONTIG_FLAG_PM_FREED;

        /* Copy back to user space */
        if (copy_to_user(fw_load->contig_mem[i],
                    &this_contig, sizeof(sec_contig_mem_t)) != 0)
        {
            SEC_ERROR("Failed to copy to user space\n");
            rc = SEC_FAIL;
            goto exit;
        }

        /* Clear the contig mem pointer to make sure we don't try to access it 
         * after the suspend; it won't be there! */
        fw_load->contig_mem[i] = NULL;
    }

    /* Reset the output info because it won't be useful when we re-load */
    cur_node->action_info.load.load_info.ipc_call.ipl = NULL;
    cur_node->action_info.load.load_info.ipc_call.opl = NULL;
    cur_node->action_info.load.load_info.ipc_call.ish_pl = NULL;
    cur_node->action_info.load.load_info.ipc_call.osh_pl = NULL;

    if (fw_load->ipc_call.opl != NULL &&
        copy_to_user((uint8_t *)fw_load->ipc_call.opl + 4,
                     &opl_result, sizeof(opl_result)))
    {
        SEC_ERROR("Could not copy result to user\n");
        rc = SEC_INTERNAL_ERROR;
        goto exit;
    }

exit:
    SEC_PM_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_pm_suspend_fw_reload
//
// The following function re-loads any available firmware images during
// suspend.
//-----------------------------------------------------------------------------
sec_result_t sec_pm_suspend_fw_reload(void)
{
    sec_result_t            rc = SEC_SUCCESS;
    const struct firmware * sec_pm_fw = NULL;

    sec_fw_list_node_t *    cur_node = NULL;
    sec_pm_action_node_t *  new_action_node = NULL;
    sec_pm_action_node_t *  cur_action_node = NULL;

    char                    request_path[SEC_FW_MAX_PATH_LEN + 3];
                            // Add 3 to accomodate '-m ' in case we are loading
                            // a manifest

    SEC_PM_TRACE();
    tdp_config_struct.tdp_config_mem_ptr = NULL;
    tdp_config_struct.tdp_config_mem_size =0;
    mutex_lock(&sec_fw_list_mutex);
    /* Iterate the FW list */
    list_for_each_entry(cur_node, &sec_fw_list, list)
    {
        SEC_PM_DPRINT("FW List Node: %d %d 0x%08x\n",
                      cur_node->action, cur_node->loaded_by,
                      cur_node->node_info.loaded_fw_id);
        /* Allocate the new node; include its action info because that is 
         * used in all cases */
        new_action_node = OS_ALLOC(sizeof(sec_pm_action_node_t));
        if (new_action_node == NULL)
        {
            rc =  SEC_OUT_OF_MEMORY;
            SEC_ERROR("Failed to allocate a list node\n");
            mutex_unlock(&sec_fw_list_mutex);
            goto error;
        }
        OS_MEMSET(new_action_node, 0x00, sizeof(sec_pm_action_node_t));
        new_action_node->action = cur_node->action;

        /* If we find an image that needs loading, request the image; the load
         * will be short-circuited at the FW IOCTL handler*/
        if (cur_node->action == SEC_FW_ACTION_LOAD_FW ||
            cur_node->action == SEC_FW_ACTION_LOAD_MANIFEST)
        {
            strncpy(new_action_node->action_info.load.load_info.image_path,
                    cur_node->image_path, SEC_FW_MAX_PATH_LEN);
            new_action_node->action_info.load.load_info.image_path[
                SEC_FW_MAX_PATH_LEN - 1] = '\0';
            new_action_node->action_info.load.load_info.module_id = cur_node->node_info.loaded_fw_id;
            SEC_PM_DPRINT("Adding LOAD action for %s\n",
                    new_action_node->action_info.load.load_info.image_path);

        }
        /* Otherwise, we only need to load the action (unload or check) */
        else
        {
            SEC_PM_TRACE();
            OS_MEMCPY(&new_action_node->action_info.unload_check,
                     &cur_node->node_info,
                     sizeof(sec_fw_info_t));
            
            SEC_PM_DPRINT("Adding %s action for 0x%08x\n",
                    (cur_node->action == SEC_FW_ACTION_UNLOAD_FW) ? "UNLOAD" :
                        "CHECK",
                    cur_node->node_info.loaded_fw_id);

        }
        if(((cur_node->node_info.loaded_fw_id == SEC_TDP_DEV_MODULE_ID)||(cur_node->node_info.loaded_fw_id == SEC_TDP_MODULE_ID)) && (g_fast_path>0) )
        {
            //store TDP configuration file reloading on resume
            rc = sec_tdp_config_file_reader(&tdp_config_struct);
            if(rc!=SEC_SUCCESS)
            {
                mutex_unlock(&sec_fw_list_mutex);
                goto error;
            }
        }
        /* Add the new node to the list */
        mutex_lock(&sec_pm_action_list_mutex);
        list_add_tail(&(new_action_node->list), &sec_pm_action_list);
        mutex_unlock(&sec_pm_action_list_mutex);
        new_action_node = NULL;
    }
    mutex_unlock(&sec_fw_list_mutex);

    SEC_PM_TRACE();

    mutex_lock(&sec_pm_action_list_mutex);
    list_for_each_entry(cur_action_node, &sec_pm_action_list, list)
    {
        /* Now that we aren't holding the FW list lock we can request loading
         * of the images */
        /* If the image isn't a load image, skip it */
        if (cur_action_node->action != SEC_FW_ACTION_LOAD_FW &&
            cur_action_node->action != SEC_FW_ACTION_LOAD_MANIFEST)
        {
            SEC_PM_DPRINT("Hit a non-load action\n");
            continue;
        }
        
        SEC_PM_DPRINT("Found load action for %s\n",
                    cur_action_node->action_info.load.load_info.image_path);

        /* Setup our request path; if this is for a manifest add a '-m ' */
        OS_MEMSET(request_path, 0x00, sizeof(request_path));
        if (cur_action_node->action == SEC_FW_ACTION_LOAD_MANIFEST)
            strncat(request_path, "-m ", sizeof(request_path));
        strncat(request_path,
                cur_action_node->action_info.load.load_info.image_path,
                sizeof(request_path));

        /* Otherwise, try to load the image to RAM */
        SEC_PM_DPRINT("Request path: %s\n", request_path);
        if (request_firmware(&sec_pm_fw, request_path, &sec_pci_dev->dev) != 0) 
        {
            SEC_ERROR("Request firmware failed for %s\n",
                    cur_action_node->action_info.load.load_info.image_path);
            rc = SEC_INTERNAL_ERROR;
        }
        SEC_PM_TRACE();

        if (sec_pm_fw != NULL)
        {
            SEC_PM_TRACE();
            release_firmware(sec_pm_fw);
            sec_pm_fw = NULL;
        }
        SEC_PM_TRACE();
    }
    mutex_unlock(&sec_pm_action_list_mutex);

exit:
    SEC_PM_RET_TRACE();
    return rc;

error:
    if (sec_pm_fw != NULL)
        release_firmware(sec_pm_fw);
    if (tdp_config_struct.tdp_config_mem_ptr != NULL)
    {
        OS_FREE(tdp_config_struct.tdp_config_mem_ptr);
        tdp_config_struct.tdp_config_mem_ptr = NULL;
        tdp_config_struct.tdp_config_mem_size = 0;
    }
    goto exit;
}

//-----------------------------------------------------------------------------
// sec_pm_resume_fw_reload
//-----------------------------------------------------------------------------
static sec_result_t sec_pm_resume_fw_reload(void)
{
    sec_result_t            rc = SEC_SUCCESS;
    sec_result_t            int_rc = SEC_SUCCESS;
    sec_pm_action_node_t *  cur_node = NULL;
    sec_pm_action_node_t *  next_node = NULL;
    sec_module_list_t       mod_list[SEC_MAX_LOADED_FW_MODULES];
    uint32_t                mod_count = 0;
    uint32_t                mod_ver;
    uint32_t                resources = SEC_AES_RES  | SEC_EAU_RES
                                      | SEC_HASH_RES | SEC_SHMEM_RES;
    int                     i;
    
    SEC_PM_TRACE();

    /* Populate the list of loaded modules */
    sec_lock_resources(resources);
    rc = tracker_add_resources(current->tgid, resources);

    if (sec_fw_get_ver_info(mod_list, &mod_count, NULL) != SEC_SUCCESS)
    {
        sec_unlock_resources(resources);
        rc = tracker_remove_resources(current->tgid, resources);
        SEC_ERROR("Could not get list of loaded modules and resume reload\n");
        rc = SEC_INTERNAL_ERROR;
        goto exit;
    }

    sec_unlock_resources(resources);
    rc = tracker_remove_resources(current->tgid, resources);
    
    SEC_PM_DPRINT("Expected reloadable image count: %d; currently loaded: %d\n",
            sec_fw_image_load_count, mod_count);
    
    /* Iterate the FW action list */
    mutex_lock(&sec_pm_action_list_mutex);
    list_for_each_entry_safe(cur_node, next_node, &sec_pm_action_list, list)
    {
        switch (cur_node->action)
        {
        case SEC_FW_ACTION_LOAD_FW:
            SEC_PM_TRACE();
            mutex_lock(&sec_fw_list_mutex);
#ifdef SEC_PM_DEBUG
            /* If in DEBUG mode, go through the contig areas and hash them.
             * This may help us determine if memory is not being preserved
             * across a suspend/resume cycle */
            for (i = 0; i < SEC_MAX_FW_CONTIG_COUNT; i++)
            {
                if (cur_node->action_info.load.contig_mem_areas[i] == NULL)
                    break;
                SEC_PM_HASH_DPRINT(
                        cur_node->action_info.load.contig_mem_areas[i],
                        cur_node->action_info.load.contig_mem_sizes[i]);
            }
#endif /* SEC_PM_DEBUG */
            int_rc = _sec_fw_load_handler(
                            &cur_node->action_info.load.load_info,
                            &cur_node->action_info.load.ipl,
                            &cur_node->action_info.load.opl,
                            &cur_node->action_info.load.ish_pl,
                            &cur_node->action_info.load.osh_pl,
                            &mod_ver);
            if (int_rc != SEC_SUCCESS && int_rc != SEC_FW_MODULE_ALREADY_LOADED)
            {
                /* We failed to reload; remove the FW from the list */
                if (_sec_fw_remove_by_id(
                            cur_node->action_info.load.load_info.module_id) !=
                        SEC_SUCCESS)
                {
                    SEC_ERROR("Failed to remove the module ID from the list\n");
                    int_rc = SEC_FAIL;
                }
            }
            else
            {
                if((cur_node->action_info.load.load_info.module_id == SEC_TDP_DEV_MODULE_ID)|| (cur_node->action_info.load.load_info.module_id == SEC_TDP_MODULE_ID))
                {
                    int_rc = sec_tdp_configuration();
                    if(int_rc == SEC_SUCCESS)
                    {
                        int_rc = sec_tdp_resume_handler(&tdp_config_struct, cur_node->action_info.load.load_info.module_id);
                    }
                }
            }
            mutex_unlock(&sec_fw_list_mutex);
            break;
        case SEC_FW_ACTION_UNLOAD_FW:
            SEC_PM_TRACE();
            /* Unload the module */
            int_rc = sec_fw_unload_by_id(
                    cur_node->action_info.unload_check.loaded_fw_id);
            break;
        case SEC_FW_ACTION_PRELOADED_FW:
            /* Just check that the module was re-loaded as expected */
            SEC_PM_TRACE();
            int_rc = SEC_FAIL;  /* Set this to fail because when we find the
                                   module we will set to success */
            for (i = 0; i < SEC_MAX_LOADED_FW_MODULES; i++)
            {
                if (mod_list[i].module_id ==
                        cur_node->action_info.unload_check.loaded_fw_id)
                {
                    if((cur_node->action_info.unload_check.loaded_fw_id == SEC_TDP_DEV_MODULE_ID)|| (cur_node->action_info.unload_check.loaded_fw_id == SEC_TDP_MODULE_ID))
                    {
                        int_rc = sec_tdp_configuration();
                        if(int_rc == SEC_SUCCESS)
                        {
                            int_rc = sec_tdp_resume_handler(&tdp_config_struct, cur_node->action_info.unload_check.loaded_fw_id);
                        }
                    }
                    else
                        int_rc = SEC_SUCCESS;
                    break;
                }
            }
            if (int_rc != SEC_SUCCESS)
            {
                SEC_ERROR("Could not find a module we expected to be "
                          "loaded\n");
            }
            break;
        case SEC_FW_ACTION_LOAD_MANIFEST:
            SEC_PM_TRACE();
#ifdef SEC_PM_DEBUG
            /* If in DEBUG mode, go through the contig areas and hash them.
             * This may help us determine if memory is not being preserved
             * across a suspend/resume cycle */
            for (i = 0; i < SEC_MAX_FW_CONTIG_COUNT; i++)
            {
                if (cur_node->action_info.load.contig_mem_areas[i] == NULL)
                    break;
                SEC_PM_HASH_DPRINT(
                        cur_node->action_info.load.contig_mem_areas[i],
                        cur_node->action_info.load.contig_mem_sizes[i]);
            }
#endif /* SEC_PM_DEBUG */
            int_rc = sec_fw_manifest_load_handler(
                    &cur_node->action_info.load.load_info,
                    &cur_node->action_info.load.ipl,
                    &cur_node->action_info.load.opl);
            if (int_rc != SEC_SUCCESS)
            {
                SEC_ERROR("Couldn't reload manifest meaning subsequent FW "
                          "loads will likely fail.\n");
            }
            break;
        default:
            SEC_ERROR("Unknown FW action %d\n", cur_node->action);
            break;
        }
        if (int_rc != SEC_SUCCESS)
        {
            SEC_ERROR("Failed action %d\n", cur_node->action);
            rc = SEC_FAIL;
        }
        if (cur_node != NULL)
        {
            list_del(&(cur_node->list));
            sec_pm_cleanup_node(cur_node);
        }
    }
    mutex_unlock(&sec_pm_action_list_mutex);

exit:
    SEC_PM_RET_TRACE();
    return rc;
}


//-----------------------------------------------------------------------------
// sec_pm_suspend_handler
//
// This function performs any actions necessary when a suspend is requested.
// The system is supposed to be quiescent when a suspend request is received,
// but we can't guarantee that. Do our best to handle things in a sane manner.
//-----------------------------------------------------------------------------
int sec_pm_suspend_handler(void)
{
    int rc = 0;

    SEC_PM_DPRINT("SUSPEND REQUESTED; current state: %d\n", sec_pm_state);
    /* If we are already in the mode requested, return OK */
    if (sec_pm_state == SEC_PM_SUSPEND)
        goto exit;

    sec_pm_state = SEC_PM_SUSPEND;

     /*    Check if we are busy:
     *       If we are processing a command: reject suspend
     *       If we are not processing a command: lock command access */
    spin_lock(&sec_ioctl_state_lock);
    if (sec_ioctl_ref_count != 0)
    {
        spin_unlock(&sec_ioctl_state_lock);
        rc = -EBUSY;
        SEC_ERROR("Could not suspend; active IOCTL was present\n");
        goto error;
    }
    sec_ioctl_ref_count = -1;
    spin_unlock(&sec_ioctl_state_lock);

    /* Disable HW interrupts and our handler */
    sec_disable_output_interrupt();

    /* Free our registered system mem (if applicable; the function will handle
     * these checks;
     * As of this writing, this function only ever returns SEC_SUCCESS */
    sec_kernel_free_sysmem(SEC_ROM_MEM); // True indicates ROM memory

exit:
    SEC_PM_RET_TRACE();
    return rc; 

error:
    SEC_PM_TRACE();

    /* Clean up any actions we may have created */
    sec_pm_cleanup_action_list();

    /* If we are error-ing, we are still running */
    sec_pm_state = SEC_PM_RUNNING;

    /* Re-enable our IOCTL */
    spin_lock(&sec_ioctl_state_lock);
    sec_ioctl_ref_count = 0;
    spin_unlock(&sec_ioctl_state_lock);

    goto exit;
}

//-----------------------------------------------------------------------------
// sec_pm_resume_handler
//-----------------------------------------------------------------------------
int sec_pm_resume_handler(void)
{
    SEC_PM_TRACE();
    if (sec_pm_state == SEC_PM_RUNNING)
    {
        SEC_PM_TRACE();
        goto exit;
    }
    
    /* We are now in 'resume' mode */
    sec_pm_state = SEC_PM_RESUME;

    SEC_PM_TRACE();

   /* Make sure the device is active; if not re-activate it */
    if(gchip_info.host_device != PCI_DEVICE_CE2600)
    {
        if (sec_kernel_check_device() != SEC_SUCCESS)
        {
            SEC_ERROR("Device is being held in reset and we can't get it out\n");
            goto error;
        }
    }
    
    SEC_PM_TRACE();
    /* Re-enable our IRQ; if that fails, go back to low-power state */
    if (sec_enable_output_interrupt() != SEC_SUCCESS)
    {
        SEC_ERROR("Failed to re-setup sec interrupts");
        goto error;
    }
       
    /* Re-setup and register system memory to ROM; if this fails go back to
     * low-power state */
    if (sec_kernel_reg_sysmem(SEC_ROM_MEM) != SEC_SUCCESS)
    {
        SEC_ERROR("Could not allocate and register Linux system memory for "
                  "the SEC HW\n");
        goto error;
    }

    SEC_PM_TRACE();
    
    //CE2600 does not require reloading of firmwares as it does not go in reset.
    //During STR SEC CE2600 go in low power state c6. Firmware state stays as it is.
    if(gchip_info.host_device != PCI_DEVICE_CE2600)
    {
        /* Reload the FW images */
        if (sec_pm_resume_fw_reload() != SEC_SUCCESS)
        {
            SEC_ERROR("Could not reload/remove at least some firmware images\n");
        }
    }

    SEC_PM_TRACE();
    /* Re-enable our IOCTL */
    spin_lock(&sec_ioctl_state_lock);
    sec_ioctl_ref_count = 0;
    spin_unlock(&sec_ioctl_state_lock);

    sec_pm_state = SEC_PM_RUNNING;

exit:
    return 0;

error:
    SEC_PM_TRACE();

    /* Clean up any actions we may have created */
    sec_pm_cleanup_action_list();

    /* If we are error-ing, we are still suspended */
    sec_pm_state = SEC_PM_SUSPEND;

    goto exit;
}

