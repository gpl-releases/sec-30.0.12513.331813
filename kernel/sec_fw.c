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

#include <linux/bitops.h>
#include <linux/kernel.h>

#include "sec_types.h"
#include "sec_kernel.h"
#include "sec_tracker.h"
#include "sec_kernel_types.h"
#include "sec_common_types.h"

#include "sec_fw.h"
#include "sec_pm.h"
#include "x86_cache.h"

//-----------------------------------------------------------------------------
// D E B U G G I N G
//-----------------------------------------------------------------------------
//#define SEC_FW_DEBUG
                         
#ifdef SEC_FW_DEBUG
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

#define SEC_FW_DPRINT(str, ...)                             \
    printk(KERN_INFO "DEBUG (%s:%d) " str, __func__, __LINE__, ##__VA_ARGS__)
#define SEC_FW_TRACE()  SEC_FW_DPRINT("TRACE\n")
#define SEC_FW_RET_TRACE()  SEC_FW_DPRINT("Returning: %d (%s)\n", rc,       \
        SEC_RESULT_TEXT(rc))
#define SEC_FW_LOAD_INFO_DPRINT(load_info_ptr)                              \
    SEC_FW_DPRINT("Load Info: id: 0x%08x -- Path: %s\n",                    \
            load_info_ptr->module_id, load_info_ptr->image_path)

#define SEC_FW_DATA_PRINT(addr, size)                                       \
    do {                                                                    \
        int _data_tracker = 0;                                              \
        uint32_t * _data_temp = (uint32_t*)addr;                            \
        while (_data_tracker < size)                                        \
        {                                                                   \
            SEC_FW_DPRINT("(%04d) 0x%08x\n",                                \
                    _data_tracker, *_data_temp);                            \
            _data_tracker += 4;                                             \
            _data_temp++;                                                   \
        }                                                                   \
    } while (0);

#define SEC_FW_IPC_DPRINT(ipc)                                              \
    do {                                                                    \
        SEC_FW_DPRINT("IPC Info\n"                                          \
                "\tcmd = %d -- sub_cmd = 0x%08x\n"                          \
                "\tipc sizes: ipl %d -- ish %d -- opl %d -- osh %d\n"       \
                "\tipl 0x%p -- ish 0x%p -- opl 0x%p -- osh 0x%p\n"          \
                "\tsrc 0x%p -- src size %d\n"                               \
                "\tdest 0x%p -- dest size %d\n"                             \
                "\tsrc_dest_buf_type: %d\n",                                \
                (ipc)->cmd, (ipc)->sub_cmd.sc,                              \
                (ipc)->io_sizes.ipl_size, (ipc)->io_sizes.ish_size,         \
                (ipc)->io_sizes.opl_size, (ipc)->io_sizes.osh_size,         \
                (ipc)->ipl, (ipc)->ish_pl, (ipc)->opl, (ipc)->osh_pl,       \
                (ipc)->src, (ipc)->src_size, (ipc)->dst, (ipc)->dst_size,   \
                (ipc)->src_dst_buf_type);                                   \
    SEC_FW_DATA_PRINT((ipc)->ipl, (ipc)->io_sizes.ipl_size);                \
    } while (0)

#define SEC_FW_NODE_DPRINT(node_ptr)                         \
    SEC_FW_DPRINT("Node info: \n\tID: 0x%08X -- Index: %d\n\tPath:%s\n",    \
            node_ptr->node_info.loaded_fw_id,                               \
            node_ptr->node_info.index,                                      \
            node_ptr->image_path)

#define SEC_FW_LIST_DPRINT()                                                \
    do {                                                                    \
        sec_fw_list_node_t * cur_node = NULL;                               \
        SEC_FW_DPRINT("~~~~~~~~DEBUG PRINT OF FW LIST~~~~~~~~~~~\n");       \
        list_for_each_entry(cur_node, &sec_fw_list, list)                   \
            SEC_FW_NODE_DPRINT(cur_node);                                   \
        SEC_FW_DPRINT("~~~~~~~~END DEBUG PRINT OF FW LIST~~~~~~~~~~~\n");   \
    } while (0);

/* This hashes the contig mem areas to for debugging purposes */
static inline void SEC_FW_HASH_DPRINT(void * ptr, size_t size)
{
    int                  i = 0;
    struct scatterlist   sg_list[1];    /* Stores info about the mem to hash */
    struct crypto_hash * md5;           /* The transform we'll be using */
    struct hash_desc     desc;          /* Hash descriptor */
    uint8_t              result[16];    /* Result */

    OS_MEMSET(result, 0x00, 16);

    /* Setup the transform */
    sg_init_one(sg_list, ptr, size);
    md5 = crypto_alloc_hash("md5", 0, 0);
    if (IS_ERR(md5))
    {
        SEC_ERROR("Couldn't setup md5 transform\n");
        return;
    }
    desc.tfm = md5;
    desc.flags = 0;

    /* Execute */
    crypto_hash_digest(&desc, sg_list, 1, result);

    /* Print the result; add spaces for each 32 bits */
    SEC_FW_DPRINT("Hash for %p was: ", ptr);
    for (i = 0; i < 16; i++)
    {
        if (i % 4 == 0 && i != 0)
            printk(" ");
        printk("%02x", result[i]);
    }
    crypto_free_hash(md5);
    SEC_FW_DPRINT("\n\n");
    return;
}

#else /* SEC_FW_DEBUG */
#define SEC_FW_DPRINT(str, ...)
#define SEC_FW_TRACE()
#define SEC_FW_RET_TRACE()
#define SEC_FW_LOAD_INFO_DPRINT(load_info_ptr)
#define SEC_FW_NODE_DPRINT(node_ptr)
#define SEC_FW_LIST_DPRINT()
#define SEC_FW_IPC_DPRINT(ipc)
#define SEC_FW_HASH_DPRINT(ptr, size)
#define SEC_FW_DATA_PRINT(addr, size)
#endif /* SEC_FW_DEBUG */

//-----------------------------------------------------------------------------
// G L O B A L S
//-----------------------------------------------------------------------------
DEFINE_MUTEX(sec_fw_list_mutex);                /* Controls access to FW list */
LIST_HEAD(sec_fw_list);                         /* FW info list */
uint32_t sec_fw_image_load_count = 0;           /* Number of modules loaded */
static volatile unsigned long sec_fw_index_board = 0; /* Index scoreboard */
static uint32_t g_rom_version = 0;

//-----------------------------------------------------------------------------
// F U N C T I O N A L I T Y
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// D E F I N I T I O N S 
//-----------------------------------------------------------------------------
#define SEC_FW_MAX_LOAD_CHECKS  4       // Maximum number of time to check
                                        // whether a modules load succeeded
#define SEC_FW_MODULE_VER_OFFSET 0x30   // Module version offset in ICSS header
                                        // of fw module
#define SEC_FW_MANIFEST_ID 0x080865ec   // An ID which is invalid for firmware
                                        // modules, but one that we can use to
                                        // identify a SEC FW manifest

//-----------------------------------------------------------------------------
// sec_fw_cleanup_list_node
//
// This inline frees any space used by the node; currently, just the node
// itself.
//-----------------------------------------------------------------------------
static inline void sec_fw_cleanup_list_node(sec_fw_list_node_t * node)
{
    SEC_FW_DPRINT("Node address: 0x%p\n", node);
    if (node)
    {
        OS_FREE(node);
    }
    return;
}

//-----------------------------------------------------------------------------
// sec_fw_get_ver_info_ipc
//
// The following function issues an IPC command to retrieve version info of
// any loaded FW modules.
//
// NOTE: Import assumptions here are:
//       1. The SEC_AES_RES resource is locked before calling this function
//       2. mod_list is an array of (at least) size SEC_MAX_LOADED_FW_MODULES
//-----------------------------------------------------------------------------
static sec_result_t sec_fw_get_ver_info_ipc(sec_module_list_t * mod_list,
                                     uint32_t *          mod_count,
                                     uint32_t *          rom_ver)
{
    sec_result_t            rc = SEC_SUCCESS;
    sec_kernel_ipc_t        ipc;
    ipl_t                   ipl;
    opl_t                   opl;
    sec_ipc_return_t        ipc_ret;
    uint8_t *               fw_info_ptr = NULL;
    uint32_t                rom_version = 0;
    uint32_t                first_module_id = 0xdeaddead;
    sec_module_list_t       int_mod_list[SEC_MAX_LOADED_FW_MODULES] = {{0,0}};

    SEC_FW_TRACE();
    SEC_FW_DPRINT("Mod list: 0x%p; Mod count: 0x%p\n", mod_list, mod_count);

    if (mod_list == NULL || mod_count == NULL)
    {
        SEC_ERROR("Passed mod list or mod count was null\n");
        rc = -EINVAL;
        goto exit;
    }

    /* Prepare the IPC command */
    OS_MEMSET( &ipl, 0x00, sizeof(ipl_t));
    OS_MEMSET( &opl, 0x00, sizeof(opl_t));
    OS_MEMSET( &ipc, 0x00, sizeof(sec_kernel_ipc_t));

    SEC_FW_TRACE();

    ipl.get_fw_version.mod_buf_ptr = OS_VIRT_TO_PHYS(int_mod_list);
    ipl.get_fw_version.buffer_size = sizeof(int_mod_list);
    ipc.cmd = IPC_GET_HW_FW_VERSION;
    ipc.sub_cmd.sc = IPC_SC_NOT_USED;
    ipc.io_sizes.ipl_size = sizeof(ipl_get_fw_version_t);
    ipc.io_sizes.opl_size = SEC_HW_MAX_PAYLOAD;
    ipc.io_sizes.ish_size = SEC_HW_NO_SHAREDMEM;
    ipc.io_sizes.osh_size = SEC_HW_NO_SHAREDMEM;

    /* Send the IPC command */
    SEC_FW_DPRINT("Sending FW command\n");
    ipc_ret = sec_kernel_ipc(IPC_GET_HW_FW_VERSION, ipc.sub_cmd,
                             ipc.io_sizes, (ipl_t *)&ipl, &opl, NULL, NULL);
    rc = ipc2sec(ipc_ret);
    SEC_FW_DPRINT("Get version returned %d\n", rc);
    if (rc != SEC_SUCCESS)
    {
        SEC_ERROR("Retrieving FW module versions failed\n");
        goto exit;
    }
    /* Parse the data returned */
    OS_MEMSET(mod_list, 0x00,
            (sizeof(sec_module_list_t) * SEC_MAX_LOADED_FW_MODULES));
    fw_info_ptr = ((uint8_t*)&opl) + 4;
    OS_MEMCPY(&rom_version, fw_info_ptr, 4);
    SEC_FW_DPRINT("ROM Version: 0x%08x\n", rom_version);
    /* Set the received rom_ver; if we received on */
    if (rom_ver != NULL)
        *rom_ver = rom_version;

    OS_MEMCPY(mod_count, fw_info_ptr + 4, 4);
    SEC_FW_DPRINT("Original mod count returned was: %d\n", *mod_count);

    VERIFY_QUICK(*mod_count != 0, exit);

    /* Earlier ROMs, for which only one FW image could be loaded, would report
     * that 1 module had been loaded if any modules had been, and garbage if
     * nothing had been loaded; work around this. */
    if (rom_version < 0x2010006 && *mod_count != 1)
    {
        SEC_FW_DPRINT("Work around ROM module count bug\n");
        *mod_count = 0;
        /* Nothing else to be done here, so skip to the end */
        goto exit;
    }

    /* On CE4100, if a module is reported as loaded, and the ROM version is
     * 0x2010005 or earlier, it means we went through a warm-reset/reboot and
     * the SEC RAM is stale. Clear the returned info.
     * Note: some older modules may not increment the ROM version, but they
     *       also will not report as loaded using this command.
     */
    if (gchip_info.host_device == PCI_DEVICE_CE4100
            && rom_version <= 0x2010005
            && *mod_count != 0)
    {
        SEC_FW_DPRINT("Working around stale SEC RAM\n");
        *mod_count = 0;
        goto exit;
    }

    if (*mod_count > SEC_MAX_LOADED_FW_MODULES)
    {
        SEC_ERROR("Invalid mod count received: %d\n", *mod_count);
        rc = SEC_INTERNAL_ERROR;
        goto exit;
    }

    //Check if the output is came from 1200 or ROM
    first_module_id = *((uint32_t *)(fw_info_ptr + 8));

    // As the IPC is patched in 1200, Input and output params are different in
    // both. Output is distinguish based on the data after mod_count.
    // If the data after mod_count contains 1200 the the output came from 
    // 1200 module's patched IPC and complete list of loaded module can be 
    // obtained from dram_pointer passes in IPL.
    // If the data is not 1200 or mod_count is 0 then OPL is coming from ROM
    // and List of loaded firmware modules is obtained from OPL.
    if((first_module_id & SEC_IPC_MODULE_ID_MASK) == 0x1200)
    {
        SEC_FW_TRACE();
        OS_MEMCPY(mod_list, int_mod_list,
                (sizeof(sec_module_list_t) * (*mod_count)));
    }
    else
    {
        SEC_FW_TRACE();
        OS_MEMCPY(mod_list, fw_info_ptr + 8,
                (sizeof(sec_module_list_t) * (*mod_count)));

    }
#ifdef SEC_FW_DEBUG
    do {
        int i = 0;
        for (i = 0; i < *mod_count; i ++)
        {
            SEC_FW_DPRINT("Module ID: 0x%08x; Version: 0x%08x\n",
                    (unsigned int) mod_list[i].module_id,
                    (unsigned int) mod_list[i].module_version);
        }
    } while (0);
#endif /* SEC_FW_DEBUG */

exit:
    SEC_FW_RET_TRACE();
    return rc;
}



//-----------------------------------------------------------------------------
// sec_fw_get_ver_info
//
// The following function issues an IPC command to retrieve version info of
// any loaded FW modules.
//
// NOTE: Import assumptions here are:
//       1. The SEC_AES_RES resource is locked before calling this function
//       2. mod_list is an array of (at least) size SEC_MAX_LOADED_FW_MODULES
//-----------------------------------------------------------------------------
sec_result_t sec_fw_get_ver_info(sec_module_list_t * mod_list,
                                 uint32_t *          mod_count,
                                 uint32_t *          rom_ver)
{
    sec_result_t            rc = SEC_SUCCESS;
    sec_fw_list_node_t *    cur_node;
    int                     i;
    uint32_t                rom_version = g_rom_version;

    SEC_FW_TRACE();
    SEC_FW_DPRINT("Mod list: 0x%p; Mod count: 0x%p\n", mod_list, mod_count);
    if (mod_list == NULL || mod_count == NULL)
    {
        SEC_ERROR("Passed mod list or mod count was null\n");
        rc = -EINVAL;
        goto exit;
    }

    /* If we are in the suspend state we need to make the loader think
     * nothing is loaded; otherwise it will error */
    if (sec_pm_state == SEC_PM_SUSPEND)
    {
        SEC_FW_DPRINT("Get FW info called from suspend; returning 0s\n");
        goto exit;
    }
    
    SEC_FW_TRACE();

   /* Set the received rom_ver; if we received on */
    if (rom_ver != NULL)
        *rom_ver = rom_version;

    SEC_FW_DPRINT("Loaded count: %d\n", sec_fw_image_load_count);
    *mod_count = sec_fw_image_load_count;

    /* On CE4100, if a module is reported as loaded, and the ROM version is
     * 0x2010005 or earlier, it means we went through a warm-reset/reboot and
     * the SEC RAM is stale. Clear the returned info.
     * Note: some older modules may not increment the ROM version, but they
     *       also will not report as loaded using this command.
     */
    if (gchip_info.host_device == PCI_DEVICE_CE4100
            && rom_version <= 0x2010005
            && *mod_count != 0)
    {
        SEC_FW_DPRINT("Working around stale SEC RAM\n");
        *mod_count = 0;
        goto exit;
    }

    if (*mod_count > SEC_MAX_LOADED_FW_MODULES)
    {
        SEC_ERROR("Invalid mod count: %d\n", *mod_count);
        rc = SEC_INTERNAL_ERROR;
        goto exit;
    }

    mutex_lock(&sec_fw_list_mutex);
    i=0;
    list_for_each_entry(cur_node, &sec_fw_list, list)
    {
        /* If the module is only in the list for unload, skip it */
        if (cur_node->action == SEC_FW_ACTION_UNLOAD_FW ||
            cur_node->action == SEC_FW_ACTION_LOAD_MANIFEST || 
            cur_node->node_info.status == SEC_FW_UNLOADED)
            continue;
        SEC_FW_NODE_DPRINT(cur_node);
        mod_list[i].module_id = cur_node->node_info.loaded_fw_id;
        mod_list[i].module_version = cur_node->node_info.version;
        i++;
        SEC_FW_DPRINT("Loaded fw count from loop: %d\n", i);
    }
    
    mutex_unlock(&sec_fw_list_mutex);
    if(i != sec_fw_image_load_count)
    {
        SEC_FW_DPRINT("Invalid loaded fw count; %d != %d\n", i,
                      sec_fw_image_load_count);
        *mod_count = 0;
        /* Nothing else to be done here, so skip to the end */
        rc = SEC_INTERNAL_ERROR;
        goto exit;
    }
exit:
    SEC_FW_RET_TRACE();
    return rc;
  
}

//-----------------------------------------------------------------------------
// sec_fw_get_ver_info_from_user
//
// This function is a shim in to sec_fw_get_ver_info to allow user space to
// access its functionality. It received user pointers, performs the
// sec_fw_get_ver_info call, and copies the information back to the user-space
// pointers.
//-----------------------------------------------------------------------------
static sec_result_t sec_fw_get_ver_info_from_user(
        unsigned long __user *      user_rom_ver,
        unsigned long __user *      user_module_count,
        sec_module_list_t __user *  user_module_list)
{
    sec_result_t        rc = SEC_SUCCESS;
    uint32_t            rom_ver = 0;
    uint32_t            mod_count = 0;
    sec_module_list_t   mod_list[SEC_MAX_LOADED_FW_MODULES];   
    int                 i = 0;
    unsigned long       mod_count_from_user = 0;

    SEC_FW_TRACE();
    /* Check our arguments */
    if (user_rom_ver == NULL &&
            user_module_count == NULL &&
            user_module_list == NULL)
    {
        SEC_ERROR("Retrieving FW version info requires at least one valid "
                "param\n");
        rc = SEC_NULL_POINTER;
        goto exit;
    }

    SEC_FW_TRACE();
    /* Make sure our output is clean */
    OS_MEMSET(mod_list, 0x00,
            sizeof(sec_module_list_t) * SEC_MAX_LOADED_FW_MODULES);

    /* CE3100 and 4100: get the fw module data from IPC */
    if(gchip_info.host_device == PCI_DEVICE_CE3100 ||
       gchip_info.host_device == PCI_DEVICE_CE4100)
    {
        rc = sec_fw_get_ver_info_ipc(mod_list, &mod_count, &rom_ver);
    }
    /* CE4200 and CE5300: get the data from kernel list*/
    else
    {
        rc = sec_fw_get_ver_info(mod_list, &mod_count, &rom_ver);
    }

    if(rc != SEC_SUCCESS)
    {
        SEC_ERROR("Failed to get the FW ver info\n");
        goto exit;
    }

    SEC_FW_TRACE();
    /* Copy the rom version out */
    if (user_rom_ver)
    {
        if (!access_ok(VERIFY_WRITE, user_rom_ver, sizeof(unsigned long)))
        {
            SEC_ERROR("Argument to FW IOCTL handler was invalid; 0x%8p\n",
                       (unsigned long __user *)user_rom_ver);
            rc = -EINVAL;
            goto exit;
        }

        SEC_FW_DPRINT("user_rom_ver set to %08x\n", rom_ver);
        SAFE_COPY_TO_USER(user_rom_ver, &rom_ver, sizeof(unsigned long));
    }

    if (user_module_count)
    {
        /* copy the mod count from user */
        if (!access_ok(VERIFY_READ, user_module_count, 
                sizeof(unsigned long)))
        {
            SEC_ERROR("Argument to FW IOCTL handler was invalid; 0x%8p\n",
                       (unsigned long __user *)user_module_count);
            rc = -EINVAL;
            goto exit;
        }
        OS_MEMSET(&mod_count_from_user, 0x00, sizeof(mod_count_from_user));
        SAFE_COPY_FROM_USER(&mod_count_from_user, 
                (unsigned long __user *)user_module_count, 
                sizeof(unsigned long));
        
        SEC_FW_DPRINT("mod_count_from_user = %ld\n", mod_count_from_user);
        /* if the mod count from user is out of bounds then reset it to 
         * the mod count from kernel assuming its a random value */
        if(mod_count_from_user > SEC_MAX_LOADED_FW_MODULES)
            mod_count_from_user = mod_count;
        
        /* copy the kernel mod count to user mod count as a return value */
        if (!access_ok(VERIFY_WRITE, user_module_count, 
                sizeof(unsigned long)))
        {
            SEC_ERROR("Argument to FW IOCTL handler was invalid; 0x%8p\n",
                       (unsigned long __user *)user_module_count);
            rc = -EINVAL;
            goto exit;
        }

        mod_count &= 0x000000FF;
        SAFE_COPY_TO_USER(user_module_count, &mod_count, 
                sizeof(unsigned long));
        SEC_FW_DPRINT("mod_count = %d\n", mod_count);
    }

    if (user_module_list)
    {
        if (!access_ok(VERIFY_WRITE, user_module_list, 
                sizeof(sec_module_list_t) * mod_count_from_user))
        {
            SEC_ERROR("Argument to FW IOCTL handler was invalid; 0x%8p\n",
                       (unsigned long __user *)user_module_list);
            rc = -EINVAL;
            goto exit;
        }
       
        /* determine the number of modules to be returned to the user
         * */ 
        if(user_module_count)
        {       
            mod_count = min(mod_count, (uint32_t)mod_count_from_user);
        }
    
        /* Copy however much module information out as we can 
         * 2 comparisons are neccessary to avoid buffer overflow */
        for (i = 0; i < mod_count; i++)
        {
            SAFE_COPY_TO_USER(user_module_list + i, &mod_list[i],
                              sizeof(sec_module_list_t));
            SEC_FW_DPRINT("Copying module ID 0x%08X, version:0x%08x\n",
                    (unsigned int) (mod_list[i]).module_id, 
                    (unsigned int)(mod_list[i]).module_version);
        }
    }

exit:
    SEC_FW_RET_TRACE();
    return rc;
}
//-----------------------------------------------------------------------------
// sec_fw_reset_loaded_image_count
//
// In the event of an error, attempt to repopulate the index scoreboard and
// loaded image count with info from the list.
// While this function may not be fool-proof, and contains more code than
// absolutely necessary, it may help debug issues that occur.
//
// NOTE: This inline function makes the following assumptions:
//       1. The list lock has already been acquired
//-----------------------------------------------------------------------------
static void sec_fw_reset_loaded_image_count(void)
{
    int i = 0;
    sec_result_t        rc = SEC_SUCCESS;
    sec_fw_list_node_t * cur_node = NULL;
    sec_module_list_t   mod_list[SEC_MAX_LOADED_FW_MODULES];
    uint32_t            mod_count = -1;
    uint32_t            resources = SEC_AES_RES  | SEC_EAU_RES
                                  | SEC_HASH_RES | SEC_SHMEM_RES;

    SEC_FW_TRACE();
    SEC_FW_DPRINT("Loaded image count is %d\n", sec_fw_image_load_count);

    /* First, get the loaded module info straight from the HW/FW */
    sec_lock_resources(resources);
    rc = tracker_add_resources(current->tgid, resources);

    if (sec_fw_get_ver_info(mod_list, &mod_count, NULL) != SEC_SUCCESS)
    {
        SEC_ERROR("Could not get FW info from FW/HW; this will make recovery "
                  "even harder\n");
    }

    sec_unlock_resources(resources);
    rc = tracker_remove_resources(current->tgid, resources);

    /* Check how many indexes are used */
    sec_fw_image_load_count = 0;
    for (i = 0; i < SEC_MAX_LOADED_FW_MODULES; i++)
    {
        if (test_bit(i, &sec_fw_index_board))
        {
            sec_fw_image_load_count++;
        }
    }
    SEC_FW_DPRINT("Index board thinks count should be: %d\n",
            sec_fw_image_load_count);

    /* Iterate the image list; check to see if all the images listed
     * have their index bits set. At the same time, count that number of images
     * for below */
    i = 0; /* Re-use this to count the number of images in the list */
    list_for_each_entry(cur_node, &sec_fw_list, list)
    {
        SEC_FW_NODE_DPRINT(cur_node);
        i++;
        if (test_and_set_bit(cur_node->node_info.index, &sec_fw_index_board) !=
                1)
        {
            SEC_ERROR("Found that image 0x%08x:%s had index %d which was not "
                      " set in the scoreboard\n",
                      cur_node->node_info.loaded_fw_id,
                      cur_node->image_path,
                      cur_node->node_info.index);
        }
    }

    /* Finally, if it the count from the index scoreboard didn't match the list
     * count, reset the scoreboard using the image list */
    if (i != sec_fw_image_load_count)
    {
        SEC_ERROR("Index scoreboard count mis-matched list count; go with the "
                  "list information (board %d, list %d)\n",
                  sec_fw_image_load_count, i);
        sec_fw_index_board = 0;
        list_for_each_entry(cur_node, &sec_fw_list, list)
        {
            set_bit(cur_node->node_info.index, &sec_fw_index_board);
        }
    }

    SEC_FW_DPRINT("Final loaded image count: %d\n", sec_fw_image_load_count);
    return;
}

//-----------------------------------------------------------------------------
//  load_fw_op
//
//  For FW destined to be loaded on CE3100 or CE4100 this function makes the
//  ioctl call using the previously prepared ipc_arg, ipl, opl, ish_pl, and
//  osh_pl.  For FW destined to be loaded on CE4200 this function builds the
//  ELF FW module body and ROM Symbol Table scatter/gather arrays. It then
//  makes the ioctl call.
//-----------------------------------------------------------------------------
static sec_result_t load_fw_op( sec_kernel_ipc_t *ipc_arg,
                                ipl_t *ipl,
                                opl_t *opl,
                                ipc_shmem_t *ish_pl,
                                ipc_shmem_t *osh_pl )
{
    void             *fw_sg_vptr;
    uint32_t         *fw_sg_ptemp;
    int               fw_sg_size;
    uint32_t          fw_sg_pptr;

    void             *rom_sg_vptr;
    uint32_t         *rom_sg_ptemp;
    int               rom_sg_size;
    uint32_t          rom_sg_pptr;

    int               i, nremain, npages;
    uint32_t          nsize, pdata, cursize;
    sec_result_t      rc;
    sec_ipc_return_t  ipc_ret;

    ipc_ret = IPC_RET_COMMAND_COMPLETE;
    // Check passed in pointers that should always be non-NULL.
    VERIFY(ipc_arg != NULL, exit, rc, SEC_FAIL);
    VERIFY(ipl != NULL, exit, rc, SEC_FAIL);
    VERIFY(opl != NULL, exit, rc, SEC_FAIL);

    rom_sg_ptemp = NULL;
    rom_sg_vptr = NULL;
    rom_sg_size = 0;
    rom_sg_pptr = 0;

    // Note ish_pl and osh_pl can be NULL. This is not a bug.
    // When either is NULL it just means they are not used.

#ifdef DEBUG_LOAD_FW_OP
    printk(KERN_DEBUG "\nload_fw_op: ipc_arg->sub_cmd.sc_fwl = %d\n",
        (int)ipc_arg->sub_cmd.sc_fwl );
#endif

    if((gchip_info.host_device == PCI_DEVICE_CE3100)
    || (gchip_info.host_device == PCI_DEVICE_CE4100))
    {
        ipc_ret = sec_kernel_ipc(ipc_arg->cmd, ipc_arg->sub_cmd, ipc_arg->io_sizes, ipl, opl, ish_pl, osh_pl);
#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "load_fw_op: FW IPC return code = 0x%08x\n", (uint32_t)ipc_ret);
#endif
        //Translate an IPC return type to a sec driver return type.
        rc = ipc2sec(ipc_ret);
        VERIFY_QUICK(rc == SEC_SUCCESS, exit);
        sec_kernel_copy_to_user(ipc_arg, opl, osh_pl);
    }
    else
    {

//----------------------------------------------------------------------------
//   C a l c u l a t i n g   E L F   S y m b o l   T a b l e   E n t r i e s
//----------------------------------------------------------------------------
        pdata = ipl->data[7];
        nsize = ipl->data[8];
#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "\nload_fw_op: FW file is for CE4200\n");
        printk(KERN_INFO "\nload_fw_op: FW ELF Module is at 0x%08x\n", pdata);
        printk(KERN_INFO "load_fw_op: FW ELF Module is %d bytes\n", nsize);
#endif
        //Check the pdata pointer, it cannot be NULL
        VERIFY(pdata != 0, exit, rc, SEC_FAIL);

        npages = nsize / PAGE_SIZE;
        if((nsize % PAGE_SIZE) != 0) npages = npages + 1;
        fw_sg_size = npages * 8;
        fw_sg_vptr = OS_ALLOC(fw_sg_size);
        if(fw_sg_vptr == NULL)
        {
#ifdef DEBUG_LOAD_FW_OP
            printk(KERN_INFO "load_fw_op: could not allocate memory for FW ELF file scatter gather table\n");
#endif
    SEC_FW_TRACE();
            rc = SEC_FAIL;
            goto exit;
        }

        fw_sg_pptr = OS_VIRT_TO_PHYS(fw_sg_vptr);
        fw_sg_ptemp= (uint32_t*)fw_sg_vptr;

        ipl->data[7] = fw_sg_pptr;
        ipl->data[8] = npages; //Number of entries in the sg table

#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "\nload_fw_op: ELF fw_sg_vptr  0x%p\n", fw_sg_vptr);
        printk(KERN_INFO "load_fw_op: ELF fw_sg_pptr  0x%08x\n", fw_sg_pptr);
        printk(KERN_INFO "load_fw_op: ELF fw_sg_ptemp 0x%p\n", fw_sg_ptemp);
#endif

        //*fw_sg_ptemp = (uint32_t)(elfsrc.page_addr + elfsrc.offset);
        *fw_sg_ptemp = bswap(pdata);
#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "\nload_fw_op: (1) *fw_sg_ptemp 0x%08x\n",
               *fw_sg_ptemp);
#endif
        fw_sg_ptemp= fw_sg_ptemp + 1;
        if(nsize < PAGE_SIZE)
        {
            *fw_sg_ptemp = bswap(nsize);
        }
        else
        {
            *fw_sg_ptemp = bswap((uint32_t)PAGE_SIZE);
        }
#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "load_fw_op: (2) *fw_sg_ptemp 0x%08x\n", *fw_sg_ptemp);
#endif
        nremain = nsize - PAGE_SIZE;
        if(nremain > 0)
        {
            fw_sg_ptemp= fw_sg_ptemp + 1;
            // Build the FW Scatter/Gather Table
            for(i=1; i<npages; i++)
            {
                pdata = pdata + PAGE_SIZE;
                *fw_sg_ptemp = bswap(pdata);
#ifdef DEBUG_LOAD_FW_OP
                printk(KERN_INFO "load_fw_op: (%d) *fw_sg_ptemp 0x%08x\n",
                       (i*2+1) ,*fw_sg_ptemp);
#endif
                cursize = PWU_MIN(nremain, PAGE_SIZE);
                fw_sg_ptemp= fw_sg_ptemp + 1;
                *fw_sg_ptemp = bswap(cursize);
#ifdef DEBUG_LOAD_FW_OP
                printk(KERN_INFO "load_fw_op: (%d) *fw_sg_ptemp 0x%08x\n",
                       (i*2+2) ,*fw_sg_ptemp);
#endif
                fw_sg_ptemp= fw_sg_ptemp + 1;
                nremain = nremain - PAGE_SIZE;
            }
        }
        if(g_fast_path)
            cache_flush_buffer(fw_sg_vptr, fw_sg_size);
//----------------------------------------------------------------------------
//     D o n e   C a l c u l a t i n g   E L F   S y m b o l   T a b l e
//----------------------------------------------------------------------------


//----------------------------------------------------------------------------
//   C a l c u l a t i n g   R O M   S y m b o l   T a b l e   E n t r i e s
//----------------------------------------------------------------------------

        pdata = ipl->data[12];
        nsize = ipl->data[13];
#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "load_fw_op: FW ROM Symbol Table is at 0x%08x\n",
               pdata);
        printk(KERN_INFO "load_fw_op: FW ROM Symbol Table size %d bytes\n",
               nsize);
#endif

        /* It is possible that there isn't any ROM symbol table with the FW. */
        if((pdata > 0) && (nsize > 0))
        { // The ROM Symbol Table exists
            npages = nsize / PAGE_SIZE;
            if((nsize % PAGE_SIZE) != 0) npages = npages + 1;
            rom_sg_size = npages * 8;
            rom_sg_vptr = OS_ALLOC(rom_sg_size);
            if(rom_sg_vptr == NULL)
            {
                OS_FREE( fw_sg_vptr );
                rc = SEC_FAIL;
#ifdef DEBUG_LOAD_FW_OP
                printk(KERN_INFO "load_fw_op: could not allocate memory for "
                       "FW ROM symbol scatter gather table\n");
#endif
                goto exit;
            }

            rom_sg_pptr = OS_VIRT_TO_PHYS(rom_sg_vptr);
            rom_sg_ptemp = (uint32_t*)rom_sg_vptr;

            ipl->data[12] = rom_sg_pptr;
            ipl->data[13] = npages;

#ifdef DEBUG_LOAD_FW_OP
            printk(KERN_INFO "load_fw_op: ROM rom_sg_vptr 0x%p\n", rom_sg_vptr);
            printk(KERN_INFO "load_fw_op: ROM rom_sg_pptr 0x%08x\n",
                   rom_sg_pptr);
            printk(KERN_INFO "load_fw_op: ROM rom_sg_ptemp 0x%p\n",
                   rom_sg_ptemp);
#endif

            *rom_sg_ptemp = bswap(pdata);
#ifdef DEBUG_LOAD_FW_OP
            printk(KERN_INFO "\nload_fw_op: (1) *rom_sg_ptemp 0x%08x\n",
                    *rom_sg_ptemp);
#endif
            rom_sg_ptemp= rom_sg_ptemp + 1;
            if(nsize < PAGE_SIZE)
            {
                *rom_sg_ptemp = bswap(nsize);
            }
            else
            {
                *rom_sg_ptemp = bswap((uint32_t)PAGE_SIZE);
            }
#ifdef DEBUG_LOAD_FW_OP
            printk(KERN_INFO "load_fw_op: (2) *rom_sg_ptemp 0x%08x\n",
                    *rom_sg_ptemp);
#endif
            nremain = nsize - PAGE_SIZE;
            if(nremain > 0)
            {
                rom_sg_ptemp= rom_sg_ptemp + 1;

                // Build the FW Scatter/Gather Table
                for(i=1; i<npages; i++)
                {
                    pdata = pdata + PAGE_SIZE;
                    *rom_sg_ptemp = bswap(pdata);
#ifdef DEBUG_LOAD_FW_OP
                    printk(KERN_INFO "load_fw_op: (%d) *rom_sg_ptemp 0x%08x\n",
                           (i*2+1) ,*rom_sg_ptemp);
#endif
                    cursize = PWU_MIN(nremain, PAGE_SIZE);
                    rom_sg_ptemp= rom_sg_ptemp + 1;
                    *rom_sg_ptemp = bswap(cursize);
#ifdef DEBUG_LOAD_FW_OP
                    printk(KERN_INFO "load_fw_op: (%d) *rom_sg_ptemp 0x%08x\n",
                           (i*2+2) ,*rom_sg_ptemp);
#endif
                    rom_sg_ptemp= rom_sg_ptemp + 1;
                    nremain = nremain - PAGE_SIZE;
                } //ENDFOR the number of pages building the Scatter/Gather Table
            } //ENDIF the remainder is greater than zero
        } //ENDIF the ROM Symbol Table exists
        if(g_fast_path)
            cache_flush_buffer(rom_sg_vptr, rom_sg_size);
//----------------------------------------------------------------------------
//     D o n e   C a l c u l a t i n g   R O M   S y m b o l   T a b l e
//----------------------------------------------------------------------------

        //Get an unique job id
        ipl->data[0] = sec_get_job_id();

#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "\nload_fw_op: Here is the input payload\n");
        for(i=0; i<16; i++)
        {
            printk(KERN_INFO "load_fw_op: ipl->data[%d] = 0x%08X\n", i,
                    ipl->data[i]);
        }
        printk(KERN_INFO "\n");
#endif
        ipc_ret = sec_kernel_ipc(ipc_arg->cmd, ipc_arg->sub_cmd,
                                 ipc_arg->io_sizes, ipl, opl, ish_pl, osh_pl);
        SEC_FW_DPRINT("ipc_ret = 0x%08x %d\n", ipc_ret, ipc_ret);
#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "load_fw_op: FW IPC return code=0x%08x\n",
                (uint32_t)ipc_ret);
        if(ipc_ret == IPC_RET_INVALID_MODULUS_SIZE)
        {
            printk(KERN_INFO "load_fw_op: input payload endianness is wrong\n");
        }
#endif
        //Translate an IPC return type to a sec driver return type.
        rc = ipc2sec(ipc_ret);
        SEC_FW_RET_TRACE();

#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "load_fw_op: Returning data via opl=%p and "
                "osh_pl=%p\n", opl, osh_pl);
#endif

        if(rc == SEC_SUCCESS)
        {
            sec_kernel_copy_to_user(ipc_arg, opl, osh_pl);
        }

#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "load_fw_op: Releasing user space pages from kernel "
                "physical memory\n");
#endif


#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "load_fw_op: Freeing memory allocated for scatter "
                "gather tables\n");
        if(rom_sg_vptr != NULL)
        {
            printk(KERN_INFO "load_fw_op: Freeing rom_sg_vptr at %p and "
                    "fw_sg_vptr at %p\n", rom_sg_vptr, fw_sg_vptr);
        }
        else
        {
            printk(KERN_INFO "\nload_fw_op: NO ROM scatter/gather to free\n");
            printk(KERN_INFO "load_fw_op: Freeing fw_sg_vptr at %p\n\n",
                    fw_sg_vptr);
        }
#endif
        // Free the memory allocated for the scatter gather tables
        if(rom_sg_vptr != NULL) OS_FREE( rom_sg_vptr );
        OS_FREE( fw_sg_vptr );

#ifdef DEBUG_LOAD_FW_OP
        printk(KERN_INFO "load_fw_op: Done loading CE4200 FW\n");
#endif
    } //ENDIF the FW file was for CE4200

exit:
    if (rc == SEC_OUT_OF_MEMORY)
    {
        SEC_ERROR("SEC ran out of memory\n");
    }
    return rc;
} /* ENDPROC load_fw_op */


//-----------------------------------------------------------------------------
//  unload_fw_op
//  This routine unloads previously loaded FW from the CE4200
//-----------------------------------------------------------------------------
static sec_result_t unload_fw_op(   sec_kernel_ipc_t *ipc_arg,
                                    ipl_t *ipl,
                                    opl_t *opl,
                                    ipc_shmem_t *ish_pl,
                                    ipc_shmem_t *osh_pl )
{
    sec_result_t      rc;
    sec_ipc_return_t  ipc_ret;

    if(ipc_arg == NULL) return SEC_NULL_POINTER;
    if(ipl == NULL) return SEC_NULL_POINTER;
    if(opl == NULL) return SEC_NULL_POINTER;
    if(ipc_arg->sub_cmd.sc_fwl == IPC_SC_PRECE4200) return SEC_NOT_SUPPORTED;

    rc = SEC_SUCCESS;

    //Get an unique job id
    ipl->data[0] = sec_get_job_id();

    ipc_ret = sec_kernel_ipc(ipc_arg->cmd, ipc_arg->sub_cmd, ipc_arg->io_sizes, ipl, opl, ish_pl, osh_pl);

#ifdef DEBUG_UNLOAD_FW_OP
        printk(KERN_INFO "unload_fw_op: FW IPC return code=0x%08x\n",
                (uint32_t)ipc_ret);
#endif
    //Translate an IPC return type to a sec driver return type.
    rc = ipc2sec(ipc_ret);
#ifdef DEBUG_UNLOAD_FW_OP
    printk(KERN_INFO "unload_fw_op: Returning data via opl=%p and osh_pl=%p\n",
            opl, osh_pl);
#endif

    if(rc == SEC_SUCCESS)
    {
        sec_kernel_copy_to_user(ipc_arg, opl, osh_pl);
    }

    return rc;
} /* ENDPROC unload_fw_op */


//-----------------------------------------------------------------------------
// sec_fw_return_index
//
// This function returns an index number back to the pool of available index
// numbers. If the index returned was not in use, report it, and return an
// error code (SEC_FAIL).
//
// NOTE: Because this is only called from within this file, this function makes
//       two assumptions:
//       1. The list lock has already been acquired
//       2. Index is a valid address
//-----------------------------------------------------------------------------
static sec_result_t sec_fw_return_index(uint32_t * index)
{
    sec_result_t rc = SEC_FW_INVALID_LOADED_FW_COUNT;

    SEC_FW_DPRINT("Arg check: %d\n", *index);
    /* Check that the index being returned is reasonable */
    if ((*index >= sizeof(sec_fw_index_board) * BITS_PER_BYTE) || 
        (*index > SEC_MAX_LOADED_FW_MODULES))
    {
        SEC_ERROR("Invalid index bit value: %d\n", *index);
        rc = SEC_FW_INVALID_LOADED_FW_COUNT;
        goto exit;
    }
    else if (test_and_clear_bit(*index, &sec_fw_index_board) == 0)
    {
        /* At this point the bit should be valid; clear it. If it wasn't set,
         * return an error... */
        SEC_ERROR("Freeing an unused index\n");

        /* To try to maintain sanity, count the taken index numbers */
        sec_fw_reset_loaded_image_count();

        rc = SEC_FAIL;
        goto exit;
    }
    else
    {
        /* If the bit was set, decrement the image count, and return success */
        SEC_FW_TRACE();
        *index = -1;
        sec_fw_image_load_count--;
        rc = SEC_SUCCESS;
    }
    SEC_FW_TRACE();
    
exit:
    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_get_index
//
// This function reserves an index field from the list of available index
// numbers. The index is returned through the int pointer passed. If no index
// is currently available, set the returned index to -1, and return
// SEC_FW_INVALID_LOADED_FW_COUNT.
//
// NOTE: Because this is only called from within this file, this function makes
//       two assumptions:
//       1. The list lock has already been acquired
//       2. Index is a valid address
//-----------------------------------------------------------------------------
static sec_result_t sec_fw_get_index(uint32_t * index)
{
    /* Although this should have already been checked, if we can't get an
     * index we are full */
    sec_result_t rc = SEC_FW_INVALID_LOADED_FW_COUNT;
    int i = 0;
    
    SEC_FW_TRACE();
    SEC_FW_DPRINT("Index: %d\n", *index);
    *index = -1;
    for (i = 0; i < SEC_MAX_LOADED_FW_MODULES; i++)
    {
        /* Set the bit; if it was already 1, we need to test the next bit.
         * If it was zero we reserved our spot */
        if (test_and_set_bit(i, &sec_fw_index_board) == 0)
        {
            SEC_FW_DPRINT("Found index at: %d\n", i);
            sec_fw_image_load_count++;
            SEC_FW_DPRINT("updated fw image count: %d\n", 
                            sec_fw_image_load_count);
            *index = i;
            rc = SEC_SUCCESS;
            break;
        }
    }

    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_add_list_node
//
// This function receives information about a newly loaded FW module, and adds
// that information to the kernels list. 
//-----------------------------------------------------------------------------
static sec_result_t sec_fw_add_list_node(sec_fw_load_time_t     loaded_by,
                                         const char *           file_path,
                                         uint32_t               id,
                                         uint32_t               version,
                                         sec_fw_loading_status_t status,
                                         sec_fw_action_t        action)
{
    sec_result_t            rc = SEC_SUCCESS;
    sec_fw_list_node_t *    new_node = NULL;

    SEC_FW_TRACE();
    SEC_FW_DPRINT("Adding Node:\n"
                  "\tLoaded by: %d; ID: 0x%08x; Version: 0x%08x; Status: %d\n"
                  "\tPath: %s\n", loaded_by, id, version, status,
                  ((file_path) ? file_path : "(NO FILE NAME PASSED)"));

    /* Allocate and cleanup the new node */
    new_node = OS_ALLOC(sizeof(sec_fw_list_node_t));
    if (new_node == NULL)
    {
        SEC_ERROR("Could not allocate a new list node\n");
        rc = SEC_OUT_OF_MEMORY;
        goto error;
    }
    OS_MEMSET(new_node, 0x00, sizeof(sec_fw_list_node_t));
    
    /* Set the info stored in the new node to that we received when called */
    new_node->loaded_by = loaded_by;
    new_node->node_info.loaded_fw_id = id;
    new_node->node_info.status = status;
    new_node->node_info.version = version;
    new_node->action = action;
    /* Get an index for the new node; if this is a manifest don't get an index
       as we won't be reporting it back to the user */
    if (id != SEC_FW_MANIFEST_ID)
        SEC_RESULT_TRY(sec_fw_get_index(&(new_node->node_info.index)), error);

    if (loaded_by == SEC_FW_LOADED_FILESYSTEM)
    {
        /* If a path was provided we at least have a chance of re-loading */
        if (file_path == NULL || strlen(file_path) == 0 ||
                file_path[0] != '/' || strlen(file_path) > SEC_FW_MAX_PATH_LEN)
        {
            SEC_ERROR("An absolute path was not passed to a node added from "
                      "the FS\n");
            rc = SEC_INTERNAL_ERROR;
            goto exit;
        }
        strncpy(new_node->image_path, file_path, SEC_FW_MAX_PATH_LEN);
        new_node->image_path[SEC_FW_MAX_PATH_LEN - 1] = '\0';
    }
    /* TODO: Do we want to store direct binary load in RAM for reload? */

    SEC_FW_NODE_DPRINT(new_node);

    /* Add the new node to the tail of the list */
    list_add_tail(&(new_node->list), &sec_fw_list);

    SEC_FW_LIST_DPRINT();

exit:
    SEC_FW_RET_TRACE();
    return rc;

error:
    SEC_FW_TRACE();
    if (new_node)
        OS_FREE(new_node);
    goto exit;
}

//-----------------------------------------------------------------------------
// sec_fw_delete_list_node
//
// This function removes a node from the list, returns its index, and cleans
// up its allocated contents.
//
// NOTE: This function makes the following assumptions:
//       1. The list lock has already been acquired
//-----------------------------------------------------------------------------
static sec_result_t sec_fw_delete_list_node(sec_fw_list_node_t * del_node)
{
    sec_result_t rc = SEC_SUCCESS;

    SEC_FW_TRACE();
    SEC_FW_NODE_DPRINT(del_node);
    /* Remove the item from the list, then return the index, then clean it up;
     * This will help us recover the list if we do run in to some sort of
     * error situation */
    list_del(&(del_node->list));
    
    /* No index was alloted for manifest files */ 
    if (del_node->node_info.loaded_fw_id != SEC_FW_MANIFEST_ID )
    {
        if (sec_fw_return_index(&(del_node->node_info.index)) != SEC_SUCCESS)
        {
            SEC_ERROR("Invalid index in the item to be deleted\n");
            rc = SEC_INTERNAL_ERROR;
        }
    }
    sec_fw_cleanup_list_node(del_node);

    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_get_ver_info_by_id
//
// The following function retrieves module version info for a particular FW
// module ID.
//
// NOTE: Import assumptions here are:
//       1. The SEC_AES_RES resource is locked before calling this function
//-----------------------------------------------------------------------------
sec_result_t sec_fw_get_ver_info_by_id(uint32_t id, uint32_t * ver)
{
    sec_result_t        rc = SEC_SUCCESS;
    sec_module_list_t   mod_list[SEC_MAX_LOADED_FW_MODULES];
    uint32_t            mod_count = 0;
    int                 i = 0;

    SEC_FW_TRACE();
    SEC_FW_DPRINT("id: 0x%08x; ver: 0x%p\n", id, ver);

    /* Verify our arguments */
    if (ver == NULL)
    {
        SEC_ERROR("Invalid version pointer passed\n");
        rc = -EINVAL;
        goto exit;
    }

    /* Set our values to something sane out of paranoia */
    *ver = SEC_FW_UNKNOWN_MODULE_VER;
    OS_MEMSET(mod_list, 0x00,
            sizeof(sec_module_list_t) * SEC_MAX_LOADED_FW_MODULES);

    /* Retrieve info about loaded modules */
    SEC_RESULT_TRY(sec_fw_get_ver_info(mod_list, &mod_count, NULL), exit);

    /* Iterate the list, and find the ID we're looking for */
    for (i = 0; i < mod_count; i++)
    {
        if (mod_list[i].module_id == id)
        {
            SEC_FW_DPRINT("Found module 0x%08x; version = 0x%08x\n",
                          id, (unsigned int) mod_list[i].module_version);
            *ver = mod_list[i].module_version;
            goto exit;
        }
    }

    /* If we didn't find the ID return an error */
    SEC_FW_DPRINT("Never found a module ID for %d\n", id);
    rc = SEC_INTERNAL_ERROR;

exit:
    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// _sec_fw_remove_by_id
// 
// The following function finds a list entry by module ID, and removes the list
// entry.
// IMPORTANT: You MUST be holding the sec_fw_list_mutex before calling this!
//-----------------------------------------------------------------------------
sec_result_t _sec_fw_remove_by_id(uint32_t module_id)
{
    sec_result_t            rc = SEC_FAIL;
    sec_fw_list_node_t *    cur_node;
    sec_fw_list_node_t *    next_node;
    
    SEC_FW_TRACE();
    SEC_FW_DPRINT("Module ID for removal: 0x%08x\n", module_id);

    list_for_each_entry_safe(cur_node, next_node, &sec_fw_list, list)
    {
        SEC_FW_NODE_DPRINT(cur_node);
        if (cur_node->node_info.loaded_fw_id == module_id)
        {
            /* We found the node; remove it, clean up the memory, and exit */
            if (cur_node->loaded_by == SEC_FW_LOADED_INIT)
            {
                /* If this node was loaded at init time by something else, we
                 * will need to remove it on resume */
                SEC_FW_DPRINT("Setting 0x%08x for auto removal\n", module_id);
                cur_node->action = SEC_FW_ACTION_UNLOAD_FW;
                if (sec_fw_return_index(&(cur_node->node_info.index)) !=
                        SEC_SUCCESS)
                {
                    SEC_ERROR("Invalid index in the item to be deleted\n");
                    rc = SEC_INTERNAL_ERROR;
                }
                rc = SEC_SUCCESS;
                goto exit;
            }
            else
            {
                SEC_FW_DPRINT("Found the node for removal\n");
                rc = sec_fw_delete_list_node(cur_node);
                goto exit;
            }
        }
    }
    /* If we got here, we didn't find the name we were looking for... */
    SEC_ERROR("Could not find image by ID: 0x%08x\n", module_id);

exit:
    SEC_FW_RET_TRACE();
    return rc;
}
//-----------------------------------------------------------------------------
// sec_fw_remove_by_id
// 
// The following function finds a list entry by module ID, and removes 
//-----------------------------------------------------------------------------
sec_result_t sec_fw_remove_by_id(uint32_t module_id)
{
    sec_result_t            rc = SEC_FAIL;

    SEC_FW_TRACE();
    SEC_FW_DPRINT("Module ID for removal: 0x%08x\n", module_id);

    mutex_lock(&sec_fw_list_mutex);
    rc = _sec_fw_remove_by_id(module_id);
    mutex_unlock(&sec_fw_list_mutex);
    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// _sec_fw_load_handler
//
// This function handles any load commands passes through the SEC_FW IOCTL.
// This action includes:
// --- Calling the load op
// --- (If successful) Add info about this module to the FW list
//-----------------------------------------------------------------------------
sec_result_t _sec_fw_load_handler(sec_fw_load_t * load_info,
                                  ipl_t *         ipl,
                                  opl_t *         opl,
                                  ipc_shmem_t *   ish_pl,
                                  ipc_shmem_t *   osh_pl,
                                  uint32_t *      mod_ver)
{
    sec_result_t        rc               = SEC_SUCCESS;
    sec_result_t        rc_alt           = SEC_SUCCESS;
    sec_module_list_t   mod_list         [SEC_MAX_LOADED_FW_MODULES];
    uint32_t            mod_count        = 0;
    uint32_t            search_attempts  = 0;
    uint32_t            resources        = SEC_AES_RES  | SEC_EAU_RES
                                         | SEC_HASH_RES | SEC_SHMEM_RES;
    uint32_t            rom_version = 0;

    SEC_FW_TRACE();
    SEC_FW_LOAD_INFO_DPRINT(load_info);

    /* Send the load */
    sec_lock_resources(resources);
    rc = tracker_add_resources(current->tgid, resources);
    if ( rc != SEC_SUCCESS )
    {
        goto exit_unlock_resources;
    }
    
    rc = load_fw_op(&(load_info->ipc_call), ipl, opl, ish_pl, osh_pl);
    SEC_FW_TRACE();
    
    /* Get the version; this double checks that the module authenticated */
    /* If this is a 0x2000 module, don't check; it only responds through a
       different interface */
    if (rc == SEC_SUCCESS) 
    {
        SEC_FW_TRACE();
        if((load_info->module_id & 0x80000000) == 0
            && (load_info->module_id != 0x2000)
            && (gchip_info.host_device == PCI_DEVICE_CE3100 ||
                    gchip_info.host_device == PCI_DEVICE_CE4100)
          )
        {
            /* Use rc as our method of determining whether a module loaded:
             * 1. DIDNOT_AUTH: try again (if we have more tries remaining)
             * 2. SUCCESS: Found our module
             * 3. (Some other ret code): Ran in to an error
             */
            SEC_FW_TRACE();
            rc = SEC_FW_LOAD_DIDNOT_AUTHENTICATE;
            while (rc == SEC_FW_LOAD_DIDNOT_AUTHENTICATE && 
                    search_attempts < SEC_FW_MAX_LOAD_CHECKS)
            {
                /* On CE3100 / 4100 check to make sure at least something loaded */
                rc = sec_fw_get_ver_info_ipc(mod_list, &mod_count, &rom_version);
                // If we succeed, but not mods are returned, we didn't find it
                if (rc == SEC_SUCCESS && mod_count == 0)
                    rc = SEC_FW_LOAD_DIDNOT_AUTHENTICATE;

                SEC_FW_TRACE();
                /* If we failed to find the module: sleep before trying again.
                 * 2 microseconds seems to be a sane wait between searches */
                if (rc == SEC_FW_LOAD_DIDNOT_AUTHENTICATE &&
                        ++search_attempts < SEC_FW_MAX_LOAD_CHECKS)
                {
                    udelay(2);
                }
            }
        } else {
        
            SEC_FW_TRACE();
            /* call get_ver_info_ipc to get rom_version */
            rc = sec_fw_get_ver_info_ipc(mod_list, &mod_count, &rom_version);

            //Following HACK is for CE4200 only
            //NOTE: Both 1100 and 1200 can have 1100 as module id in fw binary
            //HACK: if FW bianry has module id = 1100 but module list returns
            // module id as 1200 then change the module_id in load info to 1200
            if((load_info->module_id & SEC_IPC_MODULE_ID_MASK) == 0x1100
                 && (gchip_info.host_device == PCI_DEVICE_CE4200) )

            {
                bool b_1200_loaded = false;
                bool b_1100_loaded = false;
                int  i = 0;
                SEC_FW_TRACE();
                for(i=0; i<mod_count; i++)
                {
                    // check if 1200 module is loaded
                    if((mod_list[i].module_id & SEC_IPC_MODULE_ID_MASK) == 0x1200)
                    {
                        b_1200_loaded = true;
                        break;
                    }
                }
                for(i=0; i<mod_count; i++)
                {
                    // check if 1100 module is loaded
                    if((mod_list[i].module_id & SEC_IPC_MODULE_ID_MASK) == 0x1100)
                    {
                        b_1100_loaded = true;
                        break;
                    }
                }

                //HACK: If list says 1200 is loaded and load_info says 1100 is loaded
                // change load_info->module_id to 1200
                if(!b_1100_loaded && b_1200_loaded)
                {
                    SEC_FW_TRACE();
                    //Preserve 31st bit in module_id
                    load_info->module_id &= 0x80000000;
                    load_info->module_id |= 0x00001200;
                }
            }
        }
        /* Update global value of rom version */
        g_rom_version = rom_version;
        SEC_FW_DPRINT("rom version after load 0x%08x\n", g_rom_version);
    }

    rc_alt = tracker_remove_resources(current->tgid, resources);
    /*  We do not want to "forget" about any errors indicated by rc, so we
     *  only set rc to the new result if rc currently indicates SEC_SUCCESS.
     */
    rc = (rc == SEC_SUCCESS ) ? rc_alt : rc;
    
    VERIFY_QUICK(rc == SEC_SUCCESS, exit_unlock_resources);

    /* Get the version of the current module from ipl */
   if(gchip_info.host_device != PCI_DEVICE_CE3100 &&
       gchip_info.host_device != PCI_DEVICE_CE4100) 
   {
        uint32_t            *vaddr_mod_ver = NULL;;
        SEC_FW_TRACE();
        vaddr_mod_ver = phys_to_virt((ipl->data[4] + SEC_FW_MODULE_VER_OFFSET));
        if(vaddr_mod_ver)
        {
            SEC_FW_TRACE();
            *mod_ver = bswap(*vaddr_mod_ver);
            vaddr_mod_ver = NULL;
            SEC_FW_DPRINT("firmware version: 0x%08x\n", *mod_ver);
        }
    }
    //Register memory for 1200 module
    if((load_info->module_id & SEC_IPC_MODULE_ID_MASK) == 0x1200)
    {
        rc = sec_kernel_reg_sysmem(SEC_FW_PAGER_MEM); 
    }



exit_unlock_resources:;
    sec_unlock_resources(resources);

    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_load_handler
//
// This function handles any load commands passes through the SEC_FW IOCTL.
// This action includes:
// --- Copying user space info for input to the IPC
// --- Calling the load op
// --- (If successful) Add info about this module to the FW list
//-----------------------------------------------------------------------------
static sec_result_t sec_fw_load_handler(sec_fw_load_t * load_info)
{
    sec_result_t        rc = SEC_SUCCESS;
    ipl_t               ipl;
    opl_t               opl;
    ipc_shmem_t         ish_pl;
    ipc_shmem_t         osh_pl;
    uint32_t            mod_ver = 0;
    uint32_t            max_modules = -1;
    sec_fw_list_node_t * cur_node = NULL;
    sec_fw_list_node_t * next_node = NULL;

    SEC_FW_TRACE();
    SEC_FW_LOAD_INFO_DPRINT(load_info);

    OS_MEMSET(&ipl, 0x00, sizeof(ipl_t));
    OS_MEMSET(&opl, 0x00, sizeof(opl_t));
    OS_MEMSET(&ish_pl, 0x00, sizeof(ipc_shmem_t));
    OS_MEMSET(&osh_pl, 0x00, sizeof(ipc_shmem_t));

    /* Verify and copy payloads from user-space; use 'write' because we will
     * be writing to these addresses later */
    VERIFY_AND_COPY_FROM_USER(&ipl, load_info->ipc_call.ipl,
                              sizeof(ipl_t), VERIFY_WRITE);
    VERIFY_AND_COPY_FROM_USER(&opl, load_info->ipc_call.opl,
                              sizeof(opl_t), VERIFY_WRITE);
    VERIFY_AND_COPY_FROM_USER(&ish_pl, load_info->ipc_call.ish_pl,
                              sizeof(ipc_shmem_t), VERIFY_WRITE);
    VERIFY_AND_COPY_FROM_USER(&osh_pl, load_info->ipc_call.osh_pl,
                              sizeof(ipc_shmem_t), VERIFY_WRITE);

#ifdef SEC_FW_DEBUG
    /* MD5 hash memory for debugging purposes */
    do {
        int i = 0;
        sec_contig_mem_t    this_contig;
        if (sec_pm_state == SEC_PM_RUNNING)
        {
            for (i = 0; i < SEC_MAX_FW_CONTIG_COUNT; i++)
            {
                SEC_FW_DPRINT("Hash check for %p\n", load_info->contig_mem[i]);
                if (load_info->contig_mem[i] == NULL)
                    break;
                VERIFY_AND_COPY_FROM_USER(&this_contig,
                                          load_info->contig_mem[i],
                                          sizeof(sec_contig_mem_t),
                                          VERIFY_READ);
                SEC_FW_HASH_DPRINT(this_contig.kernel_vaddr, this_contig.size);
            }
        }
    } while (0);
#endif /* SEC_FW_DEBUG */

    /* Make sure we aren't trying to load more modules than we can */
    switch (gchip_info.host_device)
    {
    case PCI_DEVICE_CE3100:
    case PCI_DEVICE_CE4100:
        max_modules = SEC_MAX_CE3100_FW_MODULES;
        break;
    case PCI_DEVICE_CE2600:
    case PCI_DEVICE_CE4200:
    case PCI_DEVICE_CE5300:
        max_modules = SEC_MAX_CE4200_FW_MODULES;
        break;
    default:
        SEC_ERROR("Unrecognized host device: %d\n", gchip_info.host_device);
        rc = SEC_INTERNAL_ERROR;
        goto exit;
    }
    /* TODO: This is a temporary workaround for FW reported as loaded on
     *       CE3100 and CE4100 after a soft-reset which is not actually loaded.
     *       The load will still fail if a module has already been loaded, but
     *       with INVALID_REQUEST instead of FULL */
    if (gchip_info.host_device != PCI_DEVICE_CE3100 &&
            gchip_info.host_device != PCI_DEVICE_CE4100)
    {
        if (sec_fw_image_load_count >= max_modules)
        {
            rc = SEC_FW_CANNOT_LOAD_FULL;
            goto exit;
        }
    }

    /* Call the function which actually transmits the IPC command */
    rc = _sec_fw_load_handler(load_info,  &ipl,  &opl,
                              &ish_pl,  &osh_pl,  &mod_ver);
    if (rc != SEC_SUCCESS)
    {
        SEC_ERROR("Could not successfully load the module\n");
        goto exit;
    }

    /* We will be modifying the list; lock it */
    mutex_lock(&sec_fw_list_mutex);

    /* TODO: This is a temporary workaround for FW reported as loaded on
     *       CE3100 and CE4100 after a soft-reset which is not actually loaded.
     *       Remove any entries from the list which were previously loaded
     */
    if (gchip_info.host_device == PCI_DEVICE_CE3100 ||
            gchip_info.host_device == PCI_DEVICE_CE4100)
    {
        SEC_FW_DPRINT("Cleaning up 'previously loaded' modules\n");
        list_for_each_entry_safe(cur_node, next_node, &sec_fw_list, list)
        {
            sec_fw_delete_list_node(cur_node);
        }
    }


    /* Add a node to the fw info list */
    SEC_RESULT_TRY(sec_fw_add_list_node(load_info->loaded_by,
                                        load_info->image_path,
                                        load_info->module_id,
                                        mod_ver,
                                        SEC_FW_LOADED,
                                        SEC_FW_ACTION_LOAD_FW),
                    error_mutex_locked);

    mutex_unlock(&sec_fw_list_mutex);

exit:
    SEC_FW_RET_TRACE();
    return rc;

error_mutex_locked:       /* If the list is locked */
    mutex_unlock(&sec_fw_list_mutex);
    goto exit;
}

//-----------------------------------------------------------------------------
// _sec_fw_unload_handler
//
// This function handles the FW unload IOCTL. It requests that the firmware
// image be removed, and the image removed from the list.
//-----------------------------------------------------------------------------
static sec_result_t _sec_fw_unload_handler(sec_fw_load_t * load_info,
                                           ipl_t *         ipl,
                                           opl_t *         opl,
                                           ipc_shmem_t *   ish_pl,
                                           ipc_shmem_t *   osh_pl)
{
    sec_result_t    rc = SEC_SUCCESS;
    uint32_t        resources = SEC_AES_RES  | SEC_EAU_RES
                              | SEC_HASH_RES | SEC_SHMEM_RES;

    SEC_FW_TRACE();

    sec_lock_resources(resources);
    rc = tracker_add_resources(current->tgid, resources);

    SEC_FW_TRACE();
    rc = unload_fw_op(&(load_info->ipc_call), ipl, opl, ish_pl, osh_pl);

    sec_unlock_resources(resources);
    tracker_remove_resources(current->tgid, resources);

    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_unload_handler
//
// This function handles the FW unload IOCTL. It requests that the firmware
// image be removed, and the image removed from the list.
//-----------------------------------------------------------------------------
static sec_result_t sec_fw_unload_handler(sec_fw_load_t * load_info)
{
    sec_result_t    rc = SEC_SUCCESS;
    ipl_t           ipl;
    opl_t           opl;
    ipc_shmem_t     ish_pl;
    ipc_shmem_t     osh_pl;

    SEC_FW_TRACE();
    SEC_FW_DPRINT("Unloading module: %s - 0x%08X\n", load_info->image_path,
                   load_info->module_id);

    OS_MEMSET(&ipl, 0x00, sizeof(ipl_t));
    OS_MEMSET(&opl, 0x00, sizeof(opl_t));
    OS_MEMSET(&ish_pl, 0x00, sizeof(ipc_shmem_t));
    OS_MEMSET(&osh_pl, 0x00, sizeof(ipc_shmem_t));

    /* Copy our payloads from user-space */
    if (load_info->ipc_call.ipl)
        SAFE_COPY_FROM_USER(&ipl, load_info->ipc_call.ipl, sizeof(ipl_t));
    if (load_info->ipc_call.opl)
        SAFE_COPY_FROM_USER(&opl, load_info->ipc_call.opl, sizeof(opl_t));
    if (load_info->ipc_call.ish_pl)
        SAFE_COPY_FROM_USER(&ish_pl, load_info->ipc_call.ish_pl,
                            sizeof(ipc_shmem_t));
    if (load_info->ipc_call.osh_pl)
        SAFE_COPY_FROM_USER(&osh_pl, load_info->ipc_call.osh_pl,
                            sizeof(ipc_shmem_t));

    SEC_FW_TRACE();
    
    mutex_lock(&sec_fw_list_mutex);
    rc = _sec_fw_unload_handler(load_info, &ipl, &opl, &ish_pl, &osh_pl);

    /* If the command fails (say it isn't supported in HW), don't remove it
     * from the list */
    if (rc == SEC_SUCCESS)
    {
        SEC_FW_TRACE();
        /* Remove a node the fw info list */
        rc = _sec_fw_remove_by_id(load_info->module_id);
    }
    mutex_unlock(&sec_fw_list_mutex);

    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_unload_by_id
//-----------------------------------------------------------------------------
sec_result_t sec_fw_unload_by_id(uint32_t module_id)
{
    sec_result_t        rc = SEC_SUCCESS;
    sec_kernel_ipc_t    ipc;
    ipl_t               ipl;
    opl_t               opl;
    ipc_shmem_t         ish_pl;
    ipc_shmem_t         osh_pl;
    uint32_t *          temp_ptr = (uint32_t *)&ipl;

    /* Clean up the IPC call */
    OS_MEMSET(&ipc, 0x00, sizeof(sec_kernel_ipc_t));

    /* Check the chip we're on. If it is supported, set the sub-command */
    switch (gchip_info.host_device)
    {
    case PCI_DEVICE_CE4200:     /* These devices support unloading */
        ipc.sub_cmd.sc_fwl = IPC_SC_CE4200;
        break;
    case PCI_DEVICE_CE5300:
        ipc.sub_cmd.sc_fwl = IPC_SC_CE5300;
        break;
    case PCI_DEVICE_CE2600:
        ipc.sub_cmd.sc_fwl = IPC_SC_CE2600;
        break;
    case PCI_DEVICE_CE3100:     /* These devices do not support unloading */
    case PCI_DEVICE_CE4100:
        rc = SEC_NOT_SUPPORTED;
        goto exit;
        break;
    default:
        rc = SEC_INTERNAL_ERROR;
        goto exit;
        break;
    }

    /* Setup the IPC */
    ipc.cmd = IPC_AUTH_AND_LOAD_FW_MODULE;
    ipc.io_sizes.ipl_size = 20;
    ipc.io_sizes.ish_size = 0;
    ipc.io_sizes.opl_size = 4;
    ipc.io_sizes.osh_size = 0;

    /* Setup the IPL */
    *(temp_ptr + 3) = 1;
    *(temp_ptr + 4) = module_id;

    /* Unload the module */
    sec_lock_resources(SEC_AES_RES | SEC_EAU_RES | SEC_HASH_RES | 
                       SEC_SHMEM_RES);
    rc = unload_fw_op(&ipc, &ipl, &opl, &ish_pl, &osh_pl);
    sec_unlock_resources(SEC_AES_RES | SEC_EAU_RES | SEC_HASH_RES | 
                       SEC_SHMEM_RES);
    if (rc != SEC_SUCCESS)
    {
        SEC_ERROR("Could not unload module: 0x%08x\n", module_id);
    }
    
exit:
    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_get_loaded_fw_info
//
// This function retrieves info about the loaded FW modules, and copies it
// to an address provided by user space (the sec_loaded_fw_info_t information
// stored within the user_space library.
//-----------------------------------------------------------------------------
static sec_result_t sec_fw_get_loaded_fw_info(
        const sec_loaded_fw_info_t __user * user_fw_info)
{
    sec_result_t            rc = SEC_SUCCESS;
    sec_loaded_fw_info_t    kern_info;
    sec_fw_list_node_t *    cur_node;
    int                     i;

    SEC_FW_TRACE();
    SEC_FW_DPRINT("user_fw_info is 0x%p\n", user_fw_info);

    /* Check the pointer we received */
    if (!access_ok(VERIFY_WRITE, user_fw_info, sizeof(sec_loaded_fw_info_t)))
    {
        SEC_ERROR("Received an invalid address when retrieving FW info\n");
        rc = -EINVAL;
        goto exit;
    }

    /* Cleanup to prevent unexpected data leakage */
    OS_MEMSET(&kern_info, 0x00, sizeof(sec_loaded_fw_info_t));
    for (i = 0; i < SEC_MAX_LOADED_FW_MODULES; i++)
    {
        kern_info.fw_info[i].status = SEC_FW_UNLOADED;
    }

    /* If we are in the suspend state we need to make the loader think
     * nothing is loaded; otherwise it will error */
    if (sec_pm_state == SEC_PM_SUSPEND || sec_pm_state == SEC_PM_RESUME)
    {
        SEC_FW_DPRINT("Get FW info called from suspend; returning 0s\n");
        goto finish;
    }
    
    SEC_FW_TRACE();
    mutex_lock(&sec_fw_list_mutex);
    SEC_FW_DPRINT("Loaded count: %d\n", sec_fw_image_load_count);
    kern_info.numloaded = sec_fw_image_load_count;
    list_for_each_entry(cur_node, &sec_fw_list, list)
    {
        /* If the module is only in the list for unload, skip it */
        if (cur_node->action == SEC_FW_ACTION_UNLOAD_FW)
            continue;

        SEC_FW_NODE_DPRINT(cur_node);
        /* The kernel list is unordered; we will use the index stored in each
         * entry to fill in the ordered fw_info array */
        OS_MEMCPY(&(kern_info.fw_info[cur_node->node_info.index]),
                  &(cur_node->node_info),
                  sizeof(sec_fw_info_t));
    }
    mutex_unlock(&sec_fw_list_mutex);

finish:
    /* Now that we have created the ordered list, copy it to user space */
    if (copy_to_user((void *)user_fw_info, &kern_info,
                     sizeof(sec_loaded_fw_info_t)))
    {
        SEC_ERROR("Copy to user space failed for FW info\n");
        rc = SEC_INTERNAL_ERROR;
        goto exit;
    }
    SEC_FW_TRACE();

exit:
    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_manifest_load_handler()
//
// Calls the manifest load IPC from ipl/opl located in kernel space.
//-----------------------------------------------------------------------------
sec_result_t sec_fw_manifest_load_handler(sec_fw_load_t * fw_load,
                                          ipl_t *         ipl,
                                          opl_t *         opl)
{
    sec_ipc_return_t    ipc_ret = IPC_RET_SUCCESS;
    sec_result_t        rc = SEC_SUCCESS;

    /* Verify arguments */
    VERIFY(fw_load != NULL && ipl != NULL && opl != NULL,
            exit, rc, SEC_NULL_POINTER);

    SEC_FW_DPRINT("fw: 0x%08x, ipl: 0x%08x; opl 0x%08x\n",
                  (unsigned int) fw_load, (unsigned int) ipl,
                  (unsigned int) opl);
    SEC_FW_HASH_DPRINT(fw_load, sizeof(sec_fw_load_t));
    SEC_FW_HASH_DPRINT(ipl, sizeof(ipl_t));
    SEC_FW_HASH_DPRINT(opl, sizeof(opl_t));

    /* Lock the necessary resources */
    sec_lock_resources(fw_load->ipc_call.resources);
    rc = tracker_add_resources(current->tgid, fw_load->ipc_call.resources);
    if ( rc != SEC_SUCCESS )
    {
        goto exit_unlock_resources;
    }

    /* Send the load IPC */
    ipc_ret = sec_kernel_ipc(fw_load->ipc_call.cmd, fw_load->ipc_call.sub_cmd,
                             fw_load->ipc_call.io_sizes, ipl, opl,
                             NULL, NULL);

    /* Translate an IPC return type to a sec driver return type. */
    SEC_FW_DPRINT("IPC returned %d\n", ipc_ret);
    rc = ipc2sec(ipc_ret);

    /* Unlock our resources */
    tracker_remove_resources(current->tgid, fw_load->ipc_call.resources);
exit_unlock_resources:
    sec_unlock_resources(fw_load->ipc_call.resources);

exit:
    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_manifest_load_handler_from_user()
//
// Handles user->kernel memory translation before calling
// sec_fw_manifest_load_handler(). Adds the manifest to the tracking list.
//-----------------------------------------------------------------------------
static sec_result_t sec_fw_manifest_load_handler_from_user(
                                                    sec_fw_load_t * fw_load)
{
    sec_result_t        rc = SEC_SUCCESS;
    ipl_t               ipl;
    opl_t               opl;

    OS_MEMSET(&ipl, 0x00, sizeof(ipl_t));
    OS_MEMSET(&opl, 0x00, sizeof(opl_t));

    /* Verify arguments */
    VERIFY_AND_COPY_FROM_USER(&ipl, fw_load->ipc_call.ipl,
                              sizeof(ipl_t), VERIFY_WRITE);
    VERIFY_AND_COPY_FROM_USER(&opl, fw_load->ipc_call.opl,
                              sizeof(opl_t), VERIFY_WRITE);

    SEC_FW_TRACE();
    /* lock the fw list and call the IPC */
    mutex_lock(&sec_fw_list_mutex);
    rc = sec_fw_manifest_load_handler(fw_load, &ipl, &opl);

    /* Add the manifest to the tracking list */
    if (rc == SEC_SUCCESS)
    {
        SEC_RESULT_TRY(sec_fw_add_list_node(fw_load->loaded_by,
                                            fw_load->image_path,
                                            SEC_FW_MANIFEST_ID,
                                            0,
                                            SEC_FW_LOADED,
                                            SEC_FW_ACTION_LOAD_MANIFEST),
                        error_mutex_locked);
    }

error_mutex_locked:
    SEC_FW_TRACE();
    mutex_unlock(&sec_fw_list_mutex);

    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_ioctl_handler
//
// This function handles all SEC_FW IOCTL requests.
//-----------------------------------------------------------------------------
sec_result_t sec_fw_ioctl_handler(uint32_t arg)
{
    sec_result_t    rc = SEC_SUCCESS;
    sec_fw_ioctl_t  ioctl_info;
    
    SEC_FW_TRACE();
    SEC_FW_DPRINT("Arg is: 0x%08x\n", arg);

    /* If we are in the resume state we should not be receiving IOCTLs */
    if (sec_pm_state == SEC_PM_RESUME)
    {
        SEC_FW_TRACE();
        rc = SEC_PM_INVALID_STATE;
        goto exit;
    }

    /* Check and copy the FW info */
    if (!access_ok(VERIFY_READ, arg, sizeof(sec_fw_ioctl_t)))
    {
        SEC_ERROR("Argument to FW IOCTL handler was invalid; 0x%8p\n",
                   (sec_fw_ioctl_t __user *)arg);
        rc = -EINVAL;
        goto exit;
    }
    OS_MEMSET(&ioctl_info, 0x00, sizeof(sec_fw_ioctl_t));
    SAFE_COPY_FROM_USER(&ioctl_info, (sec_fw_ioctl_t __user *)arg,
            sizeof(sec_fw_ioctl_t));

    /* Handle the command */
    SEC_FW_DPRINT("FW IOCTL command: %d\n", ioctl_info.command);
    switch (ioctl_info.command)
    {
    case SEC_FW_LOAD:
        /* If we are receiving a load during the suspend routine it is for
         * storage to RAM, and use during resume */
        if (sec_pm_state == SEC_PM_SUSPEND)
        {
            SEC_FW_TRACE();
            rc = sec_pm_store_fw_image(&(ioctl_info.data.fw_load));
        }
        else /* Normal run state */
        {
            SEC_FW_TRACE();
            rc = sec_fw_load_handler(&(ioctl_info.data.fw_load));
        }
        break;
    case SEC_FW_UNLOAD:
        if (sec_pm_state == SEC_PM_SUSPEND) /* Not allowed in suspend */
        {
            SEC_FW_TRACE();
            rc = SEC_PM_INVALID_STATE;
        }
        else
        {
            SEC_FW_TRACE();
            rc = sec_fw_unload_handler(&(ioctl_info.data.fw_load));
        }
        break;
    case SEC_FW_GET_LOADED_FW_INFO: /* Allowed in running and suspend */
        SEC_FW_TRACE();
        rc = sec_fw_get_loaded_fw_info(ioctl_info.data.loaded_fw_info);
        break;
    case SEC_FW_GET_VERSIONS:
        SEC_FW_TRACE();
        rc = sec_fw_get_ver_info_from_user(ioctl_info.data.fw_ver_info.rom_ver,
                ioctl_info.data.fw_ver_info.mod_count,
                ioctl_info.data.fw_ver_info.mod_list);
        break;
    case SEC_FW_MANIFEST_LOAD:
        /* If we are receiving a load during the suspend routine it is for
         * storage to RAM, and use during resume */
        if (sec_pm_state == SEC_PM_SUSPEND)
        {
            SEC_FW_TRACE();
            rc = sec_pm_store_fw_image(&(ioctl_info.data.fw_load));
        }
        else /* Normal run state */
        {
            SEC_FW_TRACE();
            rc = sec_fw_manifest_load_handler_from_user(
                                                &(ioctl_info.data.fw_load));
        }
        break;
    default:
        SEC_FW_TRACE();
        rc = SEC_NOT_IMPLEMENTED_YET;
        break;
    }

exit:
    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_init_handler
//
// The following function populates information about any FW modules which
// were loaded before the kernel module was started.
//-----------------------------------------------------------------------------
sec_result_t sec_fw_init_handler(void)
{
    sec_result_t       rc = SEC_SUCCESS;
    sec_module_list_t  mod_list[SEC_MAX_LOADED_FW_MODULES];
    uint32_t           resources = SEC_AES_RES  | SEC_EAU_RES
                                 | SEC_HASH_RES | SEC_SHMEM_RES;
    uint32_t           mod_count = 0;
    int                i = 0;
    uint32_t           rom_version = 0;

    SEC_FW_TRACE();

    sec_lock_resources(resources);
    rc = tracker_add_resources(current->tgid, resources);

    /* Get info about pre-loaded modules */
    if (sec_fw_get_ver_info_ipc(mod_list, &mod_count, &rom_version) != SEC_SUCCESS)
    {
        sec_unlock_resources(resources);
        rc = tracker_remove_resources(current->tgid, resources);
        SEC_ERROR("Could not get info on pre-loaded modules\n");
        rc = SEC_FAIL;
        goto exit;
    }
    /* initializing the global rom version */
    g_rom_version = rom_version;

    sec_unlock_resources(resources);
    rc = tracker_remove_resources(current->tgid, resources);

    /* Set that information in to our list of loaded modules */
    sec_fw_image_load_count = 0;
    for (i = 0; i < SEC_MAX_LOADED_FW_MODULES; i++)
    {
        /* If the ID was zero, there is no module at this index */
        if (mod_list[i].module_id == 0)
            continue;
        SEC_RESULT_TRY(
                sec_fw_add_list_node(SEC_FW_LOADED_INIT,
                                     NULL,
                                     mod_list[i].module_id,
                                     mod_list[i].module_version,
                                     SEC_FW_LOADED,
                                     SEC_FW_ACTION_PRELOADED_FW),
                exit);
    }
    if (sec_fw_image_load_count != mod_count)
        SEC_ERROR("Expected sec_fw_image_load_count to be %d, but it was %d\n",
                mod_count, sec_fw_image_load_count);

exit:
    SEC_FW_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_fw_exit_handler
//
// This function is called when the module is removed. Its job is to cleanup
// the FW image list.
//-----------------------------------------------------------------------------
void sec_fw_exit_handler(void)
{
    sec_fw_list_node_t * cur_node = NULL;
    sec_fw_list_node_t * next_node = NULL;

    /* Lock the list and cleanup all allocated memory */
    mutex_lock(&sec_fw_list_mutex);
    list_for_each_entry_safe(cur_node, next_node, &sec_fw_list, list)
    {
        sec_fw_delete_list_node(cur_node);
    }
    mutex_unlock(&sec_fw_list_mutex);
}

//-----------------------------------------------------------------------------
// sec_fw_get_module_id
//
// This function returns the correct module id for the loaded module.
//-----------------------------------------------------------------------------
sec_result_t sec_fw_get_module_id(uint32_t* module_id)
{
    int i;
    sec_result_t rc = SEC_FAIL;
    sec_module_list_t mod_list[SEC_MAX_LOADED_FW_MODULES];
    unsigned int mod_count=0;
    unsigned int romver=0;
    if(module_id ==NULL)
        return SEC_FAIL;
    rc = sec_fw_get_ver_info(mod_list, &mod_count, &romver);
    if (SEC_SUCCESS == rc)
    {
        for(i=0; i<SEC_MAX_LOADED_FW_MODULES; i++)
        {
            if(*module_id == (mod_list[i].module_id & SEC_IPC_MODULE_ID_MASK))
            {
                *module_id = mod_list[i].module_id;
                return rc;
            }
        }
        rc = SEC_FW_MODULE_NOT_FOUND;
    }
    else
    {
        SEC_ERROR("Failed to get the FW ver info\n");
    }
    return rc;
}

