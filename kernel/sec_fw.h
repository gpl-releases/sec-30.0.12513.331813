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

#ifndef __SEC_FW_H__
#define __SEC_FW_H__

//-----------------------------------------------------------------------------
// D A T A   T Y P E   D E F I N I T I O N S
//-----------------------------------------------------------------------------
typedef enum {
    SEC_FW_ACTION_LOAD_FW,          // Action: Loaded this FW
    SEC_FW_ACTION_UNLOAD_FW,        // Action: Unloaded this FW
    SEC_FW_ACTION_PRELOADED_FW,     // Action: FW was loaded before the driver
    SEC_FW_ACTION_LOAD_MANIFEST,    // Action: Loaded this manifest
} sec_fw_action_t;

typedef struct {
    struct list_head        list;
    sec_fw_action_t         action;
    sec_fw_load_time_t      loaded_by;
    sec_fw_info_t           node_info;
    char                    image_path[SEC_FW_MAX_PATH_LEN];
} sec_fw_list_node_t;  /* An entry node for the kernel loaded image list */

//-----------------------------------------------------------------------------
//  G L O B A L S
//-----------------------------------------------------------------------------

extern struct mutex        sec_fw_list_mutex;
extern struct list_head    sec_fw_list;
extern uint32_t            sec_fw_image_load_count;

//-----------------------------------------------------------------------------
// F U N C T I O N   P R O T O T Y P E S
//-----------------------------------------------------------------------------
sec_result_t sec_fw_get_ver_info(sec_module_list_t *, uint32_t *, uint32_t *);
sec_result_t sec_fw_ioctl_handler(uint32_t);
sec_result_t sec_fw_init_handler(void);
void         sec_fw_exit_handler(void);

sec_result_t sec_fw_get_ver_info_by_id(uint32_t, uint32_t *);
sec_result_t _sec_fw_remove_by_id(uint32_t);
sec_result_t sec_fw_remove_by_id(uint32_t);
sec_result_t _sec_fw_load_handler(sec_fw_load_t *,  ipl_t *,  opl_t *,
                                  ipc_shmem_t *,  ipc_shmem_t *, uint32_t *);
sec_result_t sec_fw_unload_by_id(uint32_t);
sec_result_t sec_fw_manifest_load_handler(sec_fw_load_t *, ipl_t *, opl_t *);

sec_result_t sec_fw_get_module_id(uint32_t* module_id);

#endif /* __SEC_FW_H__ */
