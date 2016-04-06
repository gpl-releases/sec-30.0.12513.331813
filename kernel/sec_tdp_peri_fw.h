/*-----------------------------------------------------------------------------
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2008-2011 Intel Corporation. All rights reserved.
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

#ifndef __SEC_TDP_PERI_H__
#define __SEC_TDP_PERI_H__

#define OUT_OF_MEMORY         -1
#define PERI_FW_LOAD_IPC_FAIL -2
#define ADD_STR_ENTRY_FAIL    -3
#define DEL_STR_ENTRY_FAIL    -4
#define TDP_FW_NOT_LOADED     -5
#define INVALID_PARAM         -6
#define PERI_FW_UNLOAD_IPC_FAIL -7

//Generic data stucture returned to SMD API
typedef struct
{
    uint8_t fw_info[64];
} load_peripheral_ipc_data;

typedef enum
{
    UNLOAD_PERI_UNIT_DEMUX = 0,
    UNLOAD_PERI_UNIT_GVS_GVT = 1,
    UNLOAD_PERI_UNIT_MFD_GVD = 2,
    UNLOAD_PERI_UNIT_BSP_IMAGE = 3,
    UNLOAD_PERI_UNIT_DPE = 4,
    UNLOAD_PERI_UNIT_AUDIO_DSP0 = 5,
    UNLOAD_PERI_UNIT_AUDIO_DSP1 = 6,
} unload_peripheral_fw_unit;

int sec_kernel_load_peripheral_fw(char *fw_mod_file, void *pmr_dest_phys_addr);
int sec_call_load_peripheralFW_IPC(load_peripheral_ipc_data ipc);
int sec_load_peripheralFW_packager(void * fw_buffer_virtual_addr, int image_size, uint32_t pmr_dest_phys_addr, load_peripheral_ipc_data * ipc_data_buffer);
int sec_unload_peripheralFW(unload_peripheral_fw_unit unit);
#endif /* __SEC_TDP_PERI_H__ */
