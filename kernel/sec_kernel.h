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

#ifndef _SEC_KERNEL_H_
#define _SEC_KERNEL_H_

#include "sec_types.h"
#include "sec_kernel_types.h"
#include "sec_hal.h"

//-----------------------------------------------------------------------------
// M A C R O S
//-----------------------------------------------------------------------------
#define PWU_MIN(a,b) (((a) < (b))?(a):(b))

// Helpful macro to perform safe copy to user
#define SAFE_COPY_TO_USER(to, from, size) \
if (copy_to_user(to, from, size))         \
{                                           \
    SEC_ERROR("Copy to user failed\n");   \
    return SEC_FAIL;                        \
}

// Helpful macro to perform safe copy from user
#define SAFE_COPY_FROM_USER(to, from, size) \
if (copy_from_user(to, from, size))         \
{                                           \
    SEC_ERROR("Copy from user failed\n");   \
    return SEC_FAIL;                        \
}

// Helpful macro to verify address and copy from user
#define VERIFY_AND_COPY_FROM_USER(dest, src, size, rw)  \
if ((src) && (access_ok(rw, src, size)))                \
    SAFE_COPY_FROM_USER((dest), (src), (size))

// Helpful macro for trying a function call, checking 'rc', and going to 'label'
// if the attempt fails.
#define SEC_RESULT_TRY(call, label)                             \
if ((rc = call) != SEC_SUCCESS)                                 \
{                                                               \
    SEC_ERROR("ERROR: rc returned %s\n", SEC_RESULT_TEXT(rc));  \
    goto label;                                                 \
}

// Macro to standardize kernel error message output
#define SEC_PRINT_ERROR(msg, ...)                                           \
    printk(KERN_ERR "%s ERROR: " msg, __func__, ## __VA_ARGS__)

//-----------------------------------------------------------------------------
// G L O B A L S
//-----------------------------------------------------------------------------
extern sec_hal_t        sec_hal_handle;
extern sec_chip_info_t  gchip_info;
extern int g_fast_path;
extern int enable_tdp;

sec_ipc_return_t sec_kernel_ipc(sec_fw_cmd_t    ipc_cmnd,
                                sec_fw_subcmd_t sub_cmd,
                                sec_ipc_sizes_t io_sizes,
                                ipl_t *         ipl, 
                                opl_t *         opl, 
                                ipc_shmem_t *   ish_pl,
                                ipc_shmem_t *   osh_pl);

int sec_kernel_copy_to_user( sec_kernel_ipc_t *  arg,
                             opl_t            *  opl,
                             ipc_shmem_t      *  osh_pl );

sec_result_t add_dma_desc(  sec_dma_descriptor_t ** head,
                            sec_dma_descriptor_t ** tail,
                            uint32_t                size,
                            uint32_t                src,
                            uint32_t                dst,
                            uint32_t                flags);

sec_result_t sec_kernel_user_buf_lock( user_buf_t *    buf,
                            sec_address_t   vaddr,
                            uint32_t        size,
                            int             write
                            );


sec_dma_descriptor_t * sec_kernel_map_vm_for_dma_rw(   user_buf_t *    src,
                                            user_buf_t *    dst,
                                            int             block_size,
                                            unsigned long   src_rx_reg,
                                            unsigned long   dst_rx_reg,
                                            sec_fw_cmd_t    fw_cmd);

void sec_kernel_user_buf_unlock( user_buf_t *buf );


void sec_kernel_free_descriptor_list( sec_dma_descriptor_t * head );

// Translate an ipc return type to a sec return type
sec_result_t ipc2sec(sec_ipc_return_t result);

uint32_t sec_get_job_id(void);
sec_result_t user_buf_advance( user_buf_t *buf, unsigned long n );
void dump_dma_list(sec_dma_descriptor_t *list);

void sec_lock_resources  (uint32_t resources);
void sec_unlock_resources(uint32_t resources);
void sec_release_context(enum context_type type, uint32_t context_id);
void free_eau_lock(void);
int sec_kernel_check_device(void);

void         sec_disable_output_interrupt(void);
sec_result_t sec_enable_output_interrupt(void);
sec_result_t sec_kernel_reg_sysmem(bool is_rom_memory);
sec_result_t sec_kernel_free_sysmem(bool is_rom_memory);

sec_result_t __sec_do_free_pages(void *, unsigned int);

//-----------------------------------------------------------------------------
// AACS functions
//-----------------------------------------------------------------------------
int sec_kernel_aacs_init(void);

void sec_kernel_aacs_deinit(void);

sec_result_t sec_kernel_process_aacs_op(sec_kernel_ipc_t *  ipc_arg,
                                        ipl_t *             ipl,
                                        opl_t *             opl,
                                        ipc_shmem_t *       ish_pl);

sec_result_t sec_kernel_process_3000_op(sec_kernel_ipc_t *  ipc_arg,
                                        ipl_t *             ipl,
                                        opl_t *             opl,
                                        ipc_shmem_t *       ish_pl);


//-----------------------------------------------------------------------------
// DTCP functions and defines
//-----------------------------------------------------------------------------

#define SEC_IPC_DTCPIP_MODULE_ID 0x00003020ul

typedef enum
{
    SEC_DTCPIP_USE_DMA_SRC          = 0x00000001,                                    
    SEC_DTCPIP_USE_PHY_BUF_SRC      = 0x00000002,   
    SEC_DTCPIP_USE_DMA_DST          = 0x00000004,                                    
    SEC_DTCPIP_USE_PHY_BUF_DST      = 0x00000008,   
    SEC_DTCPIP_BUF_INVALID          = 0x00000000,
} dtcpip_pkt_buffer_mask;

extern struct mutex dtcpip_ipc_mutex;

int sec_kernel_dtcpip_init(void);

void sec_kernel_dtcpip_deinit(void);

sec_result_t sec_kernel_process_dtcpip_op(sec_kernel_ipc_t *  ipc_arg,
                                          ipl_t *             ipl,
                                          opl_t *             opl,
                                          ipc_shmem_t *       ish_pl);


//-----------------------------------------------------------------------------
// uint32 list functions
//-----------------------------------------------------------------------------
bool uint32_list_add_tail_node(uint32_t value, uint32_list* l);
bool uint32_list_remove_node(uint32_t value, uint32_list* l);
void uint32_list_clear_list(uint32_list* l);


//-----------------------------------------------------------------------------
// DMA operation for external module IPC
//-----------------------------------------------------------------------------
sec_result_t external_mod_ipc_dma_setup(sec_kernel_ipc_t     *ipc_arg,
                                        ipl_t *               ipl,
                                        user_buf_t           *src,
                                        user_buf_t           *dst,
                                        sec_dma_descriptor_t **phys_src_desc);

sec_result_t external_mod_ipc_dma_teardown(sec_kernel_ipc_t     *ipc_arg,
                                           user_buf_t           *src,
                                           user_buf_t           *dst,
                                           sec_dma_descriptor_t *phys_src_desc);

#endif
