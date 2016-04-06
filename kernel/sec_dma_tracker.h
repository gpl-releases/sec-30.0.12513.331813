//----------------------------------------------------------------------------
// This file is provided under a dual BSD/GPLv2 license.  When using or
// redistributing this file, you may do so under either license.
//
// GPL LICENSE SUMMARY
//
// Copyright(c) 2008-2012 Intel Corporation. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of version 2 of the GNU General Public License as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
// The full GNU General Public License is included in this distribution
// in the file called LICENSE.GPL.
//
// Contact Information:
//      Intel Corporation
//      2200 Mission College Blvd.
//      Santa Clara, CA  97052
//
// BSD LICENSE
//
// Copyright(c) 2008-2012 Intel Corporation. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//   - Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   - Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//   - Neither the name of Intel Corporation nor the names of its
//     contributors may be used to endorse or promote products derived
//     from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//----------------------------------------------------------------------------
#ifndef __SEC_DMA_TRACKER_H__
#define __SEC_DMA_TRACKER_H__

#include "sec_types.h"
#include "sec_hal.h"
#include "sec_kernel.h"
#include "sec_kernel_types.h"

// Structure describes a DMA descriptor entry
typedef struct sec_dma_node_t
{
    sec_dma_mem_t           dma_mem;   // DMA memory descriptor
    struct sec_dma_node_t  *next;      // Next entry in the list
    struct sec_dma_node_t  *prev;      // Previous entry in the list
} sec_dma_node_t;

// Structure describes client connected to SEC
typedef struct sec_dma_client_t
{
    unsigned int             tgid;   // Client's thread group identifier
    sec_dma_node_t          *dma_lt_node_start;// Link-list of long term
                                               // (lt) dma descriptors
    sec_dma_node_t          *dma_st_node_start;// Link-list of short term
                                               // (st) dma descriptors
    uint32_t                 resources; // Resources used --
                                        //  OR-ed sec_fw_resource_t flags
    struct sec_dma_client_t *next;      // Pointer to next client in list
    struct sec_dma_client_t *prev;      // Pointer to prev client in list
} sec_dma_client_t;

//==========================================
// Globals for sec_dma_tracker
//==========================================
extern sec_dma_client_t *sec_dma_clients;
extern struct semaphore dma_tracker_sema;

// Displays the data item details of the sec_dma_mem_t structure
// This function is used for debugging the structure
void show_dma_mem(sec_dma_mem_t *pdmamem);

// This is the function that coordinates all the work to create
// the DMA descriptors and associated locked pages.
// This function is in its own file sec_dma_tracker_map_vm_to_desc.c
sec_dma_descriptor_t* dma_tracker_map_vm_to_desc( user_buf_t *src,
                                                  user_buf_t *dst,
                                              sec_dma_type_t  dma_type,
                                                         int  block_size,
                                               unsigned long  src_rx_reg,
                                               unsigned long  dst_rx_reg,
                                                sec_fw_cmd_t  fw_cmd);

//----------------------------------------------------------------------------
// Interface functions
//----------------------------------------------------------------------------
// Find and Verify DMA Clients
sec_dma_client_t* dma_tracker_find_client(unsigned int tgid);

// Find and Verify Client's DMA
sec_dma_mem_t* dma_tracker_verify(sec_dma_mem_t *pdmamem);

// Add/remove DMA usage
sec_result_t dma_tracker_add_node(unsigned int tgid, sec_dma_mem_t *pdmamem);
sec_result_t dma_tracker_remove_node(unsigned int tgid, sec_dma_mem_t *pdmamem);
sec_result_t dma_tracker_remove_from_client_list(sec_dma_mem_t *pdmamem);

// Add/remove firmware resource usage
sec_result_t dma_tracker_add_resources(unsigned int tgid, uint32_t resources);
sec_result_t dma_tracker_remove_resources(unsigned int tgid, uint32_t resources);

// add client/garbage collect
void dma_tracker_client_add     (unsigned int tgid);
void dma_tracker_garbage_collect(unsigned int tgid);

// Init/deinit tracking system
void dma_tracker_init(void);
void dma_tracker_deinit(void);

#endif
