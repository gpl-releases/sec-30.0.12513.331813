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
#ifndef __SEC_TRACKER_H__
#define __SEC_TRACKER_H__

#include "sec_types.h"
#include "sec_hal.h"
#include "sec_kernel.h"
#include "sec_kernel_types.h"

// Structure describes memory entry
typedef struct sec_mem_node_t
{
    sec_contig_mem_t        mem;    // Contig memory block
    struct sec_mem_node_t * next;   // Next entry in the list
    struct sec_mem_node_t * prev;   // Previous entry in the list
} sec_mem_node_t;

// Structure describes client connected to SEC
typedef struct sec_client_t
{
    unsigned int            tgid;       // Client's thread group identifier
    sec_mem_node_t        * mem_head;   // Link-list of memory blocks used
    uint32_t                resources;  // Resources used --
                                        //      OR-ed sec_fw_resource_t flags
    int contexts[SEC_NUM_CONTEXT_TYPES][SEC_NUM_CONTEXTS]; // tracking context_ids that are in use
    struct sec_client_t   * next;       // Pointer to next client in list
    struct sec_client_t   * prev;       // Pointer to prev client in list
    uint8_t                 eau_lock;   // EAU_LOCK status
} sec_client_t;

// Find and Verify Clients
sec_client_t* tracker_find_client(unsigned int tgid);

// Find and Verify Client's memory
sec_contig_mem_t* tracker_verify_mem(sec_contig_mem_t *mem);
sec_contig_mem_t* tracker_verify_page(unsigned int tgid, unsigned int pgoff, unsigned int size);

// Add/remove memory usage
sec_result_t tracker_add_mem   (unsigned int tgid, sec_contig_mem_t * mem);
sec_result_t tracker_remove_mem(unsigned int tgid, sec_contig_mem_t * mem);
sec_result_t tracker_remove_mem_from_client_list(sec_contig_mem_t * mem);

// Add/remove firmware resource usage
sec_result_t tracker_add_resources   (unsigned int tgid, uint32_t resources);
sec_result_t tracker_remove_resources(unsigned int tgid, uint32_t resources);

// add client/garbage collect
void tracker_garbage_collect(unsigned int tgid);
void tracker_client_add     (unsigned int tgid);

// Init/deinit tracking system
void tracker_init  (void);
void tracker_deinit(void);

// add/remove/query contexts
sec_result_t tracker_add_context(enum context_type type, unsigned int tgid,
				 uint32_t context);
sec_result_t tracker_remove_context(enum context_type type, unsigned int tgid,
				    uint32_t context);
bool tracker_has_context(enum context_type type, unsigned int tgid,
			 uint32_t context);

// Add/Remove EAU LOCK
sec_result_t tracker_add_eau_lock(unsigned int tgid);
sec_result_t tracker_remove_eau_lock(unsigned int tgid);
#endif
