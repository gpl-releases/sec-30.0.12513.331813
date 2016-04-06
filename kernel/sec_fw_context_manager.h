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
#ifndef _SEC_FW_CONTEXT_MANAGER_H_
#define _SEC_FW_CONTEXT_MANAGER_H_

#include "sec_kernel_types.h"
#include "sec_types.h"
#include <linux/spinlock.h>

typedef struct _fcm_internal_session
{
    struct list_head dhead;
    uint32_t context_id;
    uint32_t ref_counter;
    void *data;
    uint32_list tgid_list;
} fcm_internal_session;

typedef struct _fcm_kernel_context
{
    struct list_head khead;
    uint32_t module_id;
    uint32_t destroy_ipc;
    struct semaphore internal_session_sema;
    spinlock_t internal_session_lock;
    fcm_internal_session dlist;
} fcm_kernel_context;

extern spinlock_t fcm_kernel_context_lock;
extern fcm_kernel_context klist;


//-----------------------------------------------------------------------------
// DRM Context Management functions
//-----------------------------------------------------------------------------
fcm_internal_session* fcm_create_internal_session(fcm_kernel_context *context,
                                                  uint32_t context_id,
                                                  bool clone,
                                                  unsigned char * data);

sec_result_t fcm_free_internal_session(fcm_kernel_context *context, int context_id);

sec_result_t fcm_free_kernel_context(fcm_kernel_context* context);

fcm_kernel_context* fcm_create_kernel_context(int module_id,
                                              int destroy_ipc, 
                                              int max_sessions);

void fcm_internal_session_garbage_collect(uint32_t tgid);

#endif
