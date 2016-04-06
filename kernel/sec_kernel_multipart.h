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

#ifndef __SEC_MULTIPART_H__
#define __SEC_MULTIPART_H__

#define SEC_MV_MODULE_ID    0x00003070ul
#define SEC_PR2_MODULE_ID   0x00003080ul

/// SFAF (sec_fw_1100 module)Scatter-gather list entry
/**
 *  This structure contains the information necessary for library functionality,
 *  such as a bulk cipher, to process one contiguous block of data.  If multiple
 *  blocks are necessary (such as if the memory is non-contiguous or part of the
 *  block must be processed with a different data endianness), multiple
 *  scatter-gather entries can be passed in a list (an array of sfaf_mem_ptr
 *  structures).
 */
typedef struct sfaf_mem_ptr
{
   void * address;           ///< Data pointer (offset within the specified zone)
   uint32_t length;          ///< Data length, in bytes
   uint8_t external;         ///< External or Internal pointer?
   uint8_t swap;             ///< Perform swapping?
   uint8_t pmr_type;         ///< PMR type of external memory
   uint8_t rsvd;             ///< For dword alignment
} sfaf_mem_ptr_t;

//-----------------------------------------------------------------------------
// F U N C T I O N S
//-----------------------------------------------------------------------------
sec_result_t aes_multipart_op(sec_kernel_ipc_t * ipc_arg,
                              ipl_t *            ipl,
                              opl_t *            opl,
                              ipc_shmem_t *      ish_pl );

sec_result_t pr2_multipart_op(sec_kernel_ipc_t * ipc_arg,
                              ipl_t *            ipl,
                              opl_t *            opl,
                              ipc_shmem_t *      ish_pl );

#endif /* __SEC_MULTIPART_H__ */
