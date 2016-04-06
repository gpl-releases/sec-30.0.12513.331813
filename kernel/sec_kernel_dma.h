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
#ifndef __SEC_KERNEL_DMA_H__
#define __SEC_KERNEL_DMA_H__

#include "sec_types.h"
#include "sec_hal.h"
#include "sec_kernel.h"
#include "sec_kernel_types.h"

//-----------------------------------------------------------------------------
// sec_kernel_dma_cleanup
//-----------------------------------------------------------------------------
sec_result_t sec_kernel_dma_cleanup(uint32_t arg);

//-----------------------------------------------------------------------------
// sec_kernel_create_dma_desc
//
// This function handles the SEC_CREATE_DMA_DESC ioctl.  This function creates
// a sec_dma_descriptor_t for a given user space virtual address. 
//-----------------------------------------------------------------------------
sec_result_t sec_kernel_create_dma_desc(uint32_t arg);


//-----------------------------------------------------------------------------
// sec_kernel_free_dma_desc
//
// This function handles the SEC_FREE_DMA_DESC ioctl.  This function frees the
// DMA descriptor and associated locks for a given sec_dma_descriptor for a
// given user space virtual address.
//-----------------------------------------------------------------------------
sec_result_t sec_kernel_free_dma_desc(uint32_t arg);


//---------------------------------------------------------------------
// sec_kernel_smd_to_dma
//
// Processes the SEC_SMD_TO_DST_DMA ioctl. It uses the SMD
// physical address as data source and DMA descriptor as destination
//---------------------------------------------------------------------
sec_result_t sec_kernel_smd_to_dma(uint32_t arg);

#endif
