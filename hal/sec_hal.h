/*==========================================================================
  This file is provided under a dual BSD/GPLv2 license.  When using or 
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2008-2012 Intel Corporation. All rights reserved.

  This program is free software; you can redistribute it and/or modify 
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but 
  WITHOUT ANY WARRANTY; without even the implied warranty of 
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
  General Public License for more details.

  You should have received a copy of the GNU General Public License 
  along with this program; if not, write to the Free Software 
  Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
  The full GNU General Public License is included in this distribution 
  in the file called LICENSE.GPL.

  Contact Information:
   Intel Corporation

   2200 Mission College Blvd.
   Santa Clara, CA  97052

  BSD LICENSE 

  Copyright(c) 2008-2012 Intel Corporation. All rights reserved.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without 
  modification, are permitted provided that the following conditions 
  are met:

    * Redistributions of source code must retain the above copyright 
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in 
      the documentation and/or other materials provided with the 
      distribution.
    * Neither the name of Intel Corporation nor the names of its 
      contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 =========================================================================*/

#ifndef SEC_HAL_H
#define SEC_HAL_H

#include "osal.h"
#include "pal.h"

#define SEC_HAL_IPC_INPUT_DOORBELL      0x080400 // IPC Input Doorbell
#define SEC_HAL_IPC_OUTPUT_DOORBELL     0x080404 // IPC Output Doorbell
#define SEC_HAL_IPC_INPUT_STATUS        0x080408 // IPC Input Status
#define SEC_HAL_IPC_OUTPUT_STATUS       0x08040c // IPC Output Status
#define SEC_HAL_IPC_HOST_INT_STATUS     0x080410 // IPC Host Interrupt Status
#define SEC_HAL_IPC_HOST_INT_MASK       0x080414 // IPC Host Interrupt Mask
#define SEC_HAL_IPC_INPUT_PAYLOAD       0x080500 // IPC Input Payload
#define SEC_HAL_IPC_OUTPUT_PAYLOAD      0x080580 // IPC Output Payload
#define SEC_HAL_IPC_SHARED_PAYLOAD      0x080600 // IPC Shared Payload

typedef enum
{
    SEC_HAL_SUCCESS         = 0x000,
    SEC_HAL_FAILURE         = 0x0001,
    SEC_HAL_INVALID_PARAM   = 0x00FF,
} sec_hal_ret_t;

typedef struct
{
   unsigned int base_addr0;/**< base_addr0*/
   uint32_t base_addr1;/**< base_addr1*/
   uint32_t base_addr2;/**< base_addr2*/
   uint32_t base_addr3;/**< base_addr3*/
   unsigned int irq_num;/**< irq_num*/
} pci_info_t;

typedef struct
{
    void           *devh ;
    pci_info_t      pci_info;
    os_interrupt_t  int_handler;
} sec_hal_t;

os_interrupt_handler_t sec_hal_intr_func;

uint32_t        sec_hal_devh_ReadReg32( sec_hal_t * sec_hal,
                                        uint32_t    addr);

uint32_t        sec_hal_devh_WriteReg32(sec_hal_t * sec_hal,
                                        uint32_t    addr,
                                        uint32_t    valu);

sec_hal_ret_t   sec_hal_create_handle(  sec_hal_t * sec_hal);

sec_hal_ret_t   sec_hal_write_sh_ram(   sec_hal_t * sec_hal,
                                        uint32_t    offset,
                                        uint32_t *  buf,
                                        uint32_t    size);

sec_hal_ret_t   sec_hal_read_sh_ram(    sec_hal_t * ec_hal,
                                        uint32_t *  dest,
                                        uint32_t    offset,
                                        uint32_t    size);

sec_hal_ret_t   sec_hal_write_pl(       sec_hal_t * sec_hal,
                                        uint32_t    offset,
                                        uint32_t *  buf,
                                        uint32_t    size);

sec_hal_ret_t   sec_hal_read_pl(        sec_hal_t * sec_hal,
                                        uint32_t *  dest,
                                        uint32_t    offset,
                                        uint32_t    size);

sec_hal_ret_t   sec_hal_ipc_call(       sec_hal_t * sec_hal,
                                        uint32_t    cmnd,
                                        uint32_t *  pl,
                                        uint32_t    pl_size,
                                        uint32_t*   sh_ram,
                                        uint32_t    sh_ram_size);

sec_hal_ret_t   sec_hal_set_irq( sec_hal_t *sec_hal );

sec_hal_ret_t   sec_hal_release_irq( sec_hal_t *sec_hal);

sec_hal_ret_t   sec_hal_delete_handle( sec_hal_t *sec_hal);

sec_hal_ret_t   sec_hal_get_pci_rev( unsigned *SEC_revision);

#endif
