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
#include "sec_types.h"
#include "sven_devh.h"
#include "sec_hal.h"
#include <linux/pci.h>

#ifndef SEC_KERNEL
#include <pthread.h>
#endif

#define PCI_VENDOR_INTEL    0x8086
#define PCI_DEVICE_SEC      0x2E64
#define SEC_ID              43


// This is actually a void pointer to the struct pci_dev associated with the SEC
// The reason for making this a global is that upon sec_kernel_exit the SEC HAL's
// sec_hal_release_irq function is called.  Within sec_hal_release_irq we must
// call pci_dev_put to free the Linux reference count for the SEC HW device.
static os_pci_dev_t pci_dev;

uint32_t sec_hal_devh_ReadReg32( sec_hal_t *sec_hal , uint32_t addr)
{
    return devh_ReadReg32((os_devhandle_t*)sec_hal->devh, addr);
}

uint32_t sec_hal_devh_WriteReg32(   sec_hal_t *sec_hal,
                                    uint32_t addr,
                                    uint32_t val)
{
    devh_WriteReg32( (os_devhandle_t*)sec_hal->devh , addr, val);
    return val;
}

sec_hal_ret_t  sec_hal_create_handle (sec_hal_t *sec_hal)
{
    unsigned int    ret = SEC_HAL_SUCCESS;
    os_devhandle_t *devh = NULL;
    int dcn_ret = 0;

    if(sec_hal != NULL)
    {
        /// allocate device handler
        devh = devhandle_factory(NULL);

        if (devh != NULL)
        {
            sec_hal->devh = (void*) devh;
            dcn_ret = devhandle_connect_name(devh, "SEC" );
            if ( dcn_ret )
            {
                sec_hal->int_handler=0;
                sec_hal->pci_info.base_addr0 = 0;
                sec_hal->pci_info.base_addr1 = 0;
                sec_hal->pci_info.base_addr2 = 0;
                sec_hal->pci_info.base_addr3 = 0;
                sec_hal->pci_info.irq_num = 0;
            }
            else
            {
                ret = SEC_HAL_FAILURE;
                printk( "\nsec_hal_create_handle: sven devhandle_connect_name failed\n");
            }
        }
        else
        {
            ret = SEC_HAL_FAILURE;
            printk( "\nsec_hal_create_handle: sven devhandle_factory failed allocating device handler\n");
        }
    }
    else
    {
        ret = SEC_HAL_FAILURE;
        printk( "\nsec_hal_create_handle: passed in sec_hal_t pointer sec_hal is NULL\n");
    }
    return ret;
}

/*
 sec_hal_write_sh_ram copies the source data at "buf" into
 the security firmware shared I/O memory at 0xDFC80600.
*/
sec_hal_ret_t sec_hal_write_sh_ram( sec_hal_t * sec_hal,
                                    uint32_t    offset,
                                    uint32_t *  buf,
                                    uint32_t    size
                                    )
{
    int i;
    uint32_t nsize;
    nsize = size;
    if(nsize > 256) nsize = 256;

    for (i=0; i < (int)nsize/4; i++)
    {
        sec_hal_devh_WriteReg32(sec_hal,
                                SEC_HAL_IPC_SHARED_PAYLOAD + offset + (i << 2),
                                buf[i]);
    }
    return SEC_HAL_SUCCESS;
}


/*
 sec_hal_read_sh_ram copies the source data from the
 security firmware shared I/O memory at 0xDFC80600 to
 the address at "dest". This can be built one of two ways.
*/
sec_hal_ret_t sec_hal_read_sh_ram(  sec_hal_t * sec_hal,
                                    uint32_t *  dest,
                                    uint32_t    offset,
                                    uint32_t    size)
{
    int i;
    uint32_t nsize;
    nsize = size;
    if(nsize > 256) nsize = 256;

#ifdef SEC_HAL_RW_IPCSHARED_DIRECT
    void *sec_sh_ram;
    sec_sh_ram = OS_MAP_IO_TO_MEM_CACHE(0xDFC80600, 256);
    OS_MEMCPY((void*)dest, sec_sh_ram+offset, nsize);
    OS_UNMAP_IO_FROM_MEM(sec_sh_ram, 256);
#else
    for (i=0; i < (int)nsize/4; i++)
    {
        dest[i] = sec_hal_devh_ReadReg32(
                        sec_hal,
                        SEC_HAL_IPC_SHARED_PAYLOAD + offset + (i << 2));
    }
#endif
    return SEC_HAL_SUCCESS;
}


/*
 sec_hal_write_pl copies the source data at "buf" into the
 security firmware shared I/O "input payload" memory at 0xDFC80500.
*/
sec_hal_ret_t sec_hal_write_pl( sec_hal_t * sec_hal,
                                uint32_t    offset,
                                uint32_t *  buf,
                                uint32_t    size)
{
    int i;
    uint32_t nsize;
    nsize = size;
    if(nsize > 64) nsize = 64;

    for (i=0; i < (int)nsize/4 ; i++)
    {
        sec_hal_devh_WriteReg32(sec_hal,
                                SEC_HAL_IPC_INPUT_PAYLOAD + (i << 2) + offset,
                                buf[i]);
    }
    return SEC_HAL_SUCCESS;
}

/*
 sec_hal_read_pl copies the source data from the security
 firmware shared I/O "output payload" memory at 0xDFC80580
 to the address at "dest".
*/
sec_hal_ret_t sec_hal_read_pl(  sec_hal_t * sec_hal,
                                uint32_t *  dest,
                                uint32_t    offset,
                                uint32_t    size)
{
    int i;
    uint32_t nsize;
    nsize = size;
    if(nsize > 64) nsize = 64;

    for (i=0; i < (int)nsize/4 ; i++)
    {
        dest[i] = sec_hal_devh_ReadReg32(
                               sec_hal,
                               SEC_HAL_IPC_OUTPUT_PAYLOAD + offset + (i << 2));
    }
    return SEC_HAL_SUCCESS;
}


//-----------------------------------------------------------------------------
// sec_hal_ipc_call
//
// This function writes any payload upto 64 bytes and any shared memory
// payload upto 256 bytes for the security hardware firmware to pick up.
// It then rings the input doorbell to signal the security hardware.
//-----------------------------------------------------------------------------
sec_hal_ret_t sec_hal_ipc_call( sec_hal_t * sec_hal,
                                uint32_t    cmnd,
                                uint32_t *  pl,
                                uint32_t    pl_size,
                                uint32_t *  sh_ram,
                                uint32_t    sh_ram_size)
{
    uint32_t nsize;

    /* Write to SEC HW Shared 64 byte input payload */
    if ((uint32_t)pl && pl_size)
    {
        nsize = pl_size;
        if(nsize > 64) nsize = 64;
        //OS_PRINT("Input Payload at %p ProcessID=0x%08X\n", pl, pl[0]);
        sec_hal_write_pl (sec_hal,0, pl, nsize);
    }

    /* Write to SEC HW Shared 256 byte memory*/
    if ((uint32_t)sh_ram && sh_ram_size)
    {
        nsize = sh_ram_size;
        if(nsize > 256) nsize = 256;
        sec_hal_write_sh_ram (sec_hal, 0, sh_ram, nsize);
    }

    /* Signal the SEC HW/FW using the "Doorbell" register */
    sec_hal_devh_WriteReg32(sec_hal,SEC_HAL_IPC_INPUT_DOORBELL, cmnd);
    return SEC_HAL_SUCCESS;
} /* ENDPROC sec_hal_ipc_call */


sec_hal_ret_t  sec_hal_set_irq( sec_hal_t *sec_hal )
{
    osal_result  osal_ret;
    unsigned int baseaddr0, iret;
    unsigned int irq=0;

    if(sec_hal == NULL) return SEC_HAL_INVALID_PARAM;

    // This function actually enables the device.
    // It wakes up the device and may also assign
    // its interrupt line and I/O regions.
    osal_ret = os_pci_enable_device(PCI_VENDOR_INTEL, PCI_DEVICE_SEC);
    if(osal_ret != OSAL_SUCCESS)
    {
        OS_PRINT("sec_hal_set_irq: os_pci_enable_device could not find SEC device 0x%04X\n",PCI_DEVICE_SEC);
        return SEC_HAL_FAILURE;
    }

    // Get the SEC PCI device info 
    // (pci_dev will point to a struct pci_dev type).
    // The Linux device reference count will be incremented.
    // The pci_dev_put must be called in sec_hal_release_irq
    // to decrement the Linux device reference count.
    osal_ret = os_pci_device_from_address( &pci_dev,
                                        (unsigned char)PCI_BUS_SEC,
                                        (unsigned char)PCI_DEV_SEC,
                                        (unsigned char)PCI_FUNC_SEC);
    if(osal_ret != OSAL_SUCCESS)
    {
        OS_PRINT("sec_hal_set_irq: os_pci_device_from_address could not get SEC device PCI info\n");
        return SEC_HAL_FAILURE;
    }

    // Get the interrupt number for the SEC device
    osal_ret = os_pci_get_interrupt(pci_dev, &irq);
    if(osal_ret != OSAL_SUCCESS)
    {
        OS_PRINT("sec_hal_set_irq: os_pci_get_interrupt could not get SEC device IRQ info\n");
        return SEC_HAL_FAILURE;
    }
    OS_PRINT("sec_hal_set_irq: os_pci_get_interrupt returned SEC IRQ=%d\n",irq);
    sec_hal->pci_info.irq_num = irq;

    // Install the interrupt handler
    sec_hal->int_handler = os_acquire_interrupt(irq,
                                                SEC_ID,
                                                "SEC int",
                                                sec_hal_intr_func,
                                                sec_hal);
    if ( sec_hal->int_handler == 0x0)
    {
        OS_PRINT("sec_hal_set_irq: os_acquire_interrupt() Failed");
        return SEC_HAL_FAILURE;
    }
    OS_PRINT("sec_hal_set_irq: os_acquire_interrupt installed the SEC\n");
    OS_PRINT(" interrupt handler, sec_hal_intr_func, to IRQ number=%d\n", irq);

    //Get the SEC PCI base address from the HW
    iret = os_pci_read_config_32(  pci_dev,
                            (unsigned int)0x10,
                            &baseaddr0);
    //OS_PRINT("sec_hal_set_irq: SEC baseaddr0= 0x%08X\n",baseaddr0);

    sec_hal->pci_info.base_addr0 = baseaddr0;

    return SEC_HAL_SUCCESS;
}

sec_hal_ret_t  sec_hal_release_irq(  sec_hal_t *sec_hal)
{
    os_release_interrupt(sec_hal->int_handler );
    if(pci_dev)
    {
        pci_dev_put((struct pci_dev*)pci_dev);
    }
    sec_hal->int_handler =0x0;
    return SEC_HAL_SUCCESS;
}

sec_hal_ret_t sec_hal_delete_handle (sec_hal_t *sec_hal)
{
    unsigned int  ret = SEC_HAL_FAILURE;

    if ((os_devhandle_t*) sec_hal->devh)
    {
        devh_Delete((os_devhandle_t*) sec_hal->devh);
        ret = SEC_HAL_SUCCESS;
    }
    return ret;
}

sec_hal_ret_t sec_hal_get_pci_rev(unsigned *SEC_revision)
{
    int             ret     = SEC_HAL_SUCCESS;
    unsigned char   revision;
    os_pci_dev_t    dev;

    if (OSAL_SUCCESS != OS_PCI_FIND_FIRST_DEVICE(   PCI_VENDOR_INTEL,
                                                    PCI_DEVICE_SEC,
                                                    &dev))
    {
        ret = SEC_HAL_FAILURE;
        goto exit;
    }

    if (OSAL_SUCCESS != OS_PCI_READ_CONFIG_8(dev, 8, &revision))
    {
        ret = SEC_HAL_FAILURE;
    }

    *SEC_revision = revision;
    OS_PCI_FREE_DEVICE(dev);

exit:
    return ret;
}
