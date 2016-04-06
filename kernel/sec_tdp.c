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
#include <linux/pci.h>
#include <linux/list.h>
#include <linux/firmware.h>
#include <linux/kobject.h>
#include <linux/types.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#include <asm/cacheflush.h>


#include "osal.h"
#include "iosf.h"
#include "sec_kernel.h"
#include "sec_kernel_types.h"
#include "sec_hal.h"
#include "sec_fw.h"
#include "sec_pci.h"
#include "sec_tdp.h"
#include "platform_config.h"
#include "platform_config_paths.h"
#include "sec_tdp_peri_fw.h"
#include "x86_cache.h"
#include "sec_fw.h"

/* Global definition used at system initialization*/
static pmr_t pmr_defs[MAX_NUM_PMRS];
int enable_tdp = 0;
DEFINE_MUTEX(sec_peri_fw_list_mutex);                /* Controls access to Peripheral FW list */
LIST_HEAD(sec_peri_fw_list);                         /* Peripheral FW info list */
uint32_t sec_peri_fw_request_count = 0;           /* Number of request for which Peripheral FW load IPC has been created */

extern sec_chip_info_t gchip_info;

/*
   Retrieve the pmr settings from the platform config tree.
   Invalid entries will contain a pmr_type field of -1 (pmr_invalid).
   Upon error, the contents of the callers pmr array is unknown
   and security initialization must prevent the system from 
   initializing successfully.
   Returns:
   0  - Protected memory must be disabled.
   1  - Protected memory must be enabled.
   -1 - Error
*/ 
// need to update this function after integration with SMD
static int get_pmr_info( pmr_t *pmrs )
{

    int retval                 = 0;
    int i = 0;
    char filename[MAX_FILE_NAME_LENGTH];
    config_result_t config_ret = CONFIG_SUCCESS;   
    config_ref_t pmr_node, child_node;

    OS_ASSERT( NULL != pmrs );
    
    // Initialize the pmr array
    memset((void *)&pmrs[0], 0, MAX_NUM_PMRS *sizeof(pmr_t));
    for(i=0;i<MAX_NUM_PMRS;i++)
    {
        pmrs[i].pmr_type=-1;
        pmrs[i].meu_region = -1;
    }
    // Enable TDP if there is a config file in platform config or if there
    // is a pmr_info entry.
    if (CONFIG_SUCCESS == config_get_str( ROOT_NODE, CONFIG_PATH_PLATFORM_TDP_CONFIG_FILE, filename, MAX_FILE_NAME_LENGTH ) )
    {
        retval = 1;
    }
 
    if( CONFIG_SUCCESS == config_node_find( ROOT_NODE, CONFIG_PATH_PLATFORM_PMR_INFO, &pmr_node ) )
    {
        unsigned int pmr_start_pa = 0;
        unsigned int pmr_size = 0;
        int pmr_type = 0;
        char pmr_name[64];
        unsigned int pmr_sta = 0;
        int pmr_meu_region =0;
        int pmr_meu_base =0; 
        config_ret = config_node_first_child(pmr_node, &child_node);
        i=0; 
        while ( config_ret == CONFIG_SUCCESS  && i < MAX_NUM_PMRS ) 
        {
            if( CONFIG_SUCCESS != (config_ret = config_node_get_name(child_node, pmr_name, sizeof(pmr_name))) )
            {
                retval = -1;
                SEC_ERROR( "Failed to find the name of this pmr.\n" );
                break;
            }
            if( CONFIG_SUCCESS != (config_ret = config_get_int(child_node, "base_pa", (int *)(&pmr_start_pa))) )
            {
                retval = -1;
                SEC_ERROR( "Failed to find the base_pa of this pmr.\n" );
                break;
            }            
            if( CONFIG_SUCCESS != (config_ret = config_get_int(child_node, "size", (int *)(&pmr_size))) )
            {
                retval = -1;  
                SEC_ERROR( "Failed to find the size of this pmr.\n" );
                break;
            }   
            if( CONFIG_SUCCESS != (config_ret = config_get_int(child_node, "type", (int *)(&pmr_type))) )
            {
                retval = -1; 
                SEC_ERROR( "Failed to find the type of this pmr.\n" );
                break;
            } 
            if( CONFIG_SUCCESS != (config_ret = config_get_int(child_node, "sta", (int *)(&pmr_sta))) )
            {
                retval = -1; 
                SEC_ERROR( "Failed to find the sta of this pmr.\n" );
                break;
            }
            if( CONFIG_SUCCESS != (config_ret = config_get_int(child_node, "meu_region", (int *)(&pmr_meu_region))) )
            {
                retval = -1;
                SEC_ERROR( "Failed to find the MEU region Id of this pmr.\n" );
                break;
            }
            if( CONFIG_SUCCESS != (config_ret = config_get_int(child_node, "meu_base", (int *)(&pmr_meu_base))) )
            {
                retval = -1;
                SEC_ERROR( "Failed to find the MEU RAM address of this pmr.\n" );
                break;
            }
 
            pmrs[pmr_type].pmr_type=pmr_type;            
            pmrs[pmr_type].start_pa=pmr_start_pa;            
            pmrs[pmr_type].size=pmr_size;            
            pmrs[pmr_type].sta=pmr_sta;
            pmrs[pmr_type].meu_region = pmr_meu_region;
            pmrs[pmr_type].meu_base = pmr_meu_base;
            strcpy( pmrs[pmr_type].name, pmr_name );            
            i++;
            config_ret = config_node_next_sibling(child_node, &child_node);
        }
        if(i>0 && retval != -1)
        {
            retval = 1;
        }
    }   
    return retval;
}

// function to call the platform_config reader
// returns the number of pmr enabled
// in case of fail returns -1
int sec_get_pmr()
{
   int i,retval;
   int pmr_count = 0;
   retval = get_pmr_info(pmr_defs);
   if(retval<=0)  
   {
       goto exit;
   }
   for(i=0;i<MAX_NUM_PMRS;i++)
   {
       if(pmr_defs[i].pmr_type != -1)
       {
           if(pmr_defs[i].size<=0)
           {
               pmr_count = -1;
               goto exit;
           }
           else
              pmr_count++;
       }
   }
   enable_tdp = 1;
exit:  
   printk("pmr_count=%d and enable_tdp = %d\n",pmr_count,enable_tdp); 
   return pmr_count;
}

// Writes configuration to MCU exposed PCI bars
// using 2 I/O address MCU_DATA_REG and MCU_CTRL_REG

static sec_result_t msgbus_write(os_pci_dev_t pci_dev, int port, uint32_t reg, uint32_t val)
{
    sec_result_t ret = SEC_SUCCESS;

    if ( os_pci_write_config_32(pci_dev, MCU_DATA_REG, val) != OSAL_SUCCESS ) 
    {
        ret = SEC_PCI_DEVICE_ACCESS_ERROR;
    }
    else if ( os_pci_write_config_32(pci_dev, MCU_CTRL_REG, 0xe00000f0|(port<<16) |(reg<<8)) != OSAL_SUCCESS ) 
    {
      ret = SEC_PCI_DEVICE_ACCESS_ERROR;
    }
    return ret;
}

// Reads configuration form MCU exposed PCI bars
// using 2 I/O address MCU_DATA_REG and MCU_CTRL_REG

static sec_result_t msgbus_read(os_pci_dev_t pci_dev, int port, uint32_t reg, uint32_t* val)
{
    sec_result_t ret = SEC_SUCCESS;

    if ( os_pci_write_config_32(pci_dev, MCU_CTRL_REG, 0xd00000f0| (port<<16) | (reg<<8)) != OSAL_SUCCESS ) 
    {
        ret = SEC_PCI_DEVICE_ACCESS_ERROR;
    }
    else if ( os_pci_read_config_32(pci_dev, MCU_DATA_REG, val) != OSAL_SUCCESS ) 
    {
      ret = SEC_PCI_DEVICE_ACCESS_ERROR;
    }
    return ret;
}

static sec_result_t sec_init_lock_meu( void )
{
    config_result_t config_ret = CONFIG_SUCCESS;
    sec_result_t result = SEC_SUCCESS;
    sec_meu_t  meu_config[MAX_NUM_MEU_REGIONS];
    config_ref_t meu_node, child_node;
    int num_meu_regions =0;
    os_pci_dev_t pci_dev;
    osal_result   ores;
    uint32_t meu_csr_bar;
    int i=0;
    volatile   uint32_t* pmeu_csr_bar = NULL;
    volatile int local_lock_reg=0;
    // MEU is only enabled on CE4200 and CE5300
    if((gchip_info.host_device != PCI_DEVICE_CE5300) && (gchip_info.host_device != PCI_DEVICE_CE4200))
        return result;

    memset((void *)&meu_config[0], 0, MAX_NUM_MEU_REGIONS *sizeof(sec_meu_t));
    if( CONFIG_SUCCESS == config_node_find( ROOT_NODE, CONFIG_PATH_PLATFORM_MEU_INFO, &meu_node ) )
    {
        config_ret = config_node_first_child(meu_node, &child_node);
        while ( config_ret == CONFIG_SUCCESS  && num_meu_regions < MAX_NUM_MEU_REGIONS )
        {
             
            unsigned int region_id = 0;
            unsigned int region_base = 0;
            unsigned int phys_base =0;
            unsigned int size=0;
            if( CONFIG_SUCCESS != (config_ret = config_get_int(child_node, "region_id", (int *)(&region_id))) )
            {
                SEC_ERROR( "Failed to find the region_id of this MEU region.\n" );
                return SEC_TDP_MEU_CONF_FAILED;
            }
            if( CONFIG_SUCCESS != (config_ret = config_get_int(child_node, "region_base", (int *)(&region_base))) )
            {
                SEC_ERROR( "Failed to find the region_base of this MEU region.\n" );
                return SEC_TDP_MEU_CONF_FAILED;
            }
            if( CONFIG_SUCCESS != (config_ret = config_get_int(child_node, "phys_base", (int *)(&phys_base))) )
            {
                SEC_ERROR( "Failed to find the phys_base of this MEU region.\n" );
                return SEC_TDP_MEU_CONF_FAILED;
            }
            if( CONFIG_SUCCESS != (config_ret = config_get_int(child_node, "size", (int *)(&size))) )
            {
                SEC_ERROR( "Failed to find the size of this MEU region.\n" );
                return SEC_TDP_MEU_CONF_FAILED;
            }
            meu_config[num_meu_regions].region_id = region_id;
            meu_config[num_meu_regions].region_base = region_base;
            meu_config[num_meu_regions].phys_base = phys_base;
            meu_config[num_meu_regions].size = size;
            num_meu_regions++;
            config_ret = config_node_next_sibling(child_node, &child_node);
        }
        if(num_meu_regions==0)
            return result; //If child node is not present treats as MEU disabled
        else
        {
            //configure and lock MEU regions
            ores = os_pci_enable_device(PCI_VENDOR_INTEL, PCI_DEVICE_ID_MEU);
            VERIFY(ores == OSAL_SUCCESS, exit, result,SEC_TDP_MEU_CONF_FAILED);
 
            ores = os_pci_find_first_device((unsigned int)PCI_VENDOR_INTEL,(unsigned int)PCI_DEVICE_ID_MEU, &pci_dev);
            VERIFY(ores == OSAL_SUCCESS, exit, result, SEC_PCI_DEVICE_NOT_FOUND); 

            ores = os_pci_read_config_32( pci_dev, MEU_CSR_MBAR, &meu_csr_bar);
            VERIFY(ores == OSAL_SUCCESS, close_pci_exit, result, SEC_TDP_MEU_CONF_FAILED); 

            //0x6C should cover all the mempry mapped registers for MEU
            pmeu_csr_bar = (uint32_t*)OS_MAP_IO_TO_MEM_NOCACHE(meu_csr_bar, 0x6C);
            VERIFY( pmeu_csr_bar != NULL, close_pci_exit, result, SEC_NULL_POINTER ); 

            for(i=0; i<num_meu_regions; i++)
            {
                local_lock_reg =0;
                if((meu_config[i].phys_base != 0) && (meu_config[i].size != 0)) 
                {
                    if(meu_config[i].region_id ==0)
                    {
                        *(pmeu_csr_bar+MEU_ATU_SRC0_BASE) = meu_config[i].region_base;
                        *(pmeu_csr_bar+MEU_ATU_DST0_BASE) = meu_config[i].phys_base;
                        *(pmeu_csr_bar+MEU_ATU_DST0_MASK) = ((~meu_config[i].size) + 1) & 0xFFFFFFFF;
                        local_lock_reg = *(pmeu_csr_bar+MEU_CTRL);
                        *(pmeu_csr_bar+MEU_CTRL) = local_lock_reg | 0x02;
                    }
                    else if (meu_config[i].region_id ==1)
                    {
                        *(pmeu_csr_bar+MEU_ATU_SRC1_BASE) = meu_config[i].region_base;
                        *(pmeu_csr_bar+MEU_ATU_DST1_BASE) = meu_config[i].phys_base;
                        *(pmeu_csr_bar+MEU_ATU_DST1_MASK) = ((~meu_config[i].size) + 1) & 0xFFFFFFFF;
                        local_lock_reg = *(pmeu_csr_bar+MEU_CTRL);
                        *(pmeu_csr_bar+MEU_CTRL) = local_lock_reg | 0x04;
                    }
                }
            }
        }
    }
    else
        return result;  //will treat as MEU disabled

close_pci_exit:
    if(pmeu_csr_bar != NULL)
        OS_UNMAP_IO_FROM_MEM( (void *)pmeu_csr_bar, 0x6C); 
    os_pci_free_device( pci_dev );    
exit:
    return result; 
}

// Configures the MCU PMR registers 
// writes the end address,size and start adress
// size should be at 1 MB boundary
//MCU exposes two I/O address to read/write the configuration
static sec_result_t sec_init_lock_pmr( void)
{
    sec_result_t ret = SEC_SUCCESS;
    //Read the PMRs from platform config here
    //The PMRs are 1MB granularity
    uint32_t pmr_entry;
    uint32_t i;
    uint32_t size;
    uint32_t upper_bound;
    uint32_t lower_bound;
    uint32_t pmr_start = (uint32_t)PMR_START;
    uint32_t one_mb = 1<<20;
    
    os_pci_dev_t pci_dev;
    iosf_handle iosf_h;
    iosf_result_t iosf_r;

    if(gchip_info.host_device == PCI_DEVICE_CE5300)
    {
        iosf_r = iosf_open(0, &iosf_h);
        if (iosf_r != IOSF_OK)
        {
            ret = SEC_IOSF_DEVICE_ACCESS_ERROR;
            return ret;
        }
    }
    else
    {
        if ( os_pci_device_from_address(&pci_dev, 0, 0, 0) != OSAL_SUCCESS )
        {
            ret = SEC_PCI_DEVICE_ACCESS_ERROR;
            return ret;
        }
    }
    // read value from config
    for( i=0;i <MAX_NUM_PMRS ; i++)
    {
        pmr_entry=0;
        if(pmr_defs[i].pmr_type !=-1) 
        {
            lower_bound = pmr_defs[i].meu_base & 0xFFF00000;
            size = pmr_defs[i].size;
            if(pmr_defs[i].size & 0x000FFFFF)
            {
                printk(KERN_WARNING "Memory layout should be at 1Mb boundary\n");
                ret=SEC_TDP_INIT_FAILED;
                return ret;
            }
            pmr_entry = lower_bound >> 16; //grab the MB units
            upper_bound = lower_bound + size - one_mb;
            pmr_entry = pmr_entry | upper_bound;
        }
        else
        {
            pmr_entry=INVALID_PMR_DEFAULT;
        }
        pmr_entry = pmr_entry | 0x01; //lock

        if(gchip_info.host_device == PCI_DEVICE_CE5300)
        {
            iosf_r = iosf_write32(iosf_h, IOSF_PORT_MCU, pmr_start +i , pmr_entry);
            VERIFY(iosf_r == IOSF_OK, exit, ret, SEC_IOSF_DEVICE_ACCESS_ERROR);
        }
        else
        {
            ret = msgbus_write(pci_dev,MSG_PORT_MCU, pmr_start +i , pmr_entry);
            VERIFY_QUICK(ret == SEC_SUCCESS, exit);
        }
    }
    //Configure the snoop register for fastpath mode
    if(gchip_info.host_device == PCI_DEVICE_CE4100)
    {
        ret = msgbus_write(pci_dev,MSG_PORT_MCU_FASTPATH, FASTPATH_CONF1,CE4100_FASTPATH_CONF_VAL1);
        VERIFY_QUICK(ret == SEC_SUCCESS, exit);
        ret = msgbus_write(pci_dev,MSG_PORT_MCU_FASTPATH, FASTPATH_CONF2,CE4100_FASTPATH_CONF_VAL2);
        VERIFY_QUICK(ret == SEC_SUCCESS, exit);
        ret = msgbus_write(pci_dev,MSG_PORT_MCU_FASTPATH, FASTPATH_LOCK,0x01);
        VERIFY_QUICK(ret == SEC_SUCCESS, exit);
    }
exit:
    if(gchip_info.host_device == PCI_DEVICE_CE5300)
        iosf_close(iosf_h);
    else
        os_pci_free_device( pci_dev );
    return ret;
}

// Configures the MCU attribute registers 
// writes the ORs of all the attribute assigned to PMR type
//MCU exposes two I/O address to read/write the configuration
//4 attribute registers are exposed to cover attribute of PMRs
//1st register for 1-4 PMR, 2nd for 5-8 PMR and so on
static sec_result_t sec_init_lock_pmr_attr(void )
{
    sec_result_t ret = SEC_SUCCESS;
    uint32_t i, sta, attr_index, region_index, bit_location;
    uint32_t pmr_attr_start = (uint32_t)PMR_ATTR_START;
    uint32_t pmr_attr_lock;
    os_pci_dev_t pci_dev;
    iosf_handle iosf_h;
    iosf_result_t iosf_r;
    uint32_t pmr_attr[NUM_ATTR_MATRIX];
    for(i=0; i<NUM_ATTR_MATRIX; i++)
    {
        pmr_attr[i] = 0;  
    }
    
    for(i=0; i<MAX_NUM_PMRS; i++)
    {
        if(pmr_defs[i].pmr_type!=-1)
        {
            bit_location =0;
            sta = pmr_defs[i].sta;
            attr_index = pmr_defs[i].pmr_type/4;
            region_index = 1 << (pmr_defs[i].pmr_type%4);
            while(sta>0)
            {
                if(sta & 0x01)
                {
                    pmr_attr[attr_index] = pmr_attr[attr_index] | (region_index << (bit_location * 4)); 
                }
                sta = sta >>1;
                bit_location++;
            }
        }
    }
    //read the attr value from PMR and write to the bus
    if(gchip_info.host_device == PCI_DEVICE_CE5300)
    {
        iosf_r = iosf_open(0, &iosf_h);
        if (iosf_r != IOSF_OK)
        {
            ret = SEC_IOSF_DEVICE_ACCESS_ERROR;
            return ret;
        }

        for (i=0;i<NUM_ATTR_MATRIX;i++)
        {
            iosf_r = iosf_write32(iosf_h, IOSF_PORT_MCU, pmr_attr_start + i, pmr_attr[i]);
            VERIFY(iosf_r == IOSF_OK, exit, ret, SEC_IOSF_DEVICE_ACCESS_ERROR);
        } 
        //lock the attr matrix
        iosf_r = iosf_read32(iosf_h, IOSF_PORT_MCU, PMR_ATTR_LOCK , &pmr_attr_lock);
        VERIFY(iosf_r == IOSF_OK, exit, ret, SEC_IOSF_DEVICE_ACCESS_ERROR);
        pmr_attr_lock = pmr_attr_lock | 0x1F;
        iosf_r = iosf_write32(iosf_h, IOSF_PORT_MCU, PMR_ATTR_LOCK, pmr_attr_lock);
        VERIFY(iosf_r == IOSF_OK, exit, ret, SEC_IOSF_DEVICE_ACCESS_ERROR);
    }
    else
    {
        if ( os_pci_device_from_address(&pci_dev, 0, 0, 0) != OSAL_SUCCESS )
        {
            ret = SEC_PCI_DEVICE_ACCESS_ERROR;
            return ret;
        }

        for (i=0;i<NUM_ATTR_MATRIX;i++)
        {
            ret=msgbus_write(pci_dev, MSG_PORT_MCU, pmr_attr_start + i, pmr_attr[i]);
            VERIFY_QUICK(ret == SEC_SUCCESS, exit);
        } 
        //lock the attr matrix
        ret = msgbus_read(pci_dev, MSG_PORT_MCU, PMR_ATTR_LOCK , &pmr_attr_lock);
        VERIFY_QUICK(ret == SEC_SUCCESS, exit);
        pmr_attr_lock = pmr_attr_lock | 0x1F;
        ret = msgbus_write(pci_dev, MSG_PORT_MCU, PMR_ATTR_LOCK, pmr_attr_lock);
        VERIFY_QUICK(ret == SEC_SUCCESS, exit);
    }
exit:
    if(gchip_info.host_device == PCI_DEVICE_CE5300)
        iosf_close(iosf_h);
    else
        os_pci_free_device( pci_dev );

    return ret;
}

//TDP needs TDP FW module to be loaded before dependent units 
//start
//If TDP is enabled , driver need to load the TDP FW if not
//loaded by CEFDK
//After system initialization, this FW unloads itself

int sec_check_tdp_fw()
{
    int ret = -1;
    sec_result_t rc = SEC_SUCCESS;
    unsigned int mod_id = (uint32_t) SEC_TDP_MODULE_ID;
    
    if(enable_tdp)
    {
        rc = sec_fw_get_module_id(&mod_id);
        if(rc == SEC_SUCCESS)
        {
            ret =PMR_ENABLED_FW_LOADED;
        }    
        else if(rc == SEC_FW_MODULE_NOT_FOUND)
        {
            ret = PMR_ENABLED_FW_TB_LOADED;
        }
    }
    else
    { 
        ret = PMR_DISABLED;
    }
    return ret;    
}

//To allow easy access to PMR configuration SEC contains 
// PMR configuration in SEC memory classification registers

static sec_result_t sec_init_lock_sec_mem_region(sec_hal_t* sec_hal)
{
    sec_result_t ret = SEC_SUCCESS;
    uint32_t pmr_class_entry;
    uint32_t i;
    uint32_t size;
    uint32_t upper_bound;
    uint32_t lower_bound;
    for(i=0; i<MAX_NUM_PMRS; i++)
    {
        pmr_class_entry=0;
        if(pmr_defs[i].pmr_type !=-1)
        {
            lower_bound = pmr_defs[i].start_pa & 0xFFF00000;
            size = pmr_defs[i].size;
            if(pmr_defs[i].size & 0x000FFFFF)
            {
                printk(KERN_WARNING "Memory layout should be at 1Mb boundary\n");
                ret=SEC_TDP_INIT_FAILED;
                goto exit;
            }
            pmr_class_entry = lower_bound >> 12; //grab the MB units
            upper_bound = lower_bound + size;
            pmr_class_entry = pmr_class_entry | upper_bound;
            pmr_class_entry = pmr_class_entry | (pmr_defs[i].pmr_type<<1);
        }
        pmr_class_entry = pmr_class_entry | 0x01; //lock
        sec_hal_devh_WriteReg32(sec_hal , SEC_CLASS_REG_BASE + i*4, pmr_class_entry);
    }
exit:
    return ret;
}

sec_result_t sec_tdp_conf_semi_trusted_unit( void * config_file_virt_ptr)
{
    sec_result_t ret = SEC_SUCCESS;
    os_pci_dev_t pci_dev;
    osal_result   ores;
    uint32_t csr_bar;
    volatile   uint32_t* p_csr_bar = NULL;
    uint32_t i;
    for(i=0; i<MAX_NUM_PMRS; i++)
    {

        if((pmr_defs[i].pmr_type == SEC_PMR_AUDIO) && (((*(int *)(config_file_virt_ptr+ AUDIO_CONFIG_FILE_OFFSET)) & 0x0F) ==0x03))
        {
            p_csr_bar = NULL;
            csr_bar = 0;
            ores = os_pci_enable_device(PCI_VENDOR_INTEL, PCI_DEVICE_ID_AUDIO_IF);
            VERIFY(ores == OSAL_SUCCESS, exit, ret,SEC_PCI_DEVICE_NOT_FOUND);

            ores = os_pci_find_first_device((unsigned int)PCI_VENDOR_INTEL,(unsigned int)PCI_DEVICE_ID_AUDIO_IF, &pci_dev);
            VERIFY(ores == OSAL_SUCCESS, exit, ret, SEC_PCI_DEVICE_NOT_FOUND);

            ores = os_pci_read_config_32( pci_dev, AUDIO_IF_CSR_MBAR, &csr_bar);
            VERIFY(ores == OSAL_SUCCESS, close_pci_exit, ret, SEC_PCI_DEVICE_ACCESS_ERROR);
            p_csr_bar = (uint32_t*)OS_MAP_IO_TO_MEM_NOCACHE(csr_bar, 0x80);
            
            VERIFY( p_csr_bar != NULL, close_pci_exit, ret, SEC_NULL_POINTER );
            *(p_csr_bar+AUDIO_IF_TTBM) = ((~pmr_defs[i].size) + 1) & 0xFFFFF000;
            *(p_csr_bar+AUDIO_IF_TTBA) = (pmr_defs[i].start_pa & 0xFFFFF000) | 0x01;;
            if(p_csr_bar != NULL)
                OS_UNMAP_IO_FROM_MEM( (void *)p_csr_bar, 0x80);
            os_pci_free_device( pci_dev );
        }

        if((pmr_defs[i].pmr_type == SEC_PMR_PIXELS) && (((*(int *)(config_file_virt_ptr+ DPE_CONFIG_FILE_OFFSET)) & 0x0F) ==0x03))
        {
            p_csr_bar = NULL;
            csr_bar = 0;
            ores = os_pci_enable_device(PCI_VENDOR_INTEL, PCI_DEVICE_ID_HDVCAP);
            VERIFY(ores == OSAL_SUCCESS, exit, ret,SEC_PCI_DEVICE_NOT_FOUND);

            ores = os_pci_find_first_device((unsigned int)PCI_VENDOR_INTEL,(unsigned int)PCI_DEVICE_ID_HDVCAP, &pci_dev);
            VERIFY(ores == OSAL_SUCCESS, exit, ret, SEC_PCI_DEVICE_NOT_FOUND);

            ores = os_pci_read_config_32( pci_dev, HDVCAP_CSR_MBAR, &csr_bar);
            VERIFY(ores == OSAL_SUCCESS, close_pci_exit, ret, SEC_PCI_DEVICE_ACCESS_ERROR);

            p_csr_bar = (uint32_t*)OS_MAP_IO_TO_MEM_NOCACHE(csr_bar, 0xAC);
            VERIFY( p_csr_bar != NULL, close_pci_exit, ret, SEC_NULL_POINTER );
            *(p_csr_bar+HDVCAP_TTBA) = (pmr_defs[i].start_pa & 0xFFFFF000) | 0x01;
            *(p_csr_bar+HDVCAP_TTBM) = ((~pmr_defs[i].size) + 1) & 0xFFFFF000;
            if(p_csr_bar != NULL)
                OS_UNMAP_IO_FROM_MEM( (void *)p_csr_bar, 0xAC);
            os_pci_free_device( pci_dev );
        }

        if((pmr_defs[i].pmr_type == SEC_PMR_VDC_WB)  && (((*(int *)(config_file_virt_ptr+ DPE_CONFIG_FILE_OFFSET)) & 0x0F) ==0x03))
        {
            p_csr_bar = NULL;
            csr_bar = 0;
            ores = os_pci_enable_device(PCI_VENDOR_INTEL, PCI_DEVICE_ID_VDC);
            VERIFY(ores == OSAL_SUCCESS, exit, ret,SEC_PCI_DEVICE_NOT_FOUND);

            ores = os_pci_find_first_device((unsigned int)PCI_VENDOR_INTEL,(unsigned int)PCI_DEVICE_ID_VDC, &pci_dev);
            VERIFY(ores == OSAL_SUCCESS, exit, ret, SEC_PCI_DEVICE_NOT_FOUND);

            ores = os_pci_read_config_32( pci_dev, VDC_CSR_MBAR, &csr_bar);
            VERIFY(ores == OSAL_SUCCESS, close_pci_exit, ret, SEC_PCI_DEVICE_ACCESS_ERROR);

            p_csr_bar = (uint32_t*)OS_MAP_IO_TO_MEM_NOCACHE(csr_bar, 0x7800C);
            VERIFY( p_csr_bar != NULL, close_pci_exit, ret, SEC_NULL_POINTER );
            *(p_csr_bar+VDC_TTBA) = (pmr_defs[i].start_pa & 0xFFFFF000) | 0x01;
            *(p_csr_bar+VDC_TTBM) = ((~pmr_defs[i].size) + 1) & 0xFFFFF000;
            if(p_csr_bar != NULL)
                OS_UNMAP_IO_FROM_MEM( (void *)p_csr_bar, 0x7800C);
            os_pci_free_device( pci_dev );
        }
    }
close_pci_exit:
    if(ret == SEC_PCI_DEVICE_ACCESS_ERROR)
        os_pci_free_device( pci_dev );
exit:
    return ret;
}



#define PMR_ADDR_HEX_STRING_BYTE_LENGTH   8

int sec_kernel_load_peripheral_fw(char *fw_mod_file, void *pmr_dest_phys_addr)
{
    struct subprocess_info *sub_info;
    char *argv[4]= {NULL,NULL,NULL,NULL};
    static char *envp[] = {
                           "HOME=/",
                           "PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/scripts", NULL
                         };
    int retval = -1;
    uint32_t  pmr_dst_addr;
    unsigned char pmr_addr_str[PMR_ADDR_HEX_STRING_BYTE_LENGTH + 1]; //+ 1 null char

    if((fw_mod_file == NULL) || (pmr_dest_phys_addr == NULL))
    {
      printk("sec_kernel_load_peripheral_fw: Invalid arguments\n");
      return -701;
    }

    //convert the address to hex string and null terminate it to pass it as argv[2] to user app.
    pmr_dst_addr = (uint32_t) pmr_dest_phys_addr;
    sprintf(pmr_addr_str, "%08X", pmr_dst_addr);
    pmr_addr_str[PMR_ADDR_HEX_STRING_BYTE_LENGTH]=0;


    argv[0] = "/bin/tdp_load_peri_fw";
    argv[1] = fw_mod_file;
    argv[2] = pmr_addr_str;
    argv[3] = NULL;

    printk(KERN_INFO "calling tdp app %s %s\n", argv[1], argv[2]);
    sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_ATOMIC);

    if(sub_info == NULL)
      return -ENOMEM;

    retval = call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);

    printk(KERN_INFO "tdp app return value = %d\n", retval );

    return retval;
}
EXPORT_SYMBOL(sec_kernel_load_peripheral_fw);

static int calc_page_required (void *body_virt_addr, uint32_t body_page_offset, int body_size)
{
   int gather_list_count=0;

   if (body_page_offset && (body_size>0))
      gather_list_count++;
   if (body_size > (PAGE_SIZE - body_page_offset)) 
   {
      body_size = body_size -(PAGE_SIZE - body_page_offset);
      gather_list_count = gather_list_count + body_size /PAGE_SIZE;
      if(body_size % PAGE_SIZE)
         gather_list_count++;
   }
   return gather_list_count; 
}

static sec_result_t sec_peri_fw_add_list_node(uint32_t dst_pmr_addr, uint32_t gather_list_addr)
{
    sec_peri_fw_list_node_t *    new_node = NULL;
    sec_result_t                 rc = SEC_SUCCESS;
    new_node = OS_ALLOC(sizeof(sec_peri_fw_list_node_t));
    if (new_node == NULL)
    {
        SEC_ERROR("Could not allocate a new list node\n");
        rc = SEC_OUT_OF_MEMORY;
        goto exit;
    }
    OS_MEMSET(new_node, 0x00, sizeof(sec_peri_fw_list_node_t));
    new_node->dst_pmr_addr = dst_pmr_addr;
    new_node->gather_list_addr = gather_list_addr;
    list_add_tail(&(new_node->list), &sec_peri_fw_list);
    sec_peri_fw_request_count++;
exit:
    return rc;
}

static sec_result_t sec_peri_fw_delete_list_node(uint32_t dst_pmr_addr)
{
    sec_result_t            rc = SEC_FAIL;
    sec_peri_fw_list_node_t *    cur_node;
    sec_peri_fw_list_node_t *    next_node;

    list_for_each_entry_safe(cur_node, next_node, &sec_peri_fw_list, list)
    {
        if (cur_node->dst_pmr_addr == dst_pmr_addr)
        {
            if(sec_peri_fw_request_count>0)
                sec_peri_fw_request_count--;
            else
               goto exit;
            OS_FREE(phys_to_virt(cur_node->gather_list_addr));
            list_del(&(cur_node->list));
            OS_FREE(cur_node);
            rc = SEC_SUCCESS;
            goto exit;
        } 
    }
exit:
    return rc;
}

void sec_peri_fw_cleanup_list()
{
    sec_peri_fw_list_node_t *  cur_node = NULL;
    sec_peri_fw_list_node_t *  next_node = NULL;

    mutex_lock(&sec_peri_fw_list_mutex);
    if(sec_peri_fw_request_count>0)
    {
        list_for_each_entry_safe(cur_node, next_node, &sec_peri_fw_list, list)
        {
            OS_FREE(phys_to_virt(cur_node->gather_list_addr));
            list_del(&(cur_node->list));
            OS_FREE(cur_node);
        }
    }    
    mutex_unlock(&sec_peri_fw_list_mutex);
}

int sec_load_peripheralFW_packager(void * fw_buffer_virtual_addr, int image_size, uint32_t pmr_dest_phys_addr, load_peripheral_ipc_data * ipc_data_buffer)
{
    ipl_tdp_load_peripheral_fw_module_t ipl;
    int gather_list_count=0;
    peri_fw_body_list_info *gather_list_info=NULL;
    uint32_t body_page_offset=0;
    void *   body_virt_addr;
    int body_size, i;
    int status =0;
    sec_result_t rc;
    unsigned int mod_id = (uint32_t) SEC_TDP_MODULE_ID;

    if((fw_buffer_virtual_addr == NULL) || (image_size <= FW_MODULE_CTRL_DATA_SIZE) || (ipc_data_buffer == NULL) )
    {
       status = INVALID_PARAM;
       goto exit;
    }
    OS_MEMSET( &ipl, 0x00, sizeof(ipl_tdp_load_peripheral_fw_module_t));
    rc = sec_fw_get_module_id(&mod_id);
    if(rc != SEC_SUCCESS)
    {
       status = TDP_FW_NOT_LOADED;
       goto exit;
    }
    ipl.header.module_id       =  mod_id;
   
    ipl.header.sub_cmd         = (uint32_t) IPC_SC_TDP_LOADPHFW;
    
    ipl.fw_signing_key_ptr     = (uint32_t) OS_VIRT_TO_PHYS((void *) ((char *)fw_buffer_virtual_addr + FW_SIGNING_KEY_OFFSET));  
    ipl.fw_mod_css_header_ptr  = (uint32_t) OS_VIRT_TO_PHYS((void *) ((char *)fw_buffer_virtual_addr + FW_MODULE_CSS_HEADER_OFFSET ));  
    ipl.fw_mod_css_sign_ptr    = (uint32_t) OS_VIRT_TO_PHYS((void *) ((char *)fw_buffer_virtual_addr + FW_MODULE_CSS_SIGN_OFFSET));
    ipl.dst_pmr_addr           = pmr_dest_phys_addr;
    ipl.endianess              = 1;

    body_page_offset           = (uint32_t)((char *)fw_buffer_virtual_addr + FW_MODULE_BODY_OFFSET) & 0xFFF;
    body_virt_addr             = (void *)((char *)fw_buffer_virtual_addr + FW_MODULE_BODY_OFFSET);
    body_size                  = image_size - FW_MODULE_CTRL_DATA_SIZE;
    gather_list_count          = calc_page_required(body_virt_addr, body_page_offset, body_size);
    ipl.fw_body_gather_list_count = gather_list_count;
   
//    printk("image_size = 0x%x, body_size = 0x%x, gather_list_count = 0x%x, body_virt_addr = 0x%x , body_page_offset =0x%x\n", image_size, body_size, gather_list_count, (uint32_t)body_virt_addr, body_page_offset); 
    gather_list_info           = (peri_fw_body_list_info *) OS_ALLOC(gather_list_count * sizeof(peri_fw_body_list_info));
    if(gather_list_info == NULL)
    {
        status = OUT_OF_MEMORY;
        goto exit;
    }
    OS_MEMSET( gather_list_info, 0x00, gather_list_count * sizeof(peri_fw_body_list_info));    
 
    for(i=0; i<gather_list_count; i++)
    {
       if(body_page_offset !=0)
       {
            (gather_list_info + i)->phys_addr = (uint32_t) OS_VIRT_TO_PHYS((void *)body_virt_addr);
            (gather_list_info + i)->size = PAGE_SIZE - body_page_offset;
            body_virt_addr = body_virt_addr + (PAGE_SIZE - body_page_offset);
            body_size = body_size - (PAGE_SIZE - body_page_offset);
            body_page_offset =0;
       }
       else
       {
           (gather_list_info + i)->phys_addr = (uint32_t) OS_VIRT_TO_PHYS((void *)body_virt_addr);
           if(body_size > PAGE_SIZE)
           {
              (gather_list_info + i)->size = PAGE_SIZE;
              body_virt_addr = body_virt_addr + PAGE_SIZE;
              body_size = body_size - PAGE_SIZE; 
           }
           else
           {
              (gather_list_info + i)->size = body_size;
           }
       }
       //printk ("(gather_list_info + i)->phys_addr =0x%x, (gather_list_info + i)->size =0x%x\n", (gather_list_info + i)->phys_addr, (gather_list_info + i)->size);
    }
    ipl.fw_body_gather_list_ptr = (uint32_t) OS_VIRT_TO_PHYS((void *)gather_list_info);
    cache_flush_buffer(gather_list_info,gather_list_count * sizeof(peri_fw_body_list_info));
    //add scatter-gather ptr info to STR list to free after sec_call_load_peripheralFW_IPC/ PM_POST_SUSPEND
    mutex_lock(&sec_peri_fw_list_mutex);
    if(sec_peri_fw_add_list_node(pmr_dest_phys_addr, ipl.fw_body_gather_list_ptr)!= SEC_SUCCESS)
    {
       status = ADD_STR_ENTRY_FAIL;
    }
    mutex_unlock(&sec_peri_fw_list_mutex);

exit:
    if(status == 0)
    { 
        OS_MEMCPY(ipc_data_buffer, &ipl, sizeof(ipl_tdp_load_peripheral_fw_module_t));
    }
    return status;
}
EXPORT_SYMBOL(sec_load_peripheralFW_packager);

int sec_call_load_peripheralFW_IPC(load_peripheral_ipc_data ipc)
{
    int status =0;
    sec_ipc_return_t    ipc_ret;
    sec_ipc_sizes_t     io_sizes;
    sec_result_t        rc;
    ipl_tdp_load_peripheral_fw_module_t ipl;
    peri_fw_body_list_info *gather_list_info=NULL;
    sec_fw_cmd_t        cmd=0;

    int i;
    const sec_fw_subcmd_t  sub_cmd = {.sc_tdp = IPC_SC_TDP_LOADPHFW};

    OS_MEMSET(&io_sizes, 0, sizeof(io_sizes));
    io_sizes.ipl_size = (uint16_t)sizeof(load_peripheral_ipc_data);
    
    OS_MEMSET(&ipl, 0, sizeof(ipl_tdp_load_peripheral_fw_module_t));
    OS_MEMCPY(&ipl, &ipc, sizeof(load_peripheral_ipc_data));

    gather_list_info = (peri_fw_body_list_info *) OS_ALLOC(ipl.fw_body_gather_list_count * sizeof(peri_fw_body_list_info));
    if(gather_list_info == NULL)
    {
        status = OUT_OF_MEMORY;
        goto exit;
    }
    //Flushing is required in fast path mode
    OS_MEMCPY(gather_list_info, phys_to_virt(ipl.fw_body_gather_list_ptr), ipl.fw_body_gather_list_count * sizeof(peri_fw_body_list_info));
    cache_flush_buffer(gather_list_info, ipl.fw_body_gather_list_count * sizeof(peri_fw_body_list_info));
    cache_flush_buffer(phys_to_virt(ipl.fw_signing_key_ptr), FW_SIGNING_KEY_SIZE);
    cache_flush_buffer(phys_to_virt(ipl.fw_mod_css_header_ptr), FW_MODULE_CSS_HEADER_SIZE);
    cache_flush_buffer(phys_to_virt(ipl.fw_mod_css_sign_ptr), FW_MODULE_CSS_SIGN_SIZE);
    
    for(i=0; i<ipl.fw_body_gather_list_count; i++) 
    {
        cache_flush_buffer(phys_to_virt((gather_list_info + i)->phys_addr),(gather_list_info + i)->size);
    }


    switch (gchip_info.host_device)
    {
        case PCI_DEVICE_CE2600:
        case PCI_DEVICE_CE4200:
        case PCI_DEVICE_CE5300:
             cmd = IPC_EXTERNAL_MODULE_CMD;
             break;
        default:
            printk("ERROR: Unknown SoC type %d for __FUNC__\n",gchip_info.host_device);
    }

    ipc_ret = sec_kernel_ipc(cmd, sub_cmd , io_sizes,(ipl_t *) &ipl, NULL, NULL, NULL);
    //printk("sec_call_load_peripheralFW_IPC ipc_ret=0x%x\n",ipc_ret);
    rc = ipc2sec(ipc_ret);
    if(rc != SEC_SUCCESS)
    {
        status = PERI_FW_LOAD_IPC_FAIL;
        goto exit;
    }

    //free the memory allocated for scatter gather list and update the peripheral database
    mutex_lock(&sec_peri_fw_list_mutex);
    if(sec_peri_fw_delete_list_node(ipl.dst_pmr_addr)!= SEC_SUCCESS)
        status = DEL_STR_ENTRY_FAIL;
    mutex_unlock(&sec_peri_fw_list_mutex);

exit:
    if(gather_list_info)
        OS_FREE(gather_list_info);
    return status;
}
EXPORT_SYMBOL(sec_call_load_peripheralFW_IPC);

int sec_unload_peripheralFW(unload_peripheral_fw_unit unit)
{
    int status =0;
    sec_ipc_return_t    ipc_ret;
    sec_ipc_sizes_t     io_sizes;
    sec_result_t        rc;
    ipl_tdp_unload_peripheral_fw_module_t ipl;
    sec_fw_cmd_t        cmd=0;
    unsigned int mod_id = (uint32_t) SEC_TDP_MODULE_ID;

    const sec_fw_subcmd_t  sub_cmd = {.sc_tdp = IPC_SC_TDP_UNLOADPHFW};
 
    OS_MEMSET(&io_sizes, 0, sizeof(io_sizes));
    io_sizes.ipl_size = (uint16_t)sizeof(ipl_tdp_unload_peripheral_fw_module_t);
  
    OS_MEMSET(&ipl, 0, sizeof(ipl_tdp_unload_peripheral_fw_module_t));
    rc = sec_fw_get_module_id(&mod_id);
    if(rc != SEC_SUCCESS)
    {
        status = TDP_FW_NOT_LOADED;
        goto exit;
    }
    ipl.header.module_id       =  mod_id;
    ipl.header.sub_cmd         = (uint32_t) IPC_SC_TDP_UNLOADPHFW;
 
    ipl.unit = unit;
 	 
    switch (gchip_info.host_device)
    {
        case PCI_DEVICE_CE2600:
        case PCI_DEVICE_CE4200:
        case PCI_DEVICE_CE5300:
            cmd = IPC_EXTERNAL_MODULE_CMD;
            break;
	default:
            printk("ERROR: Unknown chip type in __FUNC__\n");
    }

    ipc_ret = sec_kernel_ipc(cmd, sub_cmd , io_sizes,(ipl_t *) &ipl, NULL, NULL, NULL);
    rc = ipc2sec(ipc_ret);
    if(rc != SEC_SUCCESS)
    {
        status = PERI_FW_UNLOAD_IPC_FAIL;
    }

exit:
    return status;
}
EXPORT_SYMBOL(sec_unload_peripheralFW);

sec_result_t sec_tdp_config_file_reader( sec_tdp_config_info_t * tdp_config_struct) 
{
    sec_result_t                           rc = SEC_SUCCESS; 
    config_result_t config_ret = CONFIG_SUCCESS;
    char filename[MAX_FILE_NAME_LENGTH];
    os_firmware_t              os_fw_ctxt;
    void * local_tdp_ptr = NULL;

    VERIFY(tdp_config_struct!=NULL, exit, rc,SEC_NULL_POINTER);
    if((gchip_info.host_device != PCI_DEVICE_CE4200) && (gchip_info.host_device != PCI_DEVICE_CE5300))
        return rc;

    config_ret = config_get_str( ROOT_NODE, CONFIG_PATH_PLATFORM_TDP_CONFIG_FILE, filename, MAX_FILE_NAME_LENGTH );
    if ( CONFIG_SUCCESS != config_ret )
    {    
        printk("No TDP configuration file is found to enable MEU\n");
        return rc;
    }
    if (OSAL_SUCCESS != os_firmware_request(filename, &os_fw_ctxt))
    return rc;
    //TDP configuration file will always be less than a PAGE_SIZE
    if(os_fw_ctxt.fw_size <=0 || os_fw_ctxt.fw_size >PAGE_SIZE)
    {
         rc = SEC_INVALID_DATA_LENGTH;
         printk("TDP configuration file does not have proper file format to enable MEU\n");
         goto exit;
    }
    local_tdp_ptr = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
            get_order(os_fw_ctxt.fw_size));
    VERIFY(local_tdp_ptr!=NULL, exit, rc,SEC_OUT_OF_MEMORY);   
    set_pages_uc(virt_to_page((unsigned long)local_tdp_ptr), (1 << (get_order(os_fw_ctxt.fw_size))));

    OS_MEMCPY(local_tdp_ptr, os_fw_ctxt.fw_address, os_fw_ctxt.fw_size); 
    tdp_config_struct->tdp_config_mem_ptr = local_tdp_ptr;
    tdp_config_struct->tdp_config_mem_size =  os_fw_ctxt.fw_size;
exit:
    os_firmware_release(&os_fw_ctxt);  
    return rc;
}

sec_result_t sec_tdp_resume_handler(sec_tdp_config_info_t *tdp_config_struct, uint32_t mod_id)
{
    sec_result_t           rc = SEC_SUCCESS;
    ipl_tdp_load_config_t  ipl_tdp_config;
    ipl_tdp_init_t         ipl_tdp_init;
    const sec_fw_subcmd_t  sub_cmd_load_config = {.sc_tdp = IPC_SC_TDP_LOADCNFG};
    const sec_fw_subcmd_t  sub_cmd_tdp_init = {.sc_tdp = IPC_SC_TDP_INITTDP}; 
    sec_ipc_return_t    ipc_ret;
    sec_ipc_sizes_t     io_sizes;
    sec_fw_cmd_t cmd = IPC_EXTERNAL_MODULE_CMD;

    //No tdp_config_mem_ptr input check, since tdp_config_mem_ptr can be null too
    VERIFY(((mod_id == SEC_TDP_DEV_MODULE_ID)||(mod_id == SEC_TDP_MODULE_ID)), exit, rc,SEC_INVALID_INPUT);
    
    if(tdp_config_struct->tdp_config_mem_ptr != NULL)
    { 
        OS_MEMSET (&ipl_tdp_config, 0, sizeof(ipl_tdp_load_config_t));
        ipl_tdp_config.header.module_id   = mod_id;
        ipl_tdp_config.config_file_ptr    = (uint32_t) OS_VIRT_TO_PHYS((void *)(tdp_config_struct->tdp_config_mem_ptr));
        ipl_tdp_config.data_endianness    = 1;
        ipl_tdp_config.header.sub_cmd     = (uint32_t) IPC_SC_TDP_LOADCNFG;
        OS_MEMSET(&io_sizes, 0, sizeof(io_sizes));
        io_sizes.ipl_size = (uint16_t)sizeof(ipl_tdp_load_config_t);
        ipc_ret = sec_kernel_ipc(cmd, sub_cmd_load_config , io_sizes,(ipl_t *) &ipl_tdp_config, NULL, NULL, NULL);
        rc = ipc2sec(ipc_ret);
        VERIFY_QUICK(rc == SEC_SUCCESS,exit);
    }
    OS_MEMSET(&io_sizes, 0, sizeof(io_sizes));
    io_sizes.ipl_size = (uint16_t)sizeof(ipl_tdp_init_t);
    OS_MEMSET (&ipl_tdp_init, 0, sizeof(ipl_tdp_init_t));
    ipl_tdp_init.header.module_id   = mod_id;
    ipl_tdp_init.header.sub_cmd   = (uint32_t) IPC_SC_TDP_INITTDP;
    ipc_ret = sec_kernel_ipc(cmd, sub_cmd_tdp_init, io_sizes,(ipl_t *) &ipl_tdp_init, NULL, NULL, NULL);
    rc = ipc2sec(ipc_ret);
exit:
     if(tdp_config_struct->tdp_config_mem_ptr != NULL)
     {
        __sec_do_free_pages(tdp_config_struct->tdp_config_mem_ptr,tdp_config_struct->tdp_config_mem_size);
        tdp_config_struct->tdp_config_mem_ptr = NULL;
        tdp_config_struct->tdp_config_mem_size =0;
     }
     return rc;
}
sec_result_t sec_tdp_configuration()
{
    sec_result_t           rc = SEC_SUCCESS;
    rc = sec_init_lock_meu();
    VERIFY_QUICK(rc == SEC_SUCCESS,exit);
    rc = sec_init_lock_pmr();
    VERIFY_QUICK(rc == SEC_SUCCESS,exit);
    rc = sec_init_lock_pmr_attr();
    VERIFY_QUICK(rc == SEC_SUCCESS,exit);
    rc = sec_init_lock_sec_mem_region(&sec_hal_handle);
    VERIFY_QUICK(rc == SEC_SUCCESS,exit); 
    
exit:
    return rc;
}
