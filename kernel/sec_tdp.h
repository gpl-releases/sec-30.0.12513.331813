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

#ifndef __SEC_TDP_H__
#define __SEC_TDP_H__

extern struct pci_dev * sec_pci_dev;

#define MAX_NUM_PMRS      16
#define MAX_NUM_MEU_REGIONS 2
#define NUM_ATTR_MATRIX 4
#define SEC_TDP_MODULE_ID 0x00004000
#define SEC_TDP_DEV_MODULE_ID 0x80004000

//MEU specific definitions
#define PCI_DEVICE_ID_MEU      0x0702 // MEU
#define PCI_DEVICE_ID_AUDIO_IF 0x2E60
#define PCI_DEVICE_ID_VDC      0x2E61
#define PCI_DEVICE_ID_HDVCAP   0x0704

#define MEU_CSR_MBAR       0x10
#define AUDIO_IF_CSR_MBAR  0x10
#define VDC_CSR_MBAR       0x10
#define HDVCAP_CSR_MBAR    0x10

#define MEU_ATU_SRC0_BASE  (0x50/4)  //Bits 31..12, /4 for dwords
#define MEU_ATU_DST0_BASE  (0x54/4)  //Bits 31..12, /4 for dwords
#define MEU_ATU_DST0_MASK  (0x58/4)
#define MEU_ATU_SRC1_BASE  (0x60/4)
#define MEU_ATU_DST1_BASE  (0x64/4)
#define MEU_ATU_DST1_MASK  (0x68/4)
#define MEU_CTRL           (0x08/4)

#define AUDIO_IF_TTBA      (0x68/4)
#define AUDIO_IF_TTBM      (0x6C/4)
#define AUDIO_CONFIG_FILE_OFFSET 0x2E0
#define VDC_TTBA           (0x78004/4)
#define VDC_TTBM           (0x78008/4)
#define HDVCAP_TTBA        (0xA4/4)
#define HDVCAP_TTBM        (0xA8/4)
#define DPE_CONFIG_FILE_OFFSET 0x2DC

//PMR specific definitions

#define MSG_PORT_MCU                 0x01
#define MSG_PORT_MCU_FASTPATH        0x00
#define IOSF_PORT_MCU                0x01
#define IOSF_PORT_VT                 0x00
#define PMR_START                    0xB0
#define PMR_ATTR_START               0xFC
#define PMR_ATTR_LOCK                0xF9
#define FASTPATH_CONF1               0x30
#define FASTPATH_CONF2               0x3E
#define FASTPATH_LOCK                0x31
#define MCU_CTRL_REG                 0xD0
#define MCU_DATA_REG                 0xD4
#define CE4100_FASTPATH_CONF_VAL1    0x202820
#define CE4100_FASTPATH_CONF_VAL2    0x02
#define CE4200_FASTPATH_CONF_VAL1    0x202820
#define CE4200_FASTPATH_CONF_MASK1   0x303C30
#define CE4200_FASTPATH_CONF_VAL2    0x0A
#define CE4200_FASTPATH_CONF_MASK2   0x0F
#define CE5300_FASTPATH_CONF_VAL1    0x202820
#define CE5300_FASTPATH_CONF_MASK1   0x303C30
#define CE5300_FASTPATH_CONF_VAL2    0x00800A
#define CE5300_FASTPATH_CONF_MASK2   0x00C00E
#define INVALID_PMR_DEFAULT          0x0000FFF1 

//SEC classification register offset

#define SEC_CLASS_REG_BASE 0x0807C0

#define CONFIG_PATH_PLATFORM_MEDIA_BASE_ADDRESS "platform.memory.media_base_address"
#define CONFIG_PATH_PLATFORM_PMR_INFO  "platform.memory.pmr_info"
#define CONFIG_PATH_PLATFORM_MEU_INFO  "platform.memory.meu_info"
#define CONFIG_PATH_PLATFORM_TDP_CONFIG_FILE "platform.memory.tdp_config_file"
#define PMR_NM_SZ 64
#define MAX_FILE_NAME_LENGTH 256

//File Format of signed peripheral FW module 
#define FW_MODULE_HEADER_SIZE             12 
#define FW_SIGNING_KEY_SIZE               644   // css header + css signature + key
#define FW_MODULE_CSS_HEADER_SIZE         128
#define FW_MODULE_CSS_SIGN_SIZE           256
      
#define FW_SIGNING_KEY_OFFSET             FW_MODULE_HEADER_SIZE
#define FW_MODULE_CSS_HEADER_OFFSET      (FW_SIGNING_KEY_OFFSET + FW_SIGNING_KEY_SIZE)
#define FW_MODULE_CSS_SIGN_OFFSET        (FW_MODULE_CSS_HEADER_OFFSET + FW_MODULE_CSS_HEADER_SIZE)
#define FW_MODULE_BODY_OFFSET            (FW_MODULE_CSS_SIGN_OFFSET   + FW_MODULE_CSS_SIGN_SIZE)
          
#define FW_MODULE_CTRL_DATA_SIZE         (FW_MODULE_HEADER_SIZE \
                                          + FW_SIGNING_KEY_SIZE \
                                          + FW_MODULE_CSS_HEADER_SIZE \
                                          + FW_MODULE_CSS_SIGN_SIZE)

typedef enum {
   SEC_PMR_UNDEFINED = 0,
   SEC_PMR_SEC = 1,
   SEC_PMR_UNUSED_2 = 2,
   SEC_PMR_TSD_FW_DATA = 3,
   SEC_PMR_VIDEO_FW_CODE = 4,
   SEC_PMR_VIDEO_FW_DATA = 5,
   SEC_PMR_AV_STREAM = 6,
   SEC_PMR_CMP_VID = 7,
   SEC_PMR_AUDIO = 8,
   SEC_PMR_PIXELS = 9,
   SEC_PMR_VDC_WB = 10,
   SEC_PMR_AUDIO_FW_CODE = 11,
   SEC_PMR_AUDIO_FW_DATA = 12,
   SEC_PMR_UNUSED_13 = 13,
   SEC_PMR_UNUSED_14 = 14,
   SEC_PMR_UNUSED_15 = 15,
   SEC_PMR_TYPE_COUNT = 16,
   SEC_PMR_ERROR = -1,
} sec_tdp_pmr_type_t;

typedef struct      
{ 
    uint32_t        job_id;
    uint32_t        module_id;
    uint32_t        sub_cmd;
} ipl_common_t;
typedef struct
{   
    ipl_common_t    header;
    uint32_t        filler[13];
}ipl_tdp_init_t;

typedef struct
{
    ipl_common_t    header;
    uint32_t        fw_signing_key_ptr;
    uint32_t        fw_mod_css_header_ptr;
    uint32_t        fw_body_gather_list_ptr;
    uint32_t        fw_body_gather_list_count;
    uint32_t        fw_mod_css_sign_ptr;
    uint32_t        dst_pmr_addr;
    uint8_t         endianess;
    uint8_t         filler[27];
} ipl_tdp_load_peripheral_fw_module_t;

typedef struct
{
    ipl_common_t    header;
    uint32_t        unit;
} ipl_tdp_unload_peripheral_fw_module_t;

typedef struct
{   
    ipl_common_t    header;
    uint32_t        config_file_ptr;
    uint32_t        data_endianness;
    uint32_t        filler[11];
} ipl_tdp_load_config_t;
    

//structure of Gather list for fw module body.
typedef struct
{         
  uint32_t phys_addr;
  uint32_t  size;
} peri_fw_body_list_info;



/* Completely describe a Protected Memory Region */
typedef struct  pmr_struct {
   unsigned int start_pa;     // Physical address of PMR. If MEU is enabled, it will have MEU PCI adreess.
                              // It will be stored in SEC classification registers
   unsigned int size;         // PMR size in bytes
   int          pmr_type;     // Region as described in spec
   char         name[PMR_NM_SZ];      // Name used in memory layout configuration
   unsigned int sta;          // 32 bit flags describing Sec attr for the above region (described in spec)
   int          meu_region;  //MEU Region ID (0/1)
   unsigned int meu_base;  //meu_base is the RAM address where actual data will be stored after going through MEU.
                           //it will be configured in MCU registers
                           //meu_base and start_pa will have same value(Physical address of PMR), if MEU is disabled
} pmr_t;

typedef struct {
    struct list_head        list;
    uint32_t                dst_pmr_addr;
    uint32_t                gather_list_addr;
} sec_peri_fw_list_node_t;  /* An entry node for the kernel loaded image list */

typedef struct meu_struct {
    unsigned int region_id;
    unsigned int region_base;
    unsigned int phys_base;
    unsigned int size;
} sec_meu_t;

typedef struct
{
    uint32_t  tdp_config_mem_size;
    void *    tdp_config_mem_ptr;
}sec_tdp_config_info_t;

//-----------------------------------------------------------------------------
//  G L O B A L S
//-----------------------------------------------------------------------------

extern struct mutex        sec_peri_fw_list_mutex;
extern struct list_head    sec_peri_fw_list;
extern uint32_t            sec_peri_fw_request_count;

//-----------------------------------------------------------------------------
// F U N C T I O N S
//-----------------------------------------------------------------------------
int sec_get_pmr(void);
int sec_check_tdp_fw(void);
void sec_peri_fw_cleanup_list(void);
sec_result_t sec_tdp_config_file_reader( sec_tdp_config_info_t * );
sec_result_t sec_tdp_resume_handler(sec_tdp_config_info_t *, uint32_t );
sec_result_t sec_tdp_configuration( void );
sec_result_t sec_tdp_conf_semi_trusted_unit( void * config_file_virt_ptr );
#endif /* __SEC_TDP_H__ */
