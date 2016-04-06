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

#ifndef _SEC_KERNEL_TYPES_H_
#define _SEC_KERNEL_TYPES_H_

#include <stdint.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif

#include "osal.h"


//#define ENABLE_SEC_DEBUG
//#define ENABLE_SEC_TRACE

// Use this to print values while debugging
#ifdef ENABLE_SEC_DEBUG
#define SEC_DEBUG(x...) OS_INFO(x)
#else
#define SEC_DEBUG(x...)
#endif

// Use this only to print execution trace
#ifdef ENABLE_SEC_TRACE
#define SEC_TRACE(x...) OS_INFO(x)
#else
#define SEC_TRACE(x...)
#endif



//SEC registers
#define SEC_HCU_RX_DATA 0xffC86404

#define SEC_AES_RX_DATA 0xFFC85400

#define SEC_AES_RX_FIFO 0xFFC85600
#define SEC_AES_TX_FIFO 0xFFC85700

#define SEC_CSS_RX_FIFO 0xFFC85E00
#define SEC_CSS_TX_FIFO 0xFFC85F00

#define SEC_C2_RX_FIFO  0xFFC85A00
#define SEC_C2_TX_FIFO  0xFFC85B00

#define SEC_DES_RX_FIFO 0xFFC86200
#define SEC_DES_TX_FIFO 0xFFC86300

// bitwise left/right rotations
#define rotl(x,n)   (((x)>>(32 - (n))) | ((x) << (n)))
#define rotr(x,n)   (((x)<<(32 - (n))) | ((x) >> (n)))

// translate little endian <----> big endian
#define bswap(y)   ((rotr(y, 8) & 0xff00ff00) | (rotl(y, 8) & 0x00ff00ff))

// define SEC_ERROR macro
#define SEC_ERROR(str, ...) \
printk("[sec.ko]:%s:%d Error: " str, __func__, __LINE__, ##__VA_ARGS__)

#define SEC_MAX_OPERATION_COUNT      32
#define SEC_MAX_AACS_CONTEXT         16
#define SEC_MAX_FW_WAIT          720000
#define SEC_CE4200_MAX_FW_WAIT  2160000
#define SEC_REG_SYS_MEM_SIZE      65536
#define SEC_REG_SYS_MEM_PAGER_SIZE  2*1024*1024
#define SEC_MAX_BULK_OPERATION_COUNT 32

enum context_type {
    SEC_MAC_CONTEXT = 0x00,
    SEC_DH_CONTEXT,
    SEC_HASH_CONTEXT,
};
#define SEC_NUM_CONTEXT_TYPES 3
#define SEC_NUM_CONTEXTS 4

#define SEC_MAX_DTCPIP_CONTEXT    2

//-----------------------------------------------------------------------------
// Status returned from IPC commands
// Note: IPC_RET_INVALID_MODULUS_SIZE usually results from passing the wrong
//       endianness (i.e. 0x00000040 turns into 0x40000000 in the FW)
//-----------------------------------------------------------------------------
typedef enum
{
    IPC_RET_SUCCESS                           = 0,
    IPC_RET_COMMAND_POSTED                    = 1,
    IPC_RET_COMMAND_COMPLETE                  = 2,
    IPC_RET_COMMAND_CONTINUE                  = 3,
    IPC_RET_COMMAND_WAITING                   = 4,
    IPC_RET_DEVICE_IDLE                       = 5,
    IPC_RET_MONOTONIC_TIME_BASE_PULSE         = 6,
    IPC_RET_DEVICE_ALLOCATED                  = 7,
    IPC_RET_FIFO_EMPTY                        = 8,
    IPC_RET_FIFO_FULL                         = 9,
    IPC_RET_SHARED_RAM_ACCESS_GRANTED         = 10,
    IPC_RET_AUXILLARY_TIMER_EXPIRE            = 0x40000000,
    IPC_RET_HDCP2R_INVALID_STATE              = 0x80001001,
    IPC_RET_HDCP2R_CALCULATION_FAILED         = 0x80001002,
    IPC_RET_HDCP2R_OUT_OF_RESOURCES           = 0x80001003,
    IPC_RET_HDCP2R_OUT_OF_SESSIONS            = 0x80001004,
    IPC_RET_HDCP2R_BAD_SESSION_TYPE           = 0x80001005,
    IPC_RET_HDCP2R_INVALID_SESSION            = 0x80001006,
    IPC_RET_HDCP2R_UNPERMITTED_SESSION_TYPE   = 0x80001007,
    IPC_RET_HDCP2R_KEYBLOB_NOT_LOADED_YET     = 0x80001008,
    IPC_RET_HDCP2R_KEYBLOB_ALREADY_LOADED     = 0x80001009,
    IPC_RET_HDCP2R_KEYBLOB_NOT_GKEKED         = 0x8000100a,
    IPC_RET_HDCP2R_KEYBLOB_ALREADY_WRAPPED    = 0x8000100b,
    IPC_RET_TDP_PMR_NOT_LOCKED                = 0x80004001,
    IPC_RET_TDP_PMR_INVALID_DRAM_ADDR         = 0x80004002,
    IPC_RET_TDP_PMR_INVALID_BOUNDS            = 0x80004003,
    IPC_RET_TDP_PMR_OVERLAPPING               = 0x80004004,
    IPC_RET_TDP_MEM_CLASS_NOT_LOCKED          = 0x80004005,
    IPC_RET_TDP_MEM_CLASS_PMR_MISMATCH        = 0x80004006,
    IPC_RET_TDP_MEM_CLASS_INVALID_TYPE        = 0x80004007,
    IPC_RET_TDP_ATTRIB_MATRIX_NOT_LOCKED      = 0x80004008,
    IPC_RET_TDP_ATTRIB_MATRIX_INVALID         = 0x80004009,
    IPC_RET_TDP_VT_BASE_NOT_LOCKED            = 0x8000400a,
    IPC_RET_TDP_VT_BASE_INVALID               = 0x8000400b,
    IPC_RET_TDP_INVALID_VENDOR_ID             = 0x8000400c,
    IPC_RET_TDP_INVALID_SERIAL_NUM            = 0x8000400d,
    IPC_RET_TDP_INVALID_UNIT_FLAGS            = 0x8000400e,
    IPC_RET_TDP_INVALID_MODULE_SIZE           = 0x8000400f,
    IPC_RET_TDP_INVALID_DESTINATION_TYPE      = 0x80004010,
    IPC_RET_TDP_INVALID_SEC_ATTRIB_TYPE       = 0x80004011,
    IPC_RET_TDP_INVALID_SNOOP_SETTING         = 0x80004012,
    IPC_RET_TDP_SNOOP_NOT_LOCKED              = 0x80004013,
    IPC_RET_TDP_INVALID_DEST_ALIGNMENT        = 0x80004014,
    IPC_RET_TDP_MODULE_ALREADY_LOADED         = 0x80004015,
    IPC_RET_TDP_MODULE_OVERLAPPING            = 0x80004016,
    IPC_RET_TDP_TOO_MANY_BSP_IMAGES           = 0x80004017,
    IPC_RET_TDP_INVALID_GATHER_ENTRY_SIZE     = 0x80004018,
    IPC_RET_TDP_NO_STR_REGIONS                = 0x80004019,
    IPC_RET_TDP_CORRUPT_STR_REGIONS           = 0x8000401a,
    IPC_RET_TDP_INVALID_CONFIG_FILE           = 0x8000401b,
    IPC_RET_TDP_INVALID_FW_VERSION            = 0x8000401c,
    IPC_RET_TDP_INVALID_MEU_CONFIG            = 0x8000401d,
    IPC_RET_TDP_INVALID_VDC_WB_TTR            = 0x8000401e,
    IPC_RET_TDP_INVALID_HDVCAP_TTR            = 0x8000401f,
    IPC_RET_TDP_INVALID_AUDIO_TTR             = 0x80004020,
    IPC_RET_TDP_INVALID_SKU_ID                = 0x80004021,
    IPC_RET_TDP_MODULE_NOT_LOADED             = 0x80004022,
    IPC_RET_54_INVALID_INPUT                  = 0xffffff7a,
    IPC_RET_54_INVALID_VARIANT                = 0xffffff75,
    IPC_RET_INVALID_KEY_LOCATION              = 0xffffff99,
    IPC_RET_INVALID_KEY_ID                    = 0xffffff9a,
    IPC_RET_FW_INVALID_LOAD_TYPE              = 0xffffffa4,
    IPC_RET_FW_MODULE_NOT_FOUND               = 0xffffffa5,
    IPC_RET_FW_MODULE_ALREADY_LOADED          = 0xffffffa6,
    IPC_RET_FW_HKEY_OPERATION_ERROR           = 0xffffffa7,
    IPC_RET_FW_SYMBOL_TABLE_MISMATCH          = 0xffffffa8,
    IPC_RET_FW_NO_MANIFEST_ENTRY              = 0xffffffa9,
    IPC_RET_FW_ELF_LOAD_FAILED                = 0xffffffaa,
    IPC_RET_FW_FS_SEEK_OUT_OF_BOUNDS          = 0xffffffab,
    IPC_RET_FW_FS_INVALID_SEEK_TYPE           = 0xffffffac,
    IPC_RET_FW_FS_REOPEN_FILE_ERROR           = 0xffffffad,
    IPC_RET_FW_FS_PAGE_NOT_FOUND              = 0xffffffae,
    IPC_RET_FW_FS_HEADER_LENGTH_MISMATCH      = 0xffffffaf,
    IPC_RET_INVALID_PAGE_ADDRESS              = 0xffffffb0,
    IPC_RET_FW_FS_FILE_NOT_OPENED             = 0xffffffb1,
    IPC_RET_SYSTEM_MEMORY_FULL                = 0xffffffb2,
    IPC_RET_INVALID_SYSTEM_ADDRESS            = 0xffffffb3,
    IPC_RET_INVALID_MODE                      = 0xffffffb4,
    IPC_RET_INVALID_NONCE                     = 0xffffffb5,
    IPC_RET_INVALID_STEP                      = 0xffffffb6,
    IPC_RET_INVALID_KEY_ATTRIBUTES            = 0xffffffb7,
    IPC_RET_TTB_KEY_INVALID                   = 0xffffffb8,
    IPC_RET_INVALID_KEY_TYPE                  = 0xffffffb9,
    IPC_RET_INVALID_KEY_SELECT                = 0xffffffba,
    IPC_RET_NO_KEY_SLOTS_AVAILABLE            = 0xffffffbb,
    IPC_RET_DRBG_NOT_INITIALIZED              = 0xffffffbc,
    IPC_RET_INVALID_HW_COMMAND                = 0xffffffbd,
    IPC_RET_EAU_PARITY_ERROR                  = 0xffffffbe,
    IPC_RET_MOD_EXP_WITHOUT_EXPONENT          = 0xffffffbf,
    IPC_RET_INVALID_AES_CTR_MODE              = 0xffffffc0,
    IPC_RET_INVALID_CHAIN_MODE                = 0xffffffc1,
    IPC_RET_INVALID_ECC_CURVE                 = 0xffffffc4,

    /* Error codes -515 to -500 for downloadable modules
       to avoid clash with ROM error codes */
    IPC_RET_CRYPT_FAILED                      = 0xfffffdfd,
    IPC_RET_SIGN_FAILED                       = 0xfffffdfe,
    IPC_RET_NO_CONTEXT_AVAILABLE              = 0xfffffdff,
    IPC_RET_INVALID_CONTEXT                   = 0xfffffe00,
    IPC_RET_DRBG_FAILED                       = 0xfffffe01,
    IPC_RET_FEATURE_UNSUPPORTED               = 0xfffffe02,
    IPC_RET_MOD_REDUCE_FAIL                   = 0xfffffe03,
    IPC_RET_SCALAR_MULT_FAIL                  = 0xfffffe04,
    IPC_RET_SHA_FAIL                          = 0xfffffe05,
    IPC_RET_INVALID_MSG                       = 0xfffffe06,
    IPC_RET_BAD_SINK_DEVICE                   = 0xfffffe07,
    IPC_RET_DRM_NO_MEM                        = 0xfffffe08,
    IPC_RET_CONTEXT_BLACKLIST                 = 0xfffffe09,
    IPC_RET_INVALID_PROTOCOL_STATE            = 0xfffffe0a,
    IPC_RET_SRM_FAIL                          = 0xfffffe0b,
    IPC_RET_SIGNATURE_VERIFICATION_FAILED     = 0xfffffe0c,
    // End

    IPC_RET_INVALID_MODULUS_SIZE              = 0xffffffda,
    IPC_RET_FW_DOESNOT_MATCH_SOC_SKU          = 0xffffffdf,
    IPC_RET_MODULE_PARAMS_ARE_TOO_FAR_APART   = 0xffffffe2,
    IPC_RET_INVALID_ATU_CONFIGURATION         = 0xffffffe3,
    IPC_RET_SIGNATURE_GREATER_THAN_MODULUS    = 0xffffffe5,
    IPC_RET_INVALID_INPUT_SIZE                = 0xffffffe6,
    IPC_RET_WATCH_DOG_TIMER_EXPIRE            = 0xffffffe7,
    IPC_RET_INVALID_TIMER_COUNT_VALUE         = 0xffffffe8,
    IPC_RET_INVALID_TIMER_TICK_VALUE          = 0xffffffe9,
    IPC_RET_INVALID_TIMER_SELECTION           = 0xffffffea,
    IPC_RET_WAIT_TIMEOUT                      = 0xffffffeb,
    IPC_RET_PROCESS_ID_NOT_FOUND              = 0xffffffec,
    IPC_RET_INVALID_CRYPTO_ENGINE_SELECT      = 0xffffffed,
    IPC_RET_INPUT_TOO_BIG                     = 0xffffffee,
    IPC_RET_PROCESS_NOT_ASSIGNED              = 0xffffffef,
    IPC_RET_INVALID_EAU_MODE                  = 0xfffffff1,
    IPC_RET_INVALID_DES_MODE                  = 0xfffffff2,
    IPC_RET_INVALID_KEY_SIZE                  = 0xfffffff3,
    IPC_RET_USER_INVALID_MEMORY_ACCESS        = 0xfffffff4,
    IPC_RET_INVALID_SRC_KEY_PARAM             = 0xfffffff5,
    IPC_RET_INVALID_DEST_PARAM                = 0xfffffff6,
    IPC_RET_ERROR                             = 0xfffffff7,
    IPC_RET_INVALID_KEY_LADDER                = 0xfffffff8,
    IPC_RET_INVALID_RSA_KEY_SELECT            = 0xfffffff9,
    IPC_RET_INVALID_HASH_MODE                 = 0xfffffffa,
    IPC_RET_DMA_MODE_NOT_SUPPORTED            = 0xfffffffb,
    IPC_RET_COMMAND_NOT_SUPPORTED_YET         = 0xfffffffc,
    IPC_RET_DEVICE_BUSY                       = 0xfffffffd,
    IPC_RET_KERNEL_MEMORY_FULL_ERROR          = 0xfffffffe,
    IPC_RET_BAD_HOST_REQUEST                  = 0xffffffff,

    IPC_FW_RET_DUPLICATE                      = 0xffffff9f
} sec_ipc_return_t;

//-----------------------------------------------------------------------------
// Convenience macro to check if sec_ipc_return_t is "successful"
//-----------------------------------------------------------------------------
#define IPC_RET_OK(r)  ((r)>=0 && (r)<=0x7fffffff)
//-----------------------------------------------------------------------------
// Convenience macro to check if sec_ipc_return_t is "successful"
//-----------------------------------------------------------------------------
#define IPC_RET_FAILED(r)  ((r)<0 || (r)>0x7fffffff)

//-----------------------------------------------------------------------------
// IPC PAYLOADS
//-----------------------------------------------------------------------------


// Structure for dma operations
typedef struct
{
    uint32_t    dma_flags;
    uint32_t    next_descriptor;
    uint32_t    src_start;
    uint32_t    dst_start;
    uint32_t    src_size;
    uint32_t    dst_size;
} dma_info_t;

// Input payload format for AESEncryptData and AESDecryptData
typedef struct
{
  //uint32_t    filler[10];
    uint32_t    filler1[5];
    uint8_t     chain_mode;
    uint8_t     filler2[3];
    uint8_t     iv[16];
    dma_info_t  dma_info;
} ipl_aes_crypt_data_t;

// Input payload format for AES Multipart encrypt and AES Multipart Decrypt
typedef struct
{
    uint32_t    filler1[6];
    union
    {
        struct
        {
            uint32_t    multipart_list;
            uint32_t    filler2[7];
        } multipart_data;
        struct
        {
            uint32_t        aes_src_sg;
            uint32_t        aes_src_sg_count;
            uint32_t        aes_dst_sg;
            uint32_t        aes_dst_sg_count;
            uint32_t        copy_src_sg;
            uint32_t        copy_src_sg_count;
            uint32_t        copy_dst_sg;
            uint32_t        copy_dst_sg_count;
        } sg_data;
    };
    uint32_t    filler3[2];
} ipl_aes_crypt_multipart_data_t;

typedef struct
{
    uint32_t    filler1[5];
    dma_info_t  dma_info;
    uint32_t    filler2[5];
} ipl_c2_crypt_data_t;

typedef struct
{
    uint32_t    filler1[3];
    dma_info_t  dma_info;
    uint32_t    filler2[7];
} ipl_css_crypt_data_t;

typedef struct
{
    uint32_t    filler1[9];
    dma_info_t  dma_info;
    uint32_t    filler2;
} ipl_des_crypt_data_t;


// structure describes input payload for md5 and sha*
typedef struct
{
    uint32_t    filler1[3];
    uint8_t     mode; // Not used by MD5
    uint8_t     do_not_finalize;
    uint8_t     allow_user_entered_chaining_variables;
    uint8_t     chaining_variable_endianness;
    uint32_t    chaining_variable_pointer;
    uint32_t    total_length_in_bits;
    dma_info_t  dma_info;
    uint32_t    filler2[4];
} ipl_hash_data_t;

typedef struct
{
    uint32_t    filler1[3];
    uint8_t     mode;
    uint8_t     context;
    uint8_t     allow_user_entered_chaining_variables;
    uint8_t     data_source;
    uint32_t    key_id;
    uint8_t     operation;
    uint8_t     filler2[3];
    dma_info_t  dma_info;
    uint32_t    message_ptr;
    uint8_t     storage_mode;
    uint8_t     filler3[3];
    uint32_t    filler4[2];
} ipl_hash_fw_based_t;

typedef struct
{
    uint32_t    filler1[4];
    dma_info_t  dma_info;
    uint32_t    filler2[6];
} ipl_arc4_crypt_data_t;


typedef struct
{
    uint32_t    filler1;
    uint32_t    filler2;
    uint32_t    filler3;
    uint32_t    context_id;
    uint32_t    filler4[12];
} ipl_fcm_context_id_t;

typedef struct
{
    uint32_t    filler1[7];
    uint32_t    data_buffer_masks;
    uint32_t    next_desc;
    uint32_t    filler2[7];
} ipl_dtcpip_process_pkt_t;

typedef struct
{
    union
    {
        uint8_t data[64];

        struct
        {
            uint32_t    filler1[5];
            uint32_t    pr2_sg_data_start;
            uint32_t    pr2_sg_data_count;
            uint32_t    filler2[9];
        } pr2_calc_omac;

        struct
        {
            uint32_t    filler1[3];
            uint32_t    pr2_sg_data_start;
            uint32_t    pr2_sg_data_count;
            uint32_t    filler2[11];
        } pr2_hash_value;
    };
} ipl_pr2_sg_op_t;

#if 0
typedef struct
{
    uint32_t    filler1[5];
    uint32_t    pr2_sg_data_start;
    uint32_t    pr2_sg_data_count;
    uint32_t    filler2[9];
} ipl_pr2_sg_op_t;
#endif

#define SEC_DRM_DESTROY_CTX_PAYLOAD_SIZE 16

// input payload format for AACSCreateContext command
typedef struct
{
    uint32_t    filler1[3];
    uint32_t    context_memory_pointer;
    uint32_t    filler2[12];
} ipl_aacs_create_context_t;

// input payload format for AACSDestroyContext command
typedef struct
{
    uint32_t    filler1[3];
    uint32_t    context_id;
    uint32_t    filler2[12];
} ipl_aacs_destroy_context_t;

// Input payload format for IPC_SC_60_13
typedef struct
{
    uint32_t    filler1;
    uint32_t    sub_cmd;
    uint32_t    filler2[10];
    uint32_t    dma_descriptor;
    uint32_t    filler3[3];
} ipl_ipc_sc_60_13_t;

// Input payload header for ExternalModuleIPC
typedef struct
{
    uint32_t        job_id;
    uint32_t        module_id;
    uint32_t        sub_cmd;
} ipl_external_module_ipc_header_t;

// Input payload for MAC
typedef struct
{
    uint32_t        filler1[3];
    uint8_t         mac_flag;
    uint8_t         mac_context_id;
    uint8_t         ops_mode;
    uint8_t         key_location;
    uint32_t        key_id;
    uint32_t        external_key_size;
    uint32_t        data_ptr;
    uint32_t        data_size;
    uint32_t        ret_mac_ptr;
    uint8_t         external_key_endianess;
    uint8_t         data_endianess;
    uint8_t         mac_endianess;
    uint8_t         filler2[1];
    uint8_t         filler3[24];
} ipl_mac_data_t;

typedef struct
{
    uint32_t    filler1[3];
    uint8_t     subcommand;
    uint8_t     context;
    uint8_t     validation_mode;
    uint8_t     filler2;
    uint32_t    data_pointer;
    uint32_t    group_key_id;
    uint32_t    result_key_id;
    uint32_t    filler3[9];
} ipl_dh_key_exchange_t;

// Input payload for TDP
typedef struct
{
    uint32_t    fw_key_ptr;
    uint32_t    css_hdr_ptr;
    uint32_t    body_ptr;
    uint32_t    body_size;
    uint32_t    ccs_sign_ptr;
    uint32_t    dest_ptr;
    uint8_t     endianness;
    uint8_t     dest_unit;
    uint8_t     filler0[26];
} ipl_load_peripheral_module_t;

typedef struct
{
    uint32_t        job_id;
    uint32_t        module_id;
    uint32_t        sub_cmd;
    union
    {
        ipl_load_peripheral_module_t   load_peripheral_module;
        uint32_t               filler1[13];
    };
} ipl_tdp_t;

// Input payload for BulkIPC
typedef struct
{
  uint32_t    filler1[3];
  uint32_t    cmd_buff_ptr;
  uint32_t    cmd_data_ptr;
  uint32_t    cmd_count;
  uint32_t    filler2[10];
} ipl_bulkipc_t;

// Input payload for GetFirmwareVersionNumber
typedef struct
{
  uint32_t    filler1[3];
  uint32_t    mod_buf_ptr;
  uint32_t    buffer_size;
} ipl_get_fw_version_t;
 
// generic input payload structure
typedef union
{
    uint32_t                                data[16];
    ipl_external_module_ipc_header_t        external_module_ipc;
    ipl_aacs_create_context_t               aacs_create_ctx;
    ipl_aacs_destroy_context_t              aacs_destroy_ctx;
    ipl_fcm_context_id_t                    fcm_ctx_id;
    ipl_dtcpip_process_pkt_t                dtcpip_process_pkt;
    ipl_aes_crypt_data_t                    aes_crypt;
    ipl_arc4_crypt_data_t                   arc4_crypt;
    ipl_c2_crypt_data_t                     c2_crypt;
    ipl_css_crypt_data_t                    css_crypt;
    ipl_des_crypt_data_t                    des_crypt;
    ipl_hash_data_t                         hash_data;
    ipl_hash_fw_based_t                     hash_fw_based;
    ipl_ipc_sc_60_13_t                      ipc_sc_60_13;
    ipl_tdp_t                               ipc_tdp;
    ipl_mac_data_t                          mac_data;
    ipl_dh_key_exchange_t                   dh_key_exchange;
    ipl_bulkipc_t                           bulk_ipc;
    ipl_aes_crypt_multipart_data_t          aes_crypt_multipart;
    ipl_get_fw_version_t                    get_fw_version;
    ipl_pr2_sg_op_t                         pr2_sg_op;
} ipl_t;

typedef struct
{
    uint32_t    job_id;
    union
    {
        uint32_t    filler0[15]; // Most commands.
        uint32_t    context_id;  // IPC_AACS_CREATE_CONTEXT,
                                 // IPC_GENERATE_MAC,
                                 // IPC_DH_KEY_EXHCNAGE,
                                 // IPC_SHA_HASH_DATA
        struct
        {
            uint32_t key_size;
            uint32_t dh_context_id;
        };
    };
} opl_t;

typedef struct { uint32_t data[64]; } ipc_shmem_t;

typedef struct uint32_list
{
    struct list_head list;
    uint32_t value;
} uint32_list;

#include "sec_common_types.h"
#include "sec_kernel_share_types.h"

#endif
