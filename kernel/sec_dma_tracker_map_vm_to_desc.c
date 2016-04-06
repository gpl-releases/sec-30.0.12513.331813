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

#include "sec_dma_tracker.h"


//-----------------------------------------------------------------------------
// dma_tracker_map_vm_to_desc
//
// This is the function that coordinates all the work to create
// the DMA descriptors and associated locked pages.
//
// Create a linked list of SEC DMA descriptors for user space virtual memory.
// The descriptors must use physical addresses, because the physical pages
// associated with the virtual memory may not be contiguous, no descriptor 
// can specify a transfer that will cross a page boundary.
//
// Because only full blocks can be operated on by the encryption/decryption
// ciphers, SEC must buffer input and output data internally.
//
// On store-and-forward transfers of multiple blocks (total size an even
// multiple of the block size), SEC can regulate the buffering itself.
//
// When a block spans a page boundary (in either the source or the destination
// buffer) it must be transferred with multiple read operations followed by
// multiple write operations.  In these cases only a single block is transferred
// (before resuming store-and-forward) to be sure SEC buffers don't overflow.
//
// Parameters:
//  src             User-space source buffer description.
//  dst             User-space destination buffer description.
//  block_size      Cipher block size.
//  src_rx_reg      Source FIFO register for WRITE-only DMA descriptors.
//  dst_rx_reg      Dest FIFO register for READ-only DMA descriptors.
//
// Return value:    Pointer to DMA descriptor list (NULL on failure).
//-----------------------------------------------------------------------------
sec_dma_descriptor_t* dma_tracker_map_vm_to_desc( user_buf_t *src,
                                                  user_buf_t *dst,
                                              sec_dma_type_t  dma_type,
                                                         int  block_size,
                                               unsigned long  src_rx_reg,
                                               unsigned long  dst_rx_reg,
                                                sec_fw_cmd_t  fw_cmd)
{
    sec_result_t            rc;
    sec_dma_descriptor_t   *head = NULL;    // Head of descriptor linked list
    sec_dma_descriptor_t   *tail = NULL;    // Tail of descriptor linked list
    user_buf_t             *pub = NULL;
    unsigned long           srcphys;
    unsigned long           dstphys;
    unsigned long           xfer_size;
    unsigned long           partial_block_size;
    uint32_t                dma_stf_flags = 0; //store-and_forward DMA flags
    uint32_t                dma_read_flags = 0;
    uint32_t                dma_write_flags = 0;

    if(dma_type == SEC_SMD_TO_SMD)  return NULL;
    if((dma_type == SEC_SMD_TO_DMA) || (dma_type == SEC_DMA_TO_DMA))
    {
        // SEC_DMA_DST_PAGE_POINTER_IS_NULL
        if(dst == NULL) return NULL;
    }
    if((dma_type == SEC_DMA_TO_SMD) || (dma_type == SEC_DMA_TO_DMA))
    {
        // SEC_DMA_SRC_PAGE_POINTER_IS_NULL
        if(src == NULL) return NULL;
    }


    if (fw_cmd == IPC_ARC4_ENCRYPT_DECRYPT_DATA)
    {
        dma_stf_flags = SEC_DMA_STF_FLAGS_ARC4; 
    }
    else
    {
        dma_stf_flags = SEC_DMA_STF_FLAGS;
    }

    switch(dma_type)
    {
      case SEC_SMD_TO_DMA:
        dma_stf_flags |= SEC_DMA_FLAG_DST_LL;
        dma_write_flags = SEC_DMA_WRITE_FLAGS | SEC_DMA_FLAG_DST_LL;
        pub = dst;
        break;
      case SEC_DMA_TO_SMD:
        dma_stf_flags |= SEC_DMA_FLAG_SRC_LL;
        dma_read_flags = SEC_DMA_READ_FLAGS | SEC_DMA_FLAG_SRC_LL;
        pub = src;
        break;
      case SEC_DMA_TO_DMA:
        dma_stf_flags  |= SEC_DMA_FLAG_DST_LL | SEC_DMA_FLAG_SRC_LL;
        dma_read_flags  = SEC_DMA_READ_FLAGS | SEC_DMA_FLAG_SRC_LL |
                          SEC_DMA_FLAG_DST_LL | SEC_DMA_FLAG_DST_MODE_FIX;
        dma_write_flags = SEC_DMA_WRITE_FLAGS | SEC_DMA_FLAG_SRC_LL |
                          SEC_DMA_FLAG_DST_LL;
        pub = src;
        break;
      default:
        return NULL; // invalid DMA type cannot do anything
    }

    // Each iteration of this loop will generate the DMA descriptors for one 
    // physical page of the buffer. If the page ends with a partial block,
    // descriptors will be generated for both that partial block and for the
    // for the other half of the block in the next page.
#ifdef DEBUG_MAP_VM_TO_DESC
    printk(KERN_INFO "===================== dma_tracker_map_vm_to_desc =====================\n");
#endif
    while (pub->size > 0)
    {
#ifdef DEBUG_MAP_VM_TO_DESC
        printk(KERN_INFO "pub->size = %d\n", pub->size);
#endif
        // Make sure next descriptor doesn't cross page boundary in either
        // the source buffer or the destination buffer.
        switch(dma_type)
        {
          case SEC_SMD_TO_DMA:
            xfer_size = PWU_MIN(dst->page_bytes, dst->size);
            srcphys = 0;
            dstphys = dst->page_addr + dst->offset;
            break;
          case SEC_DMA_TO_SMD:
            xfer_size = PWU_MIN(src->page_bytes, src->size);
            srcphys = src->page_addr + src->offset;
            dstphys = 0;
            break;
          case SEC_DMA_TO_DMA:
            xfer_size = PWU_MIN(src->page_bytes, dst->page_bytes);
            srcphys = src->page_addr + src->offset;
            xfer_size = PWU_MIN(xfer_size, src->size);
            dstphys = dst->page_addr + dst->offset;
            break;
          default:
            return NULL; // invalid DMA type cannot do anything
        }

        //
        // Will be non-zero if the page ends with a partial block.
        partial_block_size = xfer_size % block_size;

        // If there are one or more full blocks in both source and dest pages,
        // set up descriptor for as many full blocks as possible.
        if (xfer_size >= block_size)
        {
            // Round down to block multiple, transfer partial block later.
            // (No-op if partial_block_size == 0)
            xfer_size -= partial_block_size;

            // Add STORE-AND-FORWARD DMA descriptor to list
            rc=add_dma_desc(&head,&tail,xfer_size,srcphys,dstphys,dma_stf_flags);
            VERIFY_QUICK(rc == SEC_SUCCESS, fail);

            if((dma_type == SEC_DMA_TO_SMD) || (dma_type == SEC_DMA_TO_DMA))
            {
#ifdef DEBUG_MAP_VM_TO_DESC
                printk(KERN_INFO "(1) src=%p src->page_addr=0x%08lx xfer_size=%lu src->page_index=%d\n",
                       src, src->page_addr, xfer_size, src->page_index);
#endif
                rc = user_buf_advance( src, xfer_size );
#ifdef DEBUG_MAP_VM_TO_DESC
                printk(KERN_INFO "(1a)src=%p src->page_addr=0x%08lx xfer_size=%lu src->page_index=%d\n",
                       src, src->page_addr, xfer_size, src->page_index);
#endif
                VERIFY_QUICK(rc == SEC_SUCCESS, fail);
            }

            if((dma_type == SEC_SMD_TO_DMA) || (dma_type == SEC_DMA_TO_DMA))
            {
                rc = user_buf_advance( dst, xfer_size );
                VERIFY_QUICK(rc == SEC_SUCCESS, fail);
            }
        }

        // Set up READ and WRITE descriptors for block that is split across
        // pages in one or both buffers.
        if (partial_block_size != 0)
        {
            unsigned long remaining;  // # of bytes left in block

            if (head == NULL)
            {
                // First block must be in store-and-forward mode. Partial
                // block can't be in STF mode.  If first block is partial
                // block, set up dummy STF DMA descriptor (length 0).
                rc = add_dma_desc( &head, &tail, 0, 0, 0, dma_stf_flags );
                VERIFY_QUICK(rc == SEC_SUCCESS, fail);
            }//ENDIF first block spans pages

            if((dma_type == SEC_DMA_TO_SMD) || (dma_type == SEC_DMA_TO_DMA))
            {
                // Add multiple READ descriptors (if necessary) for next block
                for (remaining = block_size; remaining > 0; remaining -= xfer_size)
                {
                    xfer_size = PWU_MIN(src->page_bytes, remaining);

                    rc = add_dma_desc( &head, &tail, xfer_size, srcphys,
                                        dst_rx_reg, dma_read_flags);
                    VERIFY_QUICK(rc == SEC_SUCCESS, fail);
#ifdef DEBUG_MAP_VM_TO_DESC
                    printk(KERN_INFO "(2)  src = %p src->page_addr 0x%08lx\n",
                           src, src->page_addr);
#endif
                    rc = user_buf_advance( src, xfer_size );
#ifdef DEBUG_MAP_VM_TO_DESC
                    printk(KERN_INFO "(2a) src = %p src->page_addr 0x%08lx\n",
                           src, src->page_addr);
#endif
                    VERIFY_QUICK(rc == SEC_SUCCESS, fail);
                }//ENDFOR multiple read decriptors for page spanning DMA
            }//ENDIF read source is DMA

            if((dma_type == SEC_SMD_TO_DMA) || (dma_type == SEC_DMA_TO_DMA))
            {
                // Add multiple WRITE descriptors (if necessary) for next block
                for (remaining = block_size; remaining > 0; remaining -= xfer_size)
                {
                    xfer_size = PWU_MIN(dst->page_bytes, remaining);

                    rc = add_dma_desc( &head, &tail, xfer_size, src_rx_reg,
                                        dstphys, dma_write_flags);
                    VERIFY_QUICK(rc == SEC_SUCCESS, fail);
                    rc = user_buf_advance( dst, xfer_size );
                    VERIFY_QUICK(rc == SEC_SUCCESS, fail);
                }//ENDFOR multiple write decriptors for page spanning DMA
            }//ENDIF write destination is DMA
        }//ENDIF DMA descriptor is split across pages
    }//ENDWHILE there are still pages to build DMA descriptors for.
#ifdef DEBUG_MAP_VM_TO_DESC
    printk(KERN_INFO "===================== dma_tracker_map_vm_to_desc =====================\n\n");
#endif

    if (head != NULL)
    {
        tail->dma_flags |= SEC_DMA_FLAG_TERM |  SEC_DMA_FLAG_DST_INT;
        dump_dma_list(head);
        return head;
    }

fail:
    if (head)
    {
        sec_kernel_free_descriptor_list(head);
    }
    return NULL;
}
