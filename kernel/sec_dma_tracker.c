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

//----------------------------------------------------------------------------
// Description:
//
// This file provides tracking capabilities for clients connected to a
// SEC driver, and allows to invoke garbage collector for clients that
// exit unexpectadly without properly deallocating all used resources
// (firmware resources and memory)
//----------------------------------------------------------------------------
#include "sec_dma_tracker.h"

// Link list of clients
sec_dma_client_t *sec_dma_clients;

// Semaphore used for avoiding race conditions when operating on
// sec_dma_clients global
struct semaphore dma_tracker_sema;

// Helpful macros to lock/unlock/init global semaphore
#define SEMA_DMA_INIT   sema_init(&dma_tracker_sema, 1);
#define SEMA_DMA_LOCK   down(&dma_tracker_sema);
#define SEMA_DMA_UNLOCK up(&dma_tracker_sema);

//----------------------------------------------------------------------------
// Helper functions
//----------------------------------------------------------------------------

#ifdef DEBUG_SHOW_DMA_MEM
// Displays the data item details of the sec_dma_mem_t structure
void show_dma_mem(sec_dma_mem_t *pdmamem)
{
    sec_dma_descriptor_t *pDMAdescriptor = NULL;
    uint32_t pPhysDMAdescriptor;

    if(pdmamem == NULL)
    {
      printk(KERN_INFO "show_dma_mem: passed in sec_dma_mem_t pointer is NULL!\n\n");
      return;
    }
    printk(KERN_INFO "\n===S=T=A=R=T============show_dma_mem============S=T=A=R=T===\n");
    printk(KERN_INFO "pdmamem->cmd = %d\n", (int)(pdmamem->cmd));
    printk(KERN_INFO "DMA Types 0=SMD to DMA, 1=DMA to SMD, 2=DMA to DMA, 3=SMD to SMD\n");
    printk(KERN_INFO "pdmamem->dma_type = %d \n", (int)(pdmamem->dma_type));
    printk(KERN_INFO "DMA Chain Type 0=LT (Long Term) 1=ST (Short Term)\n");
    printk(KERN_INFO "pdmamem->dma_chain = %d\n", (int)(pdmamem->dma_chain));
    printk(KERN_INFO "The memory size for both source and destination in bytes\n");

    printk(KERN_INFO "pdmamem->dma_size = %d bytes\n", (int)(pdmamem->dma_size));
    printk(KERN_INFO "pdmamem->dma_src_addr = 0x%p\n", pdmamem->dma_src_addr);
    printk(KERN_INFO "pdmamem->dma_dst_addr = 0x%p\n", pdmamem->dma_dst_addr);

    printk(KERN_INFO "pdmamem->dma_info.tgid = %d\n", pdmamem->dma_info.tgid);
    printk(KERN_INFO "pdmamem->dma_info.src.vaddr = 0x%08x\n", pdmamem->dma_info.src.vaddr);
    
    if(pdmamem->dma_info.src.pages != NULL)
    {
        printk(KERN_INFO "pdmamem->dma_info.src.pages = 0x%p\n", pdmamem->dma_info.src.pages);
    }
    else
    {
        printk(KERN_INFO "pdmamem->dma_info.src.pages = NULL\n");
    }
    
    printk(KERN_INFO "pdmamem->dma_info.src.num_pages = %d\n", pdmamem->dma_info.src.num_pages);
    printk(KERN_INFO "pdmamem->dma_info.src.size = %d\n", pdmamem->dma_info.src.size);
    printk(KERN_INFO "pdmamem->dma_info.src.page_index = %d\n", pdmamem->dma_info.src.page_index);
    printk(KERN_INFO "pdmamem->dma_info.src.page_addr = 0x%08lx\n", pdmamem->dma_info.src.page_addr);
    printk(KERN_INFO "pdmamem->dma_info.src.offset = 0x%08lx\n", pdmamem->dma_info.src.offset);
    printk(KERN_INFO "pdmamem->dma_info.src.page_bytes = 0x%08lx\n", pdmamem->dma_info.src.page_bytes);

    printk(KERN_INFO "pdmamem->dma_info.dst.vaddr = 0x%08x\n", pdmamem->dma_info.dst.vaddr);
    if(pdmamem->dma_info.dst.pages != NULL)
    {
        printk(KERN_INFO "pdmamem->dma_info.dst.pages = 0x%p\n", pdmamem->dma_info.dst.pages);
    }
    else
    {
        printk(KERN_INFO "pdmamem->dma_info.dst.pages = NULL\n");
    }
    
    printk(KERN_INFO "pdmamem->dma_info.dst.num_pages = %d\n", pdmamem->dma_info.dst.num_pages);
    printk(KERN_INFO "pdmamem->dma_info.dst.size = %d\n", pdmamem->dma_info.dst.size);
    printk(KERN_INFO "pdmamem->dma_info.dst.page_index = %d\n", pdmamem->dma_info.dst.page_index);
    printk(KERN_INFO "pdmamem->dma_info.dst.page_addr = 0x%08lx\n", pdmamem->dma_info.dst.page_addr);
    printk(KERN_INFO "pdmamem->dma_info.dst.offset = 0x%08lx\n", pdmamem->dma_info.dst.offset);
    printk(KERN_INFO "pdmamem->dma_info.dst.page_bytes = 0x%08lx\n", pdmamem->dma_info.dst.page_bytes);

    if(pdmamem->dma_info.dma_desc != NULL)
    {
        printk(KERN_INFO "pdmamem->dma_info.dma_desc kernel virtual address= 0x%p\n", pdmamem->dma_info.dma_desc);
        pDMAdescriptor = pdmamem->dma_info.dma_desc;
        pPhysDMAdescriptor = virt_to_phys((void*)pDMAdescriptor);
        printk(KERN_INFO "pPhysDMAdescriptor kernel physical address= 0x%08x\n", pPhysDMAdescriptor);
        while(pDMAdescriptor != NULL)
        {
            printk(KERN_INFO "\npDMAdescriptor->next = 0x%08x\n", pDMAdescriptor->next);
            printk(KERN_INFO "pDMAdescriptor->size = 0x%08x\n", pDMAdescriptor->size);
            printk(KERN_INFO "pDMAdescriptor->src = 0x%08x\n", pDMAdescriptor->src);
            printk(KERN_INFO "pDMAdescriptor->dst = 0x%08x\n", pDMAdescriptor->dst);
            printk(KERN_INFO "pDMAdescriptor->dma_flags = 0x%08x\n", pDMAdescriptor->dma_flags);
            if(pDMAdescriptor->next != 0)
            {
                pDMAdescriptor = phys_to_virt(pDMAdescriptor->next);
            }
            else
            {
                pDMAdescriptor = NULL;
            }
        } //ENDWHILE the DMA descriptor pointer is NOT NULL
    }
    else
    {
        printk(KERN_INFO "pdmamem->dma_info.dma_desc = NULL\n");
    }


    printk(KERN_INFO "pdmamem->dma_info.dma_flags = 0x%08x\n", pdmamem->dma_info.dma_flags);
    printk(KERN_INFO "pdmamem->dma_info.next_descriptor = 0x%08x\n", pdmamem->dma_info.next_descriptor);
    printk(KERN_INFO "pdmamem->dma_info.src_start = 0x%08x\n", pdmamem->dma_info.src_start);
    printk(KERN_INFO "pdmamem->dma_info.dst_start = 0x%08x\n", pdmamem->dma_info.dst_start);
    printk(KERN_INFO "pdmamem->dma_info.src_size = 0x%08x\n", pdmamem->dma_info.src_size);
    printk(KERN_INFO "pdmamem->dma_info.dst_size = 0x%08x\n", pdmamem->dma_info.dst_size);
    printk(KERN_INFO "===E=N=D=============== show_dma_mem ===============E=N=D===\n\n");
}//ENDPROC show_dma_mem
#endif


//-----------------------------------------------------------------------------
// dma_crypt_prepare
//
// Encrypt/decrypt using DMA to transfer data to/from firmware
//-----------------------------------------------------------------------------
static sec_result_t dma_crypt_prepare( sec_fw_cmd_t  cmd,
                                          uint32_t  *block_size,
                                          uint32_t  *TX,
                                          uint32_t  *RX )
{
    sec_result_t  rc = SEC_SUCCESS;

    switch (cmd)
    {
    case IPC_C2_ENCRYPT_DATA:
    case IPC_C2_DECRYPT_DATA:
        *block_size = C2_BLOCK_SIZE;
        *TX         = SEC_C2_TX_FIFO;
        *RX         = SEC_C2_RX_FIFO;
        break;
    case IPC_AES_ENCRYPT_DATA:
    case IPC_AES_DECRYPT_DATA:
        *block_size = AES_BLOCK_SIZE;
        *TX         = SEC_AES_TX_FIFO;
        *RX         = SEC_AES_RX_FIFO;
        break;
    case IPC_AES128_ENCRYPT_DECRYPT_DATA:
        /* Because this is part of the CSS block, use the CSS FIFOs.
         * AES block size and DMA info remain the same */
        *block_size = AES_BLOCK_SIZE;
        *TX         = SEC_CSS_TX_FIFO;
        *RX         = SEC_CSS_RX_FIFO;
        break;
    case IPC_CSS_DECRYPT_DATA:
        *block_size = CSS_BLOCK_SIZE;
        *TX         = SEC_CSS_TX_FIFO;
        *RX         = SEC_CSS_RX_FIFO;
        break;
    case IPC_DES_ENCRYPT_DATA:
    case IPC_DES_DECRYPT_DATA:
        *block_size = DES_BLOCK_SIZE;
        *TX         = SEC_DES_TX_FIFO;
        *RX         = SEC_DES_RX_FIFO;
        break;
    case IPC_ARC4_ENCRYPT_DECRYPT_DATA:
        *block_size = ARC4_BLOCK_SIZE;
        *TX         = SEC_C2_TX_FIFO;
        *RX         = SEC_C2_RX_FIFO;
        break;
    default:
        rc = SEC_FAIL;
        break;
    }

    return rc;
} 

//----------------------------------------------------------------------------
// __dma_client_find
//
// Searches for client with passed 'tgid' and returns the structure
// representing the client. Returns NULL if client with provided 'tgid' is
// not found.
//----------------------------------------------------------------------------
static sec_dma_client_t* __dma_client_find(unsigned int tgid)
{
    sec_dma_client_t *tmp;

    for (tmp = sec_dma_clients; tmp != NULL; tmp =  tmp->next)
    {
        if (tmp->tgid == tgid)
        {
#ifdef DEBUG_DMA_CLIENT_FIND
            printk(KERN_INFO "_dma_client_find: Found client at 0x%p\n", tmp);
#endif
            break;
        }
    }

    return tmp;
} //ENDPROC __dma_client_find


//----------------------------------------------------------------------------
// __dma_client_find_mem
//
// Searches for client with passed 'pdmamem->tgid' and 'pdmamem->dma_dst_addr'.
// If a matching client with a matching sec_dma_node_t is found
// this function returns the pointer to the tracker's copy that
// calling kernel function will use, else it returns NULL.
//----------------------------------------------------------------------------
static sec_dma_mem_t* __dma_client_find_mem(sec_dma_mem_t *pdmamem)
{
    sec_dma_client_t *this_client;
    sec_dma_node_t   *tnode;
    sec_dma_node_t   *start_node;
    sec_dma_mem_t    *ptrmem;
    unsigned int      tgid;
    int               st=0;

    this_client = NULL;
    tnode = NULL;
    ptrmem = NULL;
    start_node = NULL;
    if(pdmamem == NULL) goto exit;

    //TODO Must search both the long and short term chains.
    //     If nothing found then add to short terms

    // Search through all the DMA clients
    tgid = (unsigned int)(current->tgid);
    this_client = __dma_client_find(tgid);
    if(this_client == NULL)
    {
        printk(KERN_INFO "__dma_client_find_mem: __dma_client_find could not find %d tgid\n",tgid);
        goto exit;
    } //ENDIF DMA client was NOT found

#ifdef DEBUG_DMA_CLIENT_FIND_MEM
    printk(KERN_INFO "\n__dma_client_find_mem:\n");
    printk(KERN_INFO "    this_client=0x%p\n", this_client);
    printk(KERN_INFO "    LongTerm start_node=0x%p\n",this_client->dma_lt_node_start);
    printk(KERN_INFO "    ShortTerm start_node=0x%p\n\n",this_client->dma_st_node_start);
#endif

    st = 0;
    while( (ptrmem == NULL) && (st < 2))
    {
        // Select the long or short term linked list (chain)
        if((this_client->dma_lt_node_start != NULL) && (st == 0))
        {
            start_node = this_client->dma_lt_node_start;
            // Search through all of this matching client's sec_dma_node_t(s)
            // examining each sec_dma_node_t's sec_dma_mem_t dma_dst_addr
            for (tnode = start_node; (tnode != NULL) && (ptrmem == NULL); tnode = tnode->next)
            {
#ifdef DEBUG_DMA_CLIENT_FIND_MEM
                printk(KERN_INFO "__dma_client_find_mem: LT src_addr=0x%p this node's src_addr=0x%p\n",
                       pdmamem->dma_src_addr, tnode->dma_mem.dma_src_addr);
                printk(KERN_INFO "__dma_client_find_mem: LT dst_addr=0x%p this node's dst_addr=0x%p\n",
                       pdmamem->dma_dst_addr, tnode->dma_mem.dma_dst_addr);
#endif
                if( (tnode->dma_mem.dma_src_addr == pdmamem->dma_src_addr)
                 && (tnode->dma_mem.dma_dst_addr == pdmamem->dma_dst_addr) )
                { //found the client's node with the matching dma memory
                    ptrmem = &(tnode->dma_mem);
                }
            } //ENDFOR searching through this client's nodes
            st = st + 1;
        }
        else if((this_client->dma_st_node_start != NULL) && (st == 1)) 
        {
            start_node = this_client->dma_st_node_start;
            // Search through all of this matching client's sec_dma_node_t(s)
            // examining each sec_dma_node_t's sec_dma_mem_t dma_dst_addr
            for (tnode = start_node; (tnode != NULL) && (ptrmem == NULL); tnode = tnode->next)
            {
#ifdef DEBUG_DMA_CLIENT_FIND_MEM
                printk(KERN_INFO "__dma_client_find_mem: ST src_addr=0x%p this node's src_addr=0x%p\n",
                       pdmamem->dma_src_addr, tnode->dma_mem.dma_src_addr);
                printk(KERN_INFO "__dma_client_find_mem: ST dst_addr=0x%p this node's dst_addr=0x%p\n",
                       pdmamem->dma_dst_addr, tnode->dma_mem.dma_dst_addr);
#endif
                if( (tnode->dma_mem.dma_src_addr == pdmamem->dma_src_addr)
                 && (tnode->dma_mem.dma_dst_addr == pdmamem->dma_dst_addr) )
                { //found the client's node with the matching dma memory
                    ptrmem = &(tnode->dma_mem);
                }
            } //ENDFOR searching through this client's nodes
            st = st + 1;
        }
        else
        {
            st = st + 1;
        }
    } //ENDWHILE

#ifdef DEBUG_DMA_CLIENT_FIND_MEM
    if(ptrmem == NULL)
    {
        printk(KERN_INFO "__dma_client_find_mem: matching addresses not found\n");
    }
    else
    {
        printk(KERN_INFO "__dma_client_find_mem: sec_dma_mem_t is at 0x%p\n", ptrmem);
    }
#endif

exit:
    return ptrmem;
} //ENDPROC __dma_client_find_mem


//----------------------------------------------------------------------------
// __alloc_dma_client
//
// Allocates new structure ofr a client and zeroes all entries out.
//----------------------------------------------------------------------------
static sec_dma_client_t * __alloc_dma_client(void)
{
    sec_dma_client_t * new_client = OS_ALLOC(sizeof(sec_dma_client_t));

    if (new_client == NULL)
    {
        SEC_ERROR("FATAL ERROR: failed to allocate space for new client\n");
        goto exit;
    }

    memset(new_client, 0x0, sizeof(sec_dma_client_t));

exit:
    return new_client;
} //ENDPROC __alloc_dma_client


//----------------------------------------------------------------------------
// __dma_client_remove
//
// Removes DMA client entry from the list of all clients
//----------------------------------------------------------------------------
static sec_result_t __dma_client_remove(sec_dma_client_t * cur_client)
{
    if (cur_client->prev == NULL)
    {
        sec_dma_clients = cur_client->next;
    }
    else
    {
        cur_client->prev->next = cur_client->next;
    }

    if (cur_client->next)
    {
        cur_client->next->prev = cur_client->prev;
    }

    OS_FREE(cur_client);

    return SEC_SUCCESS;
}


//----------------------------------------------------------------------------
// __dma_client_get
//
// Returns DMA client structure for client with passed thread group id 'tgid'.
// Attempts first to find existing structure for the client. If structure
// is not found, new one is created and added to the list of all DMA clients.
//----------------------------------------------------------------------------
static sec_dma_client_t* __dma_client_get(unsigned int tgid)
{
    sec_dma_client_t * cur_client = __dma_client_find(tgid);

    // If client is not found - allocate new entry for a client and add to
    // the list of all clients
    if (cur_client == NULL)
    {
#ifdef DEBUG_DMA_CLIENT_GET
        printk(KERN_DEBUG "SEC adding tgid = %d\n",tgid);
#endif
        cur_client = __alloc_dma_client();
        if (cur_client == NULL)
        {
            goto end;
        }

        cur_client->tgid  = tgid;
        cur_client->next = sec_dma_clients;
        cur_client->prev = NULL;

        if (sec_dma_clients)
        {
            sec_dma_clients->prev = cur_client;
        }
        sec_dma_clients = cur_client;
    }

end:
    return cur_client;
} //ENDPROC __dma_client_get


//----------------------------------------------------------------------------
//  __remove_client_dma
//
// Removes DMA node entry for a specified client including its DMA pages
// and its DMA descriptor.
//----------------------------------------------------------------------------
static sec_result_t __remove_client_dma(sec_dma_client_t *client,
                                        sec_dma_mem_t *pdmamem)
{
    sec_dma_node_t       *tnode;
    sec_dma_node_t       *start_node;
    user_buf_t           *psrc;
    user_buf_t           *pdst;
    sec_dma_descriptor_t *phys_src_desc = NULL;
    sec_dma_descriptor_t *phys_dst_desc = NULL;
    sec_result_t          rc = SEC_FAIL;

    VERIFY( client != NULL, exit, rc, SEC_FAIL);
    VERIFY(pdmamem != NULL, exit, rc, SEC_FAIL);

    // Select the long or short term linked list (chain)
#ifdef DEBUG_REMOVE_CLIENT_DMA
    printk(KERN_INFO "__remove_client_dma: client->dma_lt_node_start =0x%p\n", client->dma_lt_node_start);
    printk(KERN_INFO "__remove_client_dma: client->dma_st_node_start =0x%p\n", client->dma_st_node_start);
    printk(KERN_INFO "__remove_client_dma: pdmamem->dma_chain =%d\n", pdmamem->dma_chain);
#endif

    start_node = client->dma_lt_node_start;
    if(pdmamem->dma_chain) start_node = client->dma_st_node_start;

    // Search through all of this matching client's long or short term nodes
    // examining each sec_dma_node_t's sec_dma_mem_t src and dst addresses
    for (tnode = start_node; tnode != NULL; tnode = tnode->next)
    {
        if( (tnode->dma_mem.dma_src_addr == pdmamem->dma_src_addr)
         && (tnode->dma_mem.dma_dst_addr == pdmamem->dma_dst_addr) )
        { //found the client's node with the matching dma memory
#ifdef DEBUG_REMOVE_CLIENT_DMA
            printk(KERN_INFO "__remove_client_dma: Found the client's node with the matching dma memory at 0x%p\n", tnode);
#endif
            if (tnode->prev == NULL)
            {
                if(pdmamem->dma_chain == SEC_DMA_DESC_LT)
                {
                    client->dma_lt_node_start = tnode->next;
                }
                else
                {
                    client->dma_st_node_start = tnode->next;
                }
            }
            else
            {
                tnode->prev->next = tnode->next;
            }

            if (tnode->next)
            {
                tnode->next->prev = tnode->prev;
            }

            // Free descriptor list, user buffer, then DMA node metadata
            switch (tnode->dma_mem.dma_type)
            {
              case SEC_SMD_TO_DMA:
                  phys_dst_desc = tnode->dma_mem.dma_info.dma_desc;
                  pdst = &(tnode->dma_mem.dma_info.dst);
                  sec_kernel_free_descriptor_list(phys_dst_desc);
                  sec_kernel_user_buf_unlock( pdst );
                  OS_FREE(tnode);
                  rc = SEC_SUCCESS;
              break;

              case SEC_DMA_TO_SMD:
                  phys_src_desc = tnode->dma_mem.dma_info.dma_desc;
                  psrc = &(tnode->dma_mem.dma_info.src);
                  sec_kernel_free_descriptor_list(phys_src_desc);
                  sec_kernel_user_buf_unlock( psrc );
                  OS_FREE(tnode);
                  rc = SEC_SUCCESS;
              break;

              case SEC_DMA_TO_DMA:
                  phys_src_desc = tnode->dma_mem.dma_info.dma_desc;
                  psrc = &(tnode->dma_mem.dma_info.src);
                  pdst = &(tnode->dma_mem.dma_info.dst);
                  sec_kernel_free_descriptor_list(phys_src_desc);
                  sec_kernel_user_buf_unlock( psrc );
                  sec_kernel_user_buf_unlock( pdst );
                  OS_FREE(tnode);
                  rc = SEC_SUCCESS;
              break;
              case SEC_SMD_TO_SMD:
                  OS_FREE(tnode);
                  rc = SEC_SUCCESS;
              break;
              default:
                  printk(KERN_INFO "Invalid source-destination memory type combination\n");
                  rc = SEC_INVALID_INPUT;
            } //ENDSWITCH
        }//ENDIF found the client's node with the matching dma memory
    }//ENDFOR searching through the long or short term DMA node chain

exit:
    return rc;
}

//----------------------------------------------------------------------------
// Interface functions
//----------------------------------------------------------------------------

//----------------------------------------------------------------------------
// dma_tracker_find_client
// Searches the client list for a matching tgid
//----------------------------------------------------------------------------
sec_dma_client_t* dma_tracker_find_client(unsigned int tgid)
{
    sec_dma_client_t *client;

    SEMA_DMA_LOCK;
    client = __dma_client_find(tgid);
    SEMA_DMA_UNLOCK;
    return client;
}


//----------------------------------------------------------------------------
// dma_tracker_verify
// Searches the DMA client list for a matching tgid and memory
// If found then the memory has associated DMA descriptors
//----------------------------------------------------------------------------
sec_dma_mem_t* dma_tracker_verify(sec_dma_mem_t *pdmamem)
{
    sec_dma_mem_t *ptrmem = NULL;

    SEMA_DMA_LOCK;
    ptrmem = __dma_client_find_mem(pdmamem);
    SEMA_DMA_UNLOCK;
    return ptrmem;
}


//----------------------------------------------------------------------------
// dma_tracker_add_node
//
// Adds new DMA node entry to either a client's short or long term node chain
// with process thread group identifier sec_dma_client_t->tgid.  
//
// This is where all of the stuff that sec_kernel_get_dst_dma used to do
// needs to be done.
// TODO: This needs update for twin chains and DMA types
//----------------------------------------------------------------------------
sec_result_t dma_tracker_add_node(unsigned int tgid, sec_dma_mem_t *pdmamem)
{
    sec_dma_client_t     *client   = NULL;
    sec_dma_node_t       *dma_node = NULL;
    sec_dma_descriptor_t *phys_desc = NULL;
    sec_dma_mem_t        *pdmamem_found = NULL;
    sec_fw_cmd_t          cmd;
    sec_dma_type_t        dma_type;
    uint32_t              block_size;
    uint32_t              TX;
    uint32_t              RX;
    user_buf_t           *psrc;
    user_buf_t           *pdst;
    sec_result_t          rc = SEC_SUCCESS;

    SEMA_DMA_LOCK;

    if(pdmamem == NULL)
    {
        rc = SEC_NULL_POINTER;
        goto unlock;
    }

#ifdef DEBUG_DMA_ADD_NODE
    printk(KERN_INFO "\ndma_tracker_add_node: pdmamem is at 0x%p\n",pdmamem);
    printk(KERN_INFO "dma_tracker_add_node: At beginning\n");
    show_dma_mem(pdmamem);
#endif

    if(pdmamem->dma_dst_addr == NULL)
    {
        printk(KERN_INFO "dma_tracker_add_node: pdmamem->dma_dst_addr == NULL\n");
        rc = SEC_INVALID_INPUT;
        goto unlock;
    }

    if(pdmamem->dma_src_addr == NULL)
    {
        printk(KERN_INFO "dma_tracker_add_node: pdmamem->dma_src_addr == NULL\n");
        rc = SEC_INVALID_INPUT;
        goto unlock;
    }

    // Retrieving the sec_dma_client_t structure from the linked list of
    // sec_dma_client_t structures that has the matching thread group ID (tgid)
    client = __dma_client_get(tgid);
#ifdef DEBUG_DMA_ADD_NODE
    printk(KERN_INFO "dma_tracker_add_node: client = 0x%p\n",client);
#endif
    if( client == NULL )
    {
        rc = SEC_DMA_COULD_NOT_FIND_CLIENT;
        goto exit;
    }

    // Check that there isn't already a matching node.
    rc = SEC_SUCCESS;
    pdmamem_found = __dma_client_find_mem(pdmamem);
    if(pdmamem_found != NULL) goto exit;

    // There isn't an existing matching node, so create one.
    dma_node = OS_ALLOC(sizeof(sec_dma_node_t));
    if (dma_node == NULL)
    {
        printk(KERN_INFO "dma_tracker_add_node: FATAL: Failed to allocate memory for new DMA node\n");
        rc = SEC_OUT_OF_MEMORY;
        goto unlock;
    }
    OS_MEMSET( dma_node, 0, sizeof(sec_dma_node_t));
#ifdef DEBUG_DMA_ADD_NODE
    printk(KERN_INFO "dma_tracker_add_node: allocated dma_node at 0x%p\n",dma_node);
#endif

    cmd = pdmamem->cmd;
    dma_type = pdmamem->dma_type;

    // Add this new sec_dma_node_t to this client's
    // linked list of sec_dma_node_t structures
    dma_node->dma_mem.cmd = cmd;
    dma_node->dma_mem.dma_type = dma_type;
    dma_node->dma_mem.dma_chain = pdmamem->dma_chain;
    dma_node->dma_mem.dma_size = pdmamem->dma_size;
    dma_node->dma_mem.dma_src_addr = pdmamem->dma_src_addr;
    dma_node->dma_mem.dma_dst_addr = pdmamem->dma_dst_addr;

    // Initialize block_size, TX, and RX
    rc = dma_crypt_prepare( cmd, &block_size, &TX, &RX);
    if ( rc != SEC_SUCCESS )
    {
        printk(KERN_INFO "dma_tracker_add_node: dma_crypt_prepare failed 0x%04x\n", (unsigned short)rc);
        goto exit;
    }
    
    // SMD to SMD does not use the "user pages"
    psrc = &(dma_node->dma_mem.dma_info.src);
    pdst = &(dma_node->dma_mem.dma_info.dst);

#ifdef DEBUG_DMA_ADD_NODE
    printk(KERN_INFO "dma_tracker_add_node: psrc = 0x%p\n",psrc);
    printk(KERN_INFO "dma_tracker_add_node: pdst = 0x%p\n",pdst);
#endif
    if((psrc == NULL) || (pdst == NULL))
    {
        printk(KERN_INFO "dma_tracker_add_node: user_buf_t pointers at psrc = 0x%p pdst = 0x%p are NULL\n", psrc, pdst);
        rc = SEC_NULL_POINTER;
        goto exit;
    }

    switch(dma_type)
    {
      case SEC_SMD_TO_DMA:
#ifdef DEBUG_DMA_ADD_NODE
        printk(KERN_INFO "\n========= SMD TO DMA =========\n");
#endif
        if( dma_node->dma_mem.dma_dst_addr == NULL )
        {
            rc = SEC_INVALID_INPUT;
            goto exit;
        }
        if (((uint32_t)(dma_node->dma_mem.dma_dst_addr) & 0x3) == 0)
        {
            rc = sec_kernel_user_buf_lock( pdst,
                            (sec_address_t)(dma_node->dma_mem.dma_dst_addr),
                            dma_node->dma_mem.dma_size,
                            USER_BUF_RW);
            if (rc != SEC_SUCCESS) goto exit; 
        }
        else
        {
            rc = SEC_DMA_DST_NOT_DWORD_ALIGNED;
            goto exit;
        }
        break;

      case SEC_DMA_TO_SMD:
#ifdef DEBUG_DMA_ADD_NODE
        printk(KERN_INFO "\n========= DMA TO SMD =========\n");
#endif
        if( dma_node->dma_mem.dma_src_addr == NULL )
        {
            rc = SEC_INVALID_INPUT;
            goto exit;
        }
        if (((uint32_t)(dma_node->dma_mem.dma_src_addr) & 0x3) == 0)
        {
            rc = sec_kernel_user_buf_lock( psrc,
                            (sec_address_t)(dma_node->dma_mem.dma_src_addr),
                            dma_node->dma_mem.dma_size,
                            USER_BUF_RW);
            if (rc != SEC_SUCCESS) goto exit; 
        }
        else
        {
            rc = SEC_DMA_SRC_NOT_DWORD_ALIGNED;
            goto exit;
        }
        break;

      case SEC_DMA_TO_DMA:
#ifdef DEBUG_DMA_ADD_NODE
        printk(KERN_INFO "\n========= dma_tracker_add_node: DMA TO DMA =========\n");
#endif
        if( dma_node->dma_mem.dma_src_addr == NULL )
        {
            rc = SEC_INVALID_INPUT;
            goto exit;
        }
        if( dma_node->dma_mem.dma_dst_addr == NULL )
        {
            rc = SEC_INVALID_INPUT;
            goto exit;
        }
        if (((uint32_t)(dma_node->dma_mem.dma_src_addr) & 0x3) == 0)
        {
            rc = sec_kernel_user_buf_lock( psrc,
                            (sec_address_t)(dma_node->dma_mem.dma_src_addr),
                            dma_node->dma_mem.dma_size,
                            USER_BUF_RW);
            if (rc != SEC_SUCCESS) goto exit; 
        }
        else
        {
            rc = SEC_DMA_SRC_NOT_DWORD_ALIGNED;
            goto exit;
        }

        if (((uint32_t)(dma_node->dma_mem.dma_dst_addr) & 0x3) == 0)
        {
            rc = sec_kernel_user_buf_lock( pdst,
                            (sec_address_t)(dma_node->dma_mem.dma_dst_addr),
                            dma_node->dma_mem.dma_size,
                            USER_BUF_RW);
            if (rc != SEC_SUCCESS)
            {
                sec_kernel_user_buf_unlock( psrc );
                goto exit;
            }
        }
        else
        {
            sec_kernel_user_buf_unlock( psrc );
            rc = SEC_DMA_DST_NOT_DWORD_ALIGNED;
            goto exit;
        }
        break;
      case SEC_SMD_TO_SMD:
        {
            sec_dma_descriptor_t   *head = NULL;    // Head of descriptor linked list
            sec_dma_descriptor_t   *tail = NULL;    // Tail of descriptor linked list
            uint32_t                flags=0;
            uint32_t size;
            sec_address_t smdsrc;
            sec_address_t smddst;

            // Source and destination linked-list mode are disabled for SMD to SMD
            if (cmd == IPC_ARC4_ENCRYPT_DECRYPT_DATA)
            {
                flags = SEC_DMA_STF_FLAGS_ARC4 | SEC_DMA_FLAG_DST_INT | SEC_DMA_FLAG_TERM; 
            }
            else
            {// SEC_DMA_STF_FLAGS | SEC_DMA_FLAG_DST_INT | SEC_DMA_FLAG_TERM = 0x3c016088
                flags = SEC_DMA_STF_FLAGS | SEC_DMA_FLAG_DST_INT | SEC_DMA_FLAG_TERM;
            }

            size = dma_node->dma_mem.dma_size;
            smdsrc = (sec_address_t)(dma_node->dma_mem.dma_src_addr);
            smddst = (sec_address_t)(dma_node->dma_mem.dma_dst_addr);

            rc=add_dma_desc(&head, &tail, size, smdsrc, smddst, flags);

            if(rc != SEC_SUCCESS)
            {
                printk(KERN_INFO "\ndma_tracker_add_node: SMD to SMD add_dma_desc failed rc=0x%04x\n\n", (unsigned short)rc );
                goto exit;
            }

#ifdef DEBUG_DMA_ADD_NODE
            printk(KERN_INFO "dma_tracker_add_node: SMD to SMD head=0x%p\n",head);
            printk(KERN_INFO "dma_tracker_add_node: SMD to SMD tail=0x%p\n",tail);
#endif

            if (head != NULL)
            {
                dump_dma_list(head);
                phys_desc = head;
            }
            else
            {
                printk(KERN_INFO "dma_tracker_add_node: SMD to SMD head is NULL cannot continue!\n");
                goto exit;
            }
        }
        break;
      default:
        goto exit; // invalid DMA type cannot do anything
    }

#ifdef DEBUG_DMA_ADD_NODE
    if(dma_type != SEC_SMD_TO_SMD)
    {
        printk(KERN_INFO "\ndma_tracker_add_node: Just after sec_kernel_user_buf_lock\n");
        show_dma_mem(&(dma_node->dma_mem));
    }
#endif

    // Create DMA descriptors to perform the operation. The "head" to the
    // linked list of sec_dma_descriptor_t(s) is returned in phys_dst_desc cmd, &block_size, &TX, &RX

    if(dma_type != SEC_SMD_TO_SMD)
    {
        phys_desc = dma_tracker_map_vm_to_desc( psrc, pdst, dma_type, block_size, TX, RX, cmd);
    }
        
    if (phys_desc != NULL)
    {
        dma_node->dma_mem.dma_info.tgid = tgid;
        dma_node->dma_mem.dma_info.dma_desc = phys_desc;
        dma_node->dma_mem.dma_info.dma_flags       = phys_desc->dma_flags;
        dma_node->dma_mem.dma_info.next_descriptor = phys_desc->next;
        dma_node->dma_mem.dma_info.src_start       = phys_desc->src;
        dma_node->dma_mem.dma_info.dst_start       = phys_desc->dst;
        dma_node->dma_mem.dma_info.src_size        = phys_desc->size;
        dma_node->dma_mem.dma_info.dst_size        = phys_desc->size;
        pdmamem->dma_info.dma_desc = phys_desc;

#ifdef DEBUG_DMA_ADD_NODE
        printk(KERN_INFO "dma_tracker_add_node: Just after dma_tracker_map_vm_to_desc\n");
        show_dma_mem(&(dma_node->dma_mem));
#endif
    }
    else
    {
        rc = SEC_DMA_MAP_VM_TO_DESC_FAILED;
        printk(KERN_INFO "dma_tracker_add_node: dma_tracker_map_vm_to_desc FAILED\n");
        goto exit;
    }

    // With the dma_node initialized add it to the client DMA node list
    if(pdmamem->dma_chain == SEC_DMA_DESC_LT)
    {
        // Long Term DMA node list
#ifdef DEBUG_DMA_ADD_NODE
        printk(KERN_INFO "dma_tracker_add_node: dma_lt_node_start = 0x%p\n",
               client->dma_lt_node_start);
#endif
        dma_node->next = client->dma_lt_node_start;
        dma_node->prev   = NULL;
        if (client->dma_lt_node_start)
        {
            client->dma_lt_node_start->prev = dma_node;
        }
        client->dma_lt_node_start = dma_node;
#ifdef DEBUG_DMA_ADD_NODE
        printk(KERN_INFO "dma_tracker_add_node: dma_lt_node_start = 0x%p\n",
               client->dma_lt_node_start);
#endif
    }
    else
    {
        // Short Term DMA node list
#ifdef DEBUG_DMA_ADD_NODE
        printk(KERN_INFO "dma_tracker_add_node: dma_st_node_start = 0x%p\n",
               client->dma_st_node_start);
#endif
        dma_node->next = client->dma_st_node_start;
        dma_node->prev   = NULL;
        if (client->dma_st_node_start)
        {
            client->dma_st_node_start->prev = dma_node;
        }
        client->dma_st_node_start = dma_node;
#ifdef DEBUG_DMA_ADD_NODE
        printk(KERN_INFO "dma_tracker_add_node: dma_st_node_start = 0x%p\n",
               client->dma_st_node_start);
#endif
    }

exit:
    if (rc != SEC_SUCCESS)
    {
        printk(KERN_INFO "\ndma_tracker_add_node:failed rc=0x%04x\n\n", (unsigned short)rc );
        if (dma_node != NULL)
        {
#ifdef DEBUG_DMA_ADD_NODE
            printk(KERN_INFO "\ndma_tracker_add_node:freeing dma_node at 0x%p\n\n", dma_node );
#endif
            OS_FREE(dma_node);
        }
    }

unlock:
    SEMA_DMA_UNLOCK;
#ifdef DEBUG_DMA_ADD_NODE
    printk(KERN_INFO "\ndma_tracker_add_node:returning rc=0x%04x\n\n", (unsigned short)rc );
#endif
    return rc;
} //ENDPROC dma_tracker_add_node


//----------------------------------------------------------------------------
// dma_tracker_remove_node
//
// Removes memory entry 'mem' from the client identified by thread group
// identifier 'tgid'.  Note that only tracking information is removed.
// Actual memory represented by sec_contig_mem_t structure needs to be
// free-ed by the caller (if needed)
//----------------------------------------------------------------------------
sec_result_t dma_tracker_remove_node(unsigned int tgid, sec_dma_mem_t *pdmamem)
{
    sec_dma_client_t * client;
    sec_result_t   rc = SEC_SUCCESS;

    SEMA_DMA_LOCK;

    client = __dma_client_find(tgid);
    VERIFY(client != NULL, exit, rc, SEC_FAIL);

    rc = __remove_client_dma(client, pdmamem);

exit:
    SEMA_DMA_UNLOCK;
    return rc;
}


//----------------------------------------------------------------------------
// dma_tracker_remove_from_client_list
//
// Go through all existing clients and search for the memory entry "mem"
// and remove it. Note that only tracking information is removed.
// Actual memory represented by sec_contif_mem_t structure needs
// must be free-ed by the caller.
//----------------------------------------------------------------------------
sec_result_t dma_tracker_remove_from_client_list(sec_dma_mem_t *pdmamem)
{
    sec_dma_client_t * client;
    sec_result_t   rc = SEC_FAIL;

    SEMA_DMA_LOCK;

    client = sec_dma_clients;
    while (client != NULL)
    {
       rc = __remove_client_dma(client, pdmamem);
       if (rc == SEC_SUCCESS)
       {
           break;
       }
       client=client->next;
    }

    SEMA_DMA_UNLOCK;
    return rc;
}


//----------------------------------------------------------------------------
// dma_tracker_add_resources
//
// Adds firmware resource to a tracking system for the client
// with thread group id 'tgid'.
//----------------------------------------------------------------------------
sec_result_t dma_tracker_add_resources(unsigned int tgid, uint32_t resources)
{
    sec_dma_client_t * client = NULL;
    sec_result_t   rc     = SEC_SUCCESS;

    SEMA_DMA_LOCK;

    client = __dma_client_get(tgid);
    VERIFY(client != NULL, exit, rc, SEC_FAIL);

    client->resources |= resources;

exit:
    SEMA_DMA_UNLOCK;
    return rc;
}


//----------------------------------------------------------------------------
// dma_tracker_remove_resources
//
// Removes resources from a tracking system for the client
// identified by the thread group id 'tgid'.
//----------------------------------------------------------------------------
sec_result_t dma_tracker_remove_resources(unsigned int tgid, uint32_t resources)
{
    sec_dma_client_t * client;
    sec_result_t   rc = SEC_SUCCESS;

    SEMA_DMA_LOCK;
    client = __dma_client_find(tgid);
    VERIFY(client != NULL, exit, rc, SEC_FAIL);

    client->resources &= ~resources;

exit:
    SEMA_DMA_UNLOCK;
    return rc;
}


//----------------------------------------------------------------------------
// dma_tracker_client_add
//
// Creates new dma client entry for thread group id 'tgid'
// and adds it to the list of all clients.
//----------------------------------------------------------------------------
void dma_tracker_client_add(unsigned int tgid)
{
    SEMA_DMA_LOCK;

    // Note: __dma_client_get will attempt to find tgid in the list of clients
    // If such client does not yet exist it will create a client, add it to
    // the list of clients and return the entry. We can discard returned
    // entry here.
    __dma_client_get(tgid);

    SEMA_DMA_UNLOCK;
}


//----------------------------------------------------------------------------
// dma_tracker_garbage_collect
//
// This function goes through list of all dma clients in a tracking system
// and tries to determine whether each client is still alive or not.
//
// If any dma client is not alive, all tracking resources for that client
// are destroyed, client entry is destroyed, firmware resources held by the
// client are unlocked and memory represented by sec_contig_mem_t structure
// is unmapped and free-ed.
//
// NOTE: This function should be called from drivers 'close' handler.
// 'tgid' (current->tgid in 'close' handler) needs to be passed, since
// the client that currently makes a close call is still marked as being
// alive, yet we need to destroy all its memory/resource entries.
//----------------------------------------------------------------------------
void dma_tracker_garbage_collect(unsigned int tgid)
{
    sec_dma_client_t   *this_client;
    sec_dma_client_t   *client_to_remove;
    sec_dma_node_t     *this_dma_node;
    sec_dma_node_t     *next_dma_node;
    sec_result_t       rc;
    int i;

    SEMA_DMA_LOCK;
    rc = SEC_SUCCESS;
    this_client = sec_dma_clients;

    while (this_client != NULL)
    {
        client_to_remove = NULL;
        if ((this_client->tgid == tgid)
         || (current->state == TASK_DEAD))
        {
            if (this_client->resources != 0x0)
            {
                sec_unlock_resources(this_client->resources);
                rc = dma_tracker_remove_resources(this_client->tgid, this_client->resources);
                if(rc != SEC_SUCCESS)
                {
                    printk(KERN_INFO "tracker_garbage_collect: dma_tracker_remove_resources failed 0x%04x\n",rc);
                }
            }

            // Unreserve resources
            this_client->resources = 0x0;

            // Remove memory entries for this client (if any are present)
            this_dma_node = this_client->dma_lt_node_start;

            for(i=0; i<2; i++)
            {
                while (this_dma_node != NULL)
                {
                    next_dma_node = this_dma_node->next;
                    rc = __remove_client_dma(this_client, &(this_dma_node->dma_mem));
                    if(rc != SEC_SUCCESS)
                    {
                        printk(KERN_INFO "tracker_garbage_collect: __remove_client_dma failed 0x%04x\n",rc);
                    }
                    this_dma_node = next_dma_node;
                } //ENDWHILE freeing all the memory associated with this client

                if(i ==0)
                { //finished long term node chain so clean up short term
                    this_dma_node = this_client->dma_st_node_start;
                }
                else
                { // "i" should be 1 here so just make sure the while won't run
                    this_dma_node = NULL;
                }

            }//ENDFOR short and long term node chains
        }//ENDIF this is the client to delete

        // Cleaned up the memory so now remove the client
        client_to_remove = this_client;

        if(this_client != NULL) this_client=this_client->next;

        if (client_to_remove != NULL)
        {
            __dma_client_remove(client_to_remove);
        }
    } //ENDWHILE looking through the client list for the one to free

    SEMA_DMA_UNLOCK;
} //ENDPROC dma_tracker_garbage_collect


//----------------------------------------------------------------------------
// tracker_init
//
// Intializes sec dma client memory tracker
//----------------------------------------------------------------------------
void dma_tracker_init(void)
{
    SEMA_DMA_INIT;
    sec_dma_clients = NULL;
    printk(KERN_INFO "dma_tracker_init: initialized\n");
}

//----------------------------------------------------------------------------
// tracker_deinit
//
// Deinitializes sec dma client memory tracker
//----------------------------------------------------------------------------
void dma_tracker_deinit(void)
{
    // Nothing to do for now. This function is called at module unload time
    // Before module is unloaded OS makes sure that no one is using sec
    // driver anymore, so client list should be empty
}
