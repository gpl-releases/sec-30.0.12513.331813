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
#include <linux/kernel.h>
#include <asm/cacheflush.h>
#include "sec_tracker.h"

// Link list of clients
static sec_client_t * sec_clients;

// Semaphore used for avoiding race conditions when operating on
// sec_clients global
static struct semaphore tracker_sema;

// Helpful macros to lock/unlock/init global semaphore
#define SEMA_INIT   sema_init(&tracker_sema, 1);
#define SEMA_LOCK   down(&tracker_sema);
#define SEMA_UNLOCK up(&tracker_sema);

//----------------------------------------------------------------------------
// Helper functions
//----------------------------------------------------------------------------

//----------------------------------------------------------------------------
// __client_find
//
// Searches for client with passed 'tgid' and returns the structure
// representing the client. Returns NULL if client with provided 'tgid' is
// not found.
//----------------------------------------------------------------------------
static sec_client_t* __client_find(unsigned int tgid)
{
    sec_client_t *tmp;

    for (tmp = sec_clients; tmp != NULL; tmp =  tmp->next)
    {
        if (tmp->tgid == tgid)
        {
            break;
        }
    }

    return tmp;
}


//----------------------------------------------------------------------------
// __alloc_client
//
// Allocates new structure ofr a client and zeroes all entries out.
//----------------------------------------------------------------------------
static sec_client_t * __alloc_client(void)
{
    sec_client_t * new_client = OS_ALLOC(sizeof(sec_client_t));

    if (new_client == NULL)
    {
        SEC_ERROR("FATAL ERROR: failed to allocate space for new client\n");
        goto exit;
    }

    memset(new_client, 0x0, sizeof(sec_client_t));

exit:
    return new_client;
}


//----------------------------------------------------------------------------
// __client_find_mem
//
// Searches for client with passed 'pmem->tgid' and 'pmem->paddr'.
// If a matching client with a matching sec_mem_node_t is found
// this function returns the pointer to the tracker's copy that
// calling kernel function will use, else it returns NULL.
//----------------------------------------------------------------------------
static sec_contig_mem_t * __client_find_mem(sec_contig_mem_t *pmem)
{
    sec_client_t   *tmp;
    sec_mem_node_t *tnode;
    sec_contig_mem_t *ptrmem;
    unsigned int tgid;
    unsigned int paddr;

    tmp = NULL;
    tnode = NULL;
    ptrmem = NULL;
    if(pmem == NULL) goto exit;

    // Trust only the physical address
    paddr= pmem->paddr;

    // Search through all the clients
    tgid = (unsigned int)(current->tgid);
    tmp = __client_find(tgid);
    if(tmp == NULL)
    {
        printk(KERN_INFO "__client_find_mem: __client_find could not find %d tgid\n",tgid);
        goto exit;
    } //ENDIF client was NOT found

    // Search through all of this matching client's sec_mem_node_t(s)
    // examining each sec_mem_node_t's sec_contig_mem_t paddr
    for (tnode = tmp->mem_head; tnode != NULL; tnode = tnode->next)
    {
#ifdef DEBUG_CLIENT_FIND_MEM
        printk(KERN_INFO "__client_find_mem: mem=0x%08x tnode->mem.paddr=0x%08x\n", paddr, tnode->mem.paddr);
#endif
        if (tnode->mem.paddr == paddr)
        { //found the client's node with the matching memory
          //thus we know __sec_alloc_mem allocated the memory
            ptrmem = &(tnode->mem);
            break;
        }
    } //ENDFOR searching through all the physical memory
      //addresses associated with this thread group ID
    if(ptrmem == NULL)
    {
        printk(KERN_INFO "__client_find_mem: could not find mem matching phys addr 0x%08x\n", paddr);
    }
exit:
    return ptrmem;
}


//----------------------------------------------------------------------------
// __client_find_page
//
// Searches for client with passed 'tgid'. Uses the vm page address and size
// that is available via mmap comparing the client physical memory page with
// the pgoff and size. If a matching client with a matching sec_mem_node_t is
// found this function returns the pointer to the tracker's copy that calling
// kernel function will use, else it returns NULL. This guarantees the address
// belongs to the client and the client isn't trying to get at some other memory.
//----------------------------------------------------------------------------
static sec_contig_mem_t* __client_find_page(unsigned int tgid, unsigned int pgoff, unsigned int size)
{
    sec_client_t   *tmp;
    sec_mem_node_t *tnode;
    sec_contig_mem_t *ptrmem;

    tmp = NULL;
    tnode = NULL;
    ptrmem = NULL;

    // Search through all the clients
    tmp = __client_find(tgid);
    if(tmp == NULL) goto exit;

    // Search through all of this matching client's sec_mem_node_t(s)
    // examining each sec_mem_node_t's sec_contig_mem_t paddr
    for (tnode = tmp->mem_head; tnode != NULL; tnode = tnode->next)
    {
        if ((pgoff == (tnode->mem.paddr >> PAGE_SHIFT)) &&
            (size <= (tnode->mem.size + PAGE_SIZE)))
        { //found the client's node with the matching memory page
          //thus we know __sec_alloc_mem allocated the memory
            ptrmem = &(tnode->mem);
            break;
        }
    } //ENDFOR searching through all the physical memory
      // addresses associated with this thread group ID

exit:
    return ptrmem;
}


//----------------------------------------------------------------------------
// __client_get
//
// Returns client structure for client with passed thread group id 'tgid'.
// Attempts first to find existing structure for the client. If structure
// is not found, new one is created and added to the list of all clients.
//----------------------------------------------------------------------------
static sec_client_t * __client_get(unsigned int tgid)
{
    sec_client_t * cur_client = __client_find(tgid);
    int i;
    // If client is not found - allocate new entry for a client and add to
    // the list of all clients
    if (cur_client == NULL)
    {
#ifdef DEBUG_CLIENT_GET
        printk(KERN_DEBUG "SEC adding tgid = %d\n",tgid);
#endif
        cur_client = __alloc_client();
        if (cur_client == NULL)
        {
            goto end;
        }

        cur_client->tgid  = tgid;
        cur_client->next = sec_clients;
        cur_client->prev = NULL;
        for (i = 0; i < SEC_NUM_CONTEXTS; i++)
        {
            cur_client->contexts[SEC_MAC_CONTEXT ][i]  = 0;
            cur_client->contexts[SEC_DH_CONTEXT  ][i]  = 0;
            cur_client->contexts[SEC_HASH_CONTEXT][i]  = 0;
        }
        if (sec_clients)
        {
            sec_clients->prev = cur_client;
        }
        sec_clients = cur_client;
    }

end:
    return cur_client;
}


//----------------------------------------------------------------------------
// __client_remove
//
// Removes client entry from the list of all clients
//----------------------------------------------------------------------------
static sec_result_t __client_remove(sec_client_t * cur_client)
{
    if (cur_client->prev == NULL)
    {
        sec_clients = cur_client->next;
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
//  __remove_client_mem
//
// Removes memory entry for a specified client. Note that only tracking
// information about the memory is destroyed -- actual memory (represented by
// sec_contig_mem_t structure) needs to be free-ed by the caller.
//----------------------------------------------------------------------------
static sec_result_t __remove_client_mem(sec_client_t     * client,
                                        sec_contig_mem_t * mem)
{
    sec_mem_node_t * tmp;
    sec_result_t     rc = SEC_FAIL;

    VERIFY(client != NULL, exit, rc, SEC_FAIL);
    VERIFY(   mem != NULL, exit, rc, SEC_FAIL);

    for (tmp = client->mem_head; tmp != NULL; tmp = tmp->next)
    {
        if (tmp->mem.paddr == mem->paddr)
        {
            if (tmp->prev == NULL)
            {
                client->mem_head = tmp->next;
            }
            else
            {
                tmp->prev->next = tmp->next;

            }

            if (tmp->next)
            {
                tmp->next->prev = tmp->prev;
            }

            OS_FREE(tmp);
            rc = SEC_SUCCESS;
            break;
        }
    }

exit:
    return rc;
}

//----------------------------------------------------------------------------
// Interface functions
//----------------------------------------------------------------------------

//----------------------------------------------------------------------------
// tracker_verify_mem
// Searches the client list for a matching tgid and physical memory
// If found then the physical memory was allocated and mapped by sec.
//----------------------------------------------------------------------------
sec_contig_mem_t* tracker_verify_mem(sec_contig_mem_t *mem)
{
    sec_contig_mem_t * ptrmem;

    SEMA_LOCK;
    ptrmem = __client_find_mem(mem);
    SEMA_UNLOCK;
    return ptrmem;
}

//----------------------------------------------------------------------------
// tracker_verify_page
// Searches the client list for a matching tgid and physical memory page
// If found then the physical memory page was allocated and mapped by sec.
//----------------------------------------------------------------------------
sec_contig_mem_t* tracker_verify_page(unsigned int tgid, unsigned int pgoff, unsigned int size)
{
    sec_contig_mem_t * ptrmem;

    SEMA_LOCK;
    ptrmem = __client_find_page(tgid, pgoff, size);
    SEMA_UNLOCK;
    return ptrmem;
}

//----------------------------------------------------------------------------
// tracker_find_client
// Searches the client list for a matching tgid
//----------------------------------------------------------------------------
sec_client_t* tracker_find_client(unsigned int tgid)
{
    sec_client_t *client;

    SEMA_LOCK;
    client = __client_find(tgid);
    SEMA_UNLOCK;
    return client;
}

//----------------------------------------------------------------------------
// tracker_add_mem
//
// Adds new memory entry to a clients structure for client with process thread
// group identifier mem->tgid. Note that this call only adds memory entry into
// a tracking system. Actual memory represented by sec_contig_mem_t structure
// needs to be allocated by the caller prior to calling this function.
//----------------------------------------------------------------------------
sec_result_t tracker_add_mem(unsigned int tgid, sec_contig_mem_t * mem)
{
    sec_client_t   * client   = NULL;
    sec_mem_node_t * mem_node = NULL;
    sec_result_t     rc       = SEC_SUCCESS;

    SEMA_LOCK;

    mem_node = OS_ALLOC(sizeof(sec_mem_node_t));
    if (mem_node == NULL)
    {
        SEC_ERROR("FATAL: Failed to allocate memory for new mem node\n");
        rc = SEC_FAIL;
        goto exit;
    }

    // Retrieving the sec_client_t structure from the linked list of
    // sec_client_t structures that has the matching thread group ID (tgid)
    client = __client_get(tgid);
    VERIFY(client != NULL, exit, rc, SEC_FAIL);

    memcpy(&mem_node->mem, mem, sizeof(sec_contig_mem_t));

    mem_node->next   = client->mem_head;
    mem_node->prev   = NULL;

    // Add this new sec_mem_node_t to this client's
    // linked list of sec_mem_node_t structures
    if (client->mem_head)
    {
        client->mem_head->prev = mem_node;
    }

    client->mem_head = mem_node;

exit:
    if (rc != SEC_SUCCESS)
    {
        if (mem_node != NULL)
        {
            OS_FREE(mem_node);
        }
    }

    SEMA_UNLOCK;

    return rc;
}



//----------------------------------------------------------------------------
// tracker_remove_mem
//
// Removes memory entry 'mem' from the client identified by thread group
// identifier 'tgid'.  Note that only tracking information is removed.
// Actual memory represented by sec_contig_mem_t structure needs to be
// free-ed by the caller (if needed)
//----------------------------------------------------------------------------
sec_result_t tracker_remove_mem(unsigned int tgid, sec_contig_mem_t * mem)
{
    sec_client_t * client;
    sec_result_t   rc = SEC_SUCCESS;

    SEMA_LOCK;

    client = __client_find(tgid);
    VERIFY(client != NULL, exit, rc, SEC_FAIL);

    rc = __remove_client_mem(client, mem);

exit:
    SEMA_UNLOCK;
    return rc;
}



//----------------------------------------------------------------------------
// tracker_remove_mem_from_client_list
//
// Go through all existing clients and search for the memory entry "mem"
// and remove it. Note that only tracking information is removed.
// Actual memory represented by sec_contif_mem_t structure needs
// must be free-ed by the caller.
//----------------------------------------------------------------------------
sec_result_t tracker_remove_mem_from_client_list(sec_contig_mem_t * mem)
{
    sec_client_t * client;
    sec_result_t   rc = SEC_FAIL;

    SEMA_LOCK;

    client = sec_clients;
    while (client != NULL)
    {
       rc = __remove_client_mem(client, mem);
       if (rc == SEC_SUCCESS)
       {
           break;
       }
       client=client->next;
    }

    SEMA_UNLOCK;
    return rc;
}



//----------------------------------------------------------------------------
// tracker_add_resources
//
// Adds firmware resource to a tracking system for the client
// with thread group id 'tgid'.
//----------------------------------------------------------------------------
sec_result_t tracker_add_resources(unsigned int tgid, uint32_t resources)
{
    sec_client_t * client = NULL;
    sec_result_t   rc     = SEC_SUCCESS;

    SEMA_LOCK;

    client = __client_get(tgid);
    VERIFY(client != NULL, exit, rc, SEC_FAIL);

    client->resources |= resources;

exit:
    SEMA_UNLOCK;
    return rc;
}

//----------------------------------------------------------------------------
// tracker_remove_resources
//
// Removes resources from a tracking system for the client
// identified by the thread group id 'tgid'.
//----------------------------------------------------------------------------
sec_result_t tracker_remove_resources(unsigned int tgid, uint32_t resources)
{
    sec_client_t * client;
    sec_result_t   rc = SEC_SUCCESS;

    SEMA_LOCK;
    client = __client_find(tgid);
    VERIFY(client != NULL, exit, rc, SEC_FAIL);

    client->resources &= ~resources;

exit:
    SEMA_UNLOCK;
    return rc;
}

//----------------------------------------------------------------------------
// tracker_add_eau_lock
//      
// Adds EAU_LOCK to a tracking system for the client
// with thread group id 'tgid'.
//----------------------------------------------------------------------------
sec_result_t tracker_add_eau_lock(unsigned int tgid)
{
    sec_client_t * client = NULL;
    sec_result_t   rc     = SEC_SUCCESS;
         
    SEMA_LOCK;
           
    client = __client_get(tgid);
    VERIFY(client != NULL, exit, rc, SEC_FAIL);
    
    client->eau_lock=1;
        
exit:   
    SEMA_UNLOCK;
    return rc; 
}           

//----------------------------------------------------------------------------
// tracker_remove_eau_lock
//
// Removes EAU_LOCK from a tracking system for the client
// identified by the thread group id 'tgid'.
//----------------------------------------------------------------------------
sec_result_t tracker_remove_eau_lock(unsigned int tgid)
{
    sec_client_t * client;
    sec_result_t   rc = SEC_SUCCESS;

    SEMA_LOCK;
    client = __client_find(tgid);
    VERIFY(client != NULL, exit, rc, SEC_FAIL);

    client->eau_lock=0;

exit:
    SEMA_UNLOCK;
    return rc;
}

//----------------------------------------------------------------------------
// tracker_add_context
//
// This function adds a context_id info for current seesion for
// thread group id 'tgid'.
//----------------------------------------------------------------------------
sec_result_t tracker_add_context(enum context_type type, unsigned int tgid,
				 uint32_t context_id)
{
    sec_client_t * client = NULL;
    sec_result_t   rc     = SEC_SUCCESS;

    SEMA_LOCK;

    client = __client_get(tgid);
    VERIFY(client != NULL, exit, rc, SEC_FAIL);
    VERIFY(client->contexts[type][context_id] == 0, exit, rc, SEC_FAIL);
    client->contexts[type][context_id] = 1;

exit:
    SEMA_UNLOCK;
    if((rc==SEC_FAIL) && (client->contexts[type][context_id] !=0))
    {
        printk(KERN_INFO "Thread is already running a %s session with the same"
               "context_id\n",
               type == SEC_MAC_CONTEXT  ? "mac"  :
               type == SEC_DH_CONTEXT   ? "dh"   :
               type == SEC_HASH_CONTEXT ? "hash" : "(unknown)");
    }
    return rc;
}

//----------------------------------------------------------------------------
// tracker_remove_context
//
// Removes a context_id from a tracking system for the client
// identified by the thread group id 'tgid'.
//----------------------------------------------------------------------------
sec_result_t tracker_remove_context(enum context_type type, unsigned int tgid,
                                    uint32_t context_id)
{
    sec_client_t * client;
    sec_result_t   rc = SEC_SUCCESS;

    SEMA_LOCK;
    client = __client_find(tgid);
    VERIFY(client != NULL, exit, rc, SEC_FAIL);
    client->contexts[type][context_id] = 0;

exit:
    SEMA_UNLOCK;
    return rc;
}

//----------------------------------------------------------------------------
// tracker_has_context
//
// Indicates whether the specified client tgid has the specified
// resource.
//----------------------------------------------------------------------------
bool tracker_has_context(enum context_type type, unsigned int tgid,
                         uint32_t context_id)
{
    sec_client_t * client;
    bool           ret = false;

    SEMA_LOCK;
    client = __client_find(tgid);
    if (client)
        ret = client->contexts[type][context_id];
    SEMA_UNLOCK;

    return ret;
}

//----------------------------------------------------------------------------
// tracker_garbage_collect
//
// This function goes through list of all clients in a tracking system and
// tries to determine whether each client is still alive or not.
//
// If any client is not alive, all tracking resources for that client
// are destroyed, client entry is destroyed, firmware resources held by the
// client are unlocked and memory represented by sec_contig_mem_t structure
// is unmapped and free-ed.
//
// Note that this function should be called from drivers 'close' handler.
// 'tgid' (current->tgid in 'close' handler) needs to be passed, since
// the client that currently makes a close call is still marked as being
// alive, yet we need to destroy all its memory/resource entries.
//----------------------------------------------------------------------------
void tracker_garbage_collect(unsigned int tgid)
{
    struct mm_struct   * mm;
    sec_client_t       * tmp;
    sec_client_t       * to_remove;
    sec_mem_node_t     * mem_node;
    sec_mem_node_t     * mem_nextnode;
    sec_result_t       rc;

    unsigned int offset;
    unsigned int size;
    unsigned int pg_size;
    unsigned int pg_aligned_base;
    unsigned long vaddr;
    int iret,i;

    SEMA_LOCK;
    rc = SEC_SUCCESS;
    mm = current->mm;
    tmp = sec_clients;
    while (tmp != NULL)
    {
        to_remove = NULL;
        if ((tmp->tgid == tgid)
         || (current->state == TASK_DEAD))
        {
            if (tmp->resources != 0x0)
            {
                sec_unlock_resources(tmp->resources);
                tracker_remove_resources(tmp->tgid, tmp->resources);
            }
            if(tmp->eau_lock)
            {
                free_eau_lock();
                tmp->eau_lock=0;
            }
            for (i = 0; i < SEC_NUM_CONTEXTS; i++)
            {
#define CLEAN_IF_IN_USE(type)                        \
                if (tmp->contexts[type][i])          \
                {                                    \
                    sec_release_context(type, i);    \
                    tmp->contexts[type][i] = 0;      \
                }

                CLEAN_IF_IN_USE(SEC_MAC_CONTEXT)
                CLEAN_IF_IN_USE(SEC_DH_CONTEXT)
                CLEAN_IF_IN_USE(SEC_HASH_CONTEXT)
#undef CLEAN_IF_IN_USE
            }
            // Unreserve resources
            tmp->resources = 0x0;

            // Remove memory entries for this client (if any are present)
            mem_node = tmp->mem_head;

            while (mem_node != NULL)
            {
                if (mem_node->mem.kernel_vaddr)
                {
                    if((mm != NULL)
                    && (current->state != TASK_DEAD)
                    && (mem_node->mem.mmap_count > 0)
                    && (mem_node->mem.user_vaddr != NULL)
                    && (mem_node->mem.size > 0))
                    {
                        size = mem_node->mem.size;
                        vaddr = (unsigned long)mem_node->mem.user_vaddr;
                        pg_size = PAGE_SIZE;
                        pg_aligned_base = (vaddr/pg_size)*pg_size;

                        //This is because munmap works only on pages
                        offset = vaddr - pg_aligned_base;
                        size = size + offset;
                        down_write(&mm->mmap_sem);
                        iret = do_munmap(mm, (unsigned long)pg_aligned_base, size);
                        up_write(&mm->mmap_sem);
                    }
                    if(g_fast_path)
                    {
                        set_pages_wb(virt_to_page((unsigned long)mem_node->mem.kernel_vaddr), (mem_node->mem.size >>PAGE_SHIFT));
                        free_pages((unsigned long)mem_node->mem.kernel_vaddr, get_order(mem_node->mem.size));
                    }
                    else
                    {
                        if(mem_node->mem.flags & SEC_CONTIG_FLAG_PAGE_ALLOC)
                            free_pages((unsigned long)mem_node->mem.kernel_vaddr, get_order(mem_node->mem.size));
                        else
                            OS_FREE(mem_node->mem.kernel_vaddr);
                        mem_node->mem.kernel_vaddr = NULL;
                    }
                }
                mem_nextnode = mem_node->next;
                rc = __remove_client_mem(tmp, &(mem_node->mem));
                if(rc != SEC_SUCCESS)
                {
                    printk(KERN_INFO "tracker_garbage_collect: __remove_client_mem failed 0x%04x\n",rc);
                }
                mem_node = mem_nextnode;
            } //ENDWHILE unmapping and freeing all the memory associated with this client

            to_remove = tmp;
        }//ENDIF this is the client to delete

        if(tmp != NULL) tmp=tmp->next;

        if (to_remove != NULL)
        {
            __client_remove(to_remove);
        }
    } //ENDWHILE looking through the client list for the one to free

    SEMA_UNLOCK;
}


//----------------------------------------------------------------------------
// tracker_client_add
//
// Creates new client entry for thread group id 'tgid'
// and adds it to the list of all clients.
//----------------------------------------------------------------------------
void tracker_client_add(unsigned int tgid)
{
    SEMA_LOCK;

    // Note: __client_get will attempt to find tgid in the list of clients
    // If such client does not yet exist it will create a client, add it to
    // the list of clients and return the entry. We can discard returned
    // entry here.
    __client_get(tgid);

    SEMA_UNLOCK;
}

//----------------------------------------------------------------------------
// tracker_init
//
// Intializes sec client memory tracker
//----------------------------------------------------------------------------
void tracker_init(void)
{
    SEMA_INIT;
    sec_clients = NULL;
}

//----------------------------------------------------------------------------
// tracker_deinit
//
// Deinitializes sec client memory tracker
//----------------------------------------------------------------------------
void tracker_deinit(void)
{
    // Nothing to do for now. This function is called at module unload time
    // Before module is unloaded OS makes sure that no one is using sec
    // driver anymore, so client list should be empty
}
