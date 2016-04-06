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

#ifndef __SEC_PM_H__
#define __SEC_PM_H__

#include <linux/spinlock.h>
#include <linux/pm.h>

#include "sec_common_types.h"  // For sec_fw_load_t


//-----------------------------------------------------------------------------
// D A T A   T Y P E S
//-----------------------------------------------------------------------------

typedef enum {
    SEC_PM_RUNNING = 0x0,
    SEC_PM_SUSPEND,
    SEC_PM_RESUME
} sec_pm_state_t;       /* Represents the power state the sec kernel module is
                           currently in */

//-----------------------------------------------------------------------------
// E X P O R T E D   G L O B A L S
//-----------------------------------------------------------------------------

extern sec_pm_state_t sec_pm_state;         /* Power state tracking */
extern spinlock_t     sec_ioctl_state_lock; /* Gates IOCTL for PM */
extern int            sec_ioctl_ref_count;

//-----------------------------------------------------------------------------
// I N L I N E   F U N C T I O N S   /   M A C R O S
//-----------------------------------------------------------------------------

#define SEC_ICEPM_DRIVER_NAME   "sec"

//-----------------------------------------------------------------------------
// sec_pm_get_ioctl
//
// The following inline increments the IOCTL's reference counter. This counter
// is used to ensure commands are present when suspend is requested.
//-----------------------------------------------------------------------------
static inline sec_result_t sec_pm_get_ioctl(void)
{
    sec_result_t rc = SEC_SUCCESS;

    spin_lock(&sec_ioctl_state_lock);
    if (sec_ioctl_ref_count == -1)
        rc = SEC_FAIL;
    else
        sec_ioctl_ref_count++;
    spin_unlock(&sec_ioctl_state_lock);
    return rc;
}

//-----------------------------------------------------------------------------
// sec_pm_put_ioctl
//
// The following macro decremented the IOCTL reference counter. This should
// be called when the IOCTL request is complete.
//-----------------------------------------------------------------------------
#define sec_pm_put_ioctl()                                                  \
do {                                                                        \
    spin_lock(&sec_ioctl_state_lock);                                       \
    sec_ioctl_ref_count--;                                                  \
    spin_unlock(&sec_ioctl_state_lock);                                     \
} while (0)

//-----------------------------------------------------------------------------
// F U N C T I O N   P R O T O T Y P E S
//-----------------------------------------------------------------------------
sec_result_t sec_pm_suspend_fw_reload(void);
sec_result_t sec_pm_store_fw_image(sec_fw_load_t *);
sec_result_t sec_pm_register(void);
void sec_pm_unregister(void);
void sec_pm_cleanup_action_list(void);

int sec_pm_suspend_handler(void);
int sec_pm_resume_handler(void);

#endif /* __SEC_PM_H__ */
