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
#include <linux/platform_device.h>
#include <linux/suspend.h>          // For suspend/hibernate notifiers

#include "icepm_drivers.h"          // For PM trace functionality

#include "sec_types.h"
#include "sec_kernel.h"
#include "sec_kernel_types.h"
#include "sec_common_types.h"

#include "sec_pm.h"
#include "sec_tdp.h"

//----------------------------------------------------------------------------
// For TDP, varioius SMD drivers are dependent on the sec driver to reload
// their FW at resume time.  This means sec must be suspended AFTER those
// drivers and resumed BEFORE them.
//
// Linux determines suspend/resume order of drivers based on the order in which
// their devices are registered.  PCI device registeration order is determined
// by the location of the devices in the bus topology (lower levels in
// the tree are registered first, upper levels last). Since all CE AV devices
// appear on the same bus (the AV bridge), the kernel's suspend/resume order is
// essentially random.
//
// LOGICAL DEPENDENCIES between drivers are normally worked around in ACPI
// device support, which we do not have. Instead, we work around the problem by
// registering each interdependent CE driver *twice*:
//   - A normal registration, as a PCI driver.
//   - And again as a platform device driver; at the same time we register a
//     "pseudo platform device".  Since this is done when the driver is loaded,
//     driver load order will determine platform device registration order and
//     hence platform device suspend/resume order.
// 
// The kernel suspends platform devices before PCI devices and resumes platform
// devices after PCI devices, so we are assured the platform callbacks will be
// invoked in the order we require. For this driver, both sets of callbacks
// will be invoked on suspend-to-RAM, in this order:
//
//      platform_suspend
//      pci_suspend
//      pci_resume
//      platform_resume
//----------------------------------------------------------------------------


//*****************************************************************************
// D E B U G G I N G
//*****************************************************************************
/* Debugging related macros */
#ifdef SEC_PCI_DEBUG

#define SEC_PCI_DPRINT(str, ...)                                             \
    printk(KERN_INFO "%s:%s:%d " str, __FILE__, __func__, __LINE__,          \
           ##__VA_ARGS__)

#define SEC_PCI_TRACE() SEC_PCI_DPRINT("TRACE\n") 

#define SEC_PCI_LOAD_INFO_DPRINT(load_info_ptr)                              \
    SEC_PCI_DPRINT("Load Info: id: 0x%08x -- Path: %s\n",                    \
            load_info_ptr->module_id, load_info_ptr->image_path)

#define SEC_PCI_RET_TRACE()                                                  \
    SEC_PCI_DPRINT("Returning: %d\n", rc)

#else /* SEC_PCI_DEBUG */
#define SEC_PCI_DPRINT(str, ...)
#define SEC_PCI_TRACE()
#define SEC_PCI_LOAD_INFO_DPRINT(load_info_ptr)
#define SEC_PCI_RET_TRACE()
#endif /* SEC_PCI_DEBUG */

//*****************************************************************************
//         P O W E R   E V E N T   N O T I F I C A T I O N S
//*****************************************************************************

//-----------------------------------------------------------------------------
// sec_notification_handler
//
// Function that we register for kernel power event notifications.
//
// During STR, the kernel sequence of operations is:
//      - send out PM_SUSPEND_PREPARE notifications
//      - freeze user-space threads
//      - call driver suspend functions
//      - get wake event
//      - call driver resume functions
//      - thaw user space
//      - send out PM_POST_SUSPEND notifications
//
// Kernel expects return of 0 on success, 1 on failure,
//-----------------------------------------------------------------------------
static int sec_notification_handler(
            struct notifier_block * nb,     // Block that was used to register
            unsigned long           type,   // Notification type
            void *                  ignore) // Always NULL -- ignore
{
    int rc = NOTIFY_OK;
    sec_pm_state_t save;

    switch (type)
    {
    case PM_SUSPEND_PREPARE:
        icepm_trace(KBUILD_MODNAME, "SUSPEND NOTIFICATION\n");
        // TODO: probably want to use a new flag or a new sec_pm_state value
        // to condition the FW load code, instead of saving/restoring the
        // current state.

        //CE2600 does not require reloading of firmwares as it does not go in reset.
        //During STR SEC CE2600 go in low power state c6. Firmware state stays as it is.
        if(gchip_info.host_device != PCI_DEVICE_CE2600)
        {
            save = sec_pm_state;
            sec_pm_state = SEC_PM_SUSPEND;
            if (SEC_SUCCESS != sec_pm_suspend_fw_reload())
            {
                SEC_ERROR("Could not reload all SEC FW images! Images will be "
                      "missing on resume.\n");
                // Or should we just return a failure?
            }
            sec_pm_state = save;
        }
        break;

    case PM_POST_SUSPEND:
        // System just resumed or error occurred during suspend.
        icepm_trace(KBUILD_MODNAME, "RESUME NOTIFICATION\n");
        sec_pm_cleanup_action_list();
        if(g_fast_path)
        {
            sec_peri_fw_cleanup_list();
        }
        break;

    default:
        // Hibernation (suspend-to-disk) not supported
        rc = NOTIFY_BAD;
    }

    return rc;
}


static struct notifier_block sec_notification_block =
{
    sec_notification_handler,   // Notification handler
    0,                          // Ignored when registering
    1000 /* TODO */             // Notifier chain is sorted in descending
                                //   order of this value
};

static bool registered_notifier = false;


//****************************************************************************
// DATA STUCTURES AND CALLBACKS FOR REGISTRATION AS A PCI DRIVER
//****************************************************************************

/* PCI device info for the SEC */
static DEFINE_PCI_DEVICE_TABLE(sec_pci_dev_id) = {
    { PCI_DEVICE(PCI_VENDOR_INTEL, PCI_DEVICE_SEC) },
    { PCI_DEVICE(PCI_VENDOR_INTEL, PCI_DEVICE_MEU) },
    {0} /* End of list */
};

struct pci_dev * sec_pci_dev = NULL;    // Stores addr of SEC PCI device


//-----------------------------------------------------------------------------
// sec_pci_probe
//
// This function is called whenever a PCI device is found that could be
// controlled by the SEC driver. At this time there can only be one, so that
// is all this driver supports.
// Return: 0 if this driver will control the device
//         Negative if this driver is not the correct one for this device
//-----------------------------------------------------------------------------
static int sec_pci_probe(struct pci_dev *dev, const struct pci_device_id * id)
{
    int rc = 0;

    SEC_PCI_DPRINT("Probe called: %d %d %d %d %d %d 0x%08X\n",
            id->vendor, id->device, id->subvendor, id->subdevice,
            id->class, id->class_mask, (unsigned int)(id->driver_data));

    /* Basic sanity check */
    if (id->vendor != PCI_VENDOR_INTEL)
    {
        SEC_ERROR(
                "ERROR: Received a probe for a device we should be handling\n");
        rc = -1;
        goto exit;
    }

    if ( id->device == PCI_DEVICE_SEC)
    {
        if (sec_pci_dev != NULL)
        {
            SEC_ERROR("ERROR: Received multiple probes of SEC device\n");
            rc = -1;
            goto exit;
        }

        /* Increment the PCI device reference counter */
        pci_dev_get(dev);
        /* Save the device info so we can use it in the PM code */
        sec_pci_dev = dev;
    }

exit:
    SEC_PCI_RET_TRACE();
    return rc;
}

//-----------------------------------------------------------------------------
// sec_pci_remove
//
// Handler for removing the PCI device. This should never happen, but just in
// case.
//-----------------------------------------------------------------------------
static void sec_pci_remove(struct pci_dev *dev)
{
    SEC_PCI_TRACE();
    
    if (dev == sec_pci_dev)
    {
        pci_dev_put(dev);
        sec_pci_dev = NULL;
    }
}

static int sec_pci_suspend(struct device *dev)
{
    struct pci_dev *pcidev = to_pci_dev(dev);

    icepm_trace(KBUILD_MODNAME, "PCI SUSPEND devid = %04x\n", pcidev->device);
    return 0;
}

static int sec_pci_resume(struct device *dev)
{
    struct pci_dev *pcidev = to_pci_dev(dev);

    icepm_trace(KBUILD_MODNAME, "PCI RESUME devid = %04x\n", pcidev->device);
    return 0;
}

static const struct dev_pm_ops pci_pm_ops =
{
    .suspend = sec_pci_suspend,
    .resume  = sec_pci_resume
};

static struct pci_driver sec_pci_driver =
{
    // .name **must** match the DRIVERS= entry if the firmware load rule in
    // /etc/udev/rules.d/??-sec-udev.rules
    .name = KBUILD_MODNAME,

    .id_table = sec_pci_dev_id,
    .probe = sec_pci_probe,
    .remove = sec_pci_remove,
    .driver.pm= &pci_pm_ops
};
static bool pci_driver_registered = false;

//****************************************************************************
// DATA STUCTURES AND CALLBACKS FOR REGISTRATION AS A PLATFORM DRIVER
//****************************************************************************

int  platform_suspend(struct device *dev)
{
    icepm_trace(KBUILD_MODNAME, "PLATFORM SUSPEND\n");
    return sec_pm_suspend_handler();
}

int  platform_resume(struct device *dev)
{
    icepm_trace(KBUILD_MODNAME, "PLATFORM RESUME\n");
    return sec_pm_resume_handler();
}

int platform_probe(struct platform_device *dev)
{
    return 0;
}

static const struct dev_pm_ops platform_pm_ops =
{
    .suspend = platform_suspend,
    .resume  = platform_resume
};

static struct platform_device_id platform_ids[] =
{
    { KBUILD_MODNAME, 0 },
    {  }
};

static struct platform_driver platform_driver =
{
	.id_table   = platform_ids,
    .driver.pm  = &platform_pm_ops,
    .driver.name= KBUILD_MODNAME
};

static bool platform_driver_registered = false;

static struct platform_device * platform_device = NULL;


//*****************************************************************************
//           R E G I S T R A T I O N   F U N C T I O N S
//*****************************************************************************


//-----------------------------------------------------------------------------
// sec_register_pci_dev
//
// Registers the PCI device driver for sec.
//-----------------------------------------------------------------------------
int sec_register_pci_dev(void)
{
    int rc = -EBUSY;

#ifdef SEC_PCI_DEBUG
    SEC_PCI_TRACE();
#endif

    // Register for power management notifications.
    // Kernel function, returns 0 on success.
    if ( register_pm_notifier(&sec_notification_block) )
    {
        SEC_ERROR("register_pm_notifier failed\n");
        goto exit;
    }
    registered_notifier = true;

    // Register platform device/driver
    platform_device = platform_device_register_simple(KBUILD_MODNAME,0,NULL,0);
    if ( IS_ERR(platform_device) )
    {
        SEC_ERROR("Platform device registration failed\n");
        goto exit;
    }
    if (0 != platform_driver_probe(&platform_driver, platform_probe))
    {
        SEC_ERROR("Platform driver registration failed\n");
        goto exit;
    }
    platform_driver_registered = true;


    // Register pci driver
    if (0 == pci_register_driver(&sec_pci_driver))
    {
        pci_driver_registered = true;
    }
    else
    {
        SEC_ERROR("PCI driver registration failed\n");
        goto exit;
    }

    rc = 0; // Success
exit:

#ifdef SEC_PCI_DEBUG
    SEC_PCI_RET_TRACE();
#endif

    return rc;
}

//-----------------------------------------------------------------------------
// sec_unregister_pci_dev
//
// Registers the PCI device driver for sec.
//-----------------------------------------------------------------------------
void sec_unregister_pci_dev(void)
{
    SEC_PCI_TRACE();
    if (registered_notifier)
    {
        unregister_pm_notifier(&sec_notification_block);
        registered_notifier = false;
    }

    if (pci_driver_registered)
    {
        pci_unregister_driver( &sec_pci_driver );
        pci_driver_registered = false;
    }

    if (platform_driver_registered)
    {
        platform_driver_unregister( &platform_driver );
        platform_driver_registered = false;
    }

    if ( platform_device )
    {
        platform_device_unregister( platform_device );
        platform_device = NULL;
    }

    SEC_PCI_TRACE();
}
