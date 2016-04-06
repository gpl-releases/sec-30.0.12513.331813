#-----------------------------------------------------------------------------
# This file is provided under a dual BSD/GPLv2 license.  When using or
# redistributing this file, you may do so under either license.
#
# GPL LICENSE SUMMARY
#
# Copyright(c) 2008-2012 Intel Corporation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
# The full GNU General Public License is included in this distribution
# in the file called LICENSE.GPL.
#
# Contact Information:
#      Intel Corporation
#      2200 Mission College Blvd.
#      Santa Clara, CA  97052
#
# BSD LICENSE
#
# Copyright(c) 2008-2012 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   - Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   - Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   - Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#-----------------------------------------------------------------------------

ifndef SEC_ROOT
export SEC_ROOT=$(shell cd .. && pwd)
endif
include $(SEC_ROOT)/Makefile.kernel

TARGET	= sec_kernel.ko
OBJS	= kernel.o \
          sec_tdp.o \
          sec_kernel_aacs.o \
          sec_tracker.o \
          sec_kernel_3000.o \
          sec_fw.o \
		  sec_pm.o \
          sec_pci.o \
          sec_kernel_dtcpip.o \
		  sec_kernel_dma.o \
          sec_dma_tracker.o \
          sec_dma_tracker_map_vm_to_desc.o \
          sec_fw_context_manager.o \
          sec_kernel_multipart.o

obj-m           := sec_kernel.o
sec_kernel-objs := $(OBJS) version.o
sec_kernel-y    := libsec_hal.a
KBUILD_EXTRA_SYMBOLS := $M/Import.symvers

## To turn on debug printk in sec_kernel_init
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SEC_KERNEL_INIT

## To turn on debug printk uncomment the module's EXTRA_CFLAGS line
## for routine __client_get in sec_tracker.c SEC kernel driver
## EXTRA_CFLAGS += -DDEBUG_CLIENT_FIND_MEM

## To turn on debug printk uncomment the module's EXTRA_CFLAGS line
## for routine __client_get in sec_tracker.c SEC kernel driver
## EXTRA_CFLAGS += -DDEBUG_CLIENT_GET

## To turn on debug printk in sec_kernel_reg_sysmem
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_REG_SYS_MEM

## To turn on debug printk in sec_kernel_mmap
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SEC_KERNEL_MMAP

## To turn on debug printk in __sec_munmap_call
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SEC_MUNMAP_CALL

## To turn on debug printk in __sec_free_mem
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SEC_FREE_MEM

## To turn off ZERO count reporting printk in __sec_free_mem
## comment out the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SEC_FREE_MEM_COUNT_ZERO

## To turn off error reporting printk in __sec_free_mem
## comment out the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SEC_FREE_MEM_ERR

## To turn on debug printk in __sec_free_pages
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SEC_FREE_PAGES

## To turn off error reporting printk in __sec_free_pages
## comment out the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SEC_FREE_PAGES_ERR

## To turn on debug printk in __sec_alloc_pages
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SEC_ALLOC_PAGES

## To turn on debug printk in __sec_alloc_mem
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SEC_ALLOC_MEM

## To turn on debug printk in sec_hal_get_chip_info
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SEC_HAL_GET_PCI_CHIP_INFO

## To turn on debug printk in load_fw_op
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_LOAD_FW_OP

## To turn on debug printk in unload_fw_op
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_UNLOAD_FW_OP

## To turn on debug printk in sec_get_eau_lock and sec_release_eau_lock
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_EAU_LOCKING

## To turn on debug printk in sec_kernel_dma.c
## function sec_kernel_create_dma_desc
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_CREATE_DMA_DESC

## To include show_dma_mem in sec_dma_tracker.c
## uncomment the following EXTRA_CFLAGS line
EXTRA_CFLAGS += -DDEBUG_SHOW_DMA_MEM

## To turn on debug printk in __dma_client_find in sec_dma_tracker.c
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_DMA_CLIENT_FIND

## To turn on debug printk in __dma_client_find_mem in sec_dma_tracker.c
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_DMA_CLIENT_FIND_MEM

## To turn on debug printk in __dma_client_get in sec_dma_tracker.c
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_DMA_CLIENT_GET

## To turn on debug printk in __remove_client_dma in sec_dma_tracker.c
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_REMOVE_CLIENT_DMA

## To turn on debug printk in dma_tracker_add_node in sec_dma_tracker.c
## uncomment the following EXTRA_CFLAGS line
## You must also turn on DEBUG_SHOW_DMA_MEM !!
## EXTRA_CFLAGS += -DDEBUG_DMA_ADD_NODE

## To turn on debug printk in dma_tracker_map_vm_to_desc
## in sec_dma_tracker_map_vm_to_desc.c
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_MAP_VM_TO_DESC

## To turn on debug printk in sec_kernel_smd_to_dma in sec_kernel_dma.c
## uncomment the following EXTRA_CFLAGS line
## EXTRA_CFLAGS += -DDEBUG_SMD_TO_DMA

EXTRA_CFLAGS += -I$(SEC_ROOT)/hal
EXTRA_CFLAGS += -I$(SEC_ROOT)/kernel
EXTRA_CFLAGS += -I$(BUILD_DEST)/usr/include

.PHONY: all
all: $(TARGET)

$(TARGET): Import.symvers libsec_hal.a FORCE
	@make -C $(KDIR) M=$(CURDIR) modules 

libsec_hal.a: $(SEC_ROOT)/hal/libsec_hal.a
	cp $(SEC_ROOT)/hal/libsec_hal.a .

.PHONY: debug
debug: EXTRA_CFLAGS +=-DDEBUG -g -O0
debug: all

.PHONY: clean
clean:
	-@make -C $(KDIR) M=$(CURDIR) clean
	rm -f version.c Module.symvers Import.symvers modules.order

.PHONY: install
install: install_dev install_target

.PHONY: install_dev
install_dev:

.PHONY: install_target
install_target:
	mkdir -p $(FSROOT)/lib/modules
	cp -pd sec_kernel.ko $(FSROOT)/lib/modules
	mkdir -p $(BUILD_DEST)/include
	cp -pd sec_common_types.h sec_kernel_share_types.h sec_tdp_peri_fw.h $(BUILD_DEST)/include

.PHONY: FORCE
FORCE:

$(src)/version.c: $(OBJS)
	@echo "char *gVersion = \"#@# $(TARGET) $(COMP_VER)\";" > $(src)/version.c

$(obj)/version.o: $(src)/version.c

# By building a dummy 'Module.symvers' file and exporting it to the kernel
# through the KBUILD_EXTRA_SYMBOLS variable, we suppress modpost warnings about
# undefined symbols that will be resolved at loadtime from other loadable
# kernel modules.
#
# Here is the list of symbols we import from other kernel modules. It may
# need to be updated in the future.
IMPORTS = \
	_clock_control_read \
	_clock_control_write \
	devhandle_connect_name \
	devhandle_factory \
	devh_Delete \
	devh_ReadReg32 \
	devh_WriteReg32 \
	os_event_create \
	os_event_destroy \
	os_event_hardwait \
	os_event_reset \
	os_event_set \
	os_pci_enable_device \
	os_pci_find_first_device \
	os_pci_free_device \
	os_pci_read_config_8 \
	os_pci_read_config_32 \
	os_pci_write_config_32 \
	os_pci_device_from_address \
	os_acquire_interrupt \
	os_pci_get_interrupt \
	os_release_interrupt \
	config_get_int \
	config_node_find \
	config_node_get_name \
	config_node_first_child \
	config_node_next_sibling \
	iosf_open \
	iosf_close \
	iosf_read32 \
	iosf_write32 \
	_icepm_trace_enabled \
	cache_flush_buffer

Import.symvers:
	@for i in $(IMPORTS) ; do \
		echo "0x00000000	$$i	XXX	EXPORT_SYMBOL" >> Import.symvers ;\
	done
