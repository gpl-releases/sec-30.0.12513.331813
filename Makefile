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
# Copyright(c) 2008-2011 Intel Corporation. All rights reserved.
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

# Note that CURDIR is defined by GNU make to be the current working directory
SEC_ROOT=$(CURDIR)
include Makefile.include

#------------------------------------------------------------------------
# functions
#------------------------------------------------------------------------

# Loop through the list of directories and run their make files with 
# the given target.  Parameters:
#		1: Makefile target to be invoked in each directory
#		2: Space-separated list of directories

make_loop = \
	@(for x in $(2); do \
		echo ; \
		echo '*********************************************************'; \
		echo make $(1) for $$x; \
		echo '*********************************************************'; \
		$(MAKE) -C $$x $(1) || exit 1; \
	done; )

#----------------------------------------------------------------------
# Makefile targets
#----------------------------------------------------------------------

.PHONY: help
help:
	@echo '*** No action taken - VALID Make TARGETS:'
	@echo '------------------'
	@echo '<default> Print this help message.'
	@echo 'all     Build everything, copy exports to $(BUILD_DEST)'
	@echo '        Leave copy of libraries in  $(DISP_LIB)'
	@echo 'debug   Build "all" with debug compilation options'
	@echo 'clean   Remove everything built by "all" or "debug"'
	@echo 'doc     Build documentation (only).'
	@echo 'install Copy exports to $(BUILD_DEST) and $(FSROOT)'
	@echo 'install_dev'
	@echo '        Copy development system exports to $(BUILD_DEST)'
	@echo 'install_target'
	@echo '        Copy target system exports to $(FSROOT)'
	@echo 'test    Build test applications (only).'
	@echo
	@echo 'INTERNAL TARGETS:'
	@echo 'bld     Build everything, export nothing'
	@echo '        Leave libraries in: $(DISP_LIB)'
	@echo 'db      Build "bld" with debug options'
	@echo '------------------'

.PHONY: all
all: bld test install 

.PHONY: debug
debug: db test install

.PHONY: install
install: install_dev install_target

.PHONY: install_dev
install_dev:
	if [ -e README_sec.txt ]; then cp README_sec.txt $(BUILD_DEST); fi
	$(call make_loop, install_dev, $(DIRS))

.PHONY: install_target
install_target:
	if [ -e init_sec ]; then mkdir -p $(FSROOT)/etc/init.d; cp init_sec $(FSROOT)/etc/init.d/sec; fi
	if [ -e README_sec.txt ]; then cp README_sec.txt $(FSROOT); fi
	$(call make_loop, install_target, $(DIRS))

.PHONY: clean
clean:
	$(call make_loop, clean, $(DIRS))

.PHONY: doc
doc:
	@make -C include doc

.PHONY: test
test:

.PHONY: bld
bld:
	$(call make_loop, all, $(DIRS))

.PHONY: db
db:
	$(call make_loop, debug, $(DIRS))
