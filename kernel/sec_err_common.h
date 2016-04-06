/****************************************************************************
 * This file is provided under a dual BSD/GPLv2 license.  When using or 
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2012 Intel Corporation. All rights reserved.
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
 * Copyright(c) 2012 Intel Corporation. All rights reserved.
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
 ***************************************************************************/
/*^^vvv^^^vvv^^^vvv^^^vvv^^^vvv^^^vvv^^^vvv^^^vvv^^^vvv^^^vvv^^^vvv^^^vvv^^*/

/****************************************************************************
 *  Digital Home Group
 *  Intel Corporation
 *  2200 Mission College Blvd.
 *  Santa Clara, CA  95054-1549
 *  (408) 765-8080
 *  http://www.intel.com
 ***************************************************************************/

/****************************************************************************
 * INSTRUCTIONS FOR USING THIS FILE:
 *
 * For kernel code:  #include "sec_err_common.h".
 *
 * Then receive a sec_err_t from user space, and use the macros defined
 * herein to record Extended Error Information into the sec_err_t.
 *
 * Return the sec_err_t to user space.
 ***************************************************************************/

#ifndef SEC_ERR_COMMON_H_
#define SEC_ERR_COMMON_H_

#include "sec_err_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*  #define this macro to enable SEC_ERR_ASSERT():  */
#define SEC_ERR_ENABLE_ASSERT


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = */
/** @brief macro to support run-time assertion checking
 *
 *  This macro is basically a common "assert" statement. Use it to check
 *  conditions that are assumed to be true in the source code.
 *
 *  For example, to check the assertion that x != 0:
 *
 * @code
 *  SEC_ERR_HERE( exit, &err, rv=SEC_FAIL, x != 0 );
 * @endcode
 *
 * @param[in] l
 *              Label for goto statement upon error.
 *
 * @param[in] e
 *              sec_err_t to fill in upon error.
 *
 * @param[in] v
 *              Expression to evaluate upon error.
 *
 * @param[in] h
 *              Assert expression that must evaluate to true for non-error.
 */
#ifdef SEC_ERR_ENABLE_ASSERT
#define SEC_ERR_ASSERT( l, e, v, h )                                        \
    do {                                                                    \
        if ( ! (h) )                                                        \
        {                                                                   \
            sec_err_here( e, __FILE__, __LINE__, __func__,                  \
                          SEC_ERR_DETAIL_CORE_ASSERT_FAILURE );             \
            (v);                                                            \
            goto l;                                                         \
        }                                                                   \
       } while(0)
#else
#define SEC_ERR_ASSERT( l, e, v, h )                                        \
    do {                                                                    \
        (void)(h);  (void)(e);  (void)(v);                                  \
       } while(0)
#endif
/* -  -  -  -  -  -  -  -  -  -  -  -   -  -  -  -  -  -  -  -  -  -  -  - */


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = */
/** @brief macro to indicate extended error info at this file/line location
 *
 *  Fills in Extended Error Information to record an error at this
 *  locations.
 *
 *  For example:
 *
 * @code
 *  SEC_ERR_HERE( &err, SEC_ERR_DETAIL_CORE_INTERNAL_ERROR );
 * @endcode
 *
 * @param[in] e
 *              sec_err_t to fill in for error.
 *
 * @param[in] c
 *              Detail Code (SEC_ERR_DETAIL_*) for error.
 */
#define SEC_ERR_HERE( e, c )                                                \
    sec_err_here( e, __FILE__, __LINE__, __func__, c )
/* -  -  -  -  -  -  -  -  -  -  -  -   -  -  -  -  -  -  -  -  -  -  -  - */


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = */
/** @brief general conditional check and error macro
 *
 *  This macro can be used to perform a check of a condition and record
 *  Extended Error Info if that condition is not met.
 *
 *  For example:
 *
 * @code
 *  SEC_ERR_CHECK( exit, err, rv=SEC_NULL_POINTER,
 *                 SEC_ERR_DETAIL_CORE_INVALID_PARAMETER,
 *                 x != 0 );
 * @endcode
 *
 * @param[in] l
 *              Label for goto statement upon error.
 *
 * @param[in] e
 *              sec_err_t to fill in upon error.
 *
 * @param[in] v
 *              Expression to evaluate upon error.
 *
 * @param[in] c
 *              Detail Code (SEC_ERR_DETAIL_*) to fill in upon error.
 *
 * @param[in] h
 *              Expression that must evaluate to true for non-error.
 */
#define SEC_ERR_CHECK( l, e, v, c, h )                                      \
    do {                                                                    \
        if ( ! (h) )                                                        \
        {                                                                   \
            sec_err_here( e, __FILE__, __LINE__, __func__, c );             \
            (v);                                                            \
            goto l;                                                         \
        }                                                                   \
       } while(0)
/* -  -  -  -  -  -  -  -  -  -  -  -   -  -  -  -  -  -  -  -  -  -  -  - */


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = */
/** @brief capture an error here (called via macros)
 *
 *  Normally, this function is only called through the macros such as
 *  SEC_ERR_HERE().
 *  The exception to this rule is for other error reporting functions that
 *  already have retrieved __FILE__, __LINE__, and __func__ and want to
 *  report those values on through.
 *
 * @param[in] err
 *              sec_err_t to fill in.
 *
 * @param[in] file_name
 *              Source file name where the error occured (i.e. __FILE__).
 *
 * @param[in] line_number
 *              Line number where the error occured (i.e. __LINE__).
 *
 * @param[in] function_name
 *              Function name where the error occured (i.e. __func__).
 *
 * @param[in] detail_code
 *              Detail Code (SEC_ERR_DETAIL_*) to fill in.
 */
void
sec_err_here( sec_err_t *   err,
              const char *  file_name,
              unsigned int  line_number,
              const char *  function_name,
              uint32_t      detail_code );
/* -  -  -  -  -  -  -  -  -  -  -  -   -  -  -  -  -  -  -  -  -  -  -  - */


#ifdef __cplusplus
}  /*  extern "C"  */
#endif

#endif  /*  ifndef SEC_ERR_COMMON_H_  */

