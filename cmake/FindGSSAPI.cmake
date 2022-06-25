# openvas-smb
# $Id$
# Description: GSS Api find script.
# Copied from: https://github.com/libgit2/libgit2/blob/master/cmake/Modules/FindGSSAPI.cmake
# Modified by: Andre Heinecke <aheinecke@greenbone.net>
#
# Changes: - Fixed setting of roken library in heimdal path
#          - Added lookup of libhdb
#          - Removed lookup of MIT flavor
#          - Added support for multidev
#
# - Try to find GSSAPI
# Once done this will define
#
#  KRB5_CONFIG - Path to krb5-config
#  GSSAPI_ROOT_DIR - Set this variable to the root installation of GSSAPI
#
# Read-Only variables:
#  GSSAPI_FLAVOR_HEIMDAL - set to TRUE if Heimdal Keberos has been found
#  GSSAPI_FOUND - system has GSSAPI
#  GSSAPI_INCLUDE_DIR - the GSSAPI include directory
#  GSSAPI_LIBRARIES - Link these to use GSSAPI
#  GSSAPI_DEFINITIONS - Compiler switches required for using GSSAPI
#
#=============================================================================
#  Copyright (c) 2013 Andreas Schneider <asn@cryptomilk.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

find_path(GSSAPI_ROOT_DIR
        NAMES
        include/roken.h
        include/heimdal/roken.h
        HINTS
        ${_GSSAPI_ROOT_HINTS}
        PATHS
        ${_GSSAPI_ROOT_PATHS}
        )
mark_as_advanced(GSSAPI_ROOT_DIR)

if (UNIX)
    find_program(KRB5_CONFIG
            NAMES
            krb5-config
            PATHS
            ${GSSAPI_ROOT_DIR}/bin
            /opt/local/bin)
    mark_as_advanced(KRB5_CONFIG)

    if (KRB5_CONFIG)
        execute_process(
                COMMAND
                ${KRB5_CONFIG} --vendor
                RESULT_VARIABLE
                _GSSAPI_VENDOR_RESULT
                OUTPUT_VARIABLE
                _GSSAPI_VENDOR_STRING)

        if (_GSSAPI_VENDOR_STRING MATCHES ".*Heimdal.*")
            execute_process(
                    COMMAND
                    ${KRB5_CONFIG} --libs gssapi
                    RESULT_VARIABLE
                    _GSSAPI_LIBS_RESULT
                    OUTPUT_VARIABLE
                    _GSSAPI_LIBS_STRING)

            set(GSSAPI_FLAVOR_HEIMDAL TRUE)
        else()
            set (FIND_LIBRARY_FLAGS NO_DEFAULT_PATH)
        endif()

        # Get the include dir
        execute_process(
                COMMAND
                ${KRB5_CONFIG} --cflags gssapi
                RESULT_VARIABLE
                _GSSAPI_INCLUDE_RESULT
                OUTPUT_VARIABLE
                _GSSAPI_INCLUDE_STRING)
        string(REGEX REPLACE "(\r?\n)+$" "" _GSSAPI_INCLUDE_STRING "${_GSSAPI_INCLUDE_STRING}")
        string(REGEX REPLACE " *-I" "" _GSSAPI_INCLUDEDIR "${_GSSAPI_INCLUDE_STRING}")
    endif()

    find_program(HEIMDAL_CONFIG
            NAMES
            krb5-config.heimdal
            heimdal-krb5-config
            PATHS
            ${GSSAPI_ROOT_DIR}/bin
            /opt/local/bin)
    mark_as_advanced(HEIMDAL_CONFIG)

    if (HEIMDAL_CONFIG)
        execute_process(
                COMMAND
                ${HEIMDAL_CONFIG} --vendor
                RESULT_VARIABLE
                _GSSAPI_VENDOR_RESULT
                OUTPUT_VARIABLE
                _GSSAPI_VENDOR_STRING)

        if (_GSSAPI_VENDOR_STRING MATCHES ".*Heimdal.*")
            execute_process(
                    COMMAND
                    ${HEIMDAL_CONFIG} --libs gssapi
                    RESULT_VARIABLE
                    _GSSAPI_LIBS_RESULT
                    OUTPUT_VARIABLE
                    _GSSAPI_LIBS_STRING)

            string(REGEX REPLACE "(\r?\n)+$" "" _GSSAPI_LIBS_STRING "${_GSSAPI_LIBS_STRING}")
            string(REGEX REPLACE " *-L" "" _GSSAPI_LIBS_STRING "${_GSSAPI_LIBS_STRING}")
            string(REGEX REPLACE " -l.*" "" _GSSAPI_LIBSDIR "${_GSSAPI_LIBS_STRING}")
            set(GSSAPI_FLAVOR_HEIMDAL TRUE)
            set (FIND_LIBRARY_FLAGS NO_DEFAULT_PATH)
        endif()

        # Get the include dir
        execute_process(
                COMMAND
                ${HEIMDAL_CONFIG} --cflags gssapi
                RESULT_VARIABLE
                _GSSAPI_INCLUDE_RESULT
                OUTPUT_VARIABLE
                _GSSAPI_INCLUDE_STRING)
        string(REGEX REPLACE "(\r?\n)+$" "" _GSSAPI_INCLUDE_STRING "${_GSSAPI_INCLUDE_STRING}")
        string(REGEX REPLACE " *-I" "" _GSSAPI_INCLUDEDIR "${_GSSAPI_INCLUDE_STRING}")
    endif()

    if (NOT GSSAPI_FLAVOR_HEIMDAL)
        # Check for HEIMDAL with pkg config
        find_package(PkgConfig)
        if (PKG_CONFIG_FOUND)
            pkg_check_modules(_GSSAPI heimdal-gssapi)
        endif (PKG_CONFIG_FOUND)

        if (_GSSAPI_FOUND)
            set(GSSAPI_FLAVOR_HEIMDAL TRUE)
        endif ()
    endif()
endif (UNIX)

find_path(GSSAPI_INCLUDE_DIR
        NAMES
        roken.h
        PATHS
        ${GSSAPI_ROOT_DIR}/include/heimdal
        ${GSSAPI_ROOT_DIR}/include
        ${_GSSAPI_INCLUDEDIR}
        )

if (GSSAPI_FLAVOR_HEIMDAL)
    find_library(GSSAPI_LIBRARY
            NAMES
            gssapi
            PATHS
            ${_GSSAPI_LIBSDIR}
            ${GSSAPI_ROOT_DIR}/lib
            ${FIND_LIBRARY_FLAGS}
            )

    find_library(KRB5_LIBRARY
            NAMES
            krb5
            PATHS
            ${_GSSAPI_LIBSDIR}
            ${GSSAPI_ROOT_DIR}/lib
            ${FIND_LIBRARY_FLAGS}
            )

    find_library(HCRYPTO_LIBRARY
            NAMES
            hcrypto
            PATHS
            ${_GSSAPI_LIBSDIR}
            ${GSSAPI_ROOT_DIR}/lib
            ${FIND_LIBRARY_FLAGS}
            )

    find_library(COM_ERR_LIBRARY
            NAMES
            com_err
            PATHS
            ${_GSSAPI_LIBSDIR}
            ${GSSAPI_ROOT_DIR}/lib
            )

    find_library(HEIMNTLM_LIBRARY
            NAMES
            heimntlm
            PATHS
            ${GSSAPI_ROOT_DIR}/lib
            ${_GSSAPI_LIBSDIR}
            ${FIND_LIBRARY_FLAGS}
            )

    find_library(HX509_LIBRARY
            NAMES
            hx509
            PATHS
            ${_GSSAPI_LIBSDIR}
            ${GSSAPI_ROOT_DIR}/lib
            ${FIND_LIBRARY_FLAGS}
            )

    find_library(ASN1_LIBRARY
            NAMES
            asn1
            PATHS
            ${_GSSAPI_LIBSDIR}
            ${GSSAPI_ROOT_DIR}/lib
            ${FIND_LIBRARY_FLAGS}
            )

    find_library(WIND_LIBRARY
            NAMES
            wind
            PATHS
            ${_GSSAPI_LIBSDIR}
            ${GSSAPI_ROOT_DIR}/lib
            ${FIND_LIBRARY_FLAGS}
            )

    find_library(ROKEN_LIBRARY
            NAMES
            roken
            PATHS
            ${_GSSAPI_LIBSDIR}
            ${GSSAPI_ROOT_DIR}/lib
            ${FIND_LIBRARY_FLAGS}
            )

    find_library(HDB_LIBRARY
            NAMES
            hdb
            PATHS
            ${_GSSAPI_LIBSDIR}
            ${GSSAPI_ROOT_DIR}/lib
            ${FIND_LIBRARY_FLAGS}
            )

    if (GSSAPI_LIBRARY)
        set(GSSAPI_LIBRARIES
                ${GSSAPI_LIBRARIES}
                ${GSSAPI_LIBRARY}
                )
    endif (GSSAPI_LIBRARY)

    if (KRB5_LIBRARY)
        set(GSSAPI_LIBRARIES
                ${GSSAPI_LIBRARIES}
                ${KRB5_LIBRARY}
                )
    endif (KRB5_LIBRARY)

    if (HCRYPTO_LIBRARY)
        set(GSSAPI_LIBRARIES
                ${GSSAPI_LIBRARIES}
                ${HCRYPTO_LIBRARY}
                )
    endif (HCRYPTO_LIBRARY)

    if (COM_ERR_LIBRARY)
        set(GSSAPI_LIBRARIES
                ${GSSAPI_LIBRARIES}
                ${COM_ERR_LIBRARY}
                )
    endif (COM_ERR_LIBRARY)

    if (HEIMNTLM_LIBRARY)
        set(GSSAPI_LIBRARIES
                ${GSSAPI_LIBRARIES}
                ${HEIMNTLM_LIBRARY}
                )
    endif (HEIMNTLM_LIBRARY)

    if (HX509_LIBRARY)
        set(GSSAPI_LIBRARIES
                ${GSSAPI_LIBRARIES}
                ${HX509_LIBRARY}
                )
    endif (HX509_LIBRARY)

    if (ASN1_LIBRARY)
        set(GSSAPI_LIBRARIES
                ${GSSAPI_LIBRARIES}
                ${ASN1_LIBRARY}
                )
    endif (ASN1_LIBRARY)

    if (WIND_LIBRARY)
        set(GSSAPI_LIBRARIES
                ${GSSAPI_LIBRARIES}
                ${WIND_LIBRARY}
                )
    endif (WIND_LIBRARY)

    if (ROKEN_LIBRARY)
        set(GSSAPI_LIBRARIES
                ${GSSAPI_LIBRARIES}
                ${ROKEN_LIBRARY}
                )
    endif (ROKEN_LIBRARY)

    if (HDB_LIBRARY)
        set(GSSAPI_LIBRARIES
                ${GSSAPI_LIBRARIES}
                ${HDB_LIBRARY}
                )
    endif (HDB_LIBRARY)
endif (GSSAPI_FLAVOR_HEIMDAL)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GSSAPI DEFAULT_MSG GSSAPI_LIBRARIES GSSAPI_INCLUDE_DIR)

if (GSSAPI_INCLUDE_DIRS AND GSSAPI_LIBRARIES)
    set(GSSAPI_FOUND TRUE)
endif (GSSAPI_INCLUDE_DIRS AND GSSAPI_LIBRARIES)

# show the GSSAPI_INCLUDE_DIRS and GSSAPI_LIBRARIES variables only in the advanced view
mark_as_advanced(GSSAPI_INCLUDE_DIRS GSSAPI_LIBRARIES)