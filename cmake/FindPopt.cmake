# openvas-smb
# $Id$
# Description: Popt find script.
# Copied from: http://bazaar.launchpad.net/~inkscape.dev/inkscape/trunk/view/head:/CMakeScripts/Modules/FindPopt.cmake
# Modified by: Andre Heinecke <aheinecke@greenbone.net>
#
# Changes: - Find static version of popt instead of shared variant.
#
# - Try to find Popt
# Once done this will define
#
#  POPT_FOUND - system has Popt
#  POPT_INCLUDE_DIRS - the Popt include directory
#  POPT_LIBRARIES - Link these to use Popt
#  POPT_DEFINITIONS - Compiler switches required for using Popt
#
#  Copyright (c) 2008 Joshua L. Blocher <verbalshadow@gmail.com>
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


if (POPT_LIBRARIES AND POPT_INCLUDE_DIRS)
    # in cache already
    set(POPT_FOUND TRUE)
else (POPT_LIBRARIES AND POPT_INCLUDE_DIRS)
    # use pkg-config to get the directories and then use these values
    # in the FIND_PATH() and FIND_LIBRARY() calls
    if (${CMAKE_MAJOR_VERSION} EQUAL 2 AND ${CMAKE_MINOR_VERSION} EQUAL 4)
        include(UsePkgConfig)
        pkgconfig(popt _POPT_INCLUDEDIR _POPT_LIBDIR _POPT_LDFLAGS _POPT_CFLAGS)
    else (${CMAKE_MAJOR_VERSION} EQUAL 2 AND ${CMAKE_MINOR_VERSION} EQUAL 4)
        find_package(PkgConfig)
        if (PKG_CONFIG_FOUND)
            pkg_check_modules(_POPT popt)
        endif (PKG_CONFIG_FOUND)
    endif (${CMAKE_MAJOR_VERSION} EQUAL 2 AND ${CMAKE_MINOR_VERSION} EQUAL 4)
    find_path(POPT_INCLUDE_DIR
            NAMES
            popt.h
            PATHS
            ${_POPT_INCLUDEDIR}
            /usr/include
            /usr/local/include
            /opt/local/include
            $ENV{DEVLIBS_PATH}//include//
            PATH_SUFFIXES
            popt
            )

    find_library(POPT_LIBRARY
            NAMES
            popt
            PATHS
            ${_POPT_LIBDIR}
            /usr/lib
            /usr/local/lib
            /opt/local/lib
            )

    if (POPT_LIBRARY)
        set(POPT_FOUND TRUE)
    endif (POPT_LIBRARY)

    set(POPT_INCLUDE_DIRS
            ${POPT_INCLUDE_DIR}
            )

    if (POPT_FOUND)
        set(POPT_LIBRARIES
                ${POPT_LIBRARIES}
                ${POPT_LIBRARY}
                )
    endif (POPT_FOUND)

    if (POPT_INCLUDE_DIRS AND POPT_LIBRARIES)
        set(POPT_FOUND TRUE)
    endif (POPT_INCLUDE_DIRS AND POPT_LIBRARIES)

    if (POPT_FOUND)
        if (NOT Popt_FIND_QUIETLY)
            message(STATUS "Found Popt: ${POPT_LIBRARIES}")
        endif (NOT Popt_FIND_QUIETLY)
    else (POPT_FOUND)
        if (Popt_FIND_REQUIRED)
            message(FATAL_ERROR "Could not find Popt")
        endif (Popt_FIND_REQUIRED)
    endif (POPT_FOUND)

    # show the POPT_INCLUDE_DIRS and POPT_LIBRARIES variables only in the advanced view
    mark_as_advanced(POPT_INCLUDE_DIRS POPT_LIBRARIES)

endif (POPT_LIBRARIES AND POPT_INCLUDE_DIRS)