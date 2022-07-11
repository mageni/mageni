* Most new code since 2020 by Mageni Security LLC
# Based on work Copyright (C) 2011-2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

cmake_minimum_required (VERSION 3.10.2)

set (PROJECT_VERSION_MAJOR "1")
set (PROJECT_VERSION_MINOR "1")
set (PROJECT_VERSION_PATCH "0")
set (PROJECT_VERSION_TWEAK "0")
set (MGNI_DATABASE_VERSION "206")
set (GVMD_DATABASE_VERSION "206")

project (MGN VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}.${PROJECT_VERSION_TWEAK})

if (CODE_ANALYSIS MATCHES Yes)
    set (CODE_ANALYSIS "-fanalyzer")
    message (STATUS "Code Analysis On")
else()
    message (STATUS "Code Analysis Off")
endif()

if (CMAKE_BUILD_TYPE MATCHES Debug)
    message (STATUS "Debug build")
    set (CMAKE_BUILD_TYPE Debug)
elseif (CMAKE_BUILD_TYPE MATCHES Release)
    message (STATUS "Release build")
    set (CMAKE_BUILD_TYPE Release)
else (NOT CMAKE_BUILD_TYPE)
    message (STATUS "Release build")
    set (CMAKE_BUILD_TYPE Release)
endif ()

execute_process (COMMAND sudo chown yeshua:yeshua -R ${PROJECT_SOURCE_DIR}/)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    message (STATUS "64-bit is supported.")
else ()
    message (SEND_ERROR "Only 64-bit is supported." )
endif ()

set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include (${CMAKE_MODULE_PATH}/FindLinux.cmake)
include (${CMAKE_MODULE_PATH}/IncludeHeaders.cmake)

message (STATUS "Software: ${PROJECT_NAME}")
message (STATUS "Version: ${PROJECT_VERSION}")
message (STATUS "Homepage: ${PROJECT_HOMEPAGE_URL}")
message (STATUS "Description: ${PROJECT_DESCRIPTION}")

if (POLICY CMP0005)
    cmake_policy (SET CMP0005 NEW)
endif (POLICY CMP0005)

if (POLICY CMP0054)
    cmake_policy (SET CMP0054 NEW)
endif (POLICY CMP0054)

if (POLICY CMP0048)
    cmake_policy (SET CMP0048 NEW)
endif (POLICY CMP0048)

set (LIBMAGENI_NASL_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/scanner/nasl/")
set (LIBMAGENI_MISC_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/scanner/misc/")
set (LIBMAGENI_SSH_INCLUDE_HEADERS  "/usr/local/include/libssh/")
set (LIBMAGENI_MOSP_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/libraries/osp/")
set (LIBMAGENI_MSMP_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/libraries/gmp/")
set (LIBMAGENI_BASE_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/libraries/base/")
set (LIBMAGENI_UTIL_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/libraries/util/")

set (LIBMAGENI_NASL "-L${CMAKE_SOURCE_DIR}/build/backend/scanner/nasl -lmageni_nasl")
set (LIBMAGENI_MISC "-L${CMAKE_SOURCE_DIR}/build/backend/scanner/misc -lmageni_misc")
set (LIBMAGENI_MSMP "-L${CMAKE_SOURCE_DIR}/build/backend/libraries/gmp -lmageni_gmp")
set (LIBMAGENI_MOSP "-L${CMAKE_SOURCE_DIR}/build/backend/libraries/osp -lmageni_osp")
set (LIBMAGENI_UTIL "-L${CMAKE_SOURCE_DIR}/build/backend/libraries/util -lmageni_util")
set (LIBMAGENI_BASE "-L${CMAKE_SOURCE_DIR}/build/backend/libraries/base -lmageni_base")

set (NVT_TIMEOUT "60")
set (KSBA_MIN_VERSION "1.0.7")
set (GPGME_MIN_VERSION "1.1.2")
set (SCANNER_NVT_TIMEOUT "12000")
set (GMP_VERSION ${PROJECT_VERSION})
set (GVMD_VERSION "${PROJECT_VERSION}")
set (OPENVASSD_VERSION "${PROJECT_VERSION}")
set (NVTICACHE_STR "nvticache${PROJECT_VERSION}")
#set (GVMD_DATABASE_VERSION ${MGNI_DATABASE_VERSION})
set (GVMD_SCAP_DATABASE_VERSION ${MGNI_DATABASE_VERSION})
set (GVMD_CERT_DATABASE_VERSION ${MGNI_DATABASE_VERSION})

add_definitions (-DNVTICACHE_STR="${NVTICACHE_STR}")

message (STATUS "Install path: ${CMAKE_INSTALL_PREFIX}")

include (FindPkgConfig)
find_package (Threads REQUIRED)
find_package (BISON 2.5 REQUIRED)

pkg_check_modules (ZLIB REQUIRED zlib>=1.2.8)
pkg_check_modules (GIO REQUIRED gio-2.0>=2.42)
pkg_check_modules (UUID REQUIRED uuid>=2.25.0)
pkg_check_modules (LIBXML REQUIRED libxml-2.0)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules (LIBSSH REQUIRED libssh>=0.6.0)
pkg_check_modules (REDIS REQUIRED hiredis>=0.10.1)
pkg_check_modules (GNUTLS REQUIRED gnutls>=3.2.15)
pkg_check_modules (LIBICAL REQUIRED libical>=1.00)
pkg_check_modules (SQLITE3 REQUIRED sqlite3>=3.8.3)

find_library (GPGME gpgme)
if (NOT GPGME)
    message (SEND_ERROR "The gpgme library is required.")
else (NOT GPGME)
    execute_process (COMMAND gpgme-config --version
            OUTPUT_VARIABLE GPGME_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    if (GPGME_VERSION VERSION_LESS GPGME_MIN_VERSION)
        message (SEND_ERROR "The gpgme library >= ${GPGME_MIN_VERSION} is required.")
    else (GPGME_VERSION VERSION_LESS GPGME_MIN_VERSION)
        execute_process (COMMAND gpgme-config --libs
                OUTPUT_VARIABLE GPGME_LDFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
        execute_process (COMMAND gpgme-config --cflags
                OUTPUT_VARIABLE GPGME_CFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FILE_OFFSET_BITS=64 -DLARGEFILE_SOURCE=1")
        string (REPLACE "-I" "" GPGME_INCLUDE_DIRS "${GPGME_CFLAGS}")
        message (STATUS "Found ${GPGME}")
    endif (GPGME_VERSION VERSION_LESS GPGME_MIN_VERSION)
endif (NOT GPGME)

find_library (GCRYPT gcrypt)
if (NOT GCRYPT)
    message (SEND_ERROR "The libgcrypt library is required.")
else (NOT GCRYPT)
    execute_process (COMMAND libgcrypt-config --libs
            OUTPUT_VARIABLE GCRYPT_LDFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process (COMMAND libgcrypt-config --cflags
            OUTPUT_VARIABLE GCRYPT_CFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process (COMMAND libgcrypt-config --version
            OUTPUT_VARIABLE GCRYPT_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    message (STATUS "Found ${GCRYPT}, version ${GCRYPT_VERSION}")
    if (GCRYPT_VERSION VERSION_LESS "1.6")
        message (SEND_ERROR "libgcrypt 1.6 or greater is required")
    endif (GCRYPT_VERSION VERSION_LESS "1.6")
endif (NOT GCRYPT)

find_library (SNMP netsnmp)
if (NOT SNMP)
    message (STATUS "No netsnmp library found - netsnmp support disabled")
else (NOT SNMP)
    execute_process (COMMAND net-snmp-config --libs
            OUTPUT_VARIABLE SNMP_LDFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE)
endif (NOT SNMP)

find_library (KSBA ksba)
if (NOT KSBA)
    message (SEND_ERROR "The ksba library is required.")
else (NOT KSBA)
    execute_process (COMMAND ksba-config --version
            OUTPUT_VARIABLE KSBA_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    message (STATUS "Found ksba ${KSBA_VERSION}...")
    if (${KSBA_VERSION} VERSION_LESS ${KSBA_MIN_VERSION})
        message (SEND_ERROR "The ksba library >= ${KSBA_MIN_VERSION} is required.")
    else (${KSBA_VERSION} VERSION_LESS ${KSBA_MIN_VERSION})
        execute_process (COMMAND ksba-config --libs
                OUTPUT_VARIABLE KSBA_LDFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
        execute_process (COMMAND ksba-config --cflags
                OUTPUT_VARIABLE KSBA_CFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif (${KSBA_VERSION} VERSION_LESS ${KSBA_MIN_VERSION})
endif (NOT KSBA)

find_library (PCAP pcap)
if (NOT PCAP)
    message (SEND_ERROR "No pcap library found")
else (NOT PCAP)
    find_program (PCAP_CONFIG pcap-config)
    if (PCAP_CONFIG)
        message (STATUS "Looking for pcap-config... ${PCAP_CONFIG}")
        execute_process (COMMAND pcap-config --libs
                OUTPUT_VARIABLE PCAP_LDFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
        execute_process (COMMAND pcap-config --cflags
                OUTPUT_VARIABLE PCAP_CFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
    else (PCAP_CONFIG)
        message (STATUS "pcap-config not found, using default.")
        set (PCAP_LDFLAGS "-L/usr/lib -lpcap")
        set (PCAP_CFLAGS "-I/usr/include")
    endif (PCAP_CONFIG)
endif (NOT PCAP)

set (SYSCONFDIR                 "${CMAKE_INSTALL_PREFIX}/etc")
set (EXEC_PREFIX                "${CMAKE_INSTALL_PREFIX}")
set (BINDIR                     "${EXEC_PREFIX}/bin")
set (SBINDIR                    "${EXEC_PREFIX}/sbin")
set (LIBDIR                     "${EXEC_PREFIX}/lib")
set (INCLUDEDIR                 "${CMAKE_INSTALL_PREFIX}/include")
set (LOCALSTATEDIR              "${CMAKE_INSTALL_PREFIX}/var")
set (DATADIR                    "${CMAKE_INSTALL_PREFIX}/share")
set (MAGENI_DATA_DIR            "${DATADIR}/mageni")
set (MAGENI_STATE_DIR           "${LOCALSTATEDIR}/lib/mageni")
set (MAGENI_LOG_DIR             "${LOCALSTATEDIR}/log/mageni")
set (MAGENI_RUN_DIR             "${LOCALSTATEDIR}/run")
set (MAGENI_PID_DIR             "${LOCALSTATEDIR}/run")
set (MAGENI_SYSCONF_DIR         "${SYSCONFDIR}/mageni")
set (MAGENI_CONF_DIR            "${MAGENI_SYSCONF_DIR}/vscand.conf")
set (MAGENI_SCANNER_CERTIFICATE "${MAGENI_STATE_DIR}/CA/servercert.pem")
set (MAGENI_SCANNER_KEY         "${MAGENI_STATE_DIR}/private/CA/serverkey.pem")
set (MAGENI_CLIENT_CERTIFICATE  "${MAGENI_STATE_DIR}/CA/clientcert.pem")
set (MAGENI_CLIENT_KEY          "${MAGENI_STATE_DIR}/private/CA/clientkey.pem")
set (MAGENI_CA_CERTIFICATE      "${MAGENI_STATE_DIR}/CA/cacert.pem")
set (MAGENI_CA_DIR              "${MAGENI_STATE_DIR}/trusted_certs")
set (MAGENI_SQLITE_DIR          "${MAGENI_STATE_DIR}/sqlite")
set (MAGENI_NVT_DIR             "${MAGENI_STATE_DIR}/plugins")
set (MAGENI_TMP_DIR             "${MAGENI_STATE_DIR}/tmp")
set (PLUGINS_TMP_DIR            "${MAGENI_STATE_DIR}/tmp/plugins")
set (FRONTEND_TMP_DIR           "${MAGENI_STATE_DIR}/tmp/frontend")
set (BACKEND_TMP_DIR            "${MAGENI_STATE_DIR}/tmp/backend")
set (MAGENI_ACCESS_KEY_DIR      "${MAGENI_SYSCONF_DIR}")
set (ETC_CROND_DIR              "/etc/cron.d/")
set (ETC_SUDOERS_DIR            "/etc/sudoers.d/")

add_subdirectory (backend/libraries)
add_subdirectory (backend/scanner)
add_subdirectory (backend/api)
