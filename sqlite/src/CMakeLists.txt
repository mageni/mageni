# Most new code since 2020 by Mageni Security, LLC
# Copyright (C) 2009-2018 Greenbone Networks GmbH
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

include_directories (
    ${LIBMAGENI_MSMP_INCLUDE_HEADERS}
    ${LIBMAGENI_BASE_INCLUDE_HEADERS}
    ${LIBMAGENI_UTIL_INCLUDE_HEADERS}
    ${LIBMAGENI_MOSP_INCLUDE_HEADERS}
    ${GLIB_INCLUDE_DIRS}
)

set (BINARY_NAME "mageni-sqlite")

add_executable (
    ${BINARY_NAME}
    gvmd.c
    gmpd.c
    manage_utils.c
    manage.c
    sql.c
    manage_ranges_all_tcp_nmap_5_51_top_100.c
    manage_ranges_all_tcp_nmap_5_51_top_1000.c
    manage_ranges_iana_tcp_2012.c
    manage_ranges_iana_tcp_udp_2012.c
    manage_ranges_nmap_5_51_top_2000_top_100.c
    manage_acl.c
    manage_config_discovery.c
    manage_config_host_discovery.c
    manage_config_system_discovery.c
    manage_sql.c
    manage_sql_nvts.c
    manage_sql_secinfo.c
    manage_sql_tickets.c
    manage_migrators.c
    scanner.c
    sql_sqlite3.c
    manage_sqlite3.c
    lsc_user.c
    lsc_crypt.c
    utils.c
    comm.c
    otp.c
    gmp.c
    gmp_base.c
    gmp_delete.c
    gmp_get.c
    gmp_tickets.c
)

target_link_libraries (
    ${BINARY_NAME}
    m
    ${GNUTLS_LDFLAGS}
    ${GPGME_LDFLAGS}
    ${CMAKE_THREAD_LIBS_INIT}
    ${LINKER_HARDENING_FLAGS}
    ${LINKER_DEBUG_FLAGS}
    ${SQLITE3_LDFLAGS}
    ${GLIB_LDFLAGS}
    ${GTHREAD_LDFLAGS}
    ${LIBMAGENI_BASE}
    ${LIBMAGENI_UTIL}
    ${LIBMAGENI_MOSP}
    ${LIBMAGENI_MSMP}
    ${LIBICAL_LDFLAGS}
    ${LINKER_HARDENING_FLAGS}
)

set_target_properties (${BINARY_NAME} PROPERTIES LINKER_LANGUAGE C)

if (DEBUG_FUNCTION_NAMES)
    add_definitions (-DDEBUG_FUNCTION_NAMES)
endif (DEBUG_FUNCTION_NAMES)

if (GVMD_VERSION)
    add_definitions (-DGVMD_VERSION="${GVMD_VERSION}")
endif (GVMD_VERSION)

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
    target_compile_options (${BINARY_NAME} PUBLIC ${C_FLAGS_DEBUG_GVMD})
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

if (GMP_VERSION)
    add_definitions (-DGMP_VERSION="${GMP_VERSION}")
endif (GMP_VERSION)

add_definitions (-DGVMD_DATABASE_VERSION=${GVMD_DATABASE_VERSION})
add_definitions (-DGVMD_SCAP_DATABASE_VERSION=${GVMD_SCAP_DATABASE_VERSION})
add_definitions (-DGVMD_CERT_DATABASE_VERSION=${GVMD_CERT_DATABASE_VERSION})
add_definitions (-DGVM_OS_NAME="${CMAKE_SYSTEM}")
add_definitions (-DPREFIX="${CMAKE_INSTALL_PREFIX}")
add_definitions (-DGVM_SCAP_RES_DIR="${GVM_SCAP_RES_DIR}")
add_definitions (-DGVM_SCAP_DATA_DIR="${GVM_SCAP_DATA_DIR}")
add_definitions (-DGVM_CERT_RES_DIR="${GVM_CERT_RES_DIR}")
add_definitions (-DGVM_CERT_DATA_DIR="${GVM_CERT_DATA_DIR}")

if (GVM_SCANNER_CERTIFICATE)
    add_definitions (-DSCANNERCERT="${GVM_SCANNER_CERTIFICATE}")
endif (GVM_SCANNER_CERTIFICATE)

if (GVM_SCANNER_KEY)
    add_definitions (-DSCANNERKEY="${GVM_SCANNER_KEY}")
endif (GVM_SCANNER_KEY)

if (GVM_CLIENT_CERTIFICATE)
    add_definitions (-DCLIENTCERT="${GVM_CLIENT_CERTIFICATE}")
endif (GVM_CLIENT_CERTIFICATE)

if (GVM_CLIENT_KEY)
    add_definitions (-DCLIENTKEY="${GVM_CLIENT_KEY}")
endif (GVM_CLIENT_KEY)

if (GVM_CA_CERTIFICATE)
    add_definitions (-DCACERT="${GVM_CA_CERTIFICATE}")
endif (GVM_CA_CERTIFICATE)

if (GVM_CA_DIR)
    add_definitions (-DCA_DIR="${GVM_CA_DIR}")
endif (GVM_CA_DIR)

if (GVM_LOG_DIR)
    add_definitions (-DGVM_LOG_DIR="${GVM_LOG_DIR}")
endif (GVM_LOG_DIR)

if (GVM_STATE_DIR)
    add_definitions (-DGVM_STATE_DIR="${GVM_STATE_DIR}")
endif (GVM_STATE_DIR)

if (GVMD_STATE_DIR)
    add_definitions (-DGVMD_STATE_DIR="${GVMD_STATE_DIR}")
endif (GVMD_STATE_DIR)

if (GVM_RUN_DIR)
    add_definitions (-DGVM_RUN_DIR="${GVM_RUN_DIR}")
endif (GVM_RUN_DIR)

if (GVM_SYSCONF_DIR)
    add_definitions (-DGVM_SYSCONF_DIR="${GVM_SYSCONF_DIR}")
endif (GVM_SYSCONF_DIR)

if (GVM_SYSCONF_DIR)
    add_definitions (-DGVM_SYSCONF_DIR="${GVM_SYSCONF_DIR}")
endif (GVM_SYSCONF_DIR)

if (GVM_DATA_DIR)
    add_definitions (-DGVM_DATA_DIR="${GVM_DATA_DIR}")
endif (GVM_DATA_DIR)

if (GVMD_DATA_DIR)
    add_definitions (-DGVMD_DATA_DIR="${GVMD_DATA_DIR}")
endif (GVMD_DATA_DIR)

if (GVM_LIB_INSTALL_DIR)
    add_definitions (-DGVM_LIB_INSTALL_DIR="${GVM_LIB_INSTALL_DIR}")
endif (GVM_LIB_INSTALL_DIR)

if (GVM_NVT_DIR)
    add_definitions (-DGVM_NVT_DIR="${GVM_NVT_DIR}")
endif (GVM_NVT_DIR)

if (SBINDIR)
    add_definitions (-DSBINDIR="${SBINDIR}")
endif (SBINDIR)

install (TARGETS ${BINARY_NAME}
        RUNTIME DESTINATION ${SBINDIR}
        LIBRARY DESTINATION ${LIBDIR}
        ARCHIVE DESTINATION ${LIBDIR}/static)