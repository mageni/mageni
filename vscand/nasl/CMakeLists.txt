# Most new code since 2020 by Mageni Security, LLC
# Copyright (C) 2009-2019 Greenbone Networks GmbH
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


set (MAGENI_NASL_BIN "mageni-nasl")
set (MAGENI_NASL_LIB "mageni_nasl_shared")
set (MAGENI_MISC_LIB "mageni_misc_shared")
set (MAGENI_NASL_LINT_BIN "mageni-nasl-lint")

if (SNMP)
  add_definitions (-DHAVE_NETSNMP)
endif (SNMP)

if (KSBA)
  add_definitions (-DHAVE_LIBKSBA)
endif (KSBA)

if (OPENVASSD_CONF)
  add_definitions (-DOPENVASSD_CONF="${OPENVASSD_CONF}")
endif (OPENVASSD_CONF)

set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall -Wextra -fno-strict-aliasing")
set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Werror")

add_custom_command (
  COMMAND ${BISON_EXECUTABLE}
   ARGS -d -v -t -p nasl ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.y
   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.y
   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.tab.c
   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.tab.h
   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.output)

set (FILES
  arc4.c
  capture_packet.c
  charcnv.c
  exec.c
  genrand.c
  hmacmd5.c
  iconv.c
  lint.c
  md4.c
  md5.c
  nasl.c
  nasl_builtin_find_service.c
  nasl_builtin_openvas_tcp_scanner.c
  nasl_builtin_synscan.c
  nasl_builtin_nmap.c
  nasl_cmd_exec.c
  nasl_crypto2.c
  nasl_snmp.c
  nasl_ssh.c
  nasl_cert.c
  nasl_crypto.c
  nasl_debug.c
  nasl_func.c
  nasl_grammar.tab.c
  nasl_host.c
  nasl_http.c
  nasl_init.c
  nasl_lex_ctxt.c
  nasl_misc_funcs.c
  nasl_scanner_glue.c
  nasl_packet_forgery.c
  nasl_packet_forgery_v6.c
  nasl_signature.c
  nasl_smb.c
  nasl_socket.c
  nasl_text_utils.c
  nasl_tree.c
  nasl_var.c
  nasl_wmi.c
  nasl_isotime.c
  ntlmssp.c
  smb_crypt.c
  smb_crypt2.c
  smb_signing.c
  time.c
  smb_interface_stub.c
  wmi_interface_stub.c
)

set_source_files_properties (nasl_grammar.tab.c GENERATED)

add_definitions (-DOPENVAS_STATE_DIR="${OPENVAS_STATE_DIR}")
add_definitions (-DOPENVASLIB_VERSION="${PROJECT_VERSION}")
add_definitions (-DOPENVAS_SYSCONF_DIR="${OPENVAS_SYSCONF_DIR}")
add_definitions (-DOPENVAS_NASL_VERSION="${PROJECT_VERSION}")

include_directories (
  ${GLIB_INCLUDE_DIRS}
  ${GPGME_INCLUDE_DIRS}
  ${LIBMAGENI_SSH_INCLUDE_HEADERS}
  ${LIBMAGENI_NASL_INCLUDE_HEADERS}
  ${LIBMAGENI_MISC_INCLUDE_HEADERS}
  ${LIBMAGENI_BASE_INCLUDE_HEADERS}
  ${LIBMAGENI_UTIL_INCLUDE_HEADERS}
  ${KSBA_INCLUDE_DIRS}
)

add_library (${MAGENI_NASL_LIB} SHARED ${FILES})
set_target_properties (${MAGENI_NASL_LIB} PROPERTIES OUTPUT_NAME "mageni_nasl")
set_target_properties (${MAGENI_NASL_LIB} PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (${MAGENI_NASL_LIB} PROPERTIES SOVERSION "${PROJECT_VERSION}")
set_target_properties (${MAGENI_NASL_LIB} PROPERTIES VERSION "${PROJECT_VERSION}")
target_link_libraries (
  ${MAGENI_NASL_LIB}
  ${LIBMAGENI_MISC}
  ${GLIB_LDFLAGS}
  ${GCRYPT_LDFLAGS}
  ${GPGME_LDFLAGS}
  m
  ${LIBMAGENI_BASE}
  ${LIBMAGENI_UTIL}
  ${GNUTLS_LDFLAGS}
  ${PCAP_LDFLAGS}
  ${LIBSSH_LDFLAGS}
  ${KSBA_LDFLAGS}
  ${SNMP_LDFLAGS}
  ${LINKER_HARDENING_FLAGS}
)

add_executable (${MAGENI_NASL_BIN} nasl.c)
target_link_libraries (
  ${MAGENI_NASL_BIN}
  ${MAGENI_NASL_LIB}
  ${MAGENI_MISC_LIB}
  ${GNUTLS_LDFLAGS}
  ${LIBSSH_LDFLAGS}
)

add_executable (${MAGENI_NASL_LINT_BIN} nasl-lint.c)
target_link_libraries (
  ${MAGENI_NASL_LINT_BIN}
  ${MAGENI_NASL_LIB}
  ${MAGENI_MISC_LIB}
  ${GLIB_LDFLAGS}
  ${GIO_LDFLAGS}
)

install (
  TARGETS ${MAGENI_NASL_LIB} ${MAGENI_NASL_BIN} ${MAGENI_NASL_LINT_BIN}
  RUNTIME DESTINATION ${BINDIR}
  LIBRARY DESTINATION ${LIBDIR}
  ARCHIVE DESTINATION ${LIBDIR}
)

#install (FILES ${CMAKE_SOURCE_DIR}/doc/openvas-nasl.1
#         DESTINATION ${DATADIR}/man/man1 )
#
#install (FILES ${CMAKE_SOURCE_DIR}/doc/openvas-nasl-lint.1
#         DESTINATION ${DATADIR}/man/man1 )
## End
