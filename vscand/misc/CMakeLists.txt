# Most new code since 2020 by Mageni Security, LLC
# Copyright (C) 2010-2019 Greenbone Networks GmbH
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

set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Werror")

include_directories (
  ${GLIB_INCLUDE_DIRS}
  ${LIBMAGENI_BASE_INCLUDE_HEADERS}
  ${GNUTLS_INCLUDE_DIRS}
)

set (FILES
  bpf_share.c
  ftp_funcs.c
  vendorversion.c
  network.c
  plugutils.c
  pcap.c
  strutils.c
)

set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")

set (LIBRARY_NAME "mageni_misc_shared")

add_library (${LIBRARY_NAME} SHARED ${FILES})

set_target_properties (${LIBRARY_NAME} PROPERTIES OUTPUT_NAME "mageni_misc")
set_target_properties (${LIBRARY_NAME} PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (${LIBRARY_NAME} PROPERTIES SOVERSION "${PROJECT_VERSION}")
set_target_properties (${LIBRARY_NAME} PROPERTIES VERSION "${PROJECT_VERSION}")

target_link_libraries (${LIBRARY_NAME} LINK_PRIVATE ${GNUTLS_LDFLAGS} ${UUID_LDFLAGS}
                       ${GLIB_LDFLAGS} ${PCAP_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS})

if (OPENVAS_STATE_DIR)
  add_definitions (-DOPENVAS_STATE_DIR="${OPENVAS_STATE_DIR}")
endif (OPENVAS_STATE_DIR)

if (OPENVAS_DATA_DIR)
  add_definitions (-DOPENVAS_DATA_DIR="${OPENVAS_DATA_DIR}")
endif (OPENVAS_DATA_DIR)

if (OPENVAS_SYSCONF_DIR)
  add_definitions (-DOPENVAS_SYSCONF_DIR="${OPENVAS_SYSCONF_DIR}")
endif (OPENVAS_SYSCONF_DIR)

install (TARGETS mageni_misc_shared
         RUNTIME DESTINATION ${BINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR})

install (DIRECTORY DESTINATION ${GVM_LOG_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_DATA_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_SYSCONF_DIR})
install (DIRECTORY
  DESTINATION ${OPENVAS_SYSCONF_DIR}/gnupg
  DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE)
install (DIRECTORY
  DESTINATION ${OPENVAS_STATE_DIR}/gnupg
  DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE)
