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

configure_file (VERSION.in ${PROJECT_VERSION})
configure_file (src/sqlite_log_conf.cmake_in ${CMAKE_SOURCE_DIR}/build/src/sqlite_log.conf)
configure_file (tools/mageni-manage-certs.in ${CMAKE_SOURCE_DIR}/build/tools/mageni-manage-certs @ONLY)
configure_file (src/pwpolicy.conf.in ${CMAKE_SOURCE_DIR}/build/src/pwpolicy.conf)

set (HARDENING_FLAGS            "-Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fstack-protector")
set (LINKER_HARDENING_FLAGS     "-Wl,-z,relro -Wl,-z,now")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall -D_BSD_SOURCE -D_ISOC99_SOURCE -D_SVID_SOURCE -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 ${CODE_ANALYSIS}")
set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Wno-error -Wshadow ${COVERAGE_FLAGS}")
set (CMAKE_C_FLAGS_RELEASE      "${CMAKE_C_FLAGS_RELEASE} ${HARDENING_FLAGS}")
set (C_FLAGS_DEBUG_GVMD         "-Wredundant-decls")

add_subdirectory (src)

install (DIRECTORY DESTINATION ${GVMD_STATE_DIR})

install (FILES ${CMAKE_SOURCE_DIR}/build/src/sqlite_log.conf
         DESTINATION ${GVM_SYSCONF_DIR})

install (FILES ${CMAKE_SOURCE_DIR}/build/src/pwpolicy.conf
         DESTINATION ${GVM_SYSCONF_DIR})

install (FILES ${CMAKE_SOURCE_DIR}/build/tools/mageni-manage-certs
         DESTINATION ${BINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)