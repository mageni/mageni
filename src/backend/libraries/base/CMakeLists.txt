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

include_directories (${GLIB_INCLUDE_DIRS})

set (FILES array.c credentials.c cvss.c drop_privileges.c hosts.c logging.c
           networking.c nvti.c pidfile.c prefs.c proctitle.c pwpolicy.c
           settings.c strings.c)

set (HEADERS array.h credentials.h cvss.h drop_privileges.h hosts.h logging.h
             networking.h nvti.h pidfile.h prefs.h proctitle.h pwpolicy.h
             settings.h strings.h)

set (LIBGVM_BASE_NAME )
add_library (mageni_base_shared SHARED ${FILES})
set_target_properties (mageni_base_shared PROPERTIES OUTPUT_NAME "mageni_base")
set_target_properties (mageni_base_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (mageni_base_shared PROPERTIES SOVERSION "${PROJECT_VERSION}")
set_target_properties (mageni_base_shared PROPERTIES VERSION "${PROJECT_VERSION}")
set_target_properties (mageni_base_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")
target_link_libraries (mageni_base_shared LINK_PRIVATE ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})

set (LIBGVM_BASE_NAME
     ${LIBGVM_BASE_NAME}
     PARENT_SCOPE)

if (MAGENI_PID_DIR)
  add_definitions (-DMAGENI_PID_DIR="${MAGENI_PID_DIR}")
endif (MAGENI_PID_DIR)

if (MAGENI_SYSCONF_DIR)
  add_definitions (-DMAGENI_SYSCONF_DIR="${MAGENI_SYSCONF_DIR}")
endif (MAGENI_SYSCONF_DIR)

configure_file (libmageni_base.pc.in ${CMAKE_BINARY_DIR}/libmageni_base.pc @ONLY)

install (DIRECTORY DESTINATION ${MAGENI_PID_DIR})

install (FILES ${CMAKE_BINARY_DIR}/libmageni_base.pc
         DESTINATION ${LIBDIR}/pkgconfig)

install (TARGETS mageni_base_shared
  RUNTIME DESTINATION ${BINDIR}
  LIBRARY DESTINATION ${LIBDIR}
  ARCHIVE DESTINATION ${LIBDIR}
  PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/mageni/base")
