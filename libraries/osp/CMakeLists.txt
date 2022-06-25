# Most new code since 2020 by Mageni Security, LLC
# Copyright (C) 2015-2019 Greenbone Networks GmbH
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

set (FILES osp.c)

set (HEADERS osp.h)

add_library (mageni_osp_shared SHARED ${FILES})
set_target_properties (mageni_osp_shared PROPERTIES OUTPUT_NAME "mageni_osp")
set_target_properties (mageni_osp_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (mageni_osp_shared PROPERTIES SOVERSION "${PROJECT_VERSION}")
set_target_properties (mageni_osp_shared PROPERTIES VERSION "${PROJECT_VERSION}")
set_target_properties (mageni_osp_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")
target_link_libraries (mageni_osp_shared LINK_PRIVATE ${GLIB_LDFLAGS} ${LINKER_HARDENING_FLAGS})

configure_file (libmageni_osp.pc.in ${CMAKE_BINARY_DIR}/libmageni_osp.pc @ONLY)

install (FILES ${CMAKE_BINARY_DIR}/libmageni_osp.pc
         DESTINATION ${LIBDIR}/pkgconfig)

install (TARGETS mageni_osp_shared
  RUNTIME DESTINATION ${BINDIR}
  LIBRARY DESTINATION ${LIBDIR}
  ARCHIVE DESTINATION ${LIBDIR}
  PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/mageni/osp")