# Copyright (C) 2016-2018 Greenbone Networks GmbH
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

# CMake find module for yarn package manager

find_program (YARN_EXECUTABLE NAMES yarn
  HINTS
  $ENV{NODE_DIR}
  PATH_SUFFIXES bin
  DOC "yarn node package manager binary"
)

include (FindPackageHandleStandardArgs)

if (YARN_EXECUTABLE)
  execute_process(COMMAND ${YARN_EXECUTABLE} --version
                  OUTPUT_VARIABLE _VERSION
                  RESULT_VARIABLE
                  _YARN_VERSION_RESULT)
  if (NOT _YARN_VERSION_RESULT)
    string (REPLACE "\n" "" YARN_VERSION_STRING "${_VERSION}")
    string (REPLACE "v" "" YARN_VERSION_STRING "${YARN_VERSION_STRING}")
    string (REPLACE "." ";" _VERSION_LIST "${YARN_VERSION_STRING}")
    list (GET _VERSION_LIST 0 YARN_VERSION_MAJOR)
    list (GET _VERSION_LIST 1 YARN_VERSION_MINOR)
    list (GET _VERSION_LIST 2 YARN_VERSION_PATCH)
  endif ()
endif (YARN_EXECUTABLE)

find_package_handle_standard_args (Yarn
  REQUIRED_VARS YARN_EXECUTABLE
  VERSION_VAR YARN_VERSION_STRING
  FAIL_MESSAGE "Could not find yarn executable. Please install yarn (see https://yarnpkg.com/)"
)

mark_as_advanced (YARN_EXECUTABLE)
