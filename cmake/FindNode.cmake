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

# CMake find module for nodejs

find_program (NODE_EXECUTABLE NAMES node nodejs
  HINTS
  $ENV{NODE_DIR}
  PATH_SUFFIXES bin
  DOC "node.js interpreter"
)

include (FindPackageHandleStandardArgs)

if (NODE_EXECUTABLE)
  execute_process(COMMAND ${NODE_EXECUTABLE} --version
                  OUTPUT_VARIABLE _VERSION
                  RESULT_VARIABLE
                  _NODE_VERSION_RESULT)
  if (NOT _NODE_VERSION_RESULT)
    string (REPLACE "\n" "" NODE_VERSION_STRING "${_VERSION}")
    string (REPLACE "v" "" NODE_VERSION_STRING "${NODE_VERSION_STRING}")
    string (REPLACE "." ";" _VERSION_LIST "${NODE_VERSION_STRING}")
    list (GET _VERSION_LIST 0 NODE_VERSION_MAJOR)
    list (GET _VERSION_LIST 1 NODE_VERSION_MINOR)
    list (GET _VERSION_LIST 2 NODE_VERSION_PATCH)
  endif ()
endif (NODE_EXECUTABLE)

find_package_handle_standard_args (Node
  REQUIRED_VARS NODE_EXECUTABLE
  VERSION_VAR NODE_VERSION_STRING
)

mark_as_advanced (NODE_EXECUTABLE)
