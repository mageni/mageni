# SPDX-FileCopyrightText: Copyright (C) 2010-2019 Greenbone Networks GmbH
# SPDX-FileContributor: Mageni Security LLC
#
# SPDX-License-Identifier: GPL-2.0-or-later

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

if (MAGENI_STATE_DIR)
  add_definitions (-DMAGENI_STATE_DIR="${MAGENI_STATE_DIR}")
endif (MAGENI_STATE_DIR)

if (MAGENI_DATA_DIR)
  add_definitions (-DMAGENI_DATA_DIR="${MAGENI_DATA_DIR}")
endif (MAGENI_DATA_DIR)

if (MAGENI_SYSCONF_DIR)
  add_definitions (-DMAGENI_SYSCONF_DIR="${MAGENI_SYSCONF_DIR}")
endif (MAGENI_SYSCONF_DIR)

install (TARGETS mageni_misc_shared
         RUNTIME DESTINATION ${BINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR})

install (DIRECTORY DESTINATION ${MAGENI_LOG_DIR})
install (DIRECTORY DESTINATION ${MAGENI_DATA_DIR})
install (DIRECTORY DESTINATION ${MAGENI_SYSCONF_DIR})
install (DIRECTORY
  DESTINATION ${MAGENI_SYSCONF_DIR}/gnupg
  DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE)
install (DIRECTORY
  DESTINATION ${MAGENI_STATE_DIR}/gnupg
  DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE)
