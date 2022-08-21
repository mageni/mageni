# SPDX-FileCopyrightText: Copyright (C) 2011-2018 Greenbone Networks GmbH
# SPDX-FileContributor: Mageni Security LLC
#
# SPDX-License-Identifier: GPL-2.0-or-later

set (BINARY_NAME "mageni-vscand")

add_executable (
  ${BINARY_NAME}
  attack.c
  comm.c
  hosts.c
  nasl_plugins.c
  ntp.c
  openvassd.c
  otp.c
  pluginlaunch.c
  pluginload.c
  pluginscheduler.c
  plugs_req.c
  processes.c
  sighand.c
  utils.c
)

set_target_properties (${BINARY_NAME} PROPERTIES LINKER_LANGUAGE C)

include_directories (
  ${GLIB_INCLUDE_DIRS}
  ${LIBMAGENI_NASL_INCLUDE_HEADERS}
  ${LIBMAGENI_BASE_INCLUDE_HEADERS}
  ${LIBMAGENI_UTIL_INCLUDE_HEADERS}
  ${LIBMAGENI_MISC_INCLUDE_HEADERS}
)

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Wno-error  -Wextra")

if (SCANNER_VERSION)
  add_definitions (-DSCANNER_VERSION="${SCANNER_VERSION}")
endif (SCANNER_VERSION)

add_definitions (-DPREFIX="${CMAKE_INSTALL_PREFIX}")

if (MAGENI_NVT_DIR)
  add_definitions (-DMAGENI_NVT_DIR="${MAGENI_NVT_DIR}")
endif (MAGENI_NVT_DIR)

if (MAGENI_CONF_DIR)
  add_definitions (-DMAGENI_CONF_DIR="${MAGENI_CONF_DIR}")
endif (MAGENI_CONF_DIR)

if (MAGENI_STATE_DIR)
  add_definitions (-DMAGENI_STATE_DIR="${MAGENI_STATE_DIR}")
endif (MAGENI_STATE_DIR)

if (MAGENI_PID_DIR)
  add_definitions (-DMAGENI_PID_DIR="${MAGENI_PID_DIR}")
endif (MAGENI_PID_DIR)

if (SYSCONFDIR)
  add_definitions (-DSYSCONFDIR="${SYSCONFDIR}")
endif (SYSCONFDIR)

if (MAGENI_SYSCONF_DIR)
  add_definitions (-DMAGENI_SYSCONF_DIR="${MAGENI_SYSCONF_DIR}")
endif (MAGENI_SYSCONF_DIR)

if (MAGENI_DATA_DIR)
  add_definitions (-DMAGENI_DATA_DIR="${MAGENI_DATA_DIR}")
endif (MAGENI_DATA_DIR)

if (NVT_TIMEOUT)
  add_definitions (-DNVT_TIMEOUT=${NVT_TIMEOUT})
endif (NVT_TIMEOUT)

if (SCANNER_NVT_TIMEOUT)
  add_definitions (-DSCANNER_NVT_TIMEOUT=${SCANNER_NVT_TIMEOUT})
endif (SCANNER_NVT_TIMEOUT)

if (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
  set (EXECINFO_LDFLAGS "execinfo")
endif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")

target_link_libraries (
  ${BINARY_NAME}
  ${LIBMAGENI_UTIL}
  ${LIBMAGENI_NASL}
  ${LIBMAGENI_MISC}
  ${LIBMAGENI_BASE}
  ${GLIB_LDFLAGS}
  ${GCRYPT_LDFLAGS}
  ${EXECINFO_LDFLAGS}
  ${LINKER_HARDENING_FLAGS}
)

install (TARGETS ${BINARY_NAME}
         RUNTIME DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
         GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_SOURCE_DIR}/build/src/vscand_log.conf
         DESTINATION ${MAGENI_SYSCONF_DIR})

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/redis_config_examples/redis_0.conf
        ${CMAKE_SOURCE_DIR}/build/doc/redis_config_examples/redis_3.conf
        ${CMAKE_SOURCE_DIR}/build/doc/redis_config_examples/redis_4.conf
        DESTINATION ${DATADIR}/doc/mageni-scanner/redis_config/)

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-sqlite.service
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-vscand.service
        DESTINATION /lib/systemd/system/)

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/ssl-params.conf
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/self-signed.conf
        DESTINATION /etc/nginx/snippets/)

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni
        DESTINATION /etc/nginx/sites-enabled/)

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/dhparam.pem
        DESTINATION /etc/nginx/)

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-sqlite.service
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-vscand.service
        DESTINATION ${DATADIR}/doc/mageni-scanner/redis_config/)

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-scanner-start
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-sqlite-start
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-feed-update
        ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-uninstaller
        DESTINATION /usr/local/sbin
        PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                    GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/varinit/donotremove
        DESTINATION ${MAGENI_NVT_DIR})

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/varinit/donotremove
        DESTINATION ${PLUGINS_TMP_DIR})

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/varinit/donotremove
        DESTINATION ${FRONTEND_TMP_DIR})

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/varinit/donotremove
        DESTINATION ${BACKEND_TMP_DIR})

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/varinit/donotremove
        DESTINATION ${MAGENI_TMP_DIR})

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/varinit/donotremove
        DESTINATION ${MAGENI_PID_DIR})

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/varinit/donotremove
        DESTINATION ${MAGENI_LOG_DIR})

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/sudoersd/mageni-service-init
        DESTINATION ${ETC_SUDOERS_DIR})

install (FILES
        ${CMAKE_SOURCE_DIR}/build/doc/crond/mageni-service-update
        DESTINATION ${ETC_CROND_DIR})

#install (FILES ${CMAKE_BINARY_DIR}/doc/openvassd.8
#         DESTINATION ${DATADIR}/man/man8 )