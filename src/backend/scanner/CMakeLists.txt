# SPDX-FileCopyrightText: Copyright (C) 2011-2019 Greenbone Networks GmbH
# SPDX-FileContributor: Mageni Security LLC
#
# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required (VERSION 3.0)

configure_file (doc/systemd/mageni-sqlite.service.in ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-sqlite.service @ONLY)
configure_file (doc/systemd/mageni-vscand.service.in ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-vscand.service @ONLY)
configure_file (doc/systemd/mageni-nginx.in ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni @ONLY)
configure_file (doc/systemd/dhparam-pem.in ${CMAKE_SOURCE_DIR}/build/doc/systemd/dhparam.pem @ONLY)
configure_file (doc/systemd/mageni-nginx-self-signed-conf.in ${CMAKE_SOURCE_DIR}/build/doc/systemd/self-signed.conf @ONLY)
configure_file (doc/systemd/mageni-nginx-ssl-params-conf.in ${CMAKE_SOURCE_DIR}/build/doc/systemd/ssl-params.conf @ONLY)
configure_file (doc/redis_config_examples/redis_m_0.in ${CMAKE_SOURCE_DIR}/build/doc/redis_config_examples/redis_0.conf @ONLY)
configure_file (doc/redis_config_examples/redis_3_2.conf.in ${CMAKE_SOURCE_DIR}/build/doc/redis_config_examples/redis_3.conf @ONLY)
configure_file (doc/redis_config_examples/redis_4_0.conf.in ${CMAKE_SOURCE_DIR}/build/doc/redis_config_examples/redis_4.conf @ONLY)
configure_file (doc/systemd/mageni-feed-update.in ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-feed-update @ONLY)
configure_file (doc/systemd/mageni-scanner-start.in ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-scanner-start @ONLY)
configure_file (doc/systemd/mageni-sqlite-start.in ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-sqlite-start @ONLY)
configure_file (doc/systemd/mageni-uninstaller.in ${CMAKE_SOURCE_DIR}/build/doc/systemd/mageni-uninstaller @ONLY)
configure_file (doc/sudoersd/mageni-service-init.in ${CMAKE_SOURCE_DIR}/build/doc/sudoersd/mageni-service-init @ONLY)
configure_file (doc/crond/mageni-service-update.in ${CMAKE_SOURCE_DIR}/build/doc/crond/mageni-service-update @ONLY)
configure_file (doc/varinit/init.in ${CMAKE_SOURCE_DIR}/build/doc/varinit/donotremove @ONLY)
configure_file (core/vscand_log_conf.cmake_in ${CMAKE_SOURCE_DIR}/build/src/vscand_log.conf)
configure_file (VERSION.in ${PROJECT_VERSION} @ONLY)

set (HARDENING_FLAGS            "-Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fstack-protector")
set (LINKER_HARDENING_FLAGS     "-Wl,-z,relro -Wl,-z,now")
set (GPGME_C_FLAGS              "-D_FILE_OFFSET_BITS=64 -DLARGEFILE_SOURCE=1")
set (CMAKE_C_FLAGS_RELEASE      "${CMAKE_C_FLAGS_RELEASE} ${HARDENING_FLAGS}")
set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG}")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${GPGME_C_FLAGS} -Wall -Wno-error -D_BSD_SOURCE -D_ISOC99_SOURCE -D_SVID_SOURCE -D_DEFAULT_SOURCE -fPIC ${CODE_ANALYSIS}")

add_subdirectory (misc)
add_subdirectory (nasl)
add_subdirectory (core)