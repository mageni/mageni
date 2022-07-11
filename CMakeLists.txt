cmake_minimum_required (VERSION 3.10.2)

set (PROJECT_VERSION_MAJOR "1")
set (PROJECT_VERSION_MINOR "1")
set (PROJECT_VERSION_PATCH "0")
set (PROJECT_VERSION_TWEAK "0")
set (MGNI_DATABASE_VERSION "206")
set (GVMD_DATABASE_VERSION "206")

project (MGN VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}.${PROJECT_VERSION_TWEAK})

if (CODE_ANALYSIS MATCHES Yes)
    set (CODE_ANALYSIS "-fanalyzer")
    message (STATUS "Code Analysis On")
else()
    message (STATUS "Code Analysis Off")
endif()

if (CMAKE_BUILD_TYPE MATCHES Debug)
    message (STATUS "Debug build")
    set (CMAKE_BUILD_TYPE Debug)
elseif (CMAKE_BUILD_TYPE MATCHES Release)
    message (STATUS "Release build")
    set (CMAKE_BUILD_TYPE Release)
else (NOT CMAKE_BUILD_TYPE)
    message (STATUS "Release build")
    set (CMAKE_BUILD_TYPE Release)
endif ()

execute_process (COMMAND sudo chown yeshua:yeshua -R ${PROJECT_SOURCE_DIR}/)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    message (STATUS "64-bit is supported.")
else ()
    message (SEND_ERROR "Only 64-bit is supported." )
endif ()

set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include (${CMAKE_MODULE_PATH}/FindLinux.cmake)
include (${CMAKE_MODULE_PATH}/IncludeHeaders.cmake)

message (STATUS "Software: ${PROJECT_NAME}")
message (STATUS "Version: ${PROJECT_VERSION}")
message (STATUS "Homepage: ${PROJECT_HOMEPAGE_URL}")
message (STATUS "Description: ${PROJECT_DESCRIPTION}")

if (POLICY CMP0005)
    cmake_policy (SET CMP0005 NEW)
endif (POLICY CMP0005)

if (POLICY CMP0054)
    cmake_policy (SET CMP0054 NEW)
endif (POLICY CMP0054)

if (POLICY CMP0048)
    cmake_policy (SET CMP0048 NEW)
endif (POLICY CMP0048)

set (LIBMAGENI_NASL_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/scanner/nasl/")
set (LIBMAGENI_MISC_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/scanner/misc/")
set (LIBMAGENI_SSH_INCLUDE_HEADERS  "/usr/local/include/libssh/")
set (LIBMAGENI_MOSP_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/libraries/osp/")
set (LIBMAGENI_MSMP_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/libraries/gmp/")
set (LIBMAGENI_BASE_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/libraries/base/")
set (LIBMAGENI_UTIL_INCLUDE_HEADERS "${CMAKE_SOURCE_DIR}/backend/libraries/util/")

set (LIBMAGENI_NASL "-L${CMAKE_SOURCE_DIR}/build/backend/scanner/nasl -lmageni_nasl")
set (LIBMAGENI_MISC "-L${CMAKE_SOURCE_DIR}/build/backend/scanner/misc -lmageni_misc")
set (LIBMAGENI_MSMP "-L${CMAKE_SOURCE_DIR}/build/backend/libraries/gmp -lmageni_gmp")
set (LIBMAGENI_MOSP "-L${CMAKE_SOURCE_DIR}/build/backend/libraries/osp -lmageni_osp")
set (LIBMAGENI_UTIL "-L${CMAKE_SOURCE_DIR}/build/backend/libraries/util -lmageni_util")
set (LIBMAGENI_BASE "-L${CMAKE_SOURCE_DIR}/build/backend/libraries/base -lmageni_base")

set (NVT_TIMEOUT "60")
set (KSBA_MIN_VERSION "1.0.7")
set (GPGME_MIN_VERSION "1.1.2")
set (SCANNER_NVT_TIMEOUT "12000")
set (GMP_VERSION ${PROJECT_VERSION})
set (GVMD_VERSION "${PROJECT_VERSION}")
set (OPENVASSD_VERSION "${PROJECT_VERSION}")
set (NVTICACHE_STR "nvticache${PROJECT_VERSION}")
#set (GVMD_DATABASE_VERSION ${MGNI_DATABASE_VERSION})
set (GVMD_SCAP_DATABASE_VERSION ${MGNI_DATABASE_VERSION})
set (GVMD_CERT_DATABASE_VERSION ${MGNI_DATABASE_VERSION})

add_definitions (-DNVTICACHE_STR="${NVTICACHE_STR}")

message (STATUS "Install path: ${CMAKE_INSTALL_PREFIX}")

include (FindPkgConfig)
find_package (Threads REQUIRED)
find_package (BISON 2.5 REQUIRED)

pkg_check_modules (ZLIB REQUIRED zlib>=1.2.8)
pkg_check_modules (GIO REQUIRED gio-2.0>=2.42)
pkg_check_modules (UUID REQUIRED uuid>=2.25.0)
pkg_check_modules (LIBXML REQUIRED libxml-2.0)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules (LIBSSH REQUIRED libssh>=0.6.0)
pkg_check_modules (REDIS REQUIRED hiredis>=0.10.1)
pkg_check_modules (GNUTLS REQUIRED gnutls>=3.2.15)
pkg_check_modules (LIBICAL REQUIRED libical>=1.00)
pkg_check_modules (SQLITE3 REQUIRED sqlite3>=3.8.3)

find_library (GPGME gpgme)
if (NOT GPGME)
    message (SEND_ERROR "The gpgme library is required.")
else (NOT GPGME)
    execute_process (COMMAND gpgme-config --version
            OUTPUT_VARIABLE GPGME_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    if (GPGME_VERSION VERSION_LESS GPGME_MIN_VERSION)
        message (SEND_ERROR "The gpgme library >= ${GPGME_MIN_VERSION} is required.")
    else (GPGME_VERSION VERSION_LESS GPGME_MIN_VERSION)
        execute_process (COMMAND gpgme-config --libs
                OUTPUT_VARIABLE GPGME_LDFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
        execute_process (COMMAND gpgme-config --cflags
                OUTPUT_VARIABLE GPGME_CFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FILE_OFFSET_BITS=64 -DLARGEFILE_SOURCE=1")
        string (REPLACE "-I" "" GPGME_INCLUDE_DIRS "${GPGME_CFLAGS}")
        message (STATUS "Found ${GPGME}")
    endif (GPGME_VERSION VERSION_LESS GPGME_MIN_VERSION)
endif (NOT GPGME)

find_library (GCRYPT gcrypt)
if (NOT GCRYPT)
    message (SEND_ERROR "The libgcrypt library is required.")
else (NOT GCRYPT)
    execute_process (COMMAND libgcrypt-config --libs
            OUTPUT_VARIABLE GCRYPT_LDFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process (COMMAND libgcrypt-config --cflags
            OUTPUT_VARIABLE GCRYPT_CFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process (COMMAND libgcrypt-config --version
            OUTPUT_VARIABLE GCRYPT_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    message (STATUS "Found ${GCRYPT}, version ${GCRYPT_VERSION}")
    if (GCRYPT_VERSION VERSION_LESS "1.6")
        message (SEND_ERROR "libgcrypt 1.6 or greater is required")
    endif (GCRYPT_VERSION VERSION_LESS "1.6")
endif (NOT GCRYPT)

find_library (SNMP netsnmp)
if (NOT SNMP)
    message (STATUS "No netsnmp library found - netsnmp support disabled")
else (NOT SNMP)
    execute_process (COMMAND net-snmp-config --libs
            OUTPUT_VARIABLE SNMP_LDFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE)
endif (NOT SNMP)

find_library (KSBA ksba)
if (NOT KSBA)
    message (SEND_ERROR "The ksba library is required.")
else (NOT KSBA)
    execute_process (COMMAND ksba-config --version
            OUTPUT_VARIABLE KSBA_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    message (STATUS "Found ksba ${KSBA_VERSION}...")
    if (${KSBA_VERSION} VERSION_LESS ${KSBA_MIN_VERSION})
        message (SEND_ERROR "The ksba library >= ${KSBA_MIN_VERSION} is required.")
    else (${KSBA_VERSION} VERSION_LESS ${KSBA_MIN_VERSION})
        execute_process (COMMAND ksba-config --libs
                OUTPUT_VARIABLE KSBA_LDFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
        execute_process (COMMAND ksba-config --cflags
                OUTPUT_VARIABLE KSBA_CFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif (${KSBA_VERSION} VERSION_LESS ${KSBA_MIN_VERSION})
endif (NOT KSBA)

find_library (PCAP pcap)
if (NOT PCAP)
    message (SEND_ERROR "No pcap library found")
else (NOT PCAP)
    find_program (PCAP_CONFIG pcap-config)
    if (PCAP_CONFIG)
        message (STATUS "Looking for pcap-config... ${PCAP_CONFIG}")
        execute_process (COMMAND pcap-config --libs
                OUTPUT_VARIABLE PCAP_LDFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
        execute_process (COMMAND pcap-config --cflags
                OUTPUT_VARIABLE PCAP_CFLAGS
                OUTPUT_STRIP_TRAILING_WHITESPACE)
    else (PCAP_CONFIG)
        message (STATUS "pcap-config not found, using default.")
        set (PCAP_LDFLAGS "-L/usr/lib -lpcap")
        set (PCAP_CFLAGS "-I/usr/include")
    endif (PCAP_CONFIG)
endif (NOT PCAP)

if (NOT SYSCONFDIR)
    set (SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc")
endif (NOT SYSCONFDIR)

if (NOT EXEC_PREFIX)
    set (EXEC_PREFIX "${CMAKE_INSTALL_PREFIX}")
endif (NOT EXEC_PREFIX)

if (NOT BINDIR)
    set (BINDIR "${EXEC_PREFIX}/bin")
endif (NOT BINDIR)

if (NOT SBINDIR)
    set (SBINDIR "${EXEC_PREFIX}/sbin")
endif (NOT SBINDIR)

if (NOT LIBDIR)
    set (LIBDIR "${EXEC_PREFIX}/lib")
endif (NOT LIBDIR)

if (NOT LOCALSTATEDIR)
    set (LOCALSTATEDIR "${CMAKE_INSTALL_PREFIX}/var")
endif (NOT LOCALSTATEDIR)

if (NOT INCLUDEDIR)
    set (INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif (NOT INCLUDEDIR)

if (NOT DATADIR)
    set (DATADIR "${CMAKE_INSTALL_PREFIX}/share")
endif (NOT DATADIR)

if (NOT GSAD_PID_DIR)
    set (GSAD_PID_DIR "${LOCALSTATEDIR}/run")
endif (NOT GSAD_PID_DIR)

if (NOT GVM_STATE_DIR)
    set (GVM_STATE_DIR "${LOCALSTATEDIR}/lib/mageni")
else (NOT GVM_STATE_DIR)
    set (GVM_STATE_DIR "${GVM_STATE_DIR}")
endif (NOT GVM_STATE_DIR)

if (NOT GVM_LOG_DIR)
    set (GVM_LOG_DIR "${LOCALSTATEDIR}/log/mageni")
else (NOT GVM_LOG_DIR)
    set (GVM_LOG_DIR "${GVM_LOG_DIR}")
endif (NOT GVM_LOG_DIR)

set (GSAD_DATA_DIR "${DATADIR}/mageni/websvr")
set (GSAD_LOCALE_SUBDIR "locale")
set (GSAD_LOCALE_DIR "${GSAD_DATA_DIR}/${GSAD_LOCALE_SUBDIR}")
set (GSAD_CHROOT_LOCALE_DIR "/${GSAD_LOCALE_SUBDIR}")

if (NOT GVM_SERVER_CERTIFICATE)
    set (GVM_SERVER_CERTIFICATE "${GVM_STATE_DIR}/CA/servercert.pem")
else (NOT GVM_SERVER_CERTIFICATE)
    set (GVM_SERVER_CERTIFICATE "${GVM_SERVER_CERTIFICATE}")
endif (NOT GVM_SERVER_CERTIFICATE)

if (NOT GVM_SERVER_KEY)
    set (GVM_SERVER_KEY "${GVM_STATE_DIR}/private/CA/serverkey.pem")
else (NOT GVM_SERVER_KEY)
    set (GVM_SERVER_KEY "${GVM_SERVER_KEY}")
endif (NOT GVM_SERVER_KEY)

if (NOT GVM_CA_CERTIFICATE)
    set (GVM_CA_CERTIFICATE "${GVM_STATE_DIR}/CA/cacert.pem")
else (NOT GVM_CA_CERTIFICATE)
    set (GVM_CA_CERTIFICATE "${GVM_CA_CERTIFICATE}")
endif (NOT GVM_CA_CERTIFICATE)

set (GSAD_CONFIG_DIR         "${SYSCONFDIR}/mageni/")

if (NOT GVM_RUN_DIR)
    set (GVM_RUN_DIR      "${LOCALSTATEDIR}/run")
endif (NOT GVM_RUN_DIR)

if (NOT GVM_SYSCONF_DIR)
    set (GVM_SYSCONF_DIR "${SYSCONFDIR}/mageni")
endif (NOT GVM_SYSCONF_DIR)

if (NOT GVM_PID_DIR)
    set (GVM_PID_DIR "${LOCALSTATEDIR}/run")
endif (NOT GVM_PID_DIR)

if (NOT OPENVAS_RUN_DIR)
    set (OPENVAS_RUN_DIR "${LOCALSTATEDIR}/run")
endif (NOT OPENVAS_RUN_DIR)

set (OPENVAS_DATA_DIR    "${DATADIR}/mageni")
set (OPENVAS_STATE_DIR   "${LOCALSTATEDIR}/lib/mageni")
set (GVM_LOG_DIR         "${LOCALSTATEDIR}/log/mageni")
set (OPENVAS_SYSCONF_DIR "${SYSCONFDIR}/mageni")
set (GVM_SYSCONF_DIR     "${SYSCONFDIR}/mageni")
set (GVM_SCANNER_CERTIFICATE "${GVM_STATE_DIR}/CA/servercert.pem")
set (GVM_SCANNER_KEY         "${GVM_STATE_DIR}/private/CA/serverkey.pem")
set (GVM_CLIENT_CERTIFICATE  "${GVM_STATE_DIR}/CA/clientcert.pem")
set (GVM_CLIENT_KEY          "${GVM_STATE_DIR}/private/CA/clientkey.pem")
set (GVM_CA_CERTIFICATE      "${GVM_STATE_DIR}/CA/cacert.pem")
set (GVM_DATA_DIR     "${DATADIR}/mageni")
set (GVM_SCAP_RES_DIR "${GVM_DATA_DIR}/scap")
set (GVM_CERT_RES_DIR "${GVM_DATA_DIR}/cert")
set (GVM_CA_DIR       "${GVMD_STATE_DIR}/trusted_certs")
set (OPENVASSD_CONF     "${OPENVAS_SYSCONF_DIR}/vscand.conf")

if (NOT OPENVAS_NVT_DIR)
    set (OPENVAS_NVT_DIR     "/usr/local/var/lib/mageni/plugins")
endif (NOT OPENVAS_NVT_DIR)

if (NOT MAGENI_TMP_DIR)
    set (MAGENI_TMP_DIR     "/usr/local/var/lib/mageni/tmp")
endif (NOT MAGENI_TMP_DIR)

if (NOT PLUGINS_TMP_DIR)
    set (PLUGINS_TMP_DIR     "/usr/local/var/lib/mageni/tmp/plugins")
endif (NOT PLUGINS_TMP_DIR)

if (NOT FRONTEND_TMP_DIR)
    set (FRONTEND_TMP_DIR     "/usr/local/var/lib/mageni/tmp/frontend")
endif (NOT FRONTEND_TMP_DIR)

if (NOT BACKEND_TMP_DIR)
    set (BACKEND_TMP_DIR     "/usr/local/var/lib/mageni/tmp/backend")
endif (NOT BACKEND_TMP_DIR)

if (NOT ETC_CROND_DIR)
    set (ETC_CROND_DIR     "/etc/cron.d/")
endif (NOT ETC_CROND_DIR)

if (NOT ETC_SUDOERS_DIR)
    set (ETC_SUDOERS_DIR     "/etc/sudoers.d/")
endif (NOT ETC_SUDOERS_DIR)

if (NOT CERT_DIR)
    set (CERT_DIR     "${OPENVAS_STATE_DIR}/cert-data")
endif (NOT CERT_DIR)

if (NOT SCAP_DIR)
    set (SCAP_DIR     "${OPENVAS_STATE_DIR}/scap-data")
endif (NOT SCAP_DIR)

if (NOT GVM_ACCESS_KEY_DIR)
    set (GVM_ACCESS_KEY_DIR "${GVM_SYSCONF_DIR}")
endif (NOT GVM_ACCESS_KEY_DIR)

if (NOT GVM_NVT_DIR)
    set (GVM_NVT_DIR "${LOCALSTATEDIR}/lib/mageni/plugins/")
endif (NOT GVM_NVT_DIR)

if (NOT GVM_CERT_DATA_DIR)
    set (GVM_CERT_DATA_DIR "${GVM_STATE_DIR}/cert-data")
endif (NOT GVM_CERT_DATA_DIR)

if (NOT GVM_SCAP_DATA_DIR)
    set (GVM_SCAP_DATA_DIR "${GVM_STATE_DIR}/scap-data")
endif (NOT GVM_SCAP_DATA_DIR)

if (NOT GVMD_DATA_DIR)
    set (GVMD_DATA_DIR  "${GVM_DATA_DIR}/sqlite")
endif (NOT GVMD_DATA_DIR)

if (NOT GVMD_STATE_DIR)
    set (GVMD_STATE_DIR  "${GVM_STATE_DIR}/sqlite")
endif (NOT GVMD_STATE_DIR)

add_subdirectory (backend/libraries)
add_subdirectory (backend/scanner)
add_subdirectory (backend/api)
