set (SMB_INCLUDES
        ${CMAKE_SOURCE_DIR}/libsmb/samba
        ${CMAKE_SOURCE_DIR}/libsmb/samba/include
        ${CMAKE_SOURCE_DIR}/libsmb/samba/lib
        ${CMAKE_SOURCE_DIR}/libsmb/samba/lib/appweb/ejs
        ${CMAKE_SOURCE_DIR}/libsmb/samba/lib/crypto
        ${CMAKE_SOURCE_DIR}/libsmb/samba/lib/ldb/include
        ${CMAKE_SOURCE_DIR}/libsmb/samba/lib/tdb/include
        ${CMAKE_SOURCE_DIR}/libsmb/samba/lib/replace
        ${CMAKE_SOURCE_DIR}/libsmb/samba/ntvfs
        ${CMAKE_SOURCE_DIR}/libsmb/samba/param
        ${CMAKE_SOURCE_DIR}/libsmb/samba/lib/talloc
        ${CMAKE_SOURCE_DIR}/libsmb/samba/librpc/ndr
        ${CMAKE_SOURCE_DIR}/build/libsmb/samba/
        ${CMAKE_SOURCE_DIR}/libsmb/winexe
        ${CMAKE_SOURCE_DIR}/libsmb/samba/winexe/winexesvc/
        ${CMAKE_SOURCE_DIR}/build/libsmb
        )

include_directories(${SMB_INCLUDES})
