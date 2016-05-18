include(FindPkgConfig)

#Standard stuff
cmake_minimum_required(VERSION 2.6)
project(multi-client)

find_package(Threads)

set(VALID_INIT_DAEMONS upstart systemd)

if (NOT DEFINED INIT_DAEMON)
    set(INIT_DAEMON "upstart")
    message(STATUS "INIT_DAEMON is not defined, select upstart by default")
else()
    set(VALID 0)
    foreach(daemon ${VALID_INIT_DAEMONS})
        if (INIT_DAEMON STREQUAL ${daemon})
            set(VALID 1)
            break()
	endif()
    endforeach()

    if (NOT ${VALID})
        message(STATUS "INIT_DAEMON defined in cmdline is not valid, select upstart by default")
        set(INIT_DAEMON "upstart")
    endif()
endif()

message(STATUS "INIT_DAEMON is set to " ${INIT_DAEMON})

#Library check
pkg_check_modules(LIBMNL REQUIRED libmnl>=1.0.1-1)
pkg_check_modules(LIBYAML REQUIRED yaml-0.1>=0.1.4)

#Static way of locating library
find_library(LIBIW_LIBRARY iw)

if(NOT LIBIW_LIBRARY)
    message(FATAL_ERROR "Libiw could not be found")
endif(NOT LIBIW_LIBRARY)

set(CMAKE_C_FLAGS "-g -O")

#Debian package generator
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "1")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Kristian R. Evensen <kristrev@celerway.com>")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/files/${INIT_DAEMON}/postinst;${CMAKE_CURRENT_SOURCE_DIR}/files/${INIT_DAEMON}/prerm")
set (CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
include(CPack)

add_executable(multi_client multi_multicast.c multi_core.c multi_dhcp_main.c
    multi_dhcp_network.c multi_dhcp_protocol.c multi_link_core.c
    multi_link_filter.c multi_link_netlink.c multi_common.h multi_core.h
    multi_dhcp_common.h multi_dhcp_constants.h multi_dhcp_main.h
    multi_dhcp_network.h multi_dhcp_protocol.h multi_link_core.h
    multi_link_filter.h multi_link_netlink.h multi_link_shared.h multi_shared.h
    multi_macros.h multi_cmp.h multi_cmp.c)
target_link_libraries(multi_client ${LIBMNL_LIBRARIES})
target_link_libraries(multi_client ${LIBYAML_LIBRARIES})
target_link_libraries(multi_client ${LIBIW_LIBRARY})
target_link_libraries(multi_client ${CMAKE_THREAD_LIBS_INIT})
install(TARGETS multi_client RUNTIME DESTINATION /usr/local/sbin)

if (INIT_DAEMON STREQUAL "systemd")
    install(FILES ${PROJECT_SOURCE_DIR}/files/systemd/multi.service DESTINATION
           /lib/systemd/system/ PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
           RENAME multi.service)
    install(FILES ${PROJECT_SOURCE_DIR}/files/multi.yml DESTINATION
           /etc/multi.yml PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
elseif(INIT_DAEMON STREQUAL "upstart")
    install(FILES ${PROJECT_SOURCE_DIR}/files/upstart/multi.conf DESTINATION
            /etc/init/ PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
            RENAME multi.conf)
endif()
