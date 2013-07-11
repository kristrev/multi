include(FindPkgConfig)

#Standard stuff
cmake_minimum_required(VERSION 2.6)
project(multi_client)

find_package(Threads)

#Library check
pkg_check_modules(GLIB2 REQUIRED glib-2.0>=2.32.3)
pkg_check_modules(LIBMNL REQUIRED libmnl>=1.0.1-1)
pkg_check_modules(LIBYAML REQUIRED yaml-0.1>=0.1.4)

#Static way of locating library
find_library(LIBIW_LIBRARY iw)

if(NOT LIBIW_LIBRARY)
    message(FATAL_ERROR "Libiw could not be found")
endif(NOT LIBIW_LIBRARY)

set(CMAKE_C_FLAGS "-g -O")

include_directories(${GLIB2_INCLUDE_DIRS})
add_executable(multi_client multi_multicast.c multi_core.c multi_dhcp_main.c
    multi_dhcp_network.c multi_dhcp_protocol.c multi_link_core.c
    multi_link_filter.c multi_link_netlink.c multi_common.h multi_core.h
    multi_dhcp_common.h multi_dhcp_constants.h multi_dhcp_main.h
    multi_dhcp_network.h multi_dhcp_protocol.h multi_link_core.h
    multi_link_filter.h multi_link_netlink.h multi_link_shared.h multi_shared.h
    multi_macros.h multi_cmp.h multi_cmp.c)
target_link_libraries(multi_client ${GLIB2_LIBRARIES})
target_link_libraries(multi_client ${LIBMNL_LIBRARIES})
target_link_libraries(multi_client ${LIBYAML_LIBRARIES})
target_link_libraries(multi_client ${LIBIW_LIBRARY})
target_link_libraries(multi_client ${CMAKE_THREAD_LIBS_INIT})
