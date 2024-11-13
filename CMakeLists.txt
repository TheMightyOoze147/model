cmake_minimum_required(VERSION 3.14)

project(MyZMQApp VERSION 0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ZMQ REQUIRED libzmq)

include_directories(${ZMQ_INCLUDE_DIRS} include)

add_executable(MyZMQClient tests/client.c)
target_link_libraries(MyZMQClient ${ZMQ_LIBRARIES})

find_package(PkgConfig REQUIRED)
include_directories(${PCAP_INCLUDE_DIRS})
pkg_check_modules(PCAP REQUIRED libpcap)
add_executable(MyZMQServer tests/server.c)
target_link_libraries(MyZMQServer ${ZMQ_LIBRARIES} ${PCAP_LIBRARIES})