cmake_minimum_required(VERSION 3.16)
project(argus_agent CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP QUIET libpcap)
endif()
if(NOT PCAP_FOUND)
    find_path(PCAP_INCLUDE_DIRS NAMES pcap.h)
    find_library(PCAP_LIBRARIES NAMES pcap wpcap)
    if(NOT PCAP_INCLUDE_DIRS OR NOT PCAP_LIBRARIES)
        message(FATAL_ERROR "libpcap headers/library not found. Install libpcap-dev on Linux, or Npcap SDK on Windows.")
    endif()
endif()

add_executable(argus_agent
    src/main.cpp
    src/parser.cpp
    src/flow.cpp
    src/sender.cpp
)

target_include_directories(argus_agent PRIVATE ${PCAP_INCLUDE_DIRS} src)
target_link_libraries(argus_agent PRIVATE ${PCAP_LIBRARIES})
if(UNIX)
    target_link_libraries(argus_agent PRIVATE pthread)
endif()
target_compile_options(argus_agent PRIVATE -Wall -Wextra)
