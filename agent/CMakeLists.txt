cmake_minimum_required(VERSION 3.16)
project(argus_agent CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(argus_agent
    src/main.cpp
    src/parser.cpp
    src/flow.cpp
    src/sender.cpp
)

target_include_directories(argus_agent PRIVATE ${PCAP_INCLUDE_DIRS} src)
target_link_libraries(argus_agent PRIVATE ${PCAP_LIBRARIES} pthread)
target_compile_options(argus_agent PRIVATE -Wall -Wextra)
