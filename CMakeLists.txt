project(jail)
cmake_minimum_required(VERSION 3.15)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules/")
include(GNUInstallDirs)
include(Harden)
include(EnableWarnings)
include(AddressSanitizer)
set(THREADS_PREFER_PTHREAD_FLAG ON)

# Crée des variables avec les fichiers à compiler
set(SRCS
    src/main.c
    src/jail.c
    src/parser.c
    src/run.c
    )
add_executable(jail ${SRCS})

find_package(PkgConfig)

pkg_check_modules(LIBXML2 REQUIRED libxml-2.0)
target_include_directories(jail PUBLIC ${LIBXML2_INCLUDE_DIRS})
target_link_libraries(jail ${LIBXML2_LIBRARIES})

pkg_check_modules(LIBCAP REQUIRED libcap)
target_include_directories(jail PUBLIC ${LIBCAP_INCLUDE_DIRS})
target_link_libraries(jail ${LIBCAP_LIBRARIES})

pkg_check_modules(LIBCAPNG REQUIRED libcap-ng)
target_include_directories(jail PUBLIC ${LIBCAPNG_INCLUDE_DIRS})
target_link_libraries(jail ${LIBCAPNG_LIBRARIES})

pkg_check_modules(EXPAT REQUIRED expat)
target_include_directories(jail PUBLIC ${EXPAT_INCLUDE_DIRS})
target_link_libraries(jail ${EXPAT_LIBRARIES})

target_include_directories(jail PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/inc)
set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -Wformat -Werror"
)

#install(FILES jail DESTINATION ${CMAKE_INSTALL_BINDIR})
