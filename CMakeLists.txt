cmake_minimum_required(VERSION 3.10)

PROJECT(mountd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-unused-result -Wno-format-truncation)

FIND_PATH(uci_include_dir uci.h)
INCLUDE_DIRECTORIES(${uci_include_dir})

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

ADD_EXECUTABLE(mountd main.c log.c sys.c autofs.c mount.c timer.c signal.c ucix.c led.c fs.c ucix.c)
TARGET_LINK_LIBRARIES(mountd uci ubox)

INSTALL(TARGETS mountd
	RUNTIME DESTINATION sbin
)
