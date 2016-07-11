cmake_minimum_required(VERSION 2.6)

PROJECT(mountd C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

FIND_PATH(ubus_include_dir libubus.h)
INCLUDE_DIRECTORIES(${ubus_include_dir})

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

ADD_EXECUTABLE(mountd main.c log.c sys.c autofs.c mount.c timer.c signal.c ucix.c led.c fs.c ucix.c)
TARGET_LINK_LIBRARIES(mountd uci ubox)

INSTALL(TARGETS mountd
	RUNTIME DESTINATION sbin
)
