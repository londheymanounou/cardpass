cmake_minimum_required(VERSION 3.16.0)
# The portable components (kdbx, totp, gen, ...) live one level up and are shared
# with the host tests in tests/host.
# APPEND: PlatformIO passes src/ in this variable
list(APPEND EXTRA_COMPONENT_DIRS ${CMAKE_CURRENT_LIST_DIR}/../components)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(cardpass)
