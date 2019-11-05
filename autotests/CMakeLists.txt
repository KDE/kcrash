remove_definitions(-DQT_NO_CAST_FROM_ASCII)

include(ECMAddTests)

find_package(Qt5Test ${REQUIRED_QT_VERSION} CONFIG QUIET)
find_package(Qt5Widgets ${REQUIRED_QT_VERSION} CONFIG QUIET)

if(NOT Qt5Test_FOUND)
    message(STATUS "Qt5Test not found, autotests will not be built.")
    return()
endif()

if(NOT Qt5Widgets_FOUND)
    message(STATUS "Qt5Widgets not found, autotests will not be built.")
    return()
endif()

# Include src so we have access to config-kcrash.h
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../src)

#ecm_add_tests(
#  coreconfigtest.cpp
#  kcrashtest.cpp
#  LINK_LIBRARIES Qt5::Core Qt5::Test
#)

#add_executable(test_crasher test_crasher.cpp)
#target_link_libraries(test_crasher Qt5::Widgets KF5::Crash)
#ecm_mark_as_test(test_crasher)
##ecm_mark_nongui_executable(test_crasher)
