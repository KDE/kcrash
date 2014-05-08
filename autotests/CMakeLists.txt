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

macro(KCRASH_UNIT_TESTS)
   foreach(_testname ${ARGN})
      ecm_add_test(kcrashtest.cpp TEST_NAME kcrash-kcrashtest LINK_LIBRARIES Qt5::Core Qt5::Test)
   endforeach(_testname)
endmacro(KCRASH_UNIT_TESTS)

kcrash_unit_tests(
  kcrashtest
)

add_executable(test_crasher test_crasher.cpp)
target_link_libraries(test_crasher Qt5::Widgets KF5::Crash)
ecm_mark_as_test(test_crasher)

