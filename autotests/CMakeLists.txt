remove_definitions(-DQT_NO_CAST_FROM_ASCII)

include(ECMMarkAsTest)

find_package(Qt5Test ${REQUIRED_QT_VERSION} CONFIG QUIET)

if(NOT Qt5Test_FOUND)
    message(STATUS "Qt5Test not found, autotests will not be built.")
    return()
endif()

macro(KCRASH_UNIT_TESTS)
   foreach(_testname ${ARGN})
      add_executable(${_testname} ${_testname}.cpp)
      add_test(kcrash-${_testname} ${_testname})
      target_link_libraries(${_testname} Qt5::Core Qt5::Test)
      ecm_mark_as_test(${_testname})
   endforeach(_testname)
endmacro(KCRASH_UNIT_TESTS)

kcrash_unit_tests(
  restarttest
)

add_executable(restarttest_crasher restarttest_crasher.cpp)
target_link_libraries(restarttest_crasher Qt5::Widgets KF5::Crash)
ecm_mark_as_test(restarttest_crasher)

