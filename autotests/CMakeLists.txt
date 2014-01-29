remove_definitions(-DQT_NO_CAST_FROM_ASCII)

include(ECMMarkAsTest)

find_package(Qt5 ${REQUIRED_QT_VERSION} CONFIG REQUIRED Test Widgets)

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
      add_executable(${_testname} ${_testname}.cpp)
      add_test(kcrash-${_testname} ${_testname})
      target_link_libraries(${_testname} Qt5::Core Qt5::Test)
      ecm_mark_as_test(${_testname})
   endforeach(_testname)
endmacro(KCRASH_UNIT_TESTS)

kcrash_unit_tests(
  kcrashtest
)

add_executable(test_crasher test_crasher.cpp)
target_link_libraries(test_crasher Qt5::Widgets KF5::Crash)
ecm_mark_as_test(test_crasher)

