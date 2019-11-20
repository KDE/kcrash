cmake_minimum_required(VERSION 3.5)

set(KF5_VERSION "5.65.0") # handled by release scripts
set(KF5_DEP_VERSION "5.64.0") # handled by release scripts
project(KCrash VERSION ${KF5_VERSION})

include(FeatureSummary)
find_package(ECM 5.64.0  NO_MODULE)
set_package_properties(ECM PROPERTIES TYPE REQUIRED DESCRIPTION "Extra CMake Modules." URL "https://projects.kde.org/projects/kdesupport/extra-cmake-modules")
feature_summary(WHAT REQUIRED_PACKAGES_NOT_FOUND FATAL_ON_MISSING_REQUIRED_PACKAGES)

set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

set(REQUIRED_QT_VERSION 5.11.0)
find_package(Qt5 ${REQUIRED_QT_VERSION} CONFIG REQUIRED Core)
include(KDEInstallDirs)
include(KDEFrameworkCompilerSettings NO_POLICY_SCOPE)
include(KDECMakeSettings)

if (NOT APPLE)
    find_package(X11)
endif()

set(HAVE_X11 ${X11_FOUND})


include(GenerateExportHeader)
include(ECMSetupVersion)
include(ECMGenerateHeaders)
include(ECMAddQch)

option(BUILD_QCH "Build API documentation in QCH format (for e.g. Qt Assistant, Qt Creator & KDevelop)" OFF)
add_feature_info(QCH ${BUILD_QCH} "API documentation in QCH format (for e.g. Qt Assistant, Qt Creator & KDevelop)")

ecm_setup_version(PROJECT VARIABLE_PREFIX KCrash
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/kcrash_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KF5CrashConfigVersion.cmake"
                        SOVERSION 5)

find_package(KF5CoreAddons ${KF5_DEP_VERSION} REQUIRED)
find_package(KF5WindowSystem ${KF5_DEP_VERSION} REQUIRED)

set(KCRASH_CORE_PATTERN_RAISE_DEFAULT ON)

option(KCRASH_CORE_PATTERN_RAISE
    "Enables raising signals to kernel core patterns (iff the pattern is a process). You may wish to not intall drkonqi if this can cause a UI conflict."
    ${KCRASH_CORE_PATTERN_RAISE_DEFAULT})
add_feature_info("Core Pattern Raising"
    KCRASH_CORE_PATTERN_RAISE
    "Raising signals to kernel core patterns (iff the pattern is a process). You may wish to not install drkonqi if this can cause a UI conflict. ${FEATURE_ADDENDUM}")

if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/po)
  include(ECMPoQmTools)
  ecm_install_po_files_as_qm(po)
endif()


add_definitions(-DQT_DISABLE_DEPRECATED_BEFORE=0x050d00)
add_definitions(-DKF_DISABLE_DEPRECATED_BEFORE_AND_AT=0x053f00)
add_definitions(-DQT_NO_FOREACH)
add_subdirectory(src)
if (BUILD_TESTING)
    add_subdirectory(autotests)
endif()

# create a Config.cmake and a ConfigVersion.cmake file and install them
set(CMAKECONFIG_INSTALL_DIR "${KDE_INSTALL_CMAKEPACKAGEDIR}/KF5Crash")

if (BUILD_QCH)
    ecm_install_qch_export(
        TARGETS KF5Crash_QCH
        FILE KF5CrashQchTargets.cmake
        DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
        COMPONENT Devel
    )
    set(PACKAGE_INCLUDE_QCHTARGETS "include(\"\${CMAKE_CURRENT_LIST_DIR}/KF5CrashQchTargets.cmake\")")
endif()

include(CMakePackageConfigHelpers)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/KF5CrashConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/KF5CrashConfig.cmake"
  INSTALL_DESTINATION  ${CMAKECONFIG_INSTALL_DIR}
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/KF5CrashConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/KF5CrashConfigVersion.cmake"
  DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
  COMPONENT Devel
)

install(EXPORT KF5CrashTargets DESTINATION "${CMAKECONFIG_INSTALL_DIR}" FILE KF5CrashTargets.cmake NAMESPACE KF5:: )

install(FILES
   ${CMAKE_CURRENT_BINARY_DIR}/kcrash_version.h
  DESTINATION ${KDE_INSTALL_INCLUDEDIR_KF5} COMPONENT Devel
)

install(FILES kcrash.categories  DESTINATION  ${KDE_INSTALL_LOGGINGCATEGORIESDIR})

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
