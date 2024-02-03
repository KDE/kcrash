cmake_minimum_required(VERSION 3.16)

set(KF_VERSION "5.115.0") # handled by release scripts
set(KF_DEP_VERSION "5.115.0") # handled by release scripts
project(KCrash VERSION ${KF_VERSION})

include(FeatureSummary)
find_package(ECM 5.115.0  NO_MODULE)
set_package_properties(ECM PROPERTIES TYPE REQUIRED DESCRIPTION "Extra CMake Modules." URL "https://commits.kde.org/extra-cmake-modules")
feature_summary(WHAT REQUIRED_PACKAGES_NOT_FOUND FATAL_ON_MISSING_REQUIRED_PACKAGES)

set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDEFrameworkCompilerSettings NO_POLICY_SCOPE)
include(KDECMakeSettings)
include(KDEGitCommitHooks)
include(ECMDeprecationSettings)

set(REQUIRED_QT_VERSION 5.15.2)
find_package(Qt${QT_MAJOR_VERSION} ${REQUIRED_QT_VERSION} CONFIG REQUIRED Core Gui)

if (UNIX AND NOT APPLE AND NOT ANDROID)
    option(WITH_X11 "Build with X11 integration" ON)
else()
    set(WITH_X11 OFF)
endif()

if (WITH_X11)
    find_package(X11 REQUIRED)
    if (QT_MAJOR_VERSION STREQUAL "5")
        find_package(Qt5 ${REQUIRED_QT_VERSION} CONFIG REQUIRED X11Extras)
    endif()
    set(HAVE_X11 TRUE)
endif()
find_package(Qt${QT_MAJOR_VERSION}Test ${REQUIRED_QT_VERSION} CONFIG REQUIRED)
include(GenerateExportHeader)
include(ECMSetupVersion)
include(ECMGenerateHeaders)
include(ECMAddQch)
include(ECMQtDeclareLoggingCategory)

option(BUILD_QCH "Build API documentation in QCH format (for e.g. Qt Assistant, Qt Creator & KDevelop)" OFF)
add_feature_info(QCH ${BUILD_QCH} "API documentation in QCH format (for e.g. Qt Assistant, Qt Creator & KDevelop)")

ecm_setup_version(PROJECT VARIABLE_PREFIX KCrash
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/src/kcrash_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KF5CrashConfigVersion.cmake"
                        SOVERSION 5)

find_package(KF5CoreAddons ${KF_DEP_VERSION} REQUIRED)

set(KCRASH_CORE_PATTERN_RAISE_DEFAULT ON)

option(KCRASH_CORE_PATTERN_RAISE
    "Enables raising signals to kernel core patterns (iff the pattern is a process). You may wish to not install drkonqi if this can cause a UI conflict."
    ${KCRASH_CORE_PATTERN_RAISE_DEFAULT})
add_feature_info("Core Pattern Raising"
    KCRASH_CORE_PATTERN_RAISE
    "Raising signals to kernel core patterns (iff the pattern is a process). You may wish to not install drkonqi if this can cause a UI conflict.")

ecm_set_disabled_deprecation_versions(
    QT 5.15.2
    KF 5.95.0
)

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
   ${CMAKE_CURRENT_BINARY_DIR}/src/kcrash_version.h
  DESTINATION ${KDE_INSTALL_INCLUDEDIR_KF}/KCrash COMPONENT Devel
)

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)

kde_configure_git_pre_commit_hook(CHECKS CLANG_FORMAT)
