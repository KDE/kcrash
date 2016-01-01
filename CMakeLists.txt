cmake_minimum_required(VERSION 2.8.12)

project(KCrash)

include(FeatureSummary)
find_package(ECM 5.18.0  NO_MODULE)
set_package_properties(ECM PROPERTIES TYPE REQUIRED DESCRIPTION "Extra CMake Modules." URL "https://projects.kde.org/projects/kdesupport/extra-cmake-modules")
feature_summary(WHAT REQUIRED_PACKAGES_NOT_FOUND FATAL_ON_MISSING_REQUIRED_PACKAGES)

set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH} ${ECM_KDE_MODULE_DIR})

set(REQUIRED_QT_VERSION 5.3.0)
find_package(Qt5 ${REQUIRED_QT_VERSION} CONFIG REQUIRED Core)
include(KDEInstallDirs)
include(KDEFrameworkCompilerSettings)
include(KDECMakeSettings)

if (NOT APPLE)
    find_package(X11)
endif()

set(HAVE_X11 ${X11_FOUND})


include(GenerateExportHeader)
include(ECMSetupVersion)
include(ECMGenerateHeaders)

set(KF5_VERSION "5.18.0") # handled by release scripts
set(KF5_DEP_VERSION "5.18.0") # handled by release scripts
ecm_setup_version(${KF5_VERSION} VARIABLE_PREFIX KCrash
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/kcrash_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KF5CrashConfigVersion.cmake"
                        SOVERSION 5)

find_package(KF5CoreAddons ${KF5_DEP_VERSION} REQUIRED)
find_package(KF5WindowSystem ${KF5_DEP_VERSION} REQUIRED)

if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/po)
  include(ECMPoQmTools)
  ecm_install_po_files_as_qm(po)
endif()

add_subdirectory(src)
add_subdirectory(autotests)

# create a Config.cmake and a ConfigVersion.cmake file and install them
set(CMAKECONFIG_INSTALL_DIR "${KDE_INSTALL_CMAKEPACKAGEDIR}/KF5Crash")

include(ECMPackageConfigHelpers)

ecm_configure_package_config_file(
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

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
