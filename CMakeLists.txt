cmake_minimum_required(VERSION 2.8.12)

project(KCrash)

find_package(ECM 0.0.12 REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH} ${ECM_KDE_MODULE_DIR})

set(REQUIRED_QT_VERSION 5.2.0)
find_package(Qt5 ${REQUIRED_QT_VERSION} CONFIG REQUIRED Core)
include(KDEInstallDirs)
include(KDEFrameworkCompilerSettings)
include(KDECMakeSettings)

if (NOT APPLE)
    find_package(X11)
endif()

set(HAVE_X11 ${X11_FOUND})

include(FeatureSummary)
include(GenerateExportHeader)
include(ECMSetupVersion)
include(ECMGenerateHeaders)

set(KF5_VERSION "4.98.0")
ecm_setup_version(${KF5_VERSION} VARIABLE_PREFIX KCrash
                        VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/kcrash_version.h"
                        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/KF5CrashConfigVersion.cmake"
                        SOVERSION 5)

if(NOT kdelibs_SOURCE_DIR)
  find_package(KF5CoreAddons ${KF5_VERSION} REQUIRED)
  find_package(KF5WindowSystem ${KF5_VERSION} REQUIRED)
endif()

if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/po)
  include(ECMCreateQmFromPoFiles)
  ecm_create_qm_from_po_files(
    PO_DIR po
    POT_NAME kcrash5.pot
    DATA_INSTALL_SUB_DIR kcrash
    CREATE_LOADER kcrash_QM_LOADER
  )
endif()

add_subdirectory(src)
add_subdirectory(autotests)

# create a Config.cmake and a ConfigVersion.cmake file and install them
set(CMAKECONFIG_INSTALL_DIR "${CMAKECONFIG_INSTALL_PREFIX}/KF5Crash")

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
  DESTINATION ${INCLUDE_INSTALL_DIR} COMPONENT Devel
)

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
