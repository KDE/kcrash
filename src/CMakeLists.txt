add_library(KF5Crash)
add_library(KF5::Crash ALIAS KF5Crash)

target_sources(KF5Crash PRIVATE
    coreconfig.cpp
    coreconfig_p.h
    kcrash.cpp
    kcrash.h
    metadata.cpp
    metadata_p.h
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config-kcrash.h.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/config-kcrash.h
)

ecm_qt_export_logging_category(
    IDENTIFIER LOG_KCRASH
    CATEGORY_NAME kf.crash
    OLD_CATEGORY_NAMES org.kde.kcrash
    DESCRIPTION "KCrash"
    EXPORT KCRASH
)

generate_export_header(KF5Crash BASE_NAME KCrash)

target_include_directories(KF5Crash INTERFACE "$<INSTALL_INTERFACE:${KDE_INSTALL_INCLUDEDIR_KF}/KCrash>")

target_link_libraries(KF5Crash PUBLIC Qt${QT_MAJOR_VERSION}::Core)
target_link_libraries(KF5Crash PRIVATE KF5::CoreAddons KF5::WindowSystem)

# FIXME: It is needed to work around undefined reference error on FreeBSD
# caused by --no-undefined because the `environ' variable does not exist
# in libc.so.7 -- it is in crt1.o, and so not available to shared
# libraries. We just drop the normal no-undefined flag for library building
# here, on the assumption that Linux CI will catch any *actual* undefineds.
if (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    string(REPLACE "-Wl,--no-undefined" "" CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
endif ()

if(WITH_X11)
    if (TARGET Qt5::X11Extras)
        set(_qt_x11_libs Qt5::X11Extras)
    elseif (TARGET Qt6::Gui)
        set(_qt_x11_libs Qt6::GuiPrivate) # Gui/private/qtx11extras_p.h
    endif()

    target_link_libraries(KF5Crash PRIVATE X11::X11 ${_qt_x11_libs})
endif()

set_target_properties(KF5Crash PROPERTIES VERSION   ${KCrash_VERSION}
                                          SOVERSION ${KCrash_SOVERSION}
                                          EXPORT_NAME Crash
)

ecm_generate_headers(KCrash_HEADERS
  HEADER_NAMES
  KCrash

  REQUIRED_HEADERS KCrash_HEADERS
)

install(TARGETS KF5Crash EXPORT KF5CrashTargets ${KF5_INSTALL_TARGETS_DEFAULT_ARGS})

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/kcrash_export.h
  ${KCrash_HEADERS}
  DESTINATION ${KDE_INSTALL_INCLUDEDIR_KF}/KCrash COMPONENT Devel
)

ecm_qt_install_logging_categories(
    EXPORT KCRASH
    FILE kcrash.categories
    DESTINATION ${KDE_INSTALL_LOGGINGCATEGORIESDIR}
)

if(BUILD_QCH)
    ecm_add_qch(
        KF5Crash_QCH
        NAME KCrash
        BASE_NAME KF5Crash
        VERSION ${KF_VERSION}
        ORG_DOMAIN org.kde
        SOURCES # using only public headers, to cover only public API
            ${KCrash_HEADERS}
        MD_MAINPAGE "${CMAKE_SOURCE_DIR}/README.md"
        LINK_QCHS
            Qt5Core_QCH
        INCLUDE_DIRS
            ${CMAKE_CURRENT_BINARY_DIR}
        BLANK_MACROS
            KCRASH_EXPORT
            KCRASH_DEPRECATED
            KCRASH_DEPRECATED_EXPORT
        TAGFILE_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        QCH_INSTALL_DESTINATION ${KDE_INSTALL_QTQCHDIR}
        COMPONENT Devel
    )
endif()

include(ECMGeneratePriFile)
ecm_generate_pri_file(BASE_NAME KCrash LIB_NAME KF5Crash DEPS "core" FILENAME_VAR PRI_FILENAME INCLUDE_INSTALL_DIR ${KDE_INSTALL_INCLUDEDIR_KF}/KCrash)
install(FILES ${PRI_FILENAME} DESTINATION ${ECM_MKSPECS_INSTALL_DIR})
