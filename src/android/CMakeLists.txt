# SPDX-FileCopyrightText: 2026 Volker Krause <vkrause@kde.org>
# SPDX-License-Identifier: BSD-2-Clause

gradle_add_aar(kcrash_aar BUILDFILE ${CMAKE_CURRENT_SOURCE_DIR}/build.gradle NAME KF6Crash)
gradle_install_aar(kcrash_aar DESTINATION jar)

install(FILES KF6Crash-android-dependencies.xml DESTINATION ${KDE_INSTALL_LIBDIR} RENAME KF6Crash_${CMAKE_ANDROID_ARCH_ABI}-android-dependencies.xml)
