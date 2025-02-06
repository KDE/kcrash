# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: 2025 Harald Sitter <sitter@kde.org>

ecm_add_qml_module(kcrashplugin URI org.kde.crash VERSION 1.0 GENERATE_PLUGIN_SOURCE INSTALLED_PLUGIN_TARGET KF6::kcrashplugin)
target_sources(kcrashplugin PRIVATE context.cpp)
target_link_libraries(kcrashplugin PRIVATE Qt::Quick Qt::GuiPrivate KF6Crash)
ecm_finalize_qml_module(kcrashplugin DESTINATION ${KDE_INSTALL_QMLDIR})
