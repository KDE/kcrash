/*
 * Copyright (C) 2016 Harald Sitter <sitter@kde.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "coreconfig_p.h"

#include <QFile>

#include <config-kcrash.h>

namespace KCrash {

CoreConfig::CoreConfig(const QString &path)
    : m_supported(false)
    , m_process(false)
{
#ifndef KCRASH_CORE_PATTERN_RAISE
    return; // Leave everything false unless enabled.
#endif
     QFile file(path);
     if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
         return;
     }
     char first = 0;
     if (!file.getChar(&first)) {
         return;
     }
     m_supported = true;
     m_process = first == '|';
}

bool CoreConfig::isProcess() const
{
    return m_supported && m_process;
}

} // namespace KCrash
