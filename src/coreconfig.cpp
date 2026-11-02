/*
    SPDX-FileCopyrightText: 2016-2026 Harald Sitter <sitter@kde.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include "coreconfig_p.h"

#include <QFile>

#include <config-kcrash.h>

using namespace Qt::StringLiterals;

namespace KCrash
{
CoreConfig::CoreConfig(const QString &path)
{
#if !KCRASH_CORE_PATTERN_RAISE
    return; // Leave everything false unless enabled.
#endif

    // https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#core-pattern

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return;
    }
    char first = 0;
    if (!file.getChar(&first)) {
        return;
    }
    m_supported = true;

    if (first == '|') { // process
        m_isFile = false;
        if (file.readLine().contains("systemd-coredump"_ba)) {
            m_coredumpd = true;
        }
    }

    if (first == '@') { // socket
        m_isFile = false;
        if (file.readLine().contains("systemd/coredumpd"_ba)) {
            m_coredumpd = true;
        }
    }
}

bool CoreConfig::isFile() const
{
    return m_supported && m_isFile;
}

bool CoreConfig::isCoredumpd() const
{
    return m_coredumpd;
}

} // namespace KCrash
