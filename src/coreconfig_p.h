/*
    SPDX-FileCopyrightText: 2016-2026 Harald Sitter <sitter@kde.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#ifndef KCRASH_CORECONFIG_H
#define KCRASH_CORECONFIG_H

#include <QString>

namespace KCrash
{
class CoreConfig
{
public:
    CoreConfig(const QString &path = QStringLiteral("/proc/sys/kernel/core_pattern"));

    //! Returns true if the core pattern is a legacy file path (if this is false it could be a socket or a process pattern)
    [[nodiscard]] bool isFile() const;

    //! Returns true if the core pattern is definitely a systemd-coredump pattern.
    [[nodiscard]] bool isCoredumpd() const;

    // NOTE: should this need expansion beyond coredumpd please refactor to enum

private:
    bool m_supported = false;
    bool m_isFile = true;
    bool m_coredumpd = false;
};

} // namespace KCrash

#endif // KCRASH_CORECONFIG_H
