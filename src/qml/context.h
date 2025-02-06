// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL
// SPDX-FileCopyrightText: 2025 Harald Sitter <sitter@kde.org>

#pragma once

#include <QQmlEngine>
#include <QQuickItem>

class CrashContext : public QQuickItem
{
    Q_OBJECT
    QML_ELEMENT
public:
    using QQuickItem::QQuickItem;

    void classBegin() override;
    void componentComplete() override;

private:
    void loadData();
};
