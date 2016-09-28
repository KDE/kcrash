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

#include <QTest>

#include "../src/coreconfig.cpp"

class CoreConfigTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void initTestCase() {}

    void testExec()
    {
        KCrash::CoreConfig c(QFINDTESTDATA("core_patterns/exec"));
#ifdef KCRASH_CORE_PATTERN_RAISE
        QCOMPARE(c.isProcess(), true);
#else
        QCOMPARE(c.isProcess(), false);
#endif
    }

    void testNoFile()
    {
        KCrash::CoreConfig c("/meow/kitteh/meow");
        QCOMPARE(c.isProcess(), false);
    }

    void testNoExec()
    {
        KCrash::CoreConfig c(QFINDTESTDATA("core_patterns/no-exec"));
        QCOMPARE(c.isProcess(), false);
    }
};

QTEST_MAIN(CoreConfigTest)

#include "coreconfigtest.moc"
