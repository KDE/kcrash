/*
    SPDX-FileCopyrightText: 2016 Harald Sitter <sitter@kde.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <QTest>

#include "../src/coreconfig.cpp"

class CoreConfigTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void initTestCase()
    {
    }

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
