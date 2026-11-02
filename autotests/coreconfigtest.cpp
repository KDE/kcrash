/*
    SPDX-FileCopyrightText: 2016-2026 Harald Sitter <sitter@kde.org>

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
#if KCRASH_CORE_PATTERN_RAISE
        QCOMPARE(c.isFile(), false);
        QCOMPARE(c.isCoredumpd(), true);
#else
        QCOMPARE(c.isFile(), true);
        QCOMPARE(c.isCoredumpd(), false);
#endif
    }

    void testExecNot()
    {
#if !KCRASH_CORE_PATTERN_RAISE
        QSKIP("Not useful when opting out of re-raising.")
#endif

        KCrash::CoreConfig c(QFINDTESTDATA("core_patterns/exec-apport"));
        QCOMPARE(c.isFile(), false);
        QCOMPARE(c.isCoredumpd(), false);
    }

    void testNoFile()
    {
        KCrash::CoreConfig c(QStringLiteral("/meow/kitteh/meow"));
        QCOMPARE(c.isFile(), false);
    }

    void testNoExec()
    {
        KCrash::CoreConfig c(QFINDTESTDATA("core_patterns/no-exec"));
        QCOMPARE(c.isFile(), true);
    }

    void testSocket()
    {
        KCrash::CoreConfig c(QFINDTESTDATA("core_patterns/socket"));
        QCOMPARE(c.isFile(), false);
        QCOMPARE(c.isCoredumpd(), true);
    }

    void testFilename()
    {
        KCrash::CoreConfig c(QFINDTESTDATA("core_patterns/filename"));
        QCOMPARE(c.isFile(), true);
        QCOMPARE(c.isCoredumpd(), false);
    }
};

QTEST_MAIN(CoreConfigTest)

#include "coreconfigtest.moc"
