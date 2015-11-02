/* This file is part of the KDE libraries
    Copyright (c) 2013 David Faure <faure@kde.org>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public License
    along with this library; see the file COPYING.LIB.  If not, write to
    the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA 02110-1301, USA.
*/

#include <QProcess>
#include <QFile>
#include <QTest>
#include <QSignalSpy>
#include <QDebug>

class KCrashTest : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void initTestCase() {
        // Don't bring up drkonqi
        qputenv("KDE_DEBUG", "1");
    }
    void testAutoRestart();
    void testEmergencySave();

};

static const char s_logFileName[] = "kcrashtest_log";

static QByteArray readLogFile()
{
    QFile logFile(QFile::encodeName(s_logFileName));
    if (!logFile.open(QIODevice::ReadOnly)) {
        return QByteArray();
    }
    return logFile.readAll();
}

static void startCrasher(const QByteArray &flag, const QByteArray &expectedOutput)
{
    QFile::remove(QFile::encodeName(s_logFileName));

    QProcess proc;
    QString processName;
#ifdef Q_OS_WIN
    QVERIFY(QFile::exists("./test_crasher.exe"));
    processName = "test_crasher.exe";
#else
    QVERIFY(QFile::exists("./test_crasher"));
    processName = QStringLiteral("./test_crasher");
#endif
    //qDebug() << proc.args();
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("ASAN_OPTIONS"), QStringLiteral("handle_segv=0,poison_heap=0")); // Disable ASAN
    proc.setProcessEnvironment(env);
    proc.start(processName, QStringList() << flag);
    bool ok = proc.waitForFinished();
    QVERIFY(ok);

    QByteArray logData;
    for (int i = 0; i < 50; ++i) {
        logData = readLogFile();
        if (logData == expectedOutput) {
            return;
        }
        QTest::qSleep(100);
    }
    qDebug() << proc.readAllStandardError();
    QCOMPARE(QString(logData), QString(expectedOutput));
}

void KCrashTest::testAutoRestart()
{
    startCrasher("AR", "starting AR\nautorestarted AR\n");
}

void KCrashTest::testEmergencySave()
{
    startCrasher("ES", "starting ES\nsaveFunction called\n");
}

QTEST_MAIN(KCrashTest)

#include "kcrashtest.moc"
