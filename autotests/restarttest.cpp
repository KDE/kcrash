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

class RestartTest : public QObject
{
    Q_OBJECT
public:
    RestartTest() {}

private Q_SLOTS:
    void testAutoRestart();

};

static const char s_logFileName[] = "restarttest_log";

static QByteArray checkRestartLog()
{
    QFile logFile(QFile::encodeName(s_logFileName));
    if (!logFile.open(QIODevice::ReadOnly)) {
        return QByteArray();
    }
    return logFile.readAll();
}

void RestartTest::testAutoRestart()
{
    QFile::remove(QFile::encodeName(s_logFileName));

    QProcess proc;
    QString processName;
#ifdef Q_OS_WIN
    QVERIFY(QFile::exists("./restarttest_crasher.exe"));
    processName = "restarttest_crasher.exe";
#else
    QVERIFY(QFile::exists("./restarttest_crasher"));
    processName = "./restarttest_crasher";
#endif
    //qDebug() << proc.args();
    proc.start(processName, QStringList() << "1");
    bool ok = proc.waitForFinished();
    QVERIFY(ok);

    //qDebug() << proc.readAllStandardError();

    QTRY_COMPARE(checkRestartLog().constData(), "starting 1\nautorestarted 1\n");
}

QTEST_MAIN(RestartTest)

#include "restarttest.moc"
