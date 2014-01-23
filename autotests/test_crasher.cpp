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

#include <QApplication>
#include <QFile>
#include <QDebug>
#include <kcrash.h>
#ifdef Q_OS_UNIX
#include <sys/resource.h> // setrlimit
#endif

QFile output;

void saveFunction(int)
{
    output.write("saveFunction called\n");
    output.flush();
}

int main(int argc, char **argv)
{
    QApplication app(argc, argv);

    const QStringList args = app.arguments();
    QByteArray flag = args.count() > 1 ? args.at(1).toLatin1() : QByteArray();

    if (flag == "AR") { // auto restart
        KCrash::setFlags(KCrash::AutoRestart);
    } else if (flag == "ES") { // emergency save
        KCrash::setEmergencySaveFunction(saveFunction);
    }

#ifdef Q_OS_UNIX
    // No core file
    struct rlimit rlp;
    rlp.rlim_cur = 0;
    rlp.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rlp) != 0) {
        qDebug() << strerror(errno);
    }
#endif

    output.setFileName("kcrashtest_log");
    if (!output.open(QIODevice::WriteOnly | QIODevice::Append))
        return 1;
    if (qgetenv("KCRASH_AUTO_RESTARTED").isEmpty()) {
        output.write("starting ");
        output.write(flag);
        output.write("\n");
        output.flush();
        // CRASH!
        delete (char*)0xdead;
    } else {
        output.write("autorestarted ");
        output.write(flag);
        output.write("\n");
        output.close();
    }

    return 0;
}

