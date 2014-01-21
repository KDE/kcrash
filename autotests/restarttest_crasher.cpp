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

int main(int argc, char **argv)
{
    QApplication app(argc, argv);

    KCrash::setFlags(KCrash::AutoRestart | KCrash::AlwaysDirectly);

#ifdef Q_OS_UNIX
    // No core file
    struct rlimit rlp;
    rlp.rlim_cur = 0;
    rlp.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rlp) != 0) {
        qDebug() << strerror(errno);
    }
#endif

    QFile output("restarttest_log");
    if (!output.open(QIODevice::WriteOnly | QIODevice::Append))
        return 1;
    if (qgetenv("KCRASH_AUTO_RESTARTED").isEmpty()) {
        output.write("starting\n");
        output.close();
        // CRASH!
        delete (char*)0xdead;
    } else {
        output.write("autorestarted\n");
        output.close();
    }

    return 0;
}

