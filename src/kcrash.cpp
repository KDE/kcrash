/*
 * This file is part of the KDE Libraries
 * Copyright (C) 2000 Timo Hummel <timo.hummel@sap.com>
 *                    Tom Braun <braunt@fh-konstanz.de>
 * Copyright 2009 KDE e.V.
 *   By Adriaan de Groot <groot@kde.org>
 * Copyright (C) 2010 George Kiagiadakis <kiagiadakis.george@gmail.com>
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

#include "kcrash.h"

#include <config-kcrash.h>

#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <qplatformdefs.h>
#ifndef Q_OS_WIN
#include <sys/resource.h>
#include <sys/un.h>
#include <errno.h>
#else
#include <qt_windows.h>
#endif
#ifdef Q_OS_LINUX
#include <sys/prctl.h>
#endif

#include <kaboutdata.h>
#include <kstartupinfo.h>

#include <QDebug>
#include <QGuiApplication>
#include <QtCore/QFileInfo>
#include <QtCore/QDir>
#include <QStandardPaths>
#include <QThread>
#include <QLibraryInfo>

#include <QLoggingCategory>
Q_DECLARE_LOGGING_CATEGORY(LOG_KCRASH)

// logging category for this framework, default: log stuff >= info
Q_LOGGING_CATEGORY(LOG_KCRASH, "org.kde.kcrash", QtInfoMsg)

#if HAVE_X11
#include <qx11info_x11.h>
#include <X11/Xlib.h>
#endif

#ifdef Q_OS_SOLARIS
// Solaris has built-in, thread-safe, async-signal-safe, mechanisms
// to walk the stack in the case of a crash, as well as (optionally)
// to demangle C++ symbol names. In the case of a crash, dump a stack
// trace to stderr before starting drKonqui (because what drKonqui is
// going to do is -- through a complicated process -- print the
// exact same information, but less reliably).
#include <ucontext.h>
#endif

#include "coreconfig_p.h"

// Copy from klauncher_cmds
typedef struct {
    long cmd;
    long arg_length;
}   kcrash_launcher_header;

#define LAUNCHER_OK 4
#define LAUNCHER_EXEC_NEW 12

namespace KCrash
{
KCRASH_EXPORT bool loadedByKdeinit = false;
void setApplicationFilePath(const QString &filePath);
}

static KCrash::HandlerType s_emergencySaveFunction = nullptr;
static KCrash::HandlerType s_crashHandler = nullptr;
static char *s_appName = nullptr;
static char *s_autoRestartCommand = nullptr;
static char *s_appPath = nullptr;
static int s_autoRestartArgc = 0;
static char **s_autoRestartCommandLine = nullptr;
static char *s_drkonqiPath = nullptr;
static char *s_kdeinit_socket_file = nullptr;
static KCrash::CrashFlags s_flags = nullptr;
static int s_launchDrKonqi = -1; // -1=initial value 0=disabled 1=enabled
Q_GLOBAL_STATIC(KCrash::CoreConfig, s_coreConfig)

static void kcrashInitialize()
{
    KCrash::initialize();
}
Q_COREAPP_STARTUP_FUNCTION(kcrashInitialize)

namespace KCrash
{
void setApplicationFilePath(const QString &filePath);
void startProcess(int argc, const char *argv[], bool waitAndExit);

#if defined(Q_OS_WIN)
LONG WINAPI win32UnhandledExceptionFilter(_EXCEPTION_POINTERS *exceptionInfo);
#endif
}

void KCrash::initialize()
{
    if (s_launchDrKonqi == 0) { // disabled by the program itself
        return;
    }
    const QStringList args = QCoreApplication::arguments();
    if (!qEnvironmentVariableIsSet("KDE_DEBUG")
        && !qEnvironmentVariableIsSet("KCRASH_AUTO_RESTARTED")) {
        // enable drkonqi
        KCrash::setDrKonqiEnabled(true);
    } else {
        qCDebug(LOG_KCRASH) << "KCrash disabled through environment.";
    }

    KCrash::setApplicationFilePath(QCoreApplication::applicationFilePath());

    s_coreConfig(); // Initialize.
}

void
KCrash::setEmergencySaveFunction(HandlerType saveFunction)
{
    s_emergencySaveFunction = saveFunction;

    /*
     * We need at least the default crash handler for
     * emergencySaveFunction to be called
     */
    if (s_emergencySaveFunction && !s_crashHandler) {
        setCrashHandler(defaultCrashHandler);
    }
}

KCrash::HandlerType
KCrash::emergencySaveFunction()
{
    return s_emergencySaveFunction;
}

// Set the default crash handler in 10 seconds
// This is used after an autorestart, the second instance of the application
// is started with KCRASH_AUTO_RESTARTED=1, and we
// set the defaultCrashHandler (to handle autorestart) after 10s.
// The delay is to see if we stay up for more than 10s time, to avoid infinite
// respawning if the app crashes on startup.
class KCrashDelaySetHandler : public QObject
{
public:
    KCrashDelaySetHandler()
    {
        startTimer(10000); // 10 s
    }
protected:
    void timerEvent(QTimerEvent *event) Q_DECL_OVERRIDE
    {
        if (!s_crashHandler) { // not set meanwhile
            KCrash::setCrashHandler(KCrash::defaultCrashHandler);
        }
        killTimer(event->timerId());
        this->deleteLater();
    }
};

void
KCrash::setFlags(KCrash::CrashFlags flags)
{
    s_flags = flags;
    if (s_flags & AutoRestart) {
        // We need at least the default crash handler for autorestart to work.
        if (!s_crashHandler) {
            if (qEnvironmentVariableIsSet("KCRASH_AUTO_RESTARTED")) {
                new KCrashDelaySetHandler;
            } else {
                setCrashHandler(defaultCrashHandler);
            }
        }
    }
}

void KCrash::setApplicationFilePath(const QString &filePath)
{
    const int pos = filePath.lastIndexOf(QLatin1Char('/'));
    const QString appName = filePath.mid(pos + 1);
    const QString appPath = filePath.left(pos); // could be empty, in theory

    s_appName = qstrdup(QFile::encodeName(appName).constData());
    s_appPath = qstrdup(QFile::encodeName(appPath).constData());

    // Prepare the auto-restart command
    delete[] s_autoRestartCommand;
    s_autoRestartCommand = qstrdup(QFile::encodeName(filePath).constData());

    QStringList args = QCoreApplication::arguments();
    args[0] = filePath; // replace argv[0] with full path above
    delete[] s_autoRestartCommandLine;
    s_autoRestartArgc = args.count();
    s_autoRestartCommandLine = new char *[args.count() + 1];
    for (int i = 0; i < args.count(); ++i) {
        s_autoRestartCommandLine[i] = qstrdup(QFile::encodeName(args.at(i)).constData());
    }
    s_autoRestartCommandLine[args.count()] = nullptr;
}

void KCrash::setDrKonqiEnabled(bool enabled)
{
    const int launchDrKonqi = enabled ? 1 : 0;
    if (s_launchDrKonqi == launchDrKonqi) {
        return;
    }
    s_launchDrKonqi = launchDrKonqi;
    if (s_launchDrKonqi && !s_drkonqiPath) {
        // search paths
        const QStringList paths = QStringList()
            << QFile::decodeName(qgetenv("LIBEXEC_PATH")).split(QLatin1Char(':'), QString::SkipEmptyParts) // env var is used first
            << QCoreApplication::applicationDirPath() // then look where our application binary is located
            << QLibraryInfo::location(QLibraryInfo::LibraryExecutablesPath) // look where libexec path is (can be set in qt.conf)
            << QFile::decodeName(CMAKE_INSTALL_FULL_LIBEXECDIR); // look at our installation location
        const QString exec = QStandardPaths::findExecutable(QStringLiteral("drkonqi"), paths);
        if (exec.isEmpty()) {
            qCDebug(LOG_KCRASH) << "Could not find drkonqi in search paths:" << paths;
            s_launchDrKonqi = 0;
        } else {
            s_drkonqiPath = qstrdup(qPrintable(exec));
        }
    }

    //we need at least the default crash handler to launch drkonqi
    if (s_launchDrKonqi && !s_crashHandler) {
        setCrashHandler(defaultCrashHandler);
    }
}

bool KCrash::isDrKonqiEnabled()
{
    return s_launchDrKonqi == 1;
}

// The following functions copy&pasted from kinit/wrapper.cpp :
// (which copied it from kdeinit/kinit.cpp)
static const char* displayEnvVarName_c()
{
    // Can't use QGuiApplication::platformName() here, there is no app instance.
#if HAVE_X11
    return "DISPLAY";
#elif defined(Q_OS_OSX)
    return "MAC_DISPLAY";
#elif defined(Q_OS_WIN)
    return "WIN_DISPLAY";
#endif
}

// adapted from kdeinit/kinit.cpp
// WARNING, if you change the socket name, adjust kinit.cpp too
static const QString generate_socket_file_name()
{

    QByteArray display = qgetenv(displayEnvVarName_c());
    if (display.isEmpty()) {
#if HAVE_X11
        fprintf(stderr, "Error: could not determine $%s.\n", displayEnvVarName_c());
        return QString();
    } else {
#endif
        int i;
        if ((i = display.lastIndexOf('.')) > display.lastIndexOf(':') && i >= 0) {
            display.truncate(i);
        }

        display.replace(':', '_');
#ifdef __APPLE__
        display.replace('/', '_');
#endif
    }
    const QString socketFileName = QString::fromLatin1("kdeinit5_%1").arg(QLatin1String(display));
    return socketFileName;
}

void
KCrash::setCrashHandler(HandlerType handler)
{
    if (!s_kdeinit_socket_file) {
        // Prepare this now to avoid mallocs in the crash handler.
        const QString socketFileName = generate_socket_file_name();
        QByteArray socketName = QFile::encodeName(QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation) +
                                QLatin1Char('/') + socketFileName);
        s_kdeinit_socket_file = qstrdup(socketName.constData());
    }

#if defined(Q_OS_WIN)
    static LPTOP_LEVEL_EXCEPTION_FILTER s_previousExceptionFilter = NULL;

    if (handler && !s_previousExceptionFilter) {
        s_previousExceptionFilter = SetUnhandledExceptionFilter(KCrash::win32UnhandledExceptionFilter);
    } else if (!handler && s_previousExceptionFilter) {
        SetUnhandledExceptionFilter(s_previousExceptionFilter);
        s_previousExceptionFilter = NULL;
    }
#else
    if (!handler) {
        handler = SIG_DFL;
    }

    sigset_t mask;
    sigemptyset(&mask);

#ifdef SIGSEGV
    signal(SIGSEGV, handler);
    sigaddset(&mask, SIGSEGV);
#endif
#ifdef SIGBUS
    signal(SIGBUS, handler);
    sigaddset(&mask, SIGBUS);
#endif
#ifdef SIGFPE
    signal(SIGFPE, handler);
    sigaddset(&mask, SIGFPE);
#endif
#ifdef SIGILL
    signal(SIGILL, handler);
    sigaddset(&mask, SIGILL);
#endif
#ifdef SIGABRT
    signal(SIGABRT, handler);
    sigaddset(&mask, SIGABRT);
#endif

    sigprocmask(SIG_UNBLOCK, &mask, nullptr);
#endif

    s_crashHandler = handler;
}

KCrash::HandlerType
KCrash::crashHandler()
{
    return s_crashHandler;
}

#if !defined(Q_OS_WIN) && !defined(Q_OS_OSX)
static void
closeAllFDs()
{
    // Close all remaining file descriptors except for stdin/stdout/stderr
    struct rlimit rlp;
    getrlimit(RLIMIT_NOFILE, &rlp);
    for (int i = 3; i < (int)rlp.rlim_cur; i++) {
        close(i);
    }
}
#endif

void
KCrash::defaultCrashHandler(int sig)
{
    // WABA: Do NOT use qDebug() in this function because it is much too risky!
    // Handle possible recursions
    static int crashRecursionCounter = 0;
    crashRecursionCounter++; // Nothing before this, please !

#if !defined(Q_OS_WIN)
    signal(SIGALRM, SIG_DFL);
    alarm(3); // Kill me... (in case we deadlock in malloc)
#endif

#ifdef Q_OS_SOLARIS
    (void) printstack(2 /* stderr, assuming it's still open. */);
#endif

    if (crashRecursionCounter < 2) {
        if (s_emergencySaveFunction) {
            s_emergencySaveFunction(sig);
        }
        if ((s_flags & AutoRestart) && s_autoRestartCommand) {
            QThread::sleep(1);
            startProcess(s_autoRestartArgc, const_cast<const char **>(s_autoRestartCommandLine), false);
        }
        crashRecursionCounter++;
    }

#if !defined(Q_OS_WIN) && !defined(Q_OS_OSX)
    if (!(s_flags & KeepFDs)) {
        closeAllFDs();
    }
# if HAVE_X11
    else if (QX11Info::display()) {
        close(ConnectionNumber(QX11Info::display()));
    }
# endif
#endif

    if (crashRecursionCounter < 3) {
#ifndef NDEBUG
        fprintf(stderr, "KCrash: crashing... crashRecursionCounter = %d\n",
                crashRecursionCounter);
        fprintf(stderr, "KCrash: Application Name = %s path = %s pid = %lld\n",
                s_appName ? s_appName : "<unknown>",
                s_appPath ? s_appPath : "<unknown>", QCoreApplication::applicationPid());
        fprintf(stderr, "KCrash: Arguments: ");
        for (int i = 0; s_autoRestartCommandLine[i]; ++i) {
            fprintf(stderr, "%s ", s_autoRestartCommandLine[i]);
        }
        fprintf(stderr, "\n");
#else
        fprintf(stderr, "KCrash: Application '%s' crashing...\n",
                s_appName ? s_appName : "<unknown>");
#endif

        if (s_launchDrKonqi != 1) {
            setCrashHandler(nullptr);
#if !defined(Q_OS_WIN)
            raise(sig); // dump core, or whatever is the default action for this signal.
#endif
            return;
        }

        const char *argv[29];  // don't forget to update this
        int i = 0;

        // argument 0 has to be drkonqi
        argv[i++] = s_drkonqiPath;

        const QByteArray platformName = QGuiApplication::platformName().toUtf8();
        if (!platformName.isEmpty()) {
            argv[i++] = "-platform";
            argv[i++] = platformName.constData();
        }

#if HAVE_X11
        if (platformName == QByteArrayLiteral("xcb")) {
            // start up on the correct display
            argv[i++] = "-display";
            if (QX11Info::display()) {
                argv[i++] = XDisplayString(QX11Info::display());
            } else {
                argv[i++] = getenv("DISPLAY");
            }
        }
#endif

        argv[i++] = "--appname";
        argv[i++] = s_appName ? s_appName : "<unknown>";

        if (loadedByKdeinit) {
            argv[i++] = "--kdeinit";
        }

        // only add apppath if it's not NULL
        if (s_appPath && *s_appPath) {
            argv[i++] = "--apppath";
            argv[i++] = s_appPath;
        }

        // signal number -- will never be NULL
        char sigtxt[ 10 ];
        sprintf(sigtxt, "%d", sig);
        argv[i++] = "--signal";
        argv[i++] = sigtxt;

        char pidtxt[ 20 ];
        sprintf(pidtxt, "%lld", QCoreApplication::applicationPid());
        argv[i++] = "--pid";
        argv[i++] = pidtxt;

        const KAboutData *about = KAboutData::applicationDataPointer();
        if (about) {
            if (about->internalVersion()) {
                argv[i++] = "--appversion";
                argv[i++] = about->internalVersion();
            }

            if (about->internalProgramName()) {
                argv[i++] = "--programname";
                argv[i++] = about->internalProgramName();
            }

            if (about->internalBugAddress()) {
                argv[i++] = "--bugaddress";
                argv[i++] = about->internalBugAddress();
            }
        }

        // make sure the constData() pointer remains valid when we call startProcess by making a copy
        QByteArray startupId = KStartupInfo::startupId();
        if (!startupId.isNull()) {
            argv[i++] = "--startupid";
            argv[i++] = startupId.constData();
        }

        if (s_flags & SaferDialog) {
            argv[i++] = "--safer";
        }

        if ((s_flags & AutoRestart) && s_autoRestartCommand) {
            argv[i++] = "--restarted";    //tell drkonqi if the app has been restarted
        }

#if defined(Q_OS_WIN)
        char threadId[8] = { 0 };
        sprintf(threadId, "%d", GetCurrentThreadId());
        argv[i++] = "--thread";
        argv[i++] = threadId;
#endif

        // NULL terminated list
        argv[i] = nullptr;

        startProcess(i, argv, true);
    }

    if (crashRecursionCounter < 4) {
        fprintf(stderr, "Unable to start Dr. Konqi\n");
    }

    if (s_coreConfig->isProcess()) {
        fprintf(stderr, "Re-raising signal for core dump handling.\n");
        KCrash::setCrashHandler(nullptr);
        raise(sig);
        // not getting here
    }

    _exit(255);
}

#if defined(Q_OS_WIN)

void KCrash::startProcess(int argc, const char *argv[], bool waitAndExit)
{
    QString cmdLine;
    for (int i = 0; i < argc; ++i) {
        cmdLine.append(QLatin1Char('\"'));
        cmdLine.append(QFile::decodeName(argv[i]));
        cmdLine.append(QStringLiteral("\" "));
    }

    PROCESS_INFORMATION procInfo;
    STARTUPINFOW startupInfo = { sizeof(STARTUPINFO), 0, 0, 0,
                                 (ulong)CW_USEDEFAULT, (ulong)CW_USEDEFAULT,
                                 (ulong)CW_USEDEFAULT, (ulong)CW_USEDEFAULT,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                               };

    bool success = CreateProcess(0, (wchar_t *) cmdLine.utf16(), NULL, NULL,
                                 false, CREATE_UNICODE_ENVIRONMENT, NULL, NULL,
                                 &startupInfo, &procInfo);

    if (success && waitAndExit) {
        // wait for child to exit
        WaitForSingleObject(procInfo.hProcess, INFINITE);
        _exit(253);
    }
}

//glue function for calling the unix signal handler from the windows unhandled exception filter
LONG WINAPI KCrash::win32UnhandledExceptionFilter(_EXCEPTION_POINTERS *exceptionInfo)
{
    // kdbgwin needs the context inside exceptionInfo because if getting the context after the
    // exception happened, it will walk down the stack and will stop at KiUserEventDispatch in
    // ntdll.dll, which is supposed to dispatch the exception from kernel mode back to user mode
    // so... let's create some shared memory
    HANDLE hMapFile = NULL;
    hMapFile = CreateFileMapping(
                   INVALID_HANDLE_VALUE,
                   NULL,
                   PAGE_READWRITE,
                   0,
                   sizeof(CONTEXT),
                   TEXT("Local\\KCrashShared"));

    LPCTSTR pBuf = NULL;
    pBuf = (LPCTSTR) MapViewOfFile(
               hMapFile,
               FILE_MAP_ALL_ACCESS,
               0,
               0,
               sizeof(CONTEXT));
    CopyMemory((PVOID) pBuf, exceptionInfo->ContextRecord, sizeof(CONTEXT));

    if (s_crashHandler) {
        s_crashHandler(exceptionInfo->ExceptionRecord->ExceptionCode);
    }

    CloseHandle(hMapFile);
    return EXCEPTION_EXECUTE_HANDLER; //allow windows to do the default action (terminate)
}
#else

static bool startProcessInternal(int argc, const char *argv[], bool waitAndExit, bool directly);
static pid_t startFromKdeinit(int argc, const char *argv[]);
static pid_t startDirectly(const char *argv[]);
static int write_socket(int sock, char *buffer, int len);
static int read_socket(int sock, char *buffer, int len);
static int openSocket();

void KCrash::startProcess(int argc, const char *argv[], bool waitAndExit)
{
    bool startDirectly = true;

#ifndef Q_OS_OSX
    // First try to start the app via kdeinit, if the AlwaysDirectly flag hasn't been specified.
    // This is done because it is dangerous to use fork() in the crash handler
    // (there can be functions registered to be performed before fork(), for example handling
    // of malloc locking, which doesn't work when malloc crashes because of heap corruption).
    if (!(s_flags & AlwaysDirectly)) {
        startDirectly = !startProcessInternal(argc, argv, waitAndExit, false);
    }
#endif

    // If we can't reach kdeinit, we can still at least try to fork()
    if (startDirectly) {
        startProcessInternal(argc, argv, waitAndExit, true);
    }
}

static bool startProcessInternal(int argc, const char *argv[], bool waitAndExit, bool directly)
{
    fprintf(stderr, "KCrash: Attempting to start %s %s\n", argv[0], directly ? "directly" : "from kdeinit");

    pid_t pid = directly ? startDirectly(argv) : startFromKdeinit(argc, argv);

    if (pid > 0 && waitAndExit) {
        // Seems we made it....
        alarm(0); //stop the pending alarm that was set at the top of the defaultCrashHandler

        // Wait forever until the started process exits. This code path is executed
        // when launching drkonqi. Note that drkonqi will stop this process in the meantime.
        if (directly) {
            //if the process was started directly, use waitpid(), as it's a child...
            while (waitpid(-1, nullptr, 0) != pid) {}
        } else {
#ifdef Q_OS_LINUX
            // Declare the process that will be debugging the crashed KDE app (#245529)
#ifndef PR_SET_PTRACER
# define PR_SET_PTRACER 0x59616d61
#endif
            prctl(PR_SET_PTRACER, pid, 0, 0, 0);
#endif
            //...else poll its status using kill()
            while (kill(pid, 0) >= 0) {
                sleep(1);
            }
        }
        if (!s_coreConfig->isProcess()) {
            // Only exit if we don't forward to core dumps
            _exit(253);
        }
    }

    return (pid > 0); //return true on success
}

static pid_t startFromKdeinit(int argc, const char *argv[])
{
    int socket = openSocket();
    if (socket < -1) {
        return 0;
    }
    kcrash_launcher_header header;
    header.cmd = LAUNCHER_EXEC_NEW;
    const int BUFSIZE = 8192; // make sure this is big enough
    const int CWDSIZE = 2000;
    char buffer[ BUFSIZE + 10 + 24 /*the env var*/ + CWDSIZE+1 ];
    int pos = 0;
    long argcl = argc;
    memcpy(buffer + pos, &argcl, sizeof(argcl));
    pos += sizeof(argcl);
    for (int i = 0;
            i < argc;
            ++i) {
        int len = strlen(argv[ i ]) + 1;   // include terminating \0
        if (pos + len >= BUFSIZE) {
            fprintf(stderr, "BUFSIZE in KCrash not big enough!\n");
            return 0;
        }
        memcpy(buffer + pos, argv[ i ], len);
        pos += len;
    }

    long env = 1; // 1 env var
    memcpy(buffer + pos, &env, sizeof(env));
    pos += sizeof(env);
    static const char s_envVar[] = "KCRASH_AUTO_RESTARTED=1";
    int len = strlen(s_envVar) + 1;
    memcpy(buffer + pos, s_envVar, len);
    pos += len;

    long avoid_loops = 0;
    memcpy(buffer + pos, &avoid_loops, sizeof(avoid_loops));
    pos += sizeof(avoid_loops);

    char cwd[CWDSIZE];
    if (getcwd(cwd, CWDSIZE-1)) {
        len = strlen(cwd) + 1; // include terminating \0
        memcpy(buffer + pos, cwd, len);
        pos += len;
    }

    header.arg_length = pos;
    write_socket(socket, (char *) &header, sizeof(header));
    write_socket(socket, buffer, pos);

    if (read_socket(socket, (char *) &header, sizeof(header)) < 0
            || header.cmd != LAUNCHER_OK) {
        return 0;
    }
    long pid;
    read_socket(socket, (char *) &pid, sizeof(pid));
    return static_cast<pid_t>(pid);
}

static pid_t startDirectly(const char *argv[])
{
    pid_t pid = fork();
    switch (pid) {
    case -1:
        fprintf(stderr, "KCrash failed to fork(), errno = %d\n", errno);
        return 0;
    case 0:
        setgroups(0, nullptr); // Remove any extraneous groups
        if (setgid(getgid()) < 0 || setuid(getuid()) < 0) {
            _exit(253);    // This cannot happen. Theoretically.
        }
#ifndef Q_OS_OSX
        closeAllFDs(); // We are in the child now. Close FDs unconditionally.
#endif
        setenv("KCRASH_AUTO_RESTARTED", "1", 1);
        execvp(argv[0], const_cast< char ** >(argv));
        fprintf(stderr, "KCrash failed to exec(), errno = %d\n", errno);
        _exit(253);
    default:
        return pid;
    }
}

/*
 * Write 'len' bytes from 'buffer' into 'sock'.
 * returns 0 on success, -1 on failure.
 */
static int write_socket(int sock, char *buffer, int len)
{
    ssize_t result;
    int bytes_left = len;
    while (bytes_left > 0) {
        result = write(sock, buffer, bytes_left);
        if (result > 0) {
            buffer += result;
            bytes_left -= result;
        } else if (result == 0) {
            return -1;
        } else if ((result == -1) && (errno != EINTR) && (errno != EAGAIN)) {
            return -1;
        }
    }
    return 0;
}

/*
 * Read 'len' bytes from 'sock' into 'buffer'.
 * returns 0 on success, -1 on failure.
 */
static int read_socket(int sock, char *buffer, int len)
{
    ssize_t result;
    int bytes_left = len;
    while (bytes_left > 0) {
        result = read(sock, buffer, bytes_left);
        if (result > 0) {
            buffer += result;
            bytes_left -= result;
        } else if (result == 0) {
            return -1;
        } else if ((result == -1) && (errno != EINTR) && (errno != EAGAIN)) {
            return -1;
        }
    }
    return 0;
}

static int openSocket()
{
    struct sockaddr_un server;
    if (!s_kdeinit_socket_file ||
        strlen(s_kdeinit_socket_file) > (sizeof(server.sun_path) - 1))
    {
        fprintf(stderr, "kcrash: Unable to communicate with kdeinit5, socket name is %s!",
                (s_kdeinit_socket_file) ? "too long" : "undefined");
        return -1;
    }

    /*
     * create the socket stream
     */
    int s = socket(PF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Warning: socket() failed: ");
        return -1;
    }

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, s_kdeinit_socket_file);
    printf("sock_file=%s\n", s_kdeinit_socket_file);
    kde_socklen_t socklen = sizeof(server);
    if (connect(s, (struct sockaddr *)&server, socklen) == -1) {
        perror("Warning: connect() failed: ");
        close(s);
        return -1;
    }
    return s;
}

#endif // Q_OS_UNIX
