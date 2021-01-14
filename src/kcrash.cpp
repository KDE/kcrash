/*
    This file is part of the KDE Libraries
    SPDX-FileCopyrightText: 2000 Timo Hummel <timo.hummel@sap.com>
    SPDX-FileCopyrightText: 2000 Tom Braun <braunt@fh-konstanz.de>
    SPDX-FileCopyrightText: 2010 George Kiagiadakis <kiagiadakis.george@gmail.com>
    SPDX-FileCopyrightText: 2009 KDE e.V. <kde-ev-board@kde.org> 
    SPDX-FileContributor: 2009 Adriaan de Groot <groot@kde.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
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
#include <sys/poll.h>
#include <sys/prctl.h>
#endif

#include <KAboutData>
#include <kstartupinfo.h>

#include <array>
#include <algorithm>
#include <memory>

#include <QDebug>
#include <QGuiApplication>
#include <QStandardPaths>
#include <QThread>
#include <QLibraryInfo>
#include <QFile>

#include <QLoggingCategory>
Q_DECLARE_LOGGING_CATEGORY(LOG_KCRASH)

// logging category for this framework, default: log stuff >= info
Q_LOGGING_CATEGORY(LOG_KCRASH, "kf.crash", QtInfoMsg)

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
        // Create socket path to transfer ptrace scope and open connection
}
#ifdef Q_OS_LINUX
static QByteArray s_socketpath;
#endif

struct Args
{
    ~Args()
    {
        clear();
    }

    void clear()
    {
        if (!argc) {
            return;
        }

        for (int i = 0; i < argc; ++i) {
            delete[] argv[i];
        }
        delete[] argv;

        argv = nullptr;
        argc = 0;
    }

    void resize(int size)
    {
        clear();
        argc = size;
        argv = new char *[argc + 1];
        for (int i = 0; i < argc + 1; ++i) {
            argv[i] = nullptr;
        }
    }

    explicit operator bool() const
    {
        return argc > 0;
    }

    int argc = 0;
    // null-terminated array of null-terminated strings
    char **argv = nullptr;
};

static KCrash::HandlerType s_emergencySaveFunction = nullptr;
static KCrash::HandlerType s_crashHandler = nullptr;
static std::unique_ptr<char[]> s_appName;
static std::unique_ptr<char[]> s_appPath;
static Args s_autoRestartCommandLine;
static std::unique_ptr<char[]> s_drkonqiPath;
static KCrash::CrashFlags s_flags = KCrash::CrashFlags();
static int s_launchDrKonqi = -1; // -1=initial value 0=disabled 1=enabled

static std::unique_ptr<char[]> s_kcrashErrorMessage;
Q_GLOBAL_STATIC(KCrash::CoreConfig, s_coreConfig)

static void kcrashInitialize()
{

    // Static because in some cases this is called multiple times
    // but if an application had any of the bad cases we always want
    // to skip the check
    static bool doAutoInitKCrash = true;

    if (!doAutoInitKCrash) {
        return;
    }

    QCoreApplication *app = QCoreApplication::instance();
    if (!app) {
        doAutoInitKCrash = false;
        return;
    }

    if (!QCoreApplication::startingUp()) {
        // If the app has already started, this means we're not being run as part of
        // qt_call_pre_routines, which most probably means that we're being run as part
        // of KCrash being loaded as part of some plugin of the app, so don't
        // do any magic
        doAutoInitKCrash = false;
        return;
    }

    if (!QCoreApplication::eventDispatcher()) {
        // We are called with event dispatcher being null when KCrash is being loaded
        // through plasma-integration instead of being linked to the app (i.e. QtCreator vs Okular)
        // For apps that don't link directly to KCrash do not do the magic
        doAutoInitKCrash = false;
        return;
    }

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
        && !qEnvironmentVariableIsSet("KCRASH_AUTO_RESTARTED")
        && !qEnvironmentVariableIntValue("RUNNING_UNDER_RR")) {
        // enable drkonqi
        KCrash::setDrKonqiEnabled(true);
    } else {
        // This loads qtlogging.ini very early which prevents unittests from doing QStandardPaths::setTestModeEnabled(true) in initTestCase()
        //qCDebug(LOG_KCRASH) << "KCrash disabled through environment.";
    }

    if (QCoreApplication::instance()) {
        KCrash::setApplicationFilePath(QCoreApplication::applicationFilePath());
    } else {
        qWarning() << "This process needs a QCoreApplication instance in order to use KCrash";
    }

#ifdef Q_OS_LINUX
    // Create socket path to transfer ptrace scope and open connection
    s_socketpath = QFile::encodeName(
            QStringLiteral("%1/kcrash_%2").arg(QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation))
                                          .arg(getpid()));
#endif

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
    void timerEvent(QTimerEvent *event) override
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

    s_appName.reset(qstrdup(QFile::encodeName(appName).constData()));
    s_appPath.reset(qstrdup(QFile::encodeName(appPath).constData()));

    // Prepare the auto-restart command
    QStringList args = QCoreApplication::arguments();
    if (args.isEmpty()) { // edge case: tst_QX11Info::startupId does QApplication app(argc, nullptr)...
        args.append(filePath);
    } else {
        args[0] = filePath; // replace argv[0] with full path above
    }

    s_autoRestartCommandLine.resize(args.count());
    for (int i = 0; i < args.count(); ++i) {
        s_autoRestartCommandLine.argv[i] = qstrdup(QFile::encodeName(args.at(i)).constData());
    }
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
            << QFile::decodeName(qgetenv("LIBEXEC_PATH")).split(QLatin1Char(':'), Qt::SkipEmptyParts) // env var is used first
            << QCoreApplication::applicationDirPath() // then look where our application binary is located
            << QLibraryInfo::location(QLibraryInfo::LibraryExecutablesPath) // look where libexec path is (can be set in qt.conf)
            << QFile::decodeName(CMAKE_INSTALL_FULL_LIBEXECDIR); // look at our installation location
        const QString exec = QStandardPaths::findExecutable(QStringLiteral("drkonqi"), paths);
        if (exec.isEmpty()) {
            qCDebug(LOG_KCRASH) << "Could not find drkonqi in search paths:" << paths;
            s_launchDrKonqi = 0;
        } else {
            s_drkonqiPath.reset(qstrdup(qPrintable(exec)));
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

void
KCrash::setCrashHandler(HandlerType handler)
{
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
        if ((s_flags & AutoRestart) && s_autoRestartCommandLine) {
            QThread::sleep(1);
            startProcess(s_autoRestartCommandLine.argc, const_cast<const char **>(s_autoRestartCommandLine.argv), false);
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
                s_appName ? s_appName.get() : "<unknown>",
                s_appPath ? s_appPath.get() : "<unknown>", QCoreApplication::applicationPid());
        fprintf(stderr, "KCrash: Arguments: ");
        for (int i = 0; i < s_autoRestartCommandLine.argc; ++i) {
            fprintf(stderr, "%s ", s_autoRestartCommandLine.argv[i]);
        }
        fprintf(stderr, "\n");
#else
        fprintf(stderr, "KCrash: Application '%s' crashing...\n",
                s_appName ? s_appName.get() : "<unknown>");
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
        argv[i++] = s_drkonqiPath.get();

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
        argv[i++] = s_appName ? s_appName.get() : "<unknown>";

        if (loadedByKdeinit) {
            argv[i++] = "--kdeinit";
        }

        // only add apppath if it's not NULL
        if (s_appPath && s_appPath[0]) {
            argv[i++] = "--apppath";
            argv[i++] = s_appPath.get();
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

        if ((s_flags & AutoRestart) && s_autoRestartCommandLine) {
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

static pid_t startDirectly(const char *argv[]);
static int write_socket(int sock, char *buffer, int len);
static int read_socket(int sock, char *buffer, int len);

#ifdef Q_OS_LINUX
static int openDrKonqiSocket(const QByteArray &socketpath);
static int pollDrKonqiSocket(pid_t pid, int sockfd);
#endif

void KCrash::startProcess(int argc, const char *argv[], bool waitAndExit)
{
    Q_UNUSED(argc);
    fprintf(stderr, "KCrash: Attempting to start %s\n", argv[0]);

    pid_t pid = startDirectly(argv);

    if (pid > 0 && waitAndExit) {
        // Seems we made it....
        alarm(0); // Stop the pending alarm that was set at the top of the defaultCrashHandler

        bool running = true;
        // Wait forever until the started process exits. This code path is executed
        // when launching drkonqi. Note that DrKonqi will SIGSTOP this process in the meantime
        // and only send SIGCONT when it is about to attach a debugger.
#ifdef Q_OS_LINUX
        // Declare the process that will be debugging the crashed KDE app (#245529).
        // For now that will be DrKonqi, which may ask to transfer the ptrace scope to
        // a debugger it is not an ancestor of (because it was started via kdeinit or
        // KProcess::startDetached()) using a socket.
#ifndef PR_SET_PTRACER
# define PR_SET_PTRACER 0x59616d61
#endif
        prctl(PR_SET_PTRACER, pid, 0, 0, 0);

        int sockfd = openDrKonqiSocket(s_socketpath);

        if (sockfd >= 0) {
            // Wait while DrKonqi is running and the socket connection exists
            // If the process was started directly, use waitpid(), as it's a child...
            while ((running = waitpid(pid, nullptr, WNOHANG) != pid) && pollDrKonqiSocket(pid, sockfd) >= 0) {}
            close(sockfd);
            unlink(s_socketpath.constData());
        }
#endif
        if (running) {
            // If the process was started directly, use waitpid(), as it's a child...
            while (waitpid(pid, nullptr, 0) != pid) {}
        }
        if (!s_coreConfig->isProcess()) {
            // Only exit if we don't forward to core dumps
            _exit(253);
        }
    }
}

extern "C" char **environ;
static pid_t startDirectly(const char *argv[])
{
    char** environ_end;
    for(environ_end = environ; *environ_end; ++environ_end) {}

    std::array<const char*, 1024> environ_data; //hope it's big enough
    if((unsigned)(environ_end - environ) +2 >= environ_data.size()) {
        fprintf(stderr, "environ_data in KCrash not big enough!\n");
        return 0;
    }
    auto end = std::copy_if(environ, environ_end, environ_data.begin(),
                            [](const char* s) {
                              static const char envvar[] = "KCRASH_AUTO_RESTARTED=";
                              return strncmp(envvar, s, sizeof(envvar)-1) != 0;
                            });
    *end++ = "KCRASH_AUTO_RESTARTED=1";
    *end++ = nullptr;
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
        execve(argv[0], const_cast< char ** >(argv), const_cast<char**> (environ_data.data()));
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

#ifdef Q_OS_LINUX

static int openDrKonqiSocket(const QByteArray &socketpath)
{
    int sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Warning: socket() for communication with DrKonqi failed");
        return -1;
    }

    struct sockaddr_un drkonqi_server;
    drkonqi_server.sun_family = AF_UNIX;

    if (socketpath.size() >= static_cast<int>(sizeof(drkonqi_server.sun_path))) {
        fprintf(stderr, "Warning: socket path is too long\n");
        close(sockfd);
        return -1;
    }
    strcpy(drkonqi_server.sun_path, socketpath.constData());

    unlink(drkonqi_server.sun_path); // remove potential stale socket
    if (bind(sockfd, (struct sockaddr *)&drkonqi_server, sizeof(drkonqi_server)) < 0) {
        perror("Warning: bind() for communication with DrKonqi failed");
        close(sockfd);
        unlink(drkonqi_server.sun_path);
        return -1;
    }

    listen(sockfd, 1);

    return sockfd;
}

static int pollDrKonqiSocket(pid_t pid, int sockfd)
{
    struct pollfd fd;
    fd.fd = sockfd;
    fd.events = POLLIN;
    int r;
    do {
        r = poll(&fd, 1, 1000); // wait for 1 second for a request by DrKonqi
    } while (r == -1 && errno == EINTR);
    // only continue if POLLIN event returned
    if (r == 0) // timeout
        return 0;
    else if (r == -1 || !(fd.revents & POLLIN)) // some error
        return -1;

    static struct sockaddr_un drkonqi_client;
    static socklen_t cllength = sizeof(drkonqi_client);
    int clsockfd;
    do {
        clsockfd = accept(sockfd, (struct sockaddr *)&drkonqi_client, &cllength);
    } while (clsockfd == -1 && errno == EINTR);
    if (clsockfd < 0)
        return -1;

    // check whether the message is coming from DrKonqi
    static struct ucred ucred;
    static socklen_t credlen = sizeof(struct ucred);
    if (getsockopt(clsockfd, SOL_SOCKET, SO_PEERCRED, &ucred, &credlen) < 0)
        return -1;

    if (ucred.pid != pid) {
        fprintf(stderr, "Warning: peer pid does not match DrKonqi pid\n");
        return -1;
    }

    // read PID to change ptrace scope
    static const int msize = 21; // most digits in a 64bit int (+sign +'\0')
    char msg[msize];
    if (read_socket(clsockfd, msg, msize) == 0) {
        int dpid = atoi(msg);
        prctl(PR_SET_PTRACER, dpid, 0, 0, 0);
        // confirm change to DrKonqi
        if (write_socket(clsockfd, msg, msize) == 0) {
            fprintf(stderr, "KCrash: ptrace access transferred to %s\n", msg);
        }
    }
    close(clsockfd);

    return 1;
}

#endif

#endif // Q_OS_UNIX

void KCrash::setErrorMessage(const QString &message)
{
    s_kcrashErrorMessage.reset(qstrdup(message.toUtf8().constData()));
}
