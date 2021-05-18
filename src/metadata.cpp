/*
    SPDX-License-Identifier: LGPL-2.0-or-later
    SPDX-FileCopyrightText: 2021 Harald Sitter <sitter@kde.org>
*/

#include "metadata_p.h"

#include <QByteArray>
#include <cerrno>

#ifdef Q_OS_LINUX
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace KCrash
{
#ifdef Q_OS_LINUX
MetadataINIWriter::MetadataINIWriter(const QByteArray &path)
    : MetadataWriter()
    , fd(::open(path.constData(), O_WRONLY | O_CREAT | O_NONBLOCK | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR))
{
    if (fd == -1) {
        fprintf(stderr, "Failed to open metadata file: %s\n", strerror(errno));
    } else {
        const char *header = "[KCrash]\n";
        write(fd, header, strlen(header));
    }
}

void MetadataINIWriter::close()
{
    if (fd >= 0 && ::close(fd) == -1) {
        fprintf(stderr, "Failed to close metadata file: %s\n", strerror(errno));
    }
}

void MetadataINIWriter::add(const char *key, const char *value, BoolValue boolValue)
{
    Q_ASSERT(key);
    Q_ASSERT(value);
    Q_ASSERT(key[0] == '-' && key[1] == '-'); // well-formed '--' prefix. This is important. MetadataWriter presume this
    Q_UNUSED(boolValue); // value is a bool string but we don't care, we always write the value anyway

    if (fd < 0) {
        return;
    }
    const int ret = snprintf(iniLine.data(), iniLine.max_size(), "%s=%s\n", key + 2 /** skip the leading -- */, value);
    if (ret < 0) {
        fprintf(stderr, "Failed to generate metadata line for '%s', '%s'\n", key, value);
        return;
    }
    // Cannot be negative anymore.
    const std::make_unsigned<decltype(ret)>::type lineLength = ret;
    fprintf(stderr, "%d -- %s", lineLength, iniLine.data());
    Q_ASSERT(lineLength <= iniLine.max_size()); // is not truncated41
    write(fd, iniLine.data(), lineLength);
}
#endif

Metadata::Metadata(const char *cmd, MetadataWriter *writer)
    : MetadataWriter()
    , m_writer(writer)
{
    // NB: cmd may be null! Just because we create metadata doesn't mean we'll execute drkonqi (we may only need the
    // backing writers)
    Q_ASSERT(argc == 0);
    argv.at(argc++) = cmd;
}

void Metadata::add(const char *key, const char *value)
{
    add(key, value, BoolValue::No);
}

void Metadata::addBool(const char *key)
{
    add(key, "true", BoolValue::Yes);
}

void Metadata::close()
{
    // NULL terminated list
    argv.at(argc) = nullptr;

    if (m_writer) {
        m_writer->close();
    }
}

void Metadata::add(const char *key, const char *value, BoolValue boolValue)
{
    Q_ASSERT(key);
    Q_ASSERT(value);
    Q_ASSERT(key[0] == '-' && key[1] == '-'); // well-formed '--' prefix. This is important. MetadataWriter presume this
    Q_ASSERT(argc < argv.max_size()); // argv has a static max size. guard against exhaustion

    argv.at(argc++) = key;
    if (!boolValue) {
        argv.at(argc++) = value;
    }

    if (m_writer) {
        m_writer->add(key, value, boolValue);
    }
}

} // namespace KCrash
