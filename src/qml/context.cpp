// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL
// SPDX-FileCopyrightText: 2025 Harald Sitter <sitter@kde.org>

#include "context.h"

#include <QQuickWindow>
#include <rhi/qrhi.h>

#include <kcrash.h>

using namespace Qt::StringLiterals;

namespace
{
constexpr auto hex = 16;
} // namespace

void CrashContext::classBegin()
{
    KCrash::initialize(); // just to be sure
}

void CrashContext::componentComplete()
{
    if (!window()) {
        return;
    }

    if (window()->rhi()) {
        loadData();
        return;
    }

    connect(window(), &QQuickWindow::sceneGraphInitialized, this, &CrashContext::loadData);
}

void CrashContext::loadData()
{
    QVariantHash data;

    if (window() && window()->rhi()) {
        auto rhi = window()->rhi();
        auto info = rhi->driverInfo();

        constexpr auto yes = "true"_L1;
        constexpr auto no = "false"_L1;
        data.insert({
            {u"name"_s, info.deviceName},
            // {u"memory_size"_s, },
            {u"api_type"_s, QString::fromUtf8(rhi->backendName())},
            // {u"multi_threaded_rendering"_s, },
            {u"npot_support"_s, rhi->isFeatureSupported(QRhi::NPOTTextureRepeat) ? yes : no},
            {u"max_texture_size"_s, rhi->resourceLimit(QRhi::TextureSizeMax)},
            // {u"graphics_shader_level"_s, },
            {u"supports_draw_call_instancing"_s, rhi->isFeatureSupported(QRhi::Instancing) ? yes : no},
            // {u"supports_ray_tracing"_s,},
            {u"supports_compute_shaders"_s, rhi->isFeatureSupported(QRhi::Compute) ? yes : no},
            {u"supports_geometry_shaders"_s, rhi->isFeatureSupported(QRhi::GeometryShader) ? yes : no},
        });
        if (info.deviceId > 0) {
            data[u"id"_s] = QString::number(info.deviceId, hex);
        }
        if (info.vendorId > 0) {
            data[u"vendor_id"_s] = QString::number(info.vendorId, hex);
        }
    }

    KCrash::setGPUData(data);
}
