/*
    SPDX-FileCopyrightText: 2026 Volker Krause <vkrause@kde.org>
    SPDX-License-Identifier: LGPL-2.0-or-later
*/

package org.kde.crash;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.AlertDialog;
import android.app.Application;
import android.app.ApplicationExitInfo;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import io.sentry.ScreenshotStrategyType;
import io.sentry.SentryLevel;
import io.sentry.ProfileLifecycle;
import io.sentry.android.core.SentryAndroid;
import io.sentry.SentryOptions;

import java.util.List;

public class KCrash
{
    private static final String TAG = "org.kde.crash";

    public static void initialize(Context context)
    {
        if (Build.VERSION.SDK_INT < 30) {
            Log.i(TAG, "crash reporting not supported on Android API " + Build.VERSION.SDK_INT);
            return;
        }

        ActivityManager activityManager = (ActivityManager)context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ApplicationExitInfo> exitInfoList = activityManager.getHistoricalProcessExitReasons(null, 0, 1);
        if (exitInfoList == null || exitInfoList.isEmpty()) {
            Log.i(TAG, "no exit info found");
            return;
        }

        ApplicationExitInfo lastExit = exitInfoList.get(0);
        Log.i(TAG, "found exit info with reason " + lastExit.getReason());
        if (lastExit.getReason() != ApplicationExitInfo.REASON_CRASH_NATIVE) { // TODO add other crash types?
            return;
        }

        Activity activity = (Activity)context;
        if (activity == null) {
            Log.i(TAG, "crash reporting not supported from background service");
            return;
        }

        String dsn;
        PackageManager pm = context.getPackageManager();
        try {
            ApplicationInfo appInfo = pm.getApplicationInfo(context.getPackageName(), PackageManager.GET_META_DATA);
            dsn = appInfo.metaData.getString("io.sentry.dsn");
        } catch (Exception e) {
            Log.i(TAG, "failed to load application meta-data");
            return;
        }
        if (dsn == null) {
            Log.i(TAG, "no Sentry DSN configured for this application");
            return;
        }

        activity.runOnUiThread(() -> {
            new AlertDialog.Builder(context)
                .setTitle(R.string.submit_dialog_title)
                .setMessage(R.string.submit_dialog_text)
                .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        KCrash.initSentry(context, dsn);
                    }
                })
                .setNegativeButton(android.R.string.no, null)
                .setIconAttribute(android.R.attr.alertDialogIcon)
                .show();
        });
    }

    private static void initSentry(Context context, String dsn)
    {
        Log.i(TAG, "initializing Sentry");

        try {
            SentryAndroid.init(context, options -> {
                options.setDsn(dsn);
                options.setSendDefaultPii(false);
                options.setEnableUserInteractionTracing(false);
                options.setAttachScreenshot(false);
                options.setAttachViewHierarchy(false);
                options.setStartProfilerOnAppStart(false);
                options.setTombstoneEnabled(true);
            });
        } catch (Exception e) {
            Log.e(TAG, "Sentry initialization failed", e);
        } catch (NoClassDefFoundError e) {
            Log.e(TAG, "Sentry not bundled", e);
        }
    }
}
