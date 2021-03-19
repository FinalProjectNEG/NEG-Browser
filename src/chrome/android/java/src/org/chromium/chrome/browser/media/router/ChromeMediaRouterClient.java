// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.media.router;

import android.content.Intent;

import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;

import org.chromium.base.ApplicationStatus;
import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;
import org.chromium.chrome.browser.document.ChromeIntentUtil;
import org.chromium.chrome.browser.media.ui.ChromeMediaNotificationManager;
import org.chromium.chrome.browser.tab.Tab;
import org.chromium.chrome.browser.tab.TabUtils;
import org.chromium.components.browser_ui.media.MediaNotificationInfo;
import org.chromium.components.media_router.MediaRouterClient;
import org.chromium.content_public.browser.WebContents;

/** Provides Chrome-specific behavior for Media Router. */
@JNINamespace("media_router")
public class ChromeMediaRouterClient extends MediaRouterClient {
    private ChromeMediaRouterClient() {}

    @Override
    public int getTabId(WebContents webContents) {
        Tab tab = TabUtils.fromWebContents(webContents);
        return tab == null ? -1 : tab.getId();
    }

    @Override
    public Intent createBringTabToFrontIntent(int tabId) {
        return ChromeIntentUtil.createBringTabToFrontIntent(tabId);
    }

    @Override
    public void showNotification(MediaNotificationInfo notificationInfo) {
        ChromeMediaNotificationManager.show(notificationInfo);
    }

    @Override
    public FragmentManager getSupportFragmentManager(WebContents initiator) {
        FragmentActivity currentActivity =
                (FragmentActivity) ApplicationStatus.getLastTrackedFocusedActivity();
        return currentActivity == null ? null : currentActivity.getSupportFragmentManager();
    }

    @CalledByNative
    public static void initialize() {
        if (MediaRouterClient.getInstance() != null) return;

        MediaRouterClient.setInstance(new ChromeMediaRouterClient());
    }
}
