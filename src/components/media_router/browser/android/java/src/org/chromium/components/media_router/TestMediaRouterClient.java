// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.components.media_router;

import android.content.Intent;

import androidx.fragment.app.FragmentManager;

import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;
import org.chromium.components.browser_ui.media.MediaNotificationInfo;
import org.chromium.content_public.browser.WebContents;

/** Provides Test-specific behavior for Media Router. */
@JNINamespace("media_router")
public class TestMediaRouterClient extends MediaRouterClient {
    public TestMediaRouterClient() {}

    @Override
    public int getTabId(WebContents webContents) {
        return 1;
    }

    @Override
    public Intent createBringTabToFrontIntent(int tabId) {
        return null;
    }

    @Override
    public void showNotification(MediaNotificationInfo notificationInfo) {}

    @Override
    public FragmentManager getSupportFragmentManager(WebContents initiator) {
        return null;
    }

    @CalledByNative
    public static void initialize() {
        if (MediaRouterClient.getInstance() != null) return;

        MediaRouterClient.setInstance(new TestMediaRouterClient());
    }
}
