// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.toolbar;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import android.content.Context;
import android.content.res.Resources;
import android.view.View;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.annotation.Config;

import org.chromium.base.test.BaseRobolectricTestRunner;
import org.chromium.chrome.browser.night_mode.NightModeStateProvider;
import org.chromium.chrome.browser.ntp.NewTabPage;
import org.chromium.chrome.browser.ui.TabObscuringHandler;
import org.chromium.components.browser_ui.widget.scrim.ScrimCoordinator;

/** Unit tests for ToolbarTabControllerImpl. */
@RunWith(BaseRobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class LocationBarFocusScrimHandlerTest {
    @Mock
    private View mScrimTarget;
    @Mock
    private Runnable mClickDelegate;
    @Mock
    private ToolbarDataProvider mToolbarDataProvider;
    @Mock
    private Context mContext;
    @Mock
    private Resources mResources;
    @Mock
    private NightModeStateProvider mNightModeStateProvider;
    @Mock
    private TabObscuringHandler mTabObscuringHandler;
    @Mock
    private ScrimCoordinator mScrimCoordinator;
    @Mock
    private NewTabPage mNewTabPage;

    LocationBarFocusScrimHandler mScrimHandler;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        doReturn(mResources).when(mContext).getResources();
        mScrimHandler = new LocationBarFocusScrimHandler(mScrimCoordinator, mTabObscuringHandler,
                mContext, mNightModeStateProvider, mToolbarDataProvider, mClickDelegate,
                mScrimTarget);
    }

    @Test
    public void testScrimShown_thenHidden() {
        mScrimHandler.onUrlFocusChange(true);

        verify(mScrimCoordinator).showScrim(any());

        mScrimHandler.onUrlFocusChange(false);
        verify(mScrimCoordinator).hideScrim(true);

        // A second de-focus shouldn't trigger another hide.
        mScrimHandler.onUrlFocusChange(false);
        verify(mScrimCoordinator, times(1)).hideScrim(true);
    }

    @Test
    public void testScrimShown_afterAnimation() {
        doReturn(mNewTabPage).when(mToolbarDataProvider).getNewTabPageForCurrentTab();
        doReturn(true).when(mNewTabPage).isLocationBarShownInNTP();
        mScrimHandler.onUrlFocusChange(true);

        verify(mScrimCoordinator, never()).showScrim(any());

        mScrimHandler.onUrlAnimationFinished(true);
        verify(mScrimCoordinator).showScrim(any());
    }
}
