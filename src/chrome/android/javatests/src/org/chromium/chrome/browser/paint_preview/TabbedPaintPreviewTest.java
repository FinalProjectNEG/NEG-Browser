// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.paint_preview;

import static org.chromium.base.test.util.Batch.PER_CLASS;

import android.graphics.Bitmap;
import android.graphics.Rect;
import android.os.Handler;
import android.os.Parcel;

import androidx.annotation.NonNull;
import androidx.test.filters.MediumTest;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;

import org.chromium.base.Callback;
import org.chromium.base.UnguessableToken;
import org.chromium.base.supplier.ObservableSupplier;
import org.chromium.base.test.util.Batch;
import org.chromium.base.test.util.CallbackHelper;
import org.chromium.chrome.browser.ChromeTabbedActivity;
import org.chromium.chrome.browser.browser_controls.BrowserStateBrowserControlsVisibilityDelegate;
import org.chromium.chrome.browser.paint_preview.services.PaintPreviewTabService;
import org.chromium.chrome.browser.tab.Tab;
import org.chromium.chrome.test.ChromeJUnit4ClassRunner;
import org.chromium.chrome.test.ChromeTabbedActivityTestRule;
import org.chromium.chrome.test.batch.BlankCTATabInitialStateRule;
import org.chromium.components.paintpreview.browser.NativePaintPreviewServiceProvider;
import org.chromium.components.paintpreview.player.PlayerCompositorDelegate;
import org.chromium.components.paintpreview.player.PlayerManager;
import org.chromium.content_public.browser.test.util.CriteriaHelper;
import org.chromium.content_public.browser.test.util.TestThreadUtils;
import org.chromium.ui.util.TokenHolder;
import org.chromium.url.GURL;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * Tests for the {@link TabbedPaintPreview} class.
 */
@RunWith(ChromeJUnit4ClassRunner.class)
@Batch(PER_CLASS)
public class TabbedPaintPreviewTest {
    @ClassRule
    public static ChromeTabbedActivityTestRule sActivityTestRule =
            new ChromeTabbedActivityTestRule();
    @Rule
    public final BlankCTATabInitialStateRule<ChromeTabbedActivity> mInitialStateRule =
            new BlankCTATabInitialStateRule<>(sActivityTestRule, true);

    private static final String TEST_URL = "/chrome/test/data/android/about.html";

    @BeforeClass
    public static void setUp() {
        PaintPreviewTabService mockService = Mockito.mock(PaintPreviewTabService.class);
        Mockito.doReturn(true).when(mockService).hasCaptureForTab(Mockito.anyInt());
        TabbedPaintPreview.overridePaintPreviewTabServiceForTesting(mockService);
        PlayerManager.overrideCompositorDelegateFactoryForTesting(TestCompositorDelegate::new);
    }

    @AfterClass
    public static void tearDown() {
        PlayerManager.overrideCompositorDelegateFactoryForTesting(null);
        TabbedPaintPreview.overridePaintPreviewTabServiceForTesting(null);
    }

    @Before
    public void setup() {
        sActivityTestRule.loadUrl(sActivityTestRule.getTestServer().getURL(TEST_URL));
    }

    /**
     * Tests that TabbedPaintPreview is displayed correctly if a paint preview for the current tab
     * has been captured before.
     */
    @Test
    @MediumTest
    public void testDisplayedCorrectly() throws ExecutionException, TimeoutException {
        Tab tab = sActivityTestRule.getActivity().getActivityTab();
        TabbedPaintPreview tabbedPaintPreview =
                TestThreadUtils.runOnUiThreadBlocking(() -> TabbedPaintPreview.get(tab));
        CallbackHelper viewReadyCallback = new CallbackHelper();
        CallbackHelper firstPaintCallback = new CallbackHelper();
        PlayerManager.Listener listener = new EmptyPlayerListener() {
            @Override
            public void onCompositorError(int status) {
                Assert.fail("Paint Preview should have been displayed successfully"
                        + "with no errors.");
            }

            @Override
            public void onViewReady() {
                viewReadyCallback.notifyCalled();
            }

            @Override
            public void onFirstPaint() {
                firstPaintCallback.notifyCalled();
            }
        };

        boolean showed =
                TestThreadUtils.runOnUiThreadBlocking(() -> tabbedPaintPreview.maybeShow(listener));
        Assert.assertTrue("Paint Preview failed to display.", showed);
        Assert.assertTrue("Paint Preview was not displayed.", tabbedPaintPreview.isShowing());
        Assert.assertTrue(
                "Paint Preview was not attached to tab.", tabbedPaintPreview.isAttached());
        viewReadyCallback.waitForFirst("Paint preview view ready never happened.");
        firstPaintCallback.waitForFirst("Paint preview first paint never happened.");
        TestThreadUtils.runOnUiThreadBlocking(() -> tabbedPaintPreview.remove(false, false));
    }

    /**
     * Tests that we correctly make the browser controls persistent and non-persistent on showing
     * and hiding the paint preview, or the tab.
     */
    @Test
    @MediumTest
    public void testBrowserControlsPersistent() throws ExecutionException {
        TestControlsVisibilityDelegate visibilityDelegate =
                TestThreadUtils.runOnUiThreadBlocking(TestControlsVisibilityDelegate::new);
        Tab tab = sActivityTestRule.getActivity().getActivityTab();
        TabbedPaintPreview tabbedPaintPreview =
                TestThreadUtils.runOnUiThreadBlocking(() -> TabbedPaintPreview.get(tab));
        tabbedPaintPreview.setBrowserVisibilityDelegate(visibilityDelegate);
        PlayerManager.Listener emptyListener = new EmptyPlayerListener();

        // Assert toolbar persistence is changed based on paint preview visibility.
        assertToolbarPersistence(false, visibilityDelegate);
        boolean showed = TestThreadUtils.runOnUiThreadBlocking(
                () -> tabbedPaintPreview.maybeShow(emptyListener));
        Assert.assertTrue("Paint Preview failed to display.", showed);
        assertToolbarPersistence(true, visibilityDelegate);
        TestThreadUtils.runOnUiThreadBlocking(() -> tabbedPaintPreview.remove(false, false));
        assertToolbarPersistence(false, visibilityDelegate);

        // Assert toolbar persistence is changed based visibility of the tab that is showing the
        // paint preview.
        showed = TestThreadUtils.runOnUiThreadBlocking(
                () -> tabbedPaintPreview.maybeShow(emptyListener));
        Assert.assertTrue("Paint Preview failed to display.", showed);
        assertToolbarPersistence(true, visibilityDelegate);
        Tab newTab = sActivityTestRule.loadUrlInNewTab(
                sActivityTestRule.getTestServer().getURL(TEST_URL));
        assertToolbarPersistence(false, visibilityDelegate);
        TestThreadUtils.runOnUiThreadBlocking(()
                                                      -> sActivityTestRule.getActivity()
                                                                 .getTabModelSelector()
                                                                 .getCurrentModel()
                                                                 .closeTab(newTab));
        assertToolbarPersistence(true, visibilityDelegate);
    }

    /**
     * Tests that the progressbar behaves as expected when TabbedPaintPreview is showing.
     * Progressbar updates should be prevented when the current tab is showing a paint preview. A
     * progressbar fill simulation should be requested when paint preview is removed.
     */
    @Test
    @MediumTest
    public void testProgressbar() throws ExecutionException {
        Tab tab = sActivityTestRule.getActivity().getActivityTab();
        TabbedPaintPreview tabbedPaintPreview =
                TestThreadUtils.runOnUiThreadBlocking(() -> TabbedPaintPreview.get(tab));

        CallbackHelper simulateCallback = new CallbackHelper();
        BooleanCallbackHelper preventionCallback = new BooleanCallbackHelper();
        tabbedPaintPreview.setProgressSimulatorNeededCallback(simulateCallback::notifyCalled);
        tabbedPaintPreview.setProgressbarUpdatePreventionCallback(preventionCallback::set);
        PlayerManager.Listener emptyListener = new EmptyPlayerListener();

        // Paint Preview not showing.
        Assert.assertEquals("Progressbar simulate callback shouldn't have been called.", 0,
                simulateCallback.getCallCount());
        assertProgressbarUpdatePreventionCallback(false, preventionCallback);

        // Paint Preview showing in the current tab.
        TestThreadUtils.runOnUiThreadBlocking(() -> tabbedPaintPreview.maybeShow(emptyListener));
        assertProgressbarUpdatePreventionCallback(true, preventionCallback);

        // Switch to a new tab that doesn't show paint preview.
        Tab newTab = sActivityTestRule.loadUrlInNewTab(
                sActivityTestRule.getTestServer().getURL(TEST_URL));
        assertProgressbarUpdatePreventionCallback(false, preventionCallback);

        // Close the new tab, we should be back at the old tab with the paint preview showing.
        TestThreadUtils.runOnUiThreadBlocking(()
                                                      -> sActivityTestRule.getActivity()
                                                                 .getTabModelSelector()
                                                                 .getCurrentModel()
                                                                 .closeTab(newTab));
        assertProgressbarUpdatePreventionCallback(true, preventionCallback);

        // Remove paint preview.
        Assert.assertEquals("Should have not requested progressbar fill simulation.", 0,
                simulateCallback.getCallCount());
        TestThreadUtils.runOnUiThreadBlocking(() -> tabbedPaintPreview.remove(false, false));
        Assert.assertEquals("Should have requested progressbar fill simulation.", 1,
                simulateCallback.getCallCount());
        assertProgressbarUpdatePreventionCallback(false, preventionCallback);
    }

    private static class BooleanCallbackHelper {
        private boolean mLastResult;

        public boolean get() {
            return mLastResult;
        }

        public void set(boolean lastResult) {
            this.mLastResult = lastResult;
        }
    }

    private void assertProgressbarUpdatePreventionCallback(
            boolean expected, BooleanCallbackHelper callbackHelper) {
        String message = expected ? "Progressbar updates should be prevented."
                                  : "Progressbar updates should not be prevented.";
        CriteriaHelper.pollInstrumentationThread(() -> expected == callbackHelper.get(), message);
    }

    private void assertToolbarPersistence(
            boolean expected, TestControlsVisibilityDelegate visibilityDelegate) {
        String message =
                expected ? "Toolbar should be persistent." : "Toolbar should not be persistent.";
        CriteriaHelper.pollInstrumentationThread(
                () -> expected == visibilityDelegate.isPersistent(), message);
    }

    public static void assertAttachedAndShown(
            TabbedPaintPreview tabbedPaintPreview, boolean attached, boolean shown) {
        String attachedMessage = attached ? "Paint Preview should be attached."
                                          : "Paint Preview should not be attached.";
        String shownMessage =
                shown ? "Paint Preview should be shown." : "Paint Preview should not be shown.";
        CriteriaHelper.pollUiThread(
                () -> tabbedPaintPreview.isAttached() == attached, attachedMessage);
        CriteriaHelper.pollUiThread(() -> tabbedPaintPreview.isShowing() == shown, shownMessage);
    }

    private static class TestControlsVisibilityDelegate
            extends BrowserStateBrowserControlsVisibilityDelegate {
        private int mLastToken = TokenHolder.INVALID_TOKEN;

        public TestControlsVisibilityDelegate() {
            super(new ObservableSupplier<Boolean>() {
                @Override
                public Boolean addObserver(Callback<Boolean> obs) {
                    return false;
                }

                @Override
                public void removeObserver(Callback<Boolean> obs) {}

                @Override
                public Boolean get() {
                    return false;
                }
            });
        }

        public boolean isPersistent() {
            return mLastToken != TokenHolder.INVALID_TOKEN;
        }

        @Override
        public int showControlsPersistent() {
            Assert.assertEquals("Lock toolbar persistence is called before releasing a "
                            + "previous token.",
                    mLastToken, TokenHolder.INVALID_TOKEN);
            mLastToken = super.showControlsPersistent();
            return mLastToken;
        }

        @Override
        public void releasePersistentShowingToken(int token) {
            Assert.assertEquals("Release toolbar persistence is called with the wrong"
                            + "token.",
                    mLastToken, token);
            super.releasePersistentShowingToken(token);
            mLastToken = TokenHolder.INVALID_TOKEN;
        }
    }

    /**
     * Dummy implementation of {@link PlayerCompositorDelegate}.
     */
    public static class TestCompositorDelegate implements PlayerCompositorDelegate {
        TestCompositorDelegate(NativePaintPreviewServiceProvider service, GURL url,
                String directoryKey, @NonNull CompositorListener compositorListener,
                Callback<Integer> compositorErrorCallback) {
            new Handler().postDelayed(() -> {
                Parcel parcel = Parcel.obtain();
                parcel.writeLong(4577L);
                parcel.writeLong(23L);
                parcel.setDataPosition(0);
                UnguessableToken token = UnguessableToken.CREATOR.createFromParcel(parcel);
                compositorListener.onCompositorReady(token, new UnguessableToken[] {token},
                        new int[] {500, 500}, new int[] {0, 0}, new int[] {0}, null, null);
            }, 50);
        }

        @Override
        public void requestBitmap(UnguessableToken frameGuid, Rect clipRect, float scaleFactor,
                Callback<Bitmap> bitmapCallback, Runnable errorCallback) {
            new Handler().postDelayed(() -> {
                Bitmap emptyBitmap = Bitmap.createBitmap(
                        clipRect.width(), clipRect.height(), Bitmap.Config.ARGB_4444);
                bitmapCallback.onResult(emptyBitmap);
            }, 100);
        }

        @Override
        public GURL onClick(UnguessableToken frameGuid, int x, int y) {
            return null;
        }

        @Override
        public void setCompressOnClose(boolean compressOnClose) {}

        @Override
        public void destroy() {}
    }

    /**
     * Blank implementation of {@link PlayerManager.Listener}.
     */
    public static class EmptyPlayerListener implements PlayerManager.Listener {
        @Override
        public void onCompositorError(int status) {}

        @Override
        public void onViewReady() {}

        @Override
        public void onFirstPaint() {}

        @Override
        public void onUserInteraction() {}

        @Override
        public void onUserFrustration() {}

        @Override
        public void onPullToRefresh() {}

        @Override
        public void onLinkClick(GURL url) {}
    }
}
