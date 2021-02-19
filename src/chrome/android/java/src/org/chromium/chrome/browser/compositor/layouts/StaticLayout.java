// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.compositor.layouts;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.RectF;
import android.os.Handler;

import androidx.annotation.VisibleForTesting;

import org.chromium.base.Callback;
import org.chromium.base.supplier.ObservableSupplier;
import org.chromium.chrome.browser.browser_controls.BrowserControlsStateProvider;
import org.chromium.chrome.browser.compositor.LayerTitleCache;
import org.chromium.chrome.browser.compositor.animation.CompositorAnimationHandler;
import org.chromium.chrome.browser.compositor.animation.CompositorAnimator;
import org.chromium.chrome.browser.compositor.layouts.components.LayoutTab;
import org.chromium.chrome.browser.compositor.layouts.content.TabContentManager;
import org.chromium.chrome.browser.compositor.layouts.eventfilter.EventFilter;
import org.chromium.chrome.browser.compositor.scene_layer.SceneLayer;
import org.chromium.chrome.browser.compositor.scene_layer.StaticTabSceneLayer;
import org.chromium.chrome.browser.native_page.NativePageFactory;
import org.chromium.chrome.browser.tab.SadTab;
import org.chromium.chrome.browser.tab.Tab;
import org.chromium.chrome.browser.tab.TabSelectionType;
import org.chromium.chrome.browser.tab.TabThemeColorHelper;
import org.chromium.chrome.browser.tabmodel.TabModelImpl;
import org.chromium.chrome.browser.tabmodel.TabModelSelector;
import org.chromium.chrome.browser.tabmodel.TabModelSelectorTabModelObserver;
import org.chromium.chrome.browser.tabmodel.TabModelSelectorTabObserver;
import org.chromium.chrome.browser.toolbar.ToolbarColors;
import org.chromium.components.embedder_support.util.UrlConstants;
import org.chromium.ui.modelutil.PropertyModel;
import org.chromium.ui.resources.ResourceManager;

import java.util.Arrays;
import java.util.LinkedList;

// TODO(meiliang): Rename to StaticLayoutMediator.
/**
 * A {@link Layout} that shows a single tab at full screen. This tab is chosen based on the
 * {@link #tabSelecting(long, int)} call, and is used to show a thumbnail of a {@link Tab}
 * until that {@link Tab} is ready to be shown.
 */
public class StaticLayout extends Layout {
    public static final String TAG = "StaticLayout";

    private static final int HIDE_TIMEOUT_MS = 2000;
    private static final int HIDE_DURATION_MS = 500;

    private boolean mHandlesTabLifecycles;

    private class UnstallRunnable implements Runnable {
        @Override
        public void run() {
            mUnstalling = false;
            CompositorAnimator
                    .ofWritableFloatPropertyKey(mAnimationHandler, mModel, LayoutTab.SATURATION,
                            mModel.get(LayoutTab.SATURATION), 1.0f, HIDE_DURATION_MS)
                    .start();
            CompositorAnimator
                    .ofWritableFloatPropertyKey(mAnimationHandler, mModel,
                            LayoutTab.STATIC_TO_VIEW_BLEND,
                            mModel.get(LayoutTab.STATIC_TO_VIEW_BLEND), 0.0f, HIDE_DURATION_MS)
                    .start();
            mModel.set(LayoutTab.SHOULD_STALL, false);
        }
    }
    private final Context mContext;
    private final LayoutManagerHost mViewHost;
    private final CompositorModelChangeProcessor.FrameRequestSupplier mRequestSupplier;

    private final PropertyModel mModel;
    private CompositorModelChangeProcessor mMcp;

    private StaticTabSceneLayer mSceneLayer;

    private final UnstallRunnable mUnstallRunnable;
    private final Handler mHandler;
    private boolean mUnstalling;

    private TabModelSelector mTabModelSelector;
    private TabModelSelectorTabModelObserver mTabModelSelectorTabModelObserver;
    private TabModelSelectorTabObserver mTabModelSelectorTabObserver;

    private BrowserControlsStateProvider mBrowserControlsStateProvider;
    private BrowserControlsStateProvider.Observer mBrowserControlsStateProviderObserver;

    private TabContentManager mTabContentManager;

    private final CompositorAnimationHandler mAnimationHandler;

    private boolean mIsActive;
    private boolean mIsInitialized;

    private static Integer sToolbarTextBoxBackgroundColorForTesting;
    private static Float sToolbarTextBoxAlphaForTesting;

    private float mPxToDp;

    /**
     * Creates an instance of the {@link StaticLayout}.
     * @param context             The current Android's context.
     * @param updateHost          The {@link LayoutUpdateHost} view for this layout.
     * @param renderHost          The {@link LayoutRenderHost} view for this layout.
     */
    public StaticLayout(Context context, LayoutUpdateHost updateHost, LayoutRenderHost renderHost,
            LayoutManagerHost viewHost,
            CompositorModelChangeProcessor.FrameRequestSupplier requestSupplier,
            TabModelSelector tabModelSelector, TabContentManager tabContentManager,
            ObservableSupplier<BrowserControlsStateProvider> browserControlsStateProviderSupplier) {
        super(context, updateHost, renderHost);
        mContext = context;
        mViewHost = viewHost;
        mRequestSupplier = requestSupplier;
        assert tabContentManager != null;
        mTabContentManager = tabContentManager;

        assert tabModelSelector != null;
        setTabModelSelector(tabModelSelector);

        browserControlsStateProviderSupplier.addObserver(
                new Callback<BrowserControlsStateProvider>() {
                    @Override
                    public void onResult(
                            BrowserControlsStateProvider browserControlsStateProvider) {
                        setBrowserControlsStateProvider(browserControlsStateProvider);
                        browserControlsStateProviderSupplier.removeObserver(this);
                    }
                });

        mModel = new PropertyModel.Builder(LayoutTab.ALL_KEYS)
                         .with(LayoutTab.TAB_ID, Tab.INVALID_TAB_ID)
                         .with(LayoutTab.SCALE, 1.0f)
                         .with(LayoutTab.X, 0.0f)
                         .with(LayoutTab.Y, 0.0f)
                         .with(LayoutTab.RENDER_X, 0.0f)
                         .with(LayoutTab.RENDER_Y, 0.0f)
                         .with(LayoutTab.SATURATION, 1.0f)
                         .with(LayoutTab.STATIC_TO_VIEW_BLEND, 0.0f)
                         .with(LayoutTab.BRIGHTNESS, 1.0f)
                         .build();

        mAnimationHandler = updateHost.getAnimationHandler();

        mHandler = new Handler();
        mUnstallRunnable = new UnstallRunnable();
        mUnstalling = false;

        Resources res = context.getResources();
        float dpToPx = res.getDisplayMetrics().density;
        mPxToDp = 1.0f / dpToPx;
    }

    private void setTabModelSelector(TabModelSelector tabModelSelector) {
        assert tabModelSelector != null;
        assert mTabModelSelector == null : "The TabModelSelector should set at most once";

        mTabModelSelector = tabModelSelector;
        // TODO(crbug.com/1070281): Investigating to use ActivityTabProvider instead.
        mTabModelSelectorTabModelObserver = new TabModelSelectorTabModelObserver(tabModelSelector) {
            @Override
            public void didSelectTab(Tab tab, int type, int lastId) {
                if (mIsActive) setStaticTab(tab);
            }
        };

        mTabModelSelectorTabObserver = new TabModelSelectorTabObserver(tabModelSelector) {
            @Override
            public void onPageLoadFinished(Tab tab, String url) {
                if (mIsActive) unstallImmediately(tab.getId());
            }
            @Override
            public void onShown(Tab tab, @TabSelectionType int type) {
                if (mModel.get(LayoutTab.TAB_ID) != tab.getId()) {
                    setStaticTab(tab);
                } else {
                    updateStaticTab(tab);
                }
            }

            @Override
            public void onContentChanged(Tab tab) {
                updateStaticTab(tab);
            }

            @Override
            public void onBackgroundColorChanged(Tab tab, int color) {
                updateStaticTab(tab);
            }

            @Override
            public void onDidChangeThemeColor(Tab tab, int color) {
                updateStaticTab(tab);
            }
        };
    }

    private void setBrowserControlsStateProvider(
            BrowserControlsStateProvider browserControlsStateProvider) {
        assert browserControlsStateProvider != null;
        assert mBrowserControlsStateProvider
                == null : "The ChromeFullscreenManager should set at most once";

        mModel.set(LayoutTab.CONTENT_OFFSET, browserControlsStateProvider.getContentOffset());
        mBrowserControlsStateProvider = browserControlsStateProvider;
        mBrowserControlsStateProviderObserver = new BrowserControlsStateProvider.Observer() {
            @Override
            public void onControlsOffsetChanged(int topOffset, int topControlsMinHeightOffset,
                    int bottomOffset, int bottomControlsMinHeightOffset, boolean needsAnimate) {
                mModel.set(
                        LayoutTab.CONTENT_OFFSET, browserControlsStateProvider.getContentOffset());
            }
        };
        mBrowserControlsStateProvider.addObserver(mBrowserControlsStateProviderObserver);
    }

    /**
     * @param handlesTabLifecycles Whether or not this {@link Layout} should handle tab closing and
     *                             creating events.
     */
    public void setLayoutHandlesTabLifecycles(boolean handlesTabLifecycles) {
        mHandlesTabLifecycles = handlesTabLifecycles;
    }

    @Override
    public void onFinishNativeInitialization() {
        assert !mIsInitialized : "StaticLayoutMediator should initialize at most once";

        mIsInitialized = true;
        if (mSceneLayer == null) {
            mSceneLayer = new StaticTabSceneLayer();
            mSceneLayer.setTabContentManager(mTabContentManager);
        }

        mMcp = CompositorModelChangeProcessor.create(
                mModel, mSceneLayer, StaticTabSceneLayer::bind, mRequestSupplier);
    }

    @Override
    public @ViewportMode int getViewportMode() {
        return ViewportMode.DYNAMIC_BROWSER_CONTROLS;
    }

    /**
     * Initialize the layout to be shown.
     * @param time   The current time of the app in ms.
     * @param animate Whether to play an entry animation.
     */
    @Override
    public void show(long time, boolean animate) {
        super.show(time, animate);

        mIsActive = true;
        Tab tab = mTabModelSelector.getCurrentTab();
        if (tab == null) return;
        setStaticTab(tab);
    }

    @Override
    protected void updateLayout(long time, long dt) {
        super.updateLayout(time, dt);
        updateSnap(dt, mModel);
    }

    @Override
    public void doneHiding() {
        super.doneHiding();
        mIsActive = false;
    }

    @Override
    public void onTabSelected(long time, int id, int prevId, boolean incognito) {

    }

    @Override
    public void onTabSelecting(long time, int id) {

    }

    @Override
    public void onTabCreated(long time, int tabId, int tabIndex, int sourceTabId,
            boolean newIsIncognito, boolean background, float originX, float originY) {
    }

    @Override
    public void onTabModelSwitched(boolean incognito) {
    }

    @Override
    public void setTabModelSelector(TabModelSelector modelSelector, TabContentManager manager) {}

    private void setPreHideState() {
        mHandler.removeCallbacks(mUnstallRunnable);
        mModel.set(LayoutTab.STATIC_TO_VIEW_BLEND, 1.0f);
        mModel.set(LayoutTab.SATURATION, 0.0f);
        mUnstalling = true;
    }

    private void setPostHideState() {
        mHandler.removeCallbacks(mUnstallRunnable);
        mModel.set(LayoutTab.STATIC_TO_VIEW_BLEND, 0.0f);
        mModel.set(LayoutTab.SATURATION, 1.0f);
        mUnstalling = false;
    }

    private void setStaticTab(Tab tab) {
        assert tab != null;

        if (mModel.get(LayoutTab.TAB_ID) == tab.getId() && !mModel.get(LayoutTab.SHOULD_STALL)) {
            setPostHideState();
            return;
        }

        if (mTabContentManager != null) {
            mTabContentManager.updateVisibleIds(
                    new LinkedList<Integer>(Arrays.asList(tab.getId())), tab.getId());
        }

        mModel.set(LayoutTab.TAB_ID, tab.getId());
        mModel.set(LayoutTab.IS_INCOGNITO, tab.isIncognito());
        mModel.set(LayoutTab.ORIGINAL_CONTENT_WIDTH_IN_DP, mViewHost.getWidth() * mPxToDp);
        mModel.set(LayoutTab.ORIGINAL_CONTENT_HEIGHT_IN_DP, mViewHost.getHeight() * mPxToDp);
        mModel.set(LayoutTab.MAX_CONTENT_WIDTH, mViewHost.getWidth() * mPxToDp);
        mModel.set(LayoutTab.MAX_CONTENT_HEIGHT, mViewHost.getHeight() * mPxToDp);

        updateStaticTab(tab);

        if (mModel.get(LayoutTab.SHOULD_STALL)) {
            setPreHideState();
            mHandler.postDelayed(mUnstallRunnable, HIDE_TIMEOUT_MS);
        } else {
            setPostHideState();
        }
    }

    private void updateStaticTab(Tab tab) {
        if (!mIsActive || mModel.get(LayoutTab.TAB_ID) != tab.getId()) return;

        mModel.set(LayoutTab.BACKGROUND_COLOR, TabThemeColorHelper.getBackgroundColor(tab));
        mModel.set(LayoutTab.TOOLBAR_BACKGROUND_COLOR,
                ToolbarColors.getToolbarSceneLayerBackground(tab));
        mModel.set(LayoutTab.TEXT_BOX_ALPHA, getTextBoxAlphaForToolbarBackground(tab));
        mModel.set(LayoutTab.SHOULD_STALL, shouldStall(tab));
        mModel.set(LayoutTab.TEXT_BOX_BACKGROUND_COLOR, getToolbarTextBoxBackgroundColor(tab));

        String url = tab.getUrlString();
        boolean isNativePage = tab.isNativePage()
                || (url != null && url.startsWith(UrlConstants.CHROME_NATIVE_URL_PREFIX));
        boolean canUseLiveTexture =
                tab.getWebContents() != null && !SadTab.isShowing(tab) && !isNativePage;
        mModel.set(LayoutTab.CAN_USE_LIVE_TEXTURE, canUseLiveTexture);
    }

    private int getToolbarTextBoxBackgroundColor(Tab tab) {
        if (sToolbarTextBoxBackgroundColorForTesting != null) {
            return sToolbarTextBoxBackgroundColorForTesting;
        }

        int themeColor = TabThemeColorHelper.getColor(tab);
        return ToolbarColors.getTextBoxColorForToolbarBackground(
                mContext.getResources(), tab, themeColor);
    }

    @VisibleForTesting
    void setTextBoxBackgroundColorForTesting(Integer color) {
        sToolbarTextBoxBackgroundColorForTesting = color;
    }

    private float getTextBoxAlphaForToolbarBackground(Tab tab) {
        if (sToolbarTextBoxAlphaForTesting != null) return sToolbarTextBoxAlphaForTesting;
        return ToolbarColors.getTextBoxAlphaForToolbarBackground(tab);
    }

    @VisibleForTesting
    void setToolbarTextBoxAlphaForTesting(Float alpha) {
        sToolbarTextBoxAlphaForTesting = alpha;
    }

    // Whether the tab is ready to display or it should be faded in as it loads.
    private boolean shouldStall(Tab tab) {
        return (tab.isFrozen() || tab.needsReload())
                && !NativePageFactory.isNativePageUrl(tab.getUrlString(), tab.isIncognito());
    }

    @Override
    public void unstallImmediately(int tabId) {
        if (mModel.get(LayoutTab.TAB_ID) == tabId && mModel.get(LayoutTab.SHOULD_STALL)
                && mUnstalling) {
            unstallImmediately();
        }
    }

    @Override
    public void unstallImmediately() {
        if (mModel.get(LayoutTab.SHOULD_STALL) && mUnstalling) {
            mHandler.removeCallbacks(mUnstallRunnable);
            mUnstallRunnable.run();
        }
    }

    @Override
    public boolean handlesTabCreating() {
        return super.handlesTabCreating() || mHandlesTabLifecycles;
    }

    @Override
    public boolean handlesTabClosing() {
        return mHandlesTabLifecycles;
    }

    @Override
    public boolean handlesCloseAll() {
        return mHandlesTabLifecycles;
    }

    @Override
    public boolean shouldDisplayContentOverlay() {
        return true;
    }

    @Override
    protected EventFilter getEventFilter() {
        return null;
    }

    @Override
    protected SceneLayer getSceneLayer() {
        return mSceneLayer;
    }

    @Override
    protected void updateSceneLayer(RectF viewport, RectF contentViewport,
            LayerTitleCache layerTitleCache, TabContentManager tabContentManager,
            ResourceManager resourceManager, BrowserControlsStateProvider browserControls) {
        super.updateSceneLayer(viewport, contentViewport, layerTitleCache, tabContentManager,
                resourceManager, browserControls);
        assert mSceneLayer != null;

        // TODO(dtrainor, crbug.com/1070281): Find the best way to properly track this metric for
        //  cold starts. We should probably erase the thumbnail when we select a tab that we need to
        //  restore. Potentially move to show().
        if (tabContentManager != null
                && tabContentManager.hasFullCachedThumbnail(mModel.get(LayoutTab.TAB_ID))) {
            TabModelImpl.logPerceivedTabSwitchLatencyMetric();
        }
    }

    @Override
    public void destroy() {
        if (mSceneLayer != null) {
            mSceneLayer.destroy();
            mSceneLayer = null;
        }
        if (mMcp != null) {
            mMcp.destroy();
            mMcp = null;
        }
        if (mTabModelSelector != null) {
            mTabModelSelectorTabModelObserver.destroy();
            mTabModelSelectorTabObserver.destroy();
        }
    }

    @VisibleForTesting
    PropertyModel getModelForTesting() {
        return mModel;
    }

    @VisibleForTesting
    void setSceneLayerForTesting(StaticTabSceneLayer sceneLayer) {
        mSceneLayer = sceneLayer;
    }

    @VisibleForTesting
    TabModelSelector getTabModelSelectorForTesting() {
        return mTabModelSelector;
    }

    @VisibleForTesting
    TabContentManager getTabContentManagerForTesting() {
        return mTabContentManager;
    }

    @VisibleForTesting
    BrowserControlsStateProvider getBrowserControlsStateProviderForTesting() {
        return mBrowserControlsStateProvider;
    }

    @VisibleForTesting
    public int getCurrentTabIdForTesting() {
        return mModel.get(LayoutTab.TAB_ID);
    }
}
