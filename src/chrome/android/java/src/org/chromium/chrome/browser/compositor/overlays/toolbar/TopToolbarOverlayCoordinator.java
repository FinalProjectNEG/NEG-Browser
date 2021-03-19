// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.compositor.overlays.toolbar;

import android.content.Context;
import android.graphics.RectF;

import org.chromium.base.Callback;
import org.chromium.chrome.R;
import org.chromium.chrome.browser.ActivityTabProvider;
import org.chromium.chrome.browser.browser_controls.BrowserControlsStateProvider;
import org.chromium.chrome.browser.compositor.LayerTitleCache;
import org.chromium.chrome.browser.compositor.layouts.CompositorModelChangeProcessor;
import org.chromium.chrome.browser.compositor.layouts.LayoutManager;
import org.chromium.chrome.browser.compositor.layouts.components.VirtualView;
import org.chromium.chrome.browser.compositor.layouts.eventfilter.EventFilter;
import org.chromium.chrome.browser.compositor.overlays.SceneOverlay;
import org.chromium.chrome.browser.compositor.scene_layer.SceneOverlayLayer;
import org.chromium.components.browser_ui.widget.ClipDrawableProgressBar;
import org.chromium.ui.modelutil.PropertyModel;
import org.chromium.ui.resources.ResourceManager;

import java.util.List;

/** The public interface for the top toolbar texture component. */
public class TopToolbarOverlayCoordinator implements SceneOverlay {
    /** The view state for this overlay. */
    private final PropertyModel mModel;

    /** A handle to the 'view' for this component as the layout manager requires access to it. */
    private final TopToolbarSceneLayer mSceneLayer;

    /** Handles processing updates to the model. */
    private final CompositorModelChangeProcessor mChangeProcessor;

    /** Business logic for this overlay. */
    private final TopToolbarOverlayMediator mMediator;

    public TopToolbarOverlayCoordinator(Context context, LayoutManager layoutManager,
            Callback<ClipDrawableProgressBar.DrawingInfo> progressInfoCallback,
            ActivityTabProvider tabSupplier,
            BrowserControlsStateProvider browserControlsStateProvider) {
        mModel = new PropertyModel.Builder(TopToolbarOverlayProperties.ALL_KEYS)
                         .with(TopToolbarOverlayProperties.RESOURCE_ID, R.id.control_container)
                         .with(TopToolbarOverlayProperties.URL_BAR_RESOURCE_ID,
                                 R.drawable.modern_location_bar)
                         .with(TopToolbarOverlayProperties.VISIBLE, true)
                         .with(TopToolbarOverlayProperties.CONTENT_OFFSET,
                                 browserControlsStateProvider.getContentOffset())
                         .build();
        mSceneLayer = new TopToolbarSceneLayer(() -> layoutManager.getResourceManager());
        mChangeProcessor =
                layoutManager.createCompositorMCP(mModel, mSceneLayer, TopToolbarSceneLayer::bind);

        mMediator = new TopToolbarOverlayMediator(mModel, context, layoutManager,
                progressInfoCallback, tabSupplier, browserControlsStateProvider);
    }

    /**
     * Set whether the android view corresponding with this overlay is showing.
     * @param isVisible Whether the android view is visible.
     */
    public void setIsAndroidViewVisible(boolean isVisible) {
        mMediator.setIsAndroidViewVisible(isVisible);
    }

    /** Clean up this component. */
    public void destroy() {
        mChangeProcessor.destroy();
        mMediator.destroy();
        mSceneLayer.destroy();
    }

    @Override
    public SceneOverlayLayer getUpdatedSceneOverlayTree(RectF viewport, RectF visibleViewport,
            LayerTitleCache layerTitleCache, ResourceManager resourceManager, float yOffset) {
        return mSceneLayer;
    }

    @Override
    public boolean isSceneOverlayTreeShowing() {
        return mMediator.shouldBeAttachedToTree();
    }

    @Override
    public EventFilter getEventFilter() {
        return null;
    }

    @Override
    public void onSizeChanged(
            float width, float height, float visibleViewportOffsetY, int orientation) {}

    @Override
    public void getVirtualViews(List<VirtualView> views) {}

    @Override
    public boolean shouldHideAndroidBrowserControls() {
        return false;
    }

    @Override
    public boolean updateOverlay(long time, long dt) {
        return false;
    }

    @Override
    public boolean onBackPressed() {
        return false;
    }

    @Override
    public boolean handlesTabCreating() {
        return false;
    }
}
