// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.video_tutorials.iph;

import android.content.Context;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.view.ViewStub;

import org.chromium.base.Callback;
import org.chromium.chrome.browser.image_fetcher.ImageFetcher;
import org.chromium.chrome.browser.video_tutorials.Tutorial;
import org.chromium.chrome.browser.video_tutorials.VideoTutorialUtils;
import org.chromium.ui.modelutil.PropertyModel;
import org.chromium.ui.modelutil.PropertyModelChangeProcessor;

/**
 * Creates and shows a video tutorial IPH. Requires a {@link ViewStub} to be passed which will
 * inflate when the IPH is shown.
 */
public class VideoIPHCoordinatorImpl implements VideoIPHCoordinator {
    private final Context mContext;
    private final PropertyModel mModel;
    private final VideoIPHView mView;
    private final ImageFetcher mImageFetcher;
    private final Callback<Tutorial> mOnClickListener;
    private final Callback<Tutorial> mOnDismissListener;

    /**
     * Constructor.
     * @param viewStub The view stub which will inflate to show the IPH.
     * @param imageFetcher The {@link ImageFetcher} to fetch thumbnail.
     * @param onClickListener The on click listener that starts playing IPH.
     * @param onDismissListener The listener to be invoked on dismissal.
     */
    public VideoIPHCoordinatorImpl(ViewStub viewStub, ImageFetcher imageFetcher,
            Callback<Tutorial> onClickListener, Callback<Tutorial> onDismissListener) {
        mContext = viewStub.getContext();
        mImageFetcher = imageFetcher;
        mOnClickListener = onClickListener;
        mOnDismissListener = onDismissListener;

        mModel = new PropertyModel(VideoIPHProperties.ALL_KEYS);
        mView = new VideoIPHView(viewStub);
        PropertyModelChangeProcessor.create(mModel, mView, VideoIPHView::bind);
    }

    @Override
    public void showVideoIPH(Tutorial tutorial) {
        mModel.set(VideoIPHProperties.VISIBILITY, true);
        mModel.set(VideoIPHProperties.DISPLAY_TITLE, tutorial.displayTitle);
        mModel.set(VideoIPHProperties.VIDEO_LENGTH,
                VideoTutorialUtils.getVideoLengthString(tutorial.videoLength));
        mModel.set(VideoIPHProperties.CLICK_LISTENER, () -> mOnClickListener.onResult(tutorial));
        mModel.set(
                VideoIPHProperties.DISMISS_LISTENER, () -> mOnDismissListener.onResult(tutorial));

        mModel.set(VideoIPHProperties.THUMBNAIL_PROVIDER, (consumer, widthPx, heightPx) -> {
            return () -> {
                ImageFetcher.Params params = ImageFetcher.Params.create(tutorial.posterUrl,
                        ImageFetcher.VIDEO_TUTORIALS_IPH_UMA_CLIENT_NAME, widthPx, heightPx);
                mImageFetcher.fetchImage(params, bitmap -> {
                    Drawable drawable = bitmap == null
                            ? null
                            : new BitmapDrawable(mContext.getResources(), bitmap);
                    consumer.onResult(drawable);
                });
            };
        });
    }

    @Override
    public void hideVideoIPH() {
        mModel.set(VideoIPHProperties.VISIBILITY, false);
    }
}