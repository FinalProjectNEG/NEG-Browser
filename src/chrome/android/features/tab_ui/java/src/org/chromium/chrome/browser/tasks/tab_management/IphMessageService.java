// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.tasks.tab_management;

import android.annotation.SuppressLint;

import org.chromium.chrome.browser.feature_engagement.TrackerFactory;
import org.chromium.chrome.browser.profiles.Profile;
import org.chromium.components.feature_engagement.FeatureConstants;
import org.chromium.components.feature_engagement.Tracker;

/**
 * One of the concrete {@link MessageService} that only serves {@link MessageType.IPH}.
 */
public class IphMessageService extends MessageService {
    private final TabSwitcherCoordinator.IphController mIphController;
    private final Tracker mTracker;

    /**
     * This is the data type that this MessageService is serving to its Observer.
     */
    class IphMessageData implements MessageData {
        private final MessageCardView.ReviewActionProvider mReviewActionProvider;
        private final MessageCardView.DismissActionProvider mDismissActionProvider;

        IphMessageData(MessageCardView.ReviewActionProvider reviewActionProvider,
                MessageCardView.DismissActionProvider dismissActionProvider) {
            mReviewActionProvider = reviewActionProvider;
            mDismissActionProvider = dismissActionProvider;
        }

        /**
         * @return The {@link MessageCardView.ReviewActionProvider} for the associated IPH.
         */
        MessageCardView.ReviewActionProvider getReviewActionProvider() {
            return mReviewActionProvider;
        }

        /**
         * @return The {@link MessageCardView.DismissActionProvider} for the associated IPH.
         */
        MessageCardView.DismissActionProvider getDismissActionProvider() {
            return mDismissActionProvider;
        }
    }

    IphMessageService(TabSwitcherCoordinator.IphController controller) {
        super(MessageType.IPH);
        mIphController = controller;
        Profile profile = Profile.getLastUsedRegularProfile().getOriginalProfile();
        mTracker = TrackerFactory.getTrackerForProfile(profile);
    }

    private void review() {
        mIphController.showIph();
    }

    @SuppressLint("CheckResult")
    private void dismiss() {
        mTracker.shouldTriggerHelpUI(FeatureConstants.TAB_GROUPS_DRAG_AND_DROP_FEATURE);
        mTracker.dismissed(FeatureConstants.TAB_GROUPS_DRAG_AND_DROP_FEATURE);
    }

    @Override
    public void addObserver(MessageObserver observer) {
        super.addObserver(observer);
        mTracker.addOnInitializedCallback(result -> {
            assert mTracker.isInitialized();

            if (mTracker.wouldTriggerHelpUI(FeatureConstants.TAB_GROUPS_DRAG_AND_DROP_FEATURE)) {
                sendAvailabilityNotification(
                        new IphMessageData(this::review, (int messageType) -> dismiss()));
            }
        });
    }
}
