// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.safe_browsing.settings;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.RadioGroup;

import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.preference.Preference;
import androidx.preference.PreferenceViewHolder;

import org.chromium.chrome.browser.safe_browsing.SafeBrowsingState;
import org.chromium.components.browser_ui.settings.ManagedPreferenceDelegate;
import org.chromium.components.browser_ui.settings.ManagedPreferencesUtils;
import org.chromium.components.browser_ui.widget.RadioButtonWithDescription;
import org.chromium.components.browser_ui.widget.RadioButtonWithDescriptionAndAuxButton;
import org.chromium.components.browser_ui.widget.RadioButtonWithDescriptionLayout;

/**
 * <p>
 * A radio button group used for Safe Browsing. Currently, it has 3 options: Enhanced Protection,
 * Standard Protection and No Protection. When the Enhanced Protection flag is disabled, the
 * Enhanced Protection option will be removed.
 * </p>
 *
 * <p>
 * This preference also provides an interface {@link
 * RadioButtonGroupSafeBrowsingPreference.OnSafeBrowsingModeDetailsRequested} that is triggered when
 * more information of a Safe Browsing mode is requested.
 * </p>
 */
public class RadioButtonGroupSafeBrowsingPreference extends Preference
        implements RadioGroup.OnCheckedChangeListener,
                   RadioButtonWithDescriptionAndAuxButton.OnAuxButtonClickedListener {
    /**
     * Interface that will subscribe to Safe Browsing mode details requested events.
     */
    public interface OnSafeBrowsingModeDetailsRequested {
        /**
         * Notify that details of a Safe Browsing mode are requested.
         * @param safeBrowsingState The Safe Browsing mode that is requested for more details.
         */
        void onSafeBrowsingModeDetailsRequested(@SafeBrowsingState int safeBrowsingState);
    }

    private @Nullable RadioButtonWithDescriptionAndAuxButton mEnhancedProtection;
    private RadioButtonWithDescriptionAndAuxButton mStandardProtection;
    private RadioButtonWithDescription mNoProtection;
    private @SafeBrowsingState int mSafeBrowsingState;
    private boolean mIsEnhancedProtectionEnabled;
    private OnSafeBrowsingModeDetailsRequested mSafeBrowsingModeDetailsRequestedListener;
    private ManagedPreferenceDelegate mManagedPrefDelegate;

    public RadioButtonGroupSafeBrowsingPreference(Context context, AttributeSet attrs) {
        super(context, attrs);
        setLayoutResource(R.layout.radio_button_group_safe_browsing_preference);
    }

    /**
     * Set Safe Browsing state and Enhanced Protection state. Called before onBindViewHolder.
     * @param safeBrowsingState The current Safe Browsing state.
     * @param isEnhancedProtectionEnabled Whether to show the Enhanced Protection button.
     */
    public void init(
            @SafeBrowsingState int safeBrowsingState, boolean isEnhancedProtectionEnabled) {
        mSafeBrowsingState = safeBrowsingState;
        mIsEnhancedProtectionEnabled = isEnhancedProtectionEnabled;
        assert ((mSafeBrowsingState != SafeBrowsingState.ENHANCED_PROTECTION)
                || mIsEnhancedProtectionEnabled)
            : "Safe Browsing state shouldn't be enhanced protection when the flag is disabled.";
    }

    @Override
    public void onCheckedChanged(RadioGroup group, int checkedId) {
        if (mIsEnhancedProtectionEnabled && checkedId == mEnhancedProtection.getId()) {
            mSafeBrowsingState = SafeBrowsingState.ENHANCED_PROTECTION;
        } else if (checkedId == mStandardProtection.getId()) {
            mSafeBrowsingState = SafeBrowsingState.STANDARD_PROTECTION;
        } else if (checkedId == mNoProtection.getId()) {
            mSafeBrowsingState = SafeBrowsingState.NO_SAFE_BROWSING;
        } else {
            assert false : "Should not be reached.";
        }
        callChangeListener(mSafeBrowsingState);
    }

    @Override
    public void onBindViewHolder(PreferenceViewHolder holder) {
        super.onBindViewHolder(holder);
        if (mIsEnhancedProtectionEnabled) {
            mEnhancedProtection = (RadioButtonWithDescriptionAndAuxButton) holder.findViewById(
                    R.id.enhanced_protection);
            mEnhancedProtection.setVisibility(View.VISIBLE);
            mEnhancedProtection.setAuxButtonClickedListener(this);
        }
        mStandardProtection = (RadioButtonWithDescriptionAndAuxButton) holder.findViewById(
                R.id.standard_protection);
        mStandardProtection.setAuxButtonClickedListener(this);
        mNoProtection = (RadioButtonWithDescription) holder.findViewById(R.id.no_protection);
        RadioButtonWithDescriptionLayout groupLayout =
                (RadioButtonWithDescriptionLayout) mNoProtection.getRootView();
        groupLayout.setOnCheckedChangeListener(this);

        setCheckedState(mSafeBrowsingState);

        // If Safe Browsing is managed, disable the radio button group, but keep the aux buttons
        // enabled to disclose information.
        if (mManagedPrefDelegate.isPreferenceClickDisabledByPolicy(this)) {
            groupLayout.setEnabled(false);
            if (mIsEnhancedProtectionEnabled) {
                mEnhancedProtection.setAuxButtonEnabled(true);
            }
            mStandardProtection.setAuxButtonEnabled(true);
        }
    }

    @Override
    public void onAuxButtonClicked(int clickedButtonId) {
        assert mSafeBrowsingModeDetailsRequestedListener
                != null : "The listener should be set if the aux button is clickable.";
        if (mIsEnhancedProtectionEnabled && clickedButtonId == mEnhancedProtection.getId()) {
            mSafeBrowsingModeDetailsRequestedListener.onSafeBrowsingModeDetailsRequested(
                    SafeBrowsingState.ENHANCED_PROTECTION);
        } else if (clickedButtonId == mStandardProtection.getId()) {
            mSafeBrowsingModeDetailsRequestedListener.onSafeBrowsingModeDetailsRequested(
                    SafeBrowsingState.STANDARD_PROTECTION);
        } else {
            assert false : "Should not be reached.";
        }
    }

    /**
     * Sets a listener that will be notified when details of a Safe Browsing mode are requested.
     * @param listener New listener that will be notified when details of a Safe Browsing mode are
     *         requested.
     */
    public void setSafeBrowsingModeDetailsRequestedListener(
            OnSafeBrowsingModeDetailsRequested listener) {
        mSafeBrowsingModeDetailsRequestedListener = listener;
    }

    /**
     * Sets the ManagedPreferenceDelegate which will determine whether this preference is managed.
     */
    public void setManagedPreferenceDelegate(ManagedPreferenceDelegate delegate) {
        mManagedPrefDelegate = delegate;
        ManagedPreferencesUtils.initPreference(mManagedPrefDelegate, this);
    }

    /**
     * Sets the checked state of the Safe Browsing radio button group.
     * @param checkedState Set the radio button of checkedState to checked, and set the radio
     *         buttons of other states to unchecked.
     */
    public void setCheckedState(@SafeBrowsingState int checkedState) {
        mSafeBrowsingState = checkedState;
        assert ((checkedState != SafeBrowsingState.ENHANCED_PROTECTION)
                || mIsEnhancedProtectionEnabled)
            : "Checked state shouldn't be enhanced protection when the flag is disabled.";
        if (mIsEnhancedProtectionEnabled) {
            mEnhancedProtection.setChecked(checkedState == SafeBrowsingState.ENHANCED_PROTECTION);
        }
        mStandardProtection.setChecked(checkedState == SafeBrowsingState.STANDARD_PROTECTION);
        mNoProtection.setChecked(checkedState == SafeBrowsingState.NO_SAFE_BROWSING);
    }

    @VisibleForTesting
    public @SafeBrowsingState int getSafeBrowsingStateForTesting() {
        return mSafeBrowsingState;
    }

    @VisibleForTesting
    public RadioButtonWithDescriptionAndAuxButton getEnhancedProtectionButtonForTesting() {
        return mEnhancedProtection;
    }

    @VisibleForTesting
    public RadioButtonWithDescriptionAndAuxButton getStandardProtectionButtonForTesting() {
        return mStandardProtection;
    }

    @VisibleForTesting
    public RadioButtonWithDescription getNoProtectionButtonForTesting() {
        return mNoProtection;
    }
}
