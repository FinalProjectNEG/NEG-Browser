// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.toolbar.top;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.annotation.Config;

import org.chromium.base.test.BaseRobolectricTestRunner;
import org.chromium.chrome.browser.tab.Tab;
import org.chromium.chrome.browser.toolbar.ButtonData;
import org.chromium.chrome.browser.toolbar.ButtonDataProvider;
import org.chromium.chrome.browser.user_education.UserEducationHelper;

import java.util.Arrays;
import java.util.List;

/** Tests for {@link OptionalBrowsingModeButtonController}. */
@RunWith(BaseRobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class OptionalBrowsingModeButtonControllerTest {
    @Mock
    UserEducationHelper mUserEducationHelper;
    @Mock
    ToolbarLayout mToolbarLayout;
    @Mock
    ButtonDataProvider mButtonDataProvider1;
    @Mock
    ButtonDataProvider mButtonDataProvider2;
    @Mock
    ButtonDataProvider mButtonDataProvider3;
    @Mock
    Tab mTab;

    ButtonData mButtonData1;
    ButtonData mButtonData2;
    ButtonData mButtonData3;

    @Captor
    ArgumentCaptor<ButtonDataProvider.ButtonDataObserver> mObserverCaptor1;
    @Captor
    ArgumentCaptor<ButtonDataProvider.ButtonDataObserver> mObserverCaptor2;
    @Captor
    ArgumentCaptor<ButtonDataProvider.ButtonDataObserver> mObserverCaptor3;

    OptionalBrowsingModeButtonController mButtonController;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        mButtonData1 = new ButtonData(true, null, null, 0, false, null, true);
        mButtonData2 = new ButtonData(true, null, null, 0, false, null, true);
        mButtonData3 = new ButtonData(true, null, null, 0, false, null, true);
        doReturn(mButtonData1).when(mButtonDataProvider1).get(mTab);
        doReturn(mButtonData2).when(mButtonDataProvider2).get(mTab);
        doReturn(mButtonData3).when(mButtonDataProvider3).get(mTab);

        List<ButtonDataProvider> buttonDataProviders =
                Arrays.asList(mButtonDataProvider1, mButtonDataProvider2, mButtonDataProvider3);
        mButtonController = new OptionalBrowsingModeButtonController(
                buttonDataProviders, mUserEducationHelper, mToolbarLayout, () -> mTab);
        verify(mButtonDataProvider1, times(1)).addObserver(mObserverCaptor1.capture());
        verify(mButtonDataProvider2, times(1)).addObserver(mObserverCaptor2.capture());
        verify(mButtonDataProvider3, times(1)).addObserver(mObserverCaptor3.capture());
    }

    @Test
    public void allProvidersEligible_highestPrecedenceShown() {
        mButtonController.updateButtonVisibility();
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData1);
    }

    @Test
    public void noProvidersEligible_noneShown() {
        mButtonData1.canShow = false;
        mButtonData2.canShow = false;
        mButtonData3.canShow = false;

        mButtonController.updateButtonVisibility();
        verify(mToolbarLayout, times(0)).updateOptionalButton(any());
    }

    @Test
    public void noProvidersEligible_oneBecomesEligible() {
        mButtonData1.canShow = false;
        mButtonData2.canShow = false;
        mButtonData3.canShow = false;

        mButtonController.updateButtonVisibility();
        verify(mToolbarLayout, times(0)).updateOptionalButton(any());

        mButtonData2.canShow = true;
        mButtonController.buttonDataProviderChanged(mButtonDataProvider2, true);
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData2);
    }

    @Test
    public void higherPrecedenceBecomesEligible() {
        mButtonData1.canShow = false;
        mButtonData2.canShow = false;

        mButtonController.updateButtonVisibility();
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData3);

        mButtonData2.canShow = true;
        mButtonController.buttonDataProviderChanged(mButtonDataProvider2, true);
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData2);

        mButtonData1.canShow = true;
        mButtonController.buttonDataProviderChanged(mButtonDataProvider1, true);
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData1);
    }

    @Test
    public void lowerPrecedenceBecomesEligible() {
        mButtonData2.canShow = false;
        mButtonData3.canShow = false;

        mButtonController.updateButtonVisibility();
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData1);

        mButtonData2.canShow = true;
        mButtonController.buttonDataProviderChanged(mButtonDataProvider2, true);
        verify(mToolbarLayout, times(0)).updateOptionalButton(mButtonData2);
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData1);
    }

    @Test
    public void updateCurrentlyShowingProvider() {
        mButtonController.updateButtonVisibility();
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData1);

        ButtonData newButtonData = new ButtonData(true, null, null, 0, false, null, true);
        doReturn(newButtonData).when(mButtonDataProvider1).get(mTab);
        mButtonController.buttonDataProviderChanged(mButtonDataProvider1, true);
        verify(mToolbarLayout, times(1)).updateOptionalButton(newButtonData);

        newButtonData.canShow = false;
        mButtonController.buttonDataProviderChanged(mButtonDataProvider1, false);
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData2);
    }

    @Test
    public void updateCurrentlyNotShowingProvider() {
        mButtonController.updateButtonVisibility();
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData1);

        ButtonData newButtonData = new ButtonData(true, null, null, 0, false, null, true);
        mButtonController.buttonDataProviderChanged(mButtonDataProvider2, true);
        verify(mToolbarLayout, times(0)).updateOptionalButton(newButtonData);

        newButtonData.canShow = false;
        mButtonController.buttonDataProviderChanged(mButtonDataProvider1, false);
        verify(mToolbarLayout, times(0)).updateOptionalButton(newButtonData);
    }

    @Test
    public void noProvidersEligible_hideCalled() {
        mButtonController.updateButtonVisibility();
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData1);
        mButtonData1.canShow = false;
        mButtonData2.canShow = false;
        mButtonData3.canShow = false;

        mButtonController.updateButtonVisibility();
        verify(mToolbarLayout, times(1)).hideOptionalButton();
    }

    @Test
    public void hintContradictsTrueValue() {
        mButtonData1.canShow = false;
        mButtonController.updateButtonVisibility();
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData2);

        mButtonController.buttonDataProviderChanged(mButtonDataProvider1, true);
        verify(mToolbarLayout, never()).updateOptionalButton(mButtonData1);
    }

    @Test
    public void destroyRemovesObservers() {
        mButtonController.destroy();
        verify(mButtonDataProvider1, times(1)).removeObserver(mObserverCaptor1.getValue());
        verify(mButtonDataProvider2, times(1)).removeObserver(mObserverCaptor2.getValue());
        verify(mButtonDataProvider3, times(1)).removeObserver(mObserverCaptor3.getValue());
    }

    @Test
    public void updateOptionalButtonIsOnEnabled() {
        mButtonData1.isEnabled = false;
        mButtonController.updateButtonVisibility();
        verify(mToolbarLayout, times(1)).updateOptionalButton(mButtonData1);
    }
}
