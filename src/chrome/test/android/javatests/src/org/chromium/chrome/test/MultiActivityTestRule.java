// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.test;

import android.content.Context;
import android.support.test.InstrumentationRegistry;

import org.hamcrest.Matchers;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import org.chromium.base.test.util.CallbackHelper;
import org.chromium.chrome.browser.app.ChromeActivity;
import org.chromium.chrome.browser.tab.Tab;
import org.chromium.chrome.browser.tab.TabCreationState;
import org.chromium.chrome.browser.tabmodel.EmptyTabModelSelectorObserver;
import org.chromium.chrome.test.util.ApplicationTestUtils;
import org.chromium.chrome.test.util.ChromeTabUtils;
import org.chromium.content_public.browser.test.util.Criteria;
import org.chromium.content_public.browser.test.util.CriteriaHelper;

import java.util.concurrent.TimeoutException;

/** Custom TestRule for MultiActivity Tests. */
public class MultiActivityTestRule implements TestRule {
    private static final String TAG = "MultiActivityTest";

    Context mContext;

    public Context getContext() {
        return mContext;
    }

    public void waitForFullLoad(final ChromeActivity activity, final String expectedTitle)
            throws TimeoutException {
        waitForTabCreation(activity);

        ApplicationTestUtils.assertWaitForPageScaleFactorMatch(activity, 0.5f);
        final Tab tab = activity.getActivityTab();
        assert tab != null;

        CriteriaHelper.pollUiThread(() -> {
            Criteria.checkThat(ChromeTabUtils.isLoadingAndRenderingDone(tab), Matchers.is(true));
            Criteria.checkThat(tab.getTitle(), Matchers.is(expectedTitle));
        });
    }

    private void waitForTabCreation(ChromeActivity activity) throws TimeoutException {
        final CallbackHelper newTabCreatorHelper = new CallbackHelper();
        activity.getTabModelSelector().addObserver(new EmptyTabModelSelectorObserver() {
            @Override
            public void onNewTabCreated(Tab tab, @TabCreationState int creationState) {
                newTabCreatorHelper.notifyCalled();
            }
        });
        newTabCreatorHelper.waitForCallback(0);
    }

    private void ruleSetUp() {
        mContext = InstrumentationRegistry.getTargetContext();
        ApplicationTestUtils.setUp(mContext);
    }

    private void ruleTearDown() {
        ApplicationTestUtils.tearDown(mContext);
    }

    @Override
    public Statement apply(final Statement base, Description desc) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                ruleSetUp();
                base.evaluate();
                ruleTearDown();
            }
        };
    }
}
