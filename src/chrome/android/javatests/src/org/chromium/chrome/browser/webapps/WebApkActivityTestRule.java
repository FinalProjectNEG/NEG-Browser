// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.webapps;

import android.content.Intent;
import android.support.test.InstrumentationRegistry;

import org.hamcrest.Matchers;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import org.chromium.base.test.util.ScalableTimeout;
import org.chromium.chrome.browser.ShortcutHelper;
import org.chromium.chrome.browser.browserservices.BrowserServicesIntentDataProvider;
import org.chromium.chrome.test.ChromeActivityTestRule;
import org.chromium.chrome.test.util.ChromeTabUtils;
import org.chromium.content_public.browser.test.util.Criteria;
import org.chromium.content_public.browser.test.util.CriteriaHelper;
import org.chromium.webapk.lib.common.WebApkConstants;

/** Custom {@link ChromeActivityTestRule} for tests using a WebAPK {@link WebappActivity}. */
public class WebApkActivityTestRule extends ChromeActivityTestRule<WebappActivity> {
    /** Time in milliseconds to wait for page to be loaded. */
    private static final long STARTUP_TIMEOUT = ScalableTimeout.scaleTimeout(10000);

    public WebApkActivityTestRule() {
        super(WebappActivity.class);
    }

    @Override
    public Statement apply(final Statement base, Description description) {
        Statement webApkUpdateManagerStatement = new Statement() {
            @Override
            public void evaluate() throws Throwable {
                WebApkUpdateManager.setUpdatesEnabledForTesting(false);

                base.evaluate();

                WebApkUpdateManager.setUpdatesEnabledForTesting(true);
            }
        };
        return super.apply(webApkUpdateManagerStatement, description);
    }

    /**
     * Launches a WebAPK Activity and waits for the page to have finished loading and for the splash
     * screen to be hidden.
     */
    public WebappActivity startWebApkActivity(
            BrowserServicesIntentDataProvider webApkIntentDataProvider) {
        WebappInfo webApkInfo = WebappInfo.create(webApkIntentDataProvider);
        Intent intent = createIntent(webApkInfo);
        WebappActivity.setIntentDataProviderForTesting(webApkIntentDataProvider);

        return startWebApkActivity(intent, webApkInfo.url());
    }

    /**
     * Launches a WebAPK Activity and waits for the page to have finished loading and for the splash
     * screen to be hidden.
     */
    public WebappActivity startWebApkActivity(final String startUrl) {
        Intent intent =
                new Intent(InstrumentationRegistry.getTargetContext(), WebappActivity.class);
        intent.putExtra(WebApkConstants.EXTRA_WEBAPK_PACKAGE_NAME, "org.chromium.webapk.test");
        intent.putExtra(ShortcutHelper.EXTRA_URL, startUrl);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

        return startWebApkActivity(intent, startUrl);
    }

    private WebappActivity startWebApkActivity(final Intent intent, final String startUrl) {
        final WebappActivity webApkActivity =
                (WebappActivity) InstrumentationRegistry.getInstrumentation().startActivitySync(
                        intent);
        setActivity(webApkActivity);
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();

        CriteriaHelper.pollInstrumentationThread(() -> {
            Criteria.checkThat(webApkActivity.getActivityTab(), Matchers.notNullValue());
        }, STARTUP_TIMEOUT, CriteriaHelper.DEFAULT_POLLING_INTERVAL);

        ChromeTabUtils.waitForTabPageLoaded(webApkActivity.getActivityTab(), startUrl);
        WebappActivityTestRule.waitUntilSplashHides(webApkActivity);
        return webApkActivity;
    }

    private Intent createIntent(WebappInfo webApkInfo) {
        Intent intent =
                new Intent(InstrumentationRegistry.getTargetContext(), WebappActivity.class);
        intent.putExtra(WebApkConstants.EXTRA_WEBAPK_PACKAGE_NAME, webApkInfo.webApkPackageName());
        intent.putExtra(ShortcutHelper.EXTRA_ID, webApkInfo.id());
        intent.putExtra(ShortcutHelper.EXTRA_URL, webApkInfo.url());
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_NEW_DOCUMENT);
        return intent;
    }
}
