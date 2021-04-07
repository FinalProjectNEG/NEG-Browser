// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.test;

import android.accounts.Account;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import org.chromium.chrome.test.util.browser.signin.AccountManagerTestRule;
import org.chromium.components.signin.base.CoreAccountInfo;
import org.chromium.content_public.browser.test.NativeLibraryTestUtils;

/**
 * JUnit test rule that takes care of important initialization for Chrome-specific tests, such as
 * initializing the AccountManagerFacade.
 */
public class ChromeBrowserTestRule implements TestRule {
    private final AccountManagerTestRule mAccountManagerTestRule = new AccountManagerTestRule();

    @Override
    public Statement apply(final Statement base, Description description) {
        Statement statement = new Statement() {
            @Override
            public void evaluate() throws Throwable {
                /**
                 * Loads the native library on the activity UI thread.  After loading the library,
                 * this will initialize the browser process if necessary.
                 */
                NativeLibraryTestUtils.loadNativeLibraryAndInitBrowserProcess();
                base.evaluate();
            }
        };
        return mAccountManagerTestRule.apply(statement, description);
    }

    /**
     * Adds an account of the given accountName to the fake AccountManagerFacade.
     */
    public Account addAccount(String accountName) {
        return mAccountManagerTestRule.addAccount(accountName);
    }

    /**
     * Add and sign in an account with the default name.
     */
    public CoreAccountInfo addTestAccountThenSigninAndEnableSync() {
        Account account = mAccountManagerTestRule.addTestAccountThenSigninAndEnableSync();
        return mAccountManagerTestRule.toCoreAccountInfo(account.name);
    }
}
