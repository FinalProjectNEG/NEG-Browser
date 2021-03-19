// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.signin;

import androidx.test.filters.SmallTest;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.chromium.base.test.util.Batch;
import org.chromium.chrome.test.ChromeJUnit4ClassRunner;
import org.chromium.chrome.test.util.browser.signin.AccountManagerTestRule;
import org.chromium.chrome.test.util.browser.signin.MockChangeEventChecker;

/**
 * Instrumentation tests for {@link SigninHelper}.
 */
@RunWith(ChromeJUnit4ClassRunner.class)
@Batch(Batch.UNIT_TESTS)
public class SigninHelperTest {
    @Rule
    public final AccountManagerTestRule mAccountManagerTestRule = new AccountManagerTestRule();

    private MockChangeEventChecker mEventChecker;

    @Before
    public void setUp() {
        mEventChecker = new MockChangeEventChecker();
    }

    @After
    public void tearDown() {
        SigninPreferencesManager.getInstance().clearAccountsStateSharedPrefsForTesting();
    }

    @Test
    @SmallTest
    public void testSimpleAccountRename() {
        mEventChecker.insertRenameEvent("A", "B");
        SigninHelper.updateAccountRenameData(mEventChecker, "A");
        Assert.assertEquals("B", getNewSignedInAccountName());
    }

    @Test
    @SmallTest
    public void testNotSignedInAccountRename() {
        mEventChecker.insertRenameEvent("B", "C");
        SigninHelper.updateAccountRenameData(mEventChecker, "A");
        Assert.assertNull(getNewSignedInAccountName());
    }

    @Test
    @SmallTest
    public void testSimpleAccountRenameTwice() {
        mEventChecker.insertRenameEvent("A", "B");
        SigninHelper.updateAccountRenameData(mEventChecker, "A");
        Assert.assertEquals("B", getNewSignedInAccountName());
        mEventChecker.insertRenameEvent("B", "C");
        SigninHelper.updateAccountRenameData(mEventChecker, "B");
        Assert.assertEquals("C", getNewSignedInAccountName());
    }

    @Test
    @SmallTest
    public void testNotSignedInAccountRename2() {
        mEventChecker.insertRenameEvent("B", "C");
        mEventChecker.insertRenameEvent("C", "D");
        SigninHelper.updateAccountRenameData(mEventChecker, "A");
        Assert.assertNull(getNewSignedInAccountName());
    }

    @Test
    @SmallTest
    public void testChainedAccountRename2() {
        mEventChecker.insertRenameEvent("Z", "Y"); // Unrelated.
        mEventChecker.insertRenameEvent("A", "B");
        mEventChecker.insertRenameEvent("Y", "X"); // Unrelated.
        mEventChecker.insertRenameEvent("B", "C");
        mEventChecker.insertRenameEvent("C", "D");
        SigninHelper.updateAccountRenameData(mEventChecker, "A");
        Assert.assertEquals("D", getNewSignedInAccountName());
    }

    @Test
    @SmallTest
    public void testLoopedAccountRename() {
        mEventChecker.insertRenameEvent("Z", "Y"); // Unrelated.
        mEventChecker.insertRenameEvent("A", "B");
        mEventChecker.insertRenameEvent("Y", "X"); // Unrelated.
        mEventChecker.insertRenameEvent("B", "C");
        mEventChecker.insertRenameEvent("C", "D");
        mEventChecker.insertRenameEvent("D", "A"); // Looped.
        mAccountManagerTestRule.addAccount("D");
        SigninHelper.updateAccountRenameData(mEventChecker, "A");
        Assert.assertEquals("D", getNewSignedInAccountName());
    }

    private String getNewSignedInAccountName() {
        return SigninPreferencesManager.getInstance().getNewSignedInAccountName();
    }
}
