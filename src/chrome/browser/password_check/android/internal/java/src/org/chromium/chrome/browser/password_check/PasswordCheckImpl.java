// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.password_check;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;

import org.chromium.base.ObserverList;
import org.chromium.chrome.browser.password_check.PasswordCheckBridge.PasswordCheckObserver;
import org.chromium.chrome.browser.settings.SettingsLauncher;
import org.chromium.chrome.browser.settings.SettingsLauncherImpl;

/**
 * This class is responsible for managing the saved passwords check for signed-in users.
 */
class PasswordCheckImpl implements PasswordCheck, PasswordCheckObserver {
    private final PasswordCheckBridge mPasswordCheckBridge;
    private final ObserverList<Observer> mObserverList;

    private boolean mCompromisedCredentialsFetched;
    private boolean mSavedPasswordsFetched;
    private @PasswordCheckUIStatus int mStatus = PasswordCheckUIStatus.IDLE;

    PasswordCheckImpl() {
        mCompromisedCredentialsFetched = false;
        mSavedPasswordsFetched = false;
        mPasswordCheckBridge = new PasswordCheckBridge(this);
        mObserverList = new ObserverList<>();
    }

    @Override
    public void showUi(Context context, @PasswordCheckReferrer int passwordCheckReferrer) {
        SettingsLauncher launcher = new SettingsLauncherImpl();
        Bundle fragmentArgs = new Bundle();
        fragmentArgs.putInt(
                PasswordCheckFragmentView.PASSWORD_CHECK_REFERRER, passwordCheckReferrer);
        launcher.launchSettingsActivity(context, PasswordCheckFragmentView.class, fragmentArgs);
        mPasswordCheckBridge.refreshScripts();
    }

    @Override
    public void destroy() {
        mPasswordCheckBridge.destroy();
    }

    @Override
    public void onCompromisedCredentialFound(CompromisedCredential credential) {
        for (Observer obs : mObserverList) obs.onCompromisedCredentialFound(credential);
    }

    @Override
    public void onCompromisedCredentialsFetched(int count) {
        mCompromisedCredentialsFetched = true;
        for (Observer obs : mObserverList) {
            obs.onCompromisedCredentialsFetchCompleted();
        }
    }

    @Override
    public void onSavedPasswordsFetched(int count) {
        mSavedPasswordsFetched = true;
        for (Observer obs : mObserverList) {
            obs.onSavedPasswordsFetchCompleted();
        }
    }

    @Override
    public void onPasswordCheckStatusChanged(@PasswordCheckUIStatus int status) {
        mStatus = status;
        for (Observer obs : mObserverList) {
            obs.onPasswordCheckStatusChanged(status);
        }
    }

    @Override
    public void onPasswordCheckProgressChanged(int alreadyProcessed, int remainingInQueue) {
        for (Observer obs : mObserverList) {
            obs.onPasswordCheckProgressChanged(alreadyProcessed, remainingInQueue);
        }
    }

    @Override
    public void updateCredential(CompromisedCredential credential, String newPassword) {
        mPasswordCheckBridge.updateCredential(credential, newPassword);
    }

    @Override
    public void removeCredential(CompromisedCredential credential) {
        mPasswordCheckBridge.removeCredential(credential);
    }

    @Override
    public void addObserver(Observer obs, boolean callImmediatelyIfReady) {
        mObserverList.addObserver(obs);
        if (callImmediatelyIfReady && mCompromisedCredentialsFetched) {
            obs.onCompromisedCredentialsFetchCompleted();
        }
        if (callImmediatelyIfReady && mSavedPasswordsFetched) {
            obs.onSavedPasswordsFetchCompleted();
        }
    }

    @Override
    public void removeObserver(Observer obs) {
        mObserverList.removeObserver(obs);
    }

    @Override
    public long getLastCheckTimestamp() {
        return mPasswordCheckBridge.getLastCheckTimestamp();
    }

    @Override
    public @PasswordCheckUIStatus int getCheckStatus() {
        return mStatus;
    }

    @Override
    public int getCompromisedCredentialsCount() {
        return mPasswordCheckBridge.getCompromisedCredentialsCount();
    }

    @Override
    public CompromisedCredential[] getCompromisedCredentials() {
        CompromisedCredential[] credentials =
                new CompromisedCredential[getCompromisedCredentialsCount()];
        mPasswordCheckBridge.getCompromisedCredentials(credentials);
        return credentials;
    }

    @Override
    public int getSavedPasswordsCount() {
        return mPasswordCheckBridge.getSavedPasswordsCount();
    }

    @Override
    public void launchCheckupInAccount(Activity activity) {
        mPasswordCheckBridge.launchCheckupInAccount(activity);
    }

    @Override
    public void startCheck() {
        mPasswordCheckBridge.startCheck();
    }

    @Override
    public void stopCheck() {
        mPasswordCheckBridge.stopCheck();
    }

    @Override
    public boolean areScriptsRefreshed() {
        return mPasswordCheckBridge.areScriptsRefreshed();
    }
}
