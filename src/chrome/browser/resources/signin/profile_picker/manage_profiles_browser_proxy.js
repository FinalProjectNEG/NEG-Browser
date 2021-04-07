// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {addSingletonGetter, sendWithPromise} from 'chrome://resources/js/cr.m.js';

/**
 * This is the data structure sent back and forth between C++ and JS.
 * @typedef {{
 *   profilePath: string,
 *   localProfileName: string,
 *   isSyncing: boolean,
 *   gaiaName: string,
 *   userName: string,
 *   isManaged: boolean,
 *   avatarIcon: string,
 * }}
 */
export let ProfileState;

/**
 * This is the data structure sent back and forth between C++ and JS.
 * `colorId` has the following special values:
 *   - `-1` for the default theme.
 *   - `0` for a manually picked color theme.
 * @typedef {{
 *   colorId: number,
 *   color: number,
 *   themeFrameColor: string,
 *   themeShapeColor: string,
 *   themeFrameTextColor: string,
 *   themeGenericAvatar: string,
 * }}
 */
export let AutogeneratedThemeColorInfo;

/**
 * This is the data structure sent back and forth between C++ and JS.
 * `colorId` has the following special values:
 *   - `-1` for the default theme..
 *   - `0` for a manually picked color theme
 * `color` is defined only for manually picked themes.
 * @typedef {{
 *   colorId: number,
 *   color: (number|undefined),
 * }}
 */
export let UserThemeChoice;

/** @interface */
export class ManageProfilesBrowserProxy {
  /**
   * Initializes profile picker main view.
   */
  initializeMainView() {}

  /**
   * Launches picked profile and closes the profile picker.
   * @param {string} profilePath
   */
  launchSelectedProfile(profilePath) {}

  /**
   * Opens profile on manage profile settings sub page and closes the
   * profile picker.
   * @param {string} profilePath
   */
  openManageProfileSettingsSubPage(profilePath) {}

  /** Launches Guest profile. */
  launchGuestProfile() {}

  /**
   * Inform native the user's choice on whether to show the profile picker
   * on startup or not.
   * @param {boolean} shouldShow
   */
  askOnStartupChanged(shouldShow) {}

  /**
   * Retrieves suggested theme for the new profile.
   * @return {!Promise<!AutogeneratedThemeColorInfo>} A promise firing with the
   * suggested theme info, once it has been retrieved.
   */
  getNewProfileSuggestedThemeInfo() {}

  /**
   * Retrieves all relevant theme information for the particular theme.
   * @param {!UserThemeChoice} theme A theme which info needs to be retrieved.
   * @return {!Promise<!AutogeneratedThemeColorInfo>} A promise firing with the
   * theme info, once it has been retrieved.
   */
  getProfileThemeInfo(theme) {}

  /**
   * Retrieves profile statistics to be shown in the remove profile warning.
   * @param {string} profilePath
   */
  getProfileStatistics(profilePath) {}

  /**
   * Removes profile.
   * @param {string} profilePath
   */
  removeProfile(profilePath) {}

  /**
   * Loads Google sign in page (and silently creates a profile with the
   * specified color).
   * @param {number} profileColor
   */
  loadSignInProfileCreationFlow(profileColor) {}

  /**
   * Creates local profile
   * @param {string} profileName
   * @param {number} profileColor
   * @param {string} avatarUrl
   * @param {boolean} isGeneric
   * @param {boolean} createShortcut
   */
  createProfile(
      profileName, profileColor, avatarUrl, isGeneric, createShortcut) {}
}

/** @implements {ManageProfilesBrowserProxy} */
export class ManageProfilesBrowserProxyImpl {
  /** @override */
  initializeMainView() {
    chrome.send('mainViewInitialize');
  }

  /** @override */
  launchSelectedProfile(profilePath) {
    chrome.send('launchSelectedProfile', [profilePath]);
  }

  /** @override */
  openManageProfileSettingsSubPage(profilePath) {
    chrome.send('openManageProfileSettingsSubPage', [profilePath]);
  }

  /** @override */
  launchGuestProfile() {
    chrome.send('launchGuestProfile');
  }

  /** @override */
  askOnStartupChanged(shouldShow) {
    chrome.send('askOnStartupChanged', [shouldShow]);
  }

  /** @override */
  getNewProfileSuggestedThemeInfo() {
    return sendWithPromise('getNewProfileSuggestedThemeInfo');
  }

  /** @override */
  getProfileThemeInfo(theme) {
    return sendWithPromise('getProfileThemeInfo', theme);
  }

  /** @override */
  removeProfile(profilePath) {
    chrome.send('removeProfile', [profilePath]);
  }

  /** @override */
  getProfileStatistics(profilePath) {
    chrome.send('getProfileStatistics', [profilePath]);
  }

  /** @override */
  loadSignInProfileCreationFlow(profileColor) {
    chrome.send('loadSignInProfileCreationFlow', [profileColor]);
  }

  /** @override */
  createProfile(
      profileName, profileColor, avatarUrl, isGeneric, createShortcut) {
    chrome.send(
        'createProfile',
        [profileName, profileColor, avatarUrl, isGeneric, createShortcut]);
  }
}

addSingletonGetter(ManageProfilesBrowserProxyImpl);
