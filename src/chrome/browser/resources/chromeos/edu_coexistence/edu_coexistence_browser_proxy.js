// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {addSingletonGetter, sendWithPromise} from 'chrome://resources/js/cr.m.js';

import {AuthCompletedCredentials} from '../../gaia_auth_host/authenticator.m.js';


/** @interface */
export class EduCoexistenceBrowserProxy {
  /** Sends 'initialize' message to prepare for starting auth. */
  initializeLogin() {}

  /**
   * Sends 'initializeEduArgs' message to provide the parameters.
   * @return {!Promise<Object>}
   */
  initializeEduArgs() {}

  /**
   * Sends 'authExtensionReady' message to handle tasks after auth extension
   * loads.
   */
  authExtensionReady() {}

  /**
   * Sends 'completeLogin' message to complete login.
   * @param {!AuthCompletedCredentials} credentials
   */
  completeLogin(credentials) {}

  /**
   * Sends 'getAccounts' message to the handler. The promise will be resolved
   * with the list of emails of accounts in session.
   * @return {!Promise<Array<string>>}
   */
  getAccounts() {}

  /**
   * Sends 'consentValid' message to the handler to notify the handler that
   * the parental consent is valid.
   */
  consentValid() {}

  /**
   * Sends 'consentLogged' message to the handler to notify the handler that
   * the parental consent is valid.
   * @param {string} account Added account email.
   * @param {string} eduCoexistenceToSVersion The terms of service version.
   * @return {!Promise<boolean>}
   */
  consentLogged(account, eduCoexistenceToSVersion) {}

  /** Sends 'dialogClose' message to close the login dialog. */
  dialogClose() {}

  /** Sends 'error' message to handler. */
  error() {}
}

/**
 * @implements {EduCoexistenceBrowserProxy}
 */
export class EduCoexistenceBrowserProxyImpl {
  /** @override */
  initializeLogin() {
    chrome.send('initialize');
  }

  /** @override */
  initializeEduArgs() {
    return sendWithPromise('initializeEduArgs');
  }


  /** @override */
  authExtensionReady() {
    chrome.send('authExtensionReady');
  }

  /** @override */
  completeLogin(credentials) {
    chrome.send('completeLogin', [credentials]);
  }

  /** @override */
  getAccounts() {
    return sendWithPromise('getAccounts');
  }

  /** @override */
  consentValid() {
    chrome.send('consentValid');
  }

  /** @override */
  consentLogged(account, eduCoexistenceToSVersion) {
    return sendWithPromise(
        'consentLogged', [account, eduCoexistenceToSVersion]);
  }

  /** @override */
  dialogClose() {
    chrome.send('dialogClose');
  }

  /** @override */
  error() {
    chrome.send('error');
  }
}

addSingletonGetter(EduCoexistenceBrowserProxyImpl);
