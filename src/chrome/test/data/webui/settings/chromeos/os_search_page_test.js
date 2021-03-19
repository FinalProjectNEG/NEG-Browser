// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// clang-format off
// #import 'chrome://os-settings/chromeos/os_settings.js';

// #import {ConsentStatus, DspHotwordState} from 'chrome://os-settings/chromeos/os_settings.js';
// #import {CrSettingsPrefs} from 'chrome://os-settings/chromeos/os_settings.js';
// #import {GoogleAssistantBrowserProxyImpl} from 'chrome://os-settings/chromeos/os_settings.js';
// #import {Router, routes} from 'chrome://os-settings/chromeos/os_settings.js';
// #import {SearchEnginesBrowserProxy, SearchEnginesBrowserProxyImpl} from 'chrome://os-settings/chromeos/os_settings.js';
// #import {SearchEnginesInfo, SearchEngine} from 'chrome://os-settings/chromeos/os_settings.js';
// #import {TestBrowserProxy} from '../../test_browser_proxy.m.js';
// #import {assertEquals, assertFalse, assertTrue} from '../../chai_assert.js';
// #import {flush} from 'chrome://resources/polymer/v3_0/polymer/polymer_bundled.min.js';
// #import {getDeepActiveElement} from 'chrome://resources/js/util.m.js';
// #import {waitAfterNextRender} from 'chrome://test/test_util.m.js';
// clang-format on

suite('OSSearchPageTests', function() {
  /** @type {?SettingsSearchPageElement} */
  let page = null;

  let browserProxy = null;

  /**
   * A test version of SearchEnginesBrowserProxy. Provides helper methods
   * for allowing tests to know when a method was called, as well as
   * specifying mock responses.
   *
   * @implements {settings.SearchEnginesBrowserProxy}
   */
  class TestSearchEnginesBrowserProxy extends TestBrowserProxy {
    constructor() {
      super([
        'getSearchEnginesList',
        'removeSearchEngine',
        'searchEngineEditCancelled',
        'searchEngineEditCompleted',
        'searchEngineEditStarted',
        'setDefaultSearchEngine',
        'validateSearchEngineInput',
      ]);

      /** @private {!SearchEnginesInfo} */
      this.searchEnginesInfo_ = {defaults: [], others: [], extensions: []};
    }

    /** @override */
    setDefaultSearchEngine(modelIndex) {
      this.methodCalled('setDefaultSearchEngine', modelIndex);
    }

    /** @override */
    removeSearchEngine(modelIndex) {
      this.methodCalled('removeSearchEngine', modelIndex);
    }

    /** @override */
    searchEngineEditStarted(modelIndex) {
      this.methodCalled('searchEngineEditStarted', modelIndex);
    }

    /** @override */
    searchEngineEditCancelled() {
      this.methodCalled('searchEngineEditCancelled');
    }

    /** @override */
    searchEngineEditCompleted(searchEngine, keyword, queryUrl) {
      this.methodCalled('searchEngineEditCompleted');
    }

    /** @override */
    getSearchEnginesList() {
      this.methodCalled('getSearchEnginesList');
      return Promise.resolve(this.searchEnginesInfo_);
    }

    /** @override */
    validateSearchEngineInput(fieldName, fieldValue) {
      this.methodCalled('validateSearchEngineInput');
      return Promise.resolve(true);
    }

    /**
     * Sets the response to be returned by |getSearchEnginesList|.
     * @param {!SearchEnginesInfo} searchEnginesInfo
     */
    setSearchEnginesInfo(searchEnginesInfo) {
      this.searchEnginesInfo_ = searchEnginesInfo;
    }
  }

  function createSampleSearchEngine(
      canBeDefault, canBeEdited, canBeRemoved) {
    return {
      canBeDefault: canBeDefault,
      canBeEdited: canBeEdited,
      canBeRemoved: canBeRemoved,
      default: false,
      displayName: 'Google',
      iconURL: 'http://www.google.com/favicon.ico',
      id: 0,
      isOmniboxExtension: false,
      keyword: 'google.com',
      modelIndex: 0,
      name: 'Google',
      url: 'https://search.foo.com/search?p=%s',
      urlLocked: false,
    };
  }

  function generateSearchEngineInfo() {
    const searchEngines0 =
        createSampleSearchEngine(true, false, false);
    searchEngines0.default = true;
    const searchEngines1 =
        createSampleSearchEngine(true, false, false);
    searchEngines1.default = false;
    const searchEngines2 =
        createSampleSearchEngine(true, false, false);
    searchEngines2.default = false;

    return {
      defaults: [searchEngines0, searchEngines1, searchEngines2],
      others: [],
      extensions: [],
    };
  }

  setup(function() {
    browserProxy = new TestSearchEnginesBrowserProxy();
    browserProxy.setSearchEnginesInfo(generateSearchEngineInfo());
    settings.SearchEnginesBrowserProxyImpl.instance_ = browserProxy;
    PolymerTest.clearBody();
    page = document.createElement('os-settings-search-page');
    page.prefs = {
      default_search_provider_data: {
        template_url_data: {},
      },
    };
    document.body.appendChild(page);
  });

  teardown(function() {
    page.remove();
    settings.Router.getInstance().resetRouteForTesting();
  });

  // Tests that the page is querying and displaying search engine info on
  // startup.
  test('Initialization', async () => {
    const selectElement = page.$$('select');
    assertTrue(!!selectElement);
    assertTrue(!!page.$$('#help-icon'));

    await browserProxy.whenCalled('getSearchEnginesList');
    Polymer.dom.flush();
    assertEquals(0, selectElement.selectedIndex);

    // Simulate a user initiated change of the default search engine.
    selectElement.selectedIndex = 1;
    selectElement.dispatchEvent(new CustomEvent('change'));
    await browserProxy.whenCalled('setDefaultSearchEngine');
    assertEquals(1, selectElement.selectedIndex);

    // Simulate a change that happened in browser settings.
    const searchEnginesInfo = generateSearchEngineInfo();
    searchEnginesInfo.defaults[0].default = false;
    searchEnginesInfo.defaults[1].default = false;
    searchEnginesInfo.defaults[2].default = true;

    browserProxy.resetResolver('setDefaultSearchEngine');
    cr.webUIListenerCallback('search-engines-changed', searchEnginesInfo);
    Polymer.dom.flush();
    assertEquals(2, selectElement.selectedIndex);

    browserProxy.whenCalled('setDefaultSearchEngine').then(function() {
      // Since the change happened in a different tab, there should be
      // no new call to |setDefaultSearchEngine|.
      assertNotReached('Should not call setDefaultSearchEngine again');
    });
  });

  test('ControlledByExtension', async () => {
    await browserProxy.whenCalled('getSearchEnginesList');
    const selectElement = page.$$('select');
    assertFalse(selectElement.disabled);
    assertFalse(!!page.$$('extension-controlled-indicator'));

    page.set('prefs.default_search_provider_data.template_url_data', {
      controlledBy: chrome.settingsPrivate.ControlledBy.EXTENSION,
      controlledByName: 'fake extension name',
      enforcement: chrome.settingsPrivate.Enforcement.ENFORCED,
      extensionId: 'fake extension id',
      extensionCanBeDisabled: true,
      value: {},
    });
    Polymer.dom.flush();

    assertTrue(selectElement.disabled);
    assertTrue(!!page.$$('extension-controlled-indicator'));
    assertFalse(!!page.$$('cr-policy-pref-indicator'));
  });

  test('ControlledByPolicy', async () => {
    await browserProxy.whenCalled('getSearchEnginesList');
    const selectElement = page.$$('select');
    assertFalse(selectElement.disabled);
    assertFalse(!!page.$$('extension-controlled-indicator'));

    page.set('prefs.default_search_provider_data.template_url_data', {
      controlledBy: chrome.settingsPrivate.ControlledBy.USER_POLICY,
      enforcement: chrome.settingsPrivate.Enforcement.ENFORCED,
      value: {},
    });
    Polymer.dom.flush();

    assertTrue(selectElement.disabled);
    assertFalse(!!page.$$('extension-controlled-indicator'));
    assertTrue(!!page.$$('cr-policy-pref-indicator'));
  });

  test('Deep link to preferred search engine', async () => {
    loadTimeData.overrideValues({isDeepLinkingEnabled: true});
    assertTrue(loadTimeData.getBoolean('isDeepLinkingEnabled'));

    const params = new URLSearchParams;
    params.append('settingId', '600');
    settings.Router.getInstance().navigateTo(
        settings.routes.OS_SEARCH, params);

    const deepLinkElement = page.$$('select');
    await test_util.waitAfterNextRender(deepLinkElement);
    assertEquals(
        deepLinkElement, getDeepActiveElement(),
        'Preferred search dropdown should be focused for settingId=600.');
  });
});
