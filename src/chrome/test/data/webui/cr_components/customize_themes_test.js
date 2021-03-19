// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'chrome://new-tab-page/strings.m.js';

import {CustomizeThemesBrowserProxy, CustomizeThemesBrowserProxyImpl} from 'chrome://resources/cr_components/customize_themes/browser_proxy.js';
import {CustomizeThemesElement} from 'chrome://resources/cr_components/customize_themes/customize_themes.js';
import {ThemeIconElement} from 'chrome://resources/cr_components/customize_themes/theme_icon.js';

import {assertEquals, assertTrue} from '../chai_assert.js';
import {TestBrowserProxy} from '../test_browser_proxy.m.js';
import {flushTasks} from '../test_util.m.js';

/**
 * Asserts the computed style value for an element.
 * @param {Element} element The element.
 * @param {string} name The name of the style to assert.
 * @param {string} expected The expected style value.
 */
function assertStyle(element, name, expected) {
  assertTrue(!!element);
  const actual = window.getComputedStyle(element).getPropertyValue(name).trim();
  assertEquals(expected, actual);
}

/** @implements {customizeThemes.mojom.CustomizeThemesHandlerInterface} */
class TestCustomizeThemesHandler extends TestBrowserProxy {
  constructor() {
    super([
      'applyAutogeneratedTheme',
      'applyChromeTheme',
      'applyDefaultTheme',
      'initializeTheme',
      'getChromeThemes',
      'confirmThemeChanges',
      'revertThemeChanges',
    ]);

    /** @private {!Array<customizeThemes.mojom.ChromeTheme>} */
    this.chromeThemes_ = [];
  }

  /** @param {!Array<customizeThemes.mojom.ChromeTheme>} chromeThemes */
  setChromeThemes(chromeThemes) {
    this.chromeThemes_ = chromeThemes;
  }

  /** @override */
  applyAutogeneratedTheme(frameColor) {
    this.methodCalled('applyAutogeneratedTheme', frameColor);
  }

  /** @override */
  applyChromeTheme(id) {
    this.methodCalled('applyChromeTheme', id);
  }

  /** @override */
  applyDefaultTheme() {
    this.methodCalled('applyDefaultTheme');
  }

  /** @override */
  initializeTheme() {
    this.methodCalled('initializeTheme');
  }

  /** @override */
  getChromeThemes() {
    this.methodCalled('getChromeThemes');
    return Promise.resolve({chromeThemes: this.chromeThemes_});
  }

  /** @override */
  confirmThemeChanges() {
    this.methodCalled('confirmThemeChanges');
  }

  /** @override */
  revertThemeChanges() {
    this.methodCalled('revertThemeChanges');
  }
}

/** @implements {CustomizeThemesBrowserProxy} */
class TestCustomizeThemesBrowserProxy extends TestBrowserProxy {
  constructor() {
    super(['open']);

    /** @type {TestCustomizeThemesHandler} */
    this.testHandler = new TestCustomizeThemesHandler();

    /** @private {customizeThemes.mojom.CustomizeThemesClientCallbackRouter} */
    this.callbackRouter_ =
        new customizeThemes.mojom.CustomizeThemesClientCallbackRouter();
  }

  /** @override */
  handler() {
    return this.testHandler;
  }

  /** @override */
  callbackRouter() {
    return this.callbackRouter_;
  }

  /** @override */
  open(url) {
    this.methodCalled('open', url);
  }
}

suite('CrComponentsCustomizeThemesTest', () => {
  /** @type {TestCustomizeThemesBrowserProxy} */
  let testProxy;

  /** @return {!CustomizeThemesElement} */
  function createCustomizeThemesElement() {
    const customizeThemesElement =
        document.createElement('cr-customize-themes');
    document.body.append(customizeThemesElement);
    return /** @type {!CustomizeThemesElement} */ (customizeThemesElement);
  }

  /**
   * @param {!Array<customizeThemes.mojom.ChromeTheme>} themes}
   * @return {!CustomizeThemesElement}
   */
  function createCustomizeThemesElementWithThemes(themes) {
    testProxy.testHandler.setChromeThemes(themes);
    return createCustomizeThemesElement();
  }

  setup(() => {
    document.innerHTML = '';
    testProxy = new TestCustomizeThemesBrowserProxy();
    CustomizeThemesBrowserProxyImpl.instance_ = testProxy;
  });

  test('creating element shows theme tiles', async () => {
    // Arrange.
    const themes = [
      {
        id: 0,
        label: 'theme_0',
        colors: {
          frame: {value: 0xff000000},      // white.
          activeTab: {value: 0xff0000ff},  // blue.
        },
      },
      {
        id: 1,
        label: 'theme_1',
        colors: {
          frame: {value: 0xffff0000},      // red.
          activeTab: {value: 0xff00ff00},  // green.
        },
      },
    ];

    // Act.
    const customizeThemesElement =
        createCustomizeThemesElementWithThemes(themes);
    assertEquals(1, testProxy.testHandler.getCallCount('initializeTheme'));
    assertEquals(1, testProxy.testHandler.getCallCount('getChromeThemes'));
    await flushTasks();

    // Assert.
    const tiles =
        customizeThemesElement.shadowRoot.querySelectorAll('cr-theme-icon');
    assertEquals(tiles.length, 4);
    assertEquals(tiles[2].getAttribute('title'), 'theme_0');
    assertStyle(tiles[2], '--cr-theme-icon-frame-color', 'rgba(0, 0, 0, 1)');
    assertStyle(
        tiles[2], '--cr-theme-icon-active-tab-color', 'rgba(0, 0, 255, 1)');
    assertEquals(tiles[3].getAttribute('title'), 'theme_1');
    assertStyle(tiles[3], '--cr-theme-icon-frame-color', 'rgba(255, 0, 0, 1)');
    assertStyle(
        tiles[3], '--cr-theme-icon-active-tab-color', 'rgba(0, 255, 0, 1)');
  });

  [true, false].forEach(autoConfirm => {
    test(
        `clicking default theme with autoConfirm="${
            autoConfirm}" applies default theme`,
        async () => {
          // Arrange.
          const customizeThemesElement = createCustomizeThemesElement();
          customizeThemesElement.autoConfirmThemeChanges = autoConfirm;
          await flushTasks();

          // Act.
          customizeThemesElement.shadowRoot.querySelector('#defaultTheme')
              .click();

          // Assert.
          assertEquals(
              1, testProxy.testHandler.getCallCount('applyDefaultTheme'));
          assertEquals(
              autoConfirm ? 1 : 0,
              testProxy.testHandler.getCallCount('confirmThemeChanges'));
        });

    test(
        `selecting color with autoConfirm="${
            autoConfirm}" applies autogenerated theme`,
        async () => {
          // Arrange.
          const customizeThemesElement = createCustomizeThemesElement();
          customizeThemesElement.autoConfirmThemeChanges = autoConfirm;
          const applyAutogeneratedThemeCalled =
              testProxy.testHandler.whenCalled('applyAutogeneratedTheme');

          // Act.
          customizeThemesElement.shadowRoot.querySelector('#colorPicker')
              .value = '#ff0000';
          customizeThemesElement.shadowRoot.querySelector('#colorPicker')
              .dispatchEvent(new Event('change'));

          // Assert.
          const {value} = await applyAutogeneratedThemeCalled;
          assertEquals(value, 0xffff0000);
          assertEquals(
              autoConfirm ? 1 : 0,
              testProxy.testHandler.getCallCount('confirmThemeChanges'));
        });
  });

  test('setting autogenerated theme selects and updates icon', async () => {
    // Arrange.
    const customizeThemesElement = createCustomizeThemesElement();

    // Act.
    customizeThemesElement.selectedTheme = {
      type: customizeThemes.mojom.ThemeType.kAutogenerated,
      info: {
        autogeneratedThemeColors: {
          frame: {value: 0xffff0000},
          activeTab: {value: 0xff0000ff},
          activeTabText: {value: 0xff00ff00},
        },
      }
    };
    await flushTasks();

    // Assert.
    const selectedIcons = customizeThemesElement.shadowRoot.querySelectorAll(
        'cr-theme-icon[selected]');
    assertEquals(selectedIcons.length, 1);
    assertEquals(
        selectedIcons[0],
        customizeThemesElement.shadowRoot.querySelector('#autogeneratedTheme'));
    assertStyle(
        selectedIcons[0], '--cr-theme-icon-frame-color', 'rgba(255, 0, 0, 1)');
    assertStyle(
        selectedIcons[0], '--cr-theme-icon-active-tab-color',
        'rgba(0, 0, 255, 1)');
  });

  test('setting default theme selects and updates icon', async () => {
    // Arrange.
    const customizeThemesElement = createCustomizeThemesElement();

    // Act.
    customizeThemesElement.selectedTheme = {
      type: customizeThemes.mojom.ThemeType.kDefault,
      info: {chromeThemeId: 0},
    };
    await flushTasks();

    // Assert.
    const selectedIcons = customizeThemesElement.shadowRoot.querySelectorAll(
        'cr-theme-icon[selected]');
    assertEquals(selectedIcons.length, 1);
    assertEquals(
        selectedIcons[0],
        customizeThemesElement.shadowRoot.querySelector('#defaultTheme'));
  });

  test('setting Chrome theme selects and updates icon', async () => {
    // Arrange.
    const themes = [
      {
        id: 0,
        label: 'foo',
        colors: {
          frame: {value: 0xff000000},
          activeTab: {value: 0xff0000ff},
          activeTabText: {value: 0xff00ff00},
        },
      },
    ];
    const customizeThemesElement =
        createCustomizeThemesElementWithThemes(themes);

    // Act.
    customizeThemesElement.selectedTheme = {
      type: customizeThemes.mojom.ThemeType.kChrome,
      info: {chromeThemeId: 0},
    };
    await flushTasks();

    // Assert.
    const selectedIcons = customizeThemesElement.shadowRoot.querySelectorAll(
        'cr-theme-icon[selected]');
    assertEquals(selectedIcons.length, 1);
    assertEquals(selectedIcons[0].getAttribute('title'), 'foo');
  });

  test('setting third-party theme shows uninstall UI', async () => {
    // Arrange.
    const customizeThemesElement = createCustomizeThemesElement();

    // Act.
    customizeThemesElement.selectedTheme = {
      type: customizeThemes.mojom.ThemeType.kThirdParty,
      info: {
        thirdPartyThemeInfo: {
          id: 'foo',
          name: 'bar',
        },
      },
    };

    // Assert.
    assertStyle(
        customizeThemesElement.shadowRoot.querySelector(
            '#thirdPartyThemeContainer'),
        'display', 'block');
    assertEquals(
        customizeThemesElement.shadowRoot.querySelector('#thirdPartyThemeName')
            .textContent.trim(),
        'bar');
  });

  test('clicking third-party link opens theme page', async () => {
    // Arrange.
    const customizeThemesElement = createCustomizeThemesElement();
    customizeThemesElement.selectedTheme = {
      type: customizeThemes.mojom.ThemeType.kThirdParty,
      info: {
        thirdPartyThemeInfo: {
          id: 'foo',
          name: 'bar',
        },
      },
    };

    // Act.
    customizeThemesElement.shadowRoot.querySelector('#thirdPartyLink').click();

    // Assert.
    const link = await testProxy.whenCalled('open');
    assertEquals('https://chrome.google.com/webstore/detail/foo', link);
  });

  test('setting non-third-party theme hides uninstall UI', async () => {
    // Arrange.
    const customizeThemesElement = createCustomizeThemesElement();

    // Act.
    customizeThemesElement.selectedTheme = {
      type: customizeThemes.mojom.ThemeType.kDefault,
      info: {chromeThemeId: 0},
    };

    // Assert.
    assertStyle(
        customizeThemesElement.shadowRoot.querySelector(
            '#thirdPartyThemeContainer'),
        'display', 'none');
  });

  test('uninstalling third-party theme sets default theme', async () => {
    // Arrange.
    const customizeThemesElement = createCustomizeThemesElement();
    customizeThemesElement.selectedTheme = {
      type: customizeThemes.mojom.ThemeType.kThirdParty,
      info: {
        thirdPartyThemeInfo: {
          id: 'foo',
          name: 'bar',
        },
      },
    };
    // Act.
    customizeThemesElement.shadowRoot
        .querySelector('#uninstallThirdPartyButton')
        .click();

    // Assert.
    assertEquals(1, testProxy.testHandler.getCallCount('applyDefaultTheme'));
    assertEquals(1, testProxy.testHandler.getCallCount('confirmThemeChanges'));
  });
});

suite('ThemeIconTest', () => {
  /** @type {!ThemeIconElement} */
  let themeIcon;

  /** @return {!NodeList<!Element>} */
  function queryAll(selector) {
    return themeIcon.shadowRoot.querySelectorAll(selector);
  }

  /** @return {Element} */
  function query(selector) {
    return themeIcon.shadowRoot.querySelector(selector);
  }

  setup(() => {
    document.innerHTML = '';

    themeIcon = /** @type {!ThemeIconElement} */ (
        document.createElement('cr-theme-icon'));
    document.body.appendChild(themeIcon);
  });

  test('setting frame color sets stroke and gradient', () => {
    // Act.
    themeIcon.style.setProperty('--cr-theme-icon-frame-color', 'red');

    // Assert.
    assertStyle(query('#circle'), 'stroke', 'rgb(255, 0, 0)');
    assertStyle(
        queryAll('#gradient > stop')[1], 'stop-color', 'rgb(255, 0, 0)');
  });

  test('setting active tab color sets gradient', async () => {
    // Act.
    themeIcon.style.setProperty('--cr-theme-icon-active-tab-color', 'red');

    // Assert.
    assertStyle(
        queryAll('#gradient > stop')[0], 'stop-color', 'rgb(255, 0, 0)');
  });

  test('setting explicit stroke color sets different stroke', async () => {
    // Act.
    themeIcon.style.setProperty('--cr-theme-icon-frame-color', 'red');
    themeIcon.style.setProperty('--cr-theme-icon-stroke-color', 'blue');

    // Assert.
    assertStyle(query('#circle'), 'stroke', 'rgb(0, 0, 255)');
    assertStyle(
        queryAll('#gradient > stop')[1], 'stop-color', 'rgb(255, 0, 0)');
  });

  test('selecting icon shows ring and check mark', async () => {
    // Act.
    themeIcon.setAttribute('selected', true);

    // Assert.
    assertStyle(query('#ring'), 'visibility', 'visible');
    assertStyle(query('#checkMark'), 'visibility', 'visible');
  });
});
