// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Include test fixture.
GEN_INCLUDE(['../testing/chromevox_next_e2e_test_base.js']);

GEN_INCLUDE(['../testing/mock_feedback.js', '../testing/fake_objects.js']);

/**
 * Test fixture involving settings pages.
 */
ChromeVoxSettingsPagesTest = class extends ChromeVoxNextE2ETest {
  /** @override */
  setUp() {
    window.doCmd = this.doCmd;
  }

  /** @override */
  testGenCppIncludes() {
    super.testGenCppIncludes();
    GEN(`
      #include "chrome/browser/ui/web_applications/system_web_app_ui_utils.h"
      #include "chrome/browser/web_applications/web_app_provider.h"
    `);
  }

  /** @override */
  testGenPreamble() {
    GEN(`
    web_app::WebAppProvider::Get(browser()->profile())
        ->system_web_app_manager()
        .InstallSystemAppsForTesting();
  `);
    super.testGenPreamble();
  }
};

TEST_F(
    'ChromeVoxSettingsPagesTest', 'TtsRateCommandOnSettingsPage', function() {
      const realTts = ChromeVox.tts;
      const mockFeedback = this.createMockFeedback();
      this.runWithLoadedTree(`unused`, function() {
        const increaseRate = realTts.increaseOrDecreaseProperty.bind(
            realTts, AbstractTts.RATE, true);
        const decreaseRate = realTts.increaseOrDecreaseProperty.bind(
            realTts, AbstractTts.RATE, false);

        mockFeedback.call(doCmd('showTtsSettings'))
            .expectSpeech(
                /(Settings)|(Text-to-Speech voice settings subpage back button)/)

            // ChromeVox presents a 0% to 100% scale.
            // Ensure we have the default rate.
            .call(
                () => chrome.settingsPrivate.setPref(
                    'settings.tts.speech_rate', 1.0))

            .call(increaseRate)
            .expectSpeech('Rate 19 percent')
            .call(increaseRate)
            .expectSpeech('Rate 21 percent')

            // Speed things up...
            .call(
                () => chrome.settingsPrivate.setPref(
                    'settings.tts.speech_rate', 4.9))
            .expectSpeech('Rate 98 percent')
            .call(increaseRate)
            .expectSpeech('Rate 100 percent')

            .call(decreaseRate)
            .expectSpeech('Rate 98 percent')
            .call(decreaseRate)
            .expectSpeech('Rate 96 percent')

            // Slow things down...
            .call(
                () => chrome.settingsPrivate.setPref(
                    'settings.tts.speech_rate', 0.3))
            .expectSpeech('Rate 2 percent')
            .call(decreaseRate)
            .expectSpeech('Rate 0 percent')

            .call(increaseRate)
            .expectSpeech('Rate 2 percent')
            .call(increaseRate)
            .expectSpeech('Rate 4 percent')

            .replay();
      });
    });
