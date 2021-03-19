// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/spellchecker/spell_check_host_chrome_impl.h"

#include "base/bind.h"
#include "base/run_loop.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/scoped_feature_list.h"
#include "base/win/windows_version.h"
#include "build/build_config.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/spellchecker/spellcheck_factory.h"
#include "chrome/browser/spellchecker/spellcheck_service.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "components/spellcheck/browser/spellcheck_platform.h"
#include "components/spellcheck/common/spellcheck_features.h"
#include "components/spellcheck/spellcheck_buildflags.h"
#include "content/public/browser/browser_context.h"
#include "content/public/test/browser_test.h"
#include "content/public/test/mock_render_process_host.h"
#include "mojo/public/cpp/bindings/remote.h"

class PlatformSpellChecker;

class SpellCheckHostChromeImplWinBrowserTest : public InProcessBrowserTest {
 public:
  SpellCheckHostChromeImplWinBrowserTest() = default;

  void SetUp() override {
    // Don't delay initialization of the SpellcheckService on browser launch.
    feature_list_.InitWithFeatures(
        /*enabled_features=*/{spellcheck::kWinUseBrowserSpellChecker},
        /*disabled_features=*/{spellcheck::kWinDelaySpellcheckServiceInit});
    InProcessBrowserTest::SetUp();
  }

  void SetUpOnMainThread() override {
    content::BrowserContext* context = browser()->profile();
    renderer_.reset(new content::MockRenderProcessHost(context));

    SpellCheckHostChromeImpl::Create(
        renderer_->GetID(), spell_check_host_.BindNewPipeAndPassReceiver());

    InitializeSpellcheckService();

    platform_spell_checker_ = SpellcheckServiceFactory::GetForContext(context)
                                  ->platform_spell_checker();
  }

  void TearDownOnMainThread() override { renderer_.reset(); }

  virtual void InitializeSpellcheckService() {}

  void OnSpellcheckResult(const std::vector<SpellCheckResult>& result) {
    received_result_ = true;
    result_ = result;
    if (quit_)
      std::move(quit_).Run();
  }

  void OnSuggestionResult(
      const std::vector<std::vector<::base::string16>>& suggestions) {
    received_result_ = true;
    suggestion_result_ = suggestions;
    if (quit_)
      std::move(quit_).Run();
  }

  void SetLanguageCompletionCallback(bool result) {
    received_result_ = true;
    if (quit_)
      std::move(quit_).Run();
  }

  void RunUntilResultReceived() {
    if (received_result_)
      return;
    base::RunLoop run_loop;
    quit_ = run_loop.QuitClosure();
    run_loop.Run();

    // reset status
    received_result_ = false;
  }

  void RunSpellCheckReturnMessageTest();
  void RunGetPerLanguageSuggestionsTest();

 protected:
  PlatformSpellChecker* platform_spell_checker_;
  base::test::ScopedFeatureList feature_list_;
  std::unique_ptr<content::MockRenderProcessHost> renderer_;
  mojo::Remote<spellcheck::mojom::SpellCheckHost> spell_check_host_;

  bool received_result_ = false;
  std::vector<SpellCheckResult> result_;
  std::vector<std::vector<::base::string16>> suggestion_result_;
  base::OnceClosure quit_;
};

// Uses browsertest to setup chrome threads.
IN_PROC_BROWSER_TEST_F(SpellCheckHostChromeImplWinBrowserTest,
                       SpellCheckReturnMessage) {
  RunSpellCheckReturnMessageTest();
}

void SpellCheckHostChromeImplWinBrowserTest::RunSpellCheckReturnMessageTest() {
  if (!spellcheck::WindowsVersionSupportsSpellchecker()) {
    return;
  }

  spellcheck_platform::SetLanguage(
      platform_spell_checker_, "en-US",
      base::BindOnce(&SpellCheckHostChromeImplWinBrowserTest::
                         SetLanguageCompletionCallback,
                     base::Unretained(this)));
  RunUntilResultReceived();

  spell_check_host_->RequestTextCheck(
      base::UTF8ToUTF16("zz."),
      /*route_id=*/123,
      base::BindOnce(
          &SpellCheckHostChromeImplWinBrowserTest::OnSpellcheckResult,
          base::Unretained(this)));
  RunUntilResultReceived();

  ASSERT_EQ(1U, result_.size());
  EXPECT_EQ(result_[0].location, 0);
  EXPECT_EQ(result_[0].length, 2);
  EXPECT_EQ(result_[0].decoration, SpellCheckResult::SPELLING);
}

IN_PROC_BROWSER_TEST_F(SpellCheckHostChromeImplWinBrowserTest,
                       GetPerLanguageSuggestions) {
  RunGetPerLanguageSuggestionsTest();
}

void SpellCheckHostChromeImplWinBrowserTest::
    RunGetPerLanguageSuggestionsTest() {
  if (!spellcheck::WindowsVersionSupportsSpellchecker()) {
    return;
  }

  spellcheck_platform::SetLanguage(
      platform_spell_checker_, "en-US",
      base::BindOnce(&SpellCheckHostChromeImplWinBrowserTest::
                         SetLanguageCompletionCallback,
                     base::Unretained(this)));
  RunUntilResultReceived();

  spell_check_host_->GetPerLanguageSuggestions(
      base::UTF8ToUTF16("tihs"),
      base::BindOnce(
          &SpellCheckHostChromeImplWinBrowserTest::OnSuggestionResult,
          base::Unretained(this)));
  RunUntilResultReceived();

  // Should have 1 vector of results, which should contain at least 1 suggestion
  ASSERT_EQ(1U, suggestion_result_.size());
  EXPECT_GT(suggestion_result_[0].size(), 0U);
}

class SpellCheckHostChromeImplWinBrowserTestDelayInit
    : public SpellCheckHostChromeImplWinBrowserTest {
 public:
  SpellCheckHostChromeImplWinBrowserTestDelayInit() = default;

  void SetUp() override {
    // Don't initialize the SpellcheckService on browser launch.
    feature_list_.InitWithFeatures(
        /*enabled_features=*/{spellcheck::kWinUseBrowserSpellChecker,
                              spellcheck::kWinDelaySpellcheckServiceInit},
        /*disabled_features=*/{});
    InProcessBrowserTest::SetUp();
  }

  void InitializeSpellcheckService() override {
    // With the kWinDelaySpellcheckServiceInit feature flag set, the spellcheck
    // service is not initialized when instantiated. Call InitializeDictionaries
    // to load the dictionaries.
    spell_check_host_->InitializeDictionaries(
        base::BindOnce(&SpellCheckHostChromeImplWinBrowserTestDelayInit::
                           InitializeDictionariesCallback,
                       base::Unretained(this)));
    RunUntilResultReceived();
  }

  void InitializeDictionariesCallback(
      std::vector<spellcheck::mojom::SpellCheckBDictLanguagePtr> dictionaries,
      const std::vector<std::string>& custom_words,
      bool enable) {
    received_result_ = true;
    if (quit_)
      std::move(quit_).Run();
  }
};

IN_PROC_BROWSER_TEST_F(SpellCheckHostChromeImplWinBrowserTestDelayInit,
                       SpellCheckReturnMessage) {
  RunSpellCheckReturnMessageTest();
}

IN_PROC_BROWSER_TEST_F(SpellCheckHostChromeImplWinBrowserTestDelayInit,
                       GetPerLanguageSuggestions) {
  RunGetPerLanguageSuggestionsTest();
}
