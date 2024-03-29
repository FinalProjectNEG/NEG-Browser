// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/webui/commander/commander_ui.h"

#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/commander/commander_view_model.h"
#include "chrome/browser/ui/webui/commander/commander_handler.h"
#include "chrome/common/chrome_isolated_world_ids.h"
#include "chrome/common/webui_url_constants.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "content/public/browser/navigation_controller.h"
#include "content/public/test/browser_test.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/test_web_ui.h"

namespace {

class TestCommanderHandler : public CommanderHandler {
 public:
  explicit TestCommanderHandler(content::WebUI* web_ui) { set_web_ui(web_ui); }
};

}  // namespace

// This actually tests the whole WebUI communication layer as a unit:
// CommanderUI and CommanderHandler.
class CommanderUITest : public InProcessBrowserTest,
                        public CommanderHandler::Delegate {
 public:
  void SetUpOnMainThread() override {
    contents_ = content::WebContents::Create(
        content::WebContents::CreateParams(browser()->profile()));
    contents_->GetController().LoadURL(
        GURL(chrome::kChromeUICommanderURL), content::Referrer(),
        ui::PAGE_TRANSITION_AUTO_TOPLEVEL, std::string());
    CommanderUI* controller =
        static_cast<CommanderUI*>(contents_->GetWebUI()->GetController());
    controller->handler()->PrepareToShow(this);

    ASSERT_TRUE(content::WaitForLoadStop(contents_.get()));
    EXPECT_EQ(contents_->GetLastCommittedURL().host(),
              chrome::kChromeUICommanderHost);
  }
  void TearDownOnMainThread() override {
    contents_.reset();
    dismiss_invocation_count_ = 0;
    text_changed_invocations_.clear();
    option_selected_invocations_.clear();
    height_changed_invocations_.clear();
  }

 protected:
  void ExecuteJS(std::string js) {
    ASSERT_TRUE(content::ExecuteScript(contents_.get(), js));
  }
  // CommanderHandler::Delegate implementation.
  void OnTextChanged(const base::string16& text) override {
    text_changed_invocations_.push_back(text);
  }
  void OnOptionSelected(size_t option_index, int result_set_id) override {
    option_selected_invocations_.emplace_back(option_index, result_set_id);
  }

  void OnDismiss() override { dismiss_invocation_count_++; }

  void OnHeightChanged(int new_height) override {
    height_changed_invocations_.emplace_back(new_height);
  }
  void OnHandlerEnabled(bool enabled) override {}

  const std::vector<base::string16> text_changed_invocations() {
    return text_changed_invocations_;
  }
  const std::vector<std::pair<size_t, int>> option_selected_invocations() {
    return option_selected_invocations_;
  }
  const std::vector<int> height_changed_invocations() {
    return height_changed_invocations_;
  }

  size_t dismiss_invocation_count() { return dismiss_invocation_count_; }

 private:
  std::unique_ptr<content::WebContents> contents_;
  size_t dismiss_invocation_count_ = 0;
  std::vector<base::string16> text_changed_invocations_;
  std::vector<std::pair<size_t, int>> option_selected_invocations_;
  std::vector<int> height_changed_invocations_;
};

IN_PROC_BROWSER_TEST_F(CommanderUITest, Dismiss) {
  EXPECT_EQ(dismiss_invocation_count(), 0u);
  ExecuteJS("chrome.send('dismiss')");
  EXPECT_EQ(dismiss_invocation_count(), 1u);
}

IN_PROC_BROWSER_TEST_F(CommanderUITest, HeightChanged) {
  EXPECT_EQ(height_changed_invocations().size(), 0u);
  ExecuteJS("chrome.send('heightChanged', [42])");
  ASSERT_EQ(height_changed_invocations().size(), 1u);
  ASSERT_EQ(height_changed_invocations().back(), 42);
}

IN_PROC_BROWSER_TEST_F(CommanderUITest, TextChanged) {
  EXPECT_EQ(text_changed_invocations().size(), 0u);
  ExecuteJS("chrome.send('textChanged', ['orange'])");
  ASSERT_EQ(text_changed_invocations().size(), 1u);
  ASSERT_EQ(text_changed_invocations().back(), base::ASCIIToUTF16("orange"));
}

IN_PROC_BROWSER_TEST_F(CommanderUITest, OptionSelected) {
  EXPECT_EQ(option_selected_invocations().size(), 0u);
  ExecuteJS("chrome.send('optionSelected', [13, 586])");
  ASSERT_EQ(option_selected_invocations().size(), 1u);
  std::pair<size_t, int> expected({13, 586});
  ASSERT_EQ(option_selected_invocations().back(), expected);
}

TEST(CommanderHandlerTest, ViewModelPassed) {
  content::TestWebUI test_web_ui;
  auto handler = std::make_unique<TestCommanderHandler>(&test_web_ui);

  commander::CommanderViewModel vm;
  vm.action = commander::CommanderViewModel::Action::kDisplayResults;
  base::string16 item_title = base::ASCIIToUTF16("Test item");
  std::vector<gfx::Range> item_ranges = {gfx::Range(0, 4)};
  vm.items.emplace_back(item_title, item_ranges);
  vm.result_set_id = 42;

  handler->AllowJavascriptForTesting();
  handler->ViewModelUpdated(std::move(vm));
  const content::TestWebUI::CallData& call_data =
      *test_web_ui.call_data().back();
  EXPECT_EQ("cr.webUIListenerCallback", call_data.function_name());
  EXPECT_EQ("view-model-updated", call_data.arg1()->GetString());

  const base::Value* arg = call_data.arg2();
  EXPECT_EQ(
      "Test item",
      arg->FindPath("options")->GetList()[0].FindPath("title")->GetString());
  EXPECT_EQ(0, arg->FindPath("options")
                   ->GetList()[0]
                   .FindPath("matched_ranges")
                   ->GetList()[0]
                   .GetList()[0]
                   .GetInt());
  EXPECT_EQ(4, arg->FindPath("options")
                   ->GetList()[0]
                   .FindPath("matched_ranges")
                   ->GetList()[0]
                   .GetList()[1]
                   .GetInt());
  EXPECT_EQ(42, arg->FindPath("result_set_id")->GetInt());
}

TEST(CommanderHandlerTest, Initialize) {
  content::TestWebUI test_web_ui;
  auto handler = std::make_unique<TestCommanderHandler>(&test_web_ui);
  handler->AllowJavascriptForTesting();
  handler->PrepareToShow(nullptr);
  const content::TestWebUI::CallData& call_data =
      *test_web_ui.call_data().back();
  EXPECT_EQ("cr.webUIListenerCallback", call_data.function_name());
  EXPECT_EQ("initialize", call_data.arg1()->GetString());
}
