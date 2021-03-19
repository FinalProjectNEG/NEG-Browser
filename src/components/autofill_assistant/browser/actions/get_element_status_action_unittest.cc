// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/autofill_assistant/browser/actions/get_element_status_action.h"

#include "base/guid.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/gmock_callback_support.h"
#include "base/test/mock_callback.h"
#include "components/autofill/core/browser/autofill_test_utils.h"
#include "components/autofill/core/browser/data_model/autofill_profile.h"
#include "components/autofill/core/browser/field_types.h"
#include "components/autofill_assistant/browser/actions/action_test_utils.h"
#include "components/autofill_assistant/browser/actions/mock_action_delegate.h"
#include "components/autofill_assistant/browser/selector.h"
#include "components/autofill_assistant/browser/service.pb.h"
#include "testing/gmock/include/gmock/gmock.h"

namespace autofill_assistant {
namespace {

using ::base::test::RunOnceCallback;
using ::testing::_;
using ::testing::Pointee;
using ::testing::Property;
using ::testing::Return;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAre;

const char kValue[] = "Some Value";

class GetElementStatusActionTest : public testing::Test {
 public:
  GetElementStatusActionTest() {}

  void SetUp() override {
    ON_CALL(mock_action_delegate_, GetUserData)
        .WillByDefault(Return(&user_data_));
    ON_CALL(mock_action_delegate_, OnShortWaitForElement(_, _))
        .WillByDefault(RunOnceCallback<1>(OkClientStatus()));
    ON_CALL(mock_action_delegate_, OnGetFieldValue(_, _))
        .WillByDefault(RunOnceCallback<1>(OkClientStatus(), kValue));
  }

 protected:
  void Run() {
    ActionProto action_proto;
    *action_proto.mutable_get_element_status() = proto_;
    GetElementStatusAction action(&mock_action_delegate_, action_proto);
    action.ProcessAction(callback_.Get());
  }

  MockActionDelegate mock_action_delegate_;
  base::MockCallback<Action::ProcessActionCallback> callback_;
  GetElementStatusProto proto_;
  UserData user_data_;
};

TEST_F(GetElementStatusActionTest, EmptySelectorFails) {
  EXPECT_CALL(
      callback_,
      Run(Pointee(Property(&ProcessedActionProto::status, INVALID_SELECTOR))));
  Run();
}

TEST_F(GetElementStatusActionTest, ActionFailsForNonExistentElement) {
  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value(
      kValue);

  EXPECT_CALL(mock_action_delegate_, OnShortWaitForElement(selector, _))
      .WillOnce(RunOnceCallback<1>(ClientStatus(TIMED_OUT)));

  EXPECT_CALL(callback_,
              Run(Pointee(Property(&ProcessedActionProto::status, TIMED_OUT))));
  Run();
}

TEST_F(GetElementStatusActionTest, ActionReportsAllVariations) {
  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value(
      kValue);

  EXPECT_CALL(
      callback_,
      Run(Pointee(AllOf(
          Property(&ProcessedActionProto::status, ACTION_APPLIED),
          Property(
              &ProcessedActionProto::get_element_status_result,
              AllOf(
                  Property(&GetElementStatusProto::Result::not_empty, true),
                  Property(&GetElementStatusProto::Result::match_success, true),
                  Property(&GetElementStatusProto::Result::reports,
                           SizeIs(4))))))));
  Run();
}

TEST_F(GetElementStatusActionTest, ActionFailsForMismatchIfRequired) {
  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value(
      "other");
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->set_full_match(true);
  proto_.set_mismatch_should_fail(true);

  EXPECT_CALL(
      callback_,
      Run(Pointee(AllOf(
          Property(&ProcessedActionProto::status, ELEMENT_MISMATCH),
          Property(
              &ProcessedActionProto::get_element_status_result,
              AllOf(Property(&GetElementStatusProto::Result::not_empty, true),
                    Property(&GetElementStatusProto::Result::match_success,
                             false)))))));
  Run();
}

TEST_F(GetElementStatusActionTest, ActionSucceedsForMismatchIfAllowed) {
  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value(
      "other");
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->set_full_match(true);

  EXPECT_CALL(
      callback_,
      Run(Pointee(AllOf(
          Property(&ProcessedActionProto::status, ACTION_APPLIED),
          Property(
              &ProcessedActionProto::get_element_status_result,
              AllOf(Property(&GetElementStatusProto::Result::not_empty, true),
                    Property(&GetElementStatusProto::Result::match_success,
                             false)))))));
  Run();
}

TEST_F(GetElementStatusActionTest, ActionSucceedsForNoExpectation) {
  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value(
      "other");
  proto_.set_mismatch_should_fail(true);

  EXPECT_CALL(
      callback_,
      Run(Pointee(AllOf(
          Property(&ProcessedActionProto::status, ACTION_APPLIED),
          Property(
              &ProcessedActionProto::get_element_status_result,
              AllOf(Property(&GetElementStatusProto::Result::not_empty, true),
                    Property(&GetElementStatusProto::Result::match_success,
                             true)))))));
  Run();
}

TEST_F(GetElementStatusActionTest, ActionSucceedsForCaseSensitiveFullMatch) {
  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value(
      kValue);
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->mutable_match_options()
      ->set_case_sensitive(true);
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->set_full_match(true);
  proto_.set_mismatch_should_fail(true);

  EXPECT_CALL(
      callback_,
      Run(Pointee(AllOf(
          Property(&ProcessedActionProto::status, ACTION_APPLIED),
          Property(
              &ProcessedActionProto::get_element_status_result,
              AllOf(Property(&GetElementStatusProto::Result::not_empty, true),
                    Property(&GetElementStatusProto::Result::match_success,
                             true)))))));
  Run();
}

TEST_F(GetElementStatusActionTest, ActionSucceedsForCaseSensitiveContains) {
  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value(
      "me Va");
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->mutable_match_options()
      ->set_case_sensitive(true);
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->set_contains(true);
  proto_.set_mismatch_should_fail(true);

  EXPECT_CALL(
      callback_,
      Run(Pointee(AllOf(
          Property(&ProcessedActionProto::status, ACTION_APPLIED),
          Property(
              &ProcessedActionProto::get_element_status_result,
              AllOf(Property(&GetElementStatusProto::Result::not_empty, true),
                    Property(&GetElementStatusProto::Result::match_success,
                             true)))))));
  Run();
}

TEST_F(GetElementStatusActionTest, ActionSucceedsForCaseSensitiveStartsWith) {
  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value(
      "Some");
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->mutable_match_options()
      ->set_case_sensitive(true);
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->set_starts_with(true);
  proto_.set_mismatch_should_fail(true);

  EXPECT_CALL(
      callback_,
      Run(Pointee(AllOf(
          Property(&ProcessedActionProto::status, ACTION_APPLIED),
          Property(
              &ProcessedActionProto::get_element_status_result,
              AllOf(Property(&GetElementStatusProto::Result::not_empty, true),
                    Property(&GetElementStatusProto::Result::match_success,
                             true)))))));
  Run();
}

TEST_F(GetElementStatusActionTest, ActionSucceedsForCaseSensitiveEndsWith) {
  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value(
      "Value");
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->mutable_match_options()
      ->set_case_sensitive(true);
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->set_ends_with(true);
  proto_.set_mismatch_should_fail(true);

  EXPECT_CALL(
      callback_,
      Run(Pointee(AllOf(
          Property(&ProcessedActionProto::status, ACTION_APPLIED),
          Property(
              &ProcessedActionProto::get_element_status_result,
              AllOf(Property(&GetElementStatusProto::Result::not_empty, true),
                    Property(&GetElementStatusProto::Result::match_success,
                             true)))))));
  Run();
}

TEST_F(GetElementStatusActionTest, ActionSucceedsForCaseInsensitiveFullMatch) {
  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value(
      "sOmE vAlUe");
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->mutable_match_options()
      ->set_case_sensitive(false);
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->set_full_match(true);
  proto_.set_mismatch_should_fail(true);

  EXPECT_CALL(
      callback_,
      Run(Pointee(AllOf(
          Property(&ProcessedActionProto::status, ACTION_APPLIED),
          Property(
              &ProcessedActionProto::get_element_status_result,
              AllOf(Property(&GetElementStatusProto::Result::not_empty, true),
                    Property(&GetElementStatusProto::Result::match_success,
                             true)))))));
  Run();
}

TEST_F(GetElementStatusActionTest, ActionSucceedsForFullMatchWithoutSpaces) {
  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value(
      "S o m eV a l u e");
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->mutable_match_options()
      ->set_case_sensitive(true);
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->mutable_match_options()
      ->set_remove_space(true);
  proto_.mutable_expected_value_match()
      ->mutable_text_match()
      ->mutable_match_expectation()
      ->set_full_match(true);
  proto_.set_mismatch_should_fail(true);

  EXPECT_CALL(
      callback_,
      Run(Pointee(AllOf(
          Property(&ProcessedActionProto::status, ACTION_APPLIED),
          Property(
              &ProcessedActionProto::get_element_status_result,
              AllOf(Property(&GetElementStatusProto::Result::not_empty, true),
                    Property(&GetElementStatusProto::Result::match_success,
                             true)))))));
  Run();
}

TEST_F(GetElementStatusActionTest, EmptyTextForEmptyFieldIsSuccess) {
  ON_CALL(mock_action_delegate_, OnGetFieldValue(_, _))
      .WillByDefault(RunOnceCallback<1>(OkClientStatus(), ""));

  Selector selector({"#element"});
  *proto_.mutable_element() = selector.proto;
  proto_.mutable_expected_value_match()->mutable_text_match()->set_value("");
  proto_.set_mismatch_should_fail(true);

  EXPECT_CALL(
      callback_,
      Run(Pointee(AllOf(
          Property(&ProcessedActionProto::status, ACTION_APPLIED),
          Property(
              &ProcessedActionProto::get_element_status_result,
              AllOf(Property(&GetElementStatusProto::Result::not_empty, false),
                    Property(&GetElementStatusProto::Result::match_success,
                             true)))))));
  Run();
}

}  // namespace
}  // namespace autofill_assistant
