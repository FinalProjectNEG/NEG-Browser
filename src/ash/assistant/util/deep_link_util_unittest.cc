// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/assistant/util/deep_link_util.h"

#include <map>
#include <string>
#include <utility>

#include "ash/test/ash_test_base.h"
#include "base/macros.h"
#include "base/optional.h"
#include "base/strings/string_number_conversions.h"
#include "base/timer/timer.h"
#include "chromeos/services/assistant/public/cpp/assistant_service.h"
#include "url/gurl.h"

namespace ash {
namespace assistant {
namespace util {

using chromeos::assistant::AssistantEntryPoint;
using chromeos::assistant::AssistantQuerySource;

using DeepLinkUtilTest = AshTestBase;

TEST_F(DeepLinkUtilTest, AppendOrReplaceEntryPointParam) {
  // Iterate over all possible entry point values.
  for (int i = 0; i < static_cast<int>(AssistantEntryPoint::kMaxValue); ++i) {
    // Test append.
    ASSERT_EQ("googleassistant://send-query?q=weather&entryPoint=" +
                  base::NumberToString(i),
              AppendOrReplaceEntryPointParam(
                  GURL("googleassistant://send-query?q=weather"),
                  static_cast<AssistantEntryPoint>(i))
                  .spec());
    // Test replace.
    ASSERT_EQ("googleassistant://send-query?q=weather&entryPoint=" +
                  base::NumberToString(i),
              AppendOrReplaceEntryPointParam(
                  GURL("googleassistant://send-query?q=weather&entryPoint=foo"),
                  static_cast<AssistantEntryPoint>(i))
                  .spec());
  }
}

TEST_F(DeepLinkUtilTest, AppendOrReplaceQuerySourceParam) {
  // Iterate over all possible query source values.
  for (int i = 0; i < static_cast<int>(AssistantQuerySource::kMaxValue); ++i) {
    // Test append.
    ASSERT_EQ("googleassistant://send-query?q=weather&querySource=" +
                  base::NumberToString(i),
              AppendOrReplaceQuerySourceParam(
                  GURL("googleassistant://send-query?q=weather"),
                  static_cast<AssistantQuerySource>(i))
                  .spec());
    // Test replace.
    ASSERT_EQ(
        "googleassistant://send-query?q=weather&querySource=" +
            base::NumberToString(i),
        AppendOrReplaceQuerySourceParam(
            GURL("googleassistant://send-query?q=weather&querySource=foo"),
            static_cast<AssistantQuerySource>(i))
            .spec());
  }
}

TEST_F(DeepLinkUtilTest, CreateAlarmTimerDeeplink) {
  // OK: Simple case.
  ASSERT_EQ(
      "googleassistant://"
      "alarm-timer?action=addTimeToTimer&id=1&durationMs=60000",
      CreateAlarmTimerDeepLink(AlarmTimerAction::kAddTimeToTimer, "1",
                               base::TimeDelta::FromMinutes(1))
          .value());
  ASSERT_EQ("googleassistant://alarm-timer?action=pauseTimer&id=1",
            CreateAlarmTimerDeepLink(AlarmTimerAction::kPauseTimer, "1",
                                     base::nullopt)
                .value());
  ASSERT_EQ("googleassistant://alarm-timer?action=removeAlarmOrTimer&id=1",
            CreateAlarmTimerDeepLink(AlarmTimerAction::kRemoveAlarmOrTimer, "1",
                                     base::nullopt)
                .value());
  ASSERT_EQ("googleassistant://alarm-timer?action=resumeTimer&id=1",
            CreateAlarmTimerDeepLink(AlarmTimerAction::kResumeTimer, "1",
                                     base::nullopt)
                .value());

  // For invalid deeplink params, we will hit DCHECK since this API isn't meant
  // to be used in such cases. We'll use a |ScopedLogAssertHandler| to safely
  // ignore the NOTREACHED assertion.
  logging::ScopedLogAssertHandler handler(base::BindRepeating(
      [](const char* file, int line, const base::StringPiece message,
         const base::StringPiece stack_trace) {}));

  ASSERT_EQ(base::nullopt,
            CreateAlarmTimerDeepLink(AlarmTimerAction::kAddTimeToTimer, "1",
                                     base::nullopt));
  ASSERT_EQ(base::nullopt, CreateAlarmTimerDeepLink(
                               AlarmTimerAction::kAddTimeToTimer, base::nullopt,
                               base::TimeDelta::FromMinutes(1)));
  ASSERT_EQ(base::nullopt,
            CreateAlarmTimerDeepLink(AlarmTimerAction::kAddTimeToTimer,
                                     base::nullopt, base::nullopt));

  ASSERT_EQ(base::nullopt,
            CreateAlarmTimerDeepLink(AlarmTimerAction::kPauseTimer,
                                     base::nullopt, base::nullopt));
  ASSERT_EQ(base::nullopt, CreateAlarmTimerDeepLink(
                               AlarmTimerAction::kPauseTimer, base::nullopt,
                               base::TimeDelta::FromMinutes(1)));
  ASSERT_EQ(base::nullopt,
            CreateAlarmTimerDeepLink(AlarmTimerAction::kPauseTimer, "1",
                                     base::TimeDelta::FromMinutes(1)));

  ASSERT_EQ(base::nullopt,
            CreateAlarmTimerDeepLink(AlarmTimerAction::kRemoveAlarmOrTimer,
                                     base::nullopt, base::nullopt));
  ASSERT_EQ(base::nullopt, CreateAlarmTimerDeepLink(
                               AlarmTimerAction::kRemoveAlarmOrTimer,
                               base::nullopt, base::TimeDelta::FromMinutes(1)));
  ASSERT_EQ(base::nullopt,
            CreateAlarmTimerDeepLink(AlarmTimerAction::kRemoveAlarmOrTimer, "1",
                                     base::TimeDelta::FromMinutes(1)));

  ASSERT_EQ(base::nullopt,
            CreateAlarmTimerDeepLink(AlarmTimerAction::kResumeTimer,
                                     base::nullopt, base::nullopt));
  ASSERT_EQ(base::nullopt, CreateAlarmTimerDeepLink(
                               AlarmTimerAction::kResumeTimer, base::nullopt,
                               base::TimeDelta::FromMinutes(1)));
  ASSERT_EQ(base::nullopt,
            CreateAlarmTimerDeepLink(AlarmTimerAction::kResumeTimer, "1",
                                     base::TimeDelta::FromMinutes(1)));
}

TEST_F(DeepLinkUtilTest, CreateAssistantQueryDeepLink) {
  const std::map<std::string, std::string> test_cases = {
      // OK: Simple query.
      {"query", "googleassistant://send-query?q=query"},

      // OK: Query containing spaces and special characters.
      {"query with / and spaces & special characters?",
       "googleassistant://"
       "send-query?q=query+with+%2F+and+spaces+%26+special+characters%3F"},
  };

  for (const auto& test_case : test_cases) {
    ASSERT_EQ(GURL(test_case.second),
              CreateAssistantQueryDeepLink(test_case.first));
  }
}

TEST_F(DeepLinkUtilTest, CreateAssistantSettingsDeepLink) {
  ASSERT_EQ(GURL("googleassistant://settings"),
            CreateAssistantSettingsDeepLink());
}

TEST_F(DeepLinkUtilTest, CreateWhatsOnMyScreenDeepLink) {
  ASSERT_EQ(GURL("googleassistant://whats-on-my-screen"),
            CreateWhatsOnMyScreenDeepLink());
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParams) {
  std::map<std::string, std::string> params;

  auto ParseDeepLinkParams = [&params](const std::string& url) {
    params = GetDeepLinkParams(GURL(url));
  };

  // OK: Supported deep link w/ parameters.
  ParseDeepLinkParams("googleassistant://onboarding?k1=v1&k2=v2");
  ASSERT_EQ(2, static_cast<int>(params.size()));
  ASSERT_EQ("v1", params["k1"]);
  ASSERT_EQ("v2", params["k2"]);

  // OK: Supported deep link w/o parameters.
  ParseDeepLinkParams("googleassistant://onboarding");
  ASSERT_TRUE(params.empty());

  // FAIL: Unsupported deep link.
  ParseDeepLinkParams("googleassistant://unsupported?k1=v1&k2=v2");
  ASSERT_TRUE(params.empty());

  // FAIL: Non-deep link URLs.
  ParseDeepLinkParams("https://www.google.com/search?q=query");
  ASSERT_TRUE(params.empty());

  // FAIL: Empty URLs.
  ParseDeepLinkParams(std::string());
  ASSERT_TRUE(params.empty());
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParam) {
  std::map<std::string, std::string> params = {
      {"action", "0"},      {"category", "1"},    {"durationMs", "60000"},
      {"eid", "1"},         {"entryPoint", "1"},  {"href", "https://g.co/"},
      {"id", "timer_id_1"}, {"index", "1"},       {"page", "main"},
      {"q", "query"},       {"querySource", "1"}, {"relaunch", "true"},
      {"veId", "1"},
  };

  auto AssertDeepLinkParamEq = [&params](
                                   const base::Optional<std::string>& expected,
                                   DeepLinkParam param) {
    ASSERT_EQ(expected, GetDeepLinkParam(params, param));
  };

  // Case: Deep link parameters present.
  AssertDeepLinkParamEq("0", DeepLinkParam::kAction);
  AssertDeepLinkParamEq("1", DeepLinkParam::kCategory);
  AssertDeepLinkParamEq("60000", DeepLinkParam::kDurationMs);
  AssertDeepLinkParamEq("1", DeepLinkParam::kEid);
  AssertDeepLinkParamEq("1", DeepLinkParam::kEntryPoint);
  AssertDeepLinkParamEq("https://g.co/", DeepLinkParam::kHref);
  AssertDeepLinkParamEq("timer_id_1", DeepLinkParam::kId);
  AssertDeepLinkParamEq("1", DeepLinkParam::kIndex);
  AssertDeepLinkParamEq("main", DeepLinkParam::kPage);
  AssertDeepLinkParamEq("query", DeepLinkParam::kQuery);
  AssertDeepLinkParamEq("1", DeepLinkParam::kQuerySource);
  AssertDeepLinkParamEq("true", DeepLinkParam::kRelaunch);
  AssertDeepLinkParamEq("1", DeepLinkParam::kVeId);

  // Case: Deep link parameter present, URL encoded.
  params["q"] = "query+with+%2F+and+spaces+%26+special+characters%3F";
  AssertDeepLinkParamEq("query with / and spaces & special characters?",
                        DeepLinkParam::kQuery);

  // Case: Deep link parameters absent.
  params.clear();
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kAction);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kCategory);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kDurationMs);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kEid);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kEntryPoint);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kHref);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kId);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kIndex);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kPage);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kQuery);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kQuerySource);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kRelaunch);
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kVeId);
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParamAsAlarmTimerAction) {
  std::map<std::string, std::string> params;

  auto AssertDeepLinkParamEq =
      [&params](const base::Optional<AlarmTimerAction>& expected) {
        ASSERT_EQ(expected, GetDeepLinkParamAsAlarmTimerAction(params));
      };

  AssertDeepLinkParamEq(base::nullopt);

  // Case: Deep link parameter present, well formed.
  params["action"] = "addTimeToTimer";
  AssertDeepLinkParamEq(AlarmTimerAction::kAddTimeToTimer);
  params["action"] = "pauseTimer";
  AssertDeepLinkParamEq(AlarmTimerAction::kPauseTimer);
  params["action"] = "removeAlarmOrTimer";
  AssertDeepLinkParamEq(AlarmTimerAction::kRemoveAlarmOrTimer);
  params["action"] = "resumeTimer";
  AssertDeepLinkParamEq(AlarmTimerAction::kResumeTimer);

  // Case: Deep link parameter present, non AlarmTimerAction value.
  params["action"] = "true";
  AssertDeepLinkParamEq(base::nullopt);

  // Case: Deep link parameter present, non AlarmTimerAction value.
  params["action"] = "100";
  AssertDeepLinkParamEq(base::nullopt);
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParamAsBool) {
  std::map<std::string, std::string> params;

  auto AssertDeepLinkParamEq = [&params](const base::Optional<bool>& expected,
                                         DeepLinkParam param) {
    ASSERT_EQ(expected, GetDeepLinkParamAsBool(params, param));
  };

  // Case: Deep link parameter present, well formed "true".
  params["relaunch"] = "true";
  AssertDeepLinkParamEq(true, DeepLinkParam::kRelaunch);

  // Case: Deep link parameter present, well formed "false".
  params["relaunch"] = "false";
  AssertDeepLinkParamEq(false, DeepLinkParam::kRelaunch);

  // Case: Deep link parameter present, incorrect case "true".
  params["relaunch"] = "TRUE";
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kRelaunch);

  // Case: Deep link parameter present, incorrect case "false".
  params["relaunch"] = "FALSE";
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kRelaunch);

  // Case: Deep link parameter present, non-bool value.
  params["relaunch"] = "non-bool";
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kRelaunch);

  // Case: Deep link parameter absent.
  params.clear();
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kRelaunch);
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParamAsEntryPoint) {
  std::map<std::string, std::string> params;

  auto AssertDeepLinkParamEq =
      [&params](const base::Optional<AssistantEntryPoint>& expected,
                DeepLinkParam param) {
        ASSERT_EQ(expected, GetDeepLinkParamAsEntryPoint(params, param));
      };

  // Case: Deep link parameter present, well formed.
  for (int i = 0; i < static_cast<int>(AssistantEntryPoint::kMaxValue); ++i) {
    params["entryPoint"] = base::NumberToString(i);
    AssertDeepLinkParamEq(static_cast<AssistantEntryPoint>(i),
                          DeepLinkParam::kEntryPoint);
  }

  // Case: Deep link parameter present, non-entry point value.
  params["entryPoint"] = "non-entry point";
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kEntryPoint);

  // Case: Deep link parameter absent.
  params.clear();
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kEntryPoint);
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParamAsGURL) {
  std::map<std::string, std::string> params;

  auto AssertDeepLinkParamEq = [&params](const base::Optional<GURL>& expected,
                                         DeepLinkParam param) {
    ASSERT_EQ(expected, GetDeepLinkParamAsGURL(params, param));
  };

  // Case: Deep link parameter present, well formed spec.
  params["href"] = "https://g.co/";
  AssertDeepLinkParamEq(GURL("https://g.co/"), DeepLinkParam::kHref);

  // Case: Deep link parameter present, malformed spec.
  // Note that GetDeepLinkParamAsGURL does not perform spec validation.
  params["href"] = "malformed_spec";
  AssertDeepLinkParamEq(GURL("malformed_spec"), DeepLinkParam::kHref);

  // Case: Deep link parameter present, empty spec.
  params["href"] = "";
  AssertDeepLinkParamEq(GURL(), DeepLinkParam::kHref);

  // Case: Deep link parameter absent.
  params.clear();
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kHref);
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParamAsInt) {
  std::map<std::string, std::string> params;

  auto AssertDeepLinkParamEq = [&params](const base::Optional<int>& expected,
                                         DeepLinkParam param) {
    ASSERT_EQ(expected, GetDeepLinkParamAsInt(params, param));
  };

  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kDurationMs);

  // Case: Deep link parameter present, well formed "1".
  params["index"] = "1";
  AssertDeepLinkParamEq(1, DeepLinkParam::kIndex);
  params["index"] = "00";
  AssertDeepLinkParamEq(0, DeepLinkParam::kIndex);

  // Case: Deep link parameter present, non-int value.
  params["index"] = "true";
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kIndex);
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParamAsInt64) {
  std::map<std::string, std::string> params;

  auto AssertDeepLinkParamEq =
      [&params](const base::Optional<int64_t>& expected, DeepLinkParam param) {
        ASSERT_EQ(expected, GetDeepLinkParamAsInt64(params, param));
      };

  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kDurationMs);

  // Case: Deep link parameter present, well formed "60000".
  params["durationMs"] = "60000";
  AssertDeepLinkParamEq(60000, DeepLinkParam::kDurationMs);
  params["durationMs"] = "00";
  AssertDeepLinkParamEq(0, DeepLinkParam::kDurationMs);

  // Case: Deep link parameter present, non-int value.
  params["durationMs"] = "true";
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kDurationMs);
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParamAsQuerySource) {
  std::map<std::string, std::string> params;

  auto AssertDeepLinkParamEq =
      [&params](const base::Optional<AssistantQuerySource>& expected,
                DeepLinkParam param) {
        ASSERT_EQ(expected, GetDeepLinkParamAsQuerySource(params, param));
      };

  // Case: Deep link parameter present, well formed.
  for (int i = 0; i < static_cast<int>(AssistantQuerySource::kMaxValue); ++i) {
    params["querySource"] = base::NumberToString(i);
    AssertDeepLinkParamEq(static_cast<AssistantQuerySource>(i),
                          DeepLinkParam::kQuerySource);
  }

  // Case: Deep link parameter present, non-query source value.
  params["querySource"] = "non-query source";
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kQuerySource);

  // Case: Deep link parameter absent.
  params.clear();
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kQuerySource);
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParamAsTimeDelta) {
  std::map<std::string, std::string> params;

  auto AssertDeepLinkParamEq =
      [&params](const base::Optional<base::TimeDelta>& expected,
                DeepLinkParam param) {
        ASSERT_EQ(expected, GetDeepLinkParamAsTimeDelta(params, param));
      };

  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kDurationMs);

  // Case: Deep link parameter present, well formed "60000".
  params["durationMs"] = "60000";
  AssertDeepLinkParamEq(base::TimeDelta::FromMinutes(1),
                        DeepLinkParam::kDurationMs);
  params["durationMs"] = "00";
  AssertDeepLinkParamEq(base::TimeDelta::FromMilliseconds(0),
                        DeepLinkParam::kDurationMs);

  // Case: Deep link parameter present, non-int value.
  params["durationMs"] = "true";
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kDurationMs);

  // Case: Not accepted deep link param.
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kAction);
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParamAsProactiveSuggestionsAction) {
  std::map<std::string, std::string> params;

  auto AssertDeepLinkParamEq =
      [&params](const base::Optional<ProactiveSuggestionsAction>& expected,
                DeepLinkParam param) {
        ASSERT_EQ(expected,
                  GetDeepLinkParamAsProactiveSuggestionsAction(params, param));
      };

  // Case: Deep link parameter present, well formed "cardClick".
  params["action"] = "cardClick";
  AssertDeepLinkParamEq(ProactiveSuggestionsAction::kCardClick,
                        DeepLinkParam::kAction);

  // Case: Deep link parameter present, well formed "entryPointClick".
  params["action"] = "entryPointClick";
  AssertDeepLinkParamEq(ProactiveSuggestionsAction::kEntryPointClick,
                        DeepLinkParam::kAction);

  // Case: Deep link parameter present, well formed "entryPointClose".
  params["action"] = "entryPointClose";
  AssertDeepLinkParamEq(ProactiveSuggestionsAction::kEntryPointClose,
                        DeepLinkParam::kAction);

  // Case: Deep link parameter present, well formed "viewImpression".
  params["action"] = "viewImpression";
  AssertDeepLinkParamEq(ProactiveSuggestionsAction::kViewImpression,
                        DeepLinkParam::kAction);

  // Case: Deep link parameter present, incorrect parameter.
  params["action"] = "invalid";
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kAction);

  // Case: Deep link parameter absent.
  params.clear();
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kAction);
}

TEST_F(DeepLinkUtilTest, GetDeepLinkParamAsRemindersAction) {
  std::map<std::string, std::string> params;

  auto AssertDeepLinkParamEq =
      [&params](const base::Optional<ReminderAction>& expected,
                DeepLinkParam param) {
        ASSERT_EQ(expected, GetDeepLinkParamAsRemindersAction(params, param));
      };

  // Case: Deep link parameter present, well formed "create".
  params["action"] = "create";
  AssertDeepLinkParamEq(ReminderAction::kCreate, DeepLinkParam::kAction);

  // Case: Deep link parameter present, well formed "edit".
  params["action"] = "edit";
  AssertDeepLinkParamEq(ReminderAction::kEdit, DeepLinkParam::kAction);

  // Case: Deep link parameter present, incorrect parameter.
  params["action"] = "invalid";
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kAction);

  // Case: Deep link parameter absent.
  params.clear();
  AssertDeepLinkParamEq(base::nullopt, DeepLinkParam::kAction);
}

TEST_F(DeepLinkUtilTest, GetDeepLinkType) {
  const std::map<std::string, DeepLinkType> test_cases = {
      // OK: Supported deep links.
      {"googleassistant://alarm-timer", DeepLinkType::kAlarmTimer},
      {"googleassistant://chrome-settings", DeepLinkType::kChromeSettings},
      {"googleassistant://lists", DeepLinkType::kLists},
      {"googleassistant://notes", DeepLinkType::kNotes},
      {"googleassistant://onboarding", DeepLinkType::kOnboarding},
      {"googleassistant://proactive-suggestions",
       DeepLinkType::kProactiveSuggestions},
      {"googleassistant://reminders", DeepLinkType::kReminders},
      {"googleassistant://send-feedback", DeepLinkType::kFeedback},
      {"googleassistant://send-query", DeepLinkType::kQuery},
      {"googleassistant://settings", DeepLinkType::kSettings},
      {"googleassistant://take-screenshot", DeepLinkType::kScreenshot},
      {"googleassistant://task-manager", DeepLinkType::kTaskManager},
      {"googleassistant://whats-on-my-screen", DeepLinkType::kWhatsOnMyScreen},

      // OK: Parameterized deep links.
      {"googleassistant://alarm-timer?param=true", DeepLinkType::kAlarmTimer},
      {"googleassistant://chrome-settings?param=true",
       DeepLinkType::kChromeSettings},
      {"googleassistant://lists?param=true", DeepLinkType::kLists},
      {"googleassistant://notes?param=true", DeepLinkType::kNotes},
      {"googleassistant://onboarding?param=true", DeepLinkType::kOnboarding},
      {"googleassistant://proactive-suggestions?param=true",
       DeepLinkType::kProactiveSuggestions},
      {"googleassistant://reminders?param=true", DeepLinkType::kReminders},
      {"googleassistant://send-feedback?param=true", DeepLinkType::kFeedback},
      {"googleassistant://send-query?param=true", DeepLinkType::kQuery},
      {"googleassistant://settings?param=true", DeepLinkType::kSettings},
      {"googleassistant://take-screenshot?param=true",
       DeepLinkType::kScreenshot},
      {"googleassistant://task-manager?param=true", DeepLinkType::kTaskManager},
      {"googleassistant://whats-on-my-screen?param=true",
       DeepLinkType::kWhatsOnMyScreen},

      // UNSUPPORTED: Deep links are case sensitive.
      {"GOOGLEASSISTANT://ALARM-TIMER", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://CHROME-SETTINGS", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://LISTS", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://NOTES", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://ONBOARDING", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://PROACTIVE-SUGGESTIONS", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://REMINDERS", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://SEND-FEEDBACK", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://SEND-QUERY", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://SETTINGS", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://TAKE-SCREENSHOT", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://TASK-MANAGER", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://WHATS-ON-MY-SCREEN", DeepLinkType::kUnsupported},

      // UNSUPPORTED: Unknown deep links.
      {"googleassistant://", DeepLinkType::kUnsupported},
      {"googleassistant://unsupported", DeepLinkType::kUnsupported},

      // UNSUPPORTED: Non-deep link URLs.
      {std::string(), DeepLinkType::kUnsupported},
      {"https://www.google.com/", DeepLinkType::kUnsupported}};

  for (const auto& test_case : test_cases)
    ASSERT_EQ(test_case.second, GetDeepLinkType(GURL(test_case.first)));
}

TEST_F(DeepLinkUtilTest, IsDeepLinkType) {
  const std::map<std::string, DeepLinkType> test_cases = {
      // OK: Supported deep link types.
      {"googleassistant://alarm-timer", DeepLinkType::kAlarmTimer},
      {"googleassistant://chrome-settings", DeepLinkType::kChromeSettings},
      {"googleassistant://lists", DeepLinkType::kLists},
      {"googleassistant://notes", DeepLinkType::kNotes},
      {"googleassistant://onboarding", DeepLinkType::kOnboarding},
      {"googleassistant://reminders", DeepLinkType::kReminders},
      {"googleassistant://send-feedback", DeepLinkType::kFeedback},
      {"googleassistant://send-query", DeepLinkType::kQuery},
      {"googleassistant://settings", DeepLinkType::kSettings},
      {"googleassistant://take-screenshot", DeepLinkType::kScreenshot},
      {"googleassistant://task-manager", DeepLinkType::kTaskManager},
      {"googleassistant://whats-on-my-screen", DeepLinkType::kWhatsOnMyScreen},

      // OK: Parameterized deep link types.
      {"googleassistant://alarm-timer?param=true", DeepLinkType::kAlarmTimer},
      {"googleassistant://chrome-settings?param=true",
       DeepLinkType::kChromeSettings},
      {"googleassistant://lists?param=true", DeepLinkType::kLists},
      {"googleassistant://notes?param=true", DeepLinkType::kNotes},
      {"googleassistant://onboarding?param=true", DeepLinkType::kOnboarding},
      {"googleassistant://reminders?param=true", DeepLinkType::kReminders},
      {"googleassistant://send-feedback?param=true", DeepLinkType::kFeedback},
      {"googleassistant://send-query?param=true", DeepLinkType::kQuery},
      {"googleassistant://settings?param=true", DeepLinkType::kSettings},
      {"googleassistant://take-screenshot?param=true",
       DeepLinkType::kScreenshot},
      {"googleassistant://task-manager?param=true", DeepLinkType::kTaskManager},
      {"googleassistant://whats-on-my-screen?param=true",
       DeepLinkType::kWhatsOnMyScreen},

      // UNSUPPORTED: Deep links are case sensitive.
      {"GOOGLEASSISTANT://ALARM-TIMER", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://CHROME-SETTINGS", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://LISTS", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://NOTES", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://ONBOARDING", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://REMINDERS", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://SEND-FEEDBACK", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://SEND-QUERY", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://SETTINGS", DeepLinkType::kUnsupported},
      {"GOOGLEASSISTANT://TASK-MANAGER", DeepLinkType::kUnsupported},

      // UNSUPPORTED: Unknown deep links.
      {"googleassistant://", DeepLinkType::kUnsupported},
      {"googleassistant://unsupported", DeepLinkType::kUnsupported},

      // UNSUPPORTED: Non-deep link URLs.
      {std::string(), DeepLinkType::kUnsupported},
      {"https://www.google.com/", DeepLinkType::kUnsupported}};

  for (const auto& test_case : test_cases)
    ASSERT_TRUE(IsDeepLinkType(GURL(test_case.first), test_case.second));
}

TEST_F(DeepLinkUtilTest, IsDeepLinkUrl) {
  const std::map<std::string, bool> test_cases = {
      // OK: Supported deep links.
      {"googleassistant://alarm-timer", true},
      {"googleassistant://chrome-settings", true},
      {"googleassistant://lists", true},
      {"googleassistant://notes", true},
      {"googleassistant://onboarding", true},
      {"googleassistant://reminders", true},
      {"googleassistant://send-feedback", true},
      {"googleassistant://send-query", true},
      {"googleassistant://settings", true},
      {"googleassistant://take-screenshot", true},
      {"googleassistant://task-manager", true},
      {"googleassistant://whats-on-my-screen", true},

      // OK: Parameterized deep links.
      {"googleassistant://alarm-timer?param=true", true},
      {"googleassistant://chrome-settings?param=true", true},
      {"googleassistant://lists?param=true", true},
      {"googleassistant://notes?param=true", true},
      {"googleassistant://onboarding?param=true", true},
      {"googleassistant://reminders?param=true", true},
      {"googleassistant://send-feedback?param=true", true},
      {"googleassistant://send-query?param=true", true},
      {"googleassistant://settings?param=true", true},
      {"googleassistant://take-screenshot?param=true", true},
      {"googleassistant://task-manager?param=true", true},
      {"googleassistant://whats-on-my-screen?param=true", true},

      // FAIL: Deep links are case sensitive.
      {"GOOGLEASSISTANT://ALARM-TIMER", false},
      {"GOOGLEASSISTANT://CHROME-SETTINGS", false},
      {"GOOGLEASSISTANT://LISTS", false},
      {"GOOGLEASSISTANT://NOTES", false},
      {"GOOGLEASSISTANT://ONBOARDING", false},
      {"GOOGLEASSISTANT://REMINDERS", false},
      {"GOOGLEASSISTANT://SEND-FEEDBACK", false},
      {"GOOGLEASSISTANT://SEND-QUERY", false},
      {"GOOGLEASSISTANT://SETTINGS", false},
      {"GOOGLEASSISTANT://TAKE-SCREENSHOT", false},
      {"GOOGLEASSISTANT://TASK-MANAGER", false},
      {"GOOGLEASSISTANT://WHATS-ON-MY-SCREEN", false},

      // FAIL: Unknown deep links.
      {"googleassistant://", false},
      {"googleassistant://unsupported", false},

      // FAIL: Non-deep link URLs.
      {std::string(), false},
      {"https://www.google.com/", false}};

  for (const auto& test_case : test_cases)
    ASSERT_EQ(test_case.second, IsDeepLinkUrl(GURL(test_case.first)));
}

TEST_F(DeepLinkUtilTest, GetAssistantUrl) {
  using TestCase = std::pair<DeepLinkType, std::map<std::string, std::string>>;

  auto CreateTestCase = [](DeepLinkType type,
                           std::map<std::string, std::string> params) {
    return std::make_pair(type, params);
  };

  auto CreateIgnoreCase = [](DeepLinkType type,
                             std::map<std::string, std::string> params) {
    return std::make_pair(std::make_pair(type, params), base::nullopt);
  };

  const std::map<TestCase, base::Optional<GURL>> test_cases = {
      // OK: Top-level lists.

      {CreateTestCase(DeepLinkType::kLists,
                      /*params=*/{{"eid", "112233"}}),
       GURL("https://assistant.google.com/lists/"
            "mainview?eid=112233&hl=en-US&source=Assistant")},

      {CreateTestCase(DeepLinkType::kLists,
                      /*params=*/{}),
       GURL("https://assistant.google.com/lists/"
            "mainview?hl=en-US&source=Assistant")},

      // OK: List by |id|.

      {CreateTestCase(DeepLinkType::kLists,
                      /*params=*/
                      {{"eid", "112233"}, {"id", "123456"}}),
       GURL("https://assistant.google.com/lists/list/"
            "123456?eid=112233&hl=en-US&source=Assistant")},

      // OK: Shoppinglist by |id|.

      {CreateTestCase(DeepLinkType::kLists,
                      /*params=*/
                      {{"type", "shopping"}, {"id", "123456"}}),
       GURL("https://shoppinglist.google.com/lists/123456"
            "?hl=en-US&source=Assistant")},

      // OK: Top-level notes.

      {CreateTestCase(DeepLinkType::kNotes,
                      /*params=*/{{"eid", "112233"}}),
       GURL("https://assistant.google.com/lists/"
            "mainview?note_tap=true&eid=112233&hl=en-US&source=Assistant")},

      {CreateTestCase(DeepLinkType::kNotes,
                      /*params=*/{}),
       GURL("https://assistant.google.com/lists/"
            "mainview?note_tap=true&hl=en-US&source=Assistant")},

      // OK: Note by |id|.

      {CreateTestCase(DeepLinkType::kNotes,
                      /*params=*/
                      {{"eid", "112233"}, {"id", "123456"}}),
       GURL("https://assistant.google.com/lists/note/"
            "123456?eid=112233&hl=en-US&source=Assistant")},

      // OK: Top-level reminders.

      {CreateTestCase(DeepLinkType::kReminders,
                      /*params=*/{}),
       GURL("https://assistant.google.com/reminders/"
            "mainview?hl=en-US&source=Assistant")},

      // OK: Reminder by |id|.

      {CreateTestCase(DeepLinkType::kReminders,
                      /*params=*/{{"id", "123456"}}),
       GURL("https://assistant.google.com/reminders/id/"
            "123456?hl=en-US&source=Assistant")},

      // IGNORE: Deep links of other types.

      CreateIgnoreCase(DeepLinkType::kUnsupported,
                       /*params=*/{}),
      CreateIgnoreCase(DeepLinkType::kUnsupported,
                       /*params=*/
                       {{"eid", "112233"}, {"id", "123456"}}),
      CreateIgnoreCase(DeepLinkType::kChromeSettings,
                       /*params=*/{}),
      CreateIgnoreCase(DeepLinkType::kChromeSettings,
                       /*params=*/
                       {{"eid", "112233"}, {"id", "123456"}}),
      CreateIgnoreCase(DeepLinkType::kFeedback,
                       /*params=*/{}),
      CreateIgnoreCase(DeepLinkType::kFeedback,
                       /*params=*/
                       {{"eid", "112233"}, {"id", "123456"}}),
      CreateIgnoreCase(DeepLinkType::kOnboarding,
                       /*params=*/{}),
      CreateIgnoreCase(DeepLinkType::kOnboarding,
                       /*params=*/
                       {{"eid", "112233"}, {"id", "123456"}}),
      CreateIgnoreCase(DeepLinkType::kQuery,
                       /*params=*/{}),
      CreateIgnoreCase(DeepLinkType::kQuery,
                       /*params=*/
                       {{"eid", "112233"}, {"id", "123456"}}),
      CreateIgnoreCase(DeepLinkType::kScreenshot,
                       /*params=*/{}),
      CreateIgnoreCase(DeepLinkType::kScreenshot,
                       /*params=*/
                       {{"eid", "112233"}, {"id", "123456"}}),
      CreateIgnoreCase(DeepLinkType::kSettings,
                       /*params=*/{}),
      CreateIgnoreCase(DeepLinkType::kSettings,
                       /*params=*/
                       {{"eid", "112233"}, {"id", "123456"}}),
      CreateIgnoreCase(DeepLinkType::kTaskManager,
                       /*params=*/{}),
      CreateIgnoreCase(DeepLinkType::kTaskManager,
                       /*params=*/
                       {{"eid", "112233"}, {"id", "123456"}}),
      CreateIgnoreCase(DeepLinkType::kWhatsOnMyScreen,
                       /*params=*/{}),
      CreateIgnoreCase(DeepLinkType::kWhatsOnMyScreen,
                       /*params=*/
                       {{"eid", "112233"}, {"id", "123456"}})};

  // For deep links that are not one of type {kLists, kNotes, kReminders}, we
  // will hit NOTREACHED since this API isn't meant to be used in such cases.
  // In unit tests, this would normally result in a DCHECK failure that would
  // cause the test to fail so we'll use a |ScopedLogAssertHandler| to safely
  // ignore the NOTREACHED assertion.
  logging::ScopedLogAssertHandler handler(base::BindRepeating(
      [](const char* file, int line, const base::StringPiece message,
         const base::StringPiece stack_trace) {}));

  for (const auto& test_case : test_cases) {
    const base::Optional<GURL>& expected = test_case.second;
    const base::Optional<GURL> actual = GetAssistantUrl(
        /*type=*/test_case.first.first, /*params=*/test_case.first.second);

    // Assert |has_value| equivalence.
    ASSERT_EQ(expected, actual);

    // Assert |value| equivalence.
    if (expected)
      ASSERT_EQ(expected.value(), actual.value());
  }
}  // namespace util

TEST_F(DeepLinkUtilTest, GetChromeSettingsUrl) {
  const std::map<base::Optional<std::string>, std::string> test_cases = {
      // OK: Absent/empty page.
      {base::nullopt, "chrome://os-settings/"},
      {base::Optional<std::string>(std::string()), "chrome://os-settings/"},

      // OK: Allowed pages.
      {base::Optional<std::string>("googleAssistant"),
       "chrome://os-settings/googleAssistant"},
      {base::Optional<std::string>("languages"),
       "chrome://os-settings/osLanguages/details"},

      // FALLBACK: Allowed pages are case sensitive.
      {base::Optional<std::string>("GOOGLEASSISTANT"), "chrome://os-settings/"},
      {base::Optional<std::string>("LANGUAGES"), "chrome://os-settings/"},

      // FALLBACK: Any page not explicitly allowed.
      {base::Optional<std::string>("search"), "chrome://os-settings/"}};

  for (const auto& test_case : test_cases)
    ASSERT_EQ(test_case.second, GetChromeSettingsUrl(test_case.first));
}

TEST_F(DeepLinkUtilTest, GetWebUrl) {
  const std::map<std::string, base::Optional<GURL>> test_cases = {
      // OK: Supported web deep links.
      {"googleassistant://lists?eid=123456",
       GURL("https://assistant.google.com/lists/"
            "mainview?eid=123456&hl=en-US&source=Assistant")},
      {"googleassistant://notes?eid=123456",
       GURL("https://assistant.google.com/lists/"
            "mainview?note_tap=true&eid=123456&hl=en-US&source=Assistant")},
      {"googleassistant://reminders",
       GURL("https://assistant.google.com/reminders/"
            "mainview?hl=en-US&source=Assistant")},
      {"googleassistant://settings",
       GURL("https://assistant.google.com/settings/mainpage?hl=en-US")},

      // OK: Parameterized deep links.
      {"googleassistant://lists?id=123456&eid=112233",
       GURL("https://assistant.google.com/lists/list/"
            "123456?eid=112233&hl=en-US&source=Assistant")},
      {"googleassistant://lists?id=123456&type=shopping",
       GURL("https://shoppinglist.google.com/lists/"
            "123456?hl=en-US&source=Assistant")},
      {"googleassistant://notes?id=123456&eid=112233",
       GURL("https://assistant.google.com/lists/note/"
            "123456?eid=112233&hl=en-US&source=Assistant")},
      {"googleassistant://reminders?id=123456",
       GURL("https://assistant.google.com/reminders/id/"
            "123456?hl=en-US&source=Assistant")},
      {"googleassistant://settings?param=true",
       GURL("https://assistant.google.com/settings/mainpage?hl=en-US")},

      // FAIL: Deep links are case sensitive.
      {"GOOGLEASSISTANT://LISTS", base::nullopt},
      {"GOOGLEASSISTANT://NOTES", base::nullopt},
      {"GOOGLEASSISTANT://REMINDERS", base::nullopt},
      {"GOOGLEASSISTANT://SETTINGS", base::nullopt},

      // FAIL: Non-web deep links.
      {"googleassistant://alarm-timer", base::nullopt},
      {"googleassistant://chrome-settings", base::nullopt},
      {"googleassistant://onboarding", base::nullopt},
      {"googleassistant://send-feedback", base::nullopt},
      {"googleassistant://send-query", base::nullopt},
      {"googleassistant://take-screenshot", base::nullopt},
      {"googleassistant://task-manager", base::nullopt},
      {"googleassistant://whats-on-my-screen", base::nullopt},

      // FAIL: Non-deep link URLs.
      {std::string(), base::nullopt},
      {"https://www.google.com/", base::nullopt}};

  for (const auto& test_case : test_cases) {
    const base::Optional<GURL>& expected = test_case.second;
    const base::Optional<GURL> actual = GetWebUrl(GURL(test_case.first));

    // Assert |has_value| equivalence.
    ASSERT_EQ(expected, actual);

    // Assert |value| equivalence.
    if (expected)
      ASSERT_EQ(expected.value(), actual.value());
  }
}

TEST_F(DeepLinkUtilTest, GetWebUrlByType) {
  using DeepLinkParams = std::map<std::string, std::string>;
  using TestCase = std::pair<DeepLinkType, DeepLinkParams>;

  // Creates a test case with a single parameter.
  auto CreateTestCaseWithParam =
      [](DeepLinkType type,
         base::Optional<std::pair<std::string, std::string>> param =
             base::nullopt) {
        DeepLinkParams params;
        if (param)
          params.insert(param.value());
        return std::make_pair(type, params);
      };

  // Creates a test case with multiple parameter.
  auto CreateTestCaseWithParams = [](DeepLinkType type, DeepLinkParams params) {
    return std::make_pair(type, params);
  };

  // Creates a test case with no parameters.
  auto CreateTestCase = [&CreateTestCaseWithParam](DeepLinkType type) {
    return CreateTestCaseWithParam(type);
  };

  const std::map<TestCase, base::Optional<GURL>> test_cases = {
      // OK: Supported web deep link types.
      {CreateTestCaseWithParam(DeepLinkType::kLists,
                               std::make_pair("eid", "123456")),
       GURL("https://assistant.google.com/lists/"
            "mainview?eid=123456&hl=en-US&source=Assistant")},
      {CreateTestCaseWithParams(DeepLinkType::kLists,
                                {{"id", "123456"}, {"eid", "112233"}}),
       GURL("https://assistant.google.com/lists/list/"
            "123456?eid=112233&hl=en-US&source=Assistant")},
      {CreateTestCaseWithParams(DeepLinkType::kLists,
                                {{"id", "123456"}, {"type", "shopping"}}),
       GURL("https://shoppinglist.google.com/lists/"
            "123456?hl=en-US&source=Assistant")},
      {CreateTestCaseWithParam(DeepLinkType::kNotes,
                               std::make_pair("eid", "123456")),
       GURL("https://assistant.google.com/lists/"
            "mainview?note_tap=true&eid=123456&hl=en-US&source=Assistant")},
      {CreateTestCaseWithParams(DeepLinkType::kNotes,
                                {{"id", "123456"}, {"eid", "112233"}}),
       GURL("https://assistant.google.com/lists/note/"
            "123456?eid=112233&hl=en-US&source=Assistant")},
      {CreateTestCase(DeepLinkType::kReminders),
       GURL("https://assistant.google.com/reminders/"
            "mainview?hl=en-US&source=Assistant")},
      {CreateTestCaseWithParam(DeepLinkType::kReminders,
                               std::make_pair("id", "123456")),
       GURL("https://assistant.google.com/reminders/id/"
            "123456?hl=en-US&source=Assistant")},
      {CreateTestCase(DeepLinkType::kSettings),
       GURL("https://assistant.google.com/settings/mainpage?hl=en-US")},

      // FAIL: Non-web deep link types.
      {CreateTestCase(DeepLinkType::kChromeSettings), base::nullopt},
      {CreateTestCase(DeepLinkType::kFeedback), base::nullopt},
      {CreateTestCase(DeepLinkType::kOnboarding), base::nullopt},
      {CreateTestCase(DeepLinkType::kQuery), base::nullopt},
      {CreateTestCase(DeepLinkType::kScreenshot), base::nullopt},
      {CreateTestCase(DeepLinkType::kTaskManager), base::nullopt},
      {CreateTestCase(DeepLinkType::kWhatsOnMyScreen), base::nullopt},

      // FAIL: Unsupported deep link types.
      {CreateTestCase(DeepLinkType::kUnsupported), base::nullopt}};

  for (const auto& test_case : test_cases) {
    const base::Optional<GURL>& expected = test_case.second;
    const base::Optional<GURL> actual = GetWebUrl(
        /*type=*/test_case.first.first, /*params=*/test_case.first.second);

    // Assert |has_value| equivalence.
    ASSERT_EQ(expected, actual);

    // Assert |value| equivalence.
    if (expected)
      ASSERT_EQ(expected.value(), actual.value());
  }
}

TEST_F(DeepLinkUtilTest, IsWebDeepLink) {
  const std::map<std::string, bool> test_cases = {
      // OK: Supported web deep links.
      {"googleassistant://lists", true},
      {"googleassistant://notes", true},
      {"googleassistant://reminders", true},
      {"googleassistant://settings", true},

      // OK: Parameterized deep links.
      {"googleassistant://lists?param=true", true},
      {"googleassistant://notes?param=true", true},
      {"googleassistant://reminders?param=true", true},
      {"googleassistant://settings?param=true", true},

      // FAIL: Deep links are case sensitive.
      {"GOOGLEASSISTANT://LISTS", false},
      {"GOOGLEASSISTANT://NOTES", false},
      {"GOOGLEASSISTANT://REMINDERS", false},
      {"GOOGLEASSISTANT://SETTINGS", false},

      // FAIL: Non-web deep links.
      {"googleassistant://alarm-timer", false},
      {"googleassistant://chrome-settings", false},
      {"googleassistant://onboarding", false},
      {"googleassistant://send-feedback", false},
      {"googleassistant://send-query", false},
      {"googleassistant://take-screenshot", false},
      {"googleassistant://task-manager", false},
      {"googleassistant://whats-on-my-screen", false},
      {"googleassistant://reminders?action=create", false},
      {"googleassistant://reminders?action=edit", false},

      // FAIL: Non-deep link URLs.
      {std::string(), false},
      {"https://www.google.com/", false}};

  for (const auto& test_case : test_cases)
    ASSERT_EQ(test_case.second, IsWebDeepLink(GURL(test_case.first)));
}

TEST_F(DeepLinkUtilTest, IsWebDeepLinkType) {
  const std::map<DeepLinkType, bool> test_cases = {
      // OK: Supported web deep link types.
      {DeepLinkType::kLists, true},
      {DeepLinkType::kNotes, true},
      {DeepLinkType::kReminders, true},
      {DeepLinkType::kSettings, true},

      // FAIL: Non-web deep link types.
      {DeepLinkType::kChromeSettings, false},
      {DeepLinkType::kFeedback, false},
      {DeepLinkType::kOnboarding, false},
      {DeepLinkType::kQuery, false},
      {DeepLinkType::kScreenshot, false},
      {DeepLinkType::kTaskManager, false},
      {DeepLinkType::kWhatsOnMyScreen, false},

      // FAIL: Unsupported deep link types.
      {DeepLinkType::kUnsupported, false}};

  auto params = std::map<std::string, std::string>();

  for (const auto& test_case : test_cases)
    ASSERT_EQ(test_case.second, IsWebDeepLinkType(test_case.first, params));

  ASSERT_FALSE(
      IsWebDeepLinkType(DeepLinkType::kReminders, {{"action", "edit"}}));
  ASSERT_FALSE(
      IsWebDeepLinkType(DeepLinkType::kReminders, {{"action", "create"}}));
}

}  // namespace util
}  // namespace assistant
}  // namespace ash
