// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_SERVICES_ASSISTANT_PUBLIC_CPP_ASSISTANT_SERVICE_H_
#define CHROMEOS_SERVICES_ASSISTANT_PUBLIC_CPP_ASSISTANT_SERVICE_H_

#include <string>
#include <vector>

#include "base/component_export.h"
#include "base/observer_list_types.h"
#include "base/scoped_observer.h"
#include "chromeos/services/assistant/public/cpp/assistant_enums.h"
#include "chromeos/services/assistant/public/cpp/assistant_notification.h"
#include "chromeos/services/assistant/public/shared/utils.h"
#include "ui/accessibility/mojom/ax_assistant_structure.mojom.h"

namespace chromeos {
namespace assistant {

// Describes an Assistant interaction.
struct COMPONENT_EXPORT(ASSISTANT_SERVICE_PUBLIC) AssistantInteractionMetadata {
  AssistantInteractionMetadata();
  AssistantInteractionMetadata(AssistantInteractionType type,
                               AssistantQuerySource source,
                               const std::string& query);
  AssistantInteractionMetadata(const AssistantInteractionMetadata& suggestion);
  AssistantInteractionMetadata& operator=(const AssistantInteractionMetadata&);
  AssistantInteractionMetadata(AssistantInteractionMetadata&& suggestion);
  AssistantInteractionMetadata& operator=(AssistantInteractionMetadata&&);
  ~AssistantInteractionMetadata();

  AssistantInteractionType type{AssistantInteractionType::kText};
  AssistantQuerySource source{AssistantQuerySource::kUnspecified};
  std::string query;
};

// Models an Assistant suggestion.
struct COMPONENT_EXPORT(ASSISTANT_SERVICE_PUBLIC) AssistantSuggestion {
  AssistantSuggestion();
  AssistantSuggestion(base::UnguessableToken id,
                      AssistantSuggestionType type,
                      const std::string& text);
  AssistantSuggestion(const AssistantSuggestion& suggestion);
  AssistantSuggestion& operator=(const AssistantSuggestion&);
  AssistantSuggestion(AssistantSuggestion&& suggestion);
  AssistantSuggestion& operator=(AssistantSuggestion&&);
  ~AssistantSuggestion();
  // Uniquely identifies a given suggestion.
  base::UnguessableToken id;

  // Allows us to differentiate between a typical Assistant suggestion and an
  // Assistant suggestion of another type (e.g. a conversation starter).
  AssistantSuggestionType type{AssistantSuggestionType::kUnspecified};

  AssistantBetterOnboardingType better_onboarding_type{
      AssistantBetterOnboardingType::kUnspecified};

  // Display text. e.g. "Cancel".
  std::string text;

  // Optional URL for icon. e.g. "https://www.gstatic.com/icon.png".
  // NOTE: This may be an icon resource link. e.g.
  // "googleassistant://resource?type=icon&name=assistant".
  GURL icon_url;

  // Optional URL for action. e.g.
  // "https://www.google.com/search?query=action".
  GURL action_url;
};

// Subscribes to Assistant's interaction event. These events are server driven
// in response to the user's direct interaction with the assistant. Responses
// from the assistant may contain untrusted third-party content. Subscriber
// implementations must be sure to handle the response data appropriately.
class COMPONENT_EXPORT(ASSISTANT_SERVICE_PUBLIC) AssistantInteractionSubscriber
    : public base::CheckedObserver {
 public:
  AssistantInteractionSubscriber() = default;
  AssistantInteractionSubscriber(const AssistantInteractionSubscriber&) =
      delete;
  AssistantInteractionSubscriber& operator=(
      const AssistantInteractionSubscriber&) = delete;
  ~AssistantInteractionSubscriber() override = default;

  // Assistant interaction has started.
  virtual void OnInteractionStarted(
      const AssistantInteractionMetadata& metadata) {}

  // Assistant interaction has ended with the specified |resolution|.
  virtual void OnInteractionFinished(
      AssistantInteractionResolution resolution) {}

  // Assistant got Html response with fallback text from server.
  virtual void OnHtmlResponse(const std::string& response,
                              const std::string& fallback) {}

  // Assistant got suggestions response from server.
  virtual void OnSuggestionsResponse(
      const std::vector<AssistantSuggestion>& response) {}

  // Assistant got text response from server.
  virtual void OnTextResponse(const std::string& response) {}

  // Assistant got open URL response from server. |in_background| refers to
  // being in background of Assistant UI, not in background of browser.
  virtual void OnOpenUrlResponse(const GURL& url, bool in_background) {}

  // Assistant got open Android app response from server. Returns if the app is
  // opened.
  virtual bool OnOpenAppResponse(const AndroidAppInfo& app_info);

  // Assistant speech recognition has started.
  virtual void OnSpeechRecognitionStarted() {}

  // Assistant speech recognition intermediate result is available.
  virtual void OnSpeechRecognitionIntermediateResult(
      const std::string& high_confidence_text,
      const std::string& low_confidence_text) {}

  // Assistant speech recognition detected end of utterance.
  virtual void OnSpeechRecognitionEndOfUtterance() {}

  // Assistant speech recognition final result is available.
  virtual void OnSpeechRecognitionFinalResult(const std::string& final_result) {
  }

  // Assistant got an instantaneous speech level update in dB.
  virtual void OnSpeechLevelUpdated(float speech_level) {}

  // Assistant has started speaking. When TTS is started due to an error that
  // occurred during the interaction, |due_to_error| is true.
  virtual void OnTtsStarted(bool due_to_error) {}

  // Assistant has started waiting. This occur during execution of a routine to
  // give the user time to digest a response before continuing execution.
  virtual void OnWaitStarted() {}
};

//  Details for Assistant feedback.
struct COMPONENT_EXPORT(ASSISTANT_SERVICE_PUBLIC) AssistantFeedback {
  // User input to be sent with the feedback report.
  std::string description;

  // Whether user consent to send debug info.
  bool assistant_debug_info_allowed{false};

  // Screenshot if allowed by user.
  // Raw data (non-encoded binary octets)
  std::string screenshot_png;
};

class COMPONENT_EXPORT(ASSISTANT_SERVICE_PUBLIC) Assistant {
 public:
  Assistant() = default;
  Assistant(const Assistant&) = delete;
  Assistant& operator=(const Assistant&) = delete;
  virtual ~Assistant() = default;

  // Starts an interaction to edit the reminder uniquely identified by
  // |client_id|. In response to the request, LibAssistant will initiate
  // a user facing interaction with the context pre-populated with details
  // to edit the specified reminder.
  virtual void StartEditReminderInteraction(const std::string& client_id) = 0;

  // Starts a screen context interaction. Results related to the screen context
  // will be returned through the |AssistantInteractionSubscriber| interface to
  // registered subscribers.
  // |assistant_screenshot| contains JPEG data.
  virtual void StartScreenContextInteraction(
      ax::mojom::AssistantStructurePtr assistant_structure,
      const std::vector<uint8_t>& assistant_screenshot) = 0;

  // Starts a new Assistant text interaction. If |allow_tts| is true, the
  // result will contain TTS. Otherwise TTS will not be present in the
  // generated server response. Results will be returned through registered
  // |AssistantInteractionSubscriber|.
  virtual void StartTextInteraction(const std::string& query,
                                    AssistantQuerySource source,
                                    bool allow_tts) = 0;

  // Starts a new Assistant voice interaction.
  virtual void StartVoiceInteraction() = 0;

  // Stops the active Assistant interaction and cancel the conversation if
  // |cancel_conversation|. If there is no active interaction, this method
  // is a no-op.
  virtual void StopActiveInteraction(bool cancel_conversation) = 0;

  // Registers assistant interaction event subscriber. Subscribers'
  // implementation is responsible for selecting events of interest.
  virtual void AddAssistantInteractionSubscriber(
      AssistantInteractionSubscriber* subscriber) = 0;
  virtual void RemoveAssistantInteractionSubscriber(
      AssistantInteractionSubscriber* subscriber) = 0;

  // Retrieves a notification. A voiceless interaction will be sent to server to
  // retrieve the notification of |action_index|, which can trigger other
  // Assistant events such as OnTextResponse to show the result in the UI. The
  // retrieved notification will be removed from the UI.
  // |action_index| is the index of the tapped action. The main UI in the
  // notification contains the top level action, which index is 0. The buttons
  // have the additional actions, which are indexed starting from 1.
  virtual void RetrieveNotification(const AssistantNotification& notification,
                                    int action_index) = 0;

  // Dismisses a notification.
  virtual void DismissNotification(
      const AssistantNotification& notification) = 0;

  // Invoked when accessibility status is changed. Note that though
  // accessibility status has changed, |spoken_feedback_enabled| may not have.
  virtual void OnAccessibilityStatusChanged(bool spoken_feedback_enabled) = 0;

  // Send Assistant feedback to Assistant server.
  virtual void SendAssistantFeedback(const AssistantFeedback& feedback) = 0;

  // Invoked on entry to Assistant UI.
  virtual void NotifyEntryIntoAssistantUi(AssistantEntryPoint entry_point) = 0;

  // Alarm/Timer methods -------------------------------------------------------

  // Adds the specified |duration| to the timer identified by |id|.  Note that
  // this method is a no-op if there is no existing timer identified by |id|.
  virtual void AddTimeToTimer(const std::string& id,
                              base::TimeDelta duration) = 0;

  // Pauses the timer specified by |id|. Note that this method is a no-op if
  // there is no existing timer identified by |id| or if a timer does exist but
  // is already paused.
  virtual void PauseTimer(const std::string& id) = 0;

  // Remove the alarm/timer specified by |id|.
  // NOTE: this is a no-op if no such alarm/timer exists.
  virtual void RemoveAlarmOrTimer(const std::string& id) = 0;

  // Resumes the timer specified by |id|. Note that this method is a no-op if
  // there is no existing timer identified by |id| or if a timer does exist but
  // isn't currently paused.
  virtual void ResumeTimer(const std::string& id) = 0;
};

using ScopedAssistantInteractionSubscriber =
    ScopedObserver<Assistant,
                   AssistantInteractionSubscriber,
                   &Assistant::AddAssistantInteractionSubscriber,
                   &Assistant::RemoveAssistantInteractionSubscriber>;

// Main interface between browser and |chromeos::assistant::Service|.
class COMPONENT_EXPORT(ASSISTANT_SERVICE_PUBLIC) AssistantService {
 public:
  AssistantService();
  AssistantService(const AssistantService&) = delete;
  AssistantService& operator=(const AssistantService&) = delete;
  virtual ~AssistantService();

  static AssistantService* Get();

  // Initiates assistant service.
  virtual void Init() = 0;

  // Signals system shutdown, the service could start cleaning up if needed.
  virtual void Shutdown() = 0;

  // Get the main Assistant interface.
  virtual Assistant* GetAssistant() = 0;
};

}  // namespace assistant
}  // namespace chromeos

#endif  // CHROMEOS_SERVICES_ASSISTANT_PUBLIC_CPP_ASSISTANT_SERVICE_H_
