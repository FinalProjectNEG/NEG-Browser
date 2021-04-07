// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_SPEECH_TTS_CONTROLLER_IMPL_H_
#define CONTENT_BROWSER_SPEECH_TTS_CONTROLLER_IMPL_H_

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "base/gtest_prod_util.h"
#include "base/json/json_reader.h"
#include "base/macros.h"
#include "base/memory/singleton.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/user_metrics.h"
#include "base/observer_list.h"
#include "base/values.h"
#include "build/build_config.h"
#include "content/common/content_export.h"
#include "content/public/browser/tts_controller.h"
#include "content/public/browser/tts_platform.h"
#include "content/public/browser/web_contents_observer.h"
#include "services/data_decoder/public/cpp/data_decoder.h"
#include "url/gurl.h"

namespace content {
class BrowserContext;

#if defined(OS_CHROMEOS)
class TtsControllerDelegate;
#endif

// Singleton class that manages text-to-speech for all TTS engines and
// APIs, maintaining a queue of pending utterances and keeping
// track of all state.
class CONTENT_EXPORT TtsControllerImpl : public TtsController,
                                         public WebContentsObserver {
 public:
  // Get the single instance of this class.
  static TtsControllerImpl* GetInstance();

  void SetStopSpeakingWhenHidden(bool value);

  // TtsController methods
  bool IsSpeaking() override;
  void SpeakOrEnqueue(std::unique_ptr<TtsUtterance> utterance) override;
  void Stop() override;
  void Stop(const GURL& source_url) override;
  void Pause() override;
  void Resume() override;
  void OnTtsEvent(int utterance_id,
                  TtsEventType event_type,
                  int char_index,
                  int length,
                  const std::string& error_message) override;
  void GetVoices(BrowserContext* browser_context,
                 std::vector<VoiceData>* out_voices) override;
  void VoicesChanged() override;
  void AddVoicesChangedDelegate(VoicesChangedDelegate* delegate) override;
  void RemoveVoicesChangedDelegate(VoicesChangedDelegate* delegate) override;
  void RemoveUtteranceEventDelegate(UtteranceEventDelegate* delegate) override;
  void SetTtsEngineDelegate(TtsEngineDelegate* delegate) override;
  TtsEngineDelegate* GetTtsEngineDelegate() override;

  // Called directly by ~BrowserContext, because a raw BrowserContext pointer
  // is stored in an Utterance.
  void OnBrowserContextDestroyed(BrowserContext* browser_context);

  // Testing methods
  void SetTtsPlatform(TtsPlatform* tts_platform) override;
  int QueueSize() override;

  // Strips SSML so that tags are not output by speech engine.
  void StripSSML(
      const std::string& utterance,
      base::OnceCallback<void(const std::string&)> callback) override;

 protected:
  TtsControllerImpl();
  ~TtsControllerImpl() override;

  // Exposed for unittest.
  bool IsPausedForTesting() const { return paused_; }

 private:
  friend class TestTtsControllerImpl;
  friend struct base::DefaultSingletonTraits<TtsControllerImpl>;

  // Get the platform TTS implementation (or injected mock).
  TtsPlatform* GetTtsPlatform();

  // Start speaking the given utterance. Will either take ownership of
  // |utterance| or delete it if there's an error. Returns true on success.
  void SpeakNow(std::unique_ptr<TtsUtterance> utterance);

  // If the current utterance matches |source_url|, it is stopped and the
  // utterance queue cleared.
  void StopAndClearQueue(const GURL& source_url);

  // Stops the current utterance if it matches |source_url|. Returns true on
  // success, false if the current utterance does not match |source_url|.
  bool StopCurrentUtteranceIfMatches(const GURL& source_url);

  // Clear the utterance queue. If send_events is true, will send
  // TTS_EVENT_CANCELLED events on each one.
  void ClearUtteranceQueue(bool send_events);

  // Finalize and delete the current utterance.
  void FinishCurrentUtterance();

  // Start speaking the next utterance in the queue.
  void SpeakNextUtterance();

  // Updates the utterance to have default values for rate, pitch, and
  // volume if they have not yet been set. On Chrome OS, defaults are
  // pulled from user prefs, and may not be the same as other platforms.
  void UpdateUtteranceDefaults(TtsUtterance* utterance);

  // Passed to Speak() as a callback.
  void OnSpeakFinished(int utterance_id, bool success);

  // Static helper methods for StripSSML.
  static void StripSSMLHelper(
      const std::string& utterance,
      base::OnceCallback<void(const std::string&)> on_ssml_parsed,
      data_decoder::DataDecoder::ValueOrError result);
  static void PopulateParsedText(std::string* parsed_text,
                                 const base::Value* element);

  int GetMatchingVoice(TtsUtterance* utterance,
                       const std::vector<VoiceData>& voices);

  // Called internally to set |current_utterance_|.
  void SetCurrentUtterance(std::unique_ptr<TtsUtterance> utterance);

  // Used when the WebContents of the current utterance is destroyed/hidden.
  void StopCurrentUtteranceAndRemoveUtterancesMatching(WebContents* wc);

  // Returns true if the utterance should be spoken.
  bool ShouldSpeakUtterance(TtsUtterance* utterance);

  // WebContentsObserver methods
  void WebContentsDestroyed() override;
  void OnVisibilityChanged(Visibility visibility) override;

#if defined(OS_CHROMEOS)
  TtsControllerDelegate* GetTtsControllerDelegate();
  void SetTtsControllerDelegateForTesting(TtsControllerDelegate* delegate);
  TtsControllerDelegate* delegate_ = nullptr;
#endif

  TtsEngineDelegate* engine_delegate_ = nullptr;

  bool stop_speaking_when_hidden_ = false;

  // A set of delegates that want to be notified when the voices change.
  base::ObserverList<VoicesChangedDelegate> voices_changed_delegates_;

  // The current utterance being spoken.
  std::unique_ptr<TtsUtterance> current_utterance_;

  // Whether the queue is paused or not.
  bool paused_ = false;

  // A pointer to the platform implementation of text-to-speech, for
  // dependency injection.
  TtsPlatform* tts_platform_ = nullptr;

  // A queue of utterances to speak after the current one finishes.
  std::list<std::unique_ptr<TtsUtterance>> utterance_list_;

  DISALLOW_COPY_AND_ASSIGN(TtsControllerImpl);
};

}  // namespace content

#endif  // CONTENT_BROWSER_SPEECH_TTS_CONTROLLER_IMPL_H_
