// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromecast/media/audio/cast_audio_manager_alsa.h"

#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/test/test_message_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "chromecast/common/mojom/service_connector.mojom.h"
#include "chromecast/media/cma/test/mock_cma_backend_factory.h"
#include "media/audio/fake_audio_log_factory.h"
#include "media/audio/test_audio_thread.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace chromecast {
namespace media {
namespace {

const char kDefaultAlsaDevice[] = "plug:default";

const ::media::AudioParameters kDefaultAudioParams(
    ::media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
    ::media::CHANNEL_LAYOUT_STEREO,
    ::media::AudioParameters::kAudioCDSampleRate,
    256);

void OnLogMessage(const std::string& message) {}

mojo::PendingRemote<chromecast::mojom::ServiceConnector> CreateConnector() {
  mojo::PendingRemote<chromecast::mojom::ServiceConnector> remote;
  ignore_result(remote.InitWithNewPipeAndPassReceiver());
  return remote;
}

std::string DummyGetSessionId(const std::string& /* audio_group_id */) {
  return "";
}

class CastAudioManagerAlsaTest : public testing::Test {
 public:
  CastAudioManagerAlsaTest() : media_thread_("CastMediaThread") {
    CHECK(media_thread_.Start());

    backend_factory_ = std::make_unique<MockCmaBackendFactory>();
    audio_manager_ = std::make_unique<CastAudioManagerAlsa>(
        std::make_unique<::media::TestAudioThread>(), &audio_log_factory_,
        base::BindRepeating(&CastAudioManagerAlsaTest::GetCmaBackendFactory,
                            base::Unretained(this)),
        base::BindRepeating(&DummyGetSessionId),
        base::ThreadTaskRunnerHandle::Get(), media_thread_.task_runner(),
        CreateConnector(), false);
  }

  ~CastAudioManagerAlsaTest() override { audio_manager_->Shutdown(); }
  CmaBackendFactory* GetCmaBackendFactory() { return backend_factory_.get(); }

 protected:
  base::TestMessageLoop message_loop_;
  std::unique_ptr<MockCmaBackendFactory> backend_factory_;
  base::Thread media_thread_;
  ::media::FakeAudioLogFactory audio_log_factory_;
  std::unique_ptr<CastAudioManagerAlsa> audio_manager_;
};

TEST_F(CastAudioManagerAlsaTest, MakeAudioInputStream) {
  ::media::AudioInputStream* stream = audio_manager_->MakeAudioInputStream(
      kDefaultAudioParams, kDefaultAlsaDevice,
      base::BindRepeating(&OnLogMessage));
  ASSERT_TRUE(stream);
  EXPECT_TRUE(stream->Open());
  stream->Close();
}

}  // namespace
}  // namespace media
}  // namespace chromecast
