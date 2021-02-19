// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromecast/media/audio/cast_audio_manager_android.h"

#include <utility>

#include "base/logging.h"
#include "chromecast/media/audio/audio_buildflags.h"
#include "chromecast/media/audio/cast_audio_input_stream.h"
#include "chromecast/media/audio/cast_audio_output_stream.h"
#include "media/audio/android/audio_track_output_stream.h"
#include "media/audio/audio_device_name.h"
#include "media/base/audio_parameters.h"
#include "media/base/channel_layout.h"

namespace chromecast {
namespace media {
namespace {

const int kDefaultSampleRate = 48000;
const int kDefaultInputBufferSize = 1024;

#if BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)
const int kCommunicationsSampleRate = 16000;
const int kCommunicationsInputBufferSize = 160;  // 10 ms.
#endif  // BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)

bool ShouldUseCastAudioOutputStream(const ::media::AudioParameters& params) {
  return params.effects() & ::media::AudioParameters::AUDIO_PREFETCH;
}

}  // namespace

CastAudioManagerAndroid::CastAudioManagerAndroid(
    std::unique_ptr<::media::AudioThread> audio_thread,
    ::media::AudioLogFactory* audio_log_factory,
    base::RepeatingCallback<CmaBackendFactory*()> backend_factory_getter,
    CastAudioManagerHelper::GetSessionIdCallback get_session_id_callback,
    scoped_refptr<base::SingleThreadTaskRunner> media_task_runner,
    mojo::PendingRemote<chromecast::mojom::ServiceConnector> connector)
    : ::media::AudioManagerAndroid(std::move(audio_thread), audio_log_factory),
      helper_(this,
              std::move(backend_factory_getter),
              std::move(get_session_id_callback),
              std::move(media_task_runner),
              std::move(connector)) {}

CastAudioManagerAndroid::~CastAudioManagerAndroid() = default;

bool CastAudioManagerAndroid::HasAudioInputDevices() {
#if BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)
  return true;
#else
  return false;
#endif  // BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)
}

void CastAudioManagerAndroid::GetAudioInputDeviceNames(
    ::media::AudioDeviceNames* device_names) {
  DCHECK(device_names->empty());
#if BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)
  device_names->push_back(::media::AudioDeviceName::CreateCommunications());
#else
  LOG(WARNING) << "No support for input audio devices";
#endif  // BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)
}

::media::AudioParameters CastAudioManagerAndroid::GetInputStreamParameters(
    const std::string& device_id) {
#if BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)
  if (device_id == ::media::AudioDeviceDescription::kCommunicationsDeviceId) {
    return ::media::AudioParameters(::media::AudioParameters::AUDIO_PCM_LINEAR,
                                    ::media::CHANNEL_LAYOUT_MONO,
                                    kCommunicationsSampleRate,
                                    kCommunicationsInputBufferSize);
  }
#endif  // BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)
  LOG(WARNING) << "No support for input audio devices";
  // Need to send a valid AudioParameters object even when it will be unused.
  return ::media::AudioParameters(
      ::media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
      ::media::CHANNEL_LAYOUT_STEREO, kDefaultSampleRate,
      kDefaultInputBufferSize);
}

::media::AudioInputStream* CastAudioManagerAndroid::MakeLinearInputStream(
    const ::media::AudioParameters& params,
    const std::string& device_id,
    const ::media::AudioManager::LogCallback& log_callback) {
#if BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)
  if (device_id == ::media::AudioDeviceDescription::kCommunicationsDeviceId) {
    return new CastAudioInputStream(this, params, device_id);
  }
#endif  // BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)
  LOG(WARNING) << "No support for input audio devices";
  return nullptr;
}

::media::AudioInputStream* CastAudioManagerAndroid::MakeLowLatencyInputStream(
    const ::media::AudioParameters& params,
    const std::string& device_id,
    const ::media::AudioManager::LogCallback& log_callback) {
#if BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)
  if (device_id == ::media::AudioDeviceDescription::kCommunicationsDeviceId) {
    return new CastAudioInputStream(this, params, device_id);
  }
#endif  // BUILDFLAG(ENABLE_AUDIO_CAPTURE_SERVICE)
  LOG(WARNING) << "No support for input audio devices";
  return nullptr;
}

void CastAudioManagerAndroid::GetAudioOutputDeviceNames(
    ::media::AudioDeviceNames* device_names) {
  DCHECK(device_names->empty());
  DCHECK(HasAudioOutputDevices());

  // Default device name is added inside AudioManagerAndroid.
  ::media::AudioManagerAndroid::GetAudioOutputDeviceNames(device_names);

  device_names->push_back(::media::AudioDeviceName::CreateCommunications());
}

::media::AudioOutputStream* CastAudioManagerAndroid::MakeLinearOutputStream(
    const ::media::AudioParameters& params,
    const ::media::AudioManager::LogCallback& log_callback) {
  DCHECK_EQ(::media::AudioParameters::AUDIO_PCM_LINEAR, params.format());

  if (ShouldUseCastAudioOutputStream(params)) {
    return new CastAudioOutputStream(
        &helper_, params, ::media::AudioDeviceDescription::kDefaultDeviceId,
        false /* use_mixer_service */);
  }

  return ::media::AudioManagerAndroid::MakeLinearOutputStream(params,
                                                              log_callback);
}

::media::AudioOutputStream* CastAudioManagerAndroid::MakeLowLatencyOutputStream(
    const ::media::AudioParameters& params,
    const std::string& device_id_or_group_id,
    const ::media::AudioManager::LogCallback& log_callback) {
  DCHECK_EQ(::media::AudioParameters::AUDIO_PCM_LOW_LATENCY, params.format());

  if (ShouldUseCastAudioOutputStream(params)) {
    return new CastAudioOutputStream(
        &helper_, params,
        device_id_or_group_id.empty()
            ? ::media::AudioDeviceDescription::kDefaultDeviceId
            : device_id_or_group_id,
        false /* use_mixer_service */);
  }

  return ::media::AudioManagerAndroid::MakeLowLatencyOutputStream(
      params, device_id_or_group_id, log_callback);
}

::media::AudioOutputStream* CastAudioManagerAndroid::MakeBitstreamOutputStream(
    const ::media::AudioParameters& params,
    const std::string& device_id,
    const ::media::AudioManager::LogCallback& log_callback) {
  DCHECK(params.IsBitstreamFormat());
  return new ::media::AudioTrackOutputStream(this, params);
}

::media::AudioOutputStream* CastAudioManagerAndroid::MakeAudioOutputStreamProxy(
    const ::media::AudioParameters& params,
    const std::string& device_id) {
  if (ShouldUseCastAudioOutputStream(params)) {
    // Override to use MakeAudioOutputStream to prevent the audio output stream
    // from closing during pause/stop.
    return MakeAudioOutputStream(params, device_id,
                                 /*log_callback, not used*/ base::DoNothing());
  }

  return ::media::AudioManagerAndroid::MakeAudioOutputStreamProxy(params,
                                                                  device_id);
}

}  // namespace media
}  // namespace chromecast
