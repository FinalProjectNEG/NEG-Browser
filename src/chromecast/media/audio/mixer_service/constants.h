// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMECAST_MEDIA_AUDIO_MIXER_SERVICE_CONSTANTS_H_
#define CHROMECAST_MEDIA_AUDIO_MIXER_SERVICE_CONSTANTS_H_

#include <stdint.h>

namespace chromecast {
namespace media {
namespace mixer_service {

constexpr char kDefaultUnixDomainSocketPath[] = "/tmp/mixer-service";
constexpr int kDefaultTcpPort = 12854;

// First 2 bytes of each message indicate if it is metadata (protobuf) or audio.
enum class MessageType : int16_t {
  kMetadata,
  kAudio,
};

// Returns true if the full mixer is present on the system, false otherwise.
bool HaveFullMixer();

}  // namespace mixer_service
}  // namespace media
}  // namespace chromecast

#endif  // CHROMECAST_MEDIA_AUDIO_MIXER_SERVICE_CONSTANTS_H_
