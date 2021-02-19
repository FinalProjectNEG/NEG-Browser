// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/media/session/media_session_controller.h"

#include "content/browser/media/media_devices_util.h"
#include "content/browser/media/media_web_contents_observer.h"
#include "content/browser/media/session/media_session_impl.h"
#include "content/browser/renderer_host/render_frame_host_impl.h"
#include "content/common/media/media_player_delegate_messages.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/media_device_id.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/web_contents.h"
#include "media/base/media_content_type.h"

namespace content {

int MediaSessionController::player_count_ = 0;

MediaSessionController::MediaSessionController(const MediaPlayerId& id,
                                               WebContents* web_contents)
    : id_(id),
      web_contents_(web_contents),
      media_session_(MediaSessionImpl::Get(web_contents)) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
}

MediaSessionController::~MediaSessionController() {
  media_session_->RemovePlayer(this, player_id_);
}

void MediaSessionController::SetMetadata(
    bool has_audio,
    bool has_video,
    media::MediaContentType media_content_type) {
  has_audio_ = has_audio;
  has_video_ = has_video;
  media_content_type_ = media_content_type;
  AddOrRemovePlayer();
}

bool MediaSessionController::OnPlaybackStarted() {
  is_paused_ = false;
  is_playback_in_progress_ = true;
  return AddOrRemovePlayer();
}

void MediaSessionController::OnSuspend(int player_id) {
  DCHECK_EQ(player_id_, player_id);
  // TODO(crbug.com/953645): Set triggered_by_user to true ONLY if that action
  // was actually triggered by user as this will activate the frame.
  id_.render_frame_host->Send(new MediaPlayerDelegateMsg_Pause(
      id_.render_frame_host->GetRoutingID(), id_.delegate_id,
      true /* triggered_by_user */));
}

void MediaSessionController::OnResume(int player_id) {
  DCHECK_EQ(player_id_, player_id);
  id_.render_frame_host->Send(new MediaPlayerDelegateMsg_Play(
      id_.render_frame_host->GetRoutingID(), id_.delegate_id));
}

void MediaSessionController::OnSeekForward(int player_id,
                                           base::TimeDelta seek_time) {
  DCHECK_EQ(player_id_, player_id);
  id_.render_frame_host->Send(new MediaPlayerDelegateMsg_SeekForward(
      id_.render_frame_host->GetRoutingID(), id_.delegate_id, seek_time));
}

void MediaSessionController::OnSeekBackward(int player_id,
                                            base::TimeDelta seek_time) {
  DCHECK_EQ(player_id_, player_id);
  id_.render_frame_host->Send(new MediaPlayerDelegateMsg_SeekBackward(
      id_.render_frame_host->GetRoutingID(), id_.delegate_id, seek_time));
}

void MediaSessionController::OnSetVolumeMultiplier(int player_id,
                                                   double volume_multiplier) {
  DCHECK_EQ(player_id_, player_id);
  id_.render_frame_host->Send(new MediaPlayerDelegateMsg_UpdateVolumeMultiplier(
      id_.render_frame_host->GetRoutingID(), id_.delegate_id,
      volume_multiplier));
}

void MediaSessionController::OnEnterPictureInPicture(int player_id) {
  DCHECK_EQ(player_id_, player_id);
  id_.render_frame_host->Send(new MediaPlayerDelegateMsg_EnterPictureInPicture(
      id_.render_frame_host->GetRoutingID(), id_.delegate_id));
}

void MediaSessionController::OnExitPictureInPicture(int player_id) {
  DCHECK_EQ(player_id_, player_id);
  id_.render_frame_host->Send(new MediaPlayerDelegateMsg_ExitPictureInPicture(
      id_.render_frame_host->GetRoutingID(), id_.delegate_id));
}

void MediaSessionController::OnSetAudioSinkId(
    int player_id,
    const std::string& raw_device_id) {
  // The sink id needs to be hashed before it is suitable for use in the
  // renderer process.
  auto salt_and_origin = content::GetMediaDeviceSaltAndOrigin(
      id_.render_frame_host->GetProcess()->GetID(),
      id_.render_frame_host->GetRoutingID());

  std::string hashed_sink_id = GetHMACForMediaDeviceID(
      salt_and_origin.device_id_salt, salt_and_origin.origin, raw_device_id);

  // Grant the renderer the permission to use this audio output device.
  static_cast<RenderFrameHostImpl*>(id_.render_frame_host)
      ->SetAudioOutputDeviceIdForGlobalMediaControls(hashed_sink_id);

  id_.render_frame_host->Send(new MediaPlayerDelegateMsg_SetAudioSinkId(
      id_.render_frame_host->GetRoutingID(), id_.delegate_id, hashed_sink_id));
}

RenderFrameHost* MediaSessionController::render_frame_host() const {
  return id_.render_frame_host;
}

base::Optional<media_session::MediaPosition>
MediaSessionController::GetPosition(int player_id) const {
  DCHECK_EQ(player_id_, player_id);
  return position_;
}

bool MediaSessionController::IsPictureInPictureAvailable(int player_id) const {
  DCHECK_EQ(player_id_, player_id);
  return is_picture_in_picture_available_;
}

void MediaSessionController::OnPlaybackPaused(bool reached_end_of_stream) {
  is_paused_ = true;

  if (reached_end_of_stream) {
    is_playback_in_progress_ = false;
    AddOrRemovePlayer();
  }

  // We check for suspension here since the renderer may issue its own pause
  // in response to or while a pause from the browser is in flight.
  if (media_session_->IsActive())
    media_session_->OnPlayerPaused(this, player_id_);
}

void MediaSessionController::PictureInPictureStateChanged(
    bool is_picture_in_picture) {
  AddOrRemovePlayer();
}

void MediaSessionController::WebContentsMutedStateChanged(bool muted) {
  AddOrRemovePlayer();
}

void MediaSessionController::OnMediaPositionStateChanged(
    const media_session::MediaPosition& position) {
  position_ = position;
  media_session_->RebuildAndNotifyMediaPositionChanged();
}

void MediaSessionController::OnPictureInPictureAvailabilityChanged(
    bool available) {
  is_picture_in_picture_available_ = available;
  media_session_->OnPictureInPictureAvailabilityChanged();
}

void MediaSessionController::OnAudioOutputSinkChanged(
    const std::string& raw_device_id) {
  audio_output_sink_id_ = raw_device_id;
  media_session_->OnAudioOutputSinkIdChanged();
}

void MediaSessionController::OnAudioOutputSinkChangingDisabled() {
  supports_audio_output_device_switching_ = false;
  media_session_->OnAudioOutputSinkChangingDisabled();
}

bool MediaSessionController::IsMediaSessionNeeded() const {
  if (!is_playback_in_progress_)
    return false;

  // We want to make sure we do not request audio focus on a muted tab as it
  // would break user expectations by pausing/ducking other playbacks.
  const bool has_audio = has_audio_ && !web_contents_->IsAudioMuted();
  return has_audio || web_contents_->HasPictureInPictureVideo();
}

bool MediaSessionController::AddOrRemovePlayer() {
  const bool needs_session = IsMediaSessionNeeded();

  if (needs_session) {
    // Attempt to add a session even if we already have one.  MediaSession
    // expects AddPlayer() to be called after OnPlaybackPaused() to reactivate
    // the session.
    if (!media_session_->AddPlayer(this, player_id_, media_content_type_)) {
      // If a session can't be created, force a pause immediately.
      OnSuspend(player_id_);
      return false;
    }

    // Need to synchronise paused/playing state in case we're adding the player
    // because of entering Picture-In-Picture.
    if (is_paused_)
      media_session_->OnPlayerPaused(this, player_id_);

    return true;
  }

  media_session_->RemovePlayer(this, player_id_);
  return true;
}

bool MediaSessionController::HasVideo(int player_id) const {
  DCHECK_EQ(player_id_, player_id);
  return has_video_ && has_audio_;
}

std::string MediaSessionController::GetAudioOutputSinkId(int player_id) const {
  DCHECK_EQ(player_id_, player_id);
  return audio_output_sink_id_;
}

bool MediaSessionController::SupportsAudioOutputDeviceSwitching(
    int player_id) const {
  DCHECK_EQ(player_id_, player_id);
  return supports_audio_output_device_switching_;
}

}  // namespace content
