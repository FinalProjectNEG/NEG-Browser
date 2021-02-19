// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_SYSTEM_MEDIA_UNIFIED_MEDIA_CONTROLS_CONTROLLER_H_
#define ASH_SYSTEM_MEDIA_UNIFIED_MEDIA_CONTROLS_CONTROLLER_H_

#include "ash/ash_export.h"
#include "base/containers/flat_set.h"
#include "base/timer/timer.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/media_session/public/mojom/media_controller.mojom.h"

namespace views {
class View;
}  // namespace views

namespace ash {

class UnifiedMediaControlsView;

// Controller class of UnifiedMediaControlsView. Handles events of the view
// and updates the view when receives media session updates.
class ASH_EXPORT UnifiedMediaControlsController
    : public media_session::mojom::MediaControllerObserver,
      public media_session::mojom::MediaControllerImageObserver {
 public:
  class Delegate {
   public:
    virtual ~Delegate() = default;
    virtual void ShowMediaControls() = 0;
    virtual void OnMediaControlsViewClicked() = 0;
  };

  explicit UnifiedMediaControlsController(Delegate* deleate);
  ~UnifiedMediaControlsController() override;

  // media_session::mojom::MediaControllerObserver implementations.
  void MediaSessionInfoChanged(
      media_session::mojom::MediaSessionInfoPtr session_info) override;
  void MediaSessionMetadataChanged(
      const base::Optional<media_session::MediaMetadata>& metadata) override;
  void MediaSessionActionsChanged(
      const std::vector<media_session::mojom::MediaSessionAction>& actions)
      override;
  void MediaSessionChanged(
      const base::Optional<base::UnguessableToken>& request_id) override;
  void MediaSessionPositionChanged(
      const base::Optional<media_session::MediaPosition>& position) override {}

  // media_session::mojom::MediaControllerImageObserver implementations.
  void MediaControllerImageChanged(
      media_session::mojom::MediaSessionImageType type,
      const SkBitmap& bitmap) override;

  views::View* CreateView();

  void OnMediaControlsViewClicked();

  // Called from view when media buttons are pressed.
  void PerformAction(media_session::mojom::MediaSessionAction action);

  void FlushForTesting();

  void set_media_controller_for_testing(
      mojo::Remote<media_session::mojom::MediaController> controller) {
    media_controller_remote_ = std::move(controller);
  }

 private:
  // Update view with pending data if necessary. Called when
  // |freeze_session_timer| is fired.
  void UpdateSession();

  // Update artwork in media controls view.
  void UpdateArtwork(const SkBitmap& bitmap, bool should_start_hide_timer);

  // Reset all pending data to empty.
  void ResetPendingData();

  // Weak ptr, owned by view hierarchy.
  UnifiedMediaControlsView* media_controls_ = nullptr;

  // Delegate for show/hide media controls.
  Delegate* const delegate_ = nullptr;

  mojo::Remote<media_session::mojom::MediaController> media_controller_remote_;

  mojo::Receiver<media_session::mojom::MediaControllerObserver>
      observer_receiver_{this};

  mojo::Receiver<media_session::mojom::MediaControllerImageObserver>
      artwork_observer_receiver_{this};

  std::unique_ptr<base::OneShotTimer> freeze_session_timer_ =
      std::make_unique<base::OneShotTimer>();

  std::unique_ptr<base::OneShotTimer> hide_artwork_timer_ =
      std::make_unique<base::OneShotTimer>();

  base::Optional<base::UnguessableToken> media_session_id_;

  base::flat_set<media_session::mojom::MediaSessionAction> enabled_actions_;

  // Pending data to update when |freeze_session_tmier_| fired.
  base::Optional<base::UnguessableToken> pending_session_id_;
  base::Optional<media_session::mojom::MediaPlaybackState>
      pending_playback_state_;
  base::Optional<media_session::MediaMetadata> pending_metadata_;
  base::Optional<base::flat_set<media_session::mojom::MediaSessionAction>>
      pending_enabled_actions_;
  base::Optional<SkBitmap> pending_artwork_;
};

}  // namespace ash

#endif  // ASH_SYSTEM_MEDIA_UNIFIED_MEDIA_CONTROLS_CONTROLLER_H_
