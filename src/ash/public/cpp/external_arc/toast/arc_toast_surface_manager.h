// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_PUBLIC_CPP_EXTERNAL_ARC_TOAST_ARC_TOAST_SURFACE_MANAGER_H_
#define ASH_PUBLIC_CPP_EXTERNAL_ARC_TOAST_ARC_TOAST_SURFACE_MANAGER_H_

#include <vector>

#include "ash/public/cpp/ash_public_export.h"
#include "ash/public/cpp/session/session_controller.h"
#include "ash/public/cpp/session/session_observer.h"
#include "base/macros.h"
#include "base/scoped_observer.h"
#include "components/exo/toast_surface_manager.h"

namespace ash {

class ASH_PUBLIC_EXPORT ArcToastSurfaceManager
    : public exo::ToastSurfaceManager,
      public SessionObserver {
 public:
  ArcToastSurfaceManager();
  ~ArcToastSurfaceManager() override;

  // Disallow copy and assign.
  ArcToastSurfaceManager(const ArcToastSurfaceManager&) = delete;
  ArcToastSurfaceManager& operator=(const ArcToastSurfaceManager&) = delete;

  // exo::ToastSurfaceManager:
  void AddSurface(exo::ToastSurface* surface) override;
  void RemoveSurface(exo::ToastSurface* surface) override;

  // SessionObserver:
  void OnSessionStateChanged(session_manager::SessionState state) override;

 private:
  FRIEND_TEST_ALL_PREFIXES(ArcToastSurfaceManagerTest, AddRemoveSurface);

  void UpdateVisibility();

  std::vector<exo::ToastSurface*> toast_surfaces_;

  bool locked_;

  ScopedObserver<SessionController, SessionObserver> scoped_observer_{this};
};

}  // namespace ash

#endif  // ASH_PUBLIC_CPP_EXTERNAL_ARC_TOAST_ARC_TOAST_SURFACE_MANAGER_H_
