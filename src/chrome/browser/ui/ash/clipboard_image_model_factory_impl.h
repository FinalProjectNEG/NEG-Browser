// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_ASH_CLIPBOARD_IMAGE_MODEL_FACTORY_IMPL_H_
#define CHROME_BROWSER_UI_ASH_CLIPBOARD_IMAGE_MODEL_FACTORY_IMPL_H_

#include <string>

#include "ash/public/cpp/clipboard_image_model_factory.h"
#include "base/memory/weak_ptr.h"
#include "base/timer/timer.h"
#include "base/unguessable_token.h"
#include "chrome/browser/ui/ash/clipboard_image_model_request.h"

class Profile;

// Implements the singleton ClipboardImageModelFactory.
class ClipboardImageModelFactoryImpl : public ash::ClipboardImageModelFactory {
 public:
  explicit ClipboardImageModelFactoryImpl(Profile* primary_profile);
  ClipboardImageModelFactoryImpl(ClipboardImageModelFactoryImpl&) = delete;
  ClipboardImageModelFactoryImpl& operator=(ClipboardImageModelFactoryImpl&) =
      delete;
  ~ClipboardImageModelFactoryImpl() override;

 private:
  // ash::ClipboardImageModelFactory:
  void Render(const base::UnguessableToken& id,
              const std::string& html_markup,
              ImageModelCallback callback) override;
  void CancelRequest(const base::UnguessableToken& id) override;
  void Activate() override;
  void Deactivate() override;
  void OnShutdown() override;

  // Starts the first request in |pending_list_|.
  void StartNextRequest();

  // Called when |request_| has been idle for 2 minutes, to clean up resources.
  void OnRequestIdle();

  // The primary profile, used instead of the active profile to create the
  // WebContents that renders html.
  Profile* const primary_profile_;

  // Whether ClipboardImageModelFactoryImpl is activated. If not, requests are
  // queued until Activate().
  bool active_ = false;

  // Requests which are waiting to be run.
  std::list<ClipboardImageModelRequest::Params> pending_list_;

  // The active request. Expensive to keep in memory and expensive to create,
  // deleted OnRequestIdle.
  std::unique_ptr<ClipboardImageModelRequest> request_;

  // Timer used to clean up |request_| if it is not used for 2 minutes.
  base::DelayTimer idle_timer_;

  base::WeakPtrFactory<ClipboardImageModelFactoryImpl> weak_ptr_factory_{this};
};

#endif  // CHROME_BROWSER_UI_ASH_CLIPBOARD_IMAGE_MODEL_FACTORY_IMPL_H_
