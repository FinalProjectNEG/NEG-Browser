// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/system/phonehub/interstitial_view_button.h"

#include "ash/system/unified/rounded_label_button.h"
#include "ui/views/controls/button/label_button.h"

namespace ash {

InterstitialViewButton::InterstitialViewButton(views::ButtonListener* listener,
                                               const base::string16& text,
                                               bool paint_background)
    : RoundedLabelButton(listener, text), paint_background_(paint_background) {}

InterstitialViewButton::~InterstitialViewButton() = default;

void InterstitialViewButton::PaintButtonContents(gfx::Canvas* canvas) {
  if (!paint_background_) {
    views::LabelButton::PaintButtonContents(canvas);
    return;
  }

  RoundedLabelButton::PaintButtonContents(canvas);
}

BEGIN_METADATA(InterstitialViewButton, RoundedLabelButton)
END_METADATA

}  // namespace ash
