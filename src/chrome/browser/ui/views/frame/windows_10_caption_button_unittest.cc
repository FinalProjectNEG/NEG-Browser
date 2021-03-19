// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/frame/windows_10_caption_button.h"

#include "chrome/browser/ui/view_ids.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "ui/views/controls/button/button.h"
#include "ui/views/view.h"

TEST(Windows10CaptionButtonTest, CheckFocusBehavior) {
  Windows10CaptionButton button(views::Button::PressedCallback(), nullptr,
                                VIEW_ID_NONE, base::string16());
  EXPECT_EQ(views::View::FocusBehavior::ACCESSIBLE_ONLY,
            button.GetFocusBehavior());
}
