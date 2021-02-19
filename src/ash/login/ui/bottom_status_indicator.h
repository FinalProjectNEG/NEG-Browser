// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_LOGIN_UI_BOTTOM_STATUS_INDICATOR_H_
#define ASH_LOGIN_UI_BOTTOM_STATUS_INDICATOR_H_

#include "ash/style/ash_color_provider.h"
#include "base/strings/string16.h"
#include "ui/accessibility/ax_enums.mojom.h"
#include "ui/views/controls/button/label_button.h"
#include "ui/views/view.h"

namespace gfx {
struct VectorIcon;
}

namespace ash {

class BottomStatusIndicator : public views::LabelButton,
                              public views::ButtonListener {
 public:
  using TappedCallback = base::RepeatingClosure;

  BottomStatusIndicator(TappedCallback on_tapped_callback);
  BottomStatusIndicator(const BottomStatusIndicator&) = delete;
  BottomStatusIndicator& operator=(const BottomStatusIndicator&) = delete;
  ~BottomStatusIndicator() override;

  void SetIcon(const gfx::VectorIcon& vector_icon,
               AshColorProvider::ContentLayerType type);

  void set_role_for_accessibility(ax::mojom::Role role) { role_ = role; }

  // views::ButtonListener:
  void ButtonPressed(views::Button* sender, const ui::Event& event) override;

  // views::View:
  void GetAccessibleNodeData(ui::AXNodeData* node_data) override;

 private:
  TappedCallback on_tapped_callback_;
  ax::mojom::Role role_ = ax::mojom::Role::kStaticText;
};

}  // namespace ash
#endif  // ASH_LOGIN_UI_BOTTOM_STATUS_INDICATOR_H_
