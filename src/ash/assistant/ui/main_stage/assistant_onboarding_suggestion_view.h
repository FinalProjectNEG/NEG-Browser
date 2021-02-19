// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_ASSISTANT_UI_MAIN_STAGE_ASSISTANT_ONBOARDING_SUGGESTION_VIEW_H_
#define ASH_ASSISTANT_UI_MAIN_STAGE_ASSISTANT_ONBOARDING_SUGGESTION_VIEW_H_

#include "base/component_export.h"
#include "base/unguessable_token.h"
#include "ui/views/controls/button/button.h"

namespace chromeos {
namespace assistant {
struct AssistantSuggestion;
}  // namespace assistant
}  // namespace chromeos

namespace views {
class ImageView;
class InkDropContainerView;
class Label;
}  // namespace views

namespace ash {

class AssistantViewDelegate;

class COMPONENT_EXPORT(ASSISTANT_UI) AssistantOnboardingSuggestionView
    : public views::Button,
      public views::ButtonListener {
 public:
  static constexpr char kClassName[] = "AssistantOnboardingSuggestionView";

  AssistantOnboardingSuggestionView(
      AssistantViewDelegate* delegate,
      const chromeos::assistant::AssistantSuggestion& suggestion,
      int index);

  AssistantOnboardingSuggestionView(const AssistantOnboardingSuggestionView&) =
      delete;
  AssistantOnboardingSuggestionView& operator=(
      const AssistantOnboardingSuggestionView&) = delete;
  ~AssistantOnboardingSuggestionView() override;

  // views::View:
  const char* GetClassName() const override;
  int GetHeightForWidth(int width) const override;
  void ChildPreferredSizeChanged(views::View* child) override;
  void AddLayerBeneathView(ui::Layer* layer) override;
  void RemoveLayerBeneathView(ui::Layer* layer) override;

  // views::ButtonListener:
  void ButtonPressed(views::Button* sender, const ui::Event& event) override;

  // Returns the icon for the suggestion.
  const gfx::ImageSkia& GetIcon() const;

  // Returns the text for the suggestion.
  const base::string16& GetText() const;

 private:
  void InitLayout(const chromeos::assistant::AssistantSuggestion& suggestion);
  void UpdateIcon(const gfx::ImageSkia& icon);

  AssistantViewDelegate* const delegate_;  // Owned by AssistantController.
  const base::UnguessableToken suggestion_id_;
  const int index_;

  // Owned by view hierarchy.
  views::ImageView* icon_ = nullptr;
  views::Label* label_ = nullptr;
  views::InkDropContainerView* ink_drop_container_ = nullptr;

  base::WeakPtrFactory<AssistantOnboardingSuggestionView> weak_factory_{this};
};

}  // namespace ash

#endif  // ASH_ASSISTANT_UI_MAIN_STAGE_ASSISTANT_ONBOARDING_SUGGESTION_VIEW_H_
