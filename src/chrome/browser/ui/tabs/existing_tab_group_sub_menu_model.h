// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_TABS_EXISTING_TAB_GROUP_SUB_MENU_MODEL_H_
#define CHROME_BROWSER_UI_TABS_EXISTING_TAB_GROUP_SUB_MENU_MODEL_H_

#include <stddef.h>

#include "chrome/browser/ui/tabs/existing_base_sub_menu_model.h"

class TabStripModel;

namespace tab_groups {
class TabGroupId;
}

class ExistingTabGroupSubMenuModel : public ExistingBaseSubMenuModel {
 public:
  ExistingTabGroupSubMenuModel(ui::SimpleMenuModel::Delegate* parent_delegate,
                               TabStripModel* model,
                               int context_index);
  ExistingTabGroupSubMenuModel(const ExistingTabGroupSubMenuModel&) = delete;
  ExistingTabGroupSubMenuModel& operator=(const ExistingTabGroupSubMenuModel&) =
      delete;
  ~ExistingTabGroupSubMenuModel() override = default;

  // Whether the submenu should be shown in the provided context. True iff
  // the submenu would show at least one group. Does not assume ownership of
  // |model|; |model| must outlive this instance.
  static bool ShouldShowSubmenu(TabStripModel* model, int context_index);

 private:
  // ExistingBaseSubMenuModel
  void ExecuteNewCommand(int event_flags) override;
  void ExecuteExistingCommand(int command_index) override;

  // Returns the group ids that appear in the submenu in the order that they
  // appear in the tab strip model, so that the user sees an ordered display.
  // Only needed for creating items and executing commands, which must be in
  // order. Otherwise, ListTabGroups() is cheaper and sufficient for determining
  // visibility and size of the menu.
  std::vector<tab_groups::TabGroupId> GetOrderedTabGroupsInSubMenu();

  // Whether the submenu should contain the group |group|. True iff at least
  // one tab that would be affected by the command is not in |group|.
  static bool ShouldShowGroup(TabStripModel* model,
                              int context_index,
                              tab_groups::TabGroupId group);
};

#endif  // CHROME_BROWSER_UI_TABS_EXISTING_TAB_GROUP_SUB_MENU_MODEL_H_
