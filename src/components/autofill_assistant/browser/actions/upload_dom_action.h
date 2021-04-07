// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_AUTOFILL_ASSISTANT_BROWSER_ACTIONS_UPLOAD_DOM_ACTION_H_
#define COMPONENTS_AUTOFILL_ASSISTANT_BROWSER_ACTIONS_UPLOAD_DOM_ACTION_H_

#include <string>

#include "base/callback.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "components/autofill_assistant/browser/actions/action.h"

namespace autofill_assistant {

class UploadDomAction : public Action {
 public:
  explicit UploadDomAction(ActionDelegate* delegate, const ActionProto& proto);
  ~UploadDomAction() override;

 private:
  // Overrides Action:
  void InternalProcessAction(ProcessActionCallback callback) override;

  void OnWaitForElement(const Selector& selector,
                        const ClientStatus& element_status);
  void OnGetOuterHtml(const ClientStatus& status,
                      const std::string& outer_html);
  void EndAction(const ClientStatus& status);

  ProcessActionCallback process_action_callback_;
  base::WeakPtrFactory<UploadDomAction> weak_ptr_factory_{this};

  DISALLOW_COPY_AND_ASSIGN(UploadDomAction);
};

}  // namespace autofill_assistant
#endif  // COMPONENTS_AUTOFILL_ASSISTANT_BROWSER_ACTIONS_UPLOAD_DOM_ACTION_H_
