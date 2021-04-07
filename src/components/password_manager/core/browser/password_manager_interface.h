// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PASSWORD_MANAGER_CORE_BROWSER_PASSWORD_MANAGER_INTERFACE_H_
#define COMPONENTS_PASSWORD_MANAGER_CORE_BROWSER_PASSWORD_MANAGER_INTERFACE_H_

#include <memory>
#include <string>
#include <vector>

#include "base/strings/string16.h"
#include "build/build_config.h"
#include "components/autofill/core/common/field_data_manager.h"
#include "components/autofill/core/common/form_data.h"
#include "components/autofill/core/common/renderer_id.h"
#include "components/password_manager/core/browser/form_submission_observer.h"
#include "components/password_manager/core/browser/password_manager_driver.h"

namespace password_manager {

// Abstract interface for PasswordManagers.
class PasswordManagerInterface : public FormSubmissionObserver {
 public:
  PasswordManagerInterface() = default;
  ~PasswordManagerInterface() override = default;

  PasswordManagerInterface(const PasswordManagerInterface&) = delete;
  PasswordManagerInterface& operator=(const PasswordManagerInterface&) = delete;

  // Handles password forms being parsed.
  virtual void OnPasswordFormsParsed(
      PasswordManagerDriver* driver,
      const std::vector<autofill::FormData>& forms_data) = 0;

  // Handles password forms being rendered.
  virtual void OnPasswordFormsRendered(
      PasswordManagerDriver* driver,
      const std::vector<autofill::FormData>& visible_forms_data,
      bool did_stop_loading) = 0;

  // Handles a password form being submitted.
  virtual void OnPasswordFormSubmitted(PasswordManagerDriver* driver,
                                       const autofill::FormData& form_data) = 0;

#if defined(OS_IOS)
  // Handles a password form being submitted, assumes that submission is
  // successful and does not do any checks on success of submission. For
  // example, this is called if |password_form| was filled upon in-page
  // navigation. This often means history.pushState being called from
  // JavaScript.
  virtual void OnPasswordFormSubmittedNoChecksForiOS(
      PasswordManagerDriver* driver,
      const autofill::FormData& form_data) = 0;

  // Presaves the form with |generated_password|. This function is called once
  // when the user accepts the generated password. The password was generated in
  // the field with identifier |generation_element|. |driver| corresponds to the
  // |form| parent frame.
  virtual void PresaveGeneratedPassword(
      PasswordManagerDriver* driver,
      const autofill::FormData& form,
      const base::string16& generated_password,
      autofill::FieldRendererId generation_element) = 0;

  // Updates the state if the PasswordFormManager which corresponds to the form
  // with |form_identifier|. In case if there is a presaved credential it
  // updates the presaved credential.
  virtual void UpdateStateOnUserInput(PasswordManagerDriver* driver,
                                      autofill::FormRendererId form_id,
                                      autofill::FieldRendererId field_id,
                                      const base::string16& field_value) = 0;

  // Stops treating a password as generated. |driver| corresponds to the
  // form parent frame.
  virtual void OnPasswordNoLongerGenerated(PasswordManagerDriver* driver) = 0;

  // Call when a form is removed so that this class can decide if whether or not
  // the form was submitted.
  virtual void OnPasswordFormRemoved(
      PasswordManagerDriver* driver,
      const autofill::FieldDataManager* field_data_manager,
      autofill::FormRendererId form_id) = 0;

  // Checks if there is a submitted PasswordFormManager for a form from the
  // detached frame.
  virtual void OnIframeDetach(
      const std::string& frame_id,
      PasswordManagerDriver* driver,
      const autofill::FieldDataManager* field_data_manager) = 0;
#endif
};

}  // namespace password_manager

#endif  // COMPONENTS_PASSWORD_MANAGER_CORE_BROWSER_PASSWORD_MANAGER_INTERFACE_H_
