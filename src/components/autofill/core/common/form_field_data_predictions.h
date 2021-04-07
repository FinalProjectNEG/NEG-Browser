// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_AUTOFILL_CORE_COMMON_FORM_FIELD_DATA_PREDICTIONS_H_
#define COMPONENTS_AUTOFILL_CORE_COMMON_FORM_FIELD_DATA_PREDICTIONS_H_

#include <string>
#include <vector>

#include "components/autofill/core/common/form_field_data.h"

namespace autofill {

// Stores information about a field in a form.
struct FormFieldDataPredictions {
  FormFieldDataPredictions();
  FormFieldDataPredictions(const FormFieldDataPredictions&);
  FormFieldDataPredictions& operator=(const FormFieldDataPredictions&);
  FormFieldDataPredictions(FormFieldDataPredictions&&);
  FormFieldDataPredictions& operator=(FormFieldDataPredictions&&);
  ~FormFieldDataPredictions();

  std::string signature;
  std::string heuristic_type;
  std::string server_type;
  std::string overall_type;
  std::string parseable_name;
  std::string section;
};

}  // namespace autofill

#endif  // COMPONENTS_AUTOFILL_CORE_COMMON_FORM_FIELD_DATA_PREDICTIONS_H_
