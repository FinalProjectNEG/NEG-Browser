// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/translate/core/browser/translate_metrics_logger_impl.h"

#include "components/translate/core/browser/translate_manager.h"

namespace translate {

TranslateMetricsLoggerImpl::TranslateMetricsLoggerImpl(
    base::WeakPtr<TranslateManager> translate_manager)
    : translate_manager_(translate_manager) {}

TranslateMetricsLoggerImpl::~TranslateMetricsLoggerImpl() = default;

void TranslateMetricsLoggerImpl::OnPageLoadStart(bool is_foreground) {
  if (translate_manager_)
    translate_manager_->RegisterTranslateMetricsLogger(
        weak_method_factory_.GetWeakPtr());

  is_foreground_ = is_foreground;
}

void TranslateMetricsLoggerImpl::OnForegroundChange(bool is_foreground) {
  is_foreground_ = is_foreground;
}

void TranslateMetricsLoggerImpl::RecordMetrics(bool is_final) {
  // TODO(curranmax): Log UKM and UMA metrics now that the page load is.
  // completed. https://crbug.com/1114868.

  sequence_no_++;
}

}  // namespace translate
