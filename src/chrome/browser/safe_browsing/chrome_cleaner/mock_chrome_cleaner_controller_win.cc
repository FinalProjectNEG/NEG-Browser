// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/safe_browsing/chrome_cleaner/mock_chrome_cleaner_controller_win.h"

namespace safe_browsing {

MockChromeCleanerController::MockChromeCleanerController() = default;

MockChromeCleanerController::~MockChromeCleanerController() = default;

void MockChromeCleanerController::OnSwReporterReady(
    SwReporterInvocationSequence&& sequence) {
  MockedOnSwReporterReady(sequence);
}

}  // namespace safe_browsing
