// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/in_session_auth/mock_in_session_auth_dialog_client.h"

#include "ash/in_session_auth/in_session_auth_dialog_controller_impl.h"
#include "ash/shell.h"

namespace ash {

MockInSessionAuthDialogClient::MockInSessionAuthDialogClient() {
  Shell::Get()->in_session_auth_dialog_controller()->SetClient(this);
}

MockInSessionAuthDialogClient::~MockInSessionAuthDialogClient() {
  Shell::Get()->in_session_auth_dialog_controller()->SetClient(nullptr);
}

}  // namespace ash
