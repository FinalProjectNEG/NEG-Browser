// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_COMPONENTS_ACCOUNT_MANAGER_ACCOUNT_MANAGER_FACADE_H_
#define CHROMEOS_COMPONENTS_ACCOUNT_MANAGER_ACCOUNT_MANAGER_FACADE_H_

#include "base/component_export.h"

// An interface to talk to |AccountManager|.
// Implementations of this interface hide the in-process / out-of-process nature
// of this communication.
// Instances of this class are singletons, and are independent of a |Profile|.
// Use |GetAccountManagerFacade()| to get an instance of this class.
class COMPONENT_EXPORT(ACCOUNT_MANAGER) AccountManagerFacade {
 public:
  AccountManagerFacade();
  AccountManagerFacade(const AccountManagerFacade&) = delete;
  AccountManagerFacade& operator=(const AccountManagerFacade&) = delete;
  virtual ~AccountManagerFacade() = 0;

  // Returns |true| if |AccountManager| is connected and has been fully
  // initialized.
  // Note: For out-of-process implementations, it returns |false| if the IPC
  // pipe to |AccountManager| is disconnected.
  virtual bool IsInitialized() = 0;
};

#endif  // CHROMEOS_COMPONENTS_ACCOUNT_MANAGER_ACCOUNT_MANAGER_FACADE_H_
