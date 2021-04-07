// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/components/phonehub/phone_model.h"

namespace chromeos {
namespace phonehub {

PhoneModel::PhoneModel() = default;

PhoneModel::~PhoneModel() = default;

void PhoneModel::AddObserver(Observer* observer) {
  observer_list_.AddObserver(observer);
}

void PhoneModel::RemoveObserver(Observer* observer) {
  observer_list_.RemoveObserver(observer);
}

void PhoneModel::NotifyModelChanged() {
  for (auto& observer : observer_list_)
    observer.OnModelChanged();
}

}  // namespace phonehub
}  // namespace chromeos
