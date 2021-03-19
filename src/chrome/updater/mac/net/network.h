// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_UPDATER_MAC_NET_NETWORK_H_
#define CHROME_UPDATER_MAC_NET_NETWORK_H_

#include <memory>

#include "base/threading/thread_checker.h"
#include "components/update_client/network.h"

namespace updater {

class NetworkFetcherFactory : public update_client::NetworkFetcherFactory {
 public:
  NetworkFetcherFactory();
  NetworkFetcherFactory(const NetworkFetcherFactory&) = delete;
  NetworkFetcherFactory& operator=(const NetworkFetcherFactory&) = delete;

  std::unique_ptr<update_client::NetworkFetcher> Create() const override;

 protected:
  ~NetworkFetcherFactory() override;

 private:
  THREAD_CHECKER(thread_checker_);
};

}  // namespace updater

#endif  // CHROME_UPDATER_MAC_NET_NETWORK_H_
