// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/net/network_diagnostics/network_diagnostics_util.h"

#include <string>
#include <vector>

#include "base/strings/string_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace chromeos {
namespace network_diagnostics {

namespace {

const char kHttpsScheme[] = "https://";

}  // namespace

TEST(NetworkDiagnosticsUtilTest, TestGetRandomString) {
  int length = 8;
  auto random_string = util::GetRandomString(length);
  // Ensure that the length equals |length| and all characters are in between
  // 'a'-'z', inclusive.
  EXPECT_EQ(length, random_string.size());
  for (char const& c : random_string) {
    EXPECT_TRUE(c >= 'a' && c <= 'z');
  }
}

TEST(NetworkDiagnosticsUtilTest, TestGetRandomHosts) {
  int num_hosts = 10;
  int prefix_length = 8;
  std::vector<std::string> random_hosts =
      util::GetRandomHosts(num_hosts, prefix_length);
  // Ensure |random_hosts| has unique entries.
  std::sort(random_hosts.begin(), random_hosts.end());
  EXPECT_TRUE(std::adjacent_find(random_hosts.begin(), random_hosts.end()) ==
              random_hosts.end());
}

TEST(NetworkDiagnosticsUtilTest, TestGetRandomHostsWithScheme) {
  int num_hosts = 10;
  int prefix_length = 8;
  std::vector<std::string> random_hosts =
      util::GetRandomHostsWithScheme(num_hosts, prefix_length, kHttpsScheme);
  // Ensure |random_hosts| has unique entries.
  std::sort(random_hosts.begin(), random_hosts.end());
  EXPECT_TRUE(std::adjacent_find(random_hosts.begin(), random_hosts.end()) ==
              random_hosts.end());
  // Ensure hosts in |random_hosts| start with |kHttpsScheme|.
  for (const auto& host : random_hosts) {
    EXPECT_TRUE(host.rfind(kHttpsScheme, 0) == 0);
  }
}

TEST(NetworkDiagnosticsUtilTest,
     TestGetRandomHostsWithSchemeAndGenerate204Path) {
  int num_hosts = 10;
  int prefix_length = 8;
  std::vector<std::string> random_hosts =
      util::GetRandomHostsWithSchemeAndGenerate204Path(num_hosts, prefix_length,
                                                       kHttpsScheme);
  // Ensure |random_hosts| has unique entries.
  std::sort(random_hosts.begin(), random_hosts.end());
  EXPECT_TRUE(std::adjacent_find(random_hosts.begin(), random_hosts.end()) ==
              random_hosts.end());
  // Ensure:
  // (1) hosts in |random_hosts| start with |kHttpsScheme|.
  // (2) hosts in |random_hosts| end with |kGenerate204Path|.
  for (const auto& host : random_hosts) {
    EXPECT_TRUE(host.rfind(kHttpsScheme, 0) == 0);
    EXPECT_TRUE(base::EndsWith(host, util::kGenerate204Path));
  }
}

}  // namespace network_diagnostics
}  // namespace chromeos
