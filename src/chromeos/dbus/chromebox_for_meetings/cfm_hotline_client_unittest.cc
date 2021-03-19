// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/dbus/chromebox_for_meetings/cfm_hotline_client.h"

#include <algorithm>
#include <atomic>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/files/file.h"
#include "base/run_loop.h"
#include "base/test/bind_test_util.h"
#include "base/test/mock_callback.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "chromeos/components/chromebox_for_meetings/features/features.h"
#include "dbus/mock_bus.h"
#include "dbus/mock_object_proxy.h"
#include "dbus/object_path.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/cros_system_api/dbus/service_constants.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

namespace chromeos {

class CfmHotlineClientTest : public testing::Test {
 public:
  CfmHotlineClientTest() {
    scoped_feature_list_.InitAndEnableFeature(
        chromeos::cfm::features::kCfmMojoServices);
  }
  ~CfmHotlineClientTest() override = default;

  void SetUp() override {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;

    // Filter uninteresting calls to the bus
    mock_bus_ = base::MakeRefCounted<::testing::NiceMock<dbus::MockBus>>(
        dbus::Bus::Options());

    mock_proxy_ = base::MakeRefCounted<dbus::MockObjectProxy>(
        mock_bus_.get(), ::cfm::broker::kServiceName,
        dbus::ObjectPath(::cfm::broker::kServicePath));

    EXPECT_CALL(*mock_bus_.get(),
                GetObjectProxy(::cfm::broker::kServiceName,
                               dbus::ObjectPath(::cfm::broker::kServicePath)))
        .WillOnce(Return(mock_proxy_.get()));

    CfmHotlineClient::Initialize(mock_bus_.get());
    client_ = CfmHotlineClient::Get();

    // The easiest source of fds is opening /dev/null.
    test_file_ = base::File(base::FilePath("/dev/null"),
                            base::File::FLAG_OPEN | base::File::FLAG_WRITE);
    ASSERT_TRUE(test_file_.IsValid());

    base::RunLoop().RunUntilIdle();
  }

  void TearDown() override { CfmHotlineClient::Shutdown(); }

  void CallMethod(dbus::MethodCall* method_call,
                  int timeout_ms,
                  dbus::ObjectProxy::ResponseCallback* callback) {
    dbus::Response* response = nullptr;

    if (!responses_.empty()) {
      used_responses_.push_back(std::move(responses_.front()));
      responses_.pop_front();
      response = used_responses_.back().get();
    }

    task_environment_.GetMainThreadTaskRunner()->PostTask(
        FROM_HERE, base::BindOnce(std::move(*callback), response));
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_;
  CfmHotlineClient* client_;
  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> mock_proxy_;
  std::deque<std::unique_ptr<dbus::Response>> responses_;
  base::File test_file_;

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
  std::deque<std::unique_ptr<dbus::Response>> used_responses_;
};

TEST_F(CfmHotlineClientTest, BootstrapMojoSuccessTest) {
  responses_.push_back(dbus::Response::CreateEmpty());

  EXPECT_CALL(*mock_proxy_.get(), DoCallMethod(_, _, _))
      .WillOnce(Invoke(this, &CfmHotlineClientTest::CallMethod));

  base::MockCallback<CfmHotlineClient::BootstrapMojoConnectionCallback>
      callback;
  EXPECT_CALL(callback, Run(true)).Times(1);

  client_->BootstrapMojoConnection(
      base::ScopedFD(test_file_.TakePlatformFile()), callback.Get());

  base::RunLoop().RunUntilIdle();
}

TEST_F(CfmHotlineClientTest, BootstrapMojoFailureTest) {
  EXPECT_CALL(*mock_proxy_.get(), DoCallMethod(_, _, _))
      .WillOnce(Invoke(this, &CfmHotlineClientTest::CallMethod));

  base::MockCallback<CfmHotlineClient::BootstrapMojoConnectionCallback>
      callback;
  EXPECT_CALL(callback, Run(false)).Times(1);

  // Fail with no normal or error response
  client_->BootstrapMojoConnection(
      base::ScopedFD(test_file_.TakePlatformFile()), callback.Get());

  base::RunLoop().RunUntilIdle();
}

}  // namespace chromeos
