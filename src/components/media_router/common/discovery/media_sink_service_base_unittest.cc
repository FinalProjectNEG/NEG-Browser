// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/media_router/common/discovery/media_sink_service_base.h"

#include "base/memory/ptr_util.h"
#include "base/test/mock_callback.h"
#include "base/timer/mock_timer.h"
#include "components/media_router/common/test/test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using ::testing::Return;

namespace {

media_router::DialSinkExtraData CreateDialSinkExtraData(
    const std::string& model_name,
    const std::string& ip_address,
    const std::string& app_url) {
  media_router::DialSinkExtraData dial_extra_data;
  EXPECT_TRUE(dial_extra_data.ip_address.AssignFromIPLiteral(ip_address));
  dial_extra_data.model_name = model_name;
  dial_extra_data.app_url = GURL(app_url);
  return dial_extra_data;
}

std::vector<media_router::MediaSinkInternal> CreateDialMediaSinks() {
  media_router::MediaSink sink1("sink1", "sink_name_1",
                                media_router::SinkIconType::CAST);
  media_router::DialSinkExtraData extra_data1 = CreateDialSinkExtraData(
      "model_name1", "192.168.1.1", "https://example1.com");

  media_router::MediaSink sink2("sink2", "sink_name_2",
                                media_router::SinkIconType::CAST);
  media_router::DialSinkExtraData extra_data2 = CreateDialSinkExtraData(
      "model_name2", "192.168.1.2", "https://example2.com");

  std::vector<media_router::MediaSinkInternal> sinks;
  sinks.push_back(media_router::MediaSinkInternal(sink1, extra_data1));
  sinks.push_back(media_router::MediaSinkInternal(sink2, extra_data2));
  return sinks;
}

}  // namespace

namespace media_router {

class MediaSinkServiceBaseTest : public ::testing::Test {
 public:
  MediaSinkServiceBaseTest()
      : media_sink_service_(mock_sink_discovered_cb_.Get()) {}
  ~MediaSinkServiceBaseTest() override {}

  void PopulateSinks(const std::vector<MediaSinkInternal>& old_sinks,
                     const std::vector<MediaSinkInternal>& new_sinks) {
    media_sink_service_.previous_sinks_.clear();
    for (const auto& old_sink : old_sinks)
      media_sink_service_.previous_sinks_.emplace(old_sink.sink().id(),
                                                  old_sink);

    media_sink_service_.sinks_.clear();
    for (const auto& new_sink : new_sinks)
      media_sink_service_.sinks_.emplace(new_sink.sink().id(), new_sink);
  }

  void TestOnDiscoveryComplete(
      const std::vector<MediaSinkInternal>& old_sinks,
      const std::vector<MediaSinkInternal>& new_sinks) {
    PopulateSinks(old_sinks, new_sinks);
    EXPECT_CALL(mock_sink_discovered_cb_, Run(new_sinks));
    media_sink_service_.OnDiscoveryComplete();
  }

 protected:
  base::MockCallback<OnSinksDiscoveredCallback> mock_sink_discovered_cb_;
  TestMediaSinkService media_sink_service_;

  DISALLOW_COPY_AND_ASSIGN(MediaSinkServiceBaseTest);
};

TEST_F(MediaSinkServiceBaseTest, TestOnDiscoveryComplete_SameSink) {
  std::vector<MediaSinkInternal> old_sinks;
  std::vector<MediaSinkInternal> new_sinks = CreateDialMediaSinks();
  TestOnDiscoveryComplete(old_sinks, new_sinks);

  // Same sink
  EXPECT_CALL(mock_sink_discovered_cb_, Run(new_sinks)).Times(0);
  media_sink_service_.OnDiscoveryComplete();
}

TEST_F(MediaSinkServiceBaseTest,
       TestOnDiscoveryComplete_SameSinkDifferentOrders) {
  std::vector<MediaSinkInternal> old_sinks = CreateDialMediaSinks();
  std::vector<MediaSinkInternal> new_sinks = CreateDialMediaSinks();
  std::reverse(new_sinks.begin(), new_sinks.end());

  PopulateSinks(old_sinks, new_sinks);
  EXPECT_CALL(mock_sink_discovered_cb_, Run(new_sinks)).Times(0);
  media_sink_service_.OnDiscoveryComplete();
}

TEST_F(MediaSinkServiceBaseTest, TestOnDiscoveryComplete_OneNewSink) {
  std::vector<MediaSinkInternal> old_sinks = CreateDialMediaSinks();
  std::vector<MediaSinkInternal> new_sinks = CreateDialMediaSinks();
  MediaSink sink3("sink3", "sink_name_3", SinkIconType::CAST);
  DialSinkExtraData extra_data3 = CreateDialSinkExtraData(
      "model_name3", "192.168.1.3", "https://example3.com");
  new_sinks.push_back(MediaSinkInternal(sink3, extra_data3));
  TestOnDiscoveryComplete(old_sinks, new_sinks);
}

TEST_F(MediaSinkServiceBaseTest, TestOnDiscoveryComplete_RemovedOneSink) {
  std::vector<MediaSinkInternal> old_sinks = CreateDialMediaSinks();
  std::vector<MediaSinkInternal> new_sinks = CreateDialMediaSinks();
  new_sinks.erase(new_sinks.begin());
  TestOnDiscoveryComplete(old_sinks, new_sinks);
}

TEST_F(MediaSinkServiceBaseTest, TestOnDiscoveryComplete_UpdatedOneSink) {
  std::vector<MediaSinkInternal> old_sinks = CreateDialMediaSinks();
  std::vector<MediaSinkInternal> new_sinks = CreateDialMediaSinks();
  new_sinks[0].sink().set_name("sink_name_4");
  TestOnDiscoveryComplete(old_sinks, new_sinks);
}

TEST_F(MediaSinkServiceBaseTest, TestOnDiscoveryComplete_Mixed) {
  std::vector<MediaSinkInternal> old_sinks = CreateDialMediaSinks();

  MediaSink sink1("sink1", "sink_name_1", SinkIconType::CAST);
  DialSinkExtraData extra_data2 = CreateDialSinkExtraData(
      "model_name2", "192.168.1.2", "https://example2.com");

  MediaSink sink3("sink3", "sink_name_3", SinkIconType::CAST);
  DialSinkExtraData extra_data3 = CreateDialSinkExtraData(
      "model_name3", "192.168.1.3", "https://example3.com");

  std::vector<MediaSinkInternal> new_sinks;
  new_sinks.push_back(MediaSinkInternal(sink1, extra_data2));
  new_sinks.push_back(MediaSinkInternal(sink3, extra_data3));

  TestOnDiscoveryComplete(old_sinks, new_sinks);
}

}  // namespace media_router
