// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/download/android/download_manager_service.h"

#include "base/android/jni_android.h"
#include "base/android/jni_string.h"
#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/macros.h"
#include "base/run_loop.h"
#include "chrome/browser/profiles/profile_key_android.h"
#include "chrome/test/base/testing_profile.h"
#include "components/download/public/common/download_item.h"
#include "components/download/public/common/download_url_parameters.h"
#include "components/download/public/common/mock_download_item.h"
#include "components/download/public/common/simple_download_manager_coordinator.h"
#include "content/public/browser/download_manager.h"
#include "content/public/test/browser_task_environment.h"
#include "content/public/test/mock_download_manager.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/origin.h"

using ::testing::_;

class DownloadManagerServiceTest : public testing::Test {
 public:
  DownloadManagerServiceTest()
      : service_(new DownloadManagerService()),
        coordinator_(base::NullCallback(), false),
        finished_(false),
        success_(false) {
    ON_CALL(manager_, GetDownloadByGuid(_))
        .WillByDefault(::testing::Invoke(
            this, &DownloadManagerServiceTest::GetDownloadByGuid));
    coordinator_.SetSimpleDownloadManager(&manager_, false);
    service_->UpdateCoordinator(&coordinator_, profile_.GetProfileKey());
  }

  void OnResumptionDone(bool success) {
    finished_ = true;
    success_ = success;
  }

  void StartDownload(const std::string& download_guid) {
    JNIEnv* env = base::android::AttachCurrentThread();
    service_->set_resume_callback_for_testing(base::Bind(
        &DownloadManagerServiceTest::OnResumptionDone, base::Unretained(this)));
    ProfileKeyAndroid profile_key_android(profile_.GetProfileKey());

    service_->ResumeDownload(
        env, nullptr,
        JavaParamRef<jstring>(
            env,
            base::android::ConvertUTF8ToJavaString(env, download_guid).obj()),
        JavaParamRef<jobject>(env,
                              profile_key_android.GetJavaObject().Release()),
        false);
    EXPECT_FALSE(success_);
    service_->OnDownloadsInitialized(&coordinator_, false);
    while (!finished_)
      base::RunLoop().RunUntilIdle();
  }

  void CreateDownloadItem(bool can_resume) {
    download_.reset(new download::MockDownloadItem());
    ON_CALL(*download_, CanResume())
        .WillByDefault(::testing::Return(can_resume));
  }

 protected:
  download::DownloadItem* GetDownloadByGuid(const std::string&) {
    return download_.get();
  }

  content::BrowserTaskEnvironment task_environment_;
  DownloadManagerService* service_;
  download::SimpleDownloadManagerCoordinator coordinator_;
  std::unique_ptr<download::MockDownloadItem> download_;
  content::MockDownloadManager manager_;
  TestingProfile profile_;
  bool finished_;
  bool success_;

  DISALLOW_COPY_AND_ASSIGN(DownloadManagerServiceTest);
};

// Test that resumption succeeds if the download item is found and can be
// resumed.
TEST_F(DownloadManagerServiceTest, ResumptionWithResumableItem) {
  CreateDownloadItem(true);
  StartDownload("0000");
  EXPECT_TRUE(success_);
}

// Test that resumption fails if the target download item is not resumable.
TEST_F(DownloadManagerServiceTest, ResumptionWithNonResumableItem) {
  CreateDownloadItem(false);
  StartDownload("0000");
  EXPECT_FALSE(success_);
}
