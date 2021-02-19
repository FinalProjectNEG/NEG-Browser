// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/printing/print_management/printing_manager_factory.h"

#include "chrome/browser/chromeos/printing/print_management/printing_manager.h"
#include "chrome/browser/history/history_service_factory.h"
#include "chrome/common/chrome_constants.h"
#include "chrome/test/base/testing_profile.h"
#include "components/history/core/browser/history_service.h"
#include "content/public/test/browser_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace chromeos {
namespace printing {
namespace print_management {

std::unique_ptr<KeyedService> BuildTestHistoryService(
    content::BrowserContext* context) {
  return std::make_unique<history::HistoryService>();
}

std::unique_ptr<KeyedService> BuildPrintingManager(
    content::BrowserContext* context) {
  return std::unique_ptr<KeyedService>(
      PrintingManagerFactory::BuildInstanceFor(context));
}

std::unique_ptr<Profile> CreateProfile(std::string file_path) {
  TestingProfile::Builder builder;
  if (!file_path.empty()) {
    builder.SetPath(base::FilePath(FILE_PATH_LITERAL(file_path)));
  }
  std::unique_ptr<Profile> profile = builder.Build();

  HistoryServiceFactory::GetInstance()->SetTestingFactory(
      profile.get(), base::BindRepeating(&BuildTestHistoryService));
  PrintingManagerFactory::GetInstance()->SetTestingFactory(
      profile.get(), base::BindRepeating(&BuildPrintingManager));

  return profile;
}

TEST(PrintingManagerFactoryTest, OriginalProfileHasService) {
  content::BrowserTaskEnvironment task_environment;
  std::unique_ptr<Profile> profile = CreateProfile("");

  EXPECT_NE(nullptr, PrintingManagerFactory::GetForProfile(profile.get()));
}

TEST(PrintingManagerFactoryTest, OffTheRecordProfileHasService) {
  content::BrowserTaskEnvironment task_environment;
  std::unique_ptr<Profile> profile = CreateProfile("");

  EXPECT_NE(nullptr, PrintingManagerFactory::GetForProfile(
                         profile->GetPrimaryOTRProfile()));
}

TEST(PrintingManagerFactoryTest, SigninProfileNoService) {
  content::BrowserTaskEnvironment task_environment;
  std::unique_ptr<Profile> signin_profile =
      CreateProfile(chrome::kInitialProfile);

  EXPECT_EQ(nullptr,
            PrintingManagerFactory::GetForProfile(signin_profile.get()));
}

TEST(PrintingManagerFactoryTest, LockScreenProfileNoService) {
  content::BrowserTaskEnvironment task_environment;
  std::unique_ptr<Profile> lockscreen_profile =
      CreateProfile(chrome::kLockScreenAppProfile);

  EXPECT_EQ(nullptr,
            PrintingManagerFactory::GetForProfile(lockscreen_profile.get()));
}

}  // namespace print_management
}  // namespace printing
}  // namespace chromeos
