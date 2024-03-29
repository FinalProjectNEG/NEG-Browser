// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/phonehub/browser_tabs_model_provider_impl.h"

#include "chromeos/components/multidevice/remote_device_test_util.h"
#include "chromeos/components/phonehub/fake_browser_tabs_metadata_fetcher.h"
#include "chromeos/components/phonehub/mutable_phone_model.h"
#include "chromeos/components/phonehub/phone_model_test_util.h"
#include "chromeos/services/multidevice_setup/public/cpp/fake_multidevice_setup_client.h"
#include "components/sync_sessions/open_tabs_ui_delegate.h"
#include "components/sync_sessions/session_sync_service.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace chromeos {
namespace phonehub {

using testing::_;
using testing::Return;

namespace {

const char kPhoneNameOne[] = "Pixel";
const char kPhoneNameTwo[] = "Galaxy";

class SessionSyncServiceMock : public sync_sessions::SessionSyncService {
 public:
  SessionSyncServiceMock() {}
  ~SessionSyncServiceMock() override {}

  MOCK_CONST_METHOD0(GetGlobalIdMapper, syncer::GlobalIdMapper*());
  MOCK_METHOD0(GetOpenTabsUIDelegate, sync_sessions::OpenTabsUIDelegate*());
  MOCK_METHOD1(SubscribeToForeignSessionsChanged,
               std::unique_ptr<base::CallbackList<void()>::Subscription>(
                   const base::RepeatingClosure& cb));
  MOCK_METHOD0(ScheduleGarbageCollection, void());
  MOCK_METHOD0(GetControllerDelegate,
               base::WeakPtr<syncer::ModelTypeControllerDelegate>());
  MOCK_METHOD1(ProxyTabsStateChanged,
               void(syncer::DataTypeController::State state));
  MOCK_METHOD1(SetSyncSessionsGUID, void(const std::string& guid));
};

class OpenTabsUIDelegateMock : public sync_sessions::OpenTabsUIDelegate {
 public:
  OpenTabsUIDelegateMock() {}
  ~OpenTabsUIDelegateMock() override {}

  MOCK_METHOD1(
      GetAllForeignSessions,
      bool(std::vector<const sync_sessions::SyncedSession*>* sessions));
  MOCK_METHOD3(GetForeignTab,
               bool(const std::string& tag,
                    const SessionID tab_id,
                    const sessions::SessionTab** tab));
  MOCK_METHOD1(DeleteForeignSession, void(const std::string& tag));
  MOCK_METHOD2(GetForeignSession,
               bool(const std::string& tag,
                    std::vector<const sessions::SessionWindow*>* windows));
  MOCK_METHOD2(GetForeignSessionTabs,
               bool(const std::string& tag,
                    std::vector<const sessions::SessionTab*>* tabs));
  MOCK_METHOD1(GetLocalSession,
               bool(const sync_sessions::SyncedSession** local));
};

multidevice::RemoteDeviceRef CreatePhoneDevice(const std::string& pii_name) {
  multidevice::RemoteDeviceRefBuilder builder;
  builder.SetPiiFreeName(pii_name);
  return builder.Build();
}

sync_sessions::SyncedSession* CreateNewSession(
    const std::string& session_name,
    const base::Time& session_time = base::Time::FromDoubleT(0)) {
  sync_sessions::SyncedSession* session = new sync_sessions::SyncedSession();
  session->session_name = session_name;
  session->modified_time = session_time;
  return session;
}

}  // namespace

class BrowserTabsModelProviderImplTest
    : public testing::Test,
      public BrowserTabsModelProvider::Observer {
 public:
  BrowserTabsModelProviderImplTest() = default;

  BrowserTabsModelProviderImplTest(const BrowserTabsModelProviderImplTest&) =
      delete;
  BrowserTabsModelProviderImplTest& operator=(
      const BrowserTabsModelProviderImplTest&) = delete;
  ~BrowserTabsModelProviderImplTest() override = default;

  void OnBrowserTabsUpdated(
      bool is_sync_enabled,
      const std::vector<BrowserTabsModel::BrowserTabMetadata>&
          browser_tabs_metadata) override {
    phone_model_.SetBrowserTabsModel(BrowserTabsModel(
        /*is_tab_sync_enabled=*/is_sync_enabled, browser_tabs_metadata));
  }

  // testing::Test:
  void SetUp() override {
    ON_CALL(mock_session_sync_service_, GetOpenTabsUIDelegate())
        .WillByDefault(Invoke(
            this, &BrowserTabsModelProviderImplTest::open_tabs_ui_delegate));

    ON_CALL(open_tabs_ui_delegate_, GetAllForeignSessions(_))
        .WillByDefault(Invoke(
            this,
            &BrowserTabsModelProviderImplTest::MockGetAllForeignSessions));

    ON_CALL(mock_session_sync_service_, SubscribeToForeignSessionsChanged(_))
        .WillByDefault(Invoke(this, &BrowserTabsModelProviderImplTest::
                                        MockSubscribeToForeignSessionsChanged));

    provider_ = std::make_unique<BrowserTabsModelProviderImpl>(
        &fake_multidevice_setup_client_, &mock_session_sync_service_,
        std::make_unique<FakeBrowserTabsMetadataFetcher>());
    provider_->AddObserver(this);
  }

  void SetPiiFreeName(const std::string& pii_free_name) {
    fake_multidevice_setup_client_.SetHostStatusWithDevice(std::make_pair(
        multidevice_setup::mojom::HostStatus::kEligibleHostExistsButNoHostSet,
        CreatePhoneDevice(/*pii_name=*/pii_free_name)));
  }

  std::unique_ptr<base::CallbackList<void()>::Subscription>
  MockSubscribeToForeignSessionsChanged(const base::RepeatingClosure& cb) {
    foreign_sessions_changed_callback_ = std::move(cb);
    return nullptr;
  }

  bool MockGetAllForeignSessions(
      std::vector<const sync_sessions::SyncedSession*>* sessions) {
    if (sessions_) {
      *sessions = *sessions_;
      return !sessions->empty();
    }
    return false;
  }

  testing::NiceMock<OpenTabsUIDelegateMock>* open_tabs_ui_delegate() {
    return enable_tab_sync_ ? &open_tabs_ui_delegate_ : nullptr;
  }

  void NotifySubscription() { foreign_sessions_changed_callback_.Run(); }

  void set_synced_sessions(
      std::vector<const sync_sessions::SyncedSession*>* sessions) {
    sessions_ = sessions;
  }

  void set_enable_tab_sync(bool is_enabled) { enable_tab_sync_ = is_enabled; }

  FakeBrowserTabsMetadataFetcher* fake_browser_tabs_metadata_fetcher() {
    return static_cast<FakeBrowserTabsMetadataFetcher*>(
        provider_->browser_tabs_metadata_fetcher_.get());
  }

  MutablePhoneModel phone_model_;
  multidevice_setup::FakeMultiDeviceSetupClient fake_multidevice_setup_client_;
  testing::NiceMock<SessionSyncServiceMock> mock_session_sync_service_;
  std::unique_ptr<BrowserTabsModelProviderImpl> provider_;

  testing::NiceMock<OpenTabsUIDelegateMock> open_tabs_ui_delegate_;

  bool enable_tab_sync_ = true;
  std::vector<const sync_sessions::SyncedSession*>* sessions_ = nullptr;
  base::RepeatingClosure foreign_sessions_changed_callback_;
};

TEST_F(BrowserTabsModelProviderImplTest, AttemptBrowserTabsModelUpdate) {
  // Test no Pii Free name despite sync being enabled.
  set_enable_tab_sync(true);
  set_synced_sessions(nullptr);
  NotifySubscription();
  EXPECT_FALSE(phone_model_.browser_tabs_model()->is_tab_sync_enabled());
  EXPECT_TRUE(phone_model_.browser_tabs_model()->most_recent_tabs().empty());
  EXPECT_FALSE(
      fake_browser_tabs_metadata_fetcher()->DoesPendingCallbackExist());

  // Set name of phone. Tests that OnHostStatusChanged causes name change.
  SetPiiFreeName(kPhoneNameOne);

  // Test disabling tab sync with no browser tab metadata.
  set_enable_tab_sync(false);
  set_synced_sessions(nullptr);
  NotifySubscription();
  EXPECT_FALSE(phone_model_.browser_tabs_model()->is_tab_sync_enabled());
  EXPECT_TRUE(phone_model_.browser_tabs_model()->most_recent_tabs().empty());
  EXPECT_FALSE(
      fake_browser_tabs_metadata_fetcher()->DoesPendingCallbackExist());

  // Test enabling tab sync with no browser tab metadata.
  set_enable_tab_sync(true);
  set_synced_sessions(nullptr);
  NotifySubscription();
  EXPECT_TRUE(phone_model_.browser_tabs_model()->is_tab_sync_enabled());
  EXPECT_TRUE(phone_model_.browser_tabs_model()->most_recent_tabs().empty());
  EXPECT_FALSE(
      fake_browser_tabs_metadata_fetcher()->DoesPendingCallbackExist());

  // Test enabling tab sync with no matching pii name with session_name.
  std::vector<const sync_sessions::SyncedSession*> sessions;
  sync_sessions::SyncedSession* session = CreateNewSession(kPhoneNameTwo);
  sessions.emplace_back(session);
  set_enable_tab_sync(true);
  set_synced_sessions(&sessions);
  NotifySubscription();
  EXPECT_TRUE(phone_model_.browser_tabs_model()->is_tab_sync_enabled());
  EXPECT_TRUE(phone_model_.browser_tabs_model()->most_recent_tabs().empty());
  EXPECT_FALSE(
      fake_browser_tabs_metadata_fetcher()->DoesPendingCallbackExist());

  // Test enabling tab sync with matching pii name with session_name, which
  // will cause the |fake_browser_tabs_metadata_fetcher()| to have a pending
  // callback.
  sync_sessions::SyncedSession* new_session = CreateNewSession(kPhoneNameOne);
  sessions.emplace_back(new_session);
  set_enable_tab_sync(true);
  set_synced_sessions(&sessions);
  NotifySubscription();
  EXPECT_TRUE(phone_model_.browser_tabs_model()->is_tab_sync_enabled());
  EXPECT_TRUE(phone_model_.browser_tabs_model()->most_recent_tabs().empty());
  EXPECT_TRUE(fake_browser_tabs_metadata_fetcher()->DoesPendingCallbackExist());

  // Test that once |fake_browser_tabs_metadata_fetcher()| responds, the phone
  // model will be appropriately updated.
  std::vector<BrowserTabsModel::BrowserTabMetadata> metadata;
  metadata.push_back(CreateFakeBrowserTabMetadata());
  fake_browser_tabs_metadata_fetcher()->RespondToCurrentFetchAttempt(
      std::move(metadata));
  EXPECT_EQ(phone_model_.browser_tabs_model()->most_recent_tabs().size(), 1U);
}

TEST_F(BrowserTabsModelProviderImplTest, ClearTabMetadataDuringMetadataFetch) {
  SetPiiFreeName(kPhoneNameOne);
  sync_sessions::SyncedSession* new_session = CreateNewSession(kPhoneNameOne);
  std::vector<const sync_sessions::SyncedSession*> sessions({new_session});

  set_enable_tab_sync(true);
  set_synced_sessions(&sessions);
  NotifySubscription();
  EXPECT_TRUE(fake_browser_tabs_metadata_fetcher()->DoesPendingCallbackExist());

  // Set to no synced sessions. Tab sync is still enabled.
  set_synced_sessions(nullptr);
  NotifySubscription();

  // Test that if the Browser tab metadata is cleared while a browser tab
  // metadata fetch is in progress, the in progress callback will be cancelled.
  std::vector<BrowserTabsModel::BrowserTabMetadata> metadata;
  metadata.push_back(CreateFakeBrowserTabMetadata());
  fake_browser_tabs_metadata_fetcher()->RespondToCurrentFetchAttempt(
      std::move(metadata));
  EXPECT_TRUE(phone_model_.browser_tabs_model()->most_recent_tabs().empty());
}

TEST_F(BrowserTabsModelProviderImplTest, SessionCorrectlySelected) {
  SetPiiFreeName(kPhoneNameOne);
  sync_sessions::SyncedSession* session_a =
      CreateNewSession(kPhoneNameOne, base::Time::FromDoubleT(1));
  sync_sessions::SyncedSession* session_b =
      CreateNewSession(kPhoneNameOne, base::Time::FromDoubleT(3));
  sync_sessions::SyncedSession* session_c =
      CreateNewSession(kPhoneNameOne, base::Time::FromDoubleT(2));
  sync_sessions::SyncedSession* session_d =
      CreateNewSession(kPhoneNameTwo, base::Time::FromDoubleT(10));

  std::vector<const sync_sessions::SyncedSession*> sessions(
      {session_a, session_b, session_c, session_d});

  set_enable_tab_sync(true);
  set_synced_sessions(&sessions);
  NotifySubscription();
  EXPECT_TRUE(fake_browser_tabs_metadata_fetcher()->DoesPendingCallbackExist());

  // |session_b| should be the selected session because it is the has the same
  // session_name as the set phone name and the latest modified time.
  EXPECT_EQ(fake_browser_tabs_metadata_fetcher()->GetSession(), session_b);
}

}  // namespace phonehub
}  // namespace chromeos
