// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/sync/driver/about_sync_util.h"

#include <string>
#include <utility>
#include <vector>

#include "base/i18n/time_formatting.h"
#include "base/notreached.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/values.h"
#include "components/sync/driver/sync_service.h"
#include "components/sync/driver/sync_token_status.h"
#include "components/sync/driver/sync_user_settings.h"
#include "components/sync/engine/cycle/sync_cycle_snapshot.h"
#include "components/sync/engine/sync_status.h"
#include "components/sync/engine/sync_string_conversions.h"
#include "components/sync/model/time.h"
#include "components/sync/protocol/proto_enum_conversions.h"
#include "url/gurl.h"

#if defined(OS_CHROMEOS)
#include "chromeos/constants/chromeos_features.h"
#endif

namespace syncer {

namespace sync_ui_util {

const char kIdentityTitle[] = "Identity";
const char kDetailsKey[] = "details";

// Resource paths.
const char kAboutJS[] = "about.js";
const char kChromeSyncJS[] = "chrome_sync.js";
const char kDataJS[] = "data.js";
const char kEventsJS[] = "events.js";
const char kSearchJS[] = "search.js";
const char kSyncIndexJS[] = "sync_index.js";
const char kSyncLogJS[] = "sync_log.js";
const char kSyncNodeBrowserJS[] = "sync_node_browser.js";
const char kSyncSearchJS[] = "sync_search.js";
const char kTypesJS[] = "types.js";
const char kUserEventsJS[] = "user_events.js";
const char kTrafficLogJS[] = "traffic_log.js";

// Message handlers.
const char kDispatchEvent[] = "chrome.sync.dispatchEvent";
const char kGetAllNodes[] = "getAllNodes";
const char kGetAllNodesCallback[] = "chrome.sync.getAllNodesCallback";
const char kRegisterForEvents[] = "registerForEvents";
const char kRegisterForPerTypeCounters[] = "registerForPerTypeCounters";
const char kRequestIncludeSpecificsInitialState[] =
    "requestIncludeSpecificsInitialState";
const char kRequestListOfTypes[] = "requestListOfTypes";
const char kRequestStart[] = "requestStart";
const char kRequestStopKeepData[] = "requestStopKeepData";
const char kRequestStopClearData[] = "requestStopClearData";
const char kRequestUpdatedAboutInfo[] = "requestUpdatedAboutInfo";
const char kRequestUserEventsVisibility[] = "requestUserEventsVisibility";
const char kSetIncludeSpecifics[] = "setIncludeSpecifics";
const char kTriggerRefresh[] = "triggerRefresh";
const char kUserEventsVisibilityCallback[] =
    "chrome.sync.userEventsVisibilityCallback";
const char kWriteUserEvent[] = "writeUserEvent";

// Other strings.
const char kCommit[] = "commit";
const char kCounters[] = "counters";
const char kCounterType[] = "counterType";
const char kIncludeSpecifics[] = "includeSpecifics";
const char kModelType[] = "modelType";
const char kOnAboutInfoUpdated[] = "onAboutInfoUpdated";
const char kOnCountersUpdated[] = "onCountersUpdated";
const char kOnProtocolEvent[] = "onProtocolEvent";
const char kOnReceivedIncludeSpecificsInitialState[] =
    "onReceivedIncludeSpecificsInitialState";
const char kOnReceivedListOfTypes[] = "onReceivedListOfTypes";
const char kStatus[] = "status";
const char kTypes[] = "types";
const char kUpdate[] = "update";

namespace {

const char kUninitialized[] = "Uninitialized";

// This class represents one field in about:sync. It gets serialized into a
// dictionary with entries for 'stat_name', 'stat_value' and 'is_valid'.
class StatBase {
 public:
  base::Value ToValue() const {
    base::Value result(base::Value::Type::DICTIONARY);
    result.SetKey("stat_name", base::Value(key_));
    result.SetKey("stat_value", value_.Clone());
    result.SetKey("is_valid", base::Value(is_valid_));
    return result;
  }

 protected:
  StatBase(const std::string& key, base::Value default_value)
      : key_(key), value_(std::move(default_value)) {}

  void SetFromValue(base::Value value) {
    value_ = std::move(value);
    is_valid_ = true;
  }

 private:
  std::string key_;
  base::Value value_;
  bool is_valid_ = false;
};

template <typename T>
class Stat : public StatBase {
 public:
  Stat(const std::string& key, const T& default_value)
      : StatBase(key, base::Value(default_value)) {}

  void Set(const T& value) { SetFromValue(base::Value(value)); }
};

// A section for display on about:sync, consisting of a title and a list of
// fields.
class Section {
 public:
  explicit Section(const std::string& title) : title_(title) {}

  void MarkSensitive() { is_sensitive_ = true; }

  Stat<bool>* AddBoolStat(const std::string& key) {
    return AddStat(key, false);
  }
  Stat<int>* AddIntStat(const std::string& key) { return AddStat(key, 0); }
  Stat<std::string>* AddStringStat(const std::string& key) {
    return AddStat(key, std::string(kUninitialized));
  }

  base::Value ToValue() const {
    base::Value result(base::Value::Type::DICTIONARY);
    result.SetKey("title", base::Value(title_));
    base::Value stats(base::Value::Type::LIST);
    for (const std::unique_ptr<StatBase>& stat : stats_)
      stats.Append(stat->ToValue());
    result.SetKey("data", std::move(stats));
    result.SetKey("is_sensitive", base::Value(is_sensitive_));
    return result;
  }

 private:
  template <typename T>
  Stat<T>* AddStat(const std::string& key, const T& default_value) {
    auto stat = std::make_unique<Stat<T>>(key, default_value);
    Stat<T>* result = stat.get();
    stats_.push_back(std::move(stat));
    return result;
  }

  std::string title_;
  std::vector<std::unique_ptr<StatBase>> stats_;
  bool is_sensitive_ = false;
};

class SectionList {
 public:
  SectionList() = default;

  Section* AddSection(const std::string& title) {
    sections_.push_back(std::make_unique<Section>(title));
    return sections_.back().get();
  }

  base::Value ToValue() const {
    base::Value result(base::Value::Type::LIST);
    for (const std::unique_ptr<Section>& section : sections_)
      result.Append(section->ToValue());
    return result;
  }

 private:
  std::vector<std::unique_ptr<Section>> sections_;
};

std::string GetDisableReasonsString(
    SyncService::DisableReasonSet disable_reasons) {
  if (disable_reasons.Empty()) {
    return "None";
  }
  std::vector<std::string> reason_strings;
  if (disable_reasons.Has(SyncService::DISABLE_REASON_PLATFORM_OVERRIDE))
    reason_strings.push_back("Platform override");
  if (disable_reasons.Has(SyncService::DISABLE_REASON_ENTERPRISE_POLICY))
    reason_strings.push_back("Enterprise policy");
  if (disable_reasons.Has(SyncService::DISABLE_REASON_NOT_SIGNED_IN))
    reason_strings.push_back("Not signed in");
  if (disable_reasons.Has(SyncService::DISABLE_REASON_USER_CHOICE))
    reason_strings.push_back("User choice");
  if (disable_reasons.Has(SyncService::DISABLE_REASON_UNRECOVERABLE_ERROR))
    reason_strings.push_back("Unrecoverable error");
  return base::JoinString(reason_strings, ", ");
}

std::string GetTransportStateString(syncer::SyncService::TransportState state) {
  switch (state) {
    case syncer::SyncService::TransportState::DISABLED:
      return "Disabled";
    case syncer::SyncService::TransportState::PAUSED:
      return "Paused";
    case syncer::SyncService::TransportState::START_DEFERRED:
      return "Start deferred";
    case syncer::SyncService::TransportState::INITIALIZING:
      return "Initializing";
    case syncer::SyncService::TransportState::PENDING_DESIRED_CONFIGURATION:
      return "Pending desired configuration";
    case syncer::SyncService::TransportState::CONFIGURING:
      return "Configuring data types";
    case syncer::SyncService::TransportState::ACTIVE:
      return "Active";
  }
  NOTREACHED();
  return std::string();
}

// Returns a string describing the chrome version environment. Version format:
// <Build Info> <OS> <Version number> (<Last change>)<channel or "-devel">
// If version information is unavailable, returns "invalid."
// TODO(zea): this approximately matches syncer::MakeUserAgentForSync in
// sync_util.h. Unify the two if possible.
std::string GetVersionString(version_info::Channel channel) {
  // Build a version string that matches syncer::MakeUserAgentForSync with the
  // addition of channel info and proper OS names.
  // chrome::GetChannelName() returns empty string for stable channel or
  // unofficial builds, the channel string otherwise. We want to have "-devel"
  // for unofficial builds only.
  std::string version_modifier = version_info::GetChannelString(channel);
  if (version_modifier.empty()) {
    if (channel != version_info::Channel::STABLE) {
      version_modifier = "-devel";
    }
  } else {
    version_modifier = " " + version_modifier;
  }
  return version_info::GetProductName() + " " + version_info::GetOSType() +
         " " + version_info::GetVersionNumber() + " (" +
         version_info::GetLastChange() + ")" + version_modifier;
}

std::string GetTimeStr(base::Time time, const std::string& default_msg) {
  if (time.is_null())
    return default_msg;
  return GetTimeDebugString(time);
}

// Analogous to GetTimeDebugString from components/sync/base/time.h. Consider
// moving it there if more places need this.
std::string GetTimeDeltaDebugString(base::TimeDelta t) {
  base::string16 result;
  if (!base::TimeDurationFormat(t, base::DURATION_WIDTH_WIDE, &result)) {
    return "Invalid TimeDelta?!";
  }
  return base::UTF16ToUTF8(result);
}

std::string GetLastSyncedTimeString(base::Time last_synced_time) {
  if (last_synced_time.is_null())
    return "Never";

  base::TimeDelta time_since_last_sync = base::Time::Now() - last_synced_time;

  if (time_since_last_sync < base::TimeDelta::FromMinutes(1))
    return "Just now";

  return GetTimeDeltaDebugString(time_since_last_sync) + " ago";
}

std::string GetConnectionStatus(const SyncTokenStatus& status) {
  switch (status.connection_status) {
    case CONNECTION_NOT_ATTEMPTED:
      return "not attempted";
    case CONNECTION_OK:
      return base::StringPrintf(
          "OK since %s",
          GetTimeStr(status.connection_status_update_time, "n/a").c_str());
    case CONNECTION_AUTH_ERROR:
      return base::StringPrintf(
          "auth error since %s",
          GetTimeStr(status.connection_status_update_time, "n/a").c_str());
    case CONNECTION_SERVER_ERROR:
      return base::StringPrintf(
          "server error since %s",
          GetTimeStr(status.connection_status_update_time, "n/a").c_str());
  }
  NOTREACHED();
  return std::string();
}

}  // namespace

// This function both defines the structure of the message to be returned and
// its contents.  Most of the message consists of simple fields in about:sync
// which are grouped into sections and populated with the help of the SyncStat
// classes defined above.
std::unique_ptr<base::DictionaryValue> ConstructAboutInformation(
    SyncService* service,
    version_info::Channel channel) {
  auto about_info = std::make_unique<base::DictionaryValue>();

  SectionList section_list;

  Section* section_summary = section_list.AddSection("Summary");
  Stat<std::string>* transport_state =
      section_summary->AddStringStat("Transport State");
  Stat<std::string>* disable_reasons =
      section_summary->AddStringStat("Disable Reasons");
#if defined(OS_CHROMEOS)
  Stat<std::string>* os_feature_state =
      section_summary->AddStringStat("Chrome OS Sync Feature");
#endif
  Stat<bool>* feature_enabled =
      section_summary->AddBoolStat("Sync Feature Enabled");
  Stat<bool>* setup_in_progress =
      section_summary->AddBoolStat("Setup In Progress");
  Stat<std::string>* auth_error = section_summary->AddStringStat("Auth Error");

  Section* section_version = section_list.AddSection("Version Info");
  Stat<std::string>* client_version =
      section_version->AddStringStat("Client Version");
  Stat<std::string>* server_url = section_version->AddStringStat("Server URL");

  Section* section_identity = section_list.AddSection(kIdentityTitle);
  section_identity->MarkSensitive();
  Stat<std::string>* sync_client_id =
      section_identity->AddStringStat("Sync Client ID");
  Stat<std::string>* invalidator_id =
      section_identity->AddStringStat("Invalidator Client ID");
  Stat<std::string>* username = section_identity->AddStringStat("Username");
  Stat<bool>* user_is_primary = section_identity->AddBoolStat("Is Primary");

  Section* section_credentials = section_list.AddSection("Credentials");
  Stat<std::string>* token_request_time =
      section_credentials->AddStringStat("Requested Token");
  Stat<std::string>* token_response_time =
      section_credentials->AddStringStat("Received Token Response");
  Stat<std::string>* last_token_request_result =
      section_credentials->AddStringStat("Last Token Request Result");
  Stat<bool>* has_token = section_credentials->AddBoolStat("Has Token");
  Stat<std::string>* next_token_request =
      section_credentials->AddStringStat("Next Token Request");

  Section* section_local = section_list.AddSection("Local State");
  Stat<std::string>* server_connection =
      section_local->AddStringStat("Server Connection");
  Stat<std::string>* last_synced = section_local->AddStringStat("Last Synced");
  Stat<bool>* is_setup_complete =
      section_local->AddBoolStat("Sync First-Time Setup Complete");
  Stat<bool>* is_syncing = section_local->AddBoolStat("Sync Cycle Ongoing");
  Stat<bool>* is_local_sync_enabled =
      section_local->AddBoolStat("Local Sync Backend Enabled");
  Stat<std::string>* local_backend_path =
      section_local->AddStringStat("Local Backend Path");

  Section* section_network = section_list.AddSection("Network");
  Stat<bool>* is_any_throttled_or_backoff =
      section_network->AddBoolStat("Throttled or Backoff");
  Stat<std::string>* retry_time = section_network->AddStringStat("Retry Time");
  Stat<bool>* are_notifications_enabled =
      section_network->AddBoolStat("Notifications Enabled");

  Section* section_encryption = section_list.AddSection("Encryption");
  Stat<bool>* is_using_explicit_passphrase =
      section_encryption->AddBoolStat("Explicit Passphrase");
  Stat<bool>* is_passphrase_required =
      section_encryption->AddBoolStat("Passphrase Required");
  Stat<bool>* cryptographer_can_encrypt =
      section_encryption->AddBoolStat("Cryptographer Ready To Encrypt");
  Stat<bool>* has_pending_keys =
      section_encryption->AddBoolStat("Cryptographer Has Pending Keys");
  Stat<std::string>* encrypted_types =
      section_encryption->AddStringStat("Encrypted Types");
  Stat<bool>* has_keystore_key =
      section_encryption->AddBoolStat("Has Keystore Key");
  Stat<std::string>* keystore_migration_time =
      section_encryption->AddStringStat("Keystore Migration Time");
  Stat<std::string>* passphrase_type =
      section_encryption->AddStringStat("Passphrase Type");
  Stat<std::string>* passphrase_time =
      section_encryption->AddStringStat("Passphrase Time");

  Section* section_last_session =
      section_list.AddSection("Status from Last Completed Session");
  Stat<std::string>* session_source =
      section_last_session->AddStringStat("Sync Source");
  Stat<std::string>* get_key_result =
      section_last_session->AddStringStat("GetKey Step Result");
  Stat<std::string>* download_result =
      section_last_session->AddStringStat("Download Step Result");
  Stat<std::string>* commit_result =
      section_last_session->AddStringStat("Commit Step Result");

  Section* section_counters = section_list.AddSection("Running Totals");
  Stat<int>* notifications_received =
      section_counters->AddIntStat("Notifications Received");
  Stat<int>* updates_received =
      section_counters->AddIntStat("Updates Downloaded");
  Stat<int>* tombstone_updates =
      section_counters->AddIntStat("Tombstone Updates");
  Stat<int>* reflected_updates =
      section_counters->AddIntStat("Reflected Updates");
  Stat<int>* successful_commits =
      section_counters->AddIntStat("Successful Commits");
  Stat<int>* conflicts_resolved_local_wins =
      section_counters->AddIntStat("Conflicts Resolved: Client Wins");
  Stat<int>* conflicts_resolved_server_wins =
      section_counters->AddIntStat("Conflicts Resolved: Server Wins");

  Section* section_this_cycle =
      section_list.AddSection("Transient Counters (this cycle)");
  Stat<int>* encryption_conflicts =
      section_this_cycle->AddIntStat("Encryption Conflicts");
  Stat<int>* hierarchy_conflicts =
      section_this_cycle->AddIntStat("Hierarchy Conflicts");
  Stat<int>* server_conflicts =
      section_this_cycle->AddIntStat("Server Conflicts");
  Stat<int>* committed_items =
      section_this_cycle->AddIntStat("Committed Items");

  Section* section_that_cycle = section_list.AddSection(
      "Transient Counters (last cycle of last completed session)");
  Stat<int>* updates_downloaded =
      section_that_cycle->AddIntStat("Updates Downloaded");
  Stat<int>* committed_count =
      section_that_cycle->AddIntStat("Committed Count");
  Stat<int>* entries = section_that_cycle->AddIntStat("Entries");

  // Populate all the fields we declared above.
  client_version->Set(GetVersionString(channel));

  if (!service) {
    transport_state->Set("Sync service does not exist");
    about_info->SetKey(kDetailsKey, section_list.ToValue());
    return about_info;
  }

  // Summary.
  transport_state->Set(GetTransportStateString(service->GetTransportState()));
  disable_reasons->Set(GetDisableReasonsString(service->GetDisableReasons()));
#if defined(OS_CHROMEOS)
  if (!chromeos::features::IsSplitSettingsSyncEnabled())
    os_feature_state->Set("Flag disabled");
  else if (service->GetUserSettings()->IsOsSyncFeatureEnabled())
    os_feature_state->Set("Enabled");
  else
    os_feature_state->Set("Disabled");
#endif  // defined(OS_CHROMEOS)
  feature_enabled->Set(service->IsSyncFeatureEnabled());
  setup_in_progress->Set(service->IsSetupInProgress());
  std::string auth_error_str = service->GetAuthError().ToString();
  auth_error->Set(base::StringPrintf(
      "%s since %s", (auth_error_str.empty() ? "OK" : auth_error_str).c_str(),
      GetTimeStr(service->GetAuthErrorTime(), "browser startup").c_str()));

  SyncStatus full_status;
  bool is_status_valid =
      service->QueryDetailedSyncStatusForDebugging(&full_status);
  const SyncCycleSnapshot& snapshot =
      service->GetLastCycleSnapshotForDebugging();
  const SyncTokenStatus& token_status =
      service->GetSyncTokenStatusForDebugging();
  bool is_local_sync_enabled_state = service->IsLocalSyncEnabled();

  // Version Info.
  // |client_version| was already set above.
  if (!is_local_sync_enabled_state)
    server_url->Set(service->GetSyncServiceUrlForDebugging().spec());

  // Identity.
  if (is_status_valid && !full_status.sync_id.empty())
    sync_client_id->Set(full_status.sync_id);
  if (is_status_valid && !full_status.invalidator_client_id.empty())
    invalidator_id->Set(full_status.invalidator_client_id);
  if (!is_local_sync_enabled_state) {
    username->Set(service->GetAuthenticatedAccountInfo().email);
    user_is_primary->Set(service->IsAuthenticatedAccountPrimary());
  }

  // Credentials.
  token_request_time->Set(GetTimeStr(token_status.token_request_time, "n/a"));
  token_response_time->Set(GetTimeStr(token_status.token_response_time, "n/a"));
  std::string err = token_status.last_get_token_error.error_message();
  last_token_request_result->Set(err.empty() ? "OK" : err);
  has_token->Set(token_status.has_token);
  next_token_request->Set(
      GetTimeStr(token_status.next_token_request_time, "not scheduled"));

  // Local State.
  server_connection->Set(GetConnectionStatus(token_status));
  last_synced->Set(
      GetLastSyncedTimeString(service->GetLastSyncedTimeForDebugging()));
  is_setup_complete->Set(service->GetUserSettings()->IsFirstSetupComplete());
  if (is_status_valid)
    is_syncing->Set(full_status.syncing);
  is_local_sync_enabled->Set(is_local_sync_enabled_state);
  if (is_local_sync_enabled_state && is_status_valid)
    local_backend_path->Set(full_status.local_sync_folder);

  // Network.
  if (snapshot.is_initialized())
    is_any_throttled_or_backoff->Set(snapshot.is_silenced());
  if (is_status_valid) {
    retry_time->Set(GetTimeStr(full_status.retry_time,
                               "Scheduler is not in backoff or throttled"));
  }
  if (is_status_valid)
    are_notifications_enabled->Set(full_status.notifications_enabled);

  // Encryption.
  if (service->IsSyncFeatureActive()) {
    is_using_explicit_passphrase->Set(
        service->GetUserSettings()->IsUsingSecondaryPassphrase());
    is_passphrase_required->Set(
        service->GetUserSettings()->IsPassphraseRequired());
    passphrase_time->Set(
        GetTimeStr(service->GetUserSettings()->GetExplicitPassphraseTime(),
                   "No Passphrase Time"));
  }
  if (is_status_valid) {
    cryptographer_can_encrypt->Set(full_status.cryptographer_can_encrypt);
    has_pending_keys->Set(full_status.crypto_has_pending_keys);
    encrypted_types->Set(ModelTypeSetToString(full_status.encrypted_types));
    has_keystore_key->Set(full_status.has_keystore_key);
    keystore_migration_time->Set(
        GetTimeStr(full_status.keystore_migration_time, "Not Migrated"));
    passphrase_type->Set(PassphraseTypeToString(full_status.passphrase_type));
  }

  // Status from Last Completed Session.
  if (snapshot.is_initialized()) {
    if (snapshot.get_updates_origin() != sync_pb::SyncEnums::UNKNOWN_ORIGIN) {
      session_source->Set(ProtoEnumToString(snapshot.get_updates_origin()));
    }
    get_key_result->Set(
        snapshot.model_neutral_state().last_get_key_result.ToString());
    download_result->Set(
        snapshot.model_neutral_state().last_download_updates_result.ToString());
    commit_result->Set(snapshot.model_neutral_state().commit_result.ToString());
  }

  // Running Totals.
  if (is_status_valid) {
    notifications_received->Set(full_status.notifications_received);
    updates_received->Set(full_status.updates_received);
    tombstone_updates->Set(full_status.tombstone_updates_received);
    reflected_updates->Set(full_status.reflected_updates_received);
    successful_commits->Set(full_status.num_commits_total);
    conflicts_resolved_local_wins->Set(full_status.num_local_overwrites_total);
    conflicts_resolved_server_wins->Set(
        full_status.num_server_overwrites_total);
  }

  // Transient Counters (this cycle).
  if (is_status_valid) {
    encryption_conflicts->Set(full_status.encryption_conflicts);
    hierarchy_conflicts->Set(full_status.hierarchy_conflicts);
    server_conflicts->Set(full_status.server_conflicts);
    committed_items->Set(full_status.committed_count);
  }

  // Transient Counters (last cycle of last completed session).
  if (snapshot.is_initialized()) {
    updates_downloaded->Set(
        snapshot.model_neutral_state().num_updates_downloaded_total);
    committed_count->Set(snapshot.model_neutral_state().num_successful_commits);
    entries->Set(static_cast<int>(snapshot.num_entries()));
  }

  // This list of sections belongs in the 'details' field of the returned
  // message.
  about_info->SetKey(kDetailsKey, section_list.ToValue());

  // The values set from this point onwards do not belong in the
  // details list.

  // We don't need to check is_status_valid here.
  // full_status.sync_protocol_error is exported directly from the
  // ProfileSyncService, even if the backend doesn't exist.
  const bool actionable_error_detected =
      full_status.sync_protocol_error.error_type != UNKNOWN_ERROR &&
      full_status.sync_protocol_error.error_type != SYNC_SUCCESS;

  about_info->SetKey("actionable_error_detected",
                     base::Value(actionable_error_detected));

  // NOTE: We won't bother showing any of the following values unless
  // actionable_error_detected is set.

  base::Value actionable_error(base::Value::Type::LIST);
  Stat<std::string> error_type("Error Type", kUninitialized);
  Stat<std::string> action("Action", kUninitialized);
  Stat<std::string> url("URL", kUninitialized);
  Stat<std::string> description("Error Description", kUninitialized);

  if (actionable_error_detected) {
    error_type.Set(
        GetSyncErrorTypeString(full_status.sync_protocol_error.error_type));
    action.Set(GetClientActionString(full_status.sync_protocol_error.action));
    url.Set(full_status.sync_protocol_error.url);
    description.Set(full_status.sync_protocol_error.error_description);
  }

  actionable_error.Append(error_type.ToValue());
  actionable_error.Append(action.ToValue());
  actionable_error.Append(url.ToValue());
  actionable_error.Append(description.ToValue());
  about_info->SetKey("actionable_error", std::move(actionable_error));

  about_info->SetKey("unrecoverable_error_detected",
                     base::Value(service->HasUnrecoverableError()));

  if (service->HasUnrecoverableError()) {
    std::string unrecoverable_error_message =
        "Unrecoverable error detected at " +
        service->GetUnrecoverableErrorLocationForDebugging().ToString() + ": " +
        service->GetUnrecoverableErrorMessageForDebugging();
    about_info->SetKey("unrecoverable_error_message",
                       base::Value(unrecoverable_error_message));
  }

  about_info->SetKey(
      "type_status",
      base::Value::FromUniquePtrValue(service->GetTypeStatusMapForDebugging()));

  return about_info;
}

}  // namespace sync_ui_util

}  // namespace syncer
