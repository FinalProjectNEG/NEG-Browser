// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <utility>
#include <vector>

#include "chrome/browser/nearby_sharing/certificates/nearby_share_certificate_storage_impl.h"

#include "base/base64url.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_functions.h"
#include "base/optional.h"
#include "base/sequenced_task_runner.h"
#include "base/task/post_task.h"
#include "base/task/thread_pool.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/util/values/values_util.h"
#include "base/values.h"
#include "chrome/browser/nearby_sharing/certificates/common.h"
#include "chrome/browser/nearby_sharing/certificates/constants.h"
#include "chrome/browser/nearby_sharing/certificates/nearby_share_private_certificate.h"
#include "chrome/browser/nearby_sharing/common/nearby_share_prefs.h"
#include "chrome/browser/nearby_sharing/logging/logging.h"
#include "chrome/browser/nearby_sharing/proto/rpc_resources.pb.h"
#include "components/leveldb_proto/public/proto_database_provider.h"
#include "components/prefs/pref_registry_simple.h"
#include "components/prefs/pref_service.h"

namespace {

// Compare to leveldb_proto::Enums::InitStatus. Using a separate enum so that
// the values don't change.
// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum InitStatusMetric {
  kOK = 0,
  kNotInitialized = 1,
  kError = 2,
  kCorrupt = 3,
  kInvalidOperation = 4,
  kMaxValue = kInvalidOperation
};

void RecordInitializationSuccessRateMetric(bool success, size_t num_attempts) {
  base::UmaHistogramBoolean(
      "Nearby.Share.Certificates.Storage.InitializeSuccessRate", success);
  if (success) {
    base::UmaHistogramExactLinear(
        "Nearby.Share.Certificates.Storage.InitializeAttemptCount",
        num_attempts,
        kNearbyShareCertificateStorageMaxNumInitializeAttempts + 1);
  }
}

void RecordInitializationAttemptResultMetric(
    leveldb_proto::Enums::InitStatus init_status) {
  InitStatusMetric metric;
  switch (init_status) {
    case leveldb_proto::Enums::InitStatus::kOK:
      metric = InitStatusMetric::kOK;
      break;
    case leveldb_proto::Enums::InitStatus::kNotInitialized:
      metric = InitStatusMetric::kNotInitialized;
      break;
    case leveldb_proto::Enums::InitStatus::kError:
      metric = InitStatusMetric::kError;
      break;
    case leveldb_proto::Enums::InitStatus::kCorrupt:
      metric = InitStatusMetric::kCorrupt;
      break;
    case leveldb_proto::Enums::InitStatus::kInvalidOperation:
      metric = InitStatusMetric::kInvalidOperation;
      break;
  }
  base::UmaHistogramEnumeration(
      "Nearby.Share.Certificates.Storage.InitializeAttemptResult", metric);
}

void RecordReplacePublicCertificatesDestroySuccessRateMetric(bool success) {
  base::UmaHistogramBoolean(
      "Nearby.Share.Certificates.Storage."
      "ReplacePublicCertificatesDestroySuccessRate",
      success);
}

void RecordReplacePublicCertificatesUpdateEntriesSuccessRateMetric(
    bool success) {
  base::UmaHistogramBoolean(
      "Nearby.Share.Certificates.Storage."
      "ReplacePublicCertificatesUpdateEntriesSuccessRate",
      success);
}

void RecordAddPublicCertificatesSuccessRateMetric(bool success) {
  base::UmaHistogramBoolean(
      "Nearby.Share.Certificates.Storage.AddPublicCertificatesSuccessRate",
      success);
}

void RecordRemoveExpiredPublicCertificatesSuccessMetric(bool success) {
  base::UmaHistogramBoolean(
      "Nearby.Share.Certificates.Storage."
      "RemoveExpiredPublicCertificatesSuccessRate",
      success);
}

void RecordClearPublicCertificatesSuccessRateMetric(bool success) {
  base::UmaHistogramBoolean(
      "Nearby.Share.Certificates.Storage.ClearPublicCertificatesSuccessRate",
      success);
}

const base::FilePath::CharType kPublicCertificateDatabaseName[] =
    FILE_PATH_LITERAL("NearbySharePublicCertificateDatabase");

std::string EncodeString(const std::string& unencoded_string) {
  std::string encoded_string;
  base::Base64UrlEncode(unencoded_string,
                        base::Base64UrlEncodePolicy::INCLUDE_PADDING,
                        &encoded_string);
  return encoded_string;
}

base::Optional<std::string> DecodeString(const std::string& encoded_string) {
  std::string decoded_string;
  if (!base::Base64UrlDecode(encoded_string,
                             base::Base64UrlDecodePolicy::REQUIRE_PADDING,
                             &decoded_string))
    return base::nullopt;

  return decoded_string;
}

bool SortBySecond(const std::pair<std::string, base::Time>& pair1,
                  const std::pair<std::string, base::Time>& pair2) {
  return pair1.second < pair2.second;
}

NearbyShareCertificateStorageImpl::ExpirationList MergeExpirations(
    const NearbyShareCertificateStorageImpl::ExpirationList& old_exp,
    const NearbyShareCertificateStorageImpl::ExpirationList& new_exp) {
  // Remove duplicates with a preference for new entries.
  std::map<std::string, base::Time> merged_map(new_exp.begin(), new_exp.end());
  merged_map.insert(old_exp.begin(), old_exp.end());
  // Convert map to vector and sort by expiration time.
  NearbyShareCertificateStorageImpl::ExpirationList merged(merged_map.begin(),
                                                           merged_map.end());
  std::sort(merged.begin(), merged.end(), SortBySecond);
  return merged;
}

base::Time TimestampToTime(nearbyshare::proto::Timestamp timestamp) {
  return base::Time::UnixEpoch() +
         base::TimeDelta::FromSeconds(timestamp.seconds()) +
         base::TimeDelta::FromNanoseconds(timestamp.nanos());
}

}  // namespace

// static
NearbyShareCertificateStorageImpl::Factory*
    NearbyShareCertificateStorageImpl::Factory::test_factory_ = nullptr;

// static
std::unique_ptr<NearbyShareCertificateStorage>
NearbyShareCertificateStorageImpl::Factory::Create(
    PrefService* pref_service,
    leveldb_proto::ProtoDatabaseProvider* proto_database_provider,
    const base::FilePath& profile_path) {
  if (test_factory_) {
    return test_factory_->CreateInstance(pref_service, proto_database_provider,
                                         profile_path);
  }

  base::FilePath database_path =
      profile_path.Append(kPublicCertificateDatabaseName);
  scoped_refptr<base::SequencedTaskRunner> database_task_runner =
      base::ThreadPool::CreateSequencedTaskRunner(
          {base::MayBlock(), base::TaskPriority::BEST_EFFORT});

  return std::make_unique<NearbyShareCertificateStorageImpl>(
      pref_service,
      proto_database_provider->GetDB<nearbyshare::proto::PublicCertificate>(
          leveldb_proto::ProtoDbType::NEARBY_SHARE_PUBLIC_CERTIFICATE_DATABASE,
          database_path, database_task_runner));
}

// static
void NearbyShareCertificateStorageImpl::Factory::SetFactoryForTesting(
    Factory* test_factory) {
  test_factory_ = test_factory;
}

NearbyShareCertificateStorageImpl::Factory::~Factory() = default;

NearbyShareCertificateStorageImpl::NearbyShareCertificateStorageImpl(
    PrefService* pref_service,
    std::unique_ptr<
        leveldb_proto::ProtoDatabase<nearbyshare::proto::PublicCertificate>>
        proto_database)
    : pref_service_(pref_service), db_(std::move(proto_database)) {
  FetchPublicCertificateExpirations();
  Initialize();
}

NearbyShareCertificateStorageImpl::~NearbyShareCertificateStorageImpl() =
    default;

void NearbyShareCertificateStorageImpl::Initialize() {
  switch (init_status_) {
    case InitStatus::kUninitialized:
    case InitStatus::kFailed:
      num_initialize_attempts_++;
      if (num_initialize_attempts_ >
          kNearbyShareCertificateStorageMaxNumInitializeAttempts) {
        FinishInitialization(false);
        break;
      }

      NS_LOG(VERBOSE) << __func__
                      << ": Attempting to initialize public certificate "
                         "database. Number of attempts: "
                      << num_initialize_attempts_;
      db_->Init(base::BindOnce(
          &NearbyShareCertificateStorageImpl::OnDatabaseInitialized,
          base::Unretained(this)));
      break;
    case InitStatus::kInitialized:
      NOTREACHED();
      break;
  }
}

void NearbyShareCertificateStorageImpl::DestroyAndReinitialize() {
  NS_LOG(ERROR) << __func__
                << ": Public certificate database corrupt. Erasing and "
                   "initializing new database.";
  init_status_ = InitStatus::kUninitialized;
  db_->Destroy(base::BindOnce(
      &NearbyShareCertificateStorageImpl::OnDatabaseDestroyedReinitialize,
      base::Unretained(this)));
}

void NearbyShareCertificateStorageImpl::OnDatabaseInitialized(
    leveldb_proto::Enums::InitStatus status) {
  switch (status) {
    case leveldb_proto::Enums::InitStatus::kOK:
      FinishInitialization(true);
      break;
    case leveldb_proto::Enums::InitStatus::kError:
      Initialize();
      break;
    case leveldb_proto::Enums::InitStatus::kCorrupt:
      DestroyAndReinitialize();
      break;
    case leveldb_proto::Enums::InitStatus::kInvalidOperation:
    case leveldb_proto::Enums::InitStatus::kNotInitialized:
      FinishInitialization(false);
      break;
  }
  RecordInitializationAttemptResultMetric(status);
}

void NearbyShareCertificateStorageImpl::FinishInitialization(bool success) {
  init_status_ = success ? InitStatus::kInitialized : InitStatus::kFailed;
  if (success) {
    NS_LOG(VERBOSE) << __func__
                    << "Public certificate database initialization succeeded.";
  } else {
    NS_LOG(ERROR) << __func__
                  << "Public certificate database initialization failed.";
  }
  RecordInitializationSuccessRateMetric(success, num_initialize_attempts_);

  // We run deferred callbacks even if initialization failed not to cause
  // possible client-side blocks of next calls to the database.
  while (!deferred_callbacks_.empty()) {
    base::SequencedTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, std::move(deferred_callbacks_.front()));
    deferred_callbacks_.pop();
  }
}

void NearbyShareCertificateStorageImpl::OnDatabaseDestroyedReinitialize(
    bool success) {
  if (!success) {
    NS_LOG(ERROR) << __func__
                  << ": Failed to destroy public certificate database.";
    FinishInitialization(false);
    return;
  }

  public_certificate_expirations_.clear();
  SavePublicCertificateExpirations();

  Initialize();
}

void NearbyShareCertificateStorageImpl::OnDatabaseDestroyed(
    ResultCallback callback,
    bool success) {
  RecordClearPublicCertificatesSuccessRateMetric(success);
  if (!success) {
    NS_LOG(ERROR) << __func__
                  << ": Failed to destroy public certificate database.";
    std::move(callback).Run(false);
    return;
  }

  public_certificate_expirations_.clear();
  SavePublicCertificateExpirations();

  std::move(callback).Run(true);
}

void NearbyShareCertificateStorageImpl::
    ReplacePublicCertificatesDestroyCallback(
        std::unique_ptr<std::vector<
            std::pair<std::string, nearbyshare::proto::PublicCertificate>>>
            new_entries,
        std::unique_ptr<ExpirationList> expirations,
        ResultCallback callback,
        bool proceed) {
  RecordReplacePublicCertificatesDestroySuccessRateMetric(proceed);
  if (!proceed) {
    std::move(callback).Run(false);
    return;
  }

  NS_LOG(VERBOSE) << __func__ << ": Inserting " << new_entries->size()
                  << " new public certificates.";
  db_->UpdateEntries(
      std::move(new_entries),
      /*keys_to_remove=*/std::make_unique<std::vector<std::string>>(),
      base::BindOnce(&NearbyShareCertificateStorageImpl::
                         ReplacePublicCertificatesUpdateEntriesCallback,
                     base::Unretained(this), std::move(expirations),
                     std::move(callback)));
}

void NearbyShareCertificateStorageImpl::
    ReplacePublicCertificatesUpdateEntriesCallback(
        std::unique_ptr<ExpirationList> expirations,
        ResultCallback callback,
        bool proceed) {
  RecordReplacePublicCertificatesUpdateEntriesSuccessRateMetric(proceed);
  if (!proceed) {
    NS_LOG(ERROR) << __func__ << ": Failed to replace public certificates.";
    std::move(callback).Run(false);
    return;
  }
  NS_LOG(VERBOSE) << __func__ << ": Successfully replaced public certificates.";

  CHECK(expirations);
  public_certificate_expirations_.swap(*expirations);
  SavePublicCertificateExpirations();
  std::move(callback).Run(true);
}

void NearbyShareCertificateStorageImpl::AddPublicCertificatesCallback(
    std::unique_ptr<ExpirationList> new_expirations,
    ResultCallback callback,
    bool proceed) {
  RecordAddPublicCertificatesSuccessRateMetric(proceed);
  if (!proceed) {
    NS_LOG(ERROR) << __func__ << ": Failed to add public certificates.";
    std::move(callback).Run(false);
    return;
  }
  NS_LOG(VERBOSE) << __func__ << ": Successfully added public certificates.";

  public_certificate_expirations_ =
      MergeExpirations(public_certificate_expirations_, *new_expirations);
  SavePublicCertificateExpirations();
  std::move(callback).Run(true);
}

void NearbyShareCertificateStorageImpl::RemoveExpiredPublicCertificatesCallback(
    std::unique_ptr<base::flat_set<std::string>> ids_to_remove,
    ResultCallback callback,
    bool proceed) {
  RecordRemoveExpiredPublicCertificatesSuccessMetric(proceed);
  if (!proceed) {
    NS_LOG(ERROR) << __func__
                  << ": Failed to remove expired public certificates.";
    std::move(callback).Run(false);
    return;
  }
  NS_LOG(VERBOSE) << __func__
                  << ": Expired public certificates successfully removed.";

  auto should_remove =
      [&](const std::pair<std::string, base::Time>& pair) -> bool {
    return ids_to_remove->contains(pair.first);
  };

  public_certificate_expirations_.erase(
      std::remove_if(public_certificate_expirations_.begin(),
                     public_certificate_expirations_.end(), should_remove),
      public_certificate_expirations_.end());
  SavePublicCertificateExpirations();
  std::move(callback).Run(true);
}

std::vector<std::string>
NearbyShareCertificateStorageImpl::GetPublicCertificateIds() const {
  std::vector<std::string> ids;
  for (const auto& pair : public_certificate_expirations_) {
    ids.emplace_back(pair.first);
  }
  return ids;
}

void NearbyShareCertificateStorageImpl::GetPublicCertificates(
    PublicCertificateCallback callback) {
  if (init_status_ == InitStatus::kFailed) {
    std::move(callback).Run(false, nullptr);
    return;
  }

  if (init_status_ == InitStatus::kUninitialized) {
    deferred_callbacks_.push(base::BindOnce(
        &NearbyShareCertificateStorageImpl::GetPublicCertificates,
        base::Unretained(this), std::move(callback)));
    return;
  }

  NS_LOG(VERBOSE) << __func__ << ": Calling LoadEntries on database.";
  db_->LoadEntries(std::move(callback));
}

base::Optional<std::vector<NearbySharePrivateCertificate>>
NearbyShareCertificateStorageImpl::GetPrivateCertificates() const {
  const base::Value* list =
      pref_service_->Get(prefs::kNearbySharingPrivateCertificateListPrefName);
  std::vector<NearbySharePrivateCertificate> certs;
  for (const base::Value& cert_dict : list->GetList()) {
    base::Optional<NearbySharePrivateCertificate> cert(
        NearbySharePrivateCertificate::FromDictionary(cert_dict));
    if (!cert)
      return base::nullopt;

    certs.push_back(*std::move(cert));
  }
  return certs;
}

base::Optional<base::Time>
NearbyShareCertificateStorageImpl::NextPublicCertificateExpirationTime() const {
  if (public_certificate_expirations_.empty())
    return base::nullopt;

  // |public_certificate_expirations_| is sorted by expiration date.
  return public_certificate_expirations_.front().second;
}

void NearbyShareCertificateStorageImpl::ReplacePrivateCertificates(
    const std::vector<NearbySharePrivateCertificate>& private_certificates) {
  base::Value list(base::Value::Type::LIST);
  for (const NearbySharePrivateCertificate& cert : private_certificates) {
    list.Append(cert.ToDictionary());
  }
  NS_LOG(VERBOSE) << __func__ << ": Overwriting private certificates pref with "
                  << private_certificates.size() << " certificates.";
  pref_service_->Set(prefs::kNearbySharingPrivateCertificateListPrefName, list);
}

void NearbyShareCertificateStorageImpl::ReplacePublicCertificates(
    const std::vector<nearbyshare::proto::PublicCertificate>&
        public_certificates,
    ResultCallback callback) {
  if (init_status_ == InitStatus::kFailed) {
    std::move(callback).Run(false);
    return;
  }

  if (init_status_ == InitStatus::kUninitialized) {
    deferred_callbacks_.push(base::BindOnce(
        &NearbyShareCertificateStorageImpl::ReplacePublicCertificates,
        base::Unretained(this), public_certificates, std::move(callback)));
    return;
  }

  auto new_entries = std::make_unique<std::vector<
      std::pair<std::string, nearbyshare::proto::PublicCertificate>>>();
  auto new_expirations = std::make_unique<ExpirationList>();
  for (const nearbyshare::proto::PublicCertificate& cert :
       public_certificates) {
    new_entries->emplace_back(cert.secret_id(), cert);
    new_expirations->emplace_back(cert.secret_id(),
                                  TimestampToTime(cert.end_time()));
  }
  std::sort(new_expirations->begin(), new_expirations->end(), SortBySecond);

  NS_LOG(VERBOSE) << __func__ << ": Clearing public certificate database.";
  db_->Destroy(base::BindOnce(&NearbyShareCertificateStorageImpl::
                                  ReplacePublicCertificatesDestroyCallback,
                              base::Unretained(this), std::move(new_entries),
                              std::move(new_expirations), std::move(callback)));
}

void NearbyShareCertificateStorageImpl::AddPublicCertificates(
    const std::vector<nearbyshare::proto::PublicCertificate>&
        public_certificates,
    ResultCallback callback) {
  if (init_status_ == InitStatus::kFailed) {
    std::move(callback).Run(false);
    return;
  }

  if (init_status_ == InitStatus::kUninitialized) {
    deferred_callbacks_.push(base::BindOnce(
        &NearbyShareCertificateStorageImpl::AddPublicCertificates,
        base::Unretained(this), public_certificates, std::move(callback)));
    return;
  }

  auto new_entries = std::make_unique<std::vector<
      std::pair<std::string, nearbyshare::proto::PublicCertificate>>>();
  auto new_expirations = std::make_unique<ExpirationList>();
  for (const nearbyshare::proto::PublicCertificate& cert :
       public_certificates) {
    new_entries->emplace_back(cert.secret_id(), cert);
    new_expirations->emplace_back(cert.secret_id(),
                                  TimestampToTime(cert.end_time()));
  }
  std::sort(new_expirations->begin(), new_expirations->end(), SortBySecond);

  NS_LOG(VERBOSE)
      << __func__
      << ": Calling UpdateEntries on public certificate database with "
      << public_certificates.size() << " new certificates.";
  db_->UpdateEntries(
      std::move(new_entries), std::make_unique<std::vector<std::string>>(),
      base::BindOnce(
          &NearbyShareCertificateStorageImpl::AddPublicCertificatesCallback,
          base::Unretained(this), std::move(new_expirations),
          std::move(callback)));
}

void NearbyShareCertificateStorageImpl::RemoveExpiredPublicCertificates(
    base::Time now,
    ResultCallback callback) {
  if (init_status_ == InitStatus::kFailed) {
    std::move(callback).Run(false);
    return;
  }

  if (init_status_ == InitStatus::kUninitialized) {
    deferred_callbacks_.push(base::BindOnce(
        &NearbyShareCertificateStorageImpl::RemoveExpiredPublicCertificates,
        base::Unretained(this), now, std::move(callback)));
    return;
  }

  auto ids_to_remove = std::make_unique<std::vector<std::string>>();
  for (const auto& pair : public_certificate_expirations_) {
    // Because the list is sorted by expiration time, break as soon as we
    // encounter an unexpired certificate. Apply a tolerance when evaluating
    // whether the certificate is expired to account for clock skew between
    // devices. This conforms this the GmsCore implementation.
    if (!IsNearbyShareCertificateExpired(
            now,
            /*not_after=*/pair.second,
            /*use_public_certificate_tolerance=*/true)) {
      break;
    }

    ids_to_remove->emplace_back(pair.first);
  }
  if (ids_to_remove->empty()) {
    std::move(callback).Run(true);
    return;
  }

  auto ids_to_add = std::make_unique<leveldb_proto::ProtoDatabase<
      nearbyshare::proto::PublicCertificate>::KeyEntryVector>();

  auto ids_to_remove_set = std::make_unique<base::flat_set<std::string>>(
      ids_to_remove->begin(), ids_to_remove->end());

  NS_LOG(VERBOSE)
      << __func__
      << ": Calling UpdateEntries on public certificate database to remove "
      << ids_to_remove->size() << " expired certificates.";
  db_->UpdateEntries(
      std::move(ids_to_add), std::move(ids_to_remove),
      base::BindOnce(&NearbyShareCertificateStorageImpl::
                         RemoveExpiredPublicCertificatesCallback,
                     base::Unretained(this), std::move(ids_to_remove_set),
                     std::move(callback)));
}

void NearbyShareCertificateStorageImpl::ClearPublicCertificates(
    ResultCallback callback) {
  if (init_status_ == InitStatus::kFailed) {
    std::move(callback).Run(false);
    return;
  }

  if (init_status_ == InitStatus::kUninitialized) {
    deferred_callbacks_.push(base::BindOnce(
        &NearbyShareCertificateStorageImpl::ClearPublicCertificates,
        base::Unretained(this), std::move(callback)));
    return;
  }

  NS_LOG(VERBOSE) << __func__
                  << ": Calling Destroy on public certificate database.";
  db_->Destroy(
      base::BindOnce(&NearbyShareCertificateStorageImpl::OnDatabaseDestroyed,
                     base::Unretained(this), std::move(callback)));
}

bool NearbyShareCertificateStorageImpl::FetchPublicCertificateExpirations() {
  const base::Value* dict = pref_service_->Get(
      prefs::kNearbySharingPublicCertificateExpirationDictPrefName);
  public_certificate_expirations_.clear();
  if (!dict) {
    return false;
  }

  public_certificate_expirations_.reserve(dict->DictSize());
  for (const std::pair<const std::string&, const base::Value&>& pair :
       dict->DictItems()) {
    base::Optional<std::string> id = DecodeString(pair.first);
    base::Optional<base::Time> expiration = util::ValueToTime(pair.second);
    if (!id || !expiration)
      return false;

    public_certificate_expirations_.emplace_back(*id, *expiration);
  }
  std::sort(public_certificate_expirations_.begin(),
            public_certificate_expirations_.end(), SortBySecond);

  return true;
}

void NearbyShareCertificateStorageImpl::SavePublicCertificateExpirations() {
  base::Value dict(base::Value::Type::DICTIONARY);

  for (const std::pair<std::string, base::Time>& pair :
       public_certificate_expirations_) {
    dict.SetKey(EncodeString(pair.first), util::TimeToValue(pair.second));
  }

  pref_service_->Set(
      prefs::kNearbySharingPublicCertificateExpirationDictPrefName, dict);
}
