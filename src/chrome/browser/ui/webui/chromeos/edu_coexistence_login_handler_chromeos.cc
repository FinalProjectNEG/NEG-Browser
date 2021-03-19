// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/webui/chromeos/edu_coexistence_login_handler_chromeos.h"

#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/guid.h"
#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/system/sys_info.h"
#include "base/values.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/browser_process_platform_part.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/profiles/profile_manager.h"
#include "chrome/browser/signin/identity_manager_factory.h"
#include "chrome/browser/ui/webui/chromeos/edu_coexistence_consent_tracker.h"
#include "chrome/browser/ui/webui/signin/inline_login_dialog_chromeos.h"
#include "chrome/common/channel_info.h"
#include "chromeos/constants/chromeos_pref_names.h"
#include "components/prefs/pref_service.h"
#include "components/session_manager/core/session_manager.h"
#include "components/signin/public/identity_manager/access_token_info.h"
#include "components/signin/public/identity_manager/account_info.h"
#include "components/signin/public/identity_manager/consent_level.h"
#include "components/signin/public/identity_manager/identity_manager.h"
#include "content/public/browser/web_ui.h"
#include "google_apis/gaia/gaia_constants.h"
#include "google_apis/gaia/gaia_urls.h"
#include "google_apis/gaia/google_service_auth_error.h"
#include "google_apis/gaia/oauth2_access_token_manager.h"
#include "ui/base/webui/web_ui_util.h"

namespace chromeos {

namespace {

constexpr char kEduCoexistenceLoginURLSwitch[] = "edu-coexistence-url";
constexpr char kEduCoexistenceLoginDefaultURL[] =
    "https://families.google.com/supervision/coexistence";
constexpr char kOobe[] = "oobe";
constexpr char kInSession[] = "in_session";

signin::IdentityManager* GetIdentityManager() {
  Profile* profile = ProfileManager::GetActiveUserProfile();
  DCHECK(profile);
  return IdentityManagerFactory::GetForProfile(profile);
}

std::string GetEduCoexistenceURL() {
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  // This should only be set during local development tests.
  if (command_line->HasSwitch(kEduCoexistenceLoginURLSwitch))
    return command_line->GetSwitchValueASCII(kEduCoexistenceLoginURLSwitch);

  return kEduCoexistenceLoginDefaultURL;
}

std::string GetSourceUI() {
  if (session_manager::SessionManager::Get()->IsUserSessionBlocked())
    return kOobe;
  return kInSession;
}

std::string GetOrCreateEduCoexistenceUserId() {
  Profile* profile = ProfileManager::GetActiveUserProfile();
  PrefService* pref_service = profile->GetPrefs();
  std::string id = pref_service->GetString(chromeos::prefs::kEduCoexistenceId);
  if (id.empty()) {
    id = base::GenerateGUID();
    pref_service->SetString(chromeos::prefs::kEduCoexistenceId, id);
  }
  return id;
}

}  // namespace

EduCoexistenceLoginHandler::EduCoexistenceLoginHandler(
    const base::RepeatingClosure& close_dialog_closure)
    : EduCoexistenceLoginHandler(close_dialog_closure, GetIdentityManager()) {}

EduCoexistenceLoginHandler::EduCoexistenceLoginHandler(
    const base::RepeatingClosure& close_dialog_closure,
    signin::IdentityManager* identity_manager)
    : close_dialog_closure_(close_dialog_closure),
      identity_manager_(identity_manager) {
  Profile* profile = ProfileManager::GetActiveUserProfile();
  DCHECK(profile->IsChild());

  // Start observing IdentityManager.
  identity_manager->AddObserver(this);

  OAuth2AccessTokenManager::ScopeSet scopes;
  scopes.insert(GaiaConstants::kKidsSupervisionSetupChildOAuth2Scope);
  scopes.insert(GaiaConstants::kPeopleApiReadOnlyOAuth2Scope);
  scopes.insert(GaiaConstants::kAccountsReauthOAuth2Scope);
  scopes.insert(GaiaConstants::kAuditRecordingOAuth2Scope);
  scopes.insert(GaiaConstants::kClearCutOAuth2Scope);

  // Start fetching oauth access token.
  access_token_fetcher_ =
      std::make_unique<signin::PrimaryAccountAccessTokenFetcher>(
          "EduCoexistenceLoginHandler", identity_manager, scopes,
          base::BindOnce(
              &EduCoexistenceLoginHandler::OnOAuthAccessTokensFetched,
              base::Unretained(this)),
          signin::PrimaryAccountAccessTokenFetcher::Mode::kWaitUntilAvailable,
          signin::ConsentLevel::kNotRequired);
}

EduCoexistenceLoginHandler::~EduCoexistenceLoginHandler() {
  identity_manager_->RemoveObserver(this);

  EduCoexistenceConsentTracker::Get()->OnDialogClosed(web_ui());
  close_dialog_closure_.Run();
}

void EduCoexistenceLoginHandler::RegisterMessages() {
  web_ui()->RegisterMessageCallback(
      "initializeEduArgs",
      base::BindRepeating(&EduCoexistenceLoginHandler::InitializeEduArgs,
                          base::Unretained(this)));

  web_ui()->RegisterMessageCallback(
      "consentValid",
      base::BindRepeating(&EduCoexistenceLoginHandler::ConsentValid,
                          base::Unretained(this)));

  web_ui()->RegisterMessageCallback(
      "consentLogged",
      base::BindRepeating(&EduCoexistenceLoginHandler::ConsentLogged,
                          base::Unretained(this)));

  web_ui()->RegisterMessageCallback(
      "error", base::BindRepeating(&EduCoexistenceLoginHandler::OnError,
                                   base::Unretained(this)));
}

void EduCoexistenceLoginHandler::OnJavascriptDisallowed() {
  access_token_fetcher_.reset();
}

void EduCoexistenceLoginHandler::OnRefreshTokenUpdatedForAccount(
    const CoreAccountInfo& account_info) {
  if (edu_account_email_.empty() || account_info.email != edu_account_email_)
    return;

  AllowJavascript();

  // TODO(yilkal): Record |terms_of_service_version_number_| in user preference.

  // Otherwise, notify the ui that account addition was successful!!
  ResolveJavascriptCallback(base::Value(account_added_callback_),
                            base::Value(true));

  account_added_callback_.clear();
  terms_of_service_version_number_.clear();
}

void EduCoexistenceLoginHandler::OnOAuthAccessTokensFetched(
    GoogleServiceAuthError error,
    signin::AccessTokenInfo info) {
  if (error.state() != GoogleServiceAuthError::State::NONE) {
    // TODO(yilkal) call on to the ui to show error screen.
    return;
  }

  oauth_access_token_ = info;
  if (initialize_edu_args_callback_.has_value()) {
    SendInitializeEduArgs();
  }
}

void EduCoexistenceLoginHandler::InitializeEduArgs(
    const base::ListValue* args) {
  AllowJavascript();

  initialize_edu_args_callback_ = args->GetList()[0].GetString();

  // If the access token is not fetched yet, wait for access token.
  if (!oauth_access_token_.has_value()) {
    return;
  }

  SendInitializeEduArgs();
}

void EduCoexistenceLoginHandler::SendInitializeEduArgs() {
  DCHECK(oauth_access_token_.has_value());
  DCHECK(initialize_edu_args_callback_.has_value());
  base::Value params(base::Value::Type::DICTIONARY);

  const std::string& app_locale = g_browser_process->GetApplicationLocale();
  params.SetStringKey("h1", app_locale);

  params.SetStringKey("url", GetEduCoexistenceURL());

  params.SetStringKey("clientId",
                      GaiaUrls::GetInstance()->oauth2_chrome_client_id());
  params.SetStringKey("sourceUi", GetSourceUI());

  params.SetStringKey("clientVersion", chrome::GetVersionString());
  params.SetStringKey("eduCoexistenceAccessToken", oauth_access_token_->token);
  params.SetStringKey("eduCoexistenceId", GetOrCreateEduCoexistenceUserId());
  params.SetStringKey("platformVersion",
                      base::SysInfo::OperatingSystemVersion());
  params.SetStringKey("releaseChannel", chrome::GetChannelName());

  ResolveJavascriptCallback(base::Value(initialize_edu_args_callback_.value()),
                            std::move(params));
  initialize_edu_args_callback_ = base::nullopt;
}

void EduCoexistenceLoginHandler::ConsentValid(const base::ListValue* args) {
  AllowJavascript();
  // TODO(yilkal): Have a state enum to record the progress.
}

void EduCoexistenceLoginHandler::ConsentLogged(const base::ListValue* args) {
  if (!args || args->GetList().size() == 0)
    return;

  account_added_callback_ = args->GetList()[0].GetString();

  const base::Value::ConstListView& arguments = args->GetList()[1].GetList();

  edu_account_email_ = arguments[0].GetString();
  terms_of_service_version_number_ = arguments[1].GetString();

  EduCoexistenceConsentTracker::Get()->OnConsentLogged(web_ui(),
                                                       edu_account_email_);
}

void EduCoexistenceLoginHandler::OnError(const base::ListValue* args) {
  // TODO(yilkal): Handle error appropriately.
}

}  // namespace chromeos
