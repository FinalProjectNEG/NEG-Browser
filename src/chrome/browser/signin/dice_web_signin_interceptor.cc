// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/signin/dice_web_signin_interceptor.h"

#include <string>

#include "base/check.h"
#include "base/i18n/case_conversion.h"
#include "base/metrics/histogram_functions.h"
#include "base/optional.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/profiles/profile_attributes_entry.h"
#include "chrome/browser/profiles/profile_attributes_storage.h"
#include "chrome/browser/profiles/profile_avatar_icon_util.h"
#include "chrome/browser/profiles/profile_manager.h"
#include "chrome/browser/profiles/profile_metrics.h"
#include "chrome/browser/profiles/profiles_state.h"
#include "chrome/browser/signin/dice_intercepted_session_startup_helper.h"
#include "chrome/browser/signin/dice_signed_in_profile_creator.h"
#include "chrome/browser/signin/dice_web_signin_interceptor_factory.h"
#include "chrome/browser/signin/identity_manager_factory.h"
#include "chrome/browser/signin/signin_features.h"
#include "chrome/browser/themes/theme_service.h"
#include "chrome/browser/themes/theme_service_factory.h"
#include "chrome/browser/ui/browser_finder.h"
#include "chrome/browser/ui/signin/profile_colors_util.h"
#include "chrome/common/pref_names.h"
#include "chrome/common/themes/autogenerated_theme_util.h"
#include "components/prefs/pref_service.h"
#include "components/signin/public/identity_manager/identity_manager.h"
#include "ui/base/l10n/l10n_util.h"

namespace {

void RecordSigninInterceptionHeuristicOutcome(
    SigninInterceptionHeuristicOutcome outcome) {
  base::UmaHistogramEnumeration("Signin.Intercept.HeuristicOutcome", outcome);
}

bool IsProfileCreationAllowed() {
  PrefService* service = g_browser_process->local_state();
  DCHECK(service);
  return service->GetBoolean(prefs::kBrowserAddPersonEnabled);
}

// Helper function to return the primary account info. The returned info is
// empty if there is no primary account, and non-empty otherwise. Extended
// fields may be missing if they are not available.
AccountInfo GetPrimaryAccountInfo(signin::IdentityManager* manager) {
  CoreAccountInfo primary_core_account_info =
      manager->GetPrimaryAccountInfo(signin::ConsentLevel::kNotRequired);
  if (primary_core_account_info.IsEmpty())
    return AccountInfo();

  base::Optional<AccountInfo> primary_account_info =
      manager->FindExtendedAccountInfoForAccountWithRefreshToken(
          primary_core_account_info);

  if (primary_account_info)
    return *primary_account_info;

  // Return an AccountInfo without extended fields, based on the core info.
  AccountInfo account_info;
  account_info.gaia = primary_core_account_info.gaia;
  account_info.email = primary_core_account_info.email;
  account_info.account_id = primary_core_account_info.account_id;
  return account_info;
}

}  // namespace

DiceWebSigninInterceptor::DiceWebSigninInterceptor(
    Profile* profile,
    std::unique_ptr<Delegate> delegate)
    : profile_(profile),
      identity_manager_(IdentityManagerFactory::GetForProfile(profile)),
      delegate_(std::move(delegate)) {
  DCHECK(profile_);
  DCHECK(identity_manager_);
  DCHECK(delegate_);
}

DiceWebSigninInterceptor::~DiceWebSigninInterceptor() = default;

void DiceWebSigninInterceptor::MaybeInterceptWebSignin(
    content::WebContents* web_contents,
    CoreAccountId account_id,
    bool is_new_account,
    bool is_sync_signin) {
  if (!base::FeatureList::IsEnabled(kDiceWebSigninInterceptionFeature))
    return;

  if (is_sync_signin) {
    // Do not intercept signins from the Sync startup flow.
    // Note: |is_sync_signin| is an approximation, and in rare cases it may be
    // true when in fact the signin was not a sync signin. In this case the
    // interception is missed.
    RecordSigninInterceptionHeuristicOutcome(
        SigninInterceptionHeuristicOutcome::kAbortSyncSignin);
    return;
  }
  if (is_interception_in_progress_) {
    // Multiple concurrent interceptions are not supported.
    RecordSigninInterceptionHeuristicOutcome(
        SigninInterceptionHeuristicOutcome::kAbortInterceptInProgress);
    return;
  }
  if (!is_new_account) {
    // Do not intercept reauth.
    RecordSigninInterceptionHeuristicOutcome(
        SigninInterceptionHeuristicOutcome::kAbortAccountNotNew);
    return;
  }

  account_id_ = account_id;
  is_interception_in_progress_ = true;
  Observe(web_contents);

  base::Optional<AccountInfo> account_info =
      identity_manager_
          ->FindExtendedAccountInfoForAccountWithRefreshTokenByAccountId(
              account_id_);
  DCHECK(account_info) << "Intercepting unknown account.";

  const ProfileAttributesEntry* entry = ShouldShowProfileSwitchBubble(
      *account_info,
      &g_browser_process->profile_manager()->GetProfileAttributesStorage());
  if (entry) {
    Delegate::BubbleParameters bubble_parameters{
        SigninInterceptionType::kProfileSwitch, *account_info,
        GetPrimaryAccountInfo(identity_manager_),
        entry->GetProfileThemeColors().profile_highlight_color};
    delegate_->ShowSigninInterceptionBubble(
        web_contents, bubble_parameters,
        base::BindOnce(&DiceWebSigninInterceptor::OnProfileSwitchChoice,
                       base::Unretained(this), entry->GetPath()));
    was_interception_ui_displayed_ = true;
    RecordSigninInterceptionHeuristicOutcome(
        SigninInterceptionHeuristicOutcome::kInterceptProfileSwitch);
    return;
  }

  if (identity_manager_->GetAccountsWithRefreshTokens().size() <= 1u) {
    // Enterprise and multi-user bubbles are only shown if there are multiple
    // accounts.
    RecordSigninInterceptionHeuristicOutcome(
        SigninInterceptionHeuristicOutcome::kAbortSingleAccount);
    Reset();
    return;
  }
  if (!IsProfileCreationAllowed()) {
    RecordSigninInterceptionHeuristicOutcome(
        SigninInterceptionHeuristicOutcome::kAbortProfileCreationDisallowed);
    Reset();
    return;
  }

  account_info_fetch_start_time_ = base::TimeTicks::Now();
  if (account_info->IsValid()) {
    OnExtendedAccountInfoUpdated(*account_info);
  } else {
    on_account_info_update_timeout_.Reset(base::BindOnce(
        &DiceWebSigninInterceptor::OnExtendedAccountInfoFetchTimeout,
        base::Unretained(this)));
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE, on_account_info_update_timeout_.callback(),
        base::TimeDelta::FromSeconds(5));
    account_info_update_observer_.Add(identity_manager_);
  }
}

void DiceWebSigninInterceptor::CreateBrowserAfterSigninInterception(
    CoreAccountId account_id,
    content::WebContents* intercepted_contents,
    bool show_customization_bubble) {
  DCHECK(!session_startup_helper_);
  session_startup_helper_ =
      std::make_unique<DiceInterceptedSessionStartupHelper>(
          profile_, account_id, intercepted_contents);
  session_startup_helper_->Startup(
      base::Bind(&DiceWebSigninInterceptor::OnNewBrowserCreated,
                 base::Unretained(this), show_customization_bubble));
}

void DiceWebSigninInterceptor::Shutdown() {
  if (is_interception_in_progress_ && !was_interception_ui_displayed_) {
    RecordSigninInterceptionHeuristicOutcome(
        SigninInterceptionHeuristicOutcome::kAbortShutdown);
  }
  Reset();
}

void DiceWebSigninInterceptor::Reset() {
  Observe(/*web_contents=*/nullptr);
  account_info_update_observer_.RemoveAll();
  on_account_info_update_timeout_.Cancel();
  is_interception_in_progress_ = false;
  account_id_ = CoreAccountId();
  dice_signed_in_profile_creator_.reset();
  was_interception_ui_displayed_ = false;
  account_info_fetch_start_time_ = base::TimeTicks();
  profile_creation_start_time_ = base::TimeTicks();
}

const ProfileAttributesEntry*
DiceWebSigninInterceptor::ShouldShowProfileSwitchBubble(
    const CoreAccountInfo& intercepted_account_info,
    ProfileAttributesStorage* profile_attribute_storage) {
  // Check if there is already an existing profile with this account.
  base::FilePath profile_path = profile_->GetPath();
  for (const auto* entry :
       profile_attribute_storage->GetAllProfilesAttributes()) {
    if (entry->GetPath() == profile_path)
      continue;
    if (entry->GetGAIAId() == intercepted_account_info.gaia) {
      return entry;
    }
  }
  return nullptr;
}

bool DiceWebSigninInterceptor::ShouldShowEnterpriseBubble(
    const AccountInfo& intercepted_account_info) {
  DCHECK(intercepted_account_info.IsValid());
  // Check if the intercepted account or the primary account is managed.
  CoreAccountInfo primary_core_account_info =
      identity_manager_->GetPrimaryAccountInfo(
          signin::ConsentLevel::kNotRequired);

  if (primary_core_account_info.IsEmpty() ||
      primary_core_account_info.account_id ==
          intercepted_account_info.account_id) {
    return false;
  }

  if (intercepted_account_info.hosted_domain != kNoHostedDomainFound)
    return true;

  base::Optional<AccountInfo> primary_account_info =
      identity_manager_->FindExtendedAccountInfoForAccountWithRefreshToken(
          primary_core_account_info);
  if (!primary_account_info || !primary_account_info->IsValid())
    return false;

  return primary_account_info->hosted_domain != kNoHostedDomainFound;
}

bool DiceWebSigninInterceptor::ShouldShowMultiUserBubble(
    const AccountInfo& intercepted_account_info) {
  DCHECK(intercepted_account_info.IsValid());
  if (identity_manager_->GetAccountsWithRefreshTokens().size() <= 1u)
    return false;
  // Check if the account has the same name as another account in the profile.
  for (const auto& account_info :
       identity_manager_->GetExtendedAccountInfoForAccountsWithRefreshToken()) {
    if (account_info.account_id == intercepted_account_info.account_id)
      continue;
    // Case-insensitve comparison supporting non-ASCII characters.
    if (base::i18n::FoldCase(base::UTF8ToUTF16(account_info.given_name)) ==
        base::i18n::FoldCase(
            base::UTF8ToUTF16(intercepted_account_info.given_name))) {
      return false;
    }
  }
  return true;
}

void DiceWebSigninInterceptor::OnExtendedAccountInfoUpdated(
    const AccountInfo& info) {
  if (info.account_id != account_id_)
    return;
  if (!info.IsValid())
    return;

  account_info_update_observer_.RemoveAll();
  on_account_info_update_timeout_.Cancel();
  base::UmaHistogramTimes(
      "Signin.Intercept.AccountInfoFetchDuration",
      base::TimeTicks::Now() - account_info_fetch_start_time_);

  base::Optional<SigninInterceptionType> interception_type;

  if (ShouldShowEnterpriseBubble(info))
    interception_type = SigninInterceptionType::kEnterprise;
  else if (ShouldShowMultiUserBubble(info))
    interception_type = SigninInterceptionType::kMultiUser;

  if (!interception_type) {
    // Signin should not be intercepted.
    RecordSigninInterceptionHeuristicOutcome(
        SigninInterceptionHeuristicOutcome::kAbortAccountInfoNotCompatible);
    Reset();
    return;
  }

  SkColor profile_color = GenerateNewProfileColor().color;
  Delegate::BubbleParameters bubble_parameters{
      *interception_type, info, GetPrimaryAccountInfo(identity_manager_),
      GetAutogeneratedThemeColors(profile_color).frame_color};
  delegate_->ShowSigninInterceptionBubble(
      web_contents(), bubble_parameters,
      base::BindOnce(&DiceWebSigninInterceptor::OnProfileCreationChoice,
                     base::Unretained(this), profile_color));
  was_interception_ui_displayed_ = true;
  RecordSigninInterceptionHeuristicOutcome(
      *interception_type == SigninInterceptionType::kEnterprise
          ? SigninInterceptionHeuristicOutcome::kInterceptEnterprise
          : SigninInterceptionHeuristicOutcome::kInterceptMultiUser);
}

void DiceWebSigninInterceptor::OnExtendedAccountInfoFetchTimeout() {
  RecordSigninInterceptionHeuristicOutcome(
      SigninInterceptionHeuristicOutcome::kAbortAccountInfoTimeout);
  Reset();
}

void DiceWebSigninInterceptor::OnProfileCreationChoice(SkColor profile_color,
                                                       bool create) {
  if (!create) {
    Reset();
    return;
  }

  profile_creation_start_time_ = base::TimeTicks::Now();
  base::string16 profile_name;
  base::Optional<AccountInfo> account_info =
      identity_manager_
          ->FindExtendedAccountInfoForAccountWithRefreshTokenByAccountId(
              account_id_);
  if (account_info) {
    profile_name = profiles::GetDefaultNameForNewSignedInProfile(*account_info);
  }

  DCHECK(!dice_signed_in_profile_creator_);
  // Unretained is fine because the profile creator is owned by this.
  dice_signed_in_profile_creator_ =
      std::make_unique<DiceSignedInProfileCreator>(
          profile_, account_id_, profile_name,
          profiles::GetPlaceholderAvatarIndex(),
          base::BindOnce(&DiceWebSigninInterceptor::OnNewSignedInProfileCreated,
                         base::Unretained(this), profile_color));
}

void DiceWebSigninInterceptor::OnProfileSwitchChoice(
    const base::FilePath& profile_path,
    bool switch_profile) {
  if (!switch_profile) {
    Reset();
    return;
  }

  profile_creation_start_time_ = base::TimeTicks::Now();
  DCHECK(!dice_signed_in_profile_creator_);
  // Unretained is fine because the profile creator is owned by this.
  dice_signed_in_profile_creator_ =
      std::make_unique<DiceSignedInProfileCreator>(
          profile_, account_id_, profile_path,
          base::BindOnce(&DiceWebSigninInterceptor::OnNewSignedInProfileCreated,
                         base::Unretained(this), base::nullopt));
}

void DiceWebSigninInterceptor::OnNewSignedInProfileCreated(
    base::Optional<SkColor> profile_color,
    Profile* new_profile) {
  DCHECK(dice_signed_in_profile_creator_);
  dice_signed_in_profile_creator_.reset();

  if (!new_profile) {
    Reset();
    return;
  }

  bool show_customization_bubble = false;
  if (profile_color.has_value()) {
    // The profile color is defined only when the profile has just been created
    // (with interception type kMultiUser or kEnterprise). If the profile is not
    // new (kProfileSwitch), then the color is not updated.
    base::UmaHistogramTimes(
        "Signin.Intercept.ProfileCreationDuration",
        base::TimeTicks::Now() - profile_creation_start_time_);
    ProfileMetrics::LogProfileAddNewUser(
        ProfileMetrics::ADD_NEW_USER_SIGNIN_INTERCEPTION);
    // Apply the new color to the profile.
    ThemeServiceFactory::GetForProfile(new_profile)
        ->BuildAutogeneratedThemeFromColor(*profile_color);
    // Show the customization UI to allow changing the color.
    show_customization_bubble = true;
  } else {
    base::UmaHistogramTimes(
        "Signin.Intercept.ProfileSwitchDuration",
        base::TimeTicks::Now() - profile_creation_start_time_);
  }

  // Work is done in this profile, the flow continues in the
  // DiceWebSigninInterceptor that is attached to the new profile.
  DiceWebSigninInterceptorFactory::GetForProfile(new_profile)
      ->CreateBrowserAfterSigninInterception(account_id_, web_contents(),
                                             show_customization_bubble);
  Reset();
}

void DiceWebSigninInterceptor::OnNewBrowserCreated(
    bool show_customization_bubble) {
  session_startup_helper_.reset();
  if (show_customization_bubble) {
    Browser* browser = chrome::FindBrowserWithProfile(profile_);
    DCHECK(browser);
    delegate_->ShowProfileCustomizationBubble(browser);
  }
}
