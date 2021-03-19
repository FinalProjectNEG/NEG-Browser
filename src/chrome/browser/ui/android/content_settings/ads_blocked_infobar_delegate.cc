// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/android/content_settings/ads_blocked_infobar_delegate.h"

#include <memory>

#include "base/memory/ptr_util.h"
#include "base/strings/utf_string_conversions.h"
#include "chrome/browser/ui/android/infobars/ads_blocked_infobar.h"
#include "components/infobars/content/content_infobar_manager.h"
#include "components/infobars/core/infobar.h"
#include "components/resources/android/theme_resources.h"
#include "components/strings/grit/components_strings.h"
#include "components/subresource_filter/content/browser/content_subresource_filter_throttle_manager.h"
#include "components/subresource_filter/core/browser/subresource_filter_constants.h"
#include "content/public/browser/web_contents.h"
#include "ui/base/l10n/l10n_util.h"

// static
void AdsBlockedInfobarDelegate::Create(
    infobars::ContentInfoBarManager* infobar_manager,
    const infobars::InfoBarAndroid::ResourceIdMapper& resource_id_mapper) {
  infobar_manager->AddInfoBar(std::make_unique<AdsBlockedInfoBar>(
      base::WrapUnique(new AdsBlockedInfobarDelegate()), resource_id_mapper));
}

AdsBlockedInfobarDelegate::~AdsBlockedInfobarDelegate() = default;

base::string16 AdsBlockedInfobarDelegate::GetExplanationText() const {
  return l10n_util::GetStringUTF16(IDS_BLOCKED_ADS_PROMPT_EXPLANATION);
}

base::string16 AdsBlockedInfobarDelegate::GetToggleText() const {
  return l10n_util::GetStringUTF16(IDS_ALWAYS_ALLOW_ADS);
}

infobars::InfoBarDelegate::InfoBarIdentifier
AdsBlockedInfobarDelegate::GetIdentifier() const {
  return ADS_BLOCKED_INFOBAR_DELEGATE_ANDROID;
}

int AdsBlockedInfobarDelegate::GetIconId() const {
  return IDR_ANDROID_INFOBAR_BLOCKED_POPUPS;
}

GURL AdsBlockedInfobarDelegate::GetLinkURL() const {
  DCHECK(infobar_expanded_);
  return GURL(subresource_filter::kLearnMoreLink);
}

bool AdsBlockedInfobarDelegate::LinkClicked(WindowOpenDisposition disposition) {
  if (infobar_expanded_) {
    subresource_filter::ContentSubresourceFilterThrottleManager::LogAction(
        subresource_filter::SubresourceFilterAction::kClickedLearnMore);
    return ConfirmInfoBarDelegate::LinkClicked(disposition);
  }

  subresource_filter::ContentSubresourceFilterThrottleManager::LogAction(
      subresource_filter::SubresourceFilterAction::kDetailsShown);
  infobar_expanded_ = true;
  return false;
}

base::string16 AdsBlockedInfobarDelegate::GetMessageText() const {
  return l10n_util::GetStringUTF16(IDS_BLOCKED_ADS_INFOBAR_MESSAGE);
}

int AdsBlockedInfobarDelegate::GetButtons() const {
  return BUTTON_OK | BUTTON_CANCEL;
}

base::string16 AdsBlockedInfobarDelegate::GetButtonLabel(
    InfoBarButton button) const {
  return l10n_util::GetStringUTF16((button == BUTTON_OK) ? IDS_OK : IDS_RELOAD);
}

bool AdsBlockedInfobarDelegate::Cancel() {
  subresource_filter::ContentSubresourceFilterThrottleManager::FromWebContents(
      infobars::ContentInfoBarManager::WebContentsFromInfoBar(infobar()))
      ->OnReloadRequested();
  return true;
}

AdsBlockedInfobarDelegate::AdsBlockedInfobarDelegate() = default;
