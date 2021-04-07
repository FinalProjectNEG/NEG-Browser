// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ssl/connection_help_tab_helper.h"

#include "base/feature_list.h"
#include "base/metrics/histogram_macros.h"
#include "chrome/common/chrome_features.h"
#include "components/security_interstitials/content/ssl_blocking_page.h"
#include "content/public/browser/navigation_handle.h"
#include "content/public/browser/web_contents.h"
#include "content/public/common/referrer.h"
#include "net/base/net_errors.h"
#include "url/gurl.h"

namespace {
const char kHelpCenterConnectionHelpUrl[] =
    "https://support.google.com/chrome/answer/6098869";
const char kBundledConnectionHelpUrl[] = "chrome://connection-help";

void RedirectToBundledHelp(content::WebContents* web_contents) {
  GURL::Replacements replacements;
  std::string error_code = web_contents->GetURL().ref();
  replacements.SetRefStr(error_code);
  web_contents->GetController().LoadURL(
      GURL(kBundledConnectionHelpUrl).ReplaceComponents(replacements),
      content::Referrer(), ui::PageTransition::PAGE_TRANSITION_AUTO_TOPLEVEL,
      std::string());
}
}  // namespace

ConnectionHelpTabHelper::~ConnectionHelpTabHelper() {}

void ConnectionHelpTabHelper::DidFinishNavigation(
    content::NavigationHandle* navigation_handle) {
  if (navigation_handle->IsInMainFrame() &&
      (web_contents()->GetURL().EqualsIgnoringRef(GetHelpCenterURL()) ||
       web_contents()->GetURL().EqualsIgnoringRef(GURL(kSymantecSupportUrl))) &&
      navigation_handle->IsErrorPage() &&
      net::IsCertificateError(navigation_handle->GetNetErrorCode())) {
    RedirectToBundledHelp(web_contents());
  }
}

void ConnectionHelpTabHelper::SetHelpCenterUrlForTesting(const GURL& url) {
  testing_url_ = url;
}

ConnectionHelpTabHelper::ConnectionHelpTabHelper(
    content::WebContents* web_contents)
    : content::WebContentsObserver(web_contents) {}

GURL ConnectionHelpTabHelper::GetHelpCenterURL() {
  if (testing_url_.is_valid())
    return testing_url_;
  return GURL(kHelpCenterConnectionHelpUrl);
}

WEB_CONTENTS_USER_DATA_KEY_IMPL(ConnectionHelpTabHelper)
