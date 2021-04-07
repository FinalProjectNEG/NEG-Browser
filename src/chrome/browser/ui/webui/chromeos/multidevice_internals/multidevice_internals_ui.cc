// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/webui/chromeos/multidevice_internals/multidevice_internals_ui.h"

#include "base/containers/span.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/webui/chromeos/multidevice_internals/multidevice_internals_logs_handler.h"
#include "chrome/browser/ui/webui/chromeos/multidevice_internals/multidevice_internals_phone_hub_handler.h"
#include "chrome/browser/ui/webui/webui_util.h"
#include "chrome/common/webui_url_constants.h"
#include "chrome/grit/multidevice_internals_resources.h"
#include "chrome/grit/multidevice_internals_resources_map.h"
#include "chromeos/constants/chromeos_features.h"
#include "content/public/browser/web_ui.h"
#include "content/public/browser/web_ui_data_source.h"
#include "ui/base/webui/web_ui_util.h"

namespace chromeos {

namespace {

constexpr char kMultideviceInternalsGeneratedPath[] =
    "@out_folder@/gen/chrome/browser/resources/chromeos/multidevice_internals/";

}  // namespace

MultideviceInternalsUI::MultideviceInternalsUI(content::WebUI* web_ui)
    : ui::MojoWebUIController(web_ui, /*enable_chrome_send=*/true) {
  content::WebUIDataSource* html_source = content::WebUIDataSource::Create(
      chrome::kChromeUIMultiDeviceInternalsHost);
  html_source->AddBoolean("isPhoneHubEnabled", features::IsPhoneHubEnabled());

  webui::SetupWebUIDataSource(
      html_source,
      base::make_span(kMultideviceInternalsResources,
                      kMultideviceInternalsResourcesSize),
      kMultideviceInternalsGeneratedPath, IDR_MULTIDEVICE_INTERNALS_INDEX_HTML);

  content::WebUIDataSource::Add(Profile::FromWebUI(web_ui), html_source);
  web_ui->AddMessageHandler(
      std::make_unique<multidevice::MultideviceLogsHandler>());
  web_ui->AddMessageHandler(
      std::make_unique<multidevice::MultidevicePhoneHubHandler>());
}

MultideviceInternalsUI::~MultideviceInternalsUI() = default;

WEB_UI_CONTROLLER_TYPE_IMPL(MultideviceInternalsUI)

}  //  namespace chromeos
