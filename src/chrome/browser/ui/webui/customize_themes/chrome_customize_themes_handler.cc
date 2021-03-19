// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/webui/customize_themes/chrome_customize_themes_handler.h"

#include "chrome/browser/chrome_notification_types.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/search/chrome_colors/chrome_colors_factory.h"
#include "chrome/browser/search/chrome_colors/chrome_colors_service.h"
#include "chrome/browser/themes/theme_properties.h"
#include "chrome/browser/themes/theme_service.h"
#include "chrome/browser/themes/theme_service_factory.h"
#include "chrome/common/search/generated_colors_info.h"
#include "chrome/common/themes/autogenerated_theme_util.h"
#include "content/public/browser/notification_service.h"
#include "content/public/browser/notification_source.h"
#include "content/public/browser/web_contents.h"
#include "extensions/browser/extension_registry.h"
#include "extensions/common/extension.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/webui/resources/cr_components/customize_themes/customize_themes.mojom.h"

ChromeCustomizeThemesHandler::ChromeCustomizeThemesHandler(
    mojo::PendingRemote<customize_themes::mojom::CustomizeThemesClient>
        pending_client,
    mojo::PendingReceiver<customize_themes::mojom::CustomizeThemesHandler>
        pending_handler,
    content::WebContents* web_contents,
    Profile* profile)
    : remote_client_(std::move(pending_client)),
      receiver_(this, std::move(pending_handler)),
      web_contents_(web_contents),
      profile_(profile),
      chrome_colors_service_(
          chrome_colors::ChromeColorsFactory::GetForProfile(profile_)),
      theme_service_(ThemeServiceFactory::GetForProfile(profile_)) {
  CHECK(web_contents_);
  CHECK(profile_);
  CHECK(chrome_colors_service_);
  CHECK(theme_service_);
  notification_registrar_.Add(this, chrome::NOTIFICATION_BROWSER_THEME_CHANGED,
                              content::NotificationService::AllSources());
}

ChromeCustomizeThemesHandler::~ChromeCustomizeThemesHandler() {
  // Revert any unconfirmed theme changes.
  chrome_colors_service_->RevertThemeChangesForTab(web_contents_);
}

void ChromeCustomizeThemesHandler::ApplyAutogeneratedTheme(
    const SkColor& frame_color) {
  chrome_colors_service_->ApplyAutogeneratedTheme(frame_color, web_contents_);
}

void ChromeCustomizeThemesHandler::ApplyDefaultTheme() {
  chrome_colors_service_->ApplyDefaultTheme(web_contents_);
}

void ChromeCustomizeThemesHandler::ApplyChromeTheme(int32_t id) {
  auto* begin = std::begin(chrome_colors::kGeneratedColorsInfo);
  auto* end = std::end(chrome_colors::kGeneratedColorsInfo);
  auto* result = std::find_if(begin, end,
                              [id](const chrome_colors::ColorInfo& color_info) {
                                return color_info.id == id;
                              });
  if (result == end)
    return;
  chrome_colors_service_->ApplyAutogeneratedTheme(result->color, web_contents_);
}

void ChromeCustomizeThemesHandler::InitializeTheme() {
  UpdateTheme();
}

void ChromeCustomizeThemesHandler::GetChromeThemes(
    GetChromeThemesCallback callback) {
  std::vector<customize_themes::mojom::ChromeThemePtr> themes;
  for (const auto& color_info : chrome_colors::kGeneratedColorsInfo) {
    auto theme_colors = GetAutogeneratedThemeColors(color_info.color);
    auto theme = customize_themes::mojom::ChromeTheme::New();
    theme->id = color_info.id;
    theme->label = l10n_util::GetStringUTF8(color_info.label_id);
    auto colors = customize_themes::mojom::ThemeColors::New();
    colors->frame = theme_colors.frame_color;
    colors->active_tab = theme_colors.active_tab_color;
    colors->active_tab_text = theme_colors.active_tab_text_color;
    theme->colors = std::move(colors);
    themes.push_back(std::move(theme));
  }
  std::move(callback).Run(std::move(themes));
}

void ChromeCustomizeThemesHandler::ConfirmThemeChanges() {
  chrome_colors_service_->ConfirmThemeChanges();
}

void ChromeCustomizeThemesHandler::RevertThemeChanges() {
  chrome_colors_service_->RevertThemeChanges();
}

void ChromeCustomizeThemesHandler::Observe(
    int type,
    const content::NotificationSource& source,
    const content::NotificationDetails& details) {
  DCHECK_EQ(type, chrome::NOTIFICATION_BROWSER_THEME_CHANGED);
  UpdateTheme();
}

void ChromeCustomizeThemesHandler::UpdateTheme() {
  auto theme = customize_themes::mojom::Theme::New();

  const ui::ThemeProvider& theme_provider =
      ThemeService::GetThemeProviderForProfile(profile_);

  if (theme_service_->UsingDefaultTheme() ||
      theme_service_->UsingSystemTheme()) {
    theme->type = customize_themes::mojom::ThemeType::kDefault;
    theme->info = customize_themes::mojom::ThemeInfo::NewChromeThemeId(-1);
  } else if (theme_service_->UsingExtensionTheme()) {
    theme->type = customize_themes::mojom::ThemeType::kThirdParty;
    auto info = customize_themes::mojom::ThirdPartyThemeInfo::New();
    const extensions::Extension* theme_extension =
        extensions::ExtensionRegistry::Get(profile_)
            ->enabled_extensions()
            .GetByID(theme_service_->GetThemeID());
    if (theme_extension) {
      info->id = theme_extension->id();
      info->name = theme_extension->name();
    }
    theme->info = customize_themes::mojom::ThemeInfo::NewThirdPartyThemeInfo(
        std::move(info));
  } else {
    DCHECK(theme_service_->UsingAutogeneratedTheme());
    int color_id = chrome_colors::ChromeColorsService::GetColorId(
        theme_service_->GetAutogeneratedThemeColor());
    if (color_id > 0) {
      theme->type = customize_themes::mojom::ThemeType::kChrome;
      theme->info =
          customize_themes::mojom::ThemeInfo::NewChromeThemeId(color_id);
    } else {
      theme->type = customize_themes::mojom::ThemeType::kAutogenerated;
      auto theme_colors = customize_themes::mojom::ThemeColors::New();
      theme_colors->frame =
          theme_provider.GetColor(ThemeProperties::COLOR_FRAME_ACTIVE);
      theme_colors->active_tab =
          theme_provider.GetColor(ThemeProperties::COLOR_NTP_BACKGROUND);
      theme_colors->active_tab_text =
          theme_provider.GetColor(ThemeProperties::COLOR_NTP_TEXT);
      theme->info =
          customize_themes::mojom::ThemeInfo::NewAutogeneratedThemeColors(
              std::move(theme_colors));
    }
  }

  remote_client_->SetTheme(std::move(theme));
}
