// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/plugin_vm/plugin_vm_uninstaller_notification.h"

#include "ash/public/cpp/notification_utils.h"
#include "base/memory/weak_ptr.h"
#include "base/strings/string16.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "chrome/app/vector_icons/vector_icons.h"
#include "chrome/browser/notifications/notification_display_service.h"
#include "chrome/grit/generated_resources.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/message_center/public/cpp/message_center_constants.h"

namespace {

constexpr char kNotifierPluginVmUninstallOperation[] =
    "plugin_vm.uninstall_operation";

int next_notification_id_ = 0;

std::string GetUniqueNotificationId() {
  return base::StringPrintf("plugin_vm_uninstaller_notification_%d",
                            next_notification_id_++);
}

base::string16 PluginVmAppName() {
  return l10n_util::GetStringUTF16(IDS_PLUGIN_VM_APP_NAME);
}

}  // namespace

PluginVmUninstallerNotification::PluginVmUninstallerNotification(
    Profile* profile)
    : profile_(profile) {
  message_center::RichNotificationData rich_notification_data;
  rich_notification_data.vector_small_image = &kNotificationPluginVmIcon;
  rich_notification_data.accent_color = ash::kSystemNotificationColorNormal;
  rich_notification_data.pinned = true;
  rich_notification_data.never_timeout = true;

  base::string16 app_name = PluginVmAppName();
  notification_ = std::make_unique<message_center::Notification>(
      message_center::NOTIFICATION_TYPE_PROGRESS, GetUniqueNotificationId(),
      l10n_util::GetStringFUTF16(
          IDS_PLUGIN_VM_REMOVING_NOTIFICATION_IN_PROGRESS_MESSAGE,
          app_name),     // title
      base::string16(),  // message
      gfx::Image(),      // icon
      app_name,
      GURL(),  // origin_url
      message_center::NotifierId(message_center::NotifierType::SYSTEM_COMPONENT,
                                 kNotifierPluginVmUninstallOperation),
      rich_notification_data,
      base::MakeRefCounted<message_center::NotificationDelegate>());
  notification_->set_progress(-1);

  ForceRedisplay();
}

PluginVmUninstallerNotification::~PluginVmUninstallerNotification() = default;

void PluginVmUninstallerNotification::SetFailed(FailedReason reason) {
  base::string16 app_name = PluginVmAppName();
  base::string16 message;
  if (reason == FailedReason::kStopVmFailed) {
    message = l10n_util::GetStringFUTF16(
        IDS_PLUGIN_VM_SHUTDOWN_WINDOWS_TO_UNINSTALL_MESSAGE, app_name);
  }

  notification_->set_type(message_center::NOTIFICATION_TYPE_SIMPLE);
  notification_->set_title(l10n_util::GetStringFUTF16(
      IDS_PLUGIN_VM_REMOVING_NOTIFICATION_FAILED_MESSAGE, app_name));
  notification_->set_message(message);
  notification_->set_pinned(false);
  notification_->set_never_timeout(false);
  notification_->set_accent_color(ash::kSystemNotificationColorCriticalWarning);

  ForceRedisplay();
}

void PluginVmUninstallerNotification::SetCompleted() {
  notification_->set_type(message_center::NOTIFICATION_TYPE_SIMPLE);
  notification_->set_title(l10n_util::GetStringFUTF16(
      IDS_PLUGIN_VM_REMOVING_NOTIFICATION_COMPLETE_MESSAGE, PluginVmAppName()));
  notification_->set_pinned(false);
  notification_->set_never_timeout(false);

  ForceRedisplay();
}

void PluginVmUninstallerNotification::ForceRedisplay() {
  NotificationDisplayService::GetForProfile(profile_)->Display(
      NotificationHandler::Type::TRANSIENT, *notification_,
      /*metadata=*/nullptr);
}
