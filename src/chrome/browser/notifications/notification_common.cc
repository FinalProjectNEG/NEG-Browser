// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/notifications/notification_common.h"

#include "build/build_config.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/chrome_pages.h"
#include "chrome/browser/ui/scoped_tabbed_browser_displayer.h"
#include "content/public/browser/browser_context.h"
#include "ui/message_center/public/cpp/notifier_id.h"

NotificationCommon::Metadata::~Metadata() = default;

PersistentNotificationMetadata::PersistentNotificationMetadata() {
  type = NotificationHandler::Type::WEB_PERSISTENT;
}

PersistentNotificationMetadata::~PersistentNotificationMetadata() = default;

// static
const PersistentNotificationMetadata* PersistentNotificationMetadata::From(
    const Metadata* metadata) {
  if (!metadata || metadata->type != NotificationHandler::Type::WEB_PERSISTENT)
    return nullptr;

  return static_cast<const PersistentNotificationMetadata*>(metadata);
}

// static
void NotificationCommon::OpenNotificationSettings(Profile* profile,
                                                  const GURL& origin) {
// TODO(peter): Use the |origin| to direct the user to a more appropriate
// settings page to toggle permission.

#if defined(OS_ANDROID) || defined(OS_CHROMEOS)
  // Android settings are handled through Java. Chrome OS settings are handled
  // through the tray's setting panel.
  NOTREACHED();
#else
  chrome::ScopedTabbedBrowserDisplayer browser_displayer(profile);
  chrome::ShowContentSettingsExceptions(browser_displayer.browser(),
                                        ContentSettingsType::NOTIFICATIONS);
#endif
}
