// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/extensions/extension_enable_flow.h"

#include <memory>

#include "base/bind.h"
#include "chrome/browser/chrome_notification_types.h"
#include "chrome/browser/extensions/extension_service.h"
#include "chrome/browser/extensions/extension_util.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/profiles/profiles_state.h"
#include "chrome/browser/ui/extensions/extension_enable_flow_delegate.h"
#include "content/public/browser/notification_details.h"
#include "content/public/browser/notification_source.h"
#include "extensions/browser/extension_prefs.h"
#include "extensions/browser/extension_system.h"

#if !defined(OS_CHROMEOS)
#include "chrome/browser/ui/user_manager.h"
#endif  // !defined(OS_CHROMEOS)

#if BUILDFLAG(ENABLE_SUPERVISED_USERS)
#include "chrome/browser/supervised_user/supervised_user_service.h"
#include "chrome/browser/supervised_user/supervised_user_service_factory.h"
#include "extensions/browser/api/management/management_api.h"
#endif  // BUILDFLAG(ENABLE_SUPERVISED_USERS)

using extensions::Extension;

ExtensionEnableFlow::ExtensionEnableFlow(Profile* profile,
                                         const std::string& extension_id,
                                         ExtensionEnableFlowDelegate* delegate)
    : profile_(profile), extension_id_(extension_id), delegate_(delegate) {}

ExtensionEnableFlow::~ExtensionEnableFlow() = default;

void ExtensionEnableFlow::StartForWebContents(
    content::WebContents* parent_contents) {
  parent_contents_ = parent_contents;
  parent_window_ = nullptr;
  Run();
}

void ExtensionEnableFlow::StartForNativeWindow(
    gfx::NativeWindow parent_window) {
  parent_contents_ = nullptr;
  parent_window_ = parent_window;
  Run();
}

void ExtensionEnableFlow::Start() {
  Run();
}

void ExtensionEnableFlow::Run() {
  extensions::ExtensionService* service =
      extensions::ExtensionSystem::Get(profile_)->extension_service();
  extensions::ExtensionRegistry* registry =
      extensions::ExtensionRegistry::Get(profile_);
  const Extension* extension =
      registry->disabled_extensions().GetByID(extension_id_);
  if (!extension) {
    extension = registry->terminated_extensions().GetByID(extension_id_);
    // It's possible (though unlikely) the app could have been uninstalled since
    // the user clicked on it.
    if (!extension)
      return;
    // If the app was terminated, reload it first.
    service->ReloadExtension(extension_id_);

    // ReloadExtension reallocates the Extension object.
    extension = registry->disabled_extensions().GetByID(extension_id_);

    // |extension| could be nullptr for asynchronous load, such as the case of
    // an unpacked extension. Wait for the load to continue the flow.
    if (!extension) {
      StartObserving();
      return;
    }
  }

  CheckPermissionAndMaybePromptUser();
}

void ExtensionEnableFlow::CheckPermissionAndMaybePromptUser() {
  extensions::ExtensionSystem* system =
      extensions::ExtensionSystem::Get(profile_);
  extensions::ExtensionService* service = system->extension_service();
  extensions::ExtensionRegistry* registry =
      extensions::ExtensionRegistry::Get(profile_);
  const Extension* extension =
      registry->disabled_extensions().GetByID(extension_id_);

#if BUILDFLAG(ENABLE_SUPERVISED_USERS)
  extensions::SupervisedUserExtensionsDelegate*
      supervised_user_extensions_delegate =
          extensions::ManagementAPI::GetFactoryInstance()
              ->Get(profile_)
              ->GetSupervisedUserExtensionsDelegate();
  DCHECK(supervised_user_extensions_delegate);
  if (profile_->IsChild() && extension &&
      // Only ask for parent approval if the extension still requires approval.
      !supervised_user_extensions_delegate->IsExtensionAllowedByParent(
          *extension, profile_)) {
    // Either ask for parent permission or notify the child that their parent
    // has disabled this action.
    auto parent_permission_callback =
        base::BindOnce(&ExtensionEnableFlow::OnParentPermissionDialogDone,
                       weak_ptr_factory_.GetWeakPtr());
    auto error_callback =
        base::BindOnce(&ExtensionEnableFlow::OnBlockedByParentDialogDone,
                       weak_ptr_factory_.GetWeakPtr());
    supervised_user_extensions_delegate->PromptForParentPermissionOrShowError(
        *extension, profile_, parent_contents_,
        std::move(parent_permission_callback), std::move(error_callback));
    return;
  }
#endif  // BUILDFLAG(ENABLE_SUPERVISED_USERS)

  bool abort = !extension ||
               // The extension might be force-disabled by policy.
               system->management_policy()->MustRemainDisabled(
                   extension, nullptr, nullptr);
  if (abort) {
    delegate_->ExtensionEnableFlowAborted(
        /*user_initiated=*/false);  // |delegate_| may delete us.
    return;
  }

  if (profiles::IsProfileLocked(profile_->GetPath())) {
#if !defined(OS_CHROMEOS)
    UserManager::Show(base::FilePath(),
                      profiles::USER_MANAGER_SELECT_PROFILE_NO_ACTION);
#endif  // !defined(OS_CHROMEOS)
    return;
  }

  extensions::ExtensionPrefs* prefs = extensions::ExtensionPrefs::Get(profile_);
  if (!prefs->DidExtensionEscalatePermissions(extension_id_)) {
    // Enable the extension immediately if its privileges weren't escalated.
    // This is a no-op if the extension was previously terminated.
    service->EnableExtension(extension_id_);

    DCHECK(service->IsExtensionEnabled(extension_id_));
    delegate_->ExtensionEnableFlowFinished();  // |delegate_| may delete us.
    return;
  }

  CreatePrompt();
  ExtensionInstallPrompt::PromptType type =
      ExtensionInstallPrompt::GetReEnablePromptTypeForExtension(profile_,
                                                                extension);
  prompt_->ShowDialog(base::Bind(&ExtensionEnableFlow::InstallPromptDone,
                                 weak_ptr_factory_.GetWeakPtr()),
                      extension, nullptr,
                      std::make_unique<ExtensionInstallPrompt::Prompt>(type),
                      ExtensionInstallPrompt::GetDefaultShowDialogCallback());
}

void ExtensionEnableFlow::CreatePrompt() {
  prompt_.reset(parent_contents_
                    ? new ExtensionInstallPrompt(parent_contents_)
                    : new ExtensionInstallPrompt(profile_, nullptr));
}

#if BUILDFLAG(ENABLE_SUPERVISED_USERS)
void ExtensionEnableFlow::OnParentPermissionDialogDone(
    extensions::SupervisedUserExtensionsDelegate::ParentPermissionDialogResult
        result) {
  switch (result) {
    case extensions::SupervisedUserExtensionsDelegate::
        ParentPermissionDialogResult::kParentPermissionReceived:
      EnableExtension();
      break;
    case extensions::SupervisedUserExtensionsDelegate::
        ParentPermissionDialogResult::kParentPermissionCanceled:
      delegate_->ExtensionEnableFlowAborted(
          /*user_initiated=*/true);  // |delegate_| may delete us.
      break;
    case extensions::SupervisedUserExtensionsDelegate::
        ParentPermissionDialogResult::kParentPermissionFailed:
      delegate_->ExtensionEnableFlowAborted(
          /*user_initiated=*/false);  // |delegate_| may delete us.
      break;
  }
}

void ExtensionEnableFlow::OnBlockedByParentDialogDone() {
  delegate_->ExtensionEnableFlowAborted(
      /*user_initiated=*/false);  // |delegate_| may delete us.
}
#endif  // BUILDFLAG(ENABLE_SUPERVISED_USERS)

void ExtensionEnableFlow::StartObserving() {
  extension_registry_observer_.Add(
      extensions::ExtensionRegistry::Get(profile_));
  registrar_.Add(this,
                 extensions::NOTIFICATION_EXTENSION_LOAD_ERROR,
                 content::Source<Profile>(profile_));
}

void ExtensionEnableFlow::StopObserving() {
  registrar_.RemoveAll();
  extension_registry_observer_.RemoveAll();
}

void ExtensionEnableFlow::Observe(int type,
                                  const content::NotificationSource& source,
                                  const content::NotificationDetails& details) {
  DCHECK_EQ(extensions::NOTIFICATION_EXTENSION_LOAD_ERROR, type);
  StopObserving();
  delegate_->ExtensionEnableFlowAborted(
      /*user_initiated=*/false);  // |delegate_| may delete us.
}

void ExtensionEnableFlow::OnExtensionLoaded(
    content::BrowserContext* browser_context,
    const Extension* extension) {
  if (extension->id() == extension_id_) {
    StopObserving();
    CheckPermissionAndMaybePromptUser();
  }
}

void ExtensionEnableFlow::OnExtensionUninstalled(
    content::BrowserContext* browser_context,
    const Extension* extension,
    extensions::UninstallReason reason) {
  if (extension->id() == extension_id_) {
    StopObserving();
    delegate_->ExtensionEnableFlowAborted(
        /*user_initiated=*/false);  // |delegate_| may delete us.
  }
}

void ExtensionEnableFlow::EnableExtension() {
  extensions::ExtensionService* service =
      extensions::ExtensionSystem::Get(profile_)->extension_service();
  extensions::ExtensionRegistry* registry =
      extensions::ExtensionRegistry::Get(profile_);
  // The extension can be uninstalled in another window while the UI was
  // showing. Treat it as a cancellation and notify |delegate_|.
  const Extension* extension =
      registry->disabled_extensions().GetByID(extension_id_);
  if (!extension) {
    delegate_->ExtensionEnableFlowAborted(
        /*user_initiated=*/true);  // |delegate_| may delete us.
    return;
  }
#if BUILDFLAG(ENABLE_SUPERVISED_USERS)
  if (profile_->IsChild()) {
    // We need to add parent approval first.
    SupervisedUserService* supervised_user_service =
        SupervisedUserServiceFactory::GetForProfile(profile_);
    supervised_user_service->AddExtensionApproval(*extension);
    supervised_user_service->RecordExtensionEnablementUmaMetrics(
        /*enabled=*/true);
  }
#endif  // BUILDFLAG(ENABLE_SUPERVISED_USERS)
  service->GrantPermissionsAndEnableExtension(extension);

  DCHECK(service->IsExtensionEnabled(extension_id_));
  delegate_->ExtensionEnableFlowFinished();  // |delegate_| may delete us.
}

void ExtensionEnableFlow::InstallPromptDone(
    ExtensionInstallPrompt::Result result) {
  if (result == ExtensionInstallPrompt::Result::ACCEPTED) {
    EnableExtension();
  } else {
    delegate_->ExtensionEnableFlowAborted(/*user_initiated=*/
                                          result == ExtensionInstallPrompt::
                                                        Result::USER_CANCELED);
    // |delegate_| may delete us.
  }
}
