// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/payments/installed_payment_apps_finder_impl.h"

#include "base/bind.h"
#include "base/supports_user_data.h"
#include "content/browser/payments/payment_app_context_impl.h"
#include "content/browser/service_worker/service_worker_context_wrapper.h"
#include "content/browser/storage_partition_impl.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/permission_controller.h"
#include "content/public/browser/permission_type.h"
#include "third_party/blink/public/mojom/permissions/permission_status.mojom.h"

namespace content {
namespace {

const char kInstalledPaymentAppsFinderImplName[] =
    "installed_payment_apps_finder_impl";

void DidGetAllPaymentAppsOnCoreThread(
    InstalledPaymentAppsFinder::GetAllPaymentAppsCallback callback,
    InstalledPaymentAppsFinder::PaymentApps apps) {
  GetUIThreadTaskRunner({})->PostTask(
      FROM_HERE, base::BindOnce(std::move(callback), std::move(apps)));
}

void GetAllPaymentAppsOnCoreThread(
    scoped_refptr<PaymentAppContextImpl> payment_app_context,
    InstalledPaymentAppsFinder::GetAllPaymentAppsCallback callback) {
  DCHECK_CURRENTLY_ON(ServiceWorkerContext::GetCoreThreadId());

  payment_app_context->payment_app_database()->ReadAllPaymentApps(
      base::BindOnce(&DidGetAllPaymentAppsOnCoreThread, std::move(callback)));
}

}  // namespace

// static
base::WeakPtr<InstalledPaymentAppsFinder>
InstalledPaymentAppsFinder::GetInstance(BrowserContext* context) {
  return InstalledPaymentAppsFinderImpl::GetInstance(context);
}

// static
base::WeakPtr<InstalledPaymentAppsFinderImpl>
InstalledPaymentAppsFinderImpl::GetInstance(BrowserContext* context) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);

  base::WeakPtr<InstalledPaymentAppsFinderImpl> result;
  InstalledPaymentAppsFinderImpl* data =
      static_cast<InstalledPaymentAppsFinderImpl*>(
          context->GetUserData(kInstalledPaymentAppsFinderImplName));

  if (!data) {
    auto owned = base::WrapUnique(new InstalledPaymentAppsFinderImpl(context));
    result = owned->weak_ptr_factory_.GetWeakPtr();
    context->SetUserData(kInstalledPaymentAppsFinderImplName, std::move(owned));
  } else {
    result = data->weak_ptr_factory_.GetWeakPtr();
  }

  return result;
}

void InstalledPaymentAppsFinderImpl::GetAllPaymentApps(
    GetAllPaymentAppsCallback callback) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);

  StoragePartitionImpl* partition = static_cast<StoragePartitionImpl*>(
      BrowserContext::GetDefaultStoragePartition(browser_context_));
  scoped_refptr<PaymentAppContextImpl> payment_app_context =
      partition->GetPaymentAppContext();

  RunOrPostTaskOnThread(
      FROM_HERE, ServiceWorkerContext::GetCoreThreadId(),
      base::BindOnce(
          &GetAllPaymentAppsOnCoreThread, payment_app_context,
          base::BindOnce(
              &InstalledPaymentAppsFinderImpl::CheckPermissionForPaymentApps,
              weak_ptr_factory_.GetWeakPtr(), std::move(callback))));
}

void InstalledPaymentAppsFinderImpl::CheckPermissionForPaymentApps(
    GetAllPaymentAppsCallback callback,
    PaymentApps apps) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);

  PermissionController* permission_controller =
      BrowserContext::GetPermissionController(browser_context_);
  DCHECK(permission_controller);

  PaymentApps permitted_apps;
  for (auto& app : apps) {
    GURL origin = app.second->scope.GetOrigin();
    if (permission_controller->GetPermissionStatus(
            PermissionType::PAYMENT_HANDLER, origin, origin) ==
        blink::mojom::PermissionStatus::GRANTED) {
      permitted_apps[app.first] = std::move(app.second);
    }
  }

  std::move(callback).Run(std::move(permitted_apps));
}

InstalledPaymentAppsFinderImpl::InstalledPaymentAppsFinderImpl(
    BrowserContext* context)
    : browser_context_(context) {}

InstalledPaymentAppsFinderImpl::~InstalledPaymentAppsFinderImpl() = default;

}  // namespace content
