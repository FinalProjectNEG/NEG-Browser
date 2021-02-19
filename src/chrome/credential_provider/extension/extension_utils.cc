// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/credential_provider/extension/extension_utils.h"

#include "chrome/credential_provider/extension/extension_strings.h"
#include "chrome/credential_provider/extension/os_service_manager.h"
#include "chrome/credential_provider/extension/scoped_handle.h"
#include "chrome/credential_provider/gaiacp/logging.h"
#include "chrome/credential_provider/gaiacp/reg_utils.h"

namespace credential_provider {

namespace extension {

DWORD GetGCPWExtensionServiceStatus(SERVICE_STATUS* service_status) {
  DCHECK(service_status);

  credential_provider::extension::OSServiceManager* service_manager =
      credential_provider::extension::OSServiceManager::Get();
  SERVICE_STATUS internal_service_status;
  DWORD error_code =
      service_manager->GetServiceStatus(&internal_service_status);
  if (error_code != ERROR_SUCCESS) {
    LOGFN(ERROR) << "service_manager->GetServiceStatus failed win32="
                 << error_code;
    return error_code;
  }
  *service_status = internal_service_status;
  return ERROR_SUCCESS;
}

bool IsGCPWExtensionRunning() {
  SERVICE_STATUS service_status;
  DWORD error_code = GetGCPWExtensionServiceStatus(&service_status);
  if (error_code == ERROR_SUCCESS) {
    return service_status.dwCurrentState == SERVICE_RUNNING;
  }

  return false;
}

DWORD InstallGCPWExtension(const base::FilePath& extension_exe_path) {
  SERVICE_STATUS service_status;
  DWORD error_code = GetGCPWExtensionServiceStatus(&service_status);
  if (error_code != ERROR && error_code != ERROR_SERVICE_DOES_NOT_EXIST) {
    LOGFN(ERROR)
        << "service_manager->GetGCPWExtensionServiceStatus failed win32="
        << error_code;
    return error_code;
  }

  credential_provider::extension::OSServiceManager* service_manager =
      credential_provider::extension::OSServiceManager::Get();
  if (error_code == ERROR_SUCCESS) {
    if (service_status.dwCurrentState != SERVICE_STOPPED) {
      error_code = service_manager->ControlService(SERVICE_CONTROL_STOP,
                                                   &service_status);
      if (error_code != ERROR_SUCCESS) {
        LOGFN(ERROR) << "service_manager->ControlService failed win32="
                     << error_code;
        return error_code;
      }
    }

    error_code = service_manager->DeleteService();
    if (error_code != ERROR_SUCCESS) {
      LOGFN(ERROR) << "service_manager->DeleteService failed win32="
                   << error_code;
      return error_code;
    }
  }

  credential_provider::extension::ScopedScHandle sc_handle;
  error_code = service_manager->InstallService(extension_exe_path, &sc_handle);
  if (error_code != ERROR_SUCCESS) {
    LOGFN(ERROR) << "service_manager->InstallService failed win32="
                 << error_code;
    return error_code;
  }

  return ERROR_SUCCESS;
}

DWORD UninstallGCPWExtension() {
  credential_provider::extension::OSServiceManager* service_manager =
      credential_provider::extension::OSServiceManager::Get();
  SERVICE_STATUS service_status;
  DWORD error_code = service_manager->GetServiceStatus(&service_status);
  if (error_code != ERROR_SUCCESS &&
      error_code != ERROR_SERVICE_DOES_NOT_EXIST) {
    LOGFN(ERROR) << "service_manager->GetServiceStatus failed win32="
                 << error_code;
    return error_code;
  }

  if (error_code == ERROR_SUCCESS) {
    if (service_status.dwCurrentState != SERVICE_STOPPED) {
      error_code = service_manager->ControlService(SERVICE_CONTROL_STOP,
                                                   &service_status);
      if (error_code != ERROR_SUCCESS) {
        LOGFN(ERROR) << "service_manager->ControlService failed win32="
                     << error_code;
        return error_code;
      }
    }

    error_code = service_manager->DeleteService();
    if (error_code != ERROR_SUCCESS) {
      LOGFN(ERROR) << "service_manager->DeleteService failed win32="
                   << error_code;
      return error_code;
    }
  }

  return ERROR_SUCCESS;
}

bool IsGCPWExtensionEnabled() {
  return GetGlobalFlagOrDefault(extension::kEnableGCPWExtension, 1);
}

}  // namespace extension
}  // namespace credential_provider
