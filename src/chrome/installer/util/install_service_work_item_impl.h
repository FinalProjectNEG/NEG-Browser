// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_INSTALLER_UTIL_INSTALL_SERVICE_WORK_ITEM_IMPL_H_
#define CHROME_INSTALLER_UTIL_INSTALL_SERVICE_WORK_ITEM_IMPL_H_

#include <windows.h>

#include <vector>

#include "base/command_line.h"
#include "base/macros.h"
#include "base/strings/string16.h"
#include "base/win/scoped_handle.h"
#include "base/win/windows_types.h"
#include "chrome/installer/util/work_item_list.h"

namespace base {

class CommandLine;

}  // namespace base

namespace installer {

// Helper class for the implementation of InstallServiceWorkItem.
class InstallServiceWorkItemImpl {
 public:
  struct ServiceConfig {
    ServiceConfig();
    ServiceConfig(uint32_t service_type,
                  uint32_t service_start_type,
                  uint32_t service_error_control,
                  const base::string16& service_cmd_line,
                  const base::char16* dependencies_multi_sz);
    ServiceConfig(ServiceConfig&& rhs);

    ServiceConfig& operator=(ServiceConfig&& rhs) = default;

    ~ServiceConfig();

    bool is_valid;
    uint32_t type;
    uint32_t start_type;
    uint32_t error_control;
    base::string16 cmd_line;
    std::vector<base::char16> dependencies;

    DISALLOW_COPY_AND_ASSIGN(ServiceConfig);
  };

  InstallServiceWorkItemImpl(const base::string16& service_name,
                             const base::string16& display_name,
                             const base::CommandLine& service_cmd_line,
                             const base::string16& registry_path,
                             const std::vector<GUID>& clsids,
                             const std::vector<GUID>& iids);

  ~InstallServiceWorkItemImpl();

  bool DoImpl();
  void RollbackImpl();
  bool DeleteServiceImpl();

  // Member functions that help with service installation or upgrades.
  bool IsServiceCorrectlyConfigured(const ServiceConfig& config);
  bool DeleteCurrentService();

  // Helper functions for service install/upgrade/delete/rollback.
  bool OpenService();
  bool GetServiceConfig(ServiceConfig* config) const;

  // Stores in the registry a versioned service name generated by
  // GenerateVersionedServiceName().
  bool CreateAndSetServiceName() const;

  // Returns the versioned service name if one exists in the registry under the
  // named value service_name_. In other cases, it returns service_name_.
  base::string16 GetCurrentServiceName() const;

  // Returns a display name of the following format:
  // "Chrome Elevation Service (ChromeElevationService)"
  // or:
  // "Chrome Elevation Service (ChromeElevationService1d59511c58deaa8)"
  //
  // The "Chrome Elevation Service" fragment is the display_name_, and the
  // "ChromeElevationService1d59511c58deaa8" fragment is the versioned service
  // name returned from GetCurrentServiceName().
  base::string16 GetCurrentServiceDisplayName() const;

  // Copies and returns a vector containing a sequence of C-style strings
  // terminated with '\0\0'. Return an empty vector if the input is nullptr.
  static std::vector<base::char16> MultiSzToVector(
      const base::char16* multi_sz);

 private:
  class ScHandleTraits {
   public:
    using Handle = SC_HANDLE;

    static bool CloseHandle(SC_HANDLE handle) {
      return ::CloseServiceHandle(handle) != FALSE;
    }

    static bool IsHandleValid(SC_HANDLE handle) { return handle != nullptr; }

    static SC_HANDLE NullHandle() { return nullptr; }

   private:
    DISALLOW_IMPLICIT_CONSTRUCTORS(ScHandleTraits);
  };

  using ScopedScHandle =
      base::win::GenericScopedHandle<ScHandleTraits,
                                     base::win::DummyVerifierTraits>;

  // This is the core functionality for installing the Windows Service itself.
  bool DoInstallService();

  // This is the core functionality for COM registration for the Service.
  bool DoComRegistration();

  // Member functions that help with service installation or upgrades.
  bool InstallNewService();

  // Upgrades an existing service's configuration in-place. Returns true if the
  // service was already properly configured, or if it was successfully
  // upgraded; otherwise, returns false in case of any failure.
  // Side-effects of this function:
  //   * Saves the original service's config in |original_service_config_| if
  //     the new service configuration will be different.
  //     |original_service_config_| is used in rollback scenarios, specifically
  //     in ReinstallOriginalService() and RestoreOriginalServiceConfig().
  //   * Sets |rollback_existing_service_| to true if the service is
  //     successfully upgraded, which is used by RollbackImpl().
  bool UpgradeService();

  // Member functions that help with rollbacks.
  bool ReinstallOriginalService();
  bool RestoreOriginalServiceConfig();

  // Helper functions for service install/upgrade/delete/rollback.
  bool InstallService(const ServiceConfig& config);
  bool ChangeServiceConfig(const ServiceConfig& config);
  bool DeleteService(ScopedScHandle service) const;

  // Generates a versioned service name prefixed with service_name_ and suffixed
  // with the current system time in hexadecimal format.
  base::string16 GenerateVersionedServiceName() const;

  // Persists the given service name in the registry.
  bool SetServiceName(const base::string16& service_name) const;

  // The COM registration is done using a contained WorkItemList.
  std::unique_ptr<WorkItemList> com_registration_work_items_;

  // The service name, or in the case of a conflict, the prefix for the service
  // name.
  const base::string16 service_name_;

  // The service name displayed to the user.
  const base::string16 display_name_;

  // The desired service command line.
  const base::CommandLine service_cmd_line_;

  // The path under HKEY_LOCAL_MACHINE where the service persists information,
  // such as a versioned service name. For legacy reasons, this path is mapped
  // to the 32-bit view of the registry.
  const base::string16 registry_path_;

  // If COM CLSID/AppId registration is required, |clsids_| would be populated.
  const std::vector<GUID> clsids_;

  // If COM Interface/Typelib registration is required, |iids_| would be
  // populated.
  const std::vector<GUID> iids_;

  ScopedScHandle scm_;
  ScopedScHandle service_;

  // Rollback-specific data.

  // True if original_service_config_ and service_ are both valid, and the
  // former should be applied to the latter on rollback.
  bool rollback_existing_service_;

  // True if service_ represents a newly-installed service that is to be deleted
  // on rollback.
  bool rollback_new_service_;

  // The configuration of a pre-existing service on the machine that may have
  // been modified or deleted.
  ServiceConfig original_service_config_;

  // The service name prior to any modifications; may be either |service_name_|
  // or a value read from the registry.
  base::string16 original_service_name_;

  // True if a pre-existing service (named |original_service_name_|) could not
  // be deleted and still exists on rollback.
  bool original_service_still_exists_;

  DISALLOW_COPY_AND_ASSIGN(InstallServiceWorkItemImpl);
};

}  // namespace installer

#endif  // CHROME_INSTALLER_UTIL_INSTALL_SERVICE_WORK_ITEM_IMPL_H_
