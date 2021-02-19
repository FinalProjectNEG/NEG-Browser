// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_THEMES_THEME_SERVICE_H_
#define CHROME_BROWSER_THEMES_THEME_SERVICE_H_

#include <map>
#include <memory>
#include <string>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/scoped_observer.h"
#include "base/task/cancelable_task_tracker.h"
#include "chrome/browser/themes/theme_helper.h"
#include "chrome/common/buildflags.h"
#include "components/keyed_service/core/keyed_service.h"
#include "extensions/buildflags/buildflags.h"
#include "extensions/common/extension_id.h"
#include "ui/base/theme_provider.h"
#include "ui/native_theme/native_theme.h"
#include "ui/native_theme/native_theme_observer.h"

class BrowserThemePack;
class CustomThemeSupplier;
class ThemeSyncableService;
class Profile;

namespace extensions {
class Extension;
}

namespace theme_service_internal {
class ThemeServiceTest;
}

class BrowserThemeProviderDelegate {
 public:
  virtual const CustomThemeSupplier* GetThemeSupplier() const = 0;
};

class ThemeService : public KeyedService,
                     public ui::NativeThemeObserver,
                     public BrowserThemeProviderDelegate {
 public:
  // This class keeps track of the number of existing |ThemeReinstaller|
  // objects. When that number reaches 0 then unused themes will be deleted.
  class ThemeReinstaller {
   public:
    ThemeReinstaller(Profile* profile, base::OnceClosure installer);
    ~ThemeReinstaller();

    void Reinstall();

   private:
    base::OnceClosure installer_;
    ThemeService* const theme_service_;

    DISALLOW_COPY_AND_ASSIGN(ThemeReinstaller);
  };

  // Constant ID to use for all autogenerated themes.
  static const char kAutogeneratedThemeID[];

  // Creates a ThemeProvider with a custom theme supplier specified via
  // |delegate|. The return value must not outlive |profile|'s ThemeService.
  static std::unique_ptr<ui::ThemeProvider> CreateBoundThemeProvider(
      Profile* profile,
      BrowserThemeProviderDelegate* delegate);

  explicit ThemeService(Profile* profile, const ThemeHelper& theme_helper);
  ~ThemeService() override;

  void Init();

  // KeyedService:
  void Shutdown() override;

  // Overridden from ui::NativeThemeObserver:
  void OnNativeThemeUpdated(ui::NativeTheme* observed_theme) override;

  // Overridden from BrowserThemeProviderDelegate:
  const CustomThemeSupplier* GetThemeSupplier() const override;

  // Set the current theme to the theme defined in |extension|.
  // |extension| must already be added to this profile's
  // ExtensionService.
  void SetTheme(const extensions::Extension* extension);

  // Similar to SetTheme, but doesn't show an undo infobar.
  void RevertToExtensionTheme(const std::string& extension_id);

  // Reset the theme to default.
  virtual void UseDefaultTheme();

  // Set the current theme to the system theme. On some platforms, the system
  // theme is the default theme.
  virtual void UseSystemTheme();

  // Returns true if the default theme and system theme are not the same on
  // this platform.
  virtual bool IsSystemThemeDistinctFromDefaultTheme() const;

  // Forwards to ThemeProviderBase::IsDefaultTheme().
  // Virtual for testing.
  virtual bool UsingDefaultTheme() const;

  // Whether we are using the system theme. On GTK, the system theme is the GTK
  // theme, not the "Classic" theme.
  virtual bool UsingSystemTheme() const;

  // Forwards to ThemeProviderBase::IsExtensionTheme().
  // Virtual for testing.
  virtual bool UsingExtensionTheme() const;

  // Forwards to ThemeProviderBase::IsAutogeneratedTheme().
  // Virtual for testing.
  virtual bool UsingAutogeneratedTheme() const;

  // Gets the id of the last installed theme. (The theme may have been further
  // locally customized.)
  virtual std::string GetThemeID() const;

  // Uninstall theme extensions which are no longer in use.
  void RemoveUnusedThemes();

  // Returns the syncable service for syncing theme. The returned service is
  // owned by |this| object.
  virtual ThemeSyncableService* GetThemeSyncableService() const;

  // Gets the ThemeProvider for |profile|. This will be different for an
  // incognito profile and its original profile, even though both profiles use
  // the same ThemeService.
  static const ui::ThemeProvider& GetThemeProviderForProfile(Profile* profile);

  // Builds an autogenerated theme from a given |color| and applies it.
  virtual void BuildAutogeneratedThemeFromColor(SkColor color);

  // Returns the theme color for an autogenerated theme.
  virtual SkColor GetAutogeneratedThemeColor() const;

  // Returns |ThemeService::ThemeReinstaller| for the current theme.
  std::unique_ptr<ThemeService::ThemeReinstaller>
  BuildReinstallerForCurrentTheme();

  const ThemeHelper& theme_helper_for_testing() const { return theme_helper_; }

  // Don't create "Cached Theme.pak" in the extension directory, for testing.
  static void DisableThemePackForTesting();

 protected:
  // Set a custom default theme instead of the normal default theme.
  virtual void SetCustomDefaultTheme(
      scoped_refptr<CustomThemeSupplier> theme_supplier);

  // Returns true if the ThemeService should use the system theme on startup.
  virtual bool ShouldInitWithSystemTheme() const;

  // Clears all the override fields and saves the dictionary.
  virtual void ClearAllThemeData();

  // Initialize current theme state data from preferences.
  virtual void InitFromPrefs();

  // Let all the browser views know that themes have changed.
  virtual void NotifyThemeChanged();

  // If there is an inconsistency in preferences, change preferences to a
  // consistent state.
  virtual void FixInconsistentPreferencesIfNeeded();

  Profile* profile() const { return profile_; }

  void set_ready() { ready_ = true; }

  // True if the theme service is ready to be used.
  // TODO(pkotwicz): Add DCHECKS to the theme service's getters once
  // ThemeSource no longer uses the ThemeService when it is not ready.
  bool ready_ = false;

 private:
  // This class implements ui::ThemeProvider on behalf of ThemeHelper and
  // keeps track of the incognito state and CustemThemeSupplier for the calling
  // code.
  class BrowserThemeProvider : public ui::ThemeProvider {
   public:
    BrowserThemeProvider(const ThemeHelper& theme_helper,
                         bool incognito,
                         const BrowserThemeProviderDelegate* delegate);
    ~BrowserThemeProvider() override;

    // Overridden from ui::ThemeProvider:
    gfx::ImageSkia* GetImageSkiaNamed(int id) const override;
    SkColor GetColor(int original_id) const override;
    color_utils::HSL GetTint(int original_id) const override;
    int GetDisplayProperty(int id) const override;
    bool ShouldUseNativeFrame() const override;
    bool HasCustomImage(int id) const override;
    bool HasCustomColor(int id) const override;
    base::RefCountedMemory* GetRawData(int id, ui::ScaleFactor scale_factor)
        const override;

   private:
    const CustomThemeSupplier* GetThemeSupplier() const;

    const ThemeHelper& theme_helper_;
    bool incognito_;
    const BrowserThemeProviderDelegate* delegate_;

    DISALLOW_COPY_AND_ASSIGN(BrowserThemeProvider);
  };
  friend class BrowserThemeProvider;
  friend class theme_service_internal::ThemeServiceTest;

  // virtual for testing.
  virtual void DoSetTheme(const extensions::Extension* extension,
                          bool suppress_infobar);


  // Called when the extension service is ready.
  void OnExtensionServiceReady();

  // Migrate the theme to the new theme pack schema by recreating the data pack
  // from the extension.
  void MigrateTheme();

  // Replaces the current theme supplier with a new one and calls
  // StopUsingTheme() or StartUsingTheme() as appropriate.
  void SwapThemeSupplier(scoped_refptr<CustomThemeSupplier> theme_supplier);

  // Implementation of SetTheme() (and the fallback from InitFromPrefs() in
  // case we don't have a theme pack). |new_theme| indicates whether this is a
  // newly installed theme or a migration.
  void BuildFromExtension(const extensions::Extension* extension,
                          bool new_theme);

  // Callback when |pack| has finished or failed building.
  void OnThemeBuiltFromExtension(const extensions::ExtensionId& extension_id,
                                 scoped_refptr<BrowserThemePack> pack,
                                 bool new_theme);

#if BUILDFLAG(ENABLE_SUPERVISED_USERS)
  // Returns true if the profile belongs to a supervised user.
  bool IsSupervisedUser() const;

  // Sets the current theme to the supervised user theme. Should only be used
  // for supervised user profiles.
  void SetSupervisedUserTheme();
#endif

  // Functions that modify theme prefs.
  void ClearThemePrefs();
  void SetThemePrefsForExtension(const extensions::Extension* extension);
  void SetThemePrefsForColor(SkColor color);

  bool DisableExtension(const std::string& extension_id);

  Profile* profile_;

  const ThemeHelper& theme_helper_;
  scoped_refptr<CustomThemeSupplier> theme_supplier_;

  // The id of the theme extension which has just been installed but has not
  // been loaded yet. The theme extension with |installed_pending_load_id_| may
  // never be loaded if the install is due to updating a disabled theme.
  // |pending_install_id_| should be set to |kDefaultThemeID| if there are no
  // recently installed theme extensions
  std::string installed_pending_load_id_ = ThemeHelper::kDefaultThemeID;

  // The number of infobars currently displayed.
  int number_of_reinstallers_ = 0;

  std::unique_ptr<ThemeSyncableService> theme_syncable_service_;

#if BUILDFLAG(ENABLE_EXTENSIONS)
  class ThemeObserver;
  std::unique_ptr<ThemeObserver> theme_observer_;
#endif

  BrowserThemeProvider original_theme_provider_;
  BrowserThemeProvider incognito_theme_provider_;

  // Allows us to cancel building a theme pack from an extension.
  base::CancelableTaskTracker build_extension_task_tracker_;

  // The ID of the theme that's currently being built on a different thread.
  // We hold onto this just to be sure not to uninstall the extension view
  // RemoveUnusedThemes while it's still being built.
  std::string building_extension_id_;

  ScopedObserver<ui::NativeTheme, ui::NativeThemeObserver>
      native_theme_observer_{this};

  base::WeakPtrFactory<ThemeService> weak_ptr_factory_{this};

  DISALLOW_COPY_AND_ASSIGN(ThemeService);
};

#endif  // CHROME_BROWSER_THEMES_THEME_SERVICE_H_
