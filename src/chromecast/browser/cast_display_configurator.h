// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMECAST_BROWSER_CAST_DISPLAY_CONFIGURATOR_H_
#define CHROMECAST_BROWSER_CAST_DISPLAY_CONFIGURATOR_H_

#include <memory>
#include <vector>

#include "base/containers/flat_map.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "ui/display/display.h"
#include "ui/display/types/display_configuration_params.h"
#include "ui/display/types/native_display_delegate.h"
#include "ui/display/types/native_display_observer.h"

namespace display {
class DisplayMode;
class DisplaySnapshot;
struct GammaRampRGBEntry;
}  // namespace display

namespace gfx {
class Point;
}  // namespace gfx

namespace chromecast {
class CastScreen;

namespace shell {
class CastTouchDeviceManager;

// The CastDisplayConfigurator class ensures native displays are initialized and
// configured properly on platforms that need that (e.g. GBM/DRM graphics via
// OzonePlatformGbm on odroid). But OzonePlatformCast, used by most Cast
// devices, relies on the platform code (outside of cast_shell) to initialize
// displays and exposes only a FakeDisplayDelegate. So CastDisplayConfigurator
// doesn't really do anything when using OzonePlatformCast.
class CastDisplayConfigurator : public display::NativeDisplayObserver {
 public:
  explicit CastDisplayConfigurator(CastScreen* screen);
  ~CastDisplayConfigurator() override;

  // display::NativeDisplayObserver implementation
  void OnConfigurationChanged() override;
  void OnDisplaySnapshotsInvalidated() override;

  void EnableDisplay(display::ConfigureCallback callback);
  void DisableDisplay(display::ConfigureCallback callback);

  void ConfigureDisplayFromCommandLine();
  void SetColorMatrix(const std::vector<float>& color_matrix);
  void SetGammaCorrection(
      const std::vector<display::GammaRampRGBEntry>& degamma_lut,
      const std::vector<display::GammaRampRGBEntry>& gamma_lut);

 private:
  void ForceInitialConfigure();
  void OnDisplaysAcquired(
      bool force_initial_configure,
      const std::vector<display::DisplaySnapshot*>& displays);
  void OnDisplayConfigured(display::DisplaySnapshot* display,
                           const display::DisplayMode* mode,
                           const gfx::Point& origin,
                           const base::flat_map<int64_t, bool>& statuses);
  void UpdateScreen(int64_t display_id,
                    const gfx::Rect& bounds,
                    float device_scale_factor,
                    display::Display::Rotation rotation);

  std::unique_ptr<display::NativeDisplayDelegate> delegate_;
  std::unique_ptr<CastTouchDeviceManager> touch_device_manager_;
  display::DisplaySnapshot* display_;
  CastScreen* const cast_screen_;

  base::WeakPtrFactory<CastDisplayConfigurator> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(CastDisplayConfigurator);
};

}  // namespace shell
}  // namespace chromecast

#endif  // CHROMECAST_BROWSER_CAST_DISPLAY_CONFIGURATOR_H_
