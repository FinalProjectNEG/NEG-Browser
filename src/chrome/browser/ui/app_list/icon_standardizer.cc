// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/app_list/icon_standardizer.h"

#include "ui/gfx/image/image_skia.h"
#include "ui/gfx/image/image_skia_operations.h"

namespace app_list {

namespace {

constexpr float kCircleOutlineStrokeWidthRatio = 0.1f;

constexpr int kMinimumVisibleAlpha = 40;

constexpr float kCircleShapePixelDifferenceThreshold = 0.01f;

constexpr float kIconScaleToFit = 0.85f;

constexpr float kBackgroundCircleScale = 176.0f / 192.0f;

// Returns the bounding rect for the opaque part of the icon.
gfx::Rect GetVisibleIconBounds(const SkBitmap& bitmap) {
  const SkPixmap pixmap = bitmap.pixmap();

  bool const nativeColorType = pixmap.colorType() == kN32_SkColorType;

  const int width = pixmap.width();
  const int height = pixmap.height();

  // Overall bounds of the visible icon.
  int y_from = -1;
  int y_to = -1;
  int x_left = width;
  int x_right = -1;

  // Find bounding rect of the visible icon by going through all pixels one row
  // at a time and for each row find the first and the last non-transparent
  // pixel.
  for (int y = 0; y < height; y++) {
    const SkColor* nativeRow =
        nativeColorType
            ? reinterpret_cast<const SkColor*>(bitmap.getAddr32(0, y))
            : nullptr;
    bool does_row_have_visible_pixels = false;

    for (int x = 0; x < width; x++) {
      if (SkColorGetA(nativeRow ? nativeRow[x] : pixmap.getColor(x, y)) >
          kMinimumVisibleAlpha) {
        does_row_have_visible_pixels = true;
        x_left = std::min(x_left, x);
        break;
      }
    }

    // No visible pixels on this row.
    if (!does_row_have_visible_pixels)
      continue;

    for (int x = width - 1; x > 0; x--) {
      if (SkColorGetA(nativeRow ? nativeRow[x] : pixmap.getColor(x, y)) >
          kMinimumVisibleAlpha) {
        x_right = std::max(x_right, x);
        break;
      }
    }

    y_to = y;
    if (y_from == -1)
      y_from = y;
  }

  int visible_width = x_right - x_left + 1;
  int visible_height = y_to - y_from + 1;
  return gfx::Rect(x_left, y_from, visible_width, visible_height);
}

float GetDistanceBetweenPoints(gfx::PointF first_point,
                               gfx::PointF second_point) {
  float x_difference = first_point.x() - second_point.x();
  float y_difference = first_point.y() - second_point.y();
  return sqrt(x_difference * x_difference + y_difference * y_difference);
}

// Returns the distance for the farthest visible pixel away from the center of
// the icon.
float GetFarthestVisiblePointFromCenter(const SkBitmap& bitmap) {
  int width = bitmap.width();
  int height = bitmap.height();

  const SkPixmap pixmap = bitmap.pixmap();
  bool const nativeColorType = pixmap.colorType() == kN32_SkColorType;

  gfx::PointF center_point((width - 1) / 2.0f, (height - 1) / 2.0f);
  float max_distance = -1.0f;

  // Find the farthest visible pixel from the center by going through one row
  // at a time and for each row find the first and the last non-transparent
  // pixel and calculate its distance from the center.
  for (int y = 0; y < height; y++) {
    const SkColor* nativeRow =
        nativeColorType
            ? reinterpret_cast<const SkColor*>(bitmap.getAddr32(0, y))
            : nullptr;
    bool does_row_have_visible_pixels = false;

    for (int x = 0; x < width; x++) {
      if (SkColorGetA(nativeRow ? nativeRow[x] : pixmap.getColor(x, y)) >
          kMinimumVisibleAlpha) {
        gfx::PointF current_point(x, y);
        max_distance =
            std::max(GetDistanceBetweenPoints(current_point, center_point),
                     max_distance);

        does_row_have_visible_pixels = true;
        break;
      }
    }

    // No visible pixels on this row.
    if (!does_row_have_visible_pixels)
      continue;

    for (int x = width - 1; x > 0; x--) {
      if (SkColorGetA(nativeRow ? nativeRow[x] : pixmap.getColor(x, y)) >
          kMinimumVisibleAlpha) {
        gfx::PointF current_point(x, y);
        max_distance =
            std::max(GetDistanceBetweenPoints(current_point, center_point),
                     max_distance);

        break;
      }
    }
  }
  return (max_distance == -1.0f) ? (sqrt(width * width * 2)) : max_distance;
}

// Returns whether the shape of the icon is roughly circle shaped.
bool IsIconCircleShaped(const gfx::ImageSkia& image) {
  bool is_icon_already_circle_shaped = false;

  for (gfx::ImageSkiaRep rep : image.image_reps()) {
    SkBitmap bitmap(rep.GetBitmap());
    int width = bitmap.width();
    int height = bitmap.height();

    SkBitmap preview;
    preview.allocN32Pixels(width, height);
    preview.eraseColor(SK_ColorTRANSPARENT);

    // |preview| will be the original icon with all visible pixels colored red.
    for (int x = 0; x < width; x++) {
      for (int y = 0; y < height; y++) {
        const SkColor* src_color =
            reinterpret_cast<SkColor*>(bitmap.getAddr32(0, y));
        SkColor* preview_color =
            reinterpret_cast<SkColor*>(preview.getAddr32(0, y));

        SkColor target_color;

        if (SkColorGetA(src_color[x]) < 1) {
          target_color = SK_ColorTRANSPARENT;
        } else {
          target_color = SK_ColorRED;
        }

        preview_color[x] = target_color;
      }
    }

    gfx::Rect visible_preview_bounds = GetVisibleIconBounds(preview);
    float visible_icon_diagonal = std::sqrt(
        visible_preview_bounds.height() * visible_preview_bounds.height() +
        visible_preview_bounds.width() * visible_preview_bounds.width());

    float preview_diagonal = std::sqrt(preview.height() * preview.height() +
                                       preview.width() * preview.width());

    float scale = preview_diagonal / visible_icon_diagonal;

    gfx::Size scaled_icon_size =
        gfx::ScaleToRoundedSize(rep.pixel_size(), scale);

    // To detect a circle shaped icon of any size, resize and scale |preview| so
    // the visible icon bounds match the maximum width and height of the bitmap.
    const SkBitmap scaled_preview = skia::ImageOperations::Resize(
        preview, skia::ImageOperations::RESIZE_BEST, scaled_icon_size.width(),
        scaled_icon_size.height());

    preview.eraseColor(SK_ColorTRANSPARENT);
    SkCanvas canvas1(preview);
    canvas1.drawBitmap(scaled_preview, -visible_preview_bounds.x() * scale,
                       -visible_preview_bounds.y() * scale);

    // Use a canvas to perform XOR and DST_OUT operations, which should
    // generate a transparent bitmap for |preview| if the original icon is
    // shaped like a circle.
    SkCanvas canvas(preview);
    SkPaint paint_circle_mask;
    paint_circle_mask.setColor(SK_ColorBLUE);
    paint_circle_mask.setStyle(SkPaint::kFill_Style);
    paint_circle_mask.setAntiAlias(true);

    // XOR operation to remove a circle.
    paint_circle_mask.setBlendMode(SkBlendMode::kXor);
    canvas.drawCircle(SkPoint::Make(width / 2.0f, height / 2.0f), width / 2.0,
                      paint_circle_mask);

    SkPaint paint_outline;
    paint_outline.setColor(SK_ColorGREEN);
    paint_outline.setStyle(SkPaint::kStroke_Style);

    const float outline_stroke_width = width * kCircleOutlineStrokeWidthRatio;
    const float radius_offset = outline_stroke_width / 8.0f;

    paint_outline.setStrokeWidth(outline_stroke_width);
    paint_outline.setAntiAlias(true);

    // DST_OUT operation to remove an extra circle outline.
    paint_outline.setBlendMode(SkBlendMode::kDstOut);
    canvas.drawCircle(SkPoint::Make(width / 2.0f, height / 2.0f),
                      width / 2.0f + radius_offset, paint_outline);

    // Compute the total pixel difference between the circle mask and the
    // original icon.
    int total_pixel_difference = 0;
    for (int y = 0; y < preview.height(); ++y) {
      SkColor* src_color = reinterpret_cast<SkColor*>(preview.getAddr32(0, y));
      for (int x = 0; x < preview.width(); ++x) {
        if (SkColorGetA(src_color[x]) >= kMinimumVisibleAlpha)
          total_pixel_difference++;
      }
    }

    float percentage_diff_pixels =
        static_cast<float>(total_pixel_difference) / (width * height);

    // If the pixel difference between a circle and the original icon is small
    // enough, then the icon can be considered circle shaped.
    if (percentage_diff_pixels < kCircleShapePixelDifferenceThreshold)
      is_icon_already_circle_shaped = true;
  }

  return is_icon_already_circle_shaped;
}

// Returns an image with equal width and height. If necessary, padding is
// added to ensure the width and height are equal.
gfx::ImageSkia StandardizeSize(const gfx::ImageSkia& image) {
  gfx::ImageSkia final_image;

  for (gfx::ImageSkiaRep rep : image.image_reps()) {
    SkBitmap unscaled_bitmap(rep.GetBitmap());
    int width = unscaled_bitmap.width();
    int height = unscaled_bitmap.height();

    if (width == height)
      return image;

    int longest_side = std::max(width, height);

    SkBitmap final_bitmap;
    final_bitmap.allocN32Pixels(longest_side, longest_side);
    final_bitmap.eraseColor(SK_ColorTRANSPARENT);

    SkCanvas canvas(final_bitmap);
    canvas.drawBitmap(unscaled_bitmap, (longest_side - width) / 2,
                      (longest_side - height) / 2);

    final_image.AddRepresentation(gfx::ImageSkiaRep(final_bitmap, rep.scale()));
  }

  return final_image;
}

}  // namespace

gfx::ImageSkia CreateStandardIconImage(const gfx::ImageSkia& image) {
  gfx::ImageSkia final_image;
  gfx::ImageSkia standard_size_image = app_list::StandardizeSize(image);

  // If icon is already circle shaped, then return the original image and make
  // sure the image is scaled down if its icon size takes up too much space
  // within the bitmap.
  if (IsIconCircleShaped(standard_size_image)) {
    for (gfx::ImageSkiaRep rep : standard_size_image.image_reps()) {
      SkBitmap unscaled_bitmap(rep.GetBitmap());
      int width = unscaled_bitmap.width();
      int height = unscaled_bitmap.height();

      SkBitmap final_bitmap;
      final_bitmap.allocN32Pixels(width, height);
      final_bitmap.eraseColor(SK_ColorTRANSPARENT);

      float dis_to_center = GetFarthestVisiblePointFromCenter(unscaled_bitmap);
      float icon_to_bitmap_size_ratio = dis_to_center * 2.0f / width;

      if (icon_to_bitmap_size_ratio > kBackgroundCircleScale) {
        SkCanvas canvas(final_bitmap);
        SkPaint paint_icon;
        paint_icon.setMaskFilter(nullptr);
        paint_icon.setBlendMode(SkBlendMode::kSrcOver);

        float icon_scale = kBackgroundCircleScale / icon_to_bitmap_size_ratio;

        gfx::Size scaled_icon_size =
            gfx::ScaleToRoundedSize(rep.pixel_size(), icon_scale);
        const SkBitmap scaled_bitmap = skia::ImageOperations::Resize(
            unscaled_bitmap, skia::ImageOperations::RESIZE_BEST,
            scaled_icon_size.width(), scaled_icon_size.height());

        int target_left = (width - scaled_icon_size.width()) / 2;
        int target_top = (height - scaled_icon_size.height()) / 2;

        // Draw the scaled down bitmap and add that to the final image.
        canvas.drawBitmap(scaled_bitmap, target_left, target_top, &paint_icon);
        final_image.AddRepresentation(
            gfx::ImageSkiaRep(final_bitmap, rep.scale()));
      } else {
        // No need to scale down the icon, so just use the |unscaled_bitmap|.
        final_image.AddRepresentation(
            gfx::ImageSkiaRep(unscaled_bitmap, rep.scale()));
      }
    }

    return final_image;
  }

  for (gfx::ImageSkiaRep rep : standard_size_image.image_reps()) {
    SkBitmap unscaled_bitmap(rep.GetBitmap());
    int width = unscaled_bitmap.width();
    int height = unscaled_bitmap.height();

    SkBitmap final_bitmap;
    final_bitmap.allocN32Pixels(width, height);
    final_bitmap.eraseColor(SK_ColorTRANSPARENT);

    // To draw to |final_bitmap|, create a canvas and draw a circle background
    // with an app icon on top;
    SkCanvas canvas(final_bitmap);
    SkPaint paint_background_circle;
    paint_background_circle.setAntiAlias(true);
    paint_background_circle.setColor(SK_ColorWHITE);
    paint_background_circle.setStyle(SkPaint::kFill_Style);

    float circle_diameter = width * kBackgroundCircleScale;

    // Draw the background circle.
    canvas.drawCircle(SkPoint::Make((width - 1) / 2.0f, (height - 1) / 2.0f),
                      circle_diameter / 2.0f, paint_background_circle);

    float dis_to_center = GetFarthestVisiblePointFromCenter(unscaled_bitmap);
    float icon_diameter = dis_to_center * 2.0f;
    float target_diameter = circle_diameter * kIconScaleToFit;

    // If the icon is too big to fit correctly within the background circle,
    // then set |icon_scale| to fit.
    float icon_scale = (icon_diameter > target_diameter)
                           ? target_diameter / icon_diameter
                           : 1.0f;

    SkPaint paint_icon;
    paint_icon.setMaskFilter(nullptr);
    paint_icon.setBlendMode(SkBlendMode::kSrcOver);

    if (icon_scale == 1.0f) {
      // Draw the unscaled icon on top of the background.
      canvas.drawBitmap(unscaled_bitmap, 0, 0, &paint_icon);
    } else {
      gfx::Size scaled_icon_size =
          gfx::ScaleToRoundedSize(rep.pixel_size(), icon_scale);
      const SkBitmap scaled_bitmap = skia::ImageOperations::Resize(
          unscaled_bitmap, skia::ImageOperations::RESIZE_BEST,
          scaled_icon_size.width(), scaled_icon_size.height());

      int target_left = (width - scaled_icon_size.width()) / 2;
      int target_top = (height - scaled_icon_size.height()) / 2;

      // Draw the scaled icon on top of the background.
      canvas.drawBitmap(scaled_bitmap, target_left, target_top, &paint_icon);
    }

    final_image.AddRepresentation(gfx::ImageSkiaRep(final_bitmap, rep.scale()));
  }

  return final_image;
}

}  // namespace app_list
