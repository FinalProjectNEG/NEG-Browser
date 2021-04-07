// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/paint_preview/common/serialized_recording.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/optional.h"
#include "base/threading/thread_restrictions.h"
#include "base/unguessable_token.h"
#include "components/paint_preview/common/capture_result.h"
#include "components/paint_preview/common/paint_preview_tracker.h"
#include "components/paint_preview/common/proto/paint_preview.pb.h"
#include "components/paint_preview/common/recording_map.h"
#include "components/paint_preview/common/serial_utils.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/core/SkColor.h"
#include "third_party/skia/include/core/SkPaint.h"
#include "third_party/skia/include/core/SkPicture.h"
#include "third_party/skia/include/core/SkPictureRecorder.h"
#include "third_party/skia/include/core/SkRect.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"

namespace paint_preview {

namespace {

// Paint a picture that is gray and contains placeholder images for each of the
// subframes.
//
// |expected_deserialization_context| will contain a map that pre-associates the
// subframe guids with their skia unique ID.
sk_sp<const SkPicture> PaintGrayPictureWithSubframes(
    gfx::Size bounds,
    PictureSerializationContext* context,
    DeserializationContext* expected_deserialization_context,
    base::flat_map<base::UnguessableToken, gfx::Rect> subframes) {
  SkRect sk_bounds = SkRect::MakeWH(bounds.width(), bounds.height());
  SkPictureRecorder recorder;
  SkCanvas* canvas = recorder.beginRecording(sk_bounds);
  SkPaint paint;
  paint.setStyle(SkPaint::kFill_Style);
  paint.setColor(SK_ColorDKGRAY);
  canvas->drawRect(sk_bounds, paint);

  for (const auto& subframe : subframes) {
    const base::UnguessableToken& subframe_id = subframe.first;
    gfx::Rect clip_rect = subframe.second;
    SkRect rect = SkRect::MakeXYWH(clip_rect.x(), clip_rect.y(),
                                   clip_rect.width(), clip_rect.height());
    sk_sp<SkPicture> temp = SkPicture::MakePlaceholder(rect);
    expected_deserialization_context->insert({temp->uniqueID(), clip_rect});
    context->content_id_to_embedding_token.insert(
        {temp->uniqueID(), subframe_id});
    context->content_id_to_transformed_clip.insert({temp->uniqueID(), rect});
    canvas->drawPicture(temp.get());
  }

  return recorder.finishRecordingAsPicture();
}

sk_sp<const SkPicture> PaintPictureSingleGrayPixel() {
  PictureSerializationContext context;
  DeserializationContext expected_deserialization_context;
  return PaintGrayPictureWithSubframes(gfx::Size(1, 1), &context,
                                       &expected_deserialization_context, {});
}

SkBitmap CreateBitmapFromPicture(const SkPicture* pic) {
  SkRect cull_rect = pic->cullRect();
  SkBitmap bitmap;
  bitmap.allocPixels(
      SkImageInfo::MakeN32Premul(cull_rect.width(), cull_rect.height()));
  SkCanvas canvas(bitmap);
  SkMatrix matrix;
  matrix.setScaleTranslate(1, 1, -cull_rect.x(), -cull_rect.y());
  canvas.drawPicture(pic, &matrix, nullptr);
  return bitmap;
}

void ExpectPicturesEqual(sk_sp<const SkPicture> pic,
                         sk_sp<const SkPicture> expected) {
  // Should not be the same pointer.
  EXPECT_NE(pic, expected);

  SkBitmap bitmap = CreateBitmapFromPicture(pic.get());
  SkBitmap expected_bitmap = CreateBitmapFromPicture(expected.get());

  EXPECT_EQ(bitmap.width(), expected_bitmap.width());
  EXPECT_EQ(bitmap.height(), expected_bitmap.height());
  EXPECT_EQ(bitmap.bytesPerPixel(), expected_bitmap.bytesPerPixel());

  // Assert that all the bytes of the backing memory are equal. This check is
  // only safe if all of the width, height and bytesPerPixel are equal between
  // the two bitmaps.
  EXPECT_EQ(memcmp(bitmap.getPixels(), expected_bitmap.getPixels(),
                   expected_bitmap.bytesPerPixel() * expected_bitmap.width() *
                       expected_bitmap.height()),
            0);
}

}  // namespace

TEST(PaintPreviewSerializedRecordingTest, RoundtripWithFileBacking) {
  base::ScopedAllowBlockingForTesting scoped_blocking;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  sk_sp<const SkPicture> pic = PaintPictureSingleGrayPixel();

  base::FilePath path = temp_dir.GetPath().AppendASCII("root.skp");
  PaintPreviewTracker tracker(base::UnguessableToken::Create(), base::nullopt,
                              /*is_main_frame=*/true);
  size_t serialized_size = 0;
  ASSERT_TRUE(RecordToFile(
      base::File(path, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE),
      pic, &tracker, base::nullopt, &serialized_size));
  ASSERT_GE(serialized_size, 0u);

  SerializedRecording recording(path);
  ASSERT_TRUE(recording.IsValid());

  base::Optional<SkpResult> result = std::move(recording).Deserialize();
  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->ctx.empty());
  ExpectPicturesEqual(result->skp, pic);
}

TEST(PaintPreviewSerializedRecordingTest, RoundtripWithMemoryBufferBacking) {
  sk_sp<const SkPicture> pic = PaintPictureSingleGrayPixel();

  PaintPreviewTracker tracker(base::UnguessableToken::Create(), base::nullopt,
                              /*is_main_frame=*/true);
  size_t serialized_size = 0;
  base::Optional<mojo_base::BigBuffer> buffer =
      RecordToBuffer(pic, &tracker, base::nullopt, &serialized_size);
  ASSERT_GE(serialized_size, 0u);
  ASSERT_TRUE(buffer.has_value());

  SerializedRecording recording =
      SerializedRecording(std::move(buffer.value()));
  ASSERT_TRUE(recording.IsValid());

  base::Optional<SkpResult> result = std::move(recording).Deserialize();
  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->ctx.empty());
  ExpectPicturesEqual(result->skp, pic);
}

TEST(PaintPreviewSerializedRecordingTest, InvalidBacking) {
  SerializedRecording recording;
  ASSERT_FALSE(recording.IsValid());
}

TEST(PaintPreviewSerializedRecordingTest, RoundtripHasEmbeddedContent) {
  base::ScopedAllowBlockingForTesting scoped_blocking;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  base::FilePath path = temp_dir.GetPath().AppendASCII("root.skp");
  PaintPreviewTracker tracker(base::UnguessableToken::Create(), base::nullopt,
                              /*is_main_frame=*/true);

  base::UnguessableToken subframe0 = base::UnguessableToken::Create();
  gfx::Rect subframe0_rect = gfx::Rect(5, 10, 10, 15);
  base::UnguessableToken subframe1 = base::UnguessableToken::Create();
  gfx::Rect subframe1_rect = gfx::Rect(5, 10, 10, 15);

  DeserializationContext expected;
  sk_sp<const SkPicture> pic = PaintGrayPictureWithSubframes(
      gfx::Size(25, 25), tracker.GetPictureSerializationContext(), &expected,
      {{subframe0, subframe0_rect}, {subframe1, subframe1_rect}});

  size_t serialized_size = 0;
  ASSERT_TRUE(RecordToFile(
      base::File(path, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE),
      pic, &tracker, base::nullopt, &serialized_size));
  ASSERT_GE(serialized_size, 0u);

  SerializedRecording recording(path);
  ASSERT_TRUE(recording.IsValid());

  base::Optional<SkpResult> result = std::move(recording).Deserialize();
  ASSERT_TRUE(result.has_value());

  EXPECT_FALSE(result->ctx.empty());
  EXPECT_EQ(result->ctx, expected);

  ExpectPicturesEqual(result->skp, pic);
}

TEST(PaintPreviewSerializedRecordingTest,
     RecordingMapFromCaptureResultSingleFrame) {
  sk_sp<const SkPicture> pic = PaintPictureSingleGrayPixel();

  const base::UnguessableToken root_frame_guid =
      base::UnguessableToken::Create();
  PaintPreviewTracker tracker(base::UnguessableToken::Create(), base::nullopt,
                              /*is_main_frame=*/true);
  size_t serialized_size = 0;
  base::Optional<mojo_base::BigBuffer> buffer =
      RecordToBuffer(pic, &tracker, base::nullopt, &serialized_size);
  ASSERT_GE(serialized_size, 0u);
  ASSERT_TRUE(buffer.has_value());

  CaptureResult capture_result(RecordingPersistence::kMemoryBuffer);
  capture_result.capture_success = true;
  capture_result.serialized_skps.insert(
      {root_frame_guid, std::move(buffer.value())});

  std::pair<RecordingMap, PaintPreviewProto> pair =
      RecordingMapFromCaptureResult(std::move(capture_result));

  RecordingMap recording_map = std::move(pair.first);
  EXPECT_FALSE(recording_map.empty());
  ASSERT_NE(recording_map.find(root_frame_guid), recording_map.end());
  base::Optional<SkpResult> result =
      std::move(recording_map.at(root_frame_guid)).Deserialize();
  ASSERT_TRUE(result.has_value());

  ExpectPicturesEqual(result->skp, pic);
}

TEST(PaintPreviewSerializedRecordingTest,
     RecordingMapFromPaintPreviewProtoSingleFrame) {
  base::ScopedAllowBlockingForTesting scoped_blocking;
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  base::FilePath root_path = temp_dir.GetPath().AppendASCII("root.skp");

  sk_sp<const SkPicture> pic = PaintPictureSingleGrayPixel();

  const base::UnguessableToken root_frame_guid =
      base::UnguessableToken::Create();
  PaintPreviewTracker tracker(base::UnguessableToken::Create(), base::nullopt,
                              /*is_main_frame=*/true);
  size_t serialized_size = 0;
  ASSERT_TRUE(RecordToFile(
      base::File(root_path,
                 base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE),
      pic, &tracker, base::nullopt, &serialized_size));
  ASSERT_GE(serialized_size, 0u);

  PaintPreviewProto proto;
  PaintPreviewFrameProto* root_frame = proto.mutable_root_frame();
  root_frame->set_embedding_token_high(
      root_frame_guid.GetHighForSerialization());
  root_frame->set_embedding_token_low(root_frame_guid.GetLowForSerialization());
  root_frame->set_is_main_frame(true);
  root_frame->set_file_path(root_path.MaybeAsASCII());

  RecordingMap recording_map = RecordingMapFromPaintPreviewProto(proto);
  EXPECT_FALSE(recording_map.empty());
  ASSERT_NE(recording_map.find(root_frame_guid), recording_map.end());
  base::Optional<SkpResult> result =
      std::move(recording_map.at(root_frame_guid)).Deserialize();
  ASSERT_TRUE(result.has_value());

  ExpectPicturesEqual(result->skp, pic);
}

}  // namespace paint_preview
