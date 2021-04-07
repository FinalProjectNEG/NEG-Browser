// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/common/mac/attributed_string_type_converters.h"

#include <AppKit/AppKit.h>

#include "base/check.h"
#include "base/mac/scoped_nsobject.h"
#include "base/strings/sys_string_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "content/public/common/common_param_traits.h"

namespace mojo {

namespace {

NSDictionary* ToAttributesDictionary(base::string16 name, float font_size) {
  DCHECK(!name.empty());
  NSString* font_name_ns = base::SysUTF16ToNSString(name);
  NSFont* font = [NSFont fontWithName:font_name_ns size:font_size];
  if (!font)
    return [NSDictionary dictionary];
  return [NSDictionary dictionaryWithObject:font forKey:NSFontAttributeName];
}

}  // namespace

NSAttributedString*
TypeConverter<NSAttributedString*, ui::mojom::AttributedStringPtr>::Convert(
    const ui::mojom::AttributedStringPtr& mojo_attributed_string) {
  // Create the return value.
  NSString* plain_text =
      base::SysUTF16ToNSString(mojo_attributed_string->string);
  base::scoped_nsobject<NSMutableAttributedString> decoded_string(
      [[NSMutableAttributedString alloc] initWithString:plain_text]);
  // Iterate over all the encoded attributes, attaching each to the string.
  const std::vector<ui::mojom::FontAttributePtr>& attributes =
      mojo_attributed_string->attributes;
  for (std::vector<ui::mojom::FontAttributePtr>::const_iterator it =
           attributes.begin();
       it != attributes.end(); ++it) {
    // Protect against ranges that are outside the range of the string.
    const gfx::Range& range = it->get()->effective_range;
    if (range.GetMin() > [plain_text length] ||
        range.GetMax() > [plain_text length]) {
      continue;
    }
    [decoded_string
        addAttributes:ToAttributesDictionary(it->get()->font_name,
                                             it->get()->font_point_size)
                range:range.ToNSRange()];
  }
  return [decoded_string.release() autorelease];
}

ui::mojom::AttributedStringPtr
TypeConverter<ui::mojom::AttributedStringPtr, NSAttributedString*>::Convert(
    const NSAttributedString* ns_attributed_string) {
  // Create the return value.
  ui::mojom::AttributedStringPtr attributed_string =
      ui::mojom::AttributedString::New();
  attributed_string->string =
      base::SysNSStringToUTF16([ns_attributed_string string]);

  // Iterate over all the attributes in the string.
  NSUInteger length = [ns_attributed_string length];
  for (NSUInteger i = 0; i < length;) {
    NSRange effective_range;
    NSDictionary* ns_attributes =
        [ns_attributed_string attributesAtIndex:i
                                 effectiveRange:&effective_range];

    NSFont* font = [ns_attributes objectForKey:NSFontAttributeName];
    base::string16 font_name;
    float font_point_size;
    // Only encode the attributes if the filtered set contains font information.
    if (font) {
      font_name = base::SysNSStringToUTF16([font fontName]);
      font_point_size = [font pointSize];
      if (!font_name.empty()) {
        // Convert the attributes.
        ui::mojom::FontAttributePtr attrs = ui::mojom::FontAttribute::New(
            font_name, font_point_size, gfx::Range(effective_range));
        attributed_string->attributes.push_back(std::move(attrs));
      }
    }
    // Advance the iterator to the position outside of the effective range.
    i = NSMaxRange(effective_range);
  }
  return attributed_string;
}

}  // namespace mojo
