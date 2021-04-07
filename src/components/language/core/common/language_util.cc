// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/language/core/common/language_util.h"

#include <stddef.h>
#include <algorithm>
#include <tuple>

#include "base/strings/strcat.h"
#include "base/strings/string_piece.h"
#include "components/language/core/common/locale_util.h"

namespace language {

namespace {

struct LanguageCodePair {
  // Code used in supporting list of Translate.
  const char* const translate_language;

  // Code used in Chrome internal.
  const char* const chrome_language;
};

// Some languages are treated as same languages in Translate even though they
// are different to be exact.
//
// If this table is updated, please sync this with the synonym table in
// chrome/browser/resources/settings/languages_page/languages.js.
const LanguageCodePair kChromeToTranslateLanguageMap[] = {
    {"no", "nb"},
    {"tl", "fil"},
};
const LanguageCodePair kTranslateToChromeLanguageMap[] = {
    {"tl", "fil"},
};

// Some languages have changed codes over the years and sometimes the older
// codes are used, so we must see them as synonyms.
//
// If this table is updated, please sync this with the synonym table in
// chrome/browser/resources/settings/languages_page/languages.js.
const LanguageCodePair kLanguageCodeSynonyms[] = {
    {"iw", "he"},
    {"jw", "jv"},
};

// Some Chinese language codes are compatible with zh-TW or zh-CN in terms of
// Translate.
//
// If this table is updated, please sync this with the synonym table in
// chrome/browser/resources/settings/languages_page/languages.js.
const LanguageCodePair kLanguageCodeChineseCompatiblePairs[] = {
    {"zh-TW", "zh-HK"},
    {"zh-TW", "zh-MO"},
    {"zh-CN", "zh-SG"},
};

}  // namespace

void ToTranslateLanguageSynonym(std::string* language) {
  for (const auto& language_pair : kChromeToTranslateLanguageMap) {
    if (*language == language_pair.chrome_language) {
      *language = language_pair.translate_language;
      return;
    }
  }

  base::StringPiece main_part = language::SplitIntoMainAndTail(*language).first;
  if (main_part.empty())
    return;

  // Chinese is a special case: we do not return the main_part only.
  // There is not a single base language, but two: traditional and simplified.
  // The kLanguageCodeChineseCompatiblePairs list contains the relation between
  // various Chinese locales. We need to return the code from that mapping
  // instead of the main_part.
  // Note that "zh" does not have any mapping and as such we leave it as is. See
  // https://crbug/798512 for more info.
  for (const auto& language_pair : kLanguageCodeChineseCompatiblePairs) {
    if (*language == language_pair.chrome_language) {
      *language = language_pair.translate_language;
      return;
    }
  }
  if (main_part == "zh") {
    return;
  }

  // Apply linear search here because number of items in the list is just four.
  for (const auto& language_pair : kLanguageCodeSynonyms) {
    if (main_part == language_pair.chrome_language) {
      main_part = language_pair.translate_language;
      break;
    }
  }

  *language = std::string(main_part);
}

void ToChromeLanguageSynonym(std::string* language) {
  for (const auto& language_pair : kTranslateToChromeLanguageMap) {
    if (*language == language_pair.translate_language) {
      *language = language_pair.chrome_language;
      return;
    }
  }

  base::StringPiece main_part, tail_part;
  std::tie(main_part, tail_part) = language::SplitIntoMainAndTail(*language);
  if (main_part.empty())
    return;

  // Apply linear search here because number of items in the list is just four.
  for (const auto& language_pair : kLanguageCodeSynonyms) {
    if (main_part == language_pair.translate_language) {
      main_part = language_pair.chrome_language;
      break;
    }
  }

  *language = base::StrCat({main_part, tail_part});
}

}  // namespace language
