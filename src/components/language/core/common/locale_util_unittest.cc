// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/language/core/common/locale_util.h"

#include "base/command_line.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace language {
namespace {

typedef testing::Test LocaleUtilTest;

TEST_F(LocaleUtilTest, SplitIntoMainAndTail) {
  typedef std::pair<base::StringPiece, base::StringPiece> StringPiecePair;

  EXPECT_EQ(StringPiecePair("", ""), SplitIntoMainAndTail(""));
  EXPECT_EQ(StringPiecePair("en", ""), SplitIntoMainAndTail("en"));
  EXPECT_EQ(StringPiecePair("ogard543i", ""),
            SplitIntoMainAndTail("ogard543i"));
  EXPECT_EQ(StringPiecePair("en", "-AU"), SplitIntoMainAndTail("en-AU"));
  EXPECT_EQ(StringPiecePair("es", "-419"), SplitIntoMainAndTail("es-419"));
  EXPECT_EQ(StringPiecePair("en", "-AU-2009"),
            SplitIntoMainAndTail("en-AU-2009"));
}

TEST_F(LocaleUtilTest, ConvertToActualUILocale) {
  std::string locale;

  //---------------------------------------------------------------------------
  // Languages that are enabled as display UI.
  //---------------------------------------------------------------------------
  locale = "en-US";
  bool is_ui = ConvertToActualUILocale(&locale);
  EXPECT_TRUE(is_ui);
  EXPECT_EQ("en-US", locale);

  locale = "it";
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_TRUE(is_ui);
  EXPECT_EQ("it", locale);

  locale = "fr-FR";
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_TRUE(is_ui);
  EXPECT_EQ("fr-FR", locale);

  //---------------------------------------------------------------------------
  // Languages that are converted to their fallback version.
  //---------------------------------------------------------------------------

  // All Latin American Spanish languages fall back to "es-419".
  for (const char* es_locale : {"es-AR", "es-CL", "es-CO", "es-CR", "es-HN",
                                "es-MX", "es-PE", "es-US", "es-UY", "es-VE"}) {
    locale = es_locale;
    is_ui = ConvertToActualUILocale(&locale);
    EXPECT_TRUE(is_ui) << es_locale;
    EXPECT_EQ("es-419", locale) << es_locale;
  }

  // English falls back to US.
  locale = "en";
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_TRUE(is_ui);
  EXPECT_EQ("en-US", locale);

  // All other regional English languages fall back to UK.
  for (const char* en_locale :
       {"en-AU", "en-CA", "en-GB-oxendict", "en-IN", "en-NZ", "en-ZA"}) {
    locale = en_locale;
    is_ui = ConvertToActualUILocale(&locale);
    EXPECT_TRUE(is_ui) << en_locale;
    EXPECT_EQ("en-GB", locale) << en_locale;
  }

  locale = "pt";
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_TRUE(is_ui);
  EXPECT_EQ("pt-PT", locale);

  locale = "it-CH";
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_TRUE(is_ui);
  EXPECT_EQ("it", locale);

  locale = "no";
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_TRUE(is_ui);
  EXPECT_EQ("nb", locale);

  locale = "it-IT";
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_TRUE(is_ui);
  EXPECT_EQ("it-IT", locale);

  locale = "de-DE";
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_TRUE(is_ui);
  EXPECT_EQ("de-DE", locale);

//---------------------------------------------------------------------------
// Languages that cannot be used as display UI.
//---------------------------------------------------------------------------
// This only matters for ChromeOS and Windows, as they are the only systems
// where users can set the display UI.
#if defined(OS_CHROMEOS) || defined(OS_WIN)
  locale = "sd";  // Sindhi
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_FALSE(is_ui);

  locale = "af";  // Afrikaans
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_FALSE(is_ui);

  locale = "ga";  // Irish
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_FALSE(is_ui);

  locale = "ky";  // Kyrgyz
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_FALSE(is_ui);

  locale = "zu";  // Zulu
  is_ui = ConvertToActualUILocale(&locale);
  EXPECT_FALSE(is_ui);
#endif
}

}  // namespace
}  // namespace language
