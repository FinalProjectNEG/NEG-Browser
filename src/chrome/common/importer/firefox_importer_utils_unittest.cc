// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/common/importer/firefox_importer_utils.h"

#include <stddef.h>

#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/stl_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/values.h"
#include "chrome/grit/generated_resources.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "ui/base/l10n/l10n_util.h"

using base::ASCIIToUTF16;
using base::UTF8ToUTF16;
using testing::UnorderedElementsAre;

namespace {

struct GetPrefsJsValueCase {
  std::string prefs_content;
  std::string pref_name;
  std::string pref_value;
} GetPrefsJsValueCases[] = {
    // Basic case. Single pref, unquoted value.
    {"user_pref(\"foo.bar\", 1);", "foo.bar", "1"},
    // Value is quoted. Quotes should be stripped.
    {"user_pref(\"foo.bar\", \"1\");", "foo.bar", "1"},
    // Value has parens.
    {"user_pref(\"foo.bar\", \"Value (detail)\");", "foo.bar",
     "Value (detail)"},
    // Multi-line case.
    {"user_pref(\"foo.bar\", 1);\n"
     "user_pref(\"foo.baz\", 2);\n"
     "user_pref(\"foo.bag\", 3);",
     "foo.baz", "2"},
    // Malformed content.
    {"user_pref(\"foo.bar\", 1);\n"
     "user_pref(\"foo.baz\", 2;\n"
     "user_pref(\"foo.bag\", 3);",
     "foo.baz", std::string()},
    // Malformed content.
    {"uesr_pref(\"foo.bar\", 1);", "foo.bar", std::string()},
};

struct GetFirefoxImporterNameCase {
  std::string app_ini_content;
  int resource_id;
} GetFirefoxImporterNameCases[] = {
    // Basic case
    {"[App]\n"
     "Vendor=Mozilla\n"
     "Name=iceweasel\n"
     "Version=10.0.6\n"
     "BuildID=20120717115048\n"
     "ID={ec8030f7-c20a-464f-9b0e-13a3a9e97384}",
     IDS_IMPORT_FROM_ICEWEASEL},
    // Whitespace
    {" \t[App] \n"
     "Vendor=Mozilla\n"
     "   Name=Firefox\t \r\n"
     "Version=10.0.6\n",
     IDS_IMPORT_FROM_FIREFOX},
    // No Name setting
    {"[App]\n"
     "Vendor=Mozilla\n"
     "Version=10.0.6\n"
     "BuildID=20120717115048\n"
     "ID={ec8030f7-c20a-464f-9b0e-13a3a9e97384}",
     IDS_IMPORT_FROM_FIREFOX},
    // No [App] section
    {"[Foo]\n"
     "Vendor=Mozilla\n"
     "Name=Foo\n",
     IDS_IMPORT_FROM_FIREFOX},
    // Multiple Name settings in different sections
    {"[Foo]\n"
     "Vendor=Mozilla\n"
     "Name=Firefox\n"
     "[App]\n"
     "Profile=mozilla/firefox\n"
     "Name=iceweasel\n"
     "[Bar]\n"
     "Name=Bar\n"
     "ID={ec8030f7-c20a-464f-9b0e-13a3a9e97384}",
     IDS_IMPORT_FROM_ICEWEASEL},
    // Case-insensitivity
    {"[App]\n"
     "Vendor=Mozilla\n"
     "Name=IceWeasel\n"
     "Version=10.0.6\n",
     IDS_IMPORT_FROM_ICEWEASEL},
    // Empty file
    {std::string(), IDS_IMPORT_FROM_FIREFOX}};

}  // anonymous namespace

TEST(FirefoxImporterUtilsTest, GetPrefsJsValue) {
  for (size_t i = 0; i < base::size(GetPrefsJsValueCases); ++i) {
    EXPECT_EQ(
      GetPrefsJsValueCases[i].pref_value,
      GetPrefsJsValue(GetPrefsJsValueCases[i].prefs_content,
                      GetPrefsJsValueCases[i].pref_name));
  }
}

TEST(FirefoxImporterUtilsTest, GetFirefoxImporterName) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const base::FilePath app_ini_file(
      temp_dir.GetPath().AppendASCII("application.ini"));
  for (size_t i = 0; i < base::size(GetFirefoxImporterNameCases); ++i) {
    base::WriteFile(app_ini_file,
                    GetFirefoxImporterNameCases[i].app_ini_content.c_str(),
                    GetFirefoxImporterNameCases[i].app_ini_content.size());
    EXPECT_EQ(
        GetFirefoxImporterName(temp_dir.GetPath()),
        l10n_util::GetStringUTF16(GetFirefoxImporterNameCases[i].resource_id));
  }
  EXPECT_EQ(l10n_util::GetStringUTF16(
          IDS_IMPORT_FROM_FIREFOX),
      GetFirefoxImporterName(base::FilePath(
                                        FILE_PATH_LITERAL("/invalid/path"))));
}

TEST(FirefoxImporterUtilsTest, GetFirefoxProfilePath) {
  base::DictionaryValue no_profiles;
  EXPECT_EQ(0u,
            GetFirefoxDetailsFromDictionary(no_profiles, std::string()).size());

  base::DictionaryValue single_profile;
  single_profile.SetString("Profile0.Path", "first");
  // Ensure that when there is only one profile the profile name shown in the UI
  // is empty, since there's no need to disambiguate among multiple profiles
  single_profile.SetString("Profile0.Name", "namey");
  single_profile.SetString("Profile0.IsRelative", "0");
  single_profile.SetString("Profile0.Default", "1");

  std::vector<FirefoxDetail> details =
      GetFirefoxDetailsFromDictionary(single_profile, std::string());
  EXPECT_THAT(details, UnorderedElementsAre(FirefoxDetail{
                           base::FilePath(FILE_PATH_LITERAL("first")),
                           base::string16()}));

  base::DictionaryValue no_default;
  no_default.SetString("Profile0.Path", "first");
  no_default.SetString("Profile0.Name", "namey");
  no_default.SetString("Profile0.IsRelative", "0");
  no_default.SetString("Profile1.Path", "second");
  no_default.SetString("Profile1.Name", "namey-name");
  no_default.SetString("Profile1.IsRelative", "0");
  std::vector<FirefoxDetail> no_default_details =
      GetFirefoxDetailsFromDictionary(no_default, std::string());
  EXPECT_THAT(no_default_details,
              UnorderedElementsAre(
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("first")),
                                ASCIIToUTF16("namey")},
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("second")),
                                ASCIIToUTF16("namey name")}));

  base::DictionaryValue default_first;
  default_first.SetString("Profile0.Path", "first");
  default_first.SetString("Profile0.Name", "namey");
  default_first.SetString("Profile0.IsRelative", "0");
  default_first.SetString("Profile0.Default", "1");
  default_first.SetString("Profile1.Path", "second");
  default_first.SetString("Profile1.Name", "namey-name");
  default_first.SetString("Profile1.IsRelative", "0");
  std::vector<FirefoxDetail> default_first_details =
      GetFirefoxDetailsFromDictionary(default_first, std::string());
  EXPECT_THAT(default_first_details,
              UnorderedElementsAre(
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("first")),
                                ASCIIToUTF16("namey")},
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("second")),
                                ASCIIToUTF16("namey name")}));

  base::DictionaryValue default_second;
  default_second.SetString("Profile0.Path", "first");
  default_second.SetString("Profile0.Name", "namey");
  default_second.SetString("Profile0.IsRelative", "0");
  default_second.SetString("Profile1.Path", "second");
  default_second.SetString("Profile1.Name", "namey-name");
  default_second.SetString("Profile1.IsRelative", "0");
  default_second.SetString("Profile1.Default", "1");
  std::vector<FirefoxDetail> default_second_details =
      GetFirefoxDetailsFromDictionary(default_second, std::string());
  EXPECT_THAT(default_second_details,
              UnorderedElementsAre(
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("first")),
                                ASCIIToUTF16("namey")},
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("second")),
                                ASCIIToUTF16("namey name")}));

  // Firefox format from version 67
  base::DictionaryValue default_single_install;
  default_single_install.SetString("Install01.Default", "second");
  default_single_install.SetString("Profile0.IsRelative", "0");
  default_single_install.SetString("Profile0.Default", "1");
  default_single_install.SetString("Profile1.Path", "second");
  default_single_install.SetString("Profile1.IsRelative", "0");
  std::vector<FirefoxDetail> default_single_install_details =
      GetFirefoxDetailsFromDictionary(default_single_install, std::string());
  EXPECT_EQ("second", default_single_install_details[0].path.MaybeAsASCII());

  base::DictionaryValue default_single_install_unknown_profile;
  default_single_install_unknown_profile.SetString("Install01.Default",
                                                   "wrong");
  default_single_install_unknown_profile.SetString("Profile0.Path", "first");
  default_single_install_unknown_profile.SetString("Profile0.IsRelative", "0");
  default_single_install_unknown_profile.SetString("Profile0.Default", "1");
  default_single_install_unknown_profile.SetString("Profile1.Path", "second");
  default_single_install_unknown_profile.SetString("Profile1.IsRelative", "0");
  std::vector<FirefoxDetail> default_single_install_unknown_profile_details =
      GetFirefoxDetailsFromDictionary(default_single_install_unknown_profile,
                                      std::string());
  EXPECT_THAT(default_single_install_unknown_profile_details,
              UnorderedElementsAre(
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("first")),
                                base::string16()},
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("second")),
                                base::string16()}));

  default_single_install_unknown_profile.SetString("Install01.Default",
                                                   "first");
  default_single_install_unknown_profile.SetString("Install02.Default",
                                                   "second");
  default_single_install_unknown_profile.SetString("Profile0.Path", "first");
  default_single_install_unknown_profile.SetString("Profile0.IsRelative", "0");
  default_single_install_unknown_profile.SetString("Profile0.Default", "1");
  default_single_install_unknown_profile.SetString("Profile1.Path", "second");
  default_single_install_unknown_profile.SetString("Profile1.IsRelative", "0");
  std::vector<FirefoxDetail> default_multiple_install_details =
      GetFirefoxDetailsFromDictionary(default_single_install_unknown_profile,
                                      std::string());
  EXPECT_THAT(default_multiple_install_details,
              UnorderedElementsAre(
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("first")),
                                base::string16()},
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("second")),
                                base::string16()}));

  base::DictionaryValue one_of_profiles_is_not_ascii_named;
  one_of_profiles_is_not_ascii_named.SetString("Profile0.Path", "first");
  one_of_profiles_is_not_ascii_named.SetString("Profile0.Name", "namey");
  one_of_profiles_is_not_ascii_named.SetString("Profile0.IsRelative", "0");
  one_of_profiles_is_not_ascii_named.SetString("Profile1.Path",
                                               UTF8ToUTF16("second.профиль"));
  one_of_profiles_is_not_ascii_named.SetString("Profile1.Name",
                                               UTF8ToUTF16("профиль"));
  one_of_profiles_is_not_ascii_named.SetString("Profile1.IsRelative", "0");
  std::vector<FirefoxDetail> one_of_profiles_is_not_ascii_named_details =
      GetFirefoxDetailsFromDictionary(one_of_profiles_is_not_ascii_named,
                                      std::string());
  EXPECT_THAT(one_of_profiles_is_not_ascii_named_details,
              UnorderedElementsAre(
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("first")),
                                ASCIIToUTF16("namey")},
                  FirefoxDetail{base::FilePath(FILE_PATH_LITERAL("second."
                                                                 "профиль")),
                                UTF8ToUTF16("профиль")}));
}
