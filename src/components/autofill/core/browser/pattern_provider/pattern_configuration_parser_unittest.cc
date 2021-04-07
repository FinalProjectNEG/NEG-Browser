// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/autofill/core/browser/pattern_provider/pattern_configuration_parser.h"

#include <stddef.h>

#include "base/json/json_reader.h"
#include "base/test/gtest_util.h"
#include "base/version.h"
#include "components/grit/components_resources.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "ui/base/resource/resource_bundle.h"

namespace autofill {

namespace field_type_parsing {

// Test that the |base::Value| object of the configuration is
// parsed to the map structure used by |PatternProvider| as
// expected, given the input is valid.
TEST(PatternConfigurationParserTest, WellFormedParsedCorrectly) {
  std::string JSON_message = R"(
    {
      "version": "1.0",
      "FULL_NAME": {
        "en_us": [
          {
            "pattern_identifier": "Name_en",
            "positive_pattern": "name|full name",
            "positive_score": 2.0,
            "negative_pattern": "company",
            "match_field_attributes": 2,
            "match_field_input_types": 3
          }
        ],
        "fr": [
          {
            "pattern_identifier": "Name_fr",
            "positive_pattern": "nom|prenom",
            "positive_score": 2.0,
            "negative_pattern": "compagne",
            "match_field_attributes": 2,
            "match_field_input_types": 3
          }
        ]
      },
      "ADDRESS": {
        "en_us": [
          {
            "pattern_identifier": "Address",
            "positive_pattern": "address",
            "positive_score": 2.0,
            "negative_pattern": "email",
            "match_field_attributes": 4,
            "match_field_input_types": 3
          }
        ]
      }
    })";
  base::Optional<base::Value> JSON_object =
      base::JSONReader::Read(JSON_message);

  ASSERT_TRUE(JSON_object) << "Incorrectly formatted JSON string.";

  base::Version version = ExtractVersionFromJsonObject(JSON_object.value());
  base::Optional<PatternProvider::Map> optional_patterns =
      GetConfigurationFromJsonObject(JSON_object.value());

  ASSERT_TRUE(version.IsValid());
  ASSERT_TRUE(optional_patterns);

  ASSERT_EQ(base::Version("1.0"), version);

  PatternProvider::Map patterns = optional_patterns.value();

  ASSERT_EQ(2U, patterns.size());
  ASSERT_TRUE(patterns.count("FULL_NAME"));
  ASSERT_EQ(2U, patterns["FULL_NAME"].size());
  ASSERT_TRUE(patterns["FULL_NAME"].count("en_us"));
  ASSERT_TRUE(patterns["FULL_NAME"].count("fr"));

  ASSERT_TRUE(patterns.count("ADDRESS"));
  ASSERT_EQ(1U, patterns["ADDRESS"].size());
  ASSERT_TRUE(patterns["ADDRESS"].count("en_us"));

  // Test one |MatchingPattern| to check that they are parsed correctly.
  MatchingPattern* pattern = &patterns["FULL_NAME"]["fr"][0];

  ASSERT_EQ("Name_fr", pattern->pattern_identifier);
  ASSERT_EQ("nom|prenom", pattern->positive_pattern);
  ASSERT_EQ("compagne", pattern->negative_pattern);
  ASSERT_EQ("fr", pattern->language);
  ASSERT_NEAR(2.0, pattern->positive_score, 1e-6);
  ASSERT_EQ(2, pattern->match_field_attributes);
  ASSERT_EQ(3, pattern->match_field_input_types);
}

// Test that the parser does not return anything if some |MatchingPattern|
// object is missing a property.
TEST(PatternConfigurationParserTest, MalformedMissingProperty) {
  std::string JSON_message = R"(
    {
      "version": "1.0",
      "FULL_NAME": {
        "en_us": [
          {
            "pattern_identifier": "Name_en",
            "positive_pattern": "name|full name",
            "positive_score": 2.0,
            "negative_pattern": "company",
            "match_field_attributes": 2,
            "match_field_input_types": 3
          }
        ],
        "fr": [
          {
            "pattern_identifier": "Name_fr",
            "positive_pattern": "nom|prenom",
            "negative_pattern": "compagne",
            "match_field_attributes": 2,
            "match_field_input_types": 3
          }
        ]
      }
    })";
  base::Optional<base::Value> JSON_object =
      base::JSONReader::Read(JSON_message);

  ASSERT_TRUE(JSON_object) << "Incorrectly formatted JSON string.";

  base::Optional<PatternProvider::Map> optional_patterns =
      GetConfigurationFromJsonObject(JSON_object.value());

  ASSERT_FALSE(optional_patterns);
}

// Test that the parser correctly sets the default version if
// it is not present in the configuration.
TEST(PatternConfigurationParserTest, MalformedMissingVersion) {
  std::string JSON_message = R"(
    {
      "FULL_NAME": {
        "en_us": [
          {
            "pattern_identifier": "Name_en",
            "positive_pattern": "name|full name",
            "positive_score": 2.0,
            "negative_pattern": "company",
            "match_field_attributes": 2,
            "match_field_input_types": 3
          }
        ]
      }
    })";
  base::Optional<base::Value> JSON_object =
      base::JSONReader::Read(JSON_message);

  ASSERT_TRUE(JSON_object) << "Incorrectly formatted JSON string.";

  base::Version version = ExtractVersionFromJsonObject(JSON_object.value());

  ASSERT_EQ(base::Version("0"), version);
}

// Test that the parser does not return anything if the inner key points
// to a single object instead of a list.
TEST(PatternConfigurationParserTest, MalformedNotList) {
  std::string JSON_message = R"(
    {
      "FULL_NAME": {
        "en_us": {
          "pattern_identifier": "Name_en",
          "positive_pattern": "name|full name",
          "positive_score": 2.0,
          "negative_pattern": "company",
          "match_field_attributes": 2,
          "match_field_input_types": 3
        }
      }
    })";
  base::Optional<base::Value> JSON_object =
      base::JSONReader::Read(JSON_message);

  ASSERT_TRUE(JSON_object) << "Incorrectly formatted JSON string.";

  base::Optional<PatternProvider::Map> optional_patterns =
      GetConfigurationFromJsonObject(JSON_object.value());

  ASSERT_FALSE(optional_patterns);
}

}  // namespace field_type_parsing

}  // namespace autofill
