// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_COMPONENTS_QUICK_ANSWERS_TRANSLATION_RESPONSE_PARSER_H_
#define CHROMEOS_COMPONENTS_QUICK_ANSWERS_TRANSLATION_RESPONSE_PARSER_H_

#include <memory>
#include <string>

#include "base/callback.h"
#include "base/memory/weak_ptr.h"
#include "services/data_decoder/public/cpp/data_decoder.h"

namespace chromeos {
namespace quick_answers {

struct QuickAnswer;

// Parser for extracting quick answer result out of the cloud translation
// response.
class TranslationResponseParser {
 public:
  // Callback used when parsing of |quick_answer| is complete. Note that
  // |quick_answer| may be |nullptr|.
  using TranslationResponseParserCallback =
      base::OnceCallback<void(std::unique_ptr<QuickAnswer> quick_answer)>;

  explicit TranslationResponseParser(
      TranslationResponseParserCallback complete_callback);
  ~TranslationResponseParser();

  TranslationResponseParser(const TranslationResponseParser&) = delete;
  TranslationResponseParser& operator=(const TranslationResponseParser&) =
      delete;

  // Starts processing the search response.
  void ProcessResponse(std::unique_ptr<std::string> response_body);

 private:
  void OnJsonParsed(data_decoder::DataDecoder::ValueOrError result);

  TranslationResponseParserCallback complete_callback_;

  base::WeakPtrFactory<TranslationResponseParser> weak_factory_{this};
};

}  // namespace quick_answers
}  // namespace chromeos

#endif  // CHROMEOS_COMPONENTS_QUICK_ANSWERS_TRANSLATION_RESPONSE_PARSER_H_
