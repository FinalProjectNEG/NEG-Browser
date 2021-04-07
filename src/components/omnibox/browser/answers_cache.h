// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_OMNIBOX_BROWSER_ANSWERS_CACHE_H_
#define COMPONENTS_OMNIBOX_BROWSER_ANSWERS_CACHE_H_

#include <stddef.h>

#include <list>

#include "base/strings/string16.h"

struct AnswersQueryData {
  AnswersQueryData();
  AnswersQueryData(const base::string16& full_query_text, int query_type);
  base::string16 full_query_text;
  int query_type;
};

// Cache for the most-recently seen answer for Answers in Suggest.
class AnswersCache {
 public:
  explicit AnswersCache(size_t max_entries);
  ~AnswersCache();
  AnswersCache(const AnswersCache&) = delete;
  AnswersCache& operator=(const AnswersCache&) = delete;

  // Gets the top answer query completion for the query term. The query data
  // will contain empty query text and type if no matching data was found.
  AnswersQueryData GetTopAnswerEntry(const base::string16& query);

  // Registers a query that received an answer suggestion.
  void UpdateRecentAnswers(const base::string16& full_query_text,
                           int query_type);

  // Signals if cache is empty.
  bool empty() const { return cache_.empty(); }

 private:
  size_t max_entries_;
  typedef std::list<AnswersQueryData> Cache;
  Cache cache_;
};

#endif  // COMPONENTS_OMNIBOX_BROWSER_ANSWERS_CACHE_H_
