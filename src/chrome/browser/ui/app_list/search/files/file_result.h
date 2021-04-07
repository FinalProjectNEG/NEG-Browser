// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_APP_LIST_SEARCH_FILES_FILE_RESULT_H_
#define CHROME_BROWSER_UI_APP_LIST_SEARCH_FILES_FILE_RESULT_H_

#include <iosfwd>

#include "base/files/file_path.h"
#include "chrome/browser/ui/app_list/search/chrome_search_result.h"

class Profile;

namespace app_list {

class FileResult : public ChromeSearchResult {
 public:
  FileResult(const std::string& schema,
             const base::FilePath& filepath,
             ResultType result_type,
             DisplayType display_type,
             float relevance,
             Profile* profile);
  ~FileResult() override;

  FileResult(const FileResult&) = delete;
  FileResult& operator=(const FileResult&) = delete;

  // ChromeSearchResult overrides:
  void Open(int event_flags) override;

 private:
  const base::FilePath filepath_;
  Profile* const profile_;
};

::std::ostream& operator<<(::std::ostream& os, const FileResult& result);

}  // namespace app_list

#endif  // CHROME_BROWSER_UI_APP_LIST_SEARCH_FILES_FILE_RESULT_H_
