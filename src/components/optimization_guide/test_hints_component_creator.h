// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_OPTIMIZATION_GUIDE_TEST_HINTS_COMPONENT_CREATOR_H_
#define COMPONENTS_OPTIMIZATION_GUIDE_TEST_HINTS_COMPONENT_CREATOR_H_

#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/macros.h"
#include "components/optimization_guide/optimization_guide_service.h"
#include "components/optimization_guide/proto/hints.pb.h"

namespace optimization_guide {
namespace testing {

// Helper class to create test OptimizationHints components for testing.
//
// All temporary files and paths are cleaned up when this instance goes out of
// scope.
class TestHintsComponentCreator {
 public:
  TestHintsComponentCreator();
  ~TestHintsComponentCreator();

  // Creates component data based on |whitelisted_hosts| and
  // |page_pattern| with page hints for type |optimization_type| blocking
  // resources specified by |resource_patterns|, and returns the
  // HintsComponentInfo for it.
  optimization_guide::HintsComponentInfo CreateHintsComponentInfoWithPageHints(
      optimization_guide::proto::OptimizationType optimization_type,
      const std::vector<std::string>& whitelisted_hosts,
      const std::string& page_pattern,
      const std::vector<std::string>& resource_patterns);

 private:
  // Returns the scoped temp directory path with the |file_path_suffix| that is
  // valid for the lifetime of this instance.
  // The file itself will not be automatically created.
  base::FilePath GetFilePath(std::string file_path_suffix);

  // Writes a configuration of hints to the file path.
  void WriteConfigToFile(
      const base::FilePath& file_path,
      const optimization_guide::proto::Configuration& config);

  // Writes a configuration of hints to the file path and returns the
  // HintsComponentInfo for it.
  optimization_guide::HintsComponentInfo
  WriteConfigToFileAndReturnHintsComponentInfo(
      const optimization_guide::proto::Configuration& config);

  std::unique_ptr<base::ScopedTempDir> scoped_temp_dir_;
  int next_component_version_;

  DISALLOW_COPY_AND_ASSIGN(TestHintsComponentCreator);
};

}  // namespace testing
}  // namespace optimization_guide

#endif  // COMPONENTS_OPTIMIZATION_GUIDE_TEST_HINTS_COMPONENT_CREATOR_H_
