// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/nearby_sharing/logging/logging.h"
#include "chrome/browser/nearby_sharing/logging/log_buffer.h"

ScopedLogMessage::ScopedLogMessage(const char* file,
                                   int line,
                                   logging::LogSeverity severity)
    : file_(file), line_(line), severity_(severity) {}

ScopedLogMessage::~ScopedLogMessage() {
  const std::string string_from_stream = stream_.str();
  LogBuffer::GetInstance()->AddLogMessage(LogBuffer::LogMessage(
      string_from_stream, base::Time::Now(), file_, line_, severity_));

  // Don't emit VERBOSE-level logging to the standard logging system unless
  // verbose logging is enabled for the source file.
  if (severity_ <= logging::LOG_VERBOSE &&
      logging::GetVlogLevelHelper(file_, strlen(file_) + 1) <= 0) {
    return;
  }

  // The destructor of |log_message| also creates a log for the standard logging
  // system.
  logging::LogMessage log_message(file_, line_, severity_);
  log_message.stream() << string_from_stream;
}
