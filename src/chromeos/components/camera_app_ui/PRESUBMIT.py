# Copyright 2020 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

def CheckChangeOnUpload(input_api, output_api):
  return _CommonChecks(input_api, output_api)


def CheckChangeOnCommit(input_api, output_api):
  return _CommonChecks(input_api, output_api)


def _CommonChecks(input_api, output_api):
  results = input_api.canned_checks.CheckPatchFormatted(input_api, output_api,
                                                        check_js=True)
  affected = input_api.AffectedFiles()
  if any(f for f in affected if f.LocalPath().endswith('.html')):
    results += _CheckHtml(input_api, output_api)
  results += _CheckWebDevStyle(input_api, output_api)
  return results


def _CheckHtml(input_api, output_api):
  return input_api.canned_checks.CheckLongLines(
      input_api, output_api, 80, lambda x: x.LocalPath().endswith('.html'))


def _CheckWebDevStyle(input_api, output_api):
  results = []

  try:
    import sys
    old_sys_path = sys.path[:]
    cwd = input_api.PresubmitLocalPath()
    sys.path += [input_api.os_path.join(cwd, '..', '..', '..', 'tools')]
    from web_dev_style import presubmit_support
    results += presubmit_support.CheckStyle(input_api, output_api)
  finally:
    sys.path = old_sys_path

  return results