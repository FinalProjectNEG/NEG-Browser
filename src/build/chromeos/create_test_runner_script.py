#!/usr/bin/env python
#
# Copyright 2018 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Creates a script that runs a CrOS VM test by delegating to
build/chromeos/test_runner.py.
"""

import argparse
import os
import sys

SCRIPT_TEMPLATE = """\
#!/usr/bin/env python
#
# This file was generated by build/chromeos/create_test_runner_script.py

import os
import sys

def main():
  script_directory = os.path.dirname(__file__)
  def ResolvePath(path):
    return os.path.abspath(os.path.join(script_directory, path))

  vm_test_script = os.path.abspath(
      os.path.join(script_directory, '{vm_test_script}'))

  vm_args = {vm_test_args}
  path_args = {vm_test_path_args}
  for arg, path in path_args:
    vm_args.extend([arg, ResolvePath(path)])

  os.execv(vm_test_script,
           [vm_test_script] + vm_args + sys.argv[1:])

if __name__ == '__main__':
  sys.exit(main())
"""


def main(args):
  parser = argparse.ArgumentParser()
  parser.add_argument('--script-output-path')
  parser.add_argument('--output-directory')
  parser.add_argument('--test-exe')
  parser.add_argument('--runtime-deps-path')
  parser.add_argument('--cros-cache')
  parser.add_argument('--board')
  parser.add_argument('--use-vm', action='store_true')
  parser.add_argument('--deploy-chrome', action='store_true')
  parser.add_argument('--suite-name')
  parser.add_argument('--tast-attr-expr')
  parser.add_argument('--tast-tests', action='append')
  args, extra_args = parser.parse_known_args(args)

  def RelativizePathToScript(path):
    return os.path.relpath(path, os.path.dirname(args.script_output_path))

  run_test_path = RelativizePathToScript(
      os.path.join(os.path.dirname(__file__), 'test_runner.py'))

  vm_test_args = []
  if args.test_exe:
    vm_test_args.extend([
        'vm-test',
        '--test-exe',
        args.test_exe,
    ])
  elif args.tast_attr_expr or args.tast_tests:
    vm_test_args.extend([
        'tast',
        '--suite-name',
        args.suite_name,
    ])
    if args.tast_attr_expr:
      vm_test_args.extend([
          '--attr-expr',
          args.tast_attr_expr,
      ])
    else:
      for t in args.tast_tests:
        vm_test_args.extend(['-t', t])
  else:
    vm_test_args.append('host-cmd')
    if args.deploy_chrome:
      vm_test_args.append('--deploy-chrome')

  vm_test_args += [
      '--board',
      args.board,
      '-v',
  ]
  if args.use_vm:
    vm_test_args += ['--use-vm']

  vm_test_args += extra_args

  vm_test_path_args = [
      ('--cros-cache', RelativizePathToScript(args.cros_cache)),
  ]
  if args.runtime_deps_path:
    vm_test_path_args.append(('--runtime-deps-path',
                              RelativizePathToScript(args.runtime_deps_path)))
  if args.output_directory:
    vm_test_path_args.append(('--path-to-outdir',
                              RelativizePathToScript(args.output_directory)))

  with open(args.script_output_path, 'w') as script:
    script.write(
        SCRIPT_TEMPLATE.format(
            vm_test_script=run_test_path,
            vm_test_args=str(vm_test_args),
            vm_test_path_args=str(vm_test_path_args)))

  os.chmod(args.script_output_path, 0750)


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
