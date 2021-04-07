# Copyright 2019 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from datetime import date
import logging
import os
import re
import shutil
import sys
import tempfile

from gpu_tests import color_profile_manager
from gpu_tests import common_browser_args as cba
from gpu_tests import gpu_integration_test
from gpu_tests import path_util
from gpu_tests.skia_gold import gpu_skia_gold_properties
from gpu_tests.skia_gold import gpu_skia_gold_session_manager

from py_utils import cloud_storage

from telemetry.util import image_util

GPU_RELATIVE_PATH = "content/test/data/gpu/"
GPU_DATA_DIR = os.path.join(path_util.GetChromiumSrcDir(), GPU_RELATIVE_PATH)
TEST_DATA_DIRS = [
    GPU_DATA_DIR,
    os.path.join(path_util.GetChromiumSrcDir(), 'media/test/data'),
]

SKIA_GOLD_CORPUS = 'chrome-gpu'


class _ImageParameters(object):
  def __init__(self):
    # Parameters for cloud storage reference images.
    self.vendor_id = None
    self.device_id = None
    self.vendor_string = None
    self.device_string = None
    self.msaa = False
    self.model_name = None
    self.driver_version = None
    self.driver_vendor = None


class SkiaGoldIntegrationTestBase(gpu_integration_test.GpuIntegrationTest):
  """Base class for all tests that upload results to Skia Gold."""
  # The command line options (which are passed to subclasses'
  # GenerateGpuTests) *must* be configured here, via a call to
  # SetParsedCommandLineOptions. If they are not, an error will be
  # raised when running the tests.
  _parsed_command_line_options = None

  _error_image_cloud_storage_bucket = 'chromium-browser-gpu-tests'

  # This information is class-scoped, so that it can be shared across
  # invocations of tests; but it's zapped every time the browser is
  # restarted with different command line arguments.
  _image_parameters = None

  _skia_gold_temp_dir = None
  _skia_gold_session_manager = None
  _skia_gold_properties = None

  @classmethod
  def SetParsedCommandLineOptions(cls, options):
    cls._parsed_command_line_options = options

  @classmethod
  def GetParsedCommandLineOptions(cls):
    return cls._parsed_command_line_options

  @classmethod
  def SetUpProcess(cls):
    options = cls.GetParsedCommandLineOptions()
    color_profile_manager.ForceUntilExitSRGB(
        options.dont_restore_color_profile_after_test)
    super(SkiaGoldIntegrationTestBase, cls).SetUpProcess()
    cls.CustomizeBrowserArgs([])
    cls.StartBrowser()
    cls.SetStaticServerDirs(TEST_DATA_DIRS)
    cls._skia_gold_temp_dir = tempfile.mkdtemp()

  @classmethod
  def GetSkiaGoldProperties(cls):
    if not cls._skia_gold_properties:
      cls._skia_gold_properties =\
          gpu_skia_gold_properties.GpuSkiaGoldProperties(
              cls.GetParsedCommandLineOptions())
    return cls._skia_gold_properties

  @classmethod
  def GetSkiaGoldSessionManager(cls):
    if not cls._skia_gold_session_manager:
      cls._skia_gold_session_manager =\
          gpu_skia_gold_session_manager.GpuSkiaGoldSessionManager(
              cls._skia_gold_temp_dir, cls.GetSkiaGoldProperties())
    return cls._skia_gold_session_manager

  @classmethod
  def GenerateBrowserArgs(cls, additional_args):
    """Adds default arguments to |additional_args|.

    See the parent class' method documentation for additional information.
    """
    default_args = super(SkiaGoldIntegrationTestBase,
                         cls).GenerateBrowserArgs(additional_args)
    default_args.extend([cba.ENABLE_GPU_BENCHMARKING, cba.TEST_TYPE_GPU])
    force_color_profile_arg = [
        arg for arg in default_args if arg.startswith('--force-color-profile=')
    ]
    if not force_color_profile_arg:
      default_args.extend([
          cba.FORCE_COLOR_PROFILE_SRGB,
          cba.ENSURE_FORCED_COLOR_PROFILE,
      ])
    return default_args

  @classmethod
  def StopBrowser(cls):
    super(SkiaGoldIntegrationTestBase, cls).StopBrowser()
    cls.ResetGpuInfo()

  @classmethod
  def TearDownProcess(cls):
    super(SkiaGoldIntegrationTestBase, cls).TearDownProcess()
    shutil.rmtree(cls._skia_gold_temp_dir)

  @classmethod
  def AddCommandlineArgs(cls, parser):
    super(SkiaGoldIntegrationTestBase, cls).AddCommandlineArgs(parser)
    parser.add_option(
        '--git-revision', help='Chrome revision being tested.', default=None)
    parser.add_option(
        '--test-machine-name',
        help='Name of the test machine. Specifying this argument causes this '
        'script to upload failure images and diffs to cloud storage directly, '
        'instead of relying on the archive_gpu_pixel_test_results.py script.',
        default='')
    parser.add_option(
        '--dont-restore-color-profile-after-test',
        dest='dont_restore_color_profile_after_test',
        action='store_true',
        default=False,
        help='(Mainly on Mac) don\'t restore the system\'s original color '
        'profile after the test completes; leave the system using the sRGB '
        'color profile. See http://crbug.com/784456.')
    parser.add_option(
        '--gerrit-issue',
        help='For Skia Gold integration. Gerrit issue ID.',
        default='')
    parser.add_option(
        '--gerrit-patchset',
        help='For Skia Gold integration. Gerrit patch set number.',
        default='')
    parser.add_option(
        '--buildbucket-id',
        help='For Skia Gold integration. Buildbucket build ID.',
        default='')
    parser.add_option(
        '--no-skia-gold-failure',
        action='store_true',
        default=False,
        help='For Skia Gold integration. Always report that the test passed '
        'even if the Skia Gold image comparison reported a failure, but '
        'otherwise perform the same steps as usual.')
    # Telemetry is *still* using optparse instead of argparse, so we can't have
    # these two options in a mutually exclusive group.
    parser.add_option(
        '--local-pixel-tests',
        action='store_true',
        default=None,
        help='Specifies to run the test harness in local run mode or not. When '
        'run in local mode, uploading to Gold is disabled and links to '
        'help with local debugging are output. Running in local mode also '
        'implies --no-luci-auth. If both this and --no-local-pixel-tests are '
        'left unset, the test harness will attempt to detect whether it is '
        'running on a workstation or not and set this option accordingly.')
    parser.add_option(
        '--no-local-pixel-tests',
        action='store_false',
        dest='local_pixel_tests',
        help='Specifies to run the test harness in non-local (bot) mode. When '
        'run in this mode, data is actually uploaded to Gold and triage links '
        'arge generated. If both this and --local-pixel-tests are left unset, '
        'the test harness will attempt to detect whether it is running on a '
        'workstation or not and set this option accordingly.')
    parser.add_option(
        '--no-luci-auth',
        action='store_true',
        default=False,
        help='Don\'t use the service account provided by LUCI for '
        'authentication for Skia Gold, instead relying on gsutil to be '
        'pre-authenticated. Meant for testing locally instead of on the bots.')
    parser.add_option(
        '--bypass-skia-gold-functionality',
        action='store_true',
        default=False,
        help='Bypass all interaction with Skia Gold, effectively disabling the '
        'image comparison portion of any tests that use Gold. Only meant to '
        'be used in case a Gold outage occurs and cannot be fixed quickly.')

  @classmethod
  def ResetGpuInfo(cls):
    cls._image_parameters = None

  @classmethod
  def GetImageParameters(cls, page):
    if not cls._image_parameters:
      cls._ComputeGpuInfo(page)
    return cls._image_parameters

  @classmethod
  def _ComputeGpuInfo(cls, page):
    if cls._image_parameters:
      return
    browser = cls.browser
    system_info = browser.GetSystemInfo()
    if not system_info:
      raise Exception('System info must be supported by the browser')
    if not system_info.gpu:
      raise Exception('GPU information was absent')
    device = system_info.gpu.devices[0]
    cls._image_parameters = _ImageParameters()
    params = cls._image_parameters
    if device.vendor_id and device.device_id:
      params.vendor_id = device.vendor_id
      params.device_id = device.device_id
    elif device.vendor_string and device.device_string:
      params.vendor_string = device.vendor_string
      params.device_string = device.device_string
    elif page.gpu_process_disabled:
      # Match the vendor and device IDs that the browser advertises
      # when the software renderer is active.
      params.vendor_id = 65535
      params.device_id = 65535
    else:
      raise Exception('GPU device information was incomplete')
    # TODO(senorblanco): This should probably be checking
    # for the presence of the extensions in system_info.gpu_aux_attributes
    # in order to check for MSAA, rather than sniffing the blocklist.
    params.msaa = not (('disable_chromium_framebuffer_multisample' in
                        system_info.gpu.driver_bug_workarounds) or
                       ('disable_multisample_render_to_texture' in system_info.
                        gpu.driver_bug_workarounds))
    params.model_name = system_info.model_name
    params.driver_version = device.driver_version
    params.driver_vendor = device.driver_vendor

  @classmethod
  def _UploadBitmapToCloudStorage(cls, bucket, name, bitmap, public=False):
    # This sequence of steps works on all platforms to write a temporary
    # PNG to disk, following the pattern in bitmap_unittest.py. The key to
    # avoiding PermissionErrors seems to be to not actually try to write to
    # the temporary file object, but to re-open its name for all operations.
    temp_file = tempfile.NamedTemporaryFile(suffix='.png').name
    image_util.WritePngFile(bitmap, temp_file)
    cloud_storage.Insert(bucket, name, temp_file, publicly_readable=public)

  # Not used consistently, but potentially useful for debugging issues on the
  # bots, so kept around for future use.
  @classmethod
  def _UploadGoldErrorImageToCloudStorage(cls, image_name, screenshot):
    revision = cls.GetSkiaGoldProperties().git_revision
    machine_name = re.sub(r'\W+', '_',
                          cls.GetParsedCommandLineOptions().test_machine_name)
    base_bucket = '%s/gold_failures' % (cls._error_image_cloud_storage_bucket)
    image_name_with_revision_and_machine = '%s_%s_%s.png' % (
        image_name, machine_name, revision)
    cls._UploadBitmapToCloudStorage(
        base_bucket,
        image_name_with_revision_and_machine,
        screenshot,
        public=True)

  @staticmethod
  def _UrlToImageName(url):
    image_name = re.sub(r'^(http|https|file)://(/*)', '', url)
    image_name = re.sub(r'\.\./', '', image_name)
    image_name = re.sub(r'(\.|/|-)', '_', image_name)
    return image_name

  def GetGoldJsonKeys(self, page):
    """Get all the JSON metadata that will be passed to golctl."""
    img_params = self.GetImageParameters(page)
    # The frequently changing last part of the ANGLE driver version (revision of
    # some sort?) messes a bit with inexact matching since each revision will
    # be treated as a separate trace, so strip it off.
    _StripAngleRevisionFromDriver(img_params)
    # All values need to be strings, otherwise goldctl fails.
    gpu_keys = {
        'vendor_id':
        _ToHexOrNone(img_params.vendor_id),
        'device_id':
        _ToHexOrNone(img_params.device_id),
        'vendor_string':
        _ToNonEmptyStrOrNone(img_params.vendor_string),
        'device_string':
        _ToNonEmptyStrOrNone(img_params.device_string),
        'msaa':
        str(img_params.msaa),
        'model_name':
        _ToNonEmptyStrOrNone(img_params.model_name),
        'os':
        _ToNonEmptyStrOrNone(self.browser.platform.GetOSName()),
        'os_version':
        _ToNonEmptyStrOrNone(self.browser.platform.GetOSVersionName()),
        'os_version_detail_string':
        _ToNonEmptyStrOrNone(self.browser.platform.GetOSVersionDetailString()),
        'driver_version':
        _ToNonEmptyStrOrNone(img_params.driver_version),
        'driver_vendor':
        _ToNonEmptyStrOrNone(img_params.driver_vendor),
        'combined_hardware_identifier':
        _GetCombinedHardwareIdentifier(img_params),
    }
    # If we have a grace period active, then the test is potentially flaky.
    # Include a pair that will cause Gold to ignore any untriaged images, which
    # will prevent it from automatically commenting on unrelated CLs that happen
    # to produce a new image.
    if _GracePeriodActive(page):
      gpu_keys['ignore'] = '1'
    return gpu_keys

  def _UploadTestResultToSkiaGold(self, image_name, screenshot, page):
    """Compares the given image using Skia Gold and uploads the result.

    No uploading is done if the test is being run in local run mode. Compares
    the given screenshot to baselines provided by Gold, raising an Exception if
    a match is not found.

    Args:
      image_name: the name of the image being checked.
      screenshot: the image being checked as a Telemetry Bitmap.
      page: the GPU PixelTestPage object for the test.
    """
    # Write screenshot to PNG file on local disk.
    png_temp_file = tempfile.NamedTemporaryFile(
        suffix='.png', dir=self._skia_gold_temp_dir).name
    image_util.WritePngFile(screenshot, png_temp_file)

    gpu_keys = self.GetGoldJsonKeys(page)
    gold_session = self.GetSkiaGoldSessionManager().GetSkiaGoldSession(
        gpu_keys, corpus=SKIA_GOLD_CORPUS)
    gold_properties = self.GetSkiaGoldProperties()
    use_luci = not (gold_properties.local_pixel_tests
                    or gold_properties.no_luci_auth)

    inexact_matching_args = page.matching_algorithm.GetCmdline()

    status, error = gold_session.RunComparison(
        name=image_name,
        png_file=png_temp_file,
        inexact_matching_args=inexact_matching_args,
        use_luci=use_luci)
    if not status:
      return

    status_codes =\
        self.GetSkiaGoldSessionManager().GetSessionClass().StatusCodes
    if status == status_codes.AUTH_FAILURE:
      logging.error('Gold authentication failed with output %s', error)
    elif status == status_codes.INIT_FAILURE:
      logging.error('Gold initialization failed with output %s', error)
    elif status == status_codes.COMPARISON_FAILURE_REMOTE:
      # We currently don't have an internal instance + public mirror like the
      # general Chrome Gold instance, so just report the "internal" link, which
      # points to the correct instance.
      _, triage_link = gold_session.GetTriageLinks(image_name)
      if not triage_link:
        logging.error('Failed to get triage link for %s, raw output: %s',
                      image_name, error)
        logging.error('Reason for no triage link: %s',
                      gold_session.GetTriageLinkOmissionReason(image_name))
      elif gold_properties.IsTryjobRun():
        self.artifacts.CreateLink('triage_link_for_entire_cl', triage_link)
      else:
        self.artifacts.CreateLink('gold_triage_link', triage_link)
    elif status == status_codes.COMPARISON_FAILURE_LOCAL:
      logging.error('Local comparison failed. Local diff files:')
      _OutputLocalDiffFiles(gold_session, image_name)
    elif status == status_codes.LOCAL_DIFF_FAILURE:
      logging.error(
          'Local comparison failed and an error occurred during diff '
          'generation: %s', error)
      # There might be some files, so try outputting them.
      logging.error('Local diff files:')
      _OutputLocalDiffFiles(gold_session, image_name)
    else:
      logging.error(
          'Given unhandled SkiaGoldSession StatusCode %s with error %s', status,
          error)
    if self._ShouldReportGoldFailure(page):
      raise Exception('goldctl command failed, see above for details')

  def _ShouldReportGoldFailure(self, page):
    """Determines if a Gold failure should actually be surfaced.

    Args:
      page: The GPU PixelTestPage object for the test.

    Returns:
      True if the failure should be surfaced, i.e. the test should fail,
      otherwise False.
    """
    parsed_options = self.GetParsedCommandLineOptions()
    # Don't surface if we're explicitly told not to.
    if parsed_options.no_skia_gold_failure:
      return False
    # Don't surface if the test was recently added and we're still within its
    # grace period.
    if _GracePeriodActive(page):
      return False
    return True

  @classmethod
  def GenerateGpuTests(cls, options):
    del options
    return []

  def RunActualGpuTest(self, options):
    raise NotImplementedError(
        'RunActualGpuTest must be overridden in a subclass')


def _ToHex(num):
  return hex(int(num))


def _ToHexOrNone(num):
  return 'None' if num == None else _ToHex(num)


def _ToNonEmptyStrOrNone(val):
  return 'None' if val == '' else str(val)


def _GracePeriodActive(page):
  """Returns whether a grace period is currently active for a test.

  Args:
    page: The GPU PixelTestPage object for the test in question.

  Returns:
    True if a grace period is defined for |page| and has not yet expired.
    Otherwise, False.
  """
  return page.grace_period_end and date.today() <= page.grace_period_end


def _StripAngleRevisionFromDriver(img_params):
  """Strips the revision off the end of an ANGLE driver version.

  E.g. 2.1.0.b50541b2d6c4 -> 2.1.0

  Modifies the string in place. No-ops if the driver vendor is not ANGLE.

  Args:
    img_params: An _ImageParameters instance to modify.
  """
  if 'ANGLE' not in img_params.driver_vendor or not img_params.driver_version:
    return
  # Assume that we're never going to have portions of the driver we care about
  # that are longer than 8 characters.
  driver_parts = img_params.driver_version.split('.')
  kept_parts = []
  for part in driver_parts:
    if len(part) > 8:
      break
    kept_parts.append(part)
  img_params.driver_version = '.'.join(kept_parts)


def _GetCombinedHardwareIdentifier(img_params):
  """Combine all relevant hardware identifiers into a single key.

  This makes Gold forwarding more precise by allowing us to forward explicit
  configurations instead of individual components.
  """
  vendor_id = _ToHexOrNone(img_params.vendor_id)
  device_id = _ToHexOrNone(img_params.device_id)
  device_string = _ToNonEmptyStrOrNone(img_params.device_string)
  combined_hw_identifiers = ('vendor_id:{vendor_id}, '
                             'device_id:{device_id}, '
                             'device_string:{device_string}')
  combined_hw_identifiers = combined_hw_identifiers.format(
      vendor_id=vendor_id, device_id=device_id, device_string=device_string)
  return combined_hw_identifiers


def _OutputLocalDiffFiles(gold_session, image_name):
  """Logs the local diff image files from the given SkiaGoldSession.

  Args:
    gold_session: A skia_gold_session.SkiaGoldSession instance to pull files
        from.
    image_name: A string containing the name of the image/test that was
        compared.
  """
  given_file = gold_session.GetGivenImageLink(image_name)
  closest_file = gold_session.GetClosestImageLink(image_name)
  diff_file = gold_session.GetDiffImageLink(image_name)
  failure_message = 'Unable to retrieve link'
  logging.error('Generated image: %s', given_file or failure_message)
  logging.error('Closest image: %s', closest_file or failure_message)
  logging.error('Diff image: %s', diff_file or failure_message)


def load_tests(loader, tests, pattern):
  del loader, tests, pattern  # Unused.
  return gpu_integration_test.LoadAllTestsInModule(sys.modules[__name__])
