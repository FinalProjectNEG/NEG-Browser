# Copyright 2020 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

settings = struct(
    project = "chromium",
    # Switch this to False for branches
    is_master = True,
    # Switch this to True for LTC/LTS branches
    is_lts_branch = False,
    ref = "refs/heads/master",
    ci_bucket = "ci",
    ci_poller = "master-gitiles-trigger",
    main_console_name = "main",
    main_console_title = "Chromium Main Console",
    cq_mirrors_console_name = "mirrors",
    cq_mirrors_console_title = "Chromium CQ Mirrors Console",
    try_bucket = "try",
    try_triggering_projects = ["angle", "dawn", "skia", "v8"],
    cq_group = "cq",
    cq_ref_regexp = "refs/heads/.+",
    main_list_view_name = "try",
    main_list_view_title = "Chromium CQ console",
    # Switch this to None for branches
    tree_status_host = "chromium-status.appspot.com",
)

def _validate_settings():
    if settings.is_master and settings.is_lts_branch:
        fail("is_master and is_lts_branch can't both be True")

_validate_settings()

def _generate_project_pyl(ctx):
    ctx.output["project.pyl"] = "\n".join([
        "# This is a non-LUCI generated file",
        "# This is consumed by presubmit checks that need to validate the config",
        repr(dict(
            # On master, we want to ensure that we don't have source side specs
            # defined for non-existent builders
            # On branches, we don't want to re-generate the source side specs as
            # that would increase branch day toil and complicate cherry-picks
            validate_source_side_specs_have_builder = settings.is_master,
        )),
        "",
    ])

lucicfg.generator(_generate_project_pyl)

def _milestone_details(*, project, ref, channel):
    """Define the details for an active milestone.

    Args:
      * project - The name of the LUCI project that is configured for the
        milestone.
      * ref - The ref in the git repository that contains the code for the
        milestone.
      * channel - The name of the release channel the milestone is in (used for
        identifying the milestone in the console header).
    """
    return struct(
        project = project,
        ref = ref,
        channel = channel,
    )

# The milestone names and branch numbers of branches that we have builders
# running for (including milestone-specific projects)
# Branch numbers and milestones can be viewed in the chromium column at
# https://chromiumdash.appspot.com/branches
# The 2 highest milestones will be the ones with active branches
ACTIVE_MILESTONES = {
    "m86": _milestone_details(
        project = "chromium-m86",
        ref = "refs/branch-heads/4240",
        channel = "Stable",
    ),
    "m87": _milestone_details(
        project = "chromium-m87",
        ref = "refs/branch-heads/4280",
        channel = "Beta",
    ),
}
