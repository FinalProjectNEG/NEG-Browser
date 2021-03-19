// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview Handles automatic sticky mode toggles. Turns sticky mode off
 * when the current range is over an editable; restores sticky mode when not on
 * an editable.
 */

goog.provide('SmartStickyMode');

goog.require('AutomationUtil');
goog.require('ChromeVox');
goog.require('ChromeVoxState');

/** @implements {ChromeVoxStateObserver} */
SmartStickyMode = class {
  constructor() {
    /** @private {boolean} */
    this.ignoreRangeChanges_ = false;

    /**
     * Tracks whether we (and not the user) turned off sticky mode when over an
     * editable.
     * @private {boolean}
     */
    this.didTurnOffStickyMode_ = false;
    /** @private {chrome.automation.AutomationNode|undefined} */
    this.ignoredNodeSubtree_;

    ChromeVoxState.addObserver(this);
  }

  /** @override */
  onCurrentRangeChanged(newRange) {
    if (!newRange || this.ignoreRangeChanges_ ||
        ChromeVoxState.isReadingContinuously ||
        localStorage['smartStickyMode'] !== 'true') {
      return;
    }

    const node = newRange.start.node;
    if (this.ignoredNodeSubtree_) {
      const editableOrRelatedEditable =
          this.getEditableOrRelatedEditable_(node);
      if (editableOrRelatedEditable &&
          AutomationUtil.isDescendantOf(
              editableOrRelatedEditable, this.ignoredNodeSubtree_)) {
        return;
      }

      // Clear it when the user leaves the subtree.
      this.ignoredNodeSubtree_ = undefined;
    }

    // Several cases arise which may lead to a sticky mode toggle:
    // The node is either editable itself or a descendant of an editable.
    // The node is a relation target of an editable.
    const shouldTurnOffStickyMode = !!this.getEditableOrRelatedEditable_(node);

    // This toggler should not make any changes when the range isn't what we're
    // lloking for and we haven't previously tracked any sticky mode state from
    // the user.
    if (!shouldTurnOffStickyMode && !this.didTurnOffStickyMode_) {
      return;
    }

    if (shouldTurnOffStickyMode) {
      if (!ChromeVox.isStickyPrefOn) {
        // Sticky mode was already off; do not track the current sticky state
        // since we may have set it ourselves.
        return;
      }

      if (this.didTurnOffStickyMode_) {
        // This should not be possible with |ChromeVox.isStickyPrefOn| set to
        // true.
        throw 'Unexpected sticky state value encountered.';
      }

      // Save the sticky state for restoration later.
      this.didTurnOffStickyMode_ = true;
      ChromeVox.earcons.playEarcon(Earcon.SMART_STICKY_MODE_OFF);
      ChromeVoxBackground.setPref(
          'sticky', false /* value */, true /* announce */);
    } else if (this.didTurnOffStickyMode_) {
      // Restore the previous sticky mode state.
      ChromeVox.earcons.playEarcon(Earcon.SMART_STICKY_MODE_ON);
      ChromeVoxBackground.setPref(
          'sticky', true /* value */, true /* announce */);
      this.didTurnOffStickyMode_ = false;
    }
  }

  /**
   * When called, ignores all changes in the current range when toggling sticky
   * mode without user input.
   */
  startIgnoringRangeChanges() {
    this.ignoreRangeChanges_ = true;
  }

  /**
   * When called, stops ignoring changes in the current range when toggling
   * sticky mode without user input.
   */
  stopIgnoringRangeChanges() {
    this.ignoreRangeChanges_ = false;
  }

  /**
   * Called whenever a user toggles sticky mode. In this case, we need to ensure
   * we reset our internal state appropriately.
   * @param {!cursors.Range} range The range when the sticky mode command was
   *     received.
   */
  onStickyModeCommand(range) {
    if (!this.didTurnOffStickyMode_) {
      return;
    }

    this.didTurnOffStickyMode_ = false;

    // Resetting the above isn't quite enough. We now have to track the current
    // range, if it is editable or has an editable relation, to ensure we don't
    // interfere with the user's sticky mode state.
    if (!range || !range.start) {
      return;
    }

    let editable = this.getEditableOrRelatedEditable_(range.start.node);
    while (editable && !editable.editableRoot) {
      if (!editable.parent ||
          editable.parent.state[chrome.automation.StateType.EDITABLE]) {
        // Not all editables from all trees (e.g. Android, views) set the
        // editable root boolean attribute.
        break;
      }
      editable = editable.parent;
    }
    this.ignoredNodeSubtree_ = editable;
  }

  /**
   * @param {chrome.automation.AutomationNode} node
   * @return {chrome.automation.AutomationNode}
   * @private
   */
  getEditableOrRelatedEditable_(node) {
    if (!node) {
      return null;
    }

    if (node.state[chrome.automation.StateType.EDITABLE]) {
      return node;
    } else if (
        node.parent &&
        node.parent.state[chrome.automation.StateType.EDITABLE]) {
      // This covers inline text boxes (which are not
      // editable themselves, but may have an editable parent).
      return node.parent;
    } else {
      let focus = node;
      let found;
      while (!found && focus) {
        if (focus.activeDescendantFor && focus.activeDescendantFor.length) {
          found = focus.activeDescendantFor.find(
              (n) => n.state[chrome.automation.StateType.EDITABLE]);
        }

        if (found) {
          return found;
        }

        if (focus.controlledBy && focus.controlledBy.length) {
          found = focus.controlledBy.find(
              (n) => n.state[chrome.automation.StateType.EDITABLE]);
        }

        if (found) {
          return found;
        }

        focus = focus.parent;
      }
    }

    return null;
  }
};
