// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/accessibility/accessibility_tree_formatter_utils_auralinux.h"

#include "base/stl_util.h"

namespace content {
namespace {
struct PlatformConstantToNameEntry {
  int32_t value;
  const char* name;
};

const char* GetNameForPlatformConstant(
    const PlatformConstantToNameEntry table[],
    size_t table_size,
    int32_t value) {
  for (size_t i = 0; i < table_size; ++i) {
    auto& entry = table[i];
    if (entry.value == value)
      return entry.name;
  }
  return "<unknown>";
}
}  // namespace

#define QUOTE(X) \
  { X, #X }

#define ATSPI_CHECK_VERSION(major, minor, micro)                           \
  (major) < ATSPI_MAJOR_VERSION ||                                         \
      ((major) == ATSPI_MAJOR_VERSION && (minor) < ATSPI_MINOR_VERSION) || \
      ((major) == ATSPI_MAJOR_VERSION && (minor) == ATSPI_MINOR_VERSION && \
       (micro) <= ATSPI_MICRO_VERSION)

CONTENT_EXPORT const char* ATSPIStateToString(AtspiStateType state) {
  // These roles are listed in the order they are defined in the enum so that
  // we can more easily discard ones that are too new for the version of
  // atspi2 that we are compiling against.
  static const PlatformConstantToNameEntry state_table[] = {
    QUOTE(ATSPI_STATE_INVALID),
    QUOTE(ATSPI_STATE_ACTIVE),
    QUOTE(ATSPI_STATE_ARMED),
    QUOTE(ATSPI_STATE_BUSY),
    QUOTE(ATSPI_STATE_CHECKED),
    QUOTE(ATSPI_STATE_COLLAPSED),
    QUOTE(ATSPI_STATE_DEFUNCT),
    QUOTE(ATSPI_STATE_EDITABLE),
    QUOTE(ATSPI_STATE_ENABLED),
    QUOTE(ATSPI_STATE_EXPANDABLE),
    QUOTE(ATSPI_STATE_EXPANDED),
    QUOTE(ATSPI_STATE_FOCUSABLE),
    QUOTE(ATSPI_STATE_FOCUSED),
    QUOTE(ATSPI_STATE_HAS_TOOLTIP),
    QUOTE(ATSPI_STATE_HORIZONTAL),
    QUOTE(ATSPI_STATE_ICONIFIED),
    QUOTE(ATSPI_STATE_MODAL),
    QUOTE(ATSPI_STATE_MULTI_LINE),
    QUOTE(ATSPI_STATE_MULTISELECTABLE),
    QUOTE(ATSPI_STATE_OPAQUE),
    QUOTE(ATSPI_STATE_PRESSED),
    QUOTE(ATSPI_STATE_RESIZABLE),
    QUOTE(ATSPI_STATE_SELECTABLE),
    QUOTE(ATSPI_STATE_SELECTED),
    QUOTE(ATSPI_STATE_SENSITIVE),
    QUOTE(ATSPI_STATE_SHOWING),
    QUOTE(ATSPI_STATE_SINGLE_LINE),
    QUOTE(ATSPI_STATE_STALE),
    QUOTE(ATSPI_STATE_TRANSIENT),
    QUOTE(ATSPI_STATE_VERTICAL),
    QUOTE(ATSPI_STATE_VISIBLE),
    QUOTE(ATSPI_STATE_MANAGES_DESCENDANTS),
    QUOTE(ATSPI_STATE_INDETERMINATE),
    QUOTE(ATSPI_STATE_REQUIRED),
    QUOTE(ATSPI_STATE_TRUNCATED),
    QUOTE(ATSPI_STATE_ANIMATED),
    QUOTE(ATSPI_STATE_INVALID_ENTRY),
    QUOTE(ATSPI_STATE_SUPPORTS_AUTOCOMPLETION),
    QUOTE(ATSPI_STATE_SELECTABLE_TEXT),
    QUOTE(ATSPI_STATE_IS_DEFAULT),
    QUOTE(ATSPI_STATE_VISITED),
#if ATSPI_CHECK_VERSION(2, 12, 0)
    QUOTE(ATSPI_STATE_CHECKABLE),
    QUOTE(ATSPI_STATE_HAS_POPUP),
#endif
#if ATSPI_CHECK_VERSION(2, 16, 0)
    QUOTE(ATSPI_STATE_READ_ONLY),
#endif
  };

  return GetNameForPlatformConstant(state_table, base::size(state_table),
                                    state);
}

CONTENT_EXPORT const char* ATSPIRoleToString(AtspiRole role) {
  // These roles are listed in the order they are defined in the enum so that
  // we can more easily discard ones that are too new for the version of
  // atspi2 that we are compiling against.
  static const PlatformConstantToNameEntry role_table[] = {
    QUOTE(ATSPI_ROLE_INVALID),
    QUOTE(ATSPI_ROLE_ACCELERATOR_LABEL),
    QUOTE(ATSPI_ROLE_ALERT),
    QUOTE(ATSPI_ROLE_ANIMATION),
    QUOTE(ATSPI_ROLE_ARROW),
    QUOTE(ATSPI_ROLE_CALENDAR),
    QUOTE(ATSPI_ROLE_CANVAS),
    QUOTE(ATSPI_ROLE_CHECK_BOX),
    QUOTE(ATSPI_ROLE_CHECK_MENU_ITEM),
    QUOTE(ATSPI_ROLE_COLOR_CHOOSER),
    QUOTE(ATSPI_ROLE_COLUMN_HEADER),
    QUOTE(ATSPI_ROLE_COMBO_BOX),
    QUOTE(ATSPI_ROLE_DATE_EDITOR),
    QUOTE(ATSPI_ROLE_DESKTOP_ICON),
    QUOTE(ATSPI_ROLE_DESKTOP_FRAME),
    QUOTE(ATSPI_ROLE_DIAL),
    QUOTE(ATSPI_ROLE_DIALOG),
    QUOTE(ATSPI_ROLE_DIRECTORY_PANE),
    QUOTE(ATSPI_ROLE_DRAWING_AREA),
    QUOTE(ATSPI_ROLE_FILE_CHOOSER),
    QUOTE(ATSPI_ROLE_FILLER),
    QUOTE(ATSPI_ROLE_FOCUS_TRAVERSABLE),
    QUOTE(ATSPI_ROLE_FONT_CHOOSER),
    QUOTE(ATSPI_ROLE_FRAME),
    QUOTE(ATSPI_ROLE_GLASS_PANE),
    QUOTE(ATSPI_ROLE_HTML_CONTAINER),
    QUOTE(ATSPI_ROLE_ICON),
    QUOTE(ATSPI_ROLE_IMAGE),
    QUOTE(ATSPI_ROLE_INTERNAL_FRAME),
    QUOTE(ATSPI_ROLE_LABEL),
    QUOTE(ATSPI_ROLE_LAYERED_PANE),
    QUOTE(ATSPI_ROLE_LIST),
    QUOTE(ATSPI_ROLE_LIST_ITEM),
    QUOTE(ATSPI_ROLE_MENU),
    QUOTE(ATSPI_ROLE_MENU_BAR),
    QUOTE(ATSPI_ROLE_MENU_ITEM),
    QUOTE(ATSPI_ROLE_OPTION_PANE),
    QUOTE(ATSPI_ROLE_PAGE_TAB),
    QUOTE(ATSPI_ROLE_PAGE_TAB_LIST),
    QUOTE(ATSPI_ROLE_PANEL),
    QUOTE(ATSPI_ROLE_PASSWORD_TEXT),
    QUOTE(ATSPI_ROLE_POPUP_MENU),
    QUOTE(ATSPI_ROLE_PROGRESS_BAR),
    QUOTE(ATSPI_ROLE_PUSH_BUTTON),
    QUOTE(ATSPI_ROLE_RADIO_BUTTON),
    QUOTE(ATSPI_ROLE_RADIO_MENU_ITEM),
    QUOTE(ATSPI_ROLE_ROOT_PANE),
    QUOTE(ATSPI_ROLE_ROW_HEADER),
    QUOTE(ATSPI_ROLE_SCROLL_BAR),
    QUOTE(ATSPI_ROLE_SCROLL_PANE),
    QUOTE(ATSPI_ROLE_SEPARATOR),
    QUOTE(ATSPI_ROLE_SLIDER),
    QUOTE(ATSPI_ROLE_SPIN_BUTTON),
    QUOTE(ATSPI_ROLE_SPLIT_PANE),
    QUOTE(ATSPI_ROLE_STATUS_BAR),
    QUOTE(ATSPI_ROLE_TABLE),
    QUOTE(ATSPI_ROLE_TABLE_CELL),
    QUOTE(ATSPI_ROLE_TABLE_COLUMN_HEADER),
    QUOTE(ATSPI_ROLE_TABLE_ROW_HEADER),
    QUOTE(ATSPI_ROLE_TEAROFF_MENU_ITEM),
    QUOTE(ATSPI_ROLE_TERMINAL),
    QUOTE(ATSPI_ROLE_TEXT),
    QUOTE(ATSPI_ROLE_TOGGLE_BUTTON),
    QUOTE(ATSPI_ROLE_TOOL_BAR),
    QUOTE(ATSPI_ROLE_TOOL_TIP),
    QUOTE(ATSPI_ROLE_TREE),
    QUOTE(ATSPI_ROLE_TREE_TABLE),
    QUOTE(ATSPI_ROLE_UNKNOWN),
    QUOTE(ATSPI_ROLE_VIEWPORT),
    QUOTE(ATSPI_ROLE_WINDOW),
    QUOTE(ATSPI_ROLE_EXTENDED),
    QUOTE(ATSPI_ROLE_HEADER),
    QUOTE(ATSPI_ROLE_FOOTER),
    QUOTE(ATSPI_ROLE_PARAGRAPH),
    QUOTE(ATSPI_ROLE_RULER),
    QUOTE(ATSPI_ROLE_APPLICATION),
    QUOTE(ATSPI_ROLE_AUTOCOMPLETE),
    QUOTE(ATSPI_ROLE_EDITBAR),
    QUOTE(ATSPI_ROLE_EMBEDDED),
    QUOTE(ATSPI_ROLE_ENTRY),
    QUOTE(ATSPI_ROLE_CHART),
    QUOTE(ATSPI_ROLE_CAPTION),
    QUOTE(ATSPI_ROLE_DOCUMENT_FRAME),
    QUOTE(ATSPI_ROLE_HEADING),
    QUOTE(ATSPI_ROLE_PAGE),
    QUOTE(ATSPI_ROLE_SECTION),
    QUOTE(ATSPI_ROLE_REDUNDANT_OBJECT),
    QUOTE(ATSPI_ROLE_FORM),
    QUOTE(ATSPI_ROLE_LINK),
    QUOTE(ATSPI_ROLE_INPUT_METHOD_WINDOW),
    QUOTE(ATSPI_ROLE_TABLE_ROW),
    QUOTE(ATSPI_ROLE_TREE_ITEM),
    QUOTE(ATSPI_ROLE_DOCUMENT_SPREADSHEET),
    QUOTE(ATSPI_ROLE_DOCUMENT_PRESENTATION),
    QUOTE(ATSPI_ROLE_DOCUMENT_TEXT),
    QUOTE(ATSPI_ROLE_DOCUMENT_WEB),
    QUOTE(ATSPI_ROLE_DOCUMENT_EMAIL),
    QUOTE(ATSPI_ROLE_COMMENT),
    QUOTE(ATSPI_ROLE_LIST_BOX),
    QUOTE(ATSPI_ROLE_GROUPING),
    QUOTE(ATSPI_ROLE_IMAGE_MAP),
    QUOTE(ATSPI_ROLE_NOTIFICATION),
    QUOTE(ATSPI_ROLE_INFO_BAR),
    QUOTE(ATSPI_ROLE_LEVEL_BAR),
#if ATSPI_CHECK_VERSION(2, 12, 0)
    QUOTE(ATSPI_ROLE_TITLE_BAR),
    QUOTE(ATSPI_ROLE_BLOCK_QUOTE),
    QUOTE(ATSPI_ROLE_AUDIO),
    QUOTE(ATSPI_ROLE_VIDEO),
    QUOTE(ATSPI_ROLE_DEFINITION),
    QUOTE(ATSPI_ROLE_ARTICLE),
    QUOTE(ATSPI_ROLE_LANDMARK),
    QUOTE(ATSPI_ROLE_LOG),
    QUOTE(ATSPI_ROLE_MARQUEE),
    QUOTE(ATSPI_ROLE_MATH),
    QUOTE(ATSPI_ROLE_RATING),
    QUOTE(ATSPI_ROLE_TIMER),
#endif
#if ATSPI_CHECK_VERSION(2, 16, 0)
    QUOTE(ATSPI_ROLE_STATIC),
    QUOTE(ATSPI_ROLE_MATH_FRACTION),
    QUOTE(ATSPI_ROLE_MATH_ROOT),
    QUOTE(ATSPI_ROLE_SUBSCRIPT),
    QUOTE(ATSPI_ROLE_SUPERSCRIPT),
#endif
#if ATSPI_CHECK_VERSION(2, 26, 0)
    QUOTE(ATSPI_ROLE_DESCRIPTION_LIST),
    QUOTE(ATSPI_ROLE_DESCRIPTION_TERM),
    QUOTE(ATSPI_ROLE_DESCRIPTION_VALUE),
    QUOTE(ATSPI_ROLE_FOOTNOTE),
#endif
  };

  return GetNameForPlatformConstant(role_table, base::size(role_table), role);
}

// This is used to ensure a standard set of AtkRole name conversions between
// different versions of ATK. Older versions may not have an implementation of
// a new role and newer versions may have changed the name returned by
// atk_role_get_name. This table should be kept up to date with newer ATK
// releases.
const char* const kRoleNames[] = {
    "invalid",  // ATK_ROLE_INVALID.
    "accelerator label",
    "alert",
    "animation",
    "arrow",
    "calendar",
    "canvas",
    "check box",
    "check menu item",
    "color chooser",
    "column header",
    "combo box",
    "dateeditor",
    "desktop icon",
    "desktop frame",
    "dial",
    "dialog",
    "directory pane",
    "drawing area",
    "file chooser",
    "filler",
    "fontchooser",
    "frame",
    "glass pane",
    "html container",
    "icon",
    "image",
    "internal frame",
    "label",
    "layered pane",
    "list",
    "list item",
    "menu",
    "menu bar",
    "menu item",
    "option pane",
    "page tab",
    "page tab list",
    "panel",
    "password text",
    "popup menu",
    "progress bar",
    "push button",
    "radio button",
    "radio menu item",
    "root pane",
    "row header",
    "scroll bar",
    "scroll pane",
    "separator",
    "slider",
    "split pane",
    "spin button",
    "statusbar",
    "table",
    "table cell",
    "table column header",
    "table row header",
    "tear off menu item",
    "terminal",
    "text",
    "toggle button",
    "tool bar",
    "tool tip",
    "tree",
    "tree table",
    "unknown",
    "viewport",
    "window",
    "header",
    "footer",
    "paragraph",
    "ruler",
    "application",
    "autocomplete",
    "edit bar",
    "embedded component",
    "entry",
    "chart",
    "caption",
    "document frame",
    "heading",
    "page",
    "section",
    "redundant object",
    "form",
    "link",
    "input method window",
    "table row",
    "tree item",
    "document spreadsheet",
    "document presentation",
    "document text",
    "document web",
    "document email",
    "comment",
    "list box",
    "grouping",
    "image map",
    "notification",
    "info bar",
    "level bar",
    "title bar",
    "block quote",
    "audio",
    "video",
    "definition",
    "article",
    "landmark",
    "log",
    "marquee",
    "math",
    "rating",
    "timer",
    "description list",
    "description term",
    "description value",
    "static",
    "math fraction",
    "math root",
    "subscript",
    "superscript",
    "footnote",           // ATK_ROLE_FOOTNOTE = 122.
    "content deletion",   // ATK_ROLE_CONTENT_DELETION = 123.
    "content insertion",  // ATK_ROLE_CONTENT_DELETION = 124.
};

const char* AtkRoleToString(AtkRole role) {
  if (role < G_N_ELEMENTS(kRoleNames))
    return kRoleNames[role];
  return "<unknown AtkRole>";
}

}  // namespace content
