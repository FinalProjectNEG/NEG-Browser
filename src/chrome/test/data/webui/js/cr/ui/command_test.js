// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

function testCommandDefaultPrevented() {
  var calls = 0;
  document.addEventListener('canExecute', function(e) {
    ++calls;
    assertFalse(e.defaultPrevented);
    e.canExecute = true;
    assertTrue(e.defaultPrevented);
  });

  cr.ui.decorate('command', cr.ui.Command);
  document.querySelector('command').canExecuteChange();
  assertEquals(1, calls);
}

function createEvent(key, code, keyCode) {
  return {
    key: key,
    code: code,
    keyCode: keyCode,
    altKey: false,
    ctrlKey: true,
    metaKey: false,
    shiftKey: false
  };
}

function testShortcuts() {
  cr.ui.decorate('command', cr.ui.Command);
  const cmd = document.querySelector('command');
  // US keyboard - qwerty-N should work.
  assertTrue(cmd.matchesEvent(createEvent('n', 'KeyN', 0x4e)));
  // DV keyboard - qwerty-L (dvorak-N) should work.
  assertTrue(cmd.matchesEvent(createEvent('n', 'KeyL', 0x4e)));
  // DV keyboard - qwerty-N (dvorak-B) should not work.
  assertFalse(cmd.matchesEvent(createEvent('b', 'KeyN', 0x42)));
  // RU keyboard - qwerty-N (Cyrillic Te) should work.
  assertTrue(cmd.matchesEvent(createEvent('т', 'KeyN', 0x4e)));
}
