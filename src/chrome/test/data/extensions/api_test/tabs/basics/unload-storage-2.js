// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

window.addEventListener('unload', (e) => {
  localStorage.setItem('did_run_unload_2', 'yes');
});
