// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'chrome://resources/polymer/v3_0/iron-iconset-svg/iron-iconset-svg.js';

const element = document.createElement('iron-iconset-svg');
element.name = 'profiles';
element.innerHTML = `
<svg>
  <defs>
    <g id="add" viewBox="0 0 74 74">
      <circle cx="37" cy="37" r="37" stroke="none"/>
      <path d="M36.9999 46.4349C36.1315 46.4349 35.4274 45.7309 35.4274 44.8624V38.5724H29.1374C28.269 38.5724 27.5649 37.8684 27.5649 36.9999C27.5649 36.1315 28.269 35.4274 29.1374 35.4274H35.4274V29.1374C35.4274 28.269 36.1315 27.5649 36.9999 27.5649C37.8684 27.5649 38.5724 28.269 38.5724 29.1374V35.4274H44.8624C45.7309 35.4274 46.4349 36.1315 46.4349 36.9999C46.4349 37.8684 45.7309 38.5724 44.8624 38.5724H38.5724V44.8624C38.5724 45.7309 37.8684 46.4349 36.9999 46.4349Z" fill="var(--iron-icon-stroke-color)"/>
    </g>

    <g id="account-circle" viewBox="0 0 24 24" fill="var(--footer-text-color)" width="18px" height="18px">
      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z"/>
    </g>

    <g id="customize-banner" viewBox="0 0 678 266" width="678" height="266" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M70.51 115.677c-2.425 3.218-7.276 3.053-9.621-.248-6.711-9.738-6.63-23.107.97-32.928 7.762-9.903 20.538-12.957 31.453-8.5 3.639 1.65 4.852 6.272 2.426 9.408l-25.227 32.268zM531.612 112.52c1.744-1.18 4.236-.252 4.818 1.77 1.744 6.069-.582 12.811-6.064 16.351-5.566 3.624-12.544 2.95-17.279-1.18-1.578-1.433-1.412-3.961.332-5.141l18.193-11.8zM140 128.499c0 2.519-1.98 4.498-4.5 4.498-2.52.09-4.5-1.979-4.5-4.498 0-2.52 1.98-4.499 4.5-4.499 2.43 0 4.5 1.979 4.5 4.499z" fill="var(--theme-shape-color)"/><path d="M160.541 53.57c.993-4.303 5.297-7.035 9.601-6.042l18.294 4.222c4.304.993 7.035 5.297 6.042 9.602-.993 4.304-5.297 7.036-9.602 6.042L166.5 63.173c-4.304-.91-6.953-5.298-5.959-9.602z" stroke="var(--theme-shape-color)" stroke-width="2" stroke-miterlimit="10" stroke-linecap="round" stroke-linejoin="round"/><path d="M526 69c6.075 0 11-4.925 11-11s-4.925-11-11-11-11 4.925-11 11 4.925 11 11 11zM608.042 81.007L630.448 83c.944.08 1.631.876 1.545 1.753l-2.146 20.805c-.086.877-.945 1.515-1.889 1.435L605.552 105c-.944-.079-1.631-.876-1.545-1.753l2.146-20.805c.086-.877.945-1.515 1.889-1.435z" stroke="var(--theme-shape-color)" stroke-width="2"/>
    </g>
  </defs>
</svg>`;
document.head.appendChild(element);
