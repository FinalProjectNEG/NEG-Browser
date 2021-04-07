// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.usage_stats;

/**
 * Class that generates opaque names for use as tokens, which are themselves used as pseudonyms for
 * a fully-qualified domain name (FQDN). These pseudonyms are used to identify the FQDN when
 * reporting usage to the platform, which isn't trusted to know the actual FQDN.
 */
public class TokenGenerator {
    private long mTokenCounter;

    /**
     * Default constructor for TokenGenerator.
     */
    public TokenGenerator() {
        this(1L);
    }

    /**
     * Construct a TokenGenerator, starting the sequence of tokens at start.
     */
    public TokenGenerator(long start) {
        mTokenCounter = start;
    }

    /**
     * Generate another token. The returned token is guaranteed to not duplicate any past tokens
     * generated by this instance of TokenGenerator.
     */
    public String nextToken() {
        return Long.toString(mTokenCounter++);
    }
}
