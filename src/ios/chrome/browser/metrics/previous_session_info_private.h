// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IOS_CHROME_BROWSER_METRICS_PREVIOUS_SESSION_INFO_PRIVATE_H_
#define IOS_CHROME_BROWSER_METRICS_PREVIOUS_SESSION_INFO_PRIVATE_H_

#import "ios/chrome/browser/metrics/previous_session_info.h"

@interface PreviousSessionInfo (TestingOnly)

// Redefined to be read-write.
@property(nonatomic, assign) NSInteger availableDeviceStorage;
@property(nonatomic, assign) BOOL didSeeMemoryWarningShortlyBeforeTerminating;
@property(nonatomic, assign) BOOL isFirstSessionAfterUpgrade;
@property(nonatomic, assign) float deviceBatteryLevel;
@property(nonatomic, assign)
    previous_session_info_constants::DeviceBatteryState deviceBatteryState;
@property(nonatomic, assign) BOOL OSRestartedAfterPreviousSession;
@property(nonatomic, copy) NSString* OSVersion;
@property(nonatomic, strong) NSDate* sessionStartTime;
@property(nonatomic, strong) NSDate* sessionEndTime;
@property(nonatomic, assign) BOOL terminatedDuringSessionRestoration;
@property(nonatomic, strong) NSMutableSet<NSString*>* connectedSceneSessionsIDs;
@property(nonatomic, copy)
    NSDictionary<NSString*, NSString*>* reportParameterURLs;

+ (void)resetSharedInstanceForTesting;

- (void)pauseRecordingCurrentSession;
- (void)resumeRecordingCurrentSession;
- (void)updateApplicationState;

@end

#endif  // IOS_CHROME_BROWSER_METRICS_PREVIOUS_SESSION_INFO_PRIVATE_H_
