/// Copyright 2016 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import <Foundation/Foundation.h>

#ifdef __cplusplus
#include <google/protobuf/message.h>
#endif

@class SNTSyncState;
@class MOLXPCConnection;

@interface SNTSyncStage : NSObject

@property(readonly, nonnull) NSURLSession *urlSession;
@property(readonly, nonnull) SNTSyncState *syncState;
@property(readonly, nonnull) MOLXPCConnection *daemonConn;

/**
  Initialize this stage. Designated initializer.

  @param state A holder for state used across requests
*/
- (nullable instancetype)initWithState:(nonnull SNTSyncState *)state NS_DESIGNATED_INITIALIZER;

- (nullable instancetype)init NS_UNAVAILABLE;

/**
  Performs this sync stage.

  @return YES if sync was successful.
*/
- (BOOL)sync;

/**
  The URL for this stage.

  @return The NSURL for this stage.
*/
- (nonnull NSURL *)stageURL;

#pragma mark Internal Helpers

#ifdef __cplusplus
/**
  Creates an NSMutableURLRequest pointing at the URL for this stage and containing the JSON-encoded
  data passed in as a protocol buffer message.

  @param dictionary The values to POST to the server.
*/
- (nullable NSMutableURLRequest *)requestWithMessage:(nullable google::protobuf::Message *)message;

/**
  Perform the passed in request and attempt to parse the response as JSON into the provided protobuf
  Message.

  @param request The request to perform
  @param message The message to parse the response into
  @Param timeout The number of seconds to allow the request to run before timing out.

  @return An error if performing the request failed.
*/
- (nullable NSError *)performRequest:(nonnull NSURLRequest *)request
                         intoMessage:(nullable google::protobuf::Message *)message
                             timeout:(NSTimeInterval)timeout;
#endif

@end
