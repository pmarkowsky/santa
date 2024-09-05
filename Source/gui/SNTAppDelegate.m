/// Copyright 2015 Google Inc. All rights reserved.
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

#import "Source/gui/SNTAppDelegate.h"

#import <MOLXPCConnection/MOLXPCConnection.h>
#import <UserNotifications/UserNotifications.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#import "Source/gui/SNTAboutWindowController.h"
#import "Source/gui/SNTNotificationManager.h"

#import <Security/Security.h>
#import <UserNotifications/UserNotifications.h>


@interface SNTAppDelegate ()
@property SNTAboutWindowController *aboutWindowController;
@property SNTNotificationManager *notificationManager;
@property MOLXPCConnection *daemonListener;
@end

@implementation SNTAppDelegate

#pragma mark App Delegate methods

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
  [self setupMenu];
  self.notificationManager = [[SNTNotificationManager alloc] init];

  NSNotificationCenter *workspaceNotifications = [[NSWorkspace sharedWorkspace] notificationCenter];

  [workspaceNotifications addObserverForName:NSWorkspaceSessionDidResignActiveNotification
                                      object:nil
                                       queue:[NSOperationQueue currentQueue]
                                  usingBlock:^(NSNotification *note) {
                                    self.daemonListener.invalidationHandler = nil;
                                    [self.daemonListener invalidate];
                                    self.daemonListener = nil;
                                  }];
  [workspaceNotifications addObserverForName:NSWorkspaceSessionDidBecomeActiveNotification
                                      object:nil
                                       queue:[NSOperationQueue currentQueue]
                                  usingBlock:^(NSNotification *note) {
                                    [self attemptDaemonReconnection];
                                  }];

  [self createDaemonConnection];

  NSApplication *app = [NSApplication sharedApplication];
  [app registerForRemoteNotifications];
  NSLog(@"Registered for push notifications");
  // Print the bundle ID
  NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];

  NSLog(@"Listening for app Bundle ID: %@\n", bundleID);

  if (app.registeredForRemoteNotifications) {
        NSLog(@"Sucessfully registered for push notifications\n");
    } else {
        NSLog(@"Failed to register for Push Notifications\n");
    }
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
  if (!self.aboutWindowController) {
    self.aboutWindowController = [[SNTAboutWindowController alloc] init];
  }
  [self.aboutWindowController showWindow:self];
  return NO;
}

#pragma mark Connection handling

- (void)createDaemonConnection {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  WEAKIFY(self);

  // Create listener for return connection from daemon.
  NSXPCListener *listener = [NSXPCListener anonymousListener];
  self.daemonListener = [[MOLXPCConnection alloc] initServerWithListener:listener];
  self.daemonListener.privilegedInterface = [SNTXPCNotifierInterface notifierInterface];
  self.daemonListener.exportedObject = self.notificationManager;
  self.daemonListener.acceptedHandler = ^{
    dispatch_semaphore_signal(sema);
  };
  self.daemonListener.invalidationHandler = ^{
    STRONGIFY(self);
    [self attemptDaemonReconnection];
  };
  [self.daemonListener resume];

  // This listener will also handle bundle service requests to update the GUI.
  // When initializing connections with santabundleservice, the notification manager
  // will send along the endpoint so santabundleservice knows where to find us.
  self.notificationManager.notificationListener = listener.endpoint;

  // Tell daemon to connect back to the above listener.
  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
  [daemonConn resume];
  [[daemonConn remoteObjectProxy] setNotificationListener:listener.endpoint];
  [daemonConn invalidate];

  // Now wait for the connection to come in.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    [self attemptDaemonReconnection];
  }
}

- (void)attemptDaemonReconnection {
  self.daemonListener.invalidationHandler = nil;
  [self.daemonListener invalidate];
  [self performSelectorInBackground:@selector(createDaemonConnection) withObject:nil];
}

#pragma mark Menu Management

- (void)setupMenu {
  // Whilst the user will never see the menu, having one with the Copy and Select All options
  // allows the shortcuts for these items to work, which is useful for being able to copy
  // information from notifications. The mainMenu must have a nested menu for this to work properly.
  NSMenu *mainMenu = [[NSMenu alloc] init];
  NSMenu *editMenu = [[NSMenu alloc] init];
  [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
  [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
  NSMenuItem *editMenuItem = [[NSMenuItem alloc] init];
  [editMenuItem setSubmenu:editMenu];
  [mainMenu addItem:editMenuItem];
  [NSApp setMainMenu:mainMenu];
}

#pragma mark Push Notification

- (NSString *)hexStringFromData:(NSData *)data {
    if (!data || [data length] == 0) {
        return @"";
    }

    NSMutableString *hexString = [NSMutableString stringWithCapacity:[data length] * 2];
    const unsigned char *bytes = [data bytes];

    for (NSUInteger i = 0; i < [data length]; i++) {
        [hexString appendFormat:@"%02x", bytes[i]];
    }

    return hexString;
}

- (void)application:(NSApplication *)application didRegisterForRemoteNotificationsWithDeviceToken:(NSData *)deviceToken {
    NSString *tokenString = [self hexStringFromData:deviceToken];
    NSLog(@"PLM -- Device Token: %@\n\n", tokenString);
}

- (void)application:(NSApplication *)application didFailToRegisterForRemoteNotificationsWithError:(NSError *)error {
    NSLog(@"PLM -- Failed to register for remote notifications: %@\n\n", error.localizedDescription);
}

- (void)application:(NSApplication *)application didReceiveRemoteNotification:(NSDictionary<NSString *, id> *)userInfo  {
    NSLog(@"PLM2 -- Received Push Notification: %@\n", userInfo);
    // Handle the push notification
    // Tell the sync service to sync
    MOLXPCConnection *ss = [SNTXPCSyncServiceInterface configuredConnection];
    ss.invalidationHandler = ^(void) {
      NSLog(@"PLM2 -- Failed to connect to the sync service.");
    };

    [ss resume];

    NSXPCListener *logListener = [NSXPCListener anonymousListener];
    MOLXPCConnection *lr = [[MOLXPCConnection alloc] initServerWithListener:logListener];
    lr.exportedObject = self;
    lr.unprivilegedInterface =
    [NSXPCInterface interfaceWithProtocol:@protocol(SNTSyncServiceLogReceiverXPC)];
    [lr resume];

    NSLog(@"PLM Received Push Notfication: %@\n", userInfo);
    NSLog(@"PLM Syncing with log listener %@\n", logListener.endpoint);

    SNTSyncType syncType = SNTSyncTypeNormal;
    [[ss remoteObjectProxy] syncWithLogListener:logListener.endpoint
                   syncType:syncType
                      reply:^(SNTSyncStatusType status) {
                        if (status == SNTSyncStatusTypeTooManySyncsInProgress) {
                          NSLog(@"PLM -- Too many syncs in progress, try again later.");
                        } else {
                          NSLog(@"PLM -- sending notification");
                          [self.notificationManager postRuleSyncNotificationWithCustomMessage:@"osascript can now be run"];
                        }
                      }];
}

- (void)didReceiveLog:(NSString *)log {
  NSLog(@"PLM Pushed Sync -- %@", log);
}

@end
