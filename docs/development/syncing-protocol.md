---
title: Sync Protocol
parent: Development
---

# Syncing Overview

This document explains the sync protocol for an overview of the
process see  [[Sync Overview]]. 

#### Background

Santa can be run and configured with a sync server. Using a sync server will
enable an admin to configures rules and multiple other settings from the sync
server itself. Santa was designed from the start with a sync server in mind.
This allows an admin to easily configure and sync rules across a fleet of macOS
systems. 

# The Santa Sync Server Protocol Overview

The Santa Sync Server Protocol is an HTTP/JSON Restful protocol. The
`santasyncservice` initiates the protocol by connceting to the syncserver. 

## Concepts

* **Setting** -- A configuration option that 
* **Event** -- An event is a JSON record of a choice made by Santad (e.g. block) blockable
  * **BundleEvent** -- A bundle event.
* **Rule** --  A policy for allowing or denying an action  tied to a specifici attribute of a binary (e.g. hash, signing cert, Team ID).

## Push Notifications

## Full Sync vs. Sync

The protocol that Santad and the Sync Server use has two modes

1. Full Sync
2. Preflight only
3. Rules Download only
The protocol also supports two smaller syncs that only consists of oning a single step e.g. preflight, and ruledownload.

A full sync is used to do the following things:

 - Report config options and machine ID for a Santad instance
 - Provides the means to retrieve new configuration options from a Sync Server
 - Supports uploading events binaries that caused blockable events for further analysis
 - Download new rules and add them to the database

A full sync consists of all of these options and is broken down into four
stages. 

| Stage | What it Does |
| **Preflight ** | Report config settings to Sync Server & retrieve new ones |
| **Event Upload** | Report new blockable events to the Sync Server for further analysis |
| **Rule Download** | Retrieves new rules |
| **Postflight** | Reports stats | 

Each Stage is an HTTP/JSON transaction and follows the following outline.

```mermaidjs
santasyncservice ->> syncserver: preflight HTTP POST Request ("/santa/v1/preflight/<machine_id>")

```

### Stages

All URLs are of the form `/<stage_name>/<machine_id>`, e.g. the preflight URL is

#### Preflight

The preflight stage is used for the Santa daemon to report Information about the machine.


Initially makes the request POST /preflight/<machine_id> HTTP/1.1

With a JSON object  of 

```
{
	OSBuild              string     `json:"os_build"`
	SantaVersion         string     `json:"santa_version"`
	Hostname             string     `json:"hostname"`
	OSVersion            string     `json:"os_version"`
	CertificateRuleCount int        `json:"certificate_rule_count"`
	BinaryRuleCount      int        `json:"binary_rule_count"`
	ClientMode           ClientMode `json:"client_mode"`
	SerialNumber         string     `json:"serial_number"`
	PrimaryUser          string     `json:"primary_user"`
}
```

When a 200 is returned by the server it has a JSON object in the response.

This returns a JSON object of with the following keys:

| Key | Required | Type | Meaning |
|---|---|---|---|
| enable_bundles | NO | boolean | enabled bundle scanning  |
| bundles_enabled | NO | boolean |  deprecated key for enabling bundle scanning | enable_transitive_rules | NO | boolean | should we enable transitive whitelisting |
| enabled_transitive_whitelisting| NO | boolean | should we enable trasitive rules (deprecated) |
| transitive_whitelisting_enabled | NO | boolean | should we enable trasitive rules (deprecated) |
| batch_size | YES | integer | ??? |
| fcm_full_sync_interval | YES | integer | number of seconds between fcm |
| fcm_global_rule_sync_deadline | YES | integer | ??? |
| full_sync_interval | YES | integer | number of seconds between full syncs |
| client_mode | YES | string | either "MONITOR" or "LOCKDOWN" |
| allowed_path_regex | YES | list of strings | list of regular expressions to apply to paths |
| whitelist_regex | NO | list of strings | list of regular expressions for execution paths (deprecated) |
| blocked_path_regex | YES | list of strings | |
| clean_sync | YES | boolean | "true" or "false" |

### Example Payload

```
type Preflight struct {
	ClientMode                    ClientMode `json:"client_mode" toml:"client_mode"`
	BlacklistRegex                string     `json:"blacklist_regex" toml:"blacklist_regex"`
	WhitelistRegex                string     `json:"whitelist_regex" toml:"whitelist_regex"`
	BatchSize                     int        `json:"batch_size" toml:"batch_size"`
	EnableBundles                 bool       `json:"enable_bundles" toml:"enable_bundles"`
	EnabledTransitiveWhitelisting bool       `json:"enabled_transitive_whitelisting" toml:"enabled_transitive_whitelisting"`
}
```

```
{"enable_bundles": boolean,
 "bundles_enabled: boolean,
 "enable_transitive_rules":
}
```

# Events

<preamble>

### Example Payload

```json
type EventPayload struct {
	FileSHA  string          `json:"file_sha256"`
	UnixTime float64         `json:"execution_time"`
	Content  json.RawMessage `json:"-"`
}
```

# Rules 

## Rule Requests

Rules are retrieve from the sync server by having the client (Santa) issues an
HTTP POST request to the url `/ruledownload/<machine_id>`

| Key | Required | Type | Meaning |
|---|---|---|---|
| cursor | NO | string | the last known rule downloaded (comes from sync server) (CHECKME) |


### Example Payload 
Initially the payload is empty

```
{}

```

On subsequent requests to the server the cursor value is set.

```
{"cursor": "fosfs"} # FIXME
```

## Rule Responses

When a rule request is received the sync server responds with a JSON object
containing a list of rule objects and a cursor so the client can resume
downloading if the rules need to be downloaded in multiple batches. 

| Key | Required | Type | Meaning |
| cursor | NO | string | used to continue a rule download in a future request |
| rules | YES | a list of Rule objects | list of rule objects |


### Rules

| Key | Required | Type | Meaning |
|---|---|---|
| rule_type | YES | integer | identifies the type of rule (1= , 2=, 3=, 4=) |
| policy | YES | integer | identifies the type of policy (1= , 2=, 3=) |
| sha256 | YES | string | the sha256 of the binary or certificate |
| custom_msg | NO | string | a custom message to display when the rule fires |


### Example Payload

```
{"rules": [{"rule_type": 1, "policy": 1, "sha256": "", custom_msg: "message"}],
 "error": ""}
```


This is a high level overview of the syncing process. For a more a more detailed
account of each part, see the respective documentation. The santaclt binary can
be run in one of two modes, daemon and non-daemon. The non-daemon mode does one
full sync and exits. This is the typical way a user will interact with Santa,
mainly to force a full sync. The daemon mode is used by santad to schedule full
syncs, listen for push notifications and upload events.

1.  When the santad process starts up, it looks for a `SyncBaseURL` key/value in
    the config. If one exists it will `fork()` and `execve()` `santactl sync
    —-daemon`. Before the new process calls `execve()`, all privileges are
    dropped. All privileged actions are then restricted to the XPC interface
    made available to santactl by santad. Since this santactl process is running
    as a daemon it too exports an XPC interface so santad can interact with the
    process efficiently and securely. To ensure syncing reliability santad will
    restart the santactl daemon if it is killed or crashes.
2.  The santactl daemon process now schedules a full sync for 15 sec in the
    future. The 15 sec is used to let santad settle before santactl starts
    sending rules from the sync server to process.
3.  The full sync starts. There are a number of stages to a full sync:
    1.  preflight: The sync server can set various settings for Santa.
    2.  logupload (optional): The sync server can request that the Santa logs be
        uploaded to an endpoint.
    3.  eventupload (optional): If Santa has generated events, it will upload
        them to the sync-server.
    4.  ruledownload: Download rules from the sync server.
    5.  postflight: Updates timestamps for successful syncs.
4.  After the full sync completes a new full sync will be scheduled, by default
    this will be 10min. However there are a few ways to manipulate this:
    1.  The sync server can send down a configuration in the preflight to
        override the 10min interval. It can be anything greater than 10min.
    2.  Firebase Cloud Messaging (FCM) can be used. The sync server can send
        down a configuration in the preflight to have the santactl daemon to
        start listening for FCM messages. If a connection to FCM is made, the
        full sync interval drops to a default of 4 hours. This can be further
        configured by a preflight configuration. The FCM connection allows the
        sync-sever to talk directly with Santa. This way we can reduce polling
        the sync server dramatically.
5.  Full syncs will continue to take place at their configured interval. If
    configured FCM messages will continue to be digested and acted upon.

#### santactl XPC interface

When running as a daemon, the santactl process makes available an XPC interface
for use by santad. This allows santad to send blocked binary or bundle events
directly to santactl for immediate upload to the sync-server, enabling a
smoother user experience. The binary that was blocked on macOS is immediately
available for viewing or handling on the sync-server.
