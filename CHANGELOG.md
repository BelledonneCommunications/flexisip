# Change Log

All notable changes to this project will be documented in this file.

Group changes to describe their impact on the project, as follows:

| **Group name** | **Description**                                       |
| ----------     | ----------------------------------------------------- |
| Added          | New features                                          |
| Changed        | Changes in existing functionality                     |
| Deprecated     | Once-stable features removed in upcoming releases     |
| Removed        | Deprecated features removed in this release           |
| Fixed          | Any bug fixes                                         |
| Security       | To invite users to upgrade in case of vulnerabilities |


## [unreleased]

### [Fixed]
- Crash when trying to fetch domain records from registrar DB.

## [2.0.0] – 2020-07-31

### [Added]
**New settings**
 - `global/contextual-log-filter` ([Contextual log feature](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/C.%20Features/Contextual%20logs/))
 - `global/contextual-log-level` ([Contextual log feature](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/C.%20Features/Contextual%20logs/))
 - `global/log-filename`: allows to choose the name of the log file.
 - `module::Authentication/realm-regex`: allows to choose how the authentication module deduces the realm from the From header.
 - `module::PushNotification/retransmission-count` (PNR retransmission feature)
 - `module::PushNotification/retransmission-interval` (PNR retransmission feature)
 - `module::MediaRelay/force-public-ip-for-sdp-masquerading`: force the MediaRelay module to put the public IP address of the proxy while
   modifying the SDP body of INVITE requests. Only useful when the server is behind a NAT router.
 - `conference-server/check-capabalities` (see [Reference Documentation](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/A.%20Configuration%20Reference%20Guide/2.0.0/conference-server))

**Proxy**
 - [Contextual log feature](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/C.%20Features/Contextual%20logs/)
 - External authentication plugin.
 - Push Notification Request (PNR) retransmission feature. Allow to send PNR several time when no response for the first PNR has been received from the push server.
 - Add support for loc-key and loc-args to Firebase, in order to be compatible with apps implementing the same logic as for iOS when handling push notifications coming from Flexisip.
 - EventLog: log the value of 'Priority' header for each request event.
 - Support of [RFC 8599](https://tools.ietf.org/html/rfc8599) for the transmission of the PushNotification information through REGISTER requests.

**Presence**
 - Support of [“Server known resource lists” feature](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/C.%20Features/Presence%20server/#HServerknownresourcelists).

**Miscellaneous**
 - Add an option (`--rewrite-config`) to Flexisip command-line interface to dump a new configuration file with up-to-date doc strings but keeping the setting that
   have been set explicitly by the user.
 
### [Changed]
**Settings**
 - Default value changes:
   - `global/enable-snmp`: `true` -> `false`
   - `gloabl/dump-cores`: `true` -> `false`
   - `module::Router/message-delivery-timeout`: 1w
   - `module::Router/message-accept-timeout`: 5s
   - `module::Forward/params-to-remove`: adding `pn-provider`, `pn-prid`, `pn-param`
   - `presence-server/max-thread`: `200` -> `50`
   - `presence-server/max-thread-queue-size`: `200` -> `50`

 - Parameter renaming:
   - `event-logs/dir` -> `event-logs/filesystem-directory`
   - `module::Registrar/datasource` -> `module::Registrar/file-path`
   - `module::Registrar/name-message-expires` -> `module::Registrar/message-expires-param-name`
   - `presence-server/soci-connection-string` -> `presence-server/rls-database-connection`
   - `presence-server/external-list-subscription-request` -> `presence-server/rls-database-request`
   - `presence-server/max-thread` -> `presence-server/rls-database-max-thread`
   - `presence-server/max-thread-queue-size` -> `presence-server/rls-database-max-thread-queue-size`

 - `[monitor]` section marked as experimental.
 - `[module::Presence]` section is no more marked as experimental.

**Proxy**
 - `REGISTRAR_CLEAR` sub-command of `flexisip_cli` can now clear registration of a given SIP identity.
 - Improvement of the performance of the boolean expression engine used by module filters.
 - Breaking of the event log database schema.

**Miscellaneous**
 - Log files are now named flexisip-proxy.log, flexisip-conference.log flexisip-presence.log by default.
 - Log rotation is fully handled by Logrotate script (see [“Logging” documentation page](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Logs/#HLogrotation)).
 - `--dump-all-default` option dumps a configuration file with all the parameters commented out.
 - `--dump-default` allow to dump default settings for non-module sections.
 - Generation of plugins default settings and documentation by '--dump-all-default' option when they have been loaded using
   `--set global/plugins=<plugin-list>`.

### [Deprecated]
**New deprecated settings**
 - `global/use-maddr`
 - `global/max-log-size`
 - `module::Registrar/redis-record-serializer`
 - `module::Router/fork`
 - `module::Router/stateful`
 

### [Removed]
**Removed settings**
 - `global/debug`
 - `module::Authentication/enable-test-accounts-creation`
 - `module::Authentication/hashed-password`
 - `module::Router/generated-contact-route`
 - `module::Router/generated-contact-expected-realm`
 - `module::Router/generate-contact-even-on-filled-aor`
 - `module::Router/preroute`
 - `module::PushNotification/google`
 - `module::PushNotification/google-*`
   

### [Fixed]
**Proxy**
 - Aborted calls not logged in the event log.
 - Missing line-feed in filesystem event logs.
 - Prevent loops due to fallback routes, when two Flexisip servers have a fallback route to each other.
 - Abort server start if `module::Presence/presence-server` setting has an invalid SIP URI.
 - Don't set tag in “110 Push sent” responses. It makes no sense as a proxy doesn't have to create dialogs.
 - Prevent “110 Push sent” response from being sent after “180 Ringing”.
 - Prevent sending of multiple “110 Push sent” responses when a call is forked into several legs.
 - Prevent server abort on registration with an invalid Address-of-Record.
 - Crash when processing a REGISTER with an invalid Contact URI.
 - Bad behaviour when receiving a REGISTER request which contains a '@' in its CallID.
 - Failing authentication when the user part of the From URI has escaped sequences.
 - Improve Firebase's push notification resilience against broken sockets.
 - Remove empty 'pub-gruu' params from contact headers of OK response when `module::Registrar/reg-on-response` is on.
 - SystemD service not restarted on package update.
 - Fix MediaRelay ICE processing when the server has both IPv6 and IPv6 addresses.
   Previously, only ICE relay candidates with the "prefered" connectivity was offered. However the way the "prefered" connectivity is guessed is not reliable,
   especially when sending the INVITE to the callee, and it can change during a call, for example when one of the parties moves from an IPv6-only LTE network to an IPv4-only network.
   For these reasons, it is preferable that ICE relay candidates are added for both IPv4 and IPv6.

**Conference**
 - Fix becoming admin again after leaving and reentering a chat room.


