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



## [2.1.6] - 2023-09-22
### [Fixed]
- Backport of several fixes concerning our HTTP/2 client code.

## [2.1.5] - 2022-06-09
### [Fixed]

- 'reg-on-response' parameter no longer worked since Flexisip 2.1.0

## [2.1.4] - 2022-05-19
### [Fixed]

- Fix warning about failing SQL request on conference server starting.
- Make Flexisip to require Hiredis >= 0.14.
- Remove Sofia-SIP implementation of some functions that must be found on system.


## [2.1.3] - 2022-03-18
### [Fixed]

- ExternalPusher: the response to each HTTP request systematically has a delay of
  a few seconds when using a TCP connection instead of TLS.
- Race condition around Redis SUBSCRIBEs/UNSUBSCRIBEs that causes Flexisip to
  wrongly thinks that it is subscribed to some fork contexts. Finally, that
  causes to have end-users' device receiving push notifications for a message
  but no message is delivered by Flexisip once the application registers again.
- Weakness in the module replacement algorithm that causes some modules coming
  from plugins to be inserted in bad position in the modules list.


## [2.1.2] - 2021-12-22
### [Added]
- `rtp_bind_address` configuration parameter, which allow to choose the listening
  address of the media relay.
- Allow boolean expression filter to access the Contact header of the request.

### [Fixed]
- Have the CMake script to install flexisip-version.h header and embed it
  in the RPM/DEB package.
- Crash of the proxy when using `REGISTERAR_DELETE` command in flexisip_cli.
- Fix problems in migration of old protobuf-encoded Registrar entries.

## [2.1.1] - 2021-10-25
### [Fixed]
- Fix an issue in the CPack script that caused the name of CentOS packages to not conform
  with CentOS format, because the distribution tag (el7, el8, etc.) was missing.


## [2.1.0] - 2021-10-20
### [Added]
- New Flexisip service, 'RegEvent server', available through flexisip-regevent SystemD service.
  The RegEvent server is in charge of responding to SIP SUBSCRIBEs for the 'reg' event as defined by
  [RFC3680 - A Session Initiation Protocol (SIP) Event Package for Registrations](https://tools.ietf.org/html/rfc3680).
  To generate the outgoing NOTIFY, it relies upon the registrar database, as setup in module::Registrar section.
- **Proxy** New transport URI parameter: `tls-allow-missing-client-certificate=<true/false>`.
  This allows to accept TLS connections from clients which haven't any X.509 certificate
  even if `tls-verify-incoming` has been enabled. Valid for SIPS transport only.
- **Proxy** Add `module::DoSProtection/white-list` parameter in flexisip.conf to allow packets from
  given IP addresses to bypass the DoS protection system.
- **Proxy** Add `module::Authentication/realm` parameter that allows to force the realm
  offered by the proxy to user agents during authentication (401/407 responses).
- **Conference server** Several factory URIs can be handled by the server.
- **Push notifications** New option `--custom-payload` for flexisip_pusher utility that allows to
  manually set the payload sent to push notificaiton server (Apple push only).
- **Flexisip CLI** Add `REGISTRAR_DUMP` CLI command to dump all addresses of record registered locally.
- **Packaging** Support of CentOS 8 and Debian 10 GNU/Linux distributions.

### [Changed]
- **Proxy** `regex` operator of filter expressions in flexisip.conf now
  uses [ECMAScript grammar](https://en.cppreference.com/w/cpp/regex/ecmascript) from C++ specification.
- **Proxy** Firebase push notifications are now sent by using HTTP/2 protocol.
- **Presence server** Moving `soci-user-with-phone-request` and `soci-users-with-phones-request` parameters
  from _[module::Authenticaiton]_ section to _[presence-server]_.
- **Conference server** Conformance to 1.1 specification.
- **Packaging** Packaging process has entirely been reworked in order to embed Flexisip and Linphone SDK
  inside a single package. Thus, a given version of Flexisip is strongly bound to a specific version
  of Linphone SDK.

### [Deprecated]
- **Presence server** Setting `module::Authentication/soci-user-with-phone-request` and
  `module::Authentication/soci-users-with-phones-request` parameters still works but will raise a warning.

### [Removed]
- **Proxy/Push notifications** `pn-silent` push parameter has no more effect.
- **Proxy/Push notifications** Remove legacy `form-uri` key-value from Firebase push notification body.


## [2.0.9] - 2021-08-10
### [Fixed]
- **Proxy** Reverts the previous fix which prevents that two contacts with the same push parameters
  be registered for the same user. Side effects which caused some users to not receive
  messages or calls have been observed in production.


## [2.0.8] - 2021-08-09
### [Added]
- **Proxy** Adding 'fallback-route-filter' parameter in 'module::Router' section.
  This parameter allows to prevent some SIP requests to be forwarded to the
  fallback route when all the forked transactions have failed. The parameter expects
  a boolean expression as the filter parameter at the beggining of each module::\*
  sections. The fallback route is used when the boolean expression is evaluated to _true_.

### [Fixed]
- **Proxy** Prevent SIP client to registers two distinct contacts (distinct UID) which would have
  the same push notification parameters. That often happens when Linphone is uninstalled and
  installed again on an iOS device, causing the instance UID to be generated again but keeping
  the same push notification tokens. That causes the device to receives several push notifications
  for each SIP request because Flexisip assumes that each contact URI matches a distinct device.
  To avoid this scenario, Flexisip automatically removes the old contact URI to ensure the unicity
  of the push notification parameters.


## [2.0.7] - 2021-07-09
### [Fixed]
- **Proxy** Fix a bug that caused the fallback route to be used even if the forked request
  had succeeded.


## [2.0.6] - 2021-07-07
### [Fixed]
- **Proxy** INIVITE requests was systematically forked to the fallback route (if set)
  independently of the status of each received response. Furthermore, the fallback
  destination was called alongside the real contact addresses of the called identity.


## [2.0.5] - 2021-06-09
### [Added]
- **Flexisip CLI** Add three new counters: count-basic-forks, count-call-forks and count-message-forks.

### [Fixed]
- **Apple push notifications** Set the 'apns-push-type' header.
- **Apple push notifications** Correctly set the 'apns-expiration' header, basing on some parameters of module::Router (call-fork-timeout and message-delivery-timeout).
- **Apple push notifications** Prevent the TLS connection from blocking the main thread for more than one second while connecting.
- **Android push notifications** Fix typo in the name of one key in the PNR payload. ('form-uri' -> 'from-uri'). The old key will be
  supported until Flexisip 2.1.
- **External Authentication plugin** Correctly print the HTTP response from the authentication server in the log.
- **External Authentication plugin** Fix bug that caused the HTTP response to be matched with the bad request when
  several request was sent simultaneously.
- **Filter parameter** Fix crash on evaluation when 'contains' operator has no left-hand operand.
  Makes Flexisip to abort on starting otherwise.
- **Flexisip CLI** Fix crash with Python3 < 3.7
- **Memory usage** Fix several memory leaks.
- **XWiki doc generator** Fix bad output syntax when bullet points are used in parameter descriptions.
- **XWiki doc generator** Generate documentation for the experimental modules.


## [2.0.4] - 2021-03-01
### [Fixed]
- **Authentication** Prevent password mismatch error when hashed passwords are in upper case
  in the user database.
- **Push Notifications** Prevent the PushNotification module from sending an out-of-dialog
  "180 Ringing" reply when an in-dialog 180 reply has already
  been forwarded back by the Router module.
- **Apple push notifications** The new HTTP/2 client now automatically close the connection
  with the APNS after one minute of inactivity to prevent the connection to be silently
  destroyed by aggressive routers. That improve PNR sending reliability.
- **Android push notifications** Use timeouts that has been set in the Router module settings to fill the TTL
  of the push notification request. See
  [Flexisip's specification around push notifications](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/D.%20Specifications/Push%20notifications/#HContentofthepushnotificationssentbyFlexisip)
  for more information about the involved parameters.
- **Media relay** Fix an issue while processing a SDP without ICE containing an IPv6 connection address, and Flexisip has no IPv6 address available.
  Previously, an empty connection address was set by the MediaRelay module, causing a blank call. Now, the IPv4 address will be used as fallback, which will work if the network provides NAT64 service.
- **Proxy server** Fix several huge memory leaks. No more memory leaks issues are known on the proxy component today.
- **Conference server** The transport address now allows to restrict the listening interface.
  Before, the conference was listening on all interfaces independently of the transport host.

### [Removed]
- 'pn-silent' custom Contact parameter for push notifications.


## [2.0.3] - 2020-11-13
### [Fixed]
- Apple push notification client: the body of HTTP/2 GOAWAY frames wasn't printed in log, which
  doesn't allow to know the disconnection reason.
- Fix a regression that causes to have an empty pub-gruu parameter in the Contact header of
  forwarded REGISTERs.
- Fix potential crash or at least memory corruption when both "route" and "default-transport" are set in the ForwardModule.
  The default-transport will not be applied when route is used.
- MediaRelay: fix ICE restart not being detected or notified on the offered side. This causes relay candidates to be not added
  in the 200 Ok, which can break RTP communication.


## [2.0.2] - 2020-10-14
### [Fixed]
- Fix a crash that occures when module::Registrar/reg-on-response feature is enabled. It happens
  when the “200 Registration successful” response is received from the backend server.


## [2.0.1] - 2020-10-13
### [Changed]
- Usage of HTTP2 protocol to send Apple push notification requests. No
  change in PushNotification module configuration required.

### [Fixed]
- Crash when trying to fetch domain records from registrar DB.
- Avoid MediaRelay's channel to continously swap between IPv6 and IPv4 during ICE connectivity checks. Indeed, this causes some connectivity
  checks to fail because some stun requests sent over IPv6 are answered over IPv4 and vice versa. The workaround implemented consists in locking
  the destination choosen by the MediaRelay's channels (when receiving a packet) for a minimum of 5 seconds. The switch to a new destination
  is allowed only if the previous destination has been unused over the last 5 seconds.


## [2.0.0] – 2020-07-31
### [Added]
**New settings**
 - `global/contextual-log-filter` ([Contextual log feature](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/C.%20Features/Contextual%20logs/))
 - `global/contextual-log-level` ([Contextual log feature](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/C.%20Features/Contextual%20logs/))
 - `global/log-filename`: allows to choose the name of the log file.
 - `module::Authentication/realm-regex`: allows to choose how the authentication module deduces the realm from the From header.
 - `module::PushNotification/retransmission-count` (PNR retransmission feature)
 - `module::PushNotification/retransmission-interval` (PNR retransmission feature)
 - `module::PushNotification/display-from-uri`: controls whether the From URI is print in PN payloads.
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
 - [Push Notfifications] The From URI is no more printed in the PN payload as first element of loc-args list.
   Use `module::PushNotification/display-from-uri` setting to retore this behaviour.

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

