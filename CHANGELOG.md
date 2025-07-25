# Change Log

All notable changes to this project will be documented in this file.

Group changes to describe their impact on the project, as follows:

| **Group name** | **Description**                                                             |
|----------------|-----------------------------------------------------------------------------|
| Added          | New features                                                                |
| Changed        | Changes in existing functionality                                           |
| Deprecated     | Once-stable features removed in upcoming releases                           |
| Removed        | Deprecated features removed in this release                                 |
| Fixed          | Any bug fixes                                                               |
| Security       | To invite users to upgrade in case of vulnerabilities                       |
| Known Issues   | Issues whose fix has not been tested and cannot be included in this release |

## [2.6.0]
### [Added]
- **Proxy:**
    - Push notification delivery can now be delegated to a FlexiAPI server instance.
- **Conference server:**
    - Add the 'no-rtp-timeout' parameter that allows to set the delay before the call is automatically hung up because no RTP data is received.
    - Add support for end-to-end conference encryption by installing the EKT server plugin. For customers under a proprietary license, this functionality is under a specific license.

### [Changed]
- **Pusher:**
    - Default values of the push body are now empty instead of containing placeholders.
- **EventLogs (`flexistats` backend):** Call event data sent to [`/statistics/calls`](https://subscribe.linphone.org/api#post-statisticscalls)
      now also include a `sip_call_id` field with the value of the Call-ID header.

### [Removed]
- **Proxy:**
    - Old Firebase API as it is not supported anymore to send push notifications.
    - `$api-key` is not supported anymore in `module::PushNotification/external-push-uri`. Old Firebase is thus not 
      supported anymore in the external pusher. 
    - Parameter `module::PushNotification/google` (deprecated in 2.0.0)
    - Parameter `module::PushNotification/google-project-api-keys` (deprecated in 2.0.0)
    - Parameter `module::PushNotification/time-to-live` (deprecated in 2.0.0)
    - Parameter `module::PushNotification/add-to-tag-filter` (deprecated in 2.2.0)
    - Parameter `module::PushNotification/windowsphone` (deprecated in 2.3.0)
    - Parameter `module::PushNotification/windowsphone-package-sid` (deprecated in 2.3.0)
    - Parameter `module::PushNotification/windowsphone-application-secret` (deprecated in 2.3.0)
    - Silk audio encoder/decoder is not supported anymore.
- **EventLogs:**
    - Parameter `event-logs/dir` (deprecated in 2.0.0)
    - Parameter `event-logs/flexiapi-token` (deprecated in 2.3.3)

## [2.5.0]
### [Added]
- **Proxy:**
    - Apple push notification certificates can now be updated without restarting the server.
    - TLS/SSL certificates can now be updated without restarting the server.
    - **Authorization and authentication:** New path for all authorization and authentication steps:
        - New module called `AuthTrustedHosts` that identifies SIP requests from trusted hosts.
          For more information, see the [configuration reference guide].
        - New module called `AuthOpenIDConnect` that enables authentication using OpenID Connect method.
          For more information, see the [module::AuthOpenIDConnect documentation].
    - **PushNotification:**
        - Send push notifications on NOTIFY requests receipt if the event type is 'message-summary'
          ([RFC3842](https://datatracker.ietf.org/doc/html/rfc3842)).
          It is managed by the new parameter `enable-message-summaries-pn`.
    - **Registrar:**
        - New parameter `redis-subscription-keep-alive-check-period` to periodically ping active Redis subscription
          sessions in order to detect and mitigate connection issues (tries to reconnect if connection is closed).
- **B2BUA server:**
    - Support for early media.
    - Support for blind and attended call transfers ([RFC5589](https://datatracker.ietf.org/doc/html/rfc5589)).
      Limitations: not supported in SIP-bridge mode with the 'Random' strategy.
    - New parameters `audio-codec` and `video-codec` to force the usage of a specific audio or video codec
      (disables all other codecs). Using these parameters significantly improve performances of the server (number
      of concurrent calls). Documentation is available in the [configuration reference guide].
    - New parameter `enable-ice` to enable ICE negotiation for RTP streams (enabled by default).
    - New parameter `nat-addresses` to specify public host name or IP addresses of the server. For more information, see
      the [configuration reference guide].
    - New parameter `max-calls` to specify the maximum number of concurrent calls an instance of the server can handle.
    - New parameter `enable-keepalive` (sends 'keepalive' packets to keep udp NAT association).
    - **SIP-Bridge:**:
        - Forwarding of SUBSCRIBE and NOTIFY requests.
        - **AccountPool:**
            - New parameter `mwiServerUri` to specify the URI of the MWI server.
            - Parameter `registrar` to indicate the SIP URI of the registrar to which all users should register by
              default (optional).
        - **Account:**
            - Parameter `registrar` to indicate the hostname or full SIP URI of the registrar to which the
              user should register (optional).
            - Parameter `protocol` (which is used with `outbound_proxy` and `registrar`) to indicate which transport
              protocol to use (optional, default: udp).
- **Conference:**
    - New parameters `audio-engine-mode` and `video-engine-mode` to specify the media engine to use (`mixer`, `semi-sfu`
      and `sfu`). Documentation is available in the [configuration reference guide].
    - New parameter `subscription-refresh-delay` to change the delay before refreshing external subscriptions.

### [Changed]
- **Conference:** Parameter `conference-focus-uris` is now mandatory.
- **Proxy:**
    - TLS/SSL certificates MUST not be expired (or Flexisip will not start).
    - **Authorization:** New behavior (check if the SIP domain is authorized and reject inter domain requests),
      available in two modes (more information in the [configuration reference guide]):
        - `static`: Specify a list of authorized SIP domains in the configuration file (default behavior).
        - `dynamic`: Set up a connection to the [FlexisipAccountManager] server to dynamically get the list of
          authorized SIP domains.
- **B2BUA server:**
    - **Trenscrypter:** Invalid values in `outgoing-enc-regex` and `outgoing-srtp-regex` parameters are now
      considered as errors and prevent the server from starting.
    - **SIP-Bridge:**: For detailed information, see the [SIP-Bridge documentation].
        - **AccountPool:**
            - Parameter `outbound_proxy` is now optional.
        - **Account:**
            - Parameter `outbound_proxy` can now contain a hostname or a full SIP URI.

### [Fixed]
- **Proxy:**
    - **Forward:**
      - Contact paths were not properly processed for mid-dialog requests intended to GRUU addresses. Fetched
        paths from database were not translated into 'Route' headers before forwarding the request.
      - P-Preferred-Identity header is removed if present before forwarding the request.
      - When using `routes-config-path`, a 'Route' header is now added only to out-of-dialog requests.
    - **Router:** 
      - Performance issues for MESSAGE requests intended for the conference server (linphone-sdk >= 5.4).
        Avoid creating MESSAGE requests that could be saved in memory or database in case the conference server
        is not available. Moreover, in such cases this fix allows the UAC to know that the chat message was not delivered
        properly to the server ('202 Accepted' was previously immediately answered to the UAC).
      - Invite/Cancel (iOS devices) feature was not working properly when no response (503 or 408 to INVITE request) was
        received before CANCEL request receipt.
- **Conference server:**
    - Set the default contact address (with identity address of the conference server) to fix issues when connection
      to the Redis database is slow or broken.
- **B2BUA server:**
    - Now properly resumes calls that were paused on both sides.
    - Performance issues (memory leaks due to linphone::Account accumulations).
    - The server now checks audio and video media directions to manage call states (video calls were not handled
      properly).
    - **SIP Bridge:**
        - With `one-connection-per-account` enabled, the server now uses the correct port to answer to OPTION requests.
        - Update accounts smoothly on full (re)load.
          If the Redis connection was lost, we might have missed a notification of an account being
          created/updated/deleted. So we fetch all accounts from DB again, then run a diff to intelligently update what
          we already have (That update process is rate-limited in the same manner as that of loading all accounts on
          first boot).
        - Changes made to authentication information where not taken into account when the server was running. Now
          ensures that a new REGISTER for the involved account is sent.
- **Build:** Compilation on macOS.
- **HTTPS (External authentication plugin, Flexistats, Push Notifications):** The SNI no longer contains the port and is now only added if the target is a domain name (and not an IPv4 or IPv6 address).
This is more compliant with RFC 6066, and therefore more compatible with stricter HTTPS implementations.

### [Removed]
- **Proxy:**
  - Monitor (never released, it was in experimental state). All configuration files MUST not contain any reference to
    the Monitor module, otherwise Flexisip will not start.
  - **Registrar:** Parameter `name-message-expires` (deprecated in 2.0.0).
- **Plugin:** JweAuth.


## [2.4.3]
### [Fixed]
- **Proxy:**
  - **MediaRelay:** The server was not updating the IP address inserted in the SDP response when a client's network
    changed (e.g., if a client now proposes an IPv4 address instead of an IPv6 address on an existing channel).
  - **PushNotifications:** Apple push certificates could not contain '.dev' in their filename and be used in production 
    environment.


## [2.4.2] - 2025-07-21
### [Added]
- **Proxy/Registrar:** New parameter `default-expires` to set a default expiry value to contacts when no expiry value 
  was found in the 'REGISTER' request.

### [Fixed]
- **Proxy:**
    - Now replies 481 to CANCEL requests that are not related to any transaction (stateless CANCEL requests).
      This may occur when the caller sends it after the callee has already sent 200 and the proxy has destroyed the
      ForkCtx.
    - **PushNotifications:** Now continues to send push notifications of type `message` after 45s for calls (only for
      iOS devices when `voip` push types are not allowed).
    - **Forward:**
      - The 'Contact' header is now cleaned properly in the REGISTER request transferred to another server (with
        `reg-on-response` enabled).
      - Some incoming transactions were not answered, causing a memory leak.
    - **SanityChecker:** Server was not resilient to invalid subscriptions (no Event header).
    - **Statistics**: Counters in `module::Authentication` called `count-password-found` and `count-password-not-found`
      were not correctly incremented.
    - **Sofia-SIP:**
      - Rare race condition when resolving a domain name (leading to a crash of the server).
      - A crash of the server could happen in the outgoing transport selection algorithm when sending a SIP message.
    - **Router**: Missing userinfo in 'From' or 'To' header was leading to a crash for MESSAGE requests.
    - **Registrar:**
      - Usage of the wildcard '*' 'Contact' header field was not correctly handled (considered as a bad request).
      - Requests of type 'REGISTER' were rejected if they did not contain an expiry value (it is now compliant with
        RFC3261).
    - **NatHelper:**
      - The `contact-verified-param` parameter has been renamed but not deprecated, causing problems at startup if the
        parameter was defined in the configuration file.
      - The function that determines whether an IP address is private now complies with RFC1918.
- **B2bua/SIP Bridge**: authentication information for deleted accounts was removed too early, preventing accounts from
  properly unregistering to the registrar.
- **EventLogs (`flexiapi` logger only):** Two events (INVITE, MESSAGE, etc.) sharing the same Call-ID, the same user
  names (From & To), but different domain names, no longer have the same event id.
  (E.g. eventIdOf("user-A@domain-B", "user-C@domain-D", "call-id-E") ≠ eventIdOf("user-A@domain-F", "user-C@domain-G", "call-id-E"))
- **Conference:** compatibility issue with clients using linphone-sdk 5.4+.

### [Removed]
- **Proxy:**
  - **Statistics:** Counters in `module::Authentication` called `count-async-retrieve` and `count-sync-retrieve` were
    not implemented (always returned '0').

## [2.4.1] - 2025-03-31
### [Added]
- **B2BUA, Conference, Presence, Proxy, RegEvent:** periodically log the server memory usage (on Linux and with debug
  log level).

### [Fixed]
- All known issues from 2.4.0 have been fixed.
- **B2BUA, Conference, Presence, Proxy, RegEvent:**
    - Error in Flexisip startup phase (daemon mode) caused the watchdog process to freeze.
    - Watchdog logs could not be printed into journald.
- **RegEvent server:**
    - The server did not support several subscriptions to the same record key.
    - Not disabling call-logs and zrtp-secrets DBs caused crash at init.
- **Proxy:**
    - Invalid P-Preferred-Identity could lead to crash.
    - Drastically improved performances when retrieving undelivered chat messages from the database at startup.
    - **Sofia-SIP:** Parameter `idle-timeout` was not set in TLS connections if no message was received.
- **Conference server:** Compatibility issue between conference server using linphone-SDK 5.3 and clients using
  linphone-SDK 5.4.

## [2.4.0] - 2025-01-30
### [Added]
- **B2BUA server/SIP Bridge:**
    - Now supports bridging **incoming** (external) calls.
      I.e. calls from clients registered on third-party domains/proxies to clients registered on the local
      domain/proxies.
      This requires a corresponding external account for each user.
      Please refer to [the SIP Bridge documentation] for details.
    - [`one-connection-per-account`](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/A.%20Configuration%20Reference%20Guide/2.4.0/b2bua-server#HB2buaserver):
      Let the B2BUA use a separate connection (port) for each (external) account it manages. This can be used to work
      around DoS protection and rate-limiting systems on external proxies.
- **Proxy/Router:** New parameter `module::Router/static-targets` that lists sip addresses which will always be added to
  the list of contacts fetched from the registrar database when routing INVITE and MESSAGE requests.
- **Proxy/NatHelper:** New strategy to route requests through NATs called
  "flow-token" ([RFC5626](https://datatracker.ietf.org/doc/html/rfc5626))
    - new parameter `module::NatHelper/nat-traversal-strategy` to indicate the strategy to use for routing requests
      through NATs (`contact-correction` or `flow-token`).
    - new parameter `module::NatHelper/force-flow-token` to force the use of flow-token under specific conditions (
      boolean expression).
- **Configuration:** You can now indicate a unit (ms, s, min, h, d, m, y) along with the value for a duration
  parameter in the configuration file.
  See [File Syntax](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/#HFilesyntax) for more
  information.
- **Registrar:** Keep-alive Redis requests for subscription connections.
  Flexisip can now be more robust to middle-ware aggressively dropping idle connections.
- **Conference and B2BUA servers:** New
  parameters `b2bua-server/audio-port`, `b2bua-server/video-port`, `conference-server/audio-port`
  and `conference-server/video-port` to specify which port (or range of ports) to use for RTP and RTCP traffic.
- **Conference server:**
    - New parameter `conference-server/call-timeout` to kill all incoming calls that last longer than
      the defined value.
    - Compatibility with clients using Linphone SDK 5.4.
- **Build:**
    - Support for Ubuntu 24.04.
    - Support for Clang 18.
    - Support for GCC 14.
- **Pusher:**
    - Clearer message when Apple Push Notification Service (APNS) certificates are not read accessible.
    - `--call-id` option to customise the content of the push notification payload.

### [Fixed]
- **B2BUA, Conference, Linphone Daemon, Presence, Proxy, RegEvent:** All associated SystemD services now properly wait
  for the network to be online before starting. (Fixes interface binding issues on boot.)
- **Proxy:**
    - **NatHelper:** Parameter `module::NatHelper/contact-correction-param` is now properly removed from the `Contact`
       URI by the last hop in the proxy chain.
    - **RegistrarDb:** Failing to subscribe to a Redis Pub/Sub channel is now properly handled and logged, to help
      troubleshoot ACL issues in Redis' config. (Pub/Sub channels are used internally to trigger push notifications when
      devices register.)
    - **ForkCallContext:** Ringing devices now receive the appropriate "Accepted Elsewhere" status via push
      notifications when another device accepts the call in a multi-proxy configuration.
- **Conference server:** Group chats no longer see their title overwritten to "ICE processing concluded" when the
  conference server's connection to Redis is slow or non-existent.
- **RPM:** No longer breaks the Flexisip Account Manager (FAM) if it had been installed first. The SELinux `var_log_t`
  label is now properly applied to Flexisip's log files only.
- **B2BUA server:** Bridged calls put on hold (paused) using `a=inactive` can now be properly resumed.
- **Sofia SIP:** Incoming messages exceeding the maximum acceptable size are now answered with a 400, and can no longer
  cause a congestion blocking a socket.
- **CLI:** `REGISTRAR_DELETE` now properly deletes contacts identified by a `+sip.instance=` URI parameter.

### [Changed]
- **B2BUA:**
    - The schema of the `b2bua-server::sip-bridge/providers` JSON configuration file has been overhauled to accommodate
      for the new incoming call bridging feature, and now offers many more configuration options.
      Please refer to [the SIP Bridge documentation] for details.
    - Custom header `flexisip-b2bua` is renamed to `X-Flexisip-B2BUA`.
      (This header is no longer used by the proxy which instead relies on the `User-Agent` header. However, the B2BUA
      server still adds it to its messages for backwards compatibility.)
    - Parameter `b2bua-server/user-agent` can now include an optional `{version}` placeholder that will be replaced with
      the currently running Flexisip version.
- **Build:** Refactor of the build system to meet new CMake standards.
- **Configuration:**
    - Flexisip will now refuse to launch if duplicated keys are found in the configuration file.
      (An explanatory message will be logged.)
    - Configuration values (anything to the right of an `=` sign in the config file) can now be 10x larger (up to
      20KiB = 20480 ASCII characters), allowing for e.g. long and complex filter expressions.
- **Proxy/PushNotification:** Invite/Cancel feature is now only used for Apple voip push notifications.
- **Proxy/NatHelper:** Parameter `module::NatHelper/contact-verified-param` is
  renamed `module::NatHelper/contact-correction-param`.
- **Proxy/MediaRelay:** In early media mode, the ringing device that answered last is now the one sending audio/video.
  (Each new early media response takes over send capability.)
- **Internal:**
    - Refactored software architecture (removed singletons) so you can now run several flexisip instances on
      the same machine.
    - Flexisip tester can now be used without the need for installation.
- **EventLogs:** Event IDs are now generated with the SHA 256 algorithm to ensure reproducibility. (In lieu of C++'s
  `std::hash<string>`.)
- **Logs:** Log messages from the Sofia SIP library are now only displayed if Flexisip is configured in `debug` logging
  level. A new config option `global/sofia-level`, has been added to tweak which messages are shown in that case.
  (This new option can be adjusted on a running instance via [the
  `CONFIG_SET` CLI command](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/3.%20Operate/Examining%20run-time%20statistics/#HAccessstatisticsandconfiguration))
- **RPM:** The package now depends on `policycoreutils`, `policycoreutils-python-utils`, and `selinux-policy-targeted`
  to ensure its ability to set SELinux labels.
- **CLI:** Improved messages around `REGISTRAR_*` commands.
- **Pusher:** Added "Flexisip" to default push notification infos to make the origin of the PN clearer.

### [Deprecated]
- **Windows push notifications:** These push notifications are not handled anymore.
    - parameter `module::PushNotification/windowsphone` no longer has any effect.
    - parameter `module::PushNotification/windowsphone-package-sid` no longer has any effect.
    - parameter `module::PushNotification/windowsphone-application-secret` no longer has any effect.
- **Proxy/registrar:** Parameter `module::Registrar/redis-server-timeout` no longer has any effect. This parameter is
  not really deprecated. It is not used for the moment but may be used in the future.
- **Plugin:** The JweAuth plugin will be removed in Flexisip 2.5.

### [Removed]
- **Ubuntu 18.04:** Support discontinued as distribution has reached end-of-life (2023-05-31).
- **CentOS 7:** Support discontinued as distribution has reached end-of-life (2024-06-30).
- **Debian 10:** Support discontinued as distribution has reached end-of-life (2024-06-30).
- **Proxy/Registrar:** `module::Registrar/redis-record-serializer` (deprecated in 2.0.0)
- **Build:** `ENABLE_PROTOBUF` CMake option.
  This option only enabled a Protobuf backend for the serialization of records in Redis. It could no longer be used
  since the deprecation of the `redis-record-serializer` config option (see above).

### [Known Issues]
- **Presence server:** Intermittent crash when updating the list of subscribers
- **Sofia-SIP:**
    - Exponential memory usage when parsing data from a TCP socket.
      (A 5MB socket buffer can lead to 26GB of parsing buffers.)
    - Memory usage spike when the system clock jumps forward in time.
      (As can happen when NTP connection is (re-)established, leading to OOM in the worst case where e.g. the system
      clock inits at epoch (1970-01-01) because of a dead battery.)
- **RPM:** Rocky 8 may refuse to install the package because it detects a conflict with the SystemD package.
- **Proxy:** No "Missing call" notification will be sent if a call is cancelled after being unanswered for more than 30
  seconds.

## [2.3.5] - 2025-04-18
### [Fixed]
- **Proxy:** fix a vulnerability in authentification using P-Preferred-Identity header.

## [2.3.4] - 2024-07-24
### [Added]
- **Proxy/Registrar:** add 'max-contacts-per-registration' to reject REGISTER requests containing more Contact headers
  than the specified limit.
- **Dependencies:** added `python3-google-auth` and `python3-requests` to package dependencies.
- **Build:** added CMake variable `FLEXISIP_VERSION` to enable build without GIT repository.

### [Changed]
- **Build:** disabled default configuration file generation when crosscompiling.
- **flexisip_cli.py:** API change, REGISTRAR_DELETE now returns an empty record instead of "Error 404" when deleting
  the last contact of a Record, OR when attempting to delete a contact from a non-existent Record.

### [Fixed]
- **Proxy:** fix a crash when parsing an invalid "Contact" header value.
- **Proxy/NatHelper:** fix wrong "Contact" header correction in response when the proxy is first and last hop.
- **Configuration:** fix a crash when configuring an invalid boolean expression.
- **Proxy/PushNotification:** fix missing "to-tag" parameter on "110 Push Sent" when `module::PushNotification` is
  enabled and filter parameter `module::PushNotification/add-to-tag-filter` evaluates to true.
- **Proxy/Router:** fix no call is routed to callee when `module::Router/fork-late`
  and `module::Router/message-fork-late` are enabled.
- **Proxy/PushNotification:** fix several issues on the new Firebase V1 push notifications client.
- **Proxy/EventLogs:** fix wrong computation of event id. Previous method was sensitive to an inversion of "From"
  and "To" header values.
- **B2BUA server:** fix behavior of the B2BUA. It was erroneously trying to resume a call that was paused with
  a=inactive in SDP.
- **Proxy/Forward:** fix missing contact paths processing for mid-dialog requests intended to GRUU addresses. Fetched
  paths from database were not translated into Route headers before forwarding the request.
- **Proxy/Router:** fix Proxy does not send terminal response in case of an early cancelled call
  when `module::Router/fork-late` is on. This case could happen when a client had an offline device and/or did not have
  the time to answer to the INVITE request before the CANCELED request (from the caller) arrived to the Proxy.

### [Deprecated]
- **Proxy/EventLog:** parameter `event-logs/flexiapi-token` is renamed `event-logs/flexiapi-api-key`. It still works but
  deprecated, please use the new name.

## [2.3.3] - 2023-12-14
### [Added]
- **Presence:** last activity date is sent with long term presence.
- **B2BUA server:** you can now force the usage of a specific video codec. See the `video-codec` config for more
  information.
- **B2BUA server:** add a configurable time limit on calls and fix a bug where calls where limited to 30 minutes.
  See the `max-call-duration` config for more information.
- **B2BUA server:** allow to use other transport protocol than TCP.
- **B2BUA server:** you can now choose the User-Agent header for outgoing B2BUA request with the `user-agent` config.
- **Proxy/push-notification:** you can now choose between a HTTP/1 or a HTTP/2 client for the generic push-notification
  service. See the `external-push-protocol` config for more information.
- **[Experimental]** **Proxy/push-notification:** you can choose to use the new Firebase v1 API to send Android push
  notifications. See `firebase-service-accounts` config for more information. Use with caution, this feature is
  experimental.

### [Changed]
- **Proxy/logs:** improve Redis request logging in case of errors.
- **Proxy/router:** add a configuration parameter to choose database connection pool size for message persistence.
  See the `message-database-pool-size` config for more information.
- **Packaging:** Flexisip will create default configurations files on first install.

### [Fixed]
- **B2BUA server:** fix a bug where Trenscrypter mode placed outgoing calls using the request address instead of
  the `To` header from the incoming call.
- **Packaging:** fix Systemctl warning and service restart on Rocky Linux 9 after package update.
- **Proxy:** fix a server hangup that occurred on TLS connection timeout.
- **Proxy/push-notification:** fix crashes around HTTP/2 client that occurred on iOS push notification sending.
- **Proxy/http/2 client:** fix a problem where frames where not sent directly after an HTTP/2 window size update.
- **Proxy/registrar:** fix a race condition on rapid consecutive REGISTERs that may lead to a crash.
- **Proxy/router:** fix bug where a 5xx response was preferred over a 6xx response for some INVITEs.
- **Proxy/forward:** fix a bug where stateless CANCEL could be forwarded without the Reason header.

## [2.3.2] - 2023-09-07
### [Fixed]
- **Proxy/media-relay:** fix `candidates` media attributes being wiped out of all INVITE responses. This buggy behaviour
  was introduced in 2.3.1 while attempting to handle a response **with** ICE candidates to an INVITE **without** ICE
  candidates.
- **Proxy/registrar:** fix a regression in a domain-registration scenario with "relay-reg-to-domains" enabled, where the
  backend server fails to route to the intermediate proxy.

## [2.3.1] - 2023-08-30
### [Added]
- **B2BUA server:** add the 'no-rtp-timeout' parameter that allows to set the delay before the call is automatically
  hung up because no RTP data is received.

### [Fixed]
- **Proxy/authentication:** fix behavior differences of 'soci-password-request' according to which Soci backend
  is used. With SQlite backend the :authid placeholder was mandatory, which is not conform with parameter docstring,
  whereas it was optional with MySQL backend. It is now optional whatever the backend in use.
- **Proxy/media-relay:** fix bad behavior when the MediaRelay forwards an INVITE without ICE candidate and the
  callee send back a response with ICE candidates. In this case, the media relay didn't masquerade the connection
  address of the response.
- **Proxy/push-notification:** add support of 'google' legacy pn-type.
- **Conference & B2BUA servers:** remove liblinphone debug messages from standard output when '-d' command-line
  option isn't used.

## [2.3.0] - 2023-08-21
### [Added]
- **Flexisip proxy:** add `global/tport-message-queue-size` parameter to set the max number of SIP messages to be
  queued for writing when a socket is full.
- **Flexisip proxy:** add support for REGISTER requests with several Contact headers.
- **Flexisip proxy:** reply to OPTIONS requests with “200 Ok”. Useful to keep a connection alive by using OPTIONS
  requests.
- **Flexisip proxy:** add `module::Registrar/redis-auth-user` parameter to allow authentication to Redis servers via
  user/password.
- **Conference server:** add audio/video conferencing capability.
- **B2BUA:** forwarding of [RFC2833](https://datatracker.ietf.org/doc/html/rfc2833) and SIP INFO DTMFs.
- **flexisip_cli.py:** add `REGISTRAR_UPSERT` command that allows to modify or insert any registrar binding for a given
  Address of Record.
- **External authentication plugin:** add the SNI header in order to establish TLS connections with HTTPS virtual hosts.
- Packaging for Rocky Linux 9 and Debian 12.
- **[Experimental]** New EventLog backend based on an HTTP REST API.

### [Changed]
- **Flexisip proxy:** enforce compliance with [RFC3261](https://datatracker.ietf.org/doc/html/rfc3261) when processing
  REGISTER requests. The Call-ID is no longer used as unique-id when no `+sip-instance` parameter has been set in the
  Contact-URI; the Contact-URI is used instead by using URI comparison logic as described
  in [RFC3261 – Section 10.2.4](https://datatracker.ietf.org/doc/html/rfc3261#section-10.2.4). The CSeq value is now
  used to avoid replay attacks or SIP race conditions.

## [2.2.5] - 2023-08-02
### [Added]
- **Presence server:** add timestamp of last activity to the presence notification when the status of the user is 'away'
  or their client is no longer active.

### [Fixed]
- **Proxy:** fix system file descriptor limit detection bug that was eventually causing Flexisip to run out of file
  descriptors to handle all of its connections on some OS.
- **Proxy – ContactRouteInserter:** increase the max size of the 'CtRtxxxxx' parameter to 512 bytes to ensure that a
  full domain name can be stored.
- **Proxy – ExternalPushNotification:** fix bad behavior when an iOS client uses legacy push parameters while
  registering and the 'app-id' parameter doesn't end with '.prod' or '.dev'. It caused the '$app-id' placeholder to be
  replaced by a truncated 'app-id'. The fix makes Flexisip assume the 'app-id' ends with '.prod' if the user agent
  hasn't specified the last component.

## [2.2.4] - 2023-04-20
### [Fixed]
- Bug in SofiaSip that causes the proxy to choose a not fully established TCP connection when it needs to send a SIP
  message to a user agent. That causes some SIP message losses.
- Make the proxy to answer “200 Ok” to OPTIONS requests that are directly addressed to itself.
- Crash when the “Generic Push Notifications” feature is enabled (`module::PushNotification/external-push-uri`) but no
  Firebase API key has been put in `firebase-projects-api-keys` parameter.
- Fix a bug that causes some PUBLISH requests that was not related to presence information to be forwarded to the
  presence server.

## [2.2.3] - 2023-04-11
### [Fixed]
- CLI: print a more explicit message when the CLI cannot connect to the server socket due to permissions.
- Pusher: allow to set a custom payload for Firebase push notifications requests, as it is for Apple.
- Presence server: ensure that capabilities of each device of a user are concatenated by union while sending a NOTIFY
  request to the subscriber.
- Proxy server: make the generic pusher to replace the $app-id parameter by the right value.

## [2.2.2] - 2023-02-24
### [Fixed]
- Issue in packaging and deployment scripts.

## [2.2.1] - 2023-02-24
### [Added]

- 'global/tport-message-queue-size' parameter in flexisip.conf. Allows to set the size of the message queue which is
  used when a SIP message cannot be sent because the socket is full.

### [Changed]

- Format of `--key` option of `./flexisip_pusher` tool. The option only takes the Firebase authentication token now.

### [Fixed]

- Bug that caused the number of contacts for a given AoR to grow indefinitely when there was no '+sip.instance'
  parameter in the Contact-URI.
- Push notification was not sent to the second device when two devices had the same 'pn-prid' but distinct '
  pn-provider'.
- Messages were not forwarded with the same order as when they were received, should 'save-fork-late-message-in-db'
  feature have been enabled.
- 6xx responses were not prioritized on 4xx responses when the proxy had to forward a final response to the caller.
- Compilation with `ENABLE_SOCI=OFF` was broken.
- Crash when the “Periodic Binding Refresh” mechanism (rfc8599) was
  enabled (module::PushNotification/register-wakeup-interval>=0)
- The MediaRelay let the video stream pass in one direction only when the call was in early-media.
- Flexisip depended of useless runtime libraries such as libGLEW, libX11, etc.
- The ExternalAuthentication module didn't set the SNI header when it connected on the HTTPS server.

## [2.2.0] - 2022-10-28
### [Added]

- [Back-to-back user agent service](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/C.%20Features/3.%20Back-to-back%20User%20Agent%20server)
- `module::Router/message-database-enabled` parameter: allow to store the chat messages that are waiting for delivery
  in a SQL database instead of memory (experimental).
  Associated parameters: `message-database-backend`, `message-database-connection-string`.
- [Filter syntax](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Filter%20syntax/) getter
  additions:
    - `contact.uri.{user,domain,params}`: get parts of the Contact-URI of the current SIP message;
    - `content-type`: get the full Content-type of the body as string.
- `module::ExternalAuth/trusted-hosts` parameter: allow to let requests coming from given IP addresses pass the
  ExternalAuth module. This module is provided by 'libexternal-auth' plugin.
- Make the proxy to answer to double-CRLF ping sequence (RFC5626 §4.4.1).
- Use double-CRLF ping sequence (RFC5626 §4.4.1) to maintain connections made by the domain registration feature.
- Packaging for Rocky Linux 8, Debian 11, Ubuntu 22.04 LTS.

### [Changed]

- Improve the usage of iOS remote push notifications for notifying incoming calls. This is useful for home-automation
  applications that haven't any VoIP push notification token. In such a case, Flexisip will send several alert PNs to
  the application until one called device accept the call, and then, send a final alert PN to all the other devices
  telling that the call has been answered elsewhere. Furthermore, all the called devices receive a final PN should
  the caller cancel the call. Related parameters: `module::PushNotification/call-remote-push-interval`.
- The body of the SIP messages are hidden by default except the body of type `application/sdp`. This behaviour may be
  customized by `global/show-body-for` parameter that allows to modify the condition that discriminates which request
  should have their body displayed.

### [Fixed]

- Make the MediaRelay module to handle UPDATE requests.
- Issue where a 200 Ok for REGISTER coming from an upstream server is discarded instead of being routed back the
  originator of the REGISTER. Only concerns user of `module::Registrar/reg-on-response` feature.
- Avoid push notification sending while forwarding INVITE requests with `Replace` header.
- Issue with domain registration digest authentication which failed because of the selection of a different SRV node
  between first and authenticated request.
- Add a mechanism to ensure that all devices receive an INVITE followed by a CANCEL when a caller cancel a call
  invitation. This is useful for iOS devices that are ringing before receiving the INVITE request because they
  are notified by a VoIP push notification. Thus, such devices need to receive a CANCEL request to stop ringing.

### [Deprecated]

- `conference-server/enable-one-to-one-chat-room` parameter. Will force to `true` in further versions.
- Package for Debian 9.

## [2.1.6] - 2023-09-22
### [Fixed]
- Backport of several fixes concerning our HTTP/2 client code.

## [2.1.5] - 2022-06-09
### [Fixed]

- `reg-on-response` parameter no longer worked since Flexisip 2.1.0

## [2.1.4] - 2022-05-19
### [Fixed]

- Fix warning about failing SQL request on conference server starting.
- Make Flexisip to require Hiredis >= 0.14.
- Remove Sofia-SIP implementation of some functions that must be found on system.

## [2.1.3] - 2022-03-18
### [Fixed]

- ExternalPusher: the response to each HTTP request systematically has a delay of a few seconds when using a TCP
  connection instead of TLS.
- Race condition around Redis SUBSCRIBEs/UNSUBSCRIBEs that causes Flexisip to wrongly thinks that it is subscribed to
  some fork contexts. Finally, that causes to have end-users' device receiving push notifications for a message but no
  message is delivered by Flexisip once the application registers again.
- Weakness in the module replacement algorithm that causes some modules coming
  from plugins to be inserted in bad position in the modules list.

## [2.1.2] - 2021-12-22
### [Added]
- `rtp_bind_address` configuration parameter, which allow to choose the listening address of the media relay.
- Allow boolean expression filter to access the Contact header of the request.

### [Fixed]
- Have the CMake script to install flexisip-version.h header and embed it in the RPM/DEB package.
- Crash of the proxy when using `REGISTERAR_DELETE` command in flexisip_cli.
- Fix problems in migration of old protobuf-encoded Registrar entries.

## [2.1.1] - 2021-10-25
### [Fixed]
- Fix an issue in the CPack script that caused the name of CentOS packages to not conform with CentOS format, because
  the distribution tag (el7, el8, etc.) was missing.

## [2.1.0] - 2021-10-20
### [Added]
- New Flexisip service, 'RegEvent server', available through flexisip-regevent SystemD service.
  The RegEvent server is in charge of responding to SIP SUBSCRIBEs for the 'reg' event as defined by
  [RFC3680 - A Session Initiation Protocol (SIP) Event Package for Registrations](https://tools.ietf.org/html/rfc3680).
  To generate the outgoing NOTIFY, it relies upon the registrar database, as setup in module::Registrar section.
- **Proxy** New transport URI parameter: `tls-allow-missing-client-certificate=<true/false>`. This allows to accept TLS
  connections from clients which haven't any X.509 certificate even if `tls-verify-incoming` has been enabled. Valid for
  SIPS transport only.
- **Proxy** Add `module::DoSProtection/white-list` parameter in flexisip.conf to allow packets from given IP addresses
  to bypass the DoS protection system.
- **Proxy** Add `module::Authentication/realm` parameter that allows to force the realm offered by the proxy to user
  agents during authentication (401/407 responses).
- **Conference server** Several factory URIs can be handled by the server.
- **Push notifications** New option `--custom-payload` for flexisip_pusher utility that allows to manually set the
  payload sent to push notificaiton server (Apple push only).
- **Flexisip CLI** Add `REGISTRAR_DUMP` CLI command to dump all addresses of record registered locally.
- **Packaging** Support of CentOS 8 and Debian 10 GNU/Linux distributions.

### [Changed]
- **Proxy** `regex` operator of filter expressions in flexisip.conf now
  uses [ECMAScript grammar](https://en.cppreference.com/w/cpp/regex/ecmascript) from C++ specification.
- **Proxy** Firebase push notifications are now sent by using HTTP/2 protocol.
- **Presence server** Moving `soci-user-with-phone-request` and `soci-users-with-phones-request` parameters
  from _[module::Authenticaiton]_ section to _[presence-server]_.
- **Conference server** Conformance to 1.1 specification.
- **Packaging** Packaging process has entirely been reworked in order to embed Flexisip and Linphone SDK inside a single
  package. Thus, a given version of Flexisip is strongly bound to a specific version of Linphone SDK.

### [Deprecated]
- **Presence server** Setting `module::Authentication/soci-user-with-phone-request` and
  `module::Authentication/soci-users-with-phones-request` parameters still works but will raise a warning.

### [Removed]
- **Proxy/Push notifications** `pn-silent` push parameter has no more effect.
- **Proxy/Push notifications** Remove legacy `form-uri` key-value from Firebase push notification body.

## [2.0.9] - 2021-08-10
### [Fixed]
- **Proxy** Reverts the previous fix which prevents that two contacts with the same push parameters be registered for
  the same user. Side effects which caused some users to not receive messages or calls have been observed in production.

## [2.0.8] - 2021-08-09
### [Added]
- **Proxy** Adding 'fallback-route-filter' parameter in 'module::Router' section. This parameter allows to prevent some
  SIP requests to be forwarded to the fallback route when all the forked transactions have failed. The parameter expects
  a boolean expression as the filter parameter at the beggining of each module::\* sections. The fallback route is used
  when the boolean expression is evaluated to _true_.

### [Fixed]
- **Proxy** Prevent SIP client to registers two distinct contacts (distinct UID) which would have the same push
  notification parameters. That often happens when Linphone is uninstalled and installed again on an iOS device, causing
  the instance UID to be generated again but keeping the same push notification tokens. That causes the device to
  receives several push notifications for each SIP request because Flexisip assumes that each contact URI matches a
  distinct device. To avoid this scenario, Flexisip automatically removes the old contact URI to ensure the unicity
  of the push notification parameters.

## [2.0.7] - 2021-07-09
### [Fixed]
- **Proxy** Fix a bug that caused the fallback route to be used even if the forked request had succeeded.

## [2.0.6] - 2021-07-07
### [Fixed]
- **Proxy** INVITE requests was systematically forked to the fallback route (if set) independently of the status of each
  received response. Furthermore, the fallback destination was called alongside the real contact addresses of the called
  identity.

## [2.0.5] - 2021-06-09
### [Added]
- **Flexisip CLI** Add three new counters: count-basic-forks, count-call-forks and count-message-forks.

### [Fixed]
- **Apple push notifications** Set the 'apns-push-type' header.
- **Apple push notifications** Correctly set the 'apns-expiration' header, basing on some parameters of module::Router
  (call-fork-timeout and message-delivery-timeout).
- **Apple push notifications** Prevent the TLS connection from blocking the main thread for more than one second while
  connecting.
- **Android push notifications** Fix typo in the name of one key in the PNR payload. ('form-uri' -> 'from-uri'). The old
  key will be supported until Flexisip 2.1.
- **External Authentication plugin** Correctly print the HTTP response from the authentication server in the log.
- **External Authentication plugin** Fix bug that caused the HTTP response to be matched with the bad request when
  several request was sent simultaneously.
- **Filter parameter** Fix crash on evaluation when 'contains' operator has no left-hand operand. Makes Flexisip to
  abort on starting otherwise.
- **Flexisip CLI** Fix crash with Python3 < 3.7.
- **Memory usage** Fix several memory leaks.
- **XWiki doc generator** Fix bad output syntax when bullet points are used in parameter descriptions.
- **XWiki doc generator** Generate documentation for the experimental modules.

## [2.0.4] - 2021-03-01
### [Fixed]
- **Authentication** Prevent password mismatch error when hashed passwords are in upper case in the user database.
- **Push Notifications** Prevent the PushNotification module from sending an out-of-dialog "180 Ringing" reply when an
  in-dialog 180 reply has already been forwarded back by the Router module.
- **Apple push notifications** The new HTTP/2 client now automatically close the connection with the APNS after one
  minute of inactivity to prevent the connection to be silently destroyed by aggressive routers. That improve PNR
  sending reliability.
- **Android push notifications** Use timeouts that has been set in the Router module settings to fill the TTL with the
  push notification request.
  See [Flexisip's specification around push notifications](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/D.%20Specifications/Push%20notifications/#HContentofthepushnotificationssentbyFlexisip)
  for more information about the involved parameters.
- **Media relay** Fix an issue while processing a SDP without ICE containing an IPv6 connection address, and Flexisip
  has no IPv6 address available.
  Previously, an empty connection address was set by the MediaRelay module, causing a blank call. Now, the IPv4 address
  will be used as fallback, which will work if the network provides NAT64 service.
- **Proxy server** Fix several huge memory leaks. No more memory leaks issues are known on the proxy component today.
- **Conference server** The transport address now allows to restrict the listening interface. Before, the conference was
  listening on all interfaces independently of the transport host.

### [Removed]
- 'pn-silent' custom Contact parameter for push notifications.

## [2.0.3] - 2020-11-13
### [Fixed]
- Apple push notification client: the body of HTTP/2 GOAWAY frames wasn't printed in log, which doesn't allow to know
  the disconnection reason.
- Fix a regression that causes to have an empty pub-gruu parameter in the Contact header of forwarded REGISTERs.
- Fix potential crash or at least memory corruption when both "route" and "default-transport" are set in the
  ForwardModule. The default-transport will not be applied when route is used.
- MediaRelay: fix ICE restart not being detected or notified on the offered side. This causes relay candidates to be not
  added in the 200 Ok, which can break RTP communication.

## [2.0.2] - 2020-10-14
### [Fixed]
- Fix a crash that occures when module::Registrar/reg-on-response feature is enabled. It happens when the “200
  Registration successful” response is received from the backend server.

## [2.0.1] - 2020-10-13
### [Changed]
- Usage of HTTP2 protocol to send Apple push notification requests. No change in PushNotification module configuration
  required.

### [Fixed]
- Crash when trying to fetch domain records from registrar DB.
- Avoid MediaRelay's channel to continuously swap between IPv6 and IPv4 during ICE connectivity checks. Indeed, this
  causes some connectivity checks to fail because some stun requests sent over IPv6 are answered over IPv4 and vice
  versa. The workaround implemented consists in locking the destination chosen by the MediaRelay's channels (when
  receiving a packet) for a minimum of 5 seconds. The switch to a new destination is allowed only if the previous
  destination has been unused over the last 5 seconds.

## [2.0.0] – 2020-07-31
### [Added]
**New settings**
- `global/contextual-log-filter` ([Contextual log feature](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/C.%20Features/Contextual%20logs/))
- `global/contextual-log-level` ([Contextual log feature](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/C.%20Features/Contextual%20logs/))
- `global/log-filename`: allows to choose the name of the log file.
- `module::Authentication/realm-regex`: allows to choose how the authentication module deduces the realm from the "From"
  header.
- `module::PushNotification/retransmission-count` (PNR retransmission feature)
- `module::PushNotification/retransmission-interval` (PNR retransmission feature)
- `module::PushNotification/display-from-uri`: controls whether the "From" URI is print in PN payloads.
- `module::MediaRelay/force-public-ip-for-sdp-masquerading`: force the MediaRelay module to put the public IP address of
  the proxy while modifying the SDP body of INVITE requests. Only useful when the server is behind a NAT router.
- `conference-server/check-capabalities` (
  see [Reference Documentation](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/A.%20Configuration%20Reference%20Guide/2.0.0/conference-server))

**Proxy**
- [Contextual log feature](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/C.%20Features/Contextual%20logs/)
- External authentication plugin.
- Push Notification Request (PNR) retransmission feature. Allow to send PNR several time when no response for the first
  PNR has been received from the push server.
- Add support for loc-key and loc-args to Firebase, in order to be compatible with apps implementing the same logic as
  for iOS when handling push notifications coming from Flexisip.
- EventLog: log the value of 'Priority' header for each request event.
- Support of [RFC 8599](https://tools.ietf.org/html/rfc8599) for the transmission of the PushNotification information
  through REGISTER requests.

**Presence**
- Support
  of [“Server known resource lists” feature](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/C.%20Features/Presence%20server/#HServerknownresourcelists).

**Miscellaneous**
- Add an option (`--rewrite-config`) to Flexisip command-line interface to dump a new configuration file with up-to-date
  doc strings but keeping the setting that have been set explicitly by the user.

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
- [Push Notifications] The "From" URI is no more printed in the PN payload as first element of loc-args list.
  Use `module::PushNotification/display-from-uri` setting to restore this behaviour.

**Miscellaneous**
- Log files are now named flexisip-proxy.log, flexisip-conference.log flexisip-presence.log by default.
- Log rotation is fully handled by Logrotate script (
  see [“Logging” documentation page](https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Logs/#HLogrotation)).
- `--dump-all-default` option dumps a configuration file with all the parameters commented out.
- `--dump-default` allow to dump default settings for non-module sections.
- Generation of plugins default settings and documentation by '--dump-all-default' option when they have been loaded
  using `--set global/plugins=<plugin-list>`.

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
- Failing authentication when the user part of the "From" URI has escaped sequences.
- Improve Firebase's push notification resilience against broken sockets.
- Remove empty 'pub-gruu' params from contact headers of OK response when `module::Registrar/reg-on-response` is on.
- SystemD service not restarted on package update.
- Fix MediaRelay ICE processing when the server has both IPv6 and IPv6 addresses. Previously, only ICE relay candidates
  with the "preferred" connectivity was offered. However, the way the "preferred" connectivity is guessed is not
  reliable, especially when sending the INVITE to the callee, and it can change during a call, for example when one of
  the parties moves from an IPv6-only LTE network to an IPv4-only network. For these reasons, it is preferable that ICE
  relay candidates are added for both IPv4 and IPv6.

**Conference**
- Fix becoming admin again after leaving and reentering a chat room.

[comment]: <> (Usefull links)

[configuration reference guide]: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/A.%20Configuration%20Reference%20Guide/

[SIP-Bridge documentation]: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Back-to-back%20User%20Agent%20(b2bua)/SIP%20Bridge/

[module::AuthOpenIDConnect documentation]: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Authentication/Module-OpenIDConnect/

[FlexisipAccountManager]: https://www.linphone.org/en/flexisip-sip-server/#flexisip-software
