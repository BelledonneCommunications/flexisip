# Change Log

All notable changes to this project will be documented in this file.

Group changes to describe their impact on the project, as follows:

| **Group name** | **Description**                                       |
| ----------     | ----------------------------------------------------- |
| Added          | new features                                          |
| Changed        | changes in existing functionality                     |
| Deprecated     | once-stable features removed in upcoming releases     |
| Removed        | deprecated features removed in this release           |
| Fixed          | any bug fixes                                         |
| Security       | to invite users to upgrade in case of vulnerabilities |

## [Unreleased]

### [Added]
 - [Presence server] Support of bodyless subscription.
 - [Proxy] Add contextual logs settings.
 - [Proxy] External authentication plugin.
 - [Proxy] module::MediaRelay/force-public-ip-for-sdp-masquerading parameter
 - [Conference] 'check-capabilities' boolean parameter
 - --rewrite-config option
 - [Proxy] Add 'realm-regex' parameter in Authentication module.
 - [Proxy] Push Notification Request retransmission feature.
 - [flexisip_cli] Allow to clear registration information of a given user when using REGISTRAR_CLEAR
   sub-command.
 - [Proxy] Add support for loc-key and loc-args to Firebase, in order to be compatible with apps implementing the same logic as for iOS when handling push notifications coming from Flexisip.
 - [Proxy] EventLog: log the value of 'Priority' header of each event
 - [Proxy] Support of RFC 8599 for the transmission of the PushNotification information through REGISTER requests.
 - --dump-default can dump default settings for non-module sections.
 - Add global/log-filename parameter
 
### [Changed]
 - [Proxy] log files are now named flexisip-proxy.log, flexisip-conference.log flexisip-presence.log
 - [Proxy] boolean expression engine is faster
 - [Presence] Default value of 'max-thread' and 'max-thread-queue-size' in [presence-server] section
   switched from 200 to 50.
 - [Presence] Presence module settings are not declared as expirimental anymore.
 - Log rotation is fully handled by Logrotate script.
 - [Proxy] Change "from" into "sip-from" in firebase notification, because "from" is reserved.
 - --dump-all-default dump a configuration file with all the parameters commented out.
 - [Proxy] Default value of 'params-to-remove' parameter in Forward module. Adding 'pn-provider',
   'pn-prid', 'pn-param'.
 - Breaking of the event log database schema.
 - Default values of setting parameters:
   - global/enable-snmp: true -> false
   - gloabl/dump-cores: true -> false
   - module::Router/message-delivery-timeout: 1w
   - module::Router/decrease message-accept-timeout: 5s

 - Setting parameter renaming:
   - event-logs/dir -> event-logs/filesystem-directory
   - module::Registrar/datasource -> module::Registrar/file-path
   - module::Registrar/name-message-expires -> module::Registrar/message-expires-param-name
   - presence-server/soci-connection-string -> presence-server/rls-database-connection
   - presence-server/external-list-subscription-request -> presence-server/rls-database-request
   - presence-server/max-thread -> presence-server/rls-database-max-thread
   - presence-server/max-thread-queue-size -> presence-server/rls-database-max-thread-queue-size

 - Settings: [monitor] section marked as experimental

### [Deprecated]
 - New deprecated setting parameters:
   - global/use-maddr
   - module::Registrar/redis-record-serializer
   - module::Router/fork
   - module::Router/stateful
 

### [Removed]
 - 'max-log-size' parameter cannot be used anymore and will prevent Flexisip from starting if so.
   Log rotation and size control is now fully managed by 'logrotate' script.
 - Removed setting parameter:
   - global/debug
   - module::Authentication/enable-test-accounts-creation
   - module::Authentication/hashed-password
   - module::Router/generated-contact-route
   - module::Router/generated-contact-expected-realm
   - module::Router/generate-contact-even-on-filled-aor
   - module::Router/preroute
   - module::PushNotification/google
   - module::PushNotification/google-*
   

### [Fixed]
 - Memory leak (of SIP transactions) in presence server.
 - [Proxy] missing aborted calls in event log.
 - [Proxy] Prevent loops due to fallback routes, when two flexisip servers have fallback route to each other.
 - [Proxy] Don't set tag to 110 push messages. It makes no sense, a proxy doesn't have to create dialogs.
 - [Proxy] Abort server starting if module::Presence/presence-server setting has an invalid SIP URI.
 - Generation of plugins documentation by '--dump-all-default' option when they have been loaded using
   --set global/plugins=<plugin-list>.
 - [Proxy] Prevent sending of multiple “110 Push sent” response while a call is forked into several legs.
 - [Proxy] Crash when processing a REGISTER with a invalid Contact URI.
 - [Proxy] Prevent “110 Push Sent” response from being sent after “180 Ringing”.
 - [Proxy] Failing authentication when the user part of the From URI has escaped sequences.
 - [Proxy] Improve Firebase's push notification resilience against broken sockets.
 - [Proxy] Remove empty 'pub-gruu' params from contact headers of OK response when module::Registrar/reg-on-response is on.
 - [Proxy] [module::Authentication] adapt the digest algorithm of the Authentication header according to the algorithm used in the user database
 - [Proxy] SystemD service not restarted on package update
 - [Proxy] Prevent server abort on registration with an invalid AoR.
 - [Proxy] Fix MediaRelay ICE processing when the server has both IPv6 and IPv6 addresses.
           Previously, only ICE relay candidates with the "prefered" connectivity was offered. However the way the "prefered" connectivity is guessed is not reliable,
           especially when sending the INVITE to the callee, and it can change during a call, for example when one of the parties moves from an IPv6-only LTE network to an IPv4-only network.
           For these reasons, it is preferable that ICE relay candidates are added for both IPv4 and IPv6.
 - [Proxy] Missing line-feed in filesystem event logs
 - [Proxy] Bad behaviour when receiving a REGISTER request which contains a '@' in its CallID.
 - [Conference] Fix becoming admin again after leaving and reentering a chat room
