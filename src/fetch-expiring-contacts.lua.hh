/*  SPDX-License-Identifier: GPL-3.0-or-later

	You can set your editor to Lua for this file to get syntax highlighting.

	Brief:
		Redis script to return all ExtendedContacts that are about to expire.	
	
	KEYS:
		1: Records to match (usually equal to "fs:*" to match everything)
		   Could arguably be hardcoded, but Redis's doc says a script should
		   declare all the keys it accesses. [string]
		   https://redis.io/docs/manual/programmability/eval-intro/#script-parameterization
	ARGV:
		1: Lower temporal bound (usually the current time). ExtendedContacts expiring(ed)
		   before this time won't be returned. [Unix timestamp]
		2: Threshold. ExtendedContacts expiring after ARGV[1] plus this amount won't
		   be returned. [number of seconds]
	
	Implementation:
		Loop on all redis keys (Records), then loop on the hash fields 2 by 2 to
		get the ExtendedContacts (skipping the unique ids).
		Parse SIP URI fields and keep contacts expiring within the target range.
*/

R"lua(
local all_records = redis.call("KEYS", KEYS[1])
local current_time = tonumber(ARGV[1])
local deadline = current_time + tonumber(ARGV[2])
local expiring_contacts = {}
for _, record in ipairs(all_records) do
	local pairs = redis.call("HGETALL", record)
	for i = 2, #pairs, 2 do
		local contact = pairs[i];
		local expires, updatedAt = contact:match("expires=(%d+);.*updatedAt=(%d+);")
		if not expires then
			break
		end
		local expiration_time = tonumber(updatedAt) + tonumber(expires)
		if current_time <= expiration_time and expiration_time < deadline then
			table.insert(expiring_contacts, contact)
		end
	end
end
return expiring_contacts
)lua"