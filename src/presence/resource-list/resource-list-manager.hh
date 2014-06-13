/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2014  Belledonne Communications, Grenoble, France.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef RESOURCE_LIST_MANAGER_HH_
#define RESOURCE_LIST_MANAGER_HH_
#include <list>
using namespace std;
struct belle_sip_header_address_t;
struct belle_sip_uri_t;

/**
 * A resource list is composed by a list name
 */


class ResourceList {
public:
	/**
	 * @return the uri this list is attached to.
	 * */
	const belle_sip_uri_t* getOwner();
	/**
	 * @return the address/display name of list
	 * */
	const belle_sip_header_address_t* getName();
	/**
	 * @return list of entries
	 * */
	const list<const belle_sip_header_address_t*> getEntries() const;
};


/**
 * This class is the entry point to manage resource list as described by rfc4826.
 * main methods are asynchronous to allow asynchronous implementation
 */
class ResourceListsManager {

public:

	/***
	 * Common listener of asynchronous operations
	 */
	class Listener {
		virtual void onSuccess() throw ();
		virtual void onError(string& reason) throw ();
	};


	class FethListener : Listener{
		virtual void onResponse(const ResourceList& list) throw ();

	};

	/**
	 * get access to the list of entries linked to the list name @list_name
	 * @param list_name name of the list, can be a sip uri or a generic uri
	 * @param listener to get result
	 * */
	virtual void fetch(std::string& list_name,FethListener& listener) throw ()=0;



	/*
	 * Create or update a list of entries for a given list name
	 * @param list_name name of the list, can be a sip uri or a generic uri
	 * @param list of entries
	 * @param listener to get result
	 *
	 * */
	virtual void add(std::string& list_name,ResourceList& list, Listener& listener) throw ()=0;

	/*
	 * Create or update a list of entries for a given list name
	 * @param list_name name of the list, can be a sip uri or a generic uri
	 * @param listener to get result
	 *
	 * */
	virtual void remove(std::string& list_name,Listener& listener) throw () = 0;



};

#endif /* RESOURCE_LIST_MANAGER_HH_ */
