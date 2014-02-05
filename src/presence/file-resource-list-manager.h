/*
 * FileResourceListManager.h
 *
 *  Created on: 28 janv. 2014
 *      Author: jehanmonnier
 */

#ifndef FILERESOURCELISTMANAGER_H_
#define FILERESOURCELISTMANAGER_H_

#include <resource-list-manager.hh>

class FileResourceListManager: public ResourceListsManager {
public:
	FileResourceListManager();
	virtual ~FileResourceListManager();
};

#endif /* FILERESOURCELISTMANAGER_H_ */
