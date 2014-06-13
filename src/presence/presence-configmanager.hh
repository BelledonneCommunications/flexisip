//
//  proxy-configmanager.h
//  flexisip
//
//  Created by jeh on 07/02/14.
//  Copyright (c) 2014 Belledonne Communications. All rights reserved.
//

#ifndef __flexisip__presence_configmanager__
#define __flexisip__presence_configmanager__

#include "configmanager.hh"

class PresenceConfigManager : public GenericManager {
public:
	PresenceConfigManager();
	virtual ~PresenceConfigManager(){};
};
#endif /* defined(__flexisip__presence_configmanager__) */
