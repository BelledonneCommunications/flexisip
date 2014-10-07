/*
 * presentity-manager.hh
 *
 *  Created on: 22 septembre 2014
 *      Author: jehanmonnier
 */

#ifndef PRESENTITY_MANAGER_HH_
#define PRESENTITY_MANAGER_HH_
#include "string"
#include "flexisip-exception.hh"
namespace flexisip {
	
	class PresentityManager {
		
	public:
		virtual void addOrUpdateListener(PresentityPresenceInformation::Listener& listerner, int exires) = 0;
		virtual void removeListener(PresentityPresenceInformation::Listener& listerner) = 0;
	};
}
#endif /* PRESENTITY_MANAGER_HH_ */
