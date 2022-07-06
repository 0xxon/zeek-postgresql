
#ifndef BRO_PLUGIN_BRO_POSTGRES
#define BRO_PLUGIN_BRO_POSTGRES

#include <zeek/plugin/Plugin.h>

namespace plugin {
namespace Johanna_PostgreSQL {

class Plugin : public zeek::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	virtual zeek::plugin::Configuration Configure();
};

extern Plugin plugin;
}
}

#endif
