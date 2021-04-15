
#include "Plugin.h"
#include "PostgresWriter.h"
#include "PostgresReader.h"

namespace plugin { namespace Johanna_PostgreSQL { Plugin plugin; } }

using namespace plugin::Johanna_PostgreSQL;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new zeek::logging::Component("PostgreSQL", ::logging::writer::PostgreSQL::Instantiate));
	AddComponent(new zeek::input::Component("PostgreSQL", ::input::reader::PostgreSQL::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "Johanna::PostgreSQL";
	config.description = "PostgreSQL log writer and input reader";
	config.version.major = 0;
	config.version.minor = 2;
	return config;
	}
