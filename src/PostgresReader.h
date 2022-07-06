// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_POSTGRES_H
#define INPUT_READERS_POSTGRES_H

#include <iostream>
#include <vector>
#include <memory> // for unique_ptr

#include "zeek/input/ReaderFrontend.h"
#include "zeek/threading/formatters/Ascii.h"
#include <libpq-fe.h>

namespace input { namespace reader {

class PostgreSQL : public zeek::input::ReaderBackend {
public:
	explicit PostgreSQL(zeek::input::ReaderFrontend* frontend);
	~PostgreSQL();

	// prohibit copying and moving
	PostgreSQL(const PostgreSQL&) = delete;
	PostgreSQL& operator=(const PostgreSQL&) = delete;
	PostgreSQL(PostgreSQL&&) = delete;

	static zeek::input::ReaderBackend* Instantiate(zeek::input::ReaderFrontend* frontend) { return new PostgreSQL(frontend); }

protected:
	bool DoInit(const ReaderInfo& info, int arg_num_fields, const zeek::threading::Field* const* fields) override;

	void DoClose() override;

	bool DoUpdate() override;

	bool DoHeartbeat(double network_time, double current_time) override;

private:
	// note - EscapeIdentifier is replicated in writier
	std::string EscapeIdentifier(const char* identifier);
	std::string LookupParam(const ReaderInfo& info, const std::string name) const;
	std::unique_ptr<zeek::threading::Value> EntryToVal(std::string s, const zeek::threading::Field* type);

	PGconn *conn;
	std::unique_ptr<zeek::threading::formatter::Ascii> io;

	const zeek::threading::Field* const * fields; // raw mapping
	std::string query;
	int num_fields;
};


}
}

#endif /* INPUT_READERS_POSTGRES_H */
