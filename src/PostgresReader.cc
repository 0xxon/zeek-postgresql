// See the file "COPYING" in the main distribution directory for copyright.

#include <regex>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zeek/zeek-config.h"

#include "zeek/NetVar.h"
#include "zeek/threading/SerialTypes.h"

#include "PostgresReader.h"

using namespace input::reader;
using zeek::threading::Value;
using zeek::threading::Field;


PostgreSQL::PostgreSQL(zeek::input::ReaderFrontend *frontend) : zeek::input::ReaderBackend(frontend)
	{
	io = std::unique_ptr<zeek::threading::formatter::Ascii>(new zeek::threading::formatter::Ascii(this, zeek::threading::formatter::Ascii::SeparatorInfo()));
	}

PostgreSQL::~PostgreSQL()
	{
	if ( conn != 0 )
		PQfinish(conn);
	DoClose();
	}

void PostgreSQL::DoClose()
	{
	}

std::string PostgreSQL::LookupParam(const ReaderInfo& info, const std::string name) const
	{
	std::map<const char*, const char*>::const_iterator it = info.config.find(name.c_str());
	if ( it == info.config.end() )
		return std::string();
	else
		return it->second;
	}

bool PostgreSQL::DoInit(const ReaderInfo& info, int arg_num_fields, const zeek::threading::Field* const* arg_fields)
	{
	assert(arg_fields);
	assert(arg_num_fields >= 0);

	std::string conninfo = LookupParam(info, "conninfo");
	if ( conninfo.empty() )
		{
		std::string hostname = LookupParam(info, "hostname");
		if ( hostname.empty() )
			{
			MsgThread::Info("hostname configuration option not found. Defaulting to localhost.");
			hostname = "localhost";
			}

		std::string dbname = LookupParam(info, "dbname");
		if ( dbname.empty() )
			{
			Error("dbname configuration option not found. Aborting.");
			return false;
			}

		conninfo = std::string("host = ") + hostname + " dbname = " + dbname;

		std::string port = LookupParam(info, "port");
		if ( ! port.empty() )
			conninfo += " port = " + port;
		}

	conn = PQconnectdb(conninfo.c_str());

	num_fields = arg_num_fields;
	fields = arg_fields;

	if ( PQstatus(conn) != CONNECTION_OK )
		{
		Error(Fmt("Could not connect to pg (%s): %s", conninfo.c_str(), PQerrorMessage(conn)));
		return false;
		}

	query = info.source;

	DoUpdate();

	return true;
	}

// note - EscapeIdentifier is replicated in writer
std::string PostgreSQL::EscapeIdentifier(const char* identifier)
	{
	char* escaped = PQescapeIdentifier(conn, identifier, strlen(identifier));
	if ( escaped == nullptr )
		{
		Error(Fmt("Error while escaping identifier '%s': %s", identifier, PQerrorMessage(conn)));
		return std::string();
		}
	std::string out = escaped;
	PQfreemem(escaped);

	return out;
	}

std::unique_ptr<Value> PostgreSQL::EntryToVal(std::string s, const zeek::threading::Field* field)
	{
	std::unique_ptr<Value> val(new Value(field->type, true));

	switch ( field->type ) {
	case zeek::TYPE_ENUM:
	case zeek::TYPE_STRING:
		val->val.string_val.length  = s.size();
		val->val.string_val.data = zeek::util::copy_string(s.c_str());
		break;

	case zeek::TYPE_BOOL:
		if ( s == "t" ) {
			val->val.int_val = 1;
		} else if ( s == "f" ) {
			val->val.int_val = 0;
		} else {
			Error(Fmt("Invalid value for boolean: %s", s.c_str()));
			return nullptr;
		}
		break;

	case zeek::TYPE_INT:
		val->val.int_val = atoi(s.c_str());
		break;

	case zeek::TYPE_DOUBLE:
	case zeek::TYPE_TIME:
	case zeek::TYPE_INTERVAL:
		val->val.double_val = atof(s.c_str());
		break;

	case zeek::TYPE_COUNT:
		val->val.uint_val = atoi(s.c_str());
		break;

	case zeek::TYPE_PORT:
		val->val.port_val.port = atoi(s.c_str());
		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case zeek::TYPE_SUBNET: {
		int pos = s.find("/");
		int width = atoi(s.substr(pos+1).c_str());
		std::string addr = s.substr(0, pos);

		val->val.subnet_val.prefix = io->ParseAddr(addr);
		val->val.subnet_val.length = width;
		break;

		}
	case zeek::TYPE_ADDR:
		val->val.addr_val = io->ParseAddr(s);
		break;

	case zeek::TYPE_TABLE:
	case zeek::TYPE_VECTOR:
		// First - common stuff
		// Then - initialization for table.
		// Then - initialization for vector.
		{
		bool real_array = true;
		static std::regex comma_re(",");
		// (?:                  -> first group, non-marking. Group describes double-quoted syntax
		//    \"                -> array element has to start with double quote
		//              (.*?)   -> non-greedy capture (number 1) for content of element
		//    (?!\\\\)\"        -> element ends with a double quote that is not escaped (no \ in front)
		//    (?:,|$)           -> followed either by comma or end of string
		//  )
		//  |
		//  (?:                 -> second group, non-marking. Group describes non-double-quoted syntax
		//    ([^,{}\"\\\\]+?)  -> non-greedy capture (number 2). Minimal length of 1 (zero-length has to
		//                         be quoted). May not contain a number of special characters.
		//    (?:,|$)           -> followed either by comma or end of string
		//  )
		static std::regex elements_re("(?:\"(.*?)(?!\\\\)\"(?:,|$))|(?:([^,{}\"\\\\]+?)(?:,|$))");
		static std::regex escaped_re("(?:\\\\(\\\\))|(?:\\\\(\"))");

		// assume it is a real array. We don't really have a much better
		// way to figure this out because the Postgres code that can easily tell us the
		// SQL type lives in the backend and cannot easily be included here...
		auto it = std::sregex_token_iterator(s.begin()+1, s.end()-1, elements_re, {1,2});
		static std::sregex_token_iterator end;

		// Oh Not a postgres array. Just assume Bro-style comma separated values.
		if ( s.front() != '{' || s.back() != '}' )
			{
			real_array = false;
			it = std::sregex_token_iterator(s.begin(), s.end(), comma_re, -1);
			}

		std::unique_ptr<Field> newfield(new Field(*field));
		newfield->type = field->subtype;

		std::vector<std::unique_ptr<Value>> vals;

		int match_number = 0;
		while ( it != end )
			{
			match_number++;
			if ( ! (*it).matched )
				{
				it++;
				continue;
				}

			std::string element = *it;

			// real postgres array and double-colons -> unescape
			if ( real_array && match_number % 2 == 1 )
				element = std::regex_replace(element, escaped_re, "$1$2");

			// real postgres array, no double-colons, string equals null -> real null
			if ( real_array && match_number % 2 == 0 && element == "NULL" )
				// note that this actually leeds to problems at the moment downstream.
				vals.emplace_back(new Value(field->subtype, false));
			else
				{
				auto newval = EntryToVal(element, newfield.get());
				if ( newval == nullptr )
					{
					Error("Error while reading set");
					return nullptr;
					}
				vals.push_back(std::move(newval));
				}

			it++;
			}


		// this should not leak in case of error -- instead, Value::~Value will clean it up.
		Value** lvals = new Value* [vals.size()];
		for ( decltype(vals.size()) i = 0; i<vals.size(); ++i )
			lvals[i] = vals[i].release();

		if ( field->type == zeek::TYPE_TABLE )
			{
			val->val.set_val.vals = lvals;
			val->val.set_val.size = vals.size();
			}
		else if ( field->type == zeek::TYPE_VECTOR )
			{
			val->val.vector_val.vals = lvals;
			val->val.vector_val.size = vals.size();
			}
		else
			assert(false);

		break;
		}

	default:
		Error(Fmt("unsupported field format %d for %s", field->type, field->name));
		return 0;
		}

	return val;

	}

bool PostgreSQL::DoUpdate()
	{
	PGresult *res = PQexecParams(conn, query.c_str(), 0, NULL, NULL, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
		{
		Error(Fmt("PostgreSQL query failed: %s", PQerrorMessage(conn)));
		PQclear(res);
		return false;
		}

	std::vector<int> mapping;
	mapping.reserve(num_fields);

	for ( int i = 0; i < num_fields; ++i ) {
		std::string fieldname = EscapeIdentifier(fields[i]->name);
		if ( fieldname.empty() )
			return false;

		int pos = PQfnumber(res, fieldname.c_str());
		if ( pos == -1 )
			{
			Error(Fmt("Field %s was not found in PostgreSQL result", fieldname.c_str()));
			PQclear(res);
			return false;
			}

		mapping.push_back(pos);
	}

	assert( mapping.size() == num_fields );

	for ( int i = 0; i < PQntuples(res); ++i )
		{
		std::vector<std::unique_ptr<Value>> ovals;
		//ovals.resize(num_fields);

		for ( int j = 0; j < num_fields; ++j )
			{
			if ( PQgetisnull(res, i, mapping[j] ) == 1 )
				ovals.emplace_back(std::unique_ptr<Value>(new Value(fields[j]->type, false)));
			else
				{
				// PQgetvalue result will be cleaned up by PQclear.
				std::string value (PQgetvalue(res, i, mapping[j]), PQgetlength(res, i, mapping[j]));
				auto res = EntryToVal(value, fields[j]);
				if ( res == nullptr )
					{
					// error occured, let's break out of this line. Just removing ovals will get rid of everything.
					ovals.clear();
					break;
					}

				ovals.push_back(std::move(res));
				}
			}

		// if there is an result, send it on :)
		if ( ! ovals.empty() )
			{
			assert( ovals.size() == num_fields );
			Value** ofields = new Value*[num_fields];

			for ( int i = 0; i < num_fields; ++i )
				{
				ofields[i] = ovals[i].release();
				}

			SendEntry(ofields);
			}
		}

	PQclear(res);
	EndCurrentSend();

	return true;
	}

// currently we do not support streaming
bool PostgreSQL::DoHeartbeat(double network_time, double current_time)
	{
	return true;
	}
