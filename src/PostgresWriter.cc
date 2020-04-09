// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <errno.h>
#include <vector>
#include <regex>

#include "zeek-config.h"

#include "NetVar.h"
#include "threading/SerialTypes.h"

#include "PostgresWriter.h"
#include "postgresql.bif.h"

using namespace logging;
using namespace writer;
using threading::Value;
using threading::Field;

PostgreSQL::PostgreSQL(WriterFrontend* frontend) : WriterBackend(frontend)
	{
	io = std::unique_ptr<threading::formatter::Ascii>(new threading::formatter::Ascii(this, threading::formatter::Ascii::SeparatorInfo()));

	default_hostname.assign(
		(const char*) BifConst::LogPostgres::default_hostname->Bytes(),
		BifConst::LogPostgres::default_hostname->Len()
		);

	default_dbname.assign(
		(const char*) BifConst::LogPostgres::default_dbname->Bytes(),
		BifConst::LogPostgres::default_dbname->Len()
		);

	default_port = BifConst::LogPostgres::default_port;

	ignore_errors = false;
	bytea_instead_text = false;
	}

PostgreSQL::~PostgreSQL()
	{
	if ( conn != 0 )
		PQfinish(conn);
	}

std::string PostgreSQL::GetTableType(int arg_type, int arg_subtype)
	{
	std::string type;

	switch ( arg_type ) {
	case TYPE_BOOL:
		type = "boolean";
		break;

	case TYPE_INT:
	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		type = "bigint";
		break;

	/*
	case TYPE_PORT:
		type = "VARCHAR(10)";
		break; */

	case TYPE_SUBNET:
	case TYPE_ADDR:
		type = "inet";
		break;

	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_DOUBLE:
		type = "double precision";
		break;

	case TYPE_ENUM:
		type = "TEXT";
		break;

	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		type = "TEXT";
		if ( bytea_instead_text )
			type = "BYTEA";
		break;

	case TYPE_TABLE:
	case TYPE_VECTOR:
		type = GetTableType(arg_subtype, 0) + "[]";
		break;

	default:
		Error(Fmt("unsupported field format %d ", arg_type));
		return std::string();
	}

	return type;
}

// preformat the insert string that we only need to create once during our lifetime
bool PostgreSQL::CreateInsert(int num_fields, const Field* const * fields, std::string add_string)
	{
	std::string names = "INSERT INTO "+table+" ( ";
	std::string values("VALUES (");

	for ( int i = 0; i < num_fields; ++i )
		{
		std::string fieldname = EscapeIdentifier(fields[i]->name);
		if ( fieldname.empty() )
			return false;

		if ( i != 0 )
			{
			values += ", ";
			names += ", ";
			}

		names += fieldname;
		values += "$" + std::to_string(i+1);
		}

	insert = names + ") " + values + ") " + add_string + ";";

	return true;
	}

std::string PostgreSQL::LookupParam(const WriterInfo& info, const std::string name) const
	{
	std::map<const char*, const char*>::const_iterator it = info.config.find(name.c_str());
	if ( it == info.config.end() )
		return std::string();
	else
		return it->second;
	}

// note - EscapeIdentifier is replicated in reader
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

bool PostgreSQL::DoInit(const WriterInfo& info, int num_fields,
			    const Field* const * fields)
	{
	std::string conninfo = LookupParam(info, "conninfo");
	if ( conninfo.empty() )
		{
		std::string hostname = LookupParam(info, "hostname");
		if ( hostname.empty() )
			{
			MsgThread::Info(Fmt("hostname configuration option not found. Defaulting to %s", default_hostname.c_str()));
			hostname = default_hostname;
			}

		std::string dbname = LookupParam(info, "dbname");
		if ( dbname.empty() )
			{
			if ( default_dbname == "" )
				{
				MsgThread::Error(Fmt("dbname configuration option not found."));
				return false;
				}
			else
				{
				MsgThread::Error(Fmt("dbname configuration option not found. Defaulting to %s", default_dbname.c_str()));
				dbname = default_dbname;
				}
			}

		conninfo = std::string("host = ") + hostname + " dbname = " + dbname;

		std::string port = LookupParam(info, "port");
		if ( ! port.empty() )
			conninfo += " port = " + port;
		else if ( default_port >= 0 )
			conninfo += Fmt(" port = %d", default_port);
		}

	std::string add_string = LookupParam(info, "sql_addition");

	std::string errorhandling = LookupParam(info, "continue_on_errors");
	if ( !errorhandling.empty() && errorhandling == "T" )
		ignore_errors = true;

	std::string bytea = LookupParam(info, "bytea_instead_of_text");
	if ( !bytea.empty() && bytea == "T" )
		bytea_instead_text = true;

	conn = PQconnectdb(conninfo.c_str());

	if ( PQstatus(conn) != CONNECTION_OK )
		{
		Error(Fmt("Could not connect to pg (%s): %s", conninfo.c_str(), PQerrorMessage(conn)));
		return false;
		}

	table = EscapeIdentifier(info.path);
	if ( table.empty() )
		return false;


	std::string create = "CREATE TABLE IF NOT EXISTS "+table+" (\n"
		"id SERIAL UNIQUE NOT NULL";

	for ( int i = 0; i < num_fields; ++i )
		{
		const Field* field = fields[i];

		create += ",\n";

		std::string escaped = EscapeIdentifier(field->name);
		if ( escaped.empty() )
			return false;
		create += escaped;

		std::string type = GetTableType(field->type, field->subtype);

		create += " "+type;
		/* if ( !field->optional ) {
			create += " NOT NULL";
		} */
		}

	create += "\n);";

	PGresult *res = PQexec(conn, create.c_str());
	if ( PQresultStatus(res) != PGRES_COMMAND_OK)
		{
		Error(Fmt("Create command failed: %s\n", PQerrorMessage(conn)));
		return false;
		}

	return CreateInsert(num_fields, fields, add_string);
	}

bool PostgreSQL::DoFlush(double network_time)
	{
	return true;
	}

bool PostgreSQL::DoFinish(double network_time)
	{
	return true;
	}

bool PostgreSQL::DoHeartbeat(double network_time, double current_time)
	{
	return true;
	}

std::tuple<bool, std::string, int> PostgreSQL::CreateParams(const Value* val)
	{
	static std::regex curly_re("\\\\|\"");

	if ( ! val->present )
		return std::make_tuple(false, std::string(), 0);

	std::string retval;
	int retlength = 0;

	switch ( val->type ) {

	case TYPE_BOOL:
		retval = val->val.int_val ? "T" : "F";
		break;

	case TYPE_INT:
		retval = std::to_string(val->val.int_val);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		retval = std::to_string(val->val.uint_val);
		break;

	case TYPE_PORT:
		retval = std::to_string(val->val.port_val.port);
		break;

	case TYPE_SUBNET:
		retval = io->Render(val->val.subnet_val);
		break;

	case TYPE_ADDR:
		retval = io->Render(val->val.addr_val);
		break;

	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_DOUBLE:
		retval = std::to_string(val->val.double_val);
		break;

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		retval = std::string(val->val.string_val.data, val->val.string_val.length);
		break;

	case TYPE_TABLE:
	case TYPE_VECTOR:
		{
		bro_int_t size;
		Value** vals;

		std::string out("{");
		retlength = 1;

		if ( val->type == TYPE_TABLE )
			{
			size = val->val.set_val.size;
			vals = val->val.set_val.vals;
			}
		else
			{
			size = val->val.vector_val.size;
			vals = val->val.vector_val.vals;
			}

		if ( ! size )
			return std::make_tuple(false, std::string(), 0);

		for ( int i = 0; i < size; ++i )
			{
			if ( i != 0 )
				out += ", ";

			auto res = CreateParams(vals[i]);
			if ( std::get<0>(res) == false )
				{
				out += "NULL";
				continue;
				}

			std::string resstr = std::get<1>(res);
			TypeTag type = vals[i]->type;
			// for all numeric types, we do not need escaping
			if ( type == TYPE_BOOL || type == TYPE_INT || type == TYPE_COUNT ||
					type == TYPE_COUNTER || type == TYPE_PORT || type == TYPE_TIME ||
					type == TYPE_INTERVAL || type == TYPE_DOUBLE )
				out += resstr;
			else
				{
				std::string escaped = std::regex_replace(resstr, curly_re, "\\$&");
				out += "\"" + escaped + "\"";
				retlength += 2+escaped.length();
				}
			}

		out += "}";
		retlength += 1;
		retval = out;
		break;
		}

	default:
		Error(Fmt("unsupported field format %d", val->type ));
		return std::make_tuple(false, std::string(), 0);
	}

	if ( retlength == 0 )
		retlength = retval.length();

	return std::make_tuple(true, retval, retlength);
	}

bool PostgreSQL::DoWrite(int num_fields, const Field* const* fields, Value** vals)
	{
	std::vector<std::tuple<bool, std::string, int>> params; // vector in which we compile the string representation of characters

	for ( int i = 0; i < num_fields; ++i )
		params.push_back(CreateParams(vals[i]));

	std::vector<const char*> params_char; // vector in which we compile the character pointers that we
	// then pass to PQexecParams. These do not have to be cleaned up because the srings will be
	// cleaned up automatically.
	std::vector<int> params_length; // vector in which we compile the lengths of the parameters that we
	// then pass to PQexecParams

	for ( auto &i: params )
		{
		if ( std::get<0>(i) == false)
			params_char.push_back(nullptr); // null pointer is accepted to signify NULL in parameters
		else
			params_char.push_back(std::get<1>(i).c_str());

		params_length.push_back(std::get<2>(i));
		}

	assert( params_char.size() == num_fields );
	assert( params_length.size() == num_fields );

	// & of vector is legal - according to current STL standard, vector has to be saved in consecutive memory.
	PGresult *res = PQexecParams(conn,
			insert.c_str(),
			params_char.size(),
			NULL,
			&params_char[0],
			&params_length[0],
			NULL,
			0);

	if ( PQresultStatus(res) != PGRES_COMMAND_OK)
		{
		Error(Fmt("Command failed: %s\n", PQerrorMessage(conn)));

		if ( ! ignore_errors )
			{
			PQclear(res);
			return false;
			}
		}

	PQclear(res);
	return true;
	}

bool PostgreSQL::DoRotate(const char* rotated_path, double open, double close, bool terminating)
	{
	FinishedRotation();
	return true;
	}

bool PostgreSQL::DoSetBuf(bool enabled)
	{
	// Nothing to do.
	return true;
	}
