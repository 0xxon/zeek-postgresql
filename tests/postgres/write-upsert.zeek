# @TEST-SERIALIZE: postgres
# @TEST-EXEC: initdb postgres
# @TEST-EXEC: perl -pi.bak -E "s/#port =.*/port = 7772/;" postgres/postgresql.conf
# @TEST-EXEC: pg_ctl start -D postgres -l serverlog
# @TEST-EXEC: sleep 5
# @TEST-EXEC: createdb -p 7772 testdb
# @TEST-EXEC: psql -p 7772 testdb < create.sql
# @TEST-EXEC: zeek %INPUT || true
# @TEST-EXEC: echo "select * from testtable" | psql -A -p 7772 testdb >ssh.out 2>&1 || true
# @TEST-EXEC: pg_ctl stop -D postgres -m fast
# @TEST-EXEC: btest-diff ssh.out

@TEST-START-FILE create.sql
create table testtable (
i integer not null unique,
s varchar not null unique);
@TEST-END-FILE

# Test all possible types.

module SSHTest;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		i: int;
		s: string;
	} &log;
}

function foo(i : count) : string
	{
	if ( i > 0 )
		return "Foo";
	else
		return "Bar";
	}

event zeek_init()
{
	Log::create_stream(SSHTest::LOG, [$columns=Log]);
	local filter: Log::Filter = [$name="postgres", $path="testtable", $writer=Log::WRITER_POSTGRESQL, $config=table(["dbname"]="testdb", ["port"]="7772", ["sql_addition"]="ON CONFLICT (i) DO UPDATE SET s=EXCLUDED.s")];
	Log::add_filter(SSHTest::LOG, filter);

	local empty_set: set[string];
	local empty_vector: vector of string;

	Log::write(SSHTest::LOG, [
		$i=-42,
		$s="hurz"
		]);

	Log::write(SSHTest::LOG, [
		$i=-42,
		$s="hurz2"
		]);
}

