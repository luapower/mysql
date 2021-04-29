
## `local mysql = require'mysql_client'`

MySQL client protocol in Lua. Stolen from OpenResty and modified to work standalone.

## Status

This library is considered production ready.

## Example

```lua
local mysql = require'mysql_client'
local db = assert(mysql:new())

assert(db:connect{
	host = '127.0.0.1',
	port = 3306,
	database = 'ngx_test',
	user = 'ngx_test',
	password = 'ngx_test',
	charset = 'utf8',
	max_packet_size = 1024 * 1024,
})

assert(db:query('drop table if exists cats'))

local res = assert(db:query('create table cats '
			  .. '(id serial primary key, '
			  .. 'name varchar(5))'))

local res = assert(db:query('insert into cats (name) '
	.. 'values (\'Bob\'),(\'\'),(null)'))

print(res.affected_rows, ' rows inserted into table cats ',
		'(last insert id: ', res.insert_id, ')')

local res = assert(db:query('select * from cats order by id asc', 10))

local cjson = require'cjson'
print(cjson.encode(res))

assert(db:close())
```

## API

### `mysql:new() -> db | nil,err`

Creates a MySQL connection object.

### `db:connect(options) -> ok | nil,err,errcode,sqlstate`

Connect to a MySQL server.

The `options` argument is a Lua table holding the following keys:

  * `host`: the host name for the MySQL server.
  * `port`: the port that the MySQL server is listening on. Default to 3306.
  * `path`: the path of the unix socket file listened by the MySQL server.
  * `database`: the MySQL database name.
  * `user`: MySQL account name for login.
  * `password`: MySQL account password for login (in clear text).
  * `charset`: the character set used for the connection, which can be one of:
  `big5`, `dec8`, `cp850`, `hp8`, `koi8r`, `latin1`, `latin2`,
  `swe7`, `ascii`, `ujis`, `sjis`, `hebrew`, `tis620`, `euckr`, `koi8u`, `gb2312`, `greek`,
  `cp1250`, `gbk`, `latin5`, `armscii8`, `utf8`, `ucs2`, `cp866`, `keybcs2`, `macce`,
  `macroman`, `cp852`, `latin7`, `utf8mb4`, `cp1251`, `utf16`, `utf16le`, `cp1256`,
  `cp1257`, `utf32`, `binary`, `geostd8`, `cp932`, `eucjpms`, `gb18030`.
  * `max_packet_size`: the upper limit for the reply packets sent from the server (default to 1MB).
  * `ssl`: if `true`, then uses SSL to connect to MySQL (default to `false`).
  If the server does not have SSL support (or just disabled), the error string
  "ssl disabled on server" will be returned.
  * `ssl_verify`: if `true`, then verifies the validity of the server SSL certificate (default to `false`).
  * `compact_arrays`: `true` to use array-of-arrays structure for the result set,
  rather than the default array-of-hashes structure.

### `db:close() -> 1 | nil,err`

Closes the current mysql connection and returns the status.

### `db:send_query(query) -> bytes | nil,err`

Sends the query to the remote MySQL server without waiting for its replies.

Returns the bytes successfully sent out. Use `read_result()` to read the replies.

### `db:read_result([nrows]) -> res | nil,err,errcode,sqlstate`

Reads in one result returned from the server.

It returns a Lua table (`res`) describing the MySQL `OK packet`
or `result set packet` for the query result.

For queries corresponding to a result set, it returns an array holding all the rows.
Each row holds key-value pairs for each data fields. For instance,

```lua
    {
        { name = "Bob", age = 32, phone = ngx.null },
        { name = "Marry", age = 18, phone = "10666372"}
    }
```

For queries that do not correspond to a result set, it returns a Lua table like this:

```lua
    {
        insert_id = 0,
        server_status = 2,
        warning_count = 1,
        affected_rows = 32,
        message = nil
    }
```

If more results are following the current result, a second `err` return value
will be given the string `again`. One should always check this (second) return
value and if it is `again`, then she should call this method again to retrieve
more results. This usually happens when the original query contains multiple
statements (separated by semicolon in the same query string) or calling a
MySQL procedure. See also [Multi-Resultset Support](#multi-resultset-support).

In case of errors, this method returns at most 4 values: `nil`, `err`, `errcode`, and `sqlstate`.
The `err` return value contains a string describing the error, the `errcode`
return value holds the MySQL error code (a numerical value), and finally,
the `sqlstate` return value contains the standard SQL error code that consists
of 5 characters. Note that, the `errcode` and `sqlstate` might be `nil`
if MySQL does not return them.

The optional argument `nrows` can be used to specify an approximate number
of rows for the result set. This value can be used to pre-allocate space
in the resulting Lua table for the result set. By default, it takes the value 4.

### `db:query(query, [nrows]) -> res, err, errcode, sqlstate`

This is a shortcut for combining the [send_query](#send_query) call
and the first [read_result](#read_result) call.

You should always check if the `err` return value  is `again` in case of
success because this method will only call [read_result](#read_result)
only once for you. See also [Multi-Resultset Support](#multi-resultset-support).

### `db:server_ver() -> s`

Returns the MySQL server version string, like `"5.1.64"`.

You should only call this method after successfully connecting to a MySQL server,
otherwise `nil` will be returned.

### `db:set_compact_arrays(true|false)`

Sets whether to use the "compact-arrays" structure for the resultsets returned
by subsequent queries. See the `compact_arrays` option for the `connect`
method for more details.

### `mysql.quote(s) -> s`

Quote literal string to be used in queries.

### Multiple result set support

For a SQL query that produces multiple result-sets, it is always your duty to
check the 'again' error message returned by the query, and keep pulling more
result sets by calling the `read_result()` until no 'again' error message
returned (or some other errors happen).

## Limitations

### Authentication

By default, of all authentication methods, only
[Old Password Authentication(mysql_old_password)](https://dev.mysql.com/doc/internals/en/old-password-authentication.html)
and [Secure Password Authentication(mysql_native_password)](https://dev.mysql.com/doc/internals/en/secure-password-authentication.html)
are suppored.

## TODO

* implement the MySQL binary row data packets.
* implement MySQL server prepare and execute packets.
* implement the data compression support in the protocol.

