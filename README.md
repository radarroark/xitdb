xitdb is an immutable database written in Zig.

* Each transaction efficiently creates a new "copy" of the database, and past copies can still be read from.
* It supports writing to a file as well as purely in-memory use.
* No query engine of any kind. You just write data structures (primarily an `ArrayList` and `HashMap`) that can be nested arbitrarily.
* No dependencies besides the Zig standard library (requires version 0.15.1).
* There is also a [Java port](https://github.com/radarroark/xitdb-java) of this library.

This database was originally made for the [xit version control system](https://github.com/radarroark/xit), but I bet it has a lot of potential for other projects. The combination of being immutable and having an API similar to in-memory data structures is pretty powerful. Consider using it instead of SQLite for your Zig projects: it's simpler, it's pure Zig, and it creates no impedence mismatch with your program the way SQL databases do.

## Example

In this example, we create a new database, write some data in a transaction, and read the data afterwards.

```zig
// create db file
const file = try std.fs.cwd().createFile("main.db", .{ .read = true });
defer file.close();

// init the buffer (optional, but better for performance)
var buffer = std.Io.Writer.Allocating.init(allocator);
defer buffer.deinit();

// init the db
const DB = xitdb.Database(.buffered_file, HashInt);
var db = try DB.init(.{ .file = file, .buffer = &buffer });

// to get the benefits of immutability, the top-level data structure
// must be an ArrayList, so each transaction is stored as an item in it
const history = try DB.ArrayList(.read_write).init(db.rootCursor());

// this is how a transaction is executed. we call history.appendContext,
// providing it with the most recent copy of the db and a context
// object. the context object has a method that will run before the
// transaction has completed. this method is where we can write
// changes to the db. if any error happens in it, the transaction
// will not complete, the data added to the file will be truncated,
// and the db will be unaffected.
//
// after this transaction, the db will look like this if represented
// as JSON (in reality the format is binary):
//
// {"foo": "foo",
//  "bar": "bar",
//  "fruits": ["apple", "pear", "grape"],
//  "people": [
//    {"name": "Alice", "age": 25},
//    {"name": "Bob", "age": 42}
//  ]}
const Ctx = struct {
    pub fn run(_: @This(), cursor: *DB.Cursor(.read_write)) !void {
        const moment = try DB.HashMap(.read_write).init(cursor.*);

        try moment.put(hashInt("foo"), .{ .bytes = "foo" });
        try moment.put(hashInt("bar"), .{ .bytes = "bar" });

        const fruits_cursor = try moment.putCursor(hashInt("fruits"));
        const fruits = try DB.ArrayList(.read_write).init(fruits_cursor);
        try fruits.append(.{ .bytes = "apple" });
        try fruits.append(.{ .bytes = "pear" });
        try fruits.append(.{ .bytes = "grape" });

        const people_cursor = try moment.putCursor(hashInt("people"));
        const people = try DB.ArrayList(.read_write).init(people_cursor);

        const alice_cursor = try people.appendCursor();
        const alice = try DB.HashMap(.read_write).init(alice_cursor);
        try alice.put(hashInt("name"), .{ .bytes = "Alice" });
        try alice.put(hashInt("age"), .{ .uint = 25 });

        const bob_cursor = try people.appendCursor();
        const bob = try DB.HashMap(.read_write).init(bob_cursor);
        try bob.put(hashInt("name"), .{ .bytes = "Bob" });
        try bob.put(hashInt("age"), .{ .uint = 42 });
    }
};
try history.appendContext(.{ .slot = try history.getSlot(-1) }, Ctx{});

// get the most recent copy of the database, like a moment
// in time. the -1 index will return the last index in the list.
const moment_cursor = (try history.getCursor(-1)).?;
const moment = try DB.HashMap(.read_only).init(moment_cursor);

// we can read the value of "foo" from the map by getting
// the cursor to "foo" and then calling readBytesAlloc on it
const foo_cursor = (try moment.getCursor(hashInt("foo"))).?;
const foo_value = try foo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
defer allocator.free(foo_value);
try std.testing.expectEqualStrings("foo", foo_value);

// to get the "fruits" list, we get the cursor to it and
// then pass it to the ArrayList init method
const fruits_cursor = (try moment.getCursor(hashInt("fruits"))).?;
const fruits = try DB.ArrayList(.read_only).init(fruits_cursor);

// now we can get the first item from the fruits list and read it
const apple_cursor = (try fruits.getCursor(0)).?;
const apple_value = try apple_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
defer allocator.free(apple_value);
try std.testing.expectEqualStrings("apple", apple_value);
```

## Initializing a Database

There are three kinds of `Database` you can create: `.buffered_file`, `.file`, and `.memory`.

* `.buffered_file` databases, like in the example above, write to a file while using an in-memory buffer to dramatically improve performance. This is highly recommended if you want to create a file-based database.
* `.file` databases use no buffering when reading and writing data. You can initialize it like in the example above, except without providing a buffer. This is almost never necessary but it's useful as a benchmark comparison with `.buffered_file` databases.
* `.memory` databases work completely in memory. You can initialize it like in the example above, except without providing a file.

Usually, you want to use a top-level `ArrayList` like in the example above, because that allows you to store a reference to each copy of the database (which I call a "moment"). This is how it supports transactions, despite not having any rollback journal or write-ahead log. It's an append-only database, so the data you are writing is invisible to any reader until the very last step, when the top-level list's header is updated.

You can also use a top-level `HashMap`, which is useful for ephemeral databases where immutability or transaction safety isn't necessary. Since xitdb supports in-memory databases, you could use it as an over-the-wire serialization format. Much like "Cap'n Proto", xitdb has no encoding/decoding step: you just give the buffer to xitdb and it can immediately read from it.

## Types

In xitdb there are a variety of immutable data structures that you can nest arbitrarily:

* `HashMap` contains key-value pairs stored with a hash
* `HashSet` is like a `HashMap` that only sets the keys; it is useful when only checking for membership
* `CountedHashMap` and `CountedHashSet` are just a `HashMap` and `HashSet` that maintain a count of their contents
* `ArrayList` is a growable array
* `LinkedArrayList` is like an `ArrayList` that can also be efficiently sliced and concatenated

All data structures use the hash array mapped trie, invented by Phil Bagwell. The `LinkedArrayList` is based on his later work on RRB trees. These data structures were originally made immutable and widely available by Rich Hickey in Clojure. To my knowledge, they haven't been available in any open source database until xitdb.

There are also scalar types you can store in the above-mentioned data structures:

* `.bytes` is a byte array
* `.uint` is an unsigned 64-bit int
* `.int` is a signed 64-bit int
* `.float` is a 64-bit float

You may also want to define custom types. For example, you may want to store a big integer that can't fit in 64 bits. You could just store this with `.bytes`, but when reading the byte array there wouldn't be any indication that it should be interpreted as a big integer.

In xitdb, you can optionally store a format tag with a byte array. A format tag is a 2 byte tag that is stored alongside the byte array. Readers can use it to decide how to interpret the byte array. Here's an example of storing a random 256-bit number with `bi` as the format tag:

```zig
var random_number_buffer: [32]u8 = undefined;
std.mem.writeInt(u256, &random_number_buffer, std.crypto.random.int(u256), .big);
try moment.put(hashInt("random-number"), .{ .bytes_object = .{ .value = &random_number_buffer, .format_tag = "bi".* } });
```

Then, you can read it like this:

```zig
const random_number_cursor = (try moment.getCursor(hashInt("random-number"))).?;
var random_number_buffer: [32]u8 = undefined;
const random_number = try random_number_cursor.readBytesObject(&random_number_buffer);
try std.testing.expectEqualStrings("bi", &random_number.format_tag.?);
const random_number_int = std.mem.readInt(u256, &random_number_buffer, .big);
```

There are many types you may want to store this way. Maybe an ISO-8601 date like `2026-01-01T18:55:48Z` could be stored with `dt` as the format tag. It's also great for storing custom structs. Just define the struct, serialize it as a byte array using whatever mechanism you wish, and store it with a format tag. Keep in mind that format tags can be *any* 2 bytes, so there are 65536 possible format tags.

## Thread Safety

It is possible to read a database from multiple threads without locks, even while writes are happening. This is a big benefit of immutable databases. However, each thread needs to use its own `Database` instance. Also, keep in mind that writes still need to come from one thread at a time.
