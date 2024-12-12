xitdb is an embedded, immutable database written in Zig.

* Each transaction efficiently creates a new "copy" of the database, and past copies can still be read from.
* It supports writing to a file as well as purely in-memory use.
* No query engine of any kind. You just write data structures (primarily an `ArrayList` and `HashMap`) that can be nested arbitrarily.
* No dependencies besides the Zig standard library.

What is this for? I don't know, really. Help me figure that out. In theory it can work in the same use cases as SQLite, I suppose. The high-level API below will probably change a lot. There is a lower-level API that I'm not even going to mention here; see the tests if you're curious.

```zig
// create db file
const file = try std.fs.cwd().createFile("main.db", .{ .read = true });
defer file.close();

// init the db
const DB = xitdb.Database(.file, HashInt);
var db = try DB.init(allocator, .{ .file = file });

// to get the benefits of immutability, the top-level data structure
// must be an ArrayList, so each transaction is stored as an item in it
const history = try DB.ArrayList(.read_write).init(db.rootCursor());

// this is how a transaction is executed. we call history.appendContext,
// providing it with the most recent copy of the db and a context
// object. the context object has a method that will run before the
// transaction has completed. this method is where we can write
// changes to the db. if any error happens in it, the transaction
// will not complete and the db will be unaffected.
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
