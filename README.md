xitdb is an embedded, immutable database written in Zig.

* Each transaction efficiently creates a new "copy" of the database, and past copies can still be read from.
* It supports writing to a file as well as purely in-memory use.
* No query engine of any kind. You just write data structures (primarily an `ArrayList` and `HashMap`) that can be nested arbitrarily.
* No dependencies besides the Zig standard library.

What is this for? I don't know, really. Help me figure that out. In theory it can work in the same use cases as SQLite, I suppose. The high-level API below will probably change a lot. There is a lower-level API that I'm not even going to mention here; see the tests if you're curious.

```zig
// create db file
const file = try std.fs.cwd().createFile("main.db", .{ .exclusive = true, .lock = .exclusive, .read = true });
defer file.close();

// init the db
const DB = xitdb.Database(.file, Hash);
var db = try DB.init(allocator, .{ .file = file });

// the top-level data structure *must* be an ArrayList,
// because each transaction is stored as an item in this list
const list = try DB.ArrayList.init(db.rootCursor());

// this is how a transaction is executed. we call list.appendCopy,
// which grabs the most recent copy of the db and appends it to the list.
// then, in the context below, we interpret it as a HashMap
// and add a bunch of data to it. after this transaction, the db will
// look like this if represented as JSON (in reality the format is binary):
//
// {"foo": "foo",
//  "bar": "bar",
//  "fruits": ["apple", "pear", "grape"],
//  "people:" [
//    {"name": "Alice", "age": 25},
//    {"name": "Bob", "age": 42},
//  ]}
const Ctx = struct {
    pub fn run(_: @This(), cursor: *DB.Cursor) !void {
        const map = try DB.HashMap.init(cursor.*);

        try map.putValue(hashBuffer("foo"), .{ .bytes = "foo" });
        try map.putValue(hashBuffer("bar"), .{ .bytes = "bar" });
        try map.remove(hashBuffer("bar"));

        const fruits_cursor = try map.put(hashBuffer("fruits"));
        const fruits = try DB.ArrayList.init(fruits_cursor);
        try fruits.appendValue(.{ .bytes = "apple" });
        try fruits.appendValue(.{ .bytes = "pear" });
        try fruits.appendValue(.{ .bytes = "grape" });

        const people_cursor = try map.put(hashBuffer("people"));
        const people = try DB.ArrayList.init(people_cursor);

        const alice_cursor = try people.append();
        const alice = try DB.HashMap.init(alice_cursor);
        try alice.putValue(hashBuffer("name"), .{ .bytes = "Alice" });
        try alice.putValue(hashBuffer("age"), .{ .uint = 25 });

        const bob_cursor = try people.append();
        const bob = try DB.HashMap.init(bob_cursor);
        try bob.putValue(hashBuffer("name"), .{ .bytes = "Bob" });
        try bob.putValue(hashBuffer("age"), .{ .uint = 42 });
    }
};
try list.appendCopy(Ctx, Ctx{});

// get the most recent copy of the database.
// the -1 index will return the last index in the list.
const map_cursor = (try list.get(-1)).?;
const map = try DB.HashMap.init(map_cursor);

// we can read the value of "foo" from the map by getting
// the cursor to "foo" and then calling readBytesAlloc on it
const foo_cursor = (try map.get(hashBuffer("foo"))).?;
const foo_value = try foo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
defer allocator.free(foo_value);
try std.testing.expectEqualStrings("foo", foo_value);

// to get the "fruits" list, we get the cursor to it and
// then call pass it to the ArrayList.init method
const fruits_cursor = (try map.get(hashBuffer("fruits"))).?;
const fruits = try DB.ArrayList.init(fruits_cursor);

// now we can get the first item from the fruits list and read it
const apple_cursor = (try fruits.get(0)).?;
const apple_value = try apple_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
defer allocator.free(apple_value);
try std.testing.expectEqualStrings("apple", apple_value);
```
