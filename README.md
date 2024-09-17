xitdb is an embedded, immutable database written in Zig.

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
// look like this:
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

        try map.put(hashBuffer("foo"), .{ .bytes = "foo" });
        try map.put(hashBuffer("bar"), .{ .bytes = "bar" });

        const fruits_cursor = try map.putCursor(hashBuffer("fruits"));
        const fruits = try DB.ArrayList.init(fruits_cursor);
        try fruits.append(.{ .bytes = "apple" });
        try fruits.append(.{ .bytes = "pear" });
        try fruits.append(.{ .bytes = "grape" });

        const people_cursor = try map.putCursor(hashBuffer("people"));
        const people = try DB.ArrayList.init(people_cursor);

        const alice_cursor = try people.appendCursor();
        const alice = try DB.HashMap.init(alice_cursor);
        try alice.put(hashBuffer("name"), .{ .bytes = "Alice" });
        try alice.put(hashBuffer("age"), .{ .uint = 25 });

        const bob_cursor = try people.appendCursor();
        const bob = try DB.HashMap.init(bob_cursor);
        try bob.put(hashBuffer("name"), .{ .bytes = "Bob" });
        try bob.put(hashBuffer("age"), .{ .uint = 42 });
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
const value = try foo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
defer allocator.free(value);
try std.testing.expectEqualStrings("foo", value);

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
