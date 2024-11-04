const std = @import("std");
const xitdb = @import("./lib.zig");

const Hash = u160;
const MAX_READ_BYTES = 1024;

test "high level api" {
    const allocator = std.testing.allocator;

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try testHighLevelApi(allocator, .memory, .{ .buffer = &buffer, .max_size = 50000, .allow_truncation = true });

    if (std.fs.cwd().openFile("main.db", .{})) |file| {
        file.close();
        try std.fs.cwd().deleteFile("main.db");
    } else |_| {}

    const file = try std.fs.cwd().createFile("main.db", .{ .read = true });
    defer {
        file.close();
        std.fs.cwd().deleteFile("main.db") catch {};
    }
    try testHighLevelApi(allocator, .file, .{ .file = file });
}

test "low level api" {
    const allocator = std.testing.allocator;

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try testLowLevelApi(allocator, .memory, .{ .buffer = &buffer, .max_size = 50000 });

    if (std.fs.cwd().openFile("main.db", .{})) |file| {
        file.close();
        try std.fs.cwd().deleteFile("main.db");
    } else |_| {}

    const file = try std.fs.cwd().createFile("main.db", .{ .read = true });
    defer {
        file.close();
        std.fs.cwd().deleteFile("main.db") catch {};
    }
    try testLowLevelApi(allocator, .file, .{ .file = file });
}

test "not using arraylist at the top level" {
    // normally an arraylist makes the most sense at the top level,
    // but this test just ensures we can use other data structures
    // at the top level. in theory a top-level hash map might make
    // sense if we're using xitdb as a format to send data over a
    // network. in that case, immutability isn't important because
    // the data is just created and immediately sent over the wire.

    const allocator = std.testing.allocator;

    // hash map
    {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        const DB = xitdb.Database(.memory, Hash);
        var db = try DB.init(allocator, .{ .buffer = &buffer, .max_size = 50000 });

        const map = try DB.HashMap(.read_write).init(db.rootCursor());
        try map.put(hashBuffer("foo"), .{ .bytes = "foo" });
        try map.put(hashBuffer("bar"), .{ .bytes = "bar" });
    }

    // linked array list
    {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        const DB = xitdb.Database(.memory, Hash);
        var db = try DB.init(allocator, .{ .buffer = &buffer, .max_size = 50000 });

        const list = try DB.LinkedArrayList(.read_write).init(db.rootCursor());
        try list.append(.{ .bytes = "foo" });
        try list.append(.{ .bytes = "bar" });
    }
}

test "low level memory operations" {
    const allocator = std.testing.allocator;

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    var db = try xitdb.Database(.memory, Hash).init(allocator, .{ .buffer = &buffer, .max_size = 10000 });

    var writer = db.core.writer();
    try db.core.seekTo(0);
    try writer.writeAll("Hello");
    try std.testing.expectEqualStrings("Hello", db.core.buffer.items[0..5]);
    try writer.writeInt(u64, 42, .little);
    const hello = try std.fmt.allocPrint(allocator, "Hello{s}", .{std.mem.asBytes(&std.mem.nativeTo(u64, 42, .little))});
    defer allocator.free(hello);
    try std.testing.expectEqualStrings(hello, db.core.buffer.items[0..13]);

    var reader = db.core.reader();
    try db.core.seekTo(0);
    var block = [_]u8{0} ** 5;
    try reader.readNoEof(&block);
    try std.testing.expectEqualStrings("Hello", &block);
    try std.testing.expectEqual(42, reader.readInt(u64, .little));
}

test "validate tag" {
    const Slot = packed struct {
        value: u64,
        tag: u7,
        flag: u1,
    };
    const invalid: xitdb.Slot = @bitCast(Slot{ .value = 0, .tag = 127, .flag = 0 });
    try std.testing.expectEqual(error.InvalidEnumTag, invalid.tag.validate());
}

fn hashBuffer(buffer: []const u8) Hash {
    var hash = [_]u8{0} ** (@bitSizeOf(Hash) / 8);
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(buffer);
    h.final(&hash);
    return std.mem.bytesToValue(Hash, &hash);
}

fn testHighLevelApi(allocator: std.mem.Allocator, comptime db_kind: xitdb.DatabaseKind, init_opts: xitdb.Database(db_kind, Hash).InitOpts) !void {
    // init the db
    const DB = xitdb.Database(db_kind, Hash);
    var db = try DB.init(allocator, init_opts);

    {
        // to get the benefits of immutability, the top-level data structure
        // must be an ArrayList, so each transaction is stored as an item in it
        const history = try DB.ArrayList(.read_write).init(db.rootCursor());

        // this is how a transaction is executed. we call history.appendContext,
        // providing it with the most recent copy of the db and a context
        // object. the context object has a method that will run before the
        // transaction has completed. this method is where we can write
        // changes to the db. if any error happens in it, the transaction
        // will not complete and the db will be unaffected.
        const Ctx = struct {
            pub fn run(_: @This(), cursor: *DB.Cursor(.read_write)) !void {
                const moment = try DB.HashMap(.read_write).init(cursor.*);

                try moment.put(hashBuffer("foo"), .{ .bytes = "foo" });
                try moment.put(hashBuffer("bar"), .{ .bytes = "bar" });

                const fruits_cursor = try moment.putCursor(hashBuffer("fruits"));
                const fruits = try DB.ArrayList(.read_write).init(fruits_cursor);
                try fruits.append(.{ .bytes = "apple" });
                try fruits.append(.{ .bytes = "pear" });
                try fruits.append(.{ .bytes = "grape" });

                const people_cursor = try moment.putCursor(hashBuffer("people"));
                const people = try DB.ArrayList(.read_write).init(people_cursor);

                const alice_cursor = try people.appendCursor();
                const alice = try DB.HashMap(.read_write).init(alice_cursor);
                try alice.put(hashBuffer("name"), .{ .bytes = "Alice" });
                try alice.put(hashBuffer("age"), .{ .uint = 25 });

                const bob_cursor = try people.appendCursor();
                const bob = try DB.HashMap(.read_write).init(bob_cursor);
                try bob.put(hashBuffer("name"), .{ .bytes = "Bob" });
                try bob.put(hashBuffer("age"), .{ .uint = 42 });

                const todos_cursor = try moment.putCursor(hashBuffer("todos"));
                const todos = try DB.LinkedArrayList(.read_write).init(todos_cursor);
                try todos.append(.{ .bytes = "Pay the bills" });
                try todos.append(.{ .bytes = "Get an oil change" });
            }
        };
        try history.appendContext(.{ .slot = try history.getSlot(-1) }, Ctx{});

        // get the most recent copy of the database, like a moment
        // in time. the -1 index will return the last index in the list.
        const moment_cursor = (try history.getCursor(-1)).?;
        const moment = try DB.HashMap(.read_only).init(moment_cursor);

        // we can read the value of "foo" from the map by getting
        // the cursor to "foo" and then calling readBytesAlloc on it
        const foo_cursor = (try moment.getCursor(hashBuffer("foo"))).?;
        const foo_value = try foo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(foo_value);
        try std.testing.expectEqualStrings("foo", foo_value);

        try std.testing.expectEqual(.short_bytes, (try moment.getSlot(hashBuffer("foo"))).?.tag);
        try std.testing.expectEqual(.short_bytes, (try moment.getSlot(hashBuffer("bar"))).?.tag);

        // to get the "fruits" list, we get the cursor to it and
        // then pass it to the ArrayList.init method
        const fruits_cursor = (try moment.getCursor(hashBuffer("fruits"))).?;
        const fruits = try DB.ArrayList(.read_only).init(fruits_cursor);
        try std.testing.expectEqual(3, try fruits.count());

        // now we can get the first item from the fruits list and read it
        const apple_cursor = (try fruits.getCursor(0)).?;
        const apple_value = try apple_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(apple_value);
        try std.testing.expectEqualStrings("apple", apple_value);

        const people_cursor = (try moment.getCursor(hashBuffer("people"))).?;
        const people = try DB.ArrayList(.read_only).init(people_cursor);
        try std.testing.expectEqual(2, try people.count());

        const alice_cursor = (try people.getCursor(0)).?;
        const alice = try DB.HashMap(.read_only).init(alice_cursor);
        const alice_age_cursor = (try alice.getCursor(hashBuffer("age"))).?;
        try std.testing.expectEqual(25, try alice_age_cursor.readUint());

        const todos_cursor = (try moment.getCursor(hashBuffer("todos"))).?;
        const todos = try DB.LinkedArrayList(.read_only).init(todos_cursor);
        try std.testing.expectEqual(2, try todos.count());

        const todo_cursor = (try todos.getCursor(0)).?;
        const todo_value = try todo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(todo_value);
        try std.testing.expectEqualStrings("Pay the bills", todo_value);

        var people_iter = try people.iterator();
        defer people_iter.deinit();
        while (try people_iter.next()) |person_cursor| {
            const person = try DB.HashMap(.read_only).init(person_cursor);
            var person_iter = try person.iterator();
            defer person_iter.deinit();
            while (try person_iter.next()) |kv_pair_cursor| {
                _ = try kv_pair_cursor.readKeyValuePair();
            }
        }
    }

    // make a new transaction and change the data
    {
        const history = try DB.ArrayList(.read_write).init(db.rootCursor());

        const Ctx = struct {
            pub fn run(_: @This(), cursor: *DB.Cursor(.read_write)) !void {
                const moment = try DB.HashMap(.read_write).init(cursor.*);

                try std.testing.expect(try moment.remove(hashBuffer("bar")));
                try std.testing.expect(!try moment.remove(hashBuffer("doesn't exist")));

                // this associates the hash of "fruits" with the actual string.
                // hash maps use hashes directly as keys so they are not able
                // to get the original bytes of the key unless we store it
                // explicitly this way.
                try moment.putKey(hashBuffer("fruits"), .{ .bytes = "fruits" });

                const fruits_cursor = try moment.putCursor(hashBuffer("fruits"));
                const fruits = try DB.ArrayList(.read_write).init(fruits_cursor);
                try fruits.put(0, .{ .bytes = "lemon" });
                try fruits.slice(2);

                const people_cursor = try moment.putCursor(hashBuffer("people"));
                const people = try DB.ArrayList(.read_write).init(people_cursor);

                const alice_cursor = try people.putCursor(0);
                const alice = try DB.HashMap(.read_write).init(alice_cursor);
                try alice.put(hashBuffer("age"), .{ .uint = 26 });

                const todos_cursor = try moment.putCursor(hashBuffer("todos"));
                const todos = try DB.LinkedArrayList(.read_write).init(todos_cursor);
                try todos.concat(todos_cursor.slot());
                try todos.slice(1, 1);
            }
        };
        try history.appendContext(.{ .slot = try history.getSlot(-1) }, Ctx{});

        const moment_cursor = (try history.getCursor(-1)).?;
        const moment = try DB.HashMap(.read_only).init(moment_cursor);

        try std.testing.expectEqual(null, try moment.getCursor(hashBuffer("bar")));

        const fruits_key_cursor = (try moment.getKeyCursor(hashBuffer("fruits"))).?;
        const fruits_key_value = try fruits_key_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(fruits_key_value);
        try std.testing.expectEqualStrings("fruits", fruits_key_value);

        const fruits_cursor = (try moment.getCursor(hashBuffer("fruits"))).?;
        const fruits = try DB.ArrayList(.read_only).init(fruits_cursor);
        try std.testing.expectEqual(2, try fruits.count());

        const lemon_cursor = (try fruits.getCursor(0)).?;
        const lemon_value = try lemon_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(lemon_value);
        try std.testing.expectEqualStrings("lemon", lemon_value);

        const people_cursor = (try moment.getCursor(hashBuffer("people"))).?;
        const people = try DB.ArrayList(.read_only).init(people_cursor);
        try std.testing.expectEqual(2, try people.count());

        const alice_cursor = (try people.getCursor(0)).?;
        const alice = try DB.HashMap(.read_only).init(alice_cursor);
        const alice_age_cursor = (try alice.getCursor(hashBuffer("age"))).?;
        try std.testing.expectEqual(26, try alice_age_cursor.readUint());

        const todos_cursor = (try moment.getCursor(hashBuffer("todos"))).?;
        const todos = try DB.LinkedArrayList(.read_only).init(todos_cursor);
        try std.testing.expectEqual(1, try todos.count());

        const todo_cursor = (try todos.getCursor(0)).?;
        const todo_value = try todo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(todo_value);
        try std.testing.expectEqualStrings("Get an oil change", todo_value);
    }

    // the old data hasn't changed
    {
        const history = try DB.ArrayList(.read_write).init(db.rootCursor());

        const moment_cursor = (try history.getCursor(0)).?;
        const moment = try DB.HashMap(.read_only).init(moment_cursor);

        const foo_cursor = (try moment.getCursor(hashBuffer("foo"))).?;
        const foo_value = try foo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(foo_value);
        try std.testing.expectEqualStrings("foo", foo_value);

        try std.testing.expectEqual(.short_bytes, (try moment.getSlot(hashBuffer("foo"))).?.tag);
        try std.testing.expectEqual(.short_bytes, (try moment.getSlot(hashBuffer("bar"))).?.tag);

        const fruits_cursor = (try moment.getCursor(hashBuffer("fruits"))).?;
        const fruits = try DB.ArrayList(.read_only).init(fruits_cursor);
        try std.testing.expectEqual(3, try fruits.count());

        const apple_cursor = (try fruits.getCursor(0)).?;
        const apple_value = try apple_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(apple_value);
        try std.testing.expectEqualStrings("apple", apple_value);

        const people_cursor = (try moment.getCursor(hashBuffer("people"))).?;
        const people = try DB.ArrayList(.read_only).init(people_cursor);
        try std.testing.expectEqual(2, try people.count());

        const alice_cursor = (try people.getCursor(0)).?;
        const alice = try DB.HashMap(.read_only).init(alice_cursor);
        const alice_age_cursor = (try alice.getCursor(hashBuffer("age"))).?;
        try std.testing.expectEqual(25, try alice_age_cursor.readUint());

        const todos_cursor = (try moment.getCursor(hashBuffer("todos"))).?;
        const todos = try DB.LinkedArrayList(.read_only).init(todos_cursor);
        try std.testing.expectEqual(2, try todos.count());

        const todo_cursor = (try todos.getCursor(0)).?;
        const todo_value = try todo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(todo_value);
        try std.testing.expectEqualStrings("Pay the bills", todo_value);
    }

    // the db size is reduced after slicing the top level arraylist
    {
        const history = try DB.ArrayList(.read_write).init(db.rootCursor());

        try db.core.seekFromEnd(0);
        const size_before = try db.core.getPos();

        // truncate the last transaction
        try history.slice(1);

        try db.core.seekFromEnd(0);
        const size_after = try db.core.getPos();

        // the size of the file/buffer has shrunk
        // because slicing the top-level array list
        // causes the file/buffer to be truncated
        try std.testing.expect(size_after < size_before);
    }

    // the last transaction is now the first one
    {
        const history = try DB.ArrayList(.read_write).init(db.rootCursor());

        const moment_cursor = (try history.getCursor(-1)).?;
        const moment = try DB.HashMap(.read_only).init(moment_cursor);

        const foo_cursor = (try moment.getCursor(hashBuffer("foo"))).?;
        const foo_value = try foo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(foo_value);
        try std.testing.expectEqualStrings("foo", foo_value);

        try std.testing.expectEqual(.short_bytes, (try moment.getSlot(hashBuffer("foo"))).?.tag);
        try std.testing.expectEqual(.short_bytes, (try moment.getSlot(hashBuffer("bar"))).?.tag);

        const fruits_cursor = (try moment.getCursor(hashBuffer("fruits"))).?;
        const fruits = try DB.ArrayList(.read_only).init(fruits_cursor);
        try std.testing.expectEqual(3, try fruits.count());

        const apple_cursor = (try fruits.getCursor(0)).?;
        const apple_value = try apple_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(apple_value);
        try std.testing.expectEqualStrings("apple", apple_value);

        const people_cursor = (try moment.getCursor(hashBuffer("people"))).?;
        const people = try DB.ArrayList(.read_only).init(people_cursor);
        try std.testing.expectEqual(2, try people.count());

        const alice_cursor = (try people.getCursor(0)).?;
        const alice = try DB.HashMap(.read_only).init(alice_cursor);
        const alice_age_cursor = (try alice.getCursor(hashBuffer("age"))).?;
        try std.testing.expectEqual(25, try alice_age_cursor.readUint());

        const todos_cursor = (try moment.getCursor(hashBuffer("todos"))).?;
        const todos = try DB.LinkedArrayList(.read_only).init(todos_cursor);
        try std.testing.expectEqual(2, try todos.count());

        const todo_cursor = (try todos.getCursor(0)).?;
        const todo_value = try todo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(todo_value);
        try std.testing.expectEqualStrings("Pay the bills", todo_value);
    }

    // the db size remains the same after writing junk data
    // and then reinitializing the db. this is useful because
    // there could be data from a transaction that never
    // completed due to an unclean shutdown.
    {
        try db.core.seekFromEnd(0);
        const size_before = try db.core.getPos();

        const writer = db.core.writer();
        try writer.writeAll("this is junk data that will be deleted during init");

        // no error is thrown if db file is opened in read-only mode
        if (db_kind == .file) {
            const file = try std.fs.cwd().openFile("main.db", .{ .mode = .read_only });
            defer file.close();
            _ = try DB.init(allocator, .{ .file = file });
        }

        db = try DB.init(allocator, init_opts);

        try db.core.seekFromEnd(0);
        const size_after = try db.core.getPos();

        try std.testing.expectEqual(size_before, size_after);
    }
}

fn clearStorage(comptime db_kind: xitdb.DatabaseKind, init_opts: xitdb.Database(db_kind, Hash).InitOpts) !void {
    switch (db_kind) {
        .file => {
            try init_opts.file.setEndPos(0);
        },
        .memory => {
            init_opts.buffer.clearAndFree();
        },
    }
}

fn testSlice(allocator: std.mem.Allocator, comptime db_kind: xitdb.DatabaseKind, init_opts: xitdb.Database(db_kind, Hash).InitOpts, comptime original_size: usize, comptime slice_offset: u64, comptime slice_size: u64) !void {
    try clearStorage(db_kind, init_opts);
    var db = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);
    var root_cursor = db.rootCursor();

    const Ctx = struct {
        allocator: std.mem.Allocator,

        pub fn run(self: @This(), cursor: *xitdb.Database(db_kind, Hash).Cursor(.read_write)) !void {
            var values = std.ArrayList(u64).init(self.allocator);
            defer values.deinit();

            // create list
            for (0..original_size) |i| {
                const n = i * 2;
                try values.append(n);
                _ = try cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("even") } },
                    .linked_array_list_init,
                    .linked_array_list_append,
                    .{ .write = .{ .uint = n } },
                });
            }

            // slice list
            const even_list_cursor = (try cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even") } },
            })).?;
            var even_list_slice_cursor = try cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even-slice") } },
                .{ .write = .{ .slot = even_list_cursor.slot_ptr.slot } },
                .linked_array_list_init,
                .{ .linked_array_list_slice = .{ .offset = slice_offset, .size = slice_size } },
            });

            // check all values in the new slice
            for (values.items[slice_offset .. slice_offset + slice_size], 0..) |val, i| {
                const n = (try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("even-slice") } },
                    .{ .linked_array_list_get = i },
                })).?.slot_ptr.slot.value;
                try std.testing.expectEqual(val, n);
            }

            // check all values in the new slice with an iterator
            {
                var iter = try even_list_slice_cursor.iterator();
                defer iter.deinit();
                var i: u64 = 0;
                while (try iter.next()) |num_cursor| {
                    try std.testing.expectEqual(values.items[slice_offset + i], try num_cursor.readUint());
                    i += 1;
                }
                try std.testing.expectEqual(slice_size, i);
            }

            // there are no extra items
            try std.testing.expectEqual(null, try cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even-slice") } },
                .{ .linked_array_list_get = slice_size },
            }));

            // concat the slice with itself
            _ = try cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                .{ .write = .{ .slot = even_list_slice_cursor.slot_ptr.slot } },
                .linked_array_list_init,
                .{ .linked_array_list_concat = .{ .list = even_list_slice_cursor.slot_ptr.slot } },
            });

            // check all values in the combo list
            var combo_values = std.ArrayList(u64).init(self.allocator);
            defer combo_values.deinit();
            try combo_values.appendSlice(values.items[slice_offset .. slice_offset + slice_size]);
            try combo_values.appendSlice(values.items[slice_offset .. slice_offset + slice_size]);
            for (combo_values.items, 0..) |val, i| {
                const n = (try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                    .{ .linked_array_list_get = i },
                })).?.slot_ptr.slot.value;
                try std.testing.expectEqual(val, n);
            }

            // append to the slice
            _ = try cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even-slice") } },
                .linked_array_list_init,
                .linked_array_list_append,
                .{ .write = .{ .uint = 3 } },
            });

            // read the new value from the slice
            try std.testing.expectEqual(3, (try cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even-slice") } },
                .{ .linked_array_list_get = -1 },
            })).?.slot_ptr.slot.value);
        }
    };
    _ = try root_cursor.writePath(Ctx, &.{
        .array_list_init,
        .array_list_append,
        .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
        .hash_map_init,
        .{ .ctx = .{ .allocator = allocator } },
    });
}

fn testConcat(allocator: std.mem.Allocator, comptime db_kind: xitdb.DatabaseKind, init_opts: xitdb.Database(db_kind, Hash).InitOpts, comptime list_a_size: usize, comptime list_b_size: usize) !void {
    try clearStorage(db_kind, init_opts);
    var db = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);
    var root_cursor = db.rootCursor();

    var values = std.ArrayList(u64).init(allocator);
    defer values.deinit();

    {
        const Ctx = struct {
            allocator: std.mem.Allocator,
            values: *std.ArrayList(u64),

            pub fn run(self: @This(), cursor: *xitdb.Database(db_kind, Hash).Cursor(.read_write)) !void {
                // create even list
                _ = try cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("even") } },
                    .linked_array_list_init,
                });
                for (0..list_a_size) |i| {
                    const n = i * 2;
                    try self.values.append(n);
                    _ = try cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hashBuffer("even") } },
                        .linked_array_list_init,
                        .linked_array_list_append,
                        .{ .write = .{ .uint = n } },
                    });
                }

                // create odd list
                _ = try cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("odd") } },
                    .linked_array_list_init,
                });
                for (0..list_b_size) |i| {
                    const n = (i * 2) + 1;
                    try self.values.append(n);
                    _ = try cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hashBuffer("odd") } },
                        .linked_array_list_init,
                        .linked_array_list_append,
                        .{ .write = .{ .uint = n } },
                    });
                }
            }
        };
        _ = try root_cursor.writePath(Ctx, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .ctx = .{ .allocator = allocator, .values = &values } },
        });
    }

    {
        const Ctx = struct {
            allocator: std.mem.Allocator,
            values: *std.ArrayList(u64),

            pub fn run(self: @This(), cursor: *xitdb.Database(db_kind, Hash).Cursor(.read_write)) !void {
                // get even list
                const even_list_cursor = (try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("even") } },
                })).?;

                // get odd list
                const odd_list_cursor = (try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("odd") } },
                })).?;

                // concat the lists
                const combo_list_cursor = try cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                    .{ .write = .{ .slot = even_list_cursor.slot_ptr.slot } },
                    .linked_array_list_init,
                    .{ .linked_array_list_concat = .{ .list = odd_list_cursor.slot_ptr.slot } },
                });

                // check all values in the new list
                for (self.values.items, 0..) |val, i| {
                    const n = (try cursor.readPath(void, &.{
                        .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                        .{ .linked_array_list_get = i },
                    })).?.slot_ptr.slot.value;
                    try std.testing.expectEqual(val, n);
                }

                // check all values in the new list with an iterator
                {
                    var iter = try combo_list_cursor.iterator();
                    defer iter.deinit();
                    var i: u64 = 0;
                    while (try iter.next()) |num_cursor| {
                        try std.testing.expectEqual(self.values.items[i], try num_cursor.readUint());
                        i += 1;
                    }
                    try std.testing.expectEqual(try even_list_cursor.count() + try odd_list_cursor.count(), i);
                }

                // there are no extra items
                try std.testing.expectEqual(null, try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                    .{ .linked_array_list_get = self.values.items.len },
                }));
            }
        };
        _ = try root_cursor.writePath(Ctx, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .ctx = .{ .allocator = allocator, .values = &values } },
        });
    }
}

fn testLowLevelApi(allocator: std.mem.Allocator, comptime db_kind: xitdb.DatabaseKind, init_opts: xitdb.Database(db_kind, Hash).InitOpts) !void {
    // open and re-open empty database
    {
        // make empty database
        try clearStorage(db_kind, init_opts);
        _ = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);

        // re-open without error
        var db = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);
        const writer = db.core.writer();

        // modify the magic number
        try db.core.seekTo(0);
        try writer.writeInt(u8, 'g', .big);

        // re-open with error
        {
            const db_or_error = xitdb.Database(db_kind, Hash).init(allocator, init_opts);
            if (db_or_error) |_| {
                return error.ExpectedInvalidDatabaseError;
            } else |err| {
                try std.testing.expectEqual(error.InvalidDatabase, err);
            }
        }

        // modify the version
        try db.core.seekTo(0);
        try writer.writeInt(u8, 'x', .big);
        try db.core.seekTo(4);
        try writer.writeInt(u16, xitdb.VERSION + 1, .big);

        // re-open with error
        {
            const db_or_error = xitdb.Database(db_kind, Hash).init(allocator, init_opts);
            if (db_or_error) |_| {
                return error.ExpectedInvalidVersionError;
            } else |err| {
                try std.testing.expectEqual(error.InvalidVersion, err);
            }
        }
    }

    // array_list of hash_maps
    {
        try clearStorage(db_kind, init_opts);
        var db = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);
        var root_cursor = db.rootCursor();

        // write foo -> bar with a writer
        const foo_key = hashBuffer("foo");
        {
            const Ctx = struct {
                pub fn run(_: @This(), cursor: *xitdb.Database(db_kind, Hash).Cursor(.read_write)) !void {
                    try std.testing.expect(cursor.slot().tag == .none);
                    var writer = try cursor.writer();
                    try writer.writeAll("bar");
                    try writer.finish();
                }
            };
            _ = try root_cursor.writePath(Ctx, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .ctx = Ctx{} },
            });
        }

        // read foo
        {
            var bar_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?;
            try std.testing.expectEqual(3, bar_cursor.count());
            const bar_value = try bar_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(bar_value);
            try std.testing.expectEqualStrings("bar", bar_value);

            // make sure we can make a buffered reader
            var buf_reader = std.io.bufferedReader(try bar_cursor.reader());
            _ = try buf_reader.read(&[_]u8{});
        }

        // read foo from ctx
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(self: @This(), cursor: *xitdb.Database(db_kind, Hash).Cursor(.read_write)) !void {
                    try std.testing.expect(cursor.slot().tag != .none);

                    const value = try cursor.readBytesAlloc(self.allocator, MAX_READ_BYTES);
                    defer self.allocator.free(value);
                    try std.testing.expectEqualStrings("bar", value);

                    var bar_reader = try cursor.reader();

                    // read into buffer
                    var bar_bytes = [_]u8{0} ** 10;
                    try bar_reader.readNoEof(bar_bytes[0..3]);
                    try std.testing.expectEqualStrings("bar", bar_bytes[0..3]);
                    try bar_reader.seekTo(0);
                    try std.testing.expectEqual(3, try bar_reader.read(&bar_bytes));
                    try std.testing.expectEqualStrings("bar", bar_bytes[0..3]);

                    // read one char at a time
                    {
                        var char = [_]u8{0} ** 1;
                        try bar_reader.seekTo(0);

                        try bar_reader.readNoEof(&char);
                        try std.testing.expectEqualStrings("b", &char);

                        try bar_reader.readNoEof(&char);
                        try std.testing.expectEqualStrings("a", &char);

                        try bar_reader.readNoEof(&char);
                        try std.testing.expectEqualStrings("r", &char);

                        try std.testing.expectEqual(error.EndOfStream, bar_reader.readNoEof(&char));

                        try bar_reader.seekTo(2);
                        try bar_reader.seekBy(-1);
                        try std.testing.expectEqual('a', try bar_reader.readInt(u8, .little));

                        try bar_reader.seekFromEnd(-3);
                        try std.testing.expectEqual('b', try bar_reader.readInt(u8, .little));
                    }
                }
            };
            _ = try root_cursor.writePath(Ctx, &.{
                .array_list_init,
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .ctx = Ctx{ .allocator = allocator } },
            });
        }

        // overwrite foo -> baz
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(self: @This(), cursor: *xitdb.Database(db_kind, Hash).Cursor(.read_write)) !void {
                    try std.testing.expect(cursor.slot().tag != .none);

                    var writer = try cursor.writer();
                    try writer.writeAll("x");
                    try writer.writeAll("x");
                    try writer.writeAll("x");
                    try writer.seekBy(-3);
                    try writer.writeAll("b");
                    try writer.seekTo(2);
                    try writer.writeAll("z");
                    try writer.seekFromEnd(-2);
                    try writer.writeAll("a");
                    try writer.finish();

                    const value = try cursor.readBytesAlloc(self.allocator, MAX_READ_BYTES);
                    defer self.allocator.free(value);
                    try std.testing.expectEqualStrings("baz", value);
                }
            };
            _ = try root_cursor.writePath(Ctx, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .ctx = Ctx{ .allocator = allocator } },
            });
        }

        // write bar -> longstring
        const bar_key = hashBuffer("bar");
        {
            var bar_cursor = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = bar_key } },
            });
            try bar_cursor.write(.{ .bytes = "longstring" });

            // the slot tag is .bytes because the byte array is > 8 bytes long
            try std.testing.expectEqual(.bytes, bar_cursor.slot().tag);

            // writing again returns the same slot
            {
                var next_bar_cursor = try root_cursor.writePath(void, &.{
                    .array_list_init,
                    .array_list_append,
                    .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                    .hash_map_init,
                    .{ .hash_map_get = .{ .value = bar_key } },
                });
                try next_bar_cursor.writeIfEmpty(.{ .bytes = "longstring" });
                try std.testing.expectEqual(bar_cursor.slot_ptr.slot, next_bar_cursor.slot_ptr.slot);
            }

            // writing with write returns a new slot
            {
                var next_bar_cursor = try root_cursor.writePath(void, &.{
                    .array_list_init,
                    .array_list_append,
                    .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                    .hash_map_init,
                    .{ .hash_map_get = .{ .value = bar_key } },
                });
                try next_bar_cursor.write(.{ .bytes = "longstring" });
                try std.testing.expect(!bar_cursor.slot_ptr.slot.eql(next_bar_cursor.slot_ptr.slot));
            }
        }

        // read bar
        {
            const foo_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = bar_key } },
            })).?;
            const foo_value = try foo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(foo_value);
            try std.testing.expectEqualStrings("longstring", foo_value);
        }

        // write bar -> shortstr
        {
            var bar_cursor = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = bar_key } },
            });
            try bar_cursor.write(.{ .bytes = "shortstr" });

            // the slot tag is .short_bytes because the byte array is <= 8 bytes long
            try std.testing.expectEqual(.short_bytes, bar_cursor.slot().tag);

            // make sure .short_bytes can be read with a reader
            var bar_reader = try bar_cursor.reader();
            const bar_value = try bar_reader.readAllAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(bar_value);
            try std.testing.expectEqualStrings("shortstr", bar_value);
        }

        // if error in ctx, db doesn't change
        {
            try db.core.seekFromEnd(0);
            const size_before = try db.core.getPos();

            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(_: @This(), cursor: *xitdb.Database(db_kind, Hash).Cursor(.read_write)) !void {
                    var writer = try cursor.writer();
                    try writer.writeAll("this value won't be visible");
                    try writer.finish();
                    return error.CancelTransaction;
                }
            };
            _ = root_cursor.writePath(Ctx, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hashBuffer("foo") } },
                .{ .ctx = Ctx{ .allocator = allocator } },
            }) catch |err| switch (err) {
                error.CancelTransaction => {},
                else => return err,
            };

            // read foo
            const value_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?;
            const value = try value_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value);
            try std.testing.expectEqualStrings("baz", value);

            // if truncation is allowed, verify that the db is
            // properly truncated back to its original size after error
            if (init_opts.allow_truncation) {
                try db.core.seekFromEnd(0);
                const size_after = try db.core.getPos();
                try std.testing.expectEqual(size_before, size_after);
            }
        }

        // read foo into stack-allocated buffer
        {
            const bar_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?;
            var bar_buffer = [_]u8{0} ** 3;
            const bar_buffer_value = try bar_cursor.readBytes(&bar_buffer);
            try std.testing.expectEqualStrings("baz", bar_buffer_value);
        }

        // write bar and get pointer to it
        const bar_slot = (try root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .value = hashBuffer("bar") } },
            .{ .write = .{ .bytes = "bar" } },
        })).slot_ptr.slot;

        // overwrite foo -> bar using the bar pointer
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .value = foo_key } },
            .{ .write = .{ .slot = bar_slot } },
        });
        const baz_cursor = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = -1 },
            .{ .hash_map_get = .{ .value = foo_key } },
        })).?;
        const baz_value = try baz_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(baz_value);
        try std.testing.expectEqualStrings("bar", baz_value);

        // can still read the old value
        const baz_cursor2 = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = -2 },
            .{ .hash_map_get = .{ .value = foo_key } },
        })).?;
        const baz_value2 = try baz_cursor2.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(baz_value2);
        try std.testing.expectEqualStrings("baz", baz_value2);

        // key not found
        const not_found_key = hashBuffer("this doesn't exist");
        try std.testing.expectEqual(null, try root_cursor.readPath(void, &.{
            .{ .array_list_get = -1 },
            .{ .hash_map_get = .{ .value = not_found_key } },
        }));

        // write key that conflicts with foo the first two bytes
        const small_conflict_mask: u64 = 0b1111_1111;
        const small_conflict_key = (hashBuffer("small conflict") & ~small_conflict_mask) | (foo_key & small_conflict_mask);
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .value = small_conflict_key } },
            .{ .write = .{ .bytes = "small" } },
        });

        // write key that conflicts with foo the first four bytes
        const conflict_mask: u64 = 0b1111_1111_1111_1111;
        const conflict_key = (hashBuffer("conflict") & ~conflict_mask) | (foo_key & conflict_mask);
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .value = conflict_key } },
            .{ .write = .{ .bytes = "hello" } },
        });

        // read conflicting key
        const hello_cursor = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = -1 },
            .{ .hash_map_get = .{ .value = conflict_key } },
        })).?;
        const hello_value = try hello_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(hello_value);
        try std.testing.expectEqualStrings("hello", hello_value);

        // we can still read foo
        const bar_cursor2 = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = -1 },
            .{ .hash_map_get = .{ .value = foo_key } },
        })).?;
        const bar_value2 = try bar_cursor2.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(bar_value2);
        try std.testing.expectEqualStrings("bar", bar_value2);

        // overwrite conflicting key
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .value = conflict_key } },
            .{ .write = .{ .bytes = "goodbye" } },
        });
        const goodbye_cursor = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = -1 },
            .{ .hash_map_get = .{ .value = conflict_key } },
        })).?;
        const goodbye_value = try goodbye_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(goodbye_value);
        try std.testing.expectEqualStrings("goodbye", goodbye_value);

        // we can still read the old conflicting key
        const hello_cursor2 = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = -2 },
            .{ .hash_map_get = .{ .value = conflict_key } },
        })).?;
        const hello_value2 = try hello_cursor2.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(hello_value2);
        try std.testing.expectEqualStrings("hello", hello_value2);

        // remove the conflicting keys
        {
            // foo's slot is an .index slot due to the conflict
            {
                const map_cursor = (try root_cursor.readPath(void, &.{
                    .{ .array_list_get = -1 },
                })).?;
                const index_pos = map_cursor.slot().value;
                try std.testing.expectEqual(.hash_map, map_cursor.slot().tag);

                const reader = db.core.reader();
                const slot_size: u64 = @bitSizeOf(xitdb.Slot) / 8;

                const i: u4 = @intCast(foo_key & xitdb.MASK);
                const slot_pos = index_pos + (slot_size * i);
                try db.core.seekTo(slot_pos);
                const slot: xitdb.Slot = @bitCast(try reader.readInt(u72, .big));

                try std.testing.expectEqual(.index, slot.tag);
            }

            // remove the small conflict key
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_remove = small_conflict_key },
            });

            // the conflict key still exists in history
            try std.testing.expect(null != try root_cursor.readPath(void, &.{
                .{ .array_list_get = -2 },
                .{ .hash_map_get = .{ .value = small_conflict_key } },
            }));

            // the conflict key doesn't exist in the latest moment
            try std.testing.expectEqual(null, try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = small_conflict_key } },
            }));

            // the other conflict key still exists
            try std.testing.expect(null != try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = conflict_key } },
            }));

            // foo's slot is still an .index slot due to the other conflicting key
            {
                const map_cursor = (try root_cursor.readPath(void, &.{
                    .{ .array_list_get = -1 },
                })).?;
                const index_pos = map_cursor.slot().value;
                try std.testing.expectEqual(.hash_map, map_cursor.slot().tag);

                const reader = db.core.reader();
                const slot_size: u64 = @bitSizeOf(xitdb.Slot) / 8;

                const i: u4 = @intCast(foo_key & xitdb.MASK);
                const slot_pos = index_pos + (slot_size * i);
                try db.core.seekTo(slot_pos);
                const slot: xitdb.Slot = @bitCast(try reader.readInt(u72, .big));

                try std.testing.expectEqual(.index, slot.tag);
            }

            // remove the conflict key
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_remove = conflict_key },
            });

            // the conflict keys don't exist in the latest moment
            try std.testing.expectEqual(null, try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = small_conflict_key } },
            }));
            try std.testing.expectEqual(null, try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = conflict_key } },
            }));

            // foo's slot is now a .kv_pair slot, because the branch was shortened
            {
                const map_cursor = (try root_cursor.readPath(void, &.{
                    .{ .array_list_get = -1 },
                })).?;
                const index_pos = map_cursor.slot().value;
                try std.testing.expectEqual(.hash_map, map_cursor.slot().tag);

                const reader = db.core.reader();
                const slot_size: u64 = @bitSizeOf(xitdb.Slot) / 8;

                const i: u4 = @intCast(foo_key & xitdb.MASK);
                const slot_pos = index_pos + (slot_size * i);
                try db.core.seekTo(slot_pos);
                const slot: xitdb.Slot = @bitCast(try reader.readInt(u72, .big));

                try std.testing.expectEqual(.kv_pair, slot.tag);
            }
        }

        {
            // overwrite foo with a uint
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .write = .{ .uint = 42 } },
            });

            // read foo
            const uint_value = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?.readUint();
            try std.testing.expectEqual(42, uint_value);
        }

        {
            // overwrite foo with an int
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .write = .{ .int = -42 } },
            });

            // read foo
            const int_value = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?.readInt();
            try std.testing.expectEqual(-42, int_value);
        }

        {
            // overwrite foo with a float
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .write = .{ .float = 42.5 } },
            });

            // read foo
            const float_value = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?.readFloat();
            try std.testing.expectEqual(42.5, float_value);
        }

        // remove foo
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .hash_map_remove = foo_key },
        });

        // remove key that does not exist
        try std.testing.expectError(error.KeyNotFound, root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .hash_map_remove = hashBuffer("doesn't exist") },
        }));

        // make sure foo doesn't exist anymore
        try std.testing.expectEqual(null, try root_cursor.readPath(void, &.{
            .{ .array_list_get = -1 },
            .{ .hash_map_get = .{ .value = foo_key } },
        }));

        // non-top-level list
        {
            // write apple
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .bytes = "apple" } },
            });

            // read apple
            const apple_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .{ .array_list_get = -1 },
            })).?;
            const apple_value = try apple_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(apple_value);
            try std.testing.expectEqualStrings("apple", apple_value);

            // write banana
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .bytes = "banana" } },
            });

            // read banana
            const banana_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .{ .array_list_get = -1 },
            })).?;
            const banana_value = try banana_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(banana_value);
            try std.testing.expectEqualStrings("banana", banana_value);

            // can't read banana in older array_list
            try std.testing.expectEqual(null, try root_cursor.readPath(void, &.{
                .{ .array_list_get = -2 },
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .{ .array_list_get = 1 },
            }));

            // write pear
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .bytes = "pear" } },
            });

            // write grape
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .bytes = "grape" } },
            });

            // read pear
            const pear_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .{ .array_list_get = -2 },
            })).?;
            const pear_value = try pear_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(pear_value);
            try std.testing.expectEqualStrings("pear", pear_value);

            // read grape
            const grape_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .{ .array_list_get = -1 },
            })).?;
            const grape_value = try grape_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(grape_value);
            try std.testing.expectEqualStrings("grape", grape_value);
        }
    }

    // append to top-level array_list many times, filling up the array_list until a root overflow occurs
    {
        try clearStorage(db_kind, init_opts);
        var db = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);
        var root_cursor = db.rootCursor();

        const wat_key = hashBuffer("wat");
        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = wat_key } },
                .{ .write = .{ .bytes = value } },
            });
        }

        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = i },
                .{ .hash_map_get = .{ .value = wat_key } },
            })).?;
            const value2 = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // slice so it contains exactly SLOT_COUNT,
        // so we have the old root again
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_slice = .{ .size = xitdb.SLOT_COUNT } },
        });

        // we can iterate over the remaining slots
        for (0..xitdb.SLOT_COUNT) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = i },
                .{ .hash_map_get = .{ .value = wat_key } },
            })).?;
            const value2 = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // but we can't get the value that we sliced out of the array list
        try std.testing.expectEqual(null, root_cursor.readPath(void, &.{
            .{ .array_list_get = xitdb.SLOT_COUNT + 1 },
        }));
    }

    // append to inner array_list many times, filling up the array_list until a root overflow occurs
    {
        try clearStorage(db_kind, init_opts);
        var db = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);
        var root_cursor = db.rootCursor();

        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .bytes = value } },
            });
        }

        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .array_list_get = i },
            })).?;
            const value2 = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // slice inner array list so it contains exactly SLOT_COUNT,
        // so we have the old root again
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_get = -1 },
            .array_list_init,
            .{ .array_list_slice = .{ .size = xitdb.SLOT_COUNT } },
        });

        // we can iterate over the remaining slots
        for (0..xitdb.SLOT_COUNT) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .array_list_get = i },
            })).?;
            const value2 = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // but we can't get the value that we sliced out of the array list
        try std.testing.expectEqual(null, root_cursor.readPath(void, &.{
            .{ .array_list_get = -1 },
            .{ .array_list_get = xitdb.SLOT_COUNT + 1 },
        }));

        // overwrite last value with hello
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .array_list_init,
            .{ .array_list_get = -1 },
            .{ .write = .{ .bytes = "hello" } },
        });

        // read last value
        {
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .array_list_get = -1 },
            })).?;
            const value = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value);
            try std.testing.expectEqualStrings("hello", value);
        }

        // overwrite last value with goodbye
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .array_list_init,
            .{ .array_list_get = -1 },
            .{ .write = .{ .bytes = "goodbye" } },
        });

        // read last value
        {
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .array_list_get = -1 },
            })).?;
            const value = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value);
            try std.testing.expectEqualStrings("goodbye", value);
        }

        // previous last value is still hello
        {
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -2 },
                .{ .array_list_get = -1 },
            })).?;
            const value = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value);
            try std.testing.expectEqualStrings("hello", value);
        }
    }

    // iterate over inner array_list
    {
        try clearStorage(db_kind, init_opts);
        var db = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);
        var root_cursor = db.rootCursor();

        // add wats
        for (0..10) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .bytes = value } },
            });

            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .array_list_get = -1 },
            })).?;
            const value2 = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // iterate over array_list
        {
            var inner_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
            })).?;
            var iter = try inner_cursor.iterator();
            defer iter.deinit();
            var i: u64 = 0;
            while (try iter.next()) |*next_cursor| {
                const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
                defer allocator.free(value);
                const value2 = try next_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                defer allocator.free(value2);
                try std.testing.expectEqualStrings(value, value2);
                i += 1;
            }
            try std.testing.expectEqual(10, i);
        }

        // set first slot to .none and make sure iteration still works.
        // this validates that it correctly returns .none slots if
        // their flag is set, rather than skipping over them.
        {
            _ = try root_cursor.writePath(void, &.{
                .{ .array_list_get = -1 },
                .{ .array_list_get = 0 },
                .{ .write = .{ .slot = null } },
            });
            var inner_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
            })).?;
            var iter = try inner_cursor.iterator();
            defer iter.deinit();
            var i: u64 = 0;
            while (try iter.next()) |_| {
                i += 1;
            }
            try std.testing.expectEqual(10, i);
        }

        // get list slot
        const list_cursor = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = -1 },
        })).?;
        try std.testing.expectEqual(10, list_cursor.count());
    }

    // iterate over inner hash_map
    {
        try clearStorage(db_kind, init_opts);
        var db = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);
        var root_cursor = db.rootCursor();

        // add wats
        for (0..10) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const wat_key = hashBuffer(value);
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = wat_key } },
                .{ .write = .{ .bytes = value } },
            });

            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = -1 },
                .{ .hash_map_get = .{ .value = wat_key } },
            })).?;
            const value2 = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // add foo
        const foo_key = hashBuffer("foo");
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .key = foo_key } },
            .{ .write = .{ .bytes = "foo" } },
        });
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .value = foo_key } },
            .{ .write = .{ .uint = 42 } },
        });

        // remove a wat
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .hash_map_remove = hashBuffer("wat0") },
        });

        // iterate over hash_map
        var inner_cursor = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = -1 },
        })).?;
        var iter = try inner_cursor.iterator();
        defer iter.deinit();
        var i: u64 = 0;
        while (try iter.next()) |kv_pair_cursor| {
            const kv_pair = try kv_pair_cursor.readKeyValuePair();
            if (kv_pair.hash == foo_key) {
                const key = try kv_pair.key_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                defer allocator.free(key);
                try std.testing.expectEqualStrings("foo", key);
                try std.testing.expectEqual(42, kv_pair.value_cursor.slot_ptr.slot.value);
            } else {
                const value = try kv_pair.value_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                defer allocator.free(value);
                try std.testing.expectEqual(kv_pair.hash, hashBuffer(value));
            }
            i += 1;
        }
        try std.testing.expectEqual(10, i);
    }

    {
        // slice linked_array_list
        try testSlice(allocator, db_kind, init_opts, xitdb.SLOT_COUNT * 5 + 1, 10, 5);
        try testSlice(allocator, db_kind, init_opts, xitdb.SLOT_COUNT * 5 + 1, 0, xitdb.SLOT_COUNT * 2);
        try testSlice(allocator, db_kind, init_opts, xitdb.SLOT_COUNT * 5, xitdb.SLOT_COUNT * 3, xitdb.SLOT_COUNT);
        try testSlice(allocator, db_kind, init_opts, xitdb.SLOT_COUNT * 5, xitdb.SLOT_COUNT * 3, xitdb.SLOT_COUNT * 2);
        try testSlice(allocator, db_kind, init_opts, xitdb.SLOT_COUNT * 2, 10, xitdb.SLOT_COUNT);
        try testSlice(allocator, db_kind, init_opts, 2, 0, 2);
        try testSlice(allocator, db_kind, init_opts, 2, 1, 1);
        try testSlice(allocator, db_kind, init_opts, 1, 0, 0);

        // concat linked_array_list
        try testConcat(allocator, db_kind, init_opts, xitdb.SLOT_COUNT * 5 + 1, xitdb.SLOT_COUNT + 1);
        try testConcat(allocator, db_kind, init_opts, xitdb.SLOT_COUNT, xitdb.SLOT_COUNT);
        try testConcat(allocator, db_kind, init_opts, 1, 1);
        try testConcat(allocator, db_kind, init_opts, 0, 0);
    }

    // concat linked_array_list multiple times
    {
        try clearStorage(db_kind, init_opts);
        var db = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);
        var root_cursor = db.rootCursor();

        const Ctx = struct {
            allocator: std.mem.Allocator,

            pub fn run(self: @This(), cursor: *xitdb.Database(db_kind, Hash).Cursor(.read_write)) !void {
                var values = std.ArrayList(u64).init(self.allocator);
                defer values.deinit();

                // create list
                for (0..xitdb.SLOT_COUNT + 1) |i| {
                    const n = i * 2;
                    try values.append(n);
                    _ = try cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hashBuffer("even") } },
                        .linked_array_list_init,
                        .linked_array_list_append,
                        .{ .write = .{ .uint = n } },
                    });
                }

                // get list slot
                const even_list_cursor = (try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("even") } },
                })).?;
                try std.testing.expectEqual(xitdb.SLOT_COUNT + 1, even_list_cursor.count());

                // iterate over list
                var inner_cursor = (try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("even") } },
                })).?;
                var iter = try inner_cursor.iterator();
                defer iter.deinit();
                var i: u64 = 0;
                while (try iter.next()) |_| {
                    i += 1;
                }
                try std.testing.expectEqual(xitdb.SLOT_COUNT + 1, i);

                // concat the list with itself multiple times.
                // since each list has 17 items, each concat
                // will create a gap, causing a root overflow
                // before a normal array list would've.
                var combo_list_cursor = try cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                    .{ .write = .{ .slot = even_list_cursor.slot_ptr.slot } },
                    .linked_array_list_init,
                });
                for (0..16) |_| {
                    combo_list_cursor = try combo_list_cursor.writePath(void, &.{
                        .{ .linked_array_list_concat = .{ .list = even_list_cursor.slot_ptr.slot } },
                    });
                }

                // append to the new list
                _ = try cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                    .linked_array_list_append,
                    .{ .write = .{ .uint = 3 } },
                });

                // read the new value from the list
                try std.testing.expectEqual(3, (try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                    .{ .linked_array_list_get = -1 },
                })).?.slot_ptr.slot.value);

                // append more to the new list
                for (0..500) |_| {
                    _ = try cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                        .linked_array_list_append,
                        .{ .write = .{ .uint = 1 } },
                    });
                }
            }
        };
        _ = try root_cursor.writePath(Ctx, &.{
            .array_list_init,
            .array_list_append,
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
            .hash_map_init,
            .{ .ctx = .{ .allocator = allocator } },
        });
    }

    // append items to linked_array_list without setting their value
    {
        try clearStorage(db_kind, init_opts);
        var db = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);
        var root_cursor = db.rootCursor();

        // appending without setting any value should work
        for (0..8) |_| {
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .linked_array_list_init,
                .linked_array_list_append,
            });
        }

        // explicitly writing a null slot should also work
        for (0..8) |_| {
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .array_list_append,
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = -1 }}) } },
                .linked_array_list_init,
                .linked_array_list_append,
                .{ .write = .{ .slot = null } },
            });
        }
    }
}
