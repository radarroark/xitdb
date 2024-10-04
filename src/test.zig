const std = @import("std");
const xitdb = @import("./lib.zig");

const Hash = u160;
const MAX_READ_BYTES = 1024;

fn hashBuffer(buffer: []const u8) Hash {
    var hash = [_]u8{0} ** (@bitSizeOf(Hash) / 8);
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(buffer);
    h.final(&hash);
    return std.mem.bytesToValue(Hash, &hash);
}

test "high level api" {
    const allocator = std.testing.allocator;

    // create db file
    const file = try std.fs.cwd().createFile("main.db", .{ .exclusive = true, .lock = .exclusive, .read = true });
    defer {
        file.close();
        std.fs.cwd().deleteFile("main.db") catch {};
    }

    // init the db
    const DB = xitdb.Database(.file, Hash);
    var db = try DB.init(allocator, .{ .file = file });

    // the top-level data structure *must* be an ArrayList,
    // because each transaction is stored as an item in this list
    const list = try DB.ArrayList(.read_write).init(db.rootCursor());

    // this is how a transaction is executed. we call list.appendValueContext,
    // providing it with the most recent copy of the db and a context
    // object. the context object has a method that will run before the
    // transaction has completed. this method is where we can write
    // changes to the db. if any error happens in it, the transaction
    // will not complete and the db will be unaffected.
    const Ctx = struct {
        pub fn run(_: @This(), cursor: *DB.Cursor(.read_write)) !void {
            const map = try DB.HashMap(.read_write).init(cursor.*);

            try map.putValue(hashBuffer("foo"), .{ .bytes = "foo" });
            try map.putValue(hashBuffer("bar"), .{ .bytes = "bar" });
            try map.remove(hashBuffer("bar"));

            const fruits_cursor = try map.put(hashBuffer("fruits"));
            const fruits = try DB.ArrayList(.read_write).init(fruits_cursor);
            try fruits.appendValue(.{ .bytes = "apple" });
            try fruits.appendValue(.{ .bytes = "pear" });
            try fruits.appendValue(.{ .bytes = "grape" });

            const people_cursor = try map.put(hashBuffer("people"));
            const people = try DB.ArrayList(.read_write).init(people_cursor);

            const alice_cursor = try people.append();
            const alice = try DB.HashMap(.read_write).init(alice_cursor);
            try alice.putValue(hashBuffer("name"), .{ .bytes = "Alice" });
            try alice.putValue(hashBuffer("age"), .{ .uint = 25 });

            const bob_cursor = try people.append();
            const bob = try DB.HashMap(.read_write).init(bob_cursor);
            try bob.putValue(hashBuffer("name"), .{ .bytes = "Bob" });
            try bob.putValue(hashBuffer("age"), .{ .uint = 42 });
        }
    };
    try list.appendValueContext(.{ .slot = try list.getSlot(-1) }, Ctx, Ctx{});

    // get the most recent copy of the database.
    // the -1 index will return the last index in the list.
    const map_cursor = (try list.get(-1)).?;
    const map = try DB.HashMap(.read_only).init(map_cursor.readOnly());

    // we can read the value of "foo" from the map by getting
    // the cursor to "foo" and then calling readBytesAlloc on it
    const foo_cursor = (try map.get(hashBuffer("foo"))).?;
    const foo_value = try foo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
    defer allocator.free(foo_value);
    try std.testing.expectEqualStrings("foo", foo_value);

    try std.testing.expect(null == try map.get(hashBuffer("bar")));

    // to get the "fruits" list, we get the cursor to it and
    // then pass it to the ArrayList.init method
    const fruits_cursor = (try map.get(hashBuffer("fruits"))).?;
    try std.testing.expectEqual(3, try fruits_cursor.count());
    const fruits = try DB.ArrayList(.read_only).init(fruits_cursor);

    // now we can get the first item from the fruits list and read it
    const apple_cursor = (try fruits.get(0)).?;
    const apple_value = try apple_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
    defer allocator.free(apple_value);
    try std.testing.expectEqualStrings("apple", apple_value);

    const people_cursor = (try map.get(hashBuffer("people"))).?;
    try std.testing.expectEqual(2, try people_cursor.count());
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
                    .{ .linked_array_list_get = .append },
                    .{ .write = .{ .uint = n } },
                });
            }

            // slice list
            const even_list_cursor = (try cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even") } },
            })).?;
            const even_list_slice_cursor = try even_list_cursor.slice(slice_offset, slice_size);

            // save the newly-made slice
            _ = try cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even-slice") } },
                .{ .write = .{ .slot = even_list_slice_cursor.slot_ptr.slot } },
            });

            // check all values in the new slice
            for (values.items[slice_offset .. slice_offset + slice_size], 0..) |val, i| {
                const n = (try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("even-slice") } },
                    .{ .linked_array_list_get = .{ .index = i } },
                })).?.slot_ptr.slot.value;
                try std.testing.expectEqual(val, n);
            }

            // there are no extra items
            try std.testing.expectEqual(null, try cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even-slice") } },
                .{ .linked_array_list_get = .{ .index = slice_size } },
            }));

            // concat the slice with itself
            const combo_list_cursor = try even_list_slice_cursor.concat(even_list_slice_cursor);
            _ = try cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                .{ .write = .{ .slot = combo_list_cursor.slot_ptr.slot } },
            });

            // check all values in the combo list
            var combo_values = std.ArrayList(u64).init(self.allocator);
            defer combo_values.deinit();
            try combo_values.appendSlice(values.items[slice_offset .. slice_offset + slice_size]);
            try combo_values.appendSlice(values.items[slice_offset .. slice_offset + slice_size]);
            for (combo_values.items, 0..) |val, i| {
                const n = (try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                    .{ .linked_array_list_get = .{ .index = i } },
                })).?.slot_ptr.slot.value;
                try std.testing.expectEqual(val, n);
            }

            // append to the slice
            _ = try cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even-slice") } },
                .linked_array_list_init,
                .{ .linked_array_list_get = .append },
                .{ .write = .{ .uint = 3 } },
            });

            // read the new value from the slice
            try std.testing.expectEqual(3, (try cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even-slice") } },
                .{ .linked_array_list_get = .{ .index = -1 } },
            })).?.slot_ptr.slot.value);
        }
    };
    _ = try root_cursor.writePath(Ctx, &.{
        .array_list_init,
        .{ .array_list_get = .append },
        .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
        .hash_map_init,
        .{ .ctx = .{ .allocator = allocator } },
    });
}

fn testConcat(allocator: std.mem.Allocator, comptime db_kind: xitdb.DatabaseKind, init_opts: xitdb.Database(db_kind, Hash).InitOpts, comptime list_a_size: usize, comptime list_b_size: usize) !void {
    try clearStorage(db_kind, init_opts);
    var db = try xitdb.Database(db_kind, Hash).init(allocator, init_opts);
    var root_cursor = db.rootCursor();

    const Ctx = struct {
        allocator: std.mem.Allocator,

        pub fn run(self: @This(), cursor: *xitdb.Database(db_kind, Hash).Cursor(.read_write)) !void {
            var values = std.ArrayList(u64).init(self.allocator);
            defer values.deinit();

            // create even list
            _ = try cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even") } },
                .linked_array_list_init,
            });
            for (0..list_a_size) |i| {
                const n = i * 2;
                try values.append(n);
                _ = try cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("even") } },
                    .linked_array_list_init,
                    .{ .linked_array_list_get = .append },
                    .{ .write = .{ .uint = n } },
                });
            }

            // get even list
            const even_list_cursor = (try cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("even") } },
            })).?;

            // create odd list
            _ = try cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("odd") } },
                .linked_array_list_init,
            });
            for (0..list_b_size) |i| {
                const n = (i * 2) + 1;
                try values.append(n);
                _ = try cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("odd") } },
                    .linked_array_list_init,
                    .{ .linked_array_list_get = .append },
                    .{ .write = .{ .uint = n } },
                });
            }

            // get odd list
            const odd_list_cursor = (try cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("odd") } },
            })).?;

            // concat the lists
            const combo_list_cursor = try even_list_cursor.concat(odd_list_cursor);
            _ = try cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                .{ .write = .{ .slot = combo_list_cursor.slot_ptr.slot } },
            });

            // check all values in the new list
            for (values.items, 0..) |val, i| {
                const n = (try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                    .{ .linked_array_list_get = .{ .index = i } },
                })).?.slot_ptr.slot.value;
                try std.testing.expectEqual(val, n);
            }

            // there are no extra items
            try std.testing.expectEqual(null, try cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                .{ .linked_array_list_get = .{ .index = values.items.len } },
            }));
        }
    };
    _ = try root_cursor.writePath(Ctx, &.{
        .array_list_init,
        .{ .array_list_get = .append },
        .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
        .hash_map_init,
        .{ .ctx = .{ .allocator = allocator } },
    });
}

fn testMain(allocator: std.mem.Allocator, comptime db_kind: xitdb.DatabaseKind, init_opts: xitdb.Database(db_kind, Hash).InitOpts) !void {
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
                    try std.testing.expect(cursor.slot() == null);
                    var writer = try cursor.writer();
                    try writer.writeAll("bar");
                    try writer.finish();
                }
            };
            _ = try root_cursor.writePath(Ctx, &.{
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .ctx = Ctx{} },
            });
        }

        // read foo
        {
            var bar_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?;
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
                    try std.testing.expect(cursor.slot() != null);

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
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .ctx = Ctx{ .allocator = allocator } },
            });
        }

        // overwrite foo -> baz
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(self: @This(), cursor: *xitdb.Database(db_kind, Hash).Cursor(.read_write)) !void {
                    try std.testing.expect(cursor.slot() != null);

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
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .ctx = Ctx{ .allocator = allocator } },
            });
        }

        // write bar -> foo with writeBytes
        const bar_key = hashBuffer("bar");
        {
            var bar_cursor = try root_cursor.writePath(void, &.{
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = bar_key } },
            });
            try bar_cursor.writeBytes("foo", .once);
            // writing again with .once returns the same slot
            {
                var next_bar_cursor = try root_cursor.writePath(void, &.{
                    .array_list_init,
                    .{ .array_list_get = .append },
                    .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                    .hash_map_init,
                    .{ .hash_map_get = .{ .value = bar_key } },
                });
                try next_bar_cursor.writeBytes("foo", .once);
                try std.testing.expectEqual(bar_cursor.slot_ptr.slot, next_bar_cursor.slot_ptr.slot);
            }
            // writing again with .replace returns a new slot
            {
                var next_bar_cursor = try root_cursor.writePath(void, &.{
                    .array_list_init,
                    .{ .array_list_get = .append },
                    .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                    .hash_map_init,
                    .{ .hash_map_get = .{ .value = bar_key } },
                });
                try next_bar_cursor.writeBytes("foo", .replace);
                try std.testing.expect(!bar_cursor.slot_ptr.slot.eql(next_bar_cursor.slot_ptr.slot));
            }
        }

        // read bar
        {
            const foo_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = bar_key } },
            })).?;
            const foo_value = try foo_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(foo_value);
            try std.testing.expectEqualStrings("foo", foo_value);
        }

        // if error in ctx, db doesn't change
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(_: @This(), cursor: *xitdb.Database(db_kind, Hash).Cursor(.read_write)) !void {
                    var writer = try cursor.writer();
                    try writer.writeAll("this value won't be visible");
                    try writer.finish();
                    return error.NotImplemented;
                }
            };
            _ = root_cursor.writePath(Ctx, &.{
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hashBuffer("foo") } },
                .{ .ctx = Ctx{ .allocator = allocator } },
            }) catch {};

            // read foo
            const value_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?;
            const value = try value_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value);
            try std.testing.expectEqualStrings("baz", value);
        }

        // read foo into stack-allocated buffer
        {
            const bar_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?;
            var bar_buffer = [_]u8{0} ** 3;
            const bar_buffer_value = try bar_cursor.readBytes(&bar_buffer);
            try std.testing.expectEqualStrings("baz", bar_buffer_value);
        }

        // write bar and get pointer to it
        const bar_slot = (try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .value = hashBuffer("bar") } },
            .{ .write = .{ .bytes = "bar" } },
        })).slot_ptr.slot;

        // overwrite foo -> bar using the bar pointer
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .value = foo_key } },
            .{ .write = .{ .slot = bar_slot } },
        });
        const baz_cursor = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = foo_key } },
        })).?;
        const baz_value = try baz_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(baz_value);
        try std.testing.expectEqualStrings("bar", baz_value);

        // can still read the old value
        const baz_cursor2 = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = .{ .index = -2 } },
            .{ .hash_map_get = .{ .value = foo_key } },
        })).?;
        const baz_value2 = try baz_cursor2.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(baz_value2);
        try std.testing.expectEqualStrings("baz", baz_value2);

        // key not found
        const not_found_key = hashBuffer("this doesn't exist");
        try std.testing.expectEqual(null, try root_cursor.readPath(void, &.{
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = not_found_key } },
        }));

        // write key that conflicts with foo
        var conflict_key = hashBuffer("conflict");
        conflict_key = (conflict_key & ~xitdb.MASK) | (foo_key & xitdb.MASK);
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .value = conflict_key } },
            .{ .write = .{ .bytes = "hello" } },
        });

        // read conflicting key
        const hello_cursor = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = conflict_key } },
        })).?;
        const hello_value = try hello_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(hello_value);
        try std.testing.expectEqualStrings("hello", hello_value);

        // we can still read foo
        const bar_cursor2 = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = foo_key } },
        })).?;
        const bar_value2 = try bar_cursor2.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(bar_value2);
        try std.testing.expectEqualStrings("bar", bar_value2);

        // overwrite conflicting key
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .value = conflict_key } },
            .{ .write = .{ .bytes = "goodbye" } },
        });
        const goodbye_cursor = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = conflict_key } },
        })).?;
        const goodbye_value = try goodbye_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(goodbye_value);
        try std.testing.expectEqualStrings("goodbye", goodbye_value);

        // we can still read the old conflicting key
        const hello_cursor2 = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = .{ .index = -2 } },
            .{ .hash_map_get = .{ .value = conflict_key } },
        })).?;
        const hello_value2 = try hello_cursor2.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(hello_value2);
        try std.testing.expectEqualStrings("hello", hello_value2);

        {
            // overwrite foo with a uint
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .write = .{ .uint = 42 } },
            });

            // read foo
            const uint_value = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?.readUint();
            try std.testing.expectEqual(42, uint_value);
        }

        {
            // overwrite foo with an int
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .write = .{ .int = -42 } },
            });

            // read foo
            const int_value = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?.readInt();
            try std.testing.expectEqual(-42, int_value);
        }

        {
            // overwrite foo with a float
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .write = .{ .float = 42.5 } },
            });

            // read foo
            const float_value = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?.readFloat();
            try std.testing.expectEqual(42.5, float_value);
        }

        // remove foo
        const foo_cursor = try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
            .hash_map_init,
            .{ .hash_map_remove = foo_key },
        });
        try std.testing.expect(foo_cursor.slot_ptr.position != null);

        // remove key that does not exist
        const empty_cursor = try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
            .hash_map_init,
            .{ .hash_map_remove = hashBuffer("doesn't exist") },
        });
        try std.testing.expect(empty_cursor.slot_ptr.position == null);

        // read foo
        try std.testing.expectEqual(null, try root_cursor.readPath(void, &.{
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = foo_key } },
        }));

        // non-top-level list
        {
            // write apple
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = "apple" } },
            });

            // read apple
            const apple_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const apple_value = try apple_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(apple_value);
            try std.testing.expectEqualStrings("apple", apple_value);

            // write banana
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = "banana" } },
            });

            // read banana
            const banana_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const banana_value = try banana_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(banana_value);
            try std.testing.expectEqualStrings("banana", banana_value);

            // can't read banana in older array_list
            try std.testing.expectEqual(null, try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -2 } },
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .{ .array_list_get = .{ .index = 1 } },
            }));

            // write pear
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = "pear" } },
            });

            // write grape
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = "grape" } },
            });

            // read pear
            const pear_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .{ .array_list_get = .{ .index = -2 } },
            })).?;
            const pear_value = try pear_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(pear_value);
            try std.testing.expectEqualStrings("pear", pear_value);

            // read grape
            const grape_cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = hashBuffer("fruits") } },
                .{ .array_list_get = .{ .index = -1 } },
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
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = wat_key } },
                .{ .write = .{ .bytes = value } },
            });
        }

        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = i } },
                .{ .hash_map_get = .{ .value = wat_key } },
            })).?;
            const value2 = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }
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
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = value } },
            });
        }

        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .array_list_get = .{ .index = i } },
            })).?;
            const value2 = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // overwrite last value with hello
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
            .array_list_init,
            .{ .array_list_get = .{ .index = -1 } },
            .{ .write = .{ .bytes = "hello" } },
        });

        // read last value
        {
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const value = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value);
            try std.testing.expectEqualStrings("hello", value);
        }

        // overwrite last value with goodbye
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
            .array_list_init,
            .{ .array_list_get = .{ .index = -1 } },
            .{ .write = .{ .bytes = "goodbye" } },
        });

        // read last value
        {
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const value = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value);
            try std.testing.expectEqualStrings("goodbye", value);
        }

        // previous last value is still hello
        {
            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -2 } },
                .{ .array_list_get = .{ .index = -1 } },
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
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = value } },
            });

            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const value2 = try cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // iterate over array_list
        var inner_cursor = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = .{ .index = -1 } },
        })).?;
        var iter = try inner_cursor.iter();
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

        // get list slot
        const list_cursor = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = .{ .index = -1 } },
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
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = wat_key } },
                .{ .write = .{ .bytes = value } },
            });

            const cursor = (try root_cursor.readPath(void, &.{
                .{ .array_list_get = .{ .index = -1 } },
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
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .key = foo_key } },
            .{ .write = .{ .bytes = "foo" } },
        });
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
            .hash_map_init,
            .{ .hash_map_get = .{ .value = foo_key } },
            .{ .write = .{ .uint = 42 } },
        });

        // remove a wat
        _ = try root_cursor.writePath(void, &.{
            .array_list_init,
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
            .hash_map_init,
            .{ .hash_map_remove = hashBuffer("wat0") },
        });

        // iterate over hash_map
        var inner_cursor = (try root_cursor.readPath(void, &.{
            .{ .array_list_get = .{ .index = -1 } },
        })).?;
        var iter = try inner_cursor.iter();
        defer iter.deinit();
        var i: u64 = 0;
        while (try iter.next()) |*next_cursor| {
            const kv_pair = try next_cursor.readKeyValuePair();
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
                        .{ .linked_array_list_get = .append },
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
                var iter = try inner_cursor.iter();
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
                var combo_list_cursor = even_list_cursor;
                for (0..16) |_| {
                    combo_list_cursor = try combo_list_cursor.concat(even_list_cursor);
                }

                // save the new list
                _ = try cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                    .{ .write = .{ .slot = combo_list_cursor.slot_ptr.slot } },
                });

                // append to the new list
                _ = try cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                    .{ .linked_array_list_get = .append },
                    .{ .write = .{ .uint = 3 } },
                });

                // read the new value from the list
                try std.testing.expectEqual(3, (try cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                    .{ .linked_array_list_get = .{ .index = -1 } },
                })).?.slot_ptr.slot.value);

                // append more to the new list
                for (0..500) |_| {
                    _ = try cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hashBuffer("combo") } },
                        .{ .linked_array_list_get = .append },
                        .{ .write = .{ .uint = 1 } },
                    });
                }
            }
        };
        _ = try root_cursor.writePath(Ctx, &.{
            .array_list_init,
            .{ .array_list_get = .append },
            .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
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
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .linked_array_list_init,
                .{ .linked_array_list_get = .append },
            });
        }

        // explicitly writing .none should also work
        for (0..8) |_| {
            _ = try root_cursor.writePath(void, &.{
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .slot = try root_cursor.readPathSlot(void, &.{.{ .array_list_get = .{ .index = -1 } }}) } },
                .linked_array_list_init,
                .{ .linked_array_list_get = .append },
                .{ .write = .none },
            });
        }
    }
}

test "low level api" {
    const allocator = std.testing.allocator;

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try testMain(allocator, .memory, .{ .buffer = &buffer, .max_size = 50000 });

    if (std.fs.cwd().openFile("main.db", .{})) |file| {
        file.close();
        try std.fs.cwd().deleteFile("main.db");
    } else |_| {}

    const file = try std.fs.cwd().createFile("main.db", .{ .exclusive = true, .lock = .exclusive, .read = true });
    defer {
        file.close();
        std.fs.cwd().deleteFile("main.db") catch {};
    }
    try testMain(allocator, .file, .{ .file = file });
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
