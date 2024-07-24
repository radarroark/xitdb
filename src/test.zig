const std = @import("std");
const xitdb = @import("./lib.zig");
const Database = xitdb.Database;
const DatabaseKind = xitdb.DatabaseKind;
const PathPart = xitdb.PathPart;

const MAX_READ_BYTES = 1024;

fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

fn hash_buffer(buffer: []const u8) xitdb.Hash {
    var hash = [_]u8{0} ** (@bitSizeOf(xitdb.Hash) / 8);
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(buffer);
    h.final(&hash);
    return std.mem.bytesToValue(xitdb.Hash, &hash);
}

fn initOpts(comptime kind: DatabaseKind, opts: anytype) !Database(kind).InitOpts {
    switch (kind) {
        .file => {
            const file_or_err = opts.dir.openFile(opts.path, .{ .mode = .read_write, .lock = .exclusive });
            const file = try if (file_or_err == error.FileNotFound)
                opts.dir.createFile(opts.path, .{ .read = true, .lock = .exclusive })
            else
                file_or_err;
            errdefer file.close();
            return .{ .file = file };
        },
        .memory => return opts,
    }
}

fn testSlice(allocator: std.mem.Allocator, comptime kind: DatabaseKind, opts: anytype, comptime original_size: usize, comptime slice_offset: u64, comptime slice_size: u64) !void {
    const init_opts = try initOpts(kind, opts);
    var db = try Database(kind).init(allocator, init_opts);
    defer {
        db.deinit();
        if (kind == .file) {
            opts.dir.deleteFile(opts.path) catch {};
        }
    }
    var root_cursor = db.rootCursor();

    const Ctx = struct {
        allocator: std.mem.Allocator,

        pub fn run(self: @This(), cursor: *Database(kind).Cursor) !void {
            var values = std.ArrayList(u64).init(self.allocator);
            defer values.deinit();

            // create list
            for (0..original_size) |i| {
                const n = i * 2;
                try values.append(n);
                _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                    .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                    .linked_array_list_create,
                    .{ .linked_array_list_get = .append },
                    .{ .write = .{ .uint = n } },
                });
            }

            // slice list
            const even_list_slot = (try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("even") } },
            })).?;
            const even_list_slice_slot = try cursor.db.slice(even_list_slot, slice_offset, slice_size);

            // save the newly-made slice
            _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("even-slice") } },
                .{ .write = .{ .slot = even_list_slice_slot } },
            });

            // check all values in the new slice
            for (values.items[slice_offset .. slice_offset + slice_size], 0..) |val, i| {
                const n = (try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                    .{ .hash_map_get = .{ .value = hash_buffer("even-slice") } },
                    .{ .linked_array_list_get = .{ .index = i } },
                })).?.value;
                try expectEqual(val, n);
            }

            // there are no extra items
            try expectEqual(null, try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("even-slice") } },
                .{ .linked_array_list_get = .{ .index = slice_size } },
            }));

            // concat the slice with itself
            const combo_list_slot = try cursor.db.concat(even_list_slice_slot, even_list_slice_slot);
            _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("combo") } },
                .{ .write = .{ .slot = combo_list_slot } },
            });

            // check all values in the combo list
            var combo_values = std.ArrayList(u64).init(self.allocator);
            defer combo_values.deinit();
            try combo_values.appendSlice(values.items[slice_offset .. slice_offset + slice_size]);
            try combo_values.appendSlice(values.items[slice_offset .. slice_offset + slice_size]);
            for (combo_values.items, 0..) |val, i| {
                const n = (try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                    .{ .hash_map_get = .{ .value = hash_buffer("combo") } },
                    .{ .linked_array_list_get = .{ .index = i } },
                })).?.value;
                try expectEqual(val, n);
            }

            // append to the slice
            _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("even-slice") } },
                .linked_array_list_create,
                .{ .path = &[_]PathPart(void){
                    .{ .linked_array_list_get = .append },
                    .{ .write = .{ .uint = 3 } },
                } },
            });

            // read the new value from the slice
            try expectEqual(3, (try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("even-slice") } },
                .{ .linked_array_list_get = .{ .index = -1 } },
            })).?.value);
        }
    };
    _ = try root_cursor.readSlot(.read_write, Ctx, &[_]PathPart(Ctx){
        .{ .array_list_get = .append_copy },
        .hash_map_create,
        .{ .ctx = .{ .allocator = allocator } },
    });
}

fn testConcat(allocator: std.mem.Allocator, comptime kind: DatabaseKind, opts: anytype, comptime list_a_size: usize, comptime list_b_size: usize) !void {
    const init_opts = try initOpts(kind, opts);
    var db = try Database(kind).init(allocator, init_opts);
    defer {
        db.deinit();
        if (kind == .file) {
            opts.dir.deleteFile(opts.path) catch {};
        }
    }
    var root_cursor = db.rootCursor();

    const Ctx = struct {
        allocator: std.mem.Allocator,

        pub fn run(self: @This(), cursor: *Database(kind).Cursor) !void {
            var values = std.ArrayList(u64).init(self.allocator);
            defer values.deinit();

            // create even list
            _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                .linked_array_list_create,
            });
            for (0..list_a_size) |i| {
                const n = i * 2;
                try values.append(n);
                _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                    .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                    .linked_array_list_create,
                    .{ .linked_array_list_get = .append },
                    .{ .write = .{ .uint = n } },
                });
            }

            // get even list
            const even_list_slot = (try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("even") } },
            })).?;

            // create odd list
            _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("odd") } },
                .linked_array_list_create,
            });
            for (0..list_b_size) |i| {
                const n = (i * 2) + 1;
                try values.append(n);
                _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                    .{ .hash_map_get = .{ .value = hash_buffer("odd") } },
                    .linked_array_list_create,
                    .{ .linked_array_list_get = .append },
                    .{ .write = .{ .uint = n } },
                });
            }

            // get odd list
            const odd_list_slot = (try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("odd") } },
            })).?;

            // concat the lists
            const combo_list_slot = try cursor.db.concat(even_list_slot, odd_list_slot);
            _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("combo") } },
                .{ .write = .{ .slot = combo_list_slot } },
            });

            // check all values in the new list
            for (values.items, 0..) |val, i| {
                const n = (try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                    .{ .hash_map_get = .{ .value = hash_buffer("combo") } },
                    .{ .linked_array_list_get = .{ .index = i } },
                })).?.value;
                try expectEqual(val, n);
            }

            // there are no extra items
            try expectEqual(null, try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .hash_map_get = .{ .value = hash_buffer("combo") } },
                .{ .linked_array_list_get = .{ .index = values.items.len } },
            }));
        }
    };
    _ = try root_cursor.readSlot(.read_write, Ctx, &[_]PathPart(Ctx){
        .{ .array_list_get = .append_copy },
        .hash_map_create,
        .{ .ctx = .{ .allocator = allocator } },
    });
}

fn testMain(allocator: std.mem.Allocator, comptime kind: DatabaseKind, opts: anytype) !void {
    // array_list of hash_maps
    {
        const init_opts = try initOpts(kind, opts);
        var db = try Database(kind).init(allocator, init_opts);
        defer {
            db.deinit();
            if (kind == .file) {
                opts.dir.deleteFile(opts.path) catch {};
            }
        }
        var root_cursor = db.rootCursor();

        // write foo -> bar with a writer
        const foo_key = hash_buffer("foo");
        {
            const Ctx = struct {
                pub fn run(_: @This(), cursor: *Database(kind).Cursor) !void {
                    try std.testing.expect(cursor.pointer() == null);
                    var writer = try cursor.writer(void, &[_]PathPart(void){});
                    try writer.writeAll("bar");
                    try writer.finish();
                }
            };
            _ = try root_cursor.readSlot(.read_write, Ctx, &[_]PathPart(Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .ctx = Ctx{} },
            });
        }

        // read foo
        {
            const bar_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?;
            const bar_value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, bar_slot);
            defer allocator.free(bar_value);
            try std.testing.expectEqualStrings("bar", bar_value);
        }

        // read foo from ctx
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(self: @This(), cursor: *Database(kind).Cursor) !void {
                    try std.testing.expect(cursor.pointer() != null);

                    const value_slot = (try cursor.readSlot(.read_only, void, &[_]PathPart(void){})).?;
                    const value = try cursor.db.readBytesAlloc(self.allocator, MAX_READ_BYTES, value_slot);
                    defer self.allocator.free(value);
                    try std.testing.expectEqualStrings("bar", value);

                    var bar_reader = (try cursor.reader(void, &[_]PathPart(void){})).?;

                    // read into buffer
                    var bar_bytes = [_]u8{0} ** 10;
                    try bar_reader.readNoEof(bar_bytes[0..3]);
                    try std.testing.expectEqualStrings("bar", bar_bytes[0..3]);
                    try bar_reader.seekTo(0);
                    try expectEqual(3, try bar_reader.read(&bar_bytes));
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

                        try expectEqual(error.EndOfStream, bar_reader.readNoEof(&char));

                        try bar_reader.seekTo(2);
                        try bar_reader.seekBy(-1);
                        try expectEqual('a', try bar_reader.readInt(u8, .little));

                        try bar_reader.seekFromEnd(-3);
                        try expectEqual('b', try bar_reader.readInt(u8, .little));
                    }
                }
            };
            _ = try root_cursor.readSlot(.read_write, Ctx, &[_]PathPart(Ctx){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .ctx = Ctx{ .allocator = allocator } },
            });
        }

        // overwrite foo -> baz
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(self: @This(), cursor: *Database(kind).Cursor) !void {
                    try std.testing.expect(cursor.pointer() != null);

                    var writer = try cursor.writer(void, &[_]PathPart(void){});
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

                    const value_slot = (try cursor.readSlot(.read_only, void, &[_]PathPart(void){})).?;
                    const value = try cursor.db.readBytesAlloc(self.allocator, MAX_READ_BYTES, value_slot);
                    defer self.allocator.free(value);
                    try std.testing.expectEqualStrings("baz", value);
                }
            };
            _ = try root_cursor.readSlot(.read_write, Ctx, &[_]PathPart(Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = foo_key } },
                .{ .ctx = Ctx{ .allocator = allocator } },
            });
        }

        // write bar -> foo with writeBytes
        const bar_key = hash_buffer("bar");
        {
            const foo_slot = try root_cursor.writeBytes("foo", .once, void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = bar_key } },
            });
            try expectEqual(foo_slot, try root_cursor.writeBytes("foo", .once, void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = bar_key } },
            }));
            try std.testing.expect(!foo_slot.eql(try root_cursor.writeBytes("foo", .replace, void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = bar_key } },
            })));
        }

        // read bar
        {
            const foo_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = bar_key } },
            })).?;
            const foo_value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, foo_slot);
            defer allocator.free(foo_value);
            try std.testing.expectEqualStrings("foo", foo_value);
        }

        // if error in ctx, db doesn't change
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(_: @This(), cursor: *Database(kind).Cursor) !void {
                    var writer = try cursor.writer(void, &[_]PathPart(void){});
                    try writer.writeAll("this value won't be visible");
                    try writer.finish();
                    return error.NotImplemented;
                }
            };
            _ = root_cursor.readSlot(.read_write, Ctx, &[_]PathPart(Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = hash_buffer("foo") } },
                .{ .ctx = Ctx{ .allocator = allocator } },
            }) catch {};

            // read foo
            const value_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?;
            const value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, value_slot);
            defer allocator.free(value);
            try std.testing.expectEqualStrings("baz", value);
        }

        // read foo into stack-allocated buffer
        {
            const bar_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = foo_key } },
            })).?;
            var bar_buffer = [_]u8{0} ** 3;
            const bar_buffer_value = try db.readBytes(&bar_buffer, bar_slot);
            try std.testing.expectEqualStrings("baz", bar_buffer_value);
        }

        // write bar and get pointer to it
        const bar_slot = (try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = .{ .value = hash_buffer("bar") } },
            .{ .write = .{ .bytes = "bar" } },
        })).?;

        // overwrite foo -> bar using the bar pointer
        _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = .{ .value = foo_key } },
            .{ .write = .{ .slot = bar_slot } },
        });
        const baz_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = foo_key } },
        })).?;
        const baz_value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, baz_slot);
        defer allocator.free(baz_value);
        try std.testing.expectEqualStrings("bar", baz_value);

        // can still read the old value
        const baz_slot2 = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -2 } },
            .{ .hash_map_get = .{ .value = foo_key } },
        })).?;
        const baz_value2 = try db.readBytesAlloc(allocator, MAX_READ_BYTES, baz_slot2);
        defer allocator.free(baz_value2);
        try std.testing.expectEqualStrings("baz", baz_value2);

        // key not found
        const not_found_key = hash_buffer("this doesn't exist");
        try expectEqual(null, try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = not_found_key } },
        }));

        // write key that conflicts with foo
        var conflict_key = hash_buffer("conflict");
        conflict_key = (conflict_key & ~xitdb.MASK) | (foo_key & xitdb.MASK);
        _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = .{ .value = conflict_key } },
            .{ .write = .{ .bytes = "hello" } },
        });

        // read conflicting key
        const hello_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = conflict_key } },
        })).?;
        const hello_value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, hello_slot);
        defer allocator.free(hello_value);
        try std.testing.expectEqualStrings("hello", hello_value);

        // we can still read foo
        const bar_slot2 = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = foo_key } },
        })).?;
        const bar_value2 = try db.readBytesAlloc(allocator, MAX_READ_BYTES, bar_slot2);
        defer allocator.free(bar_value2);
        try std.testing.expectEqualStrings("bar", bar_value2);

        // overwrite conflicting key
        _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = .{ .value = conflict_key } },
            .{ .write = .{ .bytes = "goodbye" } },
        });
        const goodbye_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = conflict_key } },
        })).?;
        const goodbye_value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, goodbye_slot);
        defer allocator.free(goodbye_value);
        try std.testing.expectEqualStrings("goodbye", goodbye_value);

        // we can still read the old conflicting key
        const hello_slot2 = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -2 } },
            .{ .hash_map_get = .{ .value = conflict_key } },
        })).?;
        const hello_value2 = try db.readBytesAlloc(allocator, MAX_READ_BYTES, hello_slot2);
        defer allocator.free(hello_value2);
        try std.testing.expectEqualStrings("hello", hello_value2);

        // overwrite foo with an int
        _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = .{ .value = foo_key } },
            .{ .write = .{ .uint = 42 } },
        });

        // read foo
        const int_value = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = foo_key } },
        })).?.value;
        try expectEqual(42, int_value);

        // remove foo
        _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_remove = foo_key },
        });

        // read foo
        try expectEqual(null, try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -1 } },
            .{ .hash_map_get = .{ .value = foo_key } },
        }));

        // non-top-level list
        {
            // write apple
            _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = hash_buffer("fruits") } },
                .array_list_create,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = "apple" } },
            });

            // read apple
            const apple_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = hash_buffer("fruits") } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const apple_value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, apple_slot);
            defer allocator.free(apple_value);
            try std.testing.expectEqualStrings("apple", apple_value);

            // write banana
            _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = hash_buffer("fruits") } },
                .array_list_create,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = "banana" } },
            });

            // read banana
            const banana_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = hash_buffer("fruits") } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const banana_value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, banana_slot);
            defer allocator.free(banana_value);
            try std.testing.expectEqualStrings("banana", banana_value);

            // can't read banana in older array_list
            try expectEqual(null, try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -2 } },
                .{ .hash_map_get = .{ .value = hash_buffer("fruits") } },
                .{ .array_list_get = .{ .index = 1 } },
            }));

            // write pear and grape
            _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = hash_buffer("fruits") } },
                .array_list_create,
                .{ .path = &[_]PathPart(void){
                    .{ .array_list_get = .append },
                    .{ .write = .{ .bytes = "pear" } },
                } },
                .{ .path = &[_]PathPart(void){
                    .{ .array_list_get = .append },
                    .{ .write = .{ .bytes = "grape" } },
                } },
            });

            // read pear
            const pear_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = hash_buffer("fruits") } },
                .{ .array_list_get = .{ .index = -2 } },
            })).?;
            const pear_value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, pear_slot);
            defer allocator.free(pear_value);
            try std.testing.expectEqualStrings("pear", pear_value);

            // read grape
            const grape_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = hash_buffer("fruits") } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const grape_value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, grape_slot);
            defer allocator.free(grape_value);
            try std.testing.expectEqualStrings("grape", grape_value);
        }
    }

    // append to top-level array_list many times, filling up the array_list until a root overflow occurs
    {
        const init_opts = try initOpts(kind, opts);
        var db = try Database(kind).init(allocator, init_opts);
        defer {
            db.deinit();
            if (kind == .file) {
                opts.dir.deleteFile(opts.path) catch {};
            }
        }
        var root_cursor = db.rootCursor();

        const wat_key = hash_buffer("wat");
        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = wat_key } },
                .{ .write = .{ .bytes = value } },
            });
        }

        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = i } },
                .{ .hash_map_get = .{ .value = wat_key } },
            })).?;
            const value2 = try db.readBytesAlloc(allocator, MAX_READ_BYTES, slot);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }
    }

    // append to inner array_list many times, filling up the array_list until a root overflow occurs
    {
        const init_opts = try initOpts(kind, opts);
        var db = try Database(kind).init(allocator, init_opts);
        defer {
            db.deinit();
            if (kind == .file) {
                opts.dir.deleteFile(opts.path) catch {};
            }
        }
        var root_cursor = db.rootCursor();

        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .array_list_create,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = value } },
            });
        }

        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .array_list_get = .{ .index = i } },
            })).?;
            const value2 = try db.readBytesAlloc(allocator, MAX_READ_BYTES, slot);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // overwrite last value with hello
        _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .array_list_create,
            .{ .array_list_get = .{ .index = -1 } },
            .{ .write = .{ .bytes = "hello" } },
        });

        // read last value
        {
            const slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, slot);
            defer allocator.free(value);
            try std.testing.expectEqualStrings("hello", value);
        }

        // overwrite last value with goodbye
        _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .array_list_create,
            .{ .array_list_get = .{ .index = -1 } },
            .{ .write = .{ .bytes = "goodbye" } },
        });

        // read last value
        {
            const slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, slot);
            defer allocator.free(value);
            try std.testing.expectEqualStrings("goodbye", value);
        }

        // previous last value is still hello
        {
            const slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -2 } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, slot);
            defer allocator.free(value);
            try std.testing.expectEqualStrings("hello", value);
        }
    }

    // iterate over inner array_list
    {
        const init_opts = try initOpts(kind, opts);
        var db = try Database(kind).init(allocator, init_opts);
        defer {
            db.deinit();
            if (kind == .file) {
                opts.dir.deleteFile(opts.path) catch {};
            }
        }
        var root_cursor = db.rootCursor();

        // add wats
        for (0..10) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .array_list_create,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = value } },
            });

            const slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .array_list_get = .{ .index = -1 } },
            })).?;
            const value2 = try db.readBytesAlloc(allocator, MAX_READ_BYTES, slot);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // iterate over array_list
        var inner_cursor = (try root_cursor.readCursor(void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -1 } },
        })).?;
        var iter = try inner_cursor.iter();
        defer iter.deinit();
        var i: u64 = 0;
        while (try iter.next()) |*next_cursor| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const slot = (try next_cursor.readSlot(.read_only, void, &[_]PathPart(void){})).?;
            const value2 = try db.readBytesAlloc(allocator, MAX_READ_BYTES, slot);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
            i += 1;
        }
        try expectEqual(10, i);

        // get list slot
        const list_slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -1 } },
        })).?;
        try expectEqual(10, db.count(list_slot));
    }

    // iterate over inner hash_map
    {
        const init_opts = try initOpts(kind, opts);
        var db = try Database(kind).init(allocator, init_opts);
        defer {
            db.deinit();
            if (kind == .file) {
                opts.dir.deleteFile(opts.path) catch {};
            }
        }
        var root_cursor = db.rootCursor();

        // add wats
        for (0..10) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const wat_key = hash_buffer(value);
            _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = wat_key } },
                .{ .write = .{ .bytes = value } },
            });

            const slot = (try root_cursor.readSlot(.read_only, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = -1 } },
                .{ .hash_map_get = .{ .value = wat_key } },
            })).?;
            const value2 = try db.readBytesAlloc(allocator, MAX_READ_BYTES, slot);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // add foo
        const foo_key = hash_buffer("foo");
        _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = .{ .key = foo_key } },
            .{ .write = .{ .bytes = "foo" } },
        });
        _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = .{ .value = foo_key } },
            .{ .write = .{ .uint = 42 } },
        });

        // remove a wat
        _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_remove = hash_buffer("wat0") },
        });

        // iterate over hash_map
        var inner_cursor = (try root_cursor.readCursor(void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = -1 } },
        })).?;
        var iter = try inner_cursor.iter();
        defer iter.deinit();
        var i: u64 = 0;
        while (try iter.next()) |*next_cursor| {
            const kv_slot = (try next_cursor.readSlot(.read_only, void, &[_]PathPart(void){})).?;
            const kv_pair = try db.readKeyValuePair(kv_slot);
            if (kv_pair.hash == foo_key) {
                const key = try db.readBytesAlloc(allocator, MAX_READ_BYTES, kv_pair.key_slot);
                defer allocator.free(key);
                try std.testing.expectEqualStrings("foo", key);
                try expectEqual(42, kv_pair.value_slot.value);
            } else {
                const value = try db.readBytesAlloc(allocator, MAX_READ_BYTES, kv_pair.value_slot);
                defer allocator.free(value);
                try expectEqual(kv_pair.hash, hash_buffer(value));
            }
            i += 1;
        }
        try expectEqual(10, i);
    }

    {
        // slice linked_array_list
        try testSlice(allocator, kind, opts, xitdb.SLOT_COUNT * 5 + 1, 10, 5);
        try testSlice(allocator, kind, opts, xitdb.SLOT_COUNT * 5 + 1, 0, xitdb.SLOT_COUNT * 2);
        try testSlice(allocator, kind, opts, xitdb.SLOT_COUNT * 5, xitdb.SLOT_COUNT * 3, xitdb.SLOT_COUNT);
        try testSlice(allocator, kind, opts, xitdb.SLOT_COUNT * 5, xitdb.SLOT_COUNT * 3, xitdb.SLOT_COUNT * 2);
        try testSlice(allocator, kind, opts, xitdb.SLOT_COUNT * 2, 10, xitdb.SLOT_COUNT);
        try testSlice(allocator, kind, opts, 2, 0, 2);
        try testSlice(allocator, kind, opts, 2, 1, 1);
        try testSlice(allocator, kind, opts, 1, 0, 0);

        // concat linked_array_list
        try testConcat(allocator, kind, opts, xitdb.SLOT_COUNT * 5 + 1, xitdb.SLOT_COUNT + 1);
        try testConcat(allocator, kind, opts, xitdb.SLOT_COUNT, xitdb.SLOT_COUNT);
        try testConcat(allocator, kind, opts, 1, 1);
        try testConcat(allocator, kind, opts, 0, 0);
    }

    // concat linked_array_list multiple times
    {
        const init_opts = try initOpts(kind, opts);
        var db = try Database(kind).init(allocator, init_opts);
        defer {
            db.deinit();
            if (kind == .file) {
                opts.dir.deleteFile(opts.path) catch {};
            }
        }
        var root_cursor = db.rootCursor();

        const Ctx = struct {
            allocator: std.mem.Allocator,

            pub fn run(self: @This(), cursor: *Database(kind).Cursor) !void {
                var values = std.ArrayList(u64).init(self.allocator);
                defer values.deinit();

                // create list
                for (0..xitdb.SLOT_COUNT + 1) |i| {
                    const n = i * 2;
                    try values.append(n);
                    _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                        .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                        .linked_array_list_create,
                        .{ .linked_array_list_get = .append },
                        .{ .write = .{ .uint = n } },
                    });
                }

                // get list slot
                const even_list_slot = (try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                    .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                })).?;
                try expectEqual(xitdb.SLOT_COUNT + 1, cursor.db.count(even_list_slot));

                // iterate over list
                var inner_cursor = (try cursor.readCursor(void, &[_]PathPart(void){
                    .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                })).?;
                var iter = try inner_cursor.iter();
                defer iter.deinit();
                var i: u64 = 0;
                while (try iter.next()) |_| {
                    i += 1;
                }
                try expectEqual(xitdb.SLOT_COUNT + 1, i);

                // concat the list with itself multiple times.
                // since each list has 17 items, each concat
                // will create a gap, causing a root overflow
                // before a normal array list would've.
                var combo_list_slot = even_list_slot;
                for (0..16) |_| {
                    combo_list_slot = try cursor.db.concat(combo_list_slot, even_list_slot);
                }

                // save the new list
                _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                    .{ .hash_map_get = .{ .value = hash_buffer("combo") } },
                    .{ .write = .{ .slot = combo_list_slot } },
                });

                // append to the new list
                _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                    .{ .hash_map_get = .{ .value = hash_buffer("combo") } },
                    .{ .linked_array_list_get = .append },
                    .{ .write = .{ .uint = 3 } },
                });

                // read the new value from the list
                try expectEqual(3, (try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                    .{ .hash_map_get = .{ .value = hash_buffer("combo") } },
                    .{ .linked_array_list_get = .{ .index = -1 } },
                })).?.value);

                // append more to the new list
                for (0..500) |_| {
                    _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                        .{ .hash_map_get = .{ .value = hash_buffer("combo") } },
                        .{ .linked_array_list_get = .append },
                        .{ .write = .{ .uint = 1 } },
                    });
                }
            }
        };
        _ = try root_cursor.readSlot(.read_write, Ctx, &[_]PathPart(Ctx){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .ctx = .{ .allocator = allocator } },
        });
    }

    // append items to linked_array_list without setting their value
    {
        const init_opts = try initOpts(kind, opts);
        var db = try Database(kind).init(allocator, init_opts);
        defer {
            db.deinit();
            if (kind == .file) {
                opts.dir.deleteFile(opts.path) catch {};
            }
        }
        var root_cursor = db.rootCursor();

        for (0..8) |_| {
            _ = try root_cursor.readSlot(.read_write, void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .linked_array_list_create,
                .{ .linked_array_list_get = .append },
            });
        }
    }

    // array_hash_map
    {
        const init_opts = try initOpts(kind, opts);
        var db = try Database(kind).init(allocator, init_opts);
        defer {
            db.deinit();
            if (kind == .file) {
                opts.dir.deleteFile(opts.path) catch {};
            }
        }
        var root_cursor = db.rootCursor();

        // create array map
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(self: @This(), cursor: *Database(kind).Cursor) !void {
                    for (0..xitdb.SLOT_COUNT + 1) |i| {
                        const n = i * 2;
                        const key = try std.fmt.allocPrint(self.allocator, "wat{}", .{i});
                        defer self.allocator.free(key);
                        _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                            .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                            .array_hash_map_create,
                            .{ .array_hash_map_get = .{ .value = hash_buffer(key) } },
                            .{ .write = .{ .uint = n } },
                        });
                    }
                }
            };
            _ = try root_cursor.readSlot(.read_write, Ctx, &[_]PathPart(Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .ctx = .{ .allocator = allocator } },
            });
        }

        // update array map and verify it works
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(self: @This(), cursor: *Database(kind).Cursor) !void {
                    var values = std.ArrayList(u64).init(self.allocator);
                    defer values.deinit();

                    // update array map
                    for (0..xitdb.SLOT_COUNT + 1) |i| {
                        var n = i * 2;
                        const key = try std.fmt.allocPrint(self.allocator, "wat{}", .{i});
                        defer self.allocator.free(key);

                        n = n * 2;
                        try values.append(n);
                        _ = try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                            .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                            .array_hash_map_create,
                            .{ .array_hash_map_get = .{ .value = hash_buffer(key) } },
                            .{ .write = .{ .uint = n } },
                        });
                    }

                    // get array map slot
                    const even_list_slot = (try cursor.readSlot(.read_write, void, &[_]PathPart(void){
                        .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                    })).?;
                    try expectEqual(xitdb.SLOT_COUNT + 1, cursor.db.count(even_list_slot));

                    // check all values in the new array map
                    for (values.items, 0..) |val, i| {
                        const n = (try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                            .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                            .{ .array_hash_map_get_by_index = .{ .value = i } },
                        })).?.value;
                        try expectEqual(val, n);

                        const kv_slot = (try cursor.readSlot(.read_only, void, &[_]PathPart(void){
                            .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                            .{ .array_hash_map_get_by_index = .{ .kv_pair = i } },
                        })).?;
                        const kv_pair = try cursor.db.readKeyValuePair(kv_slot);
                        try expectEqual(i, kv_pair.metadata_slot.value);
                    }

                    // iterate over array map
                    var inner_cursor = (try cursor.readCursor(void, &[_]PathPart(void){
                        .{ .hash_map_get = .{ .value = hash_buffer("even") } },
                    })).?;
                    var iter = try inner_cursor.iter();
                    defer iter.deinit();
                    var i: u64 = 0;
                    while (try iter.next()) |*next_cursor| {
                        const value_cursor = try next_cursor.valueCursor();
                        const n = (try value_cursor.readSlot(.read_only, void, &[_]PathPart(void){})).?.value;
                        try expectEqual(values.items[i], n);
                        i += 1;
                    }
                    try expectEqual(xitdb.SLOT_COUNT + 1, i);
                }
            };
            _ = try root_cursor.readSlot(.read_write, Ctx, &[_]PathPart(Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .ctx = .{ .allocator = allocator } },
            });
        }
    }
}

test "read and write" {
    const allocator = std.testing.allocator;

    try testMain(allocator, .memory, .{ .capacity = 50000 });

    try testMain(allocator, .file, .{ .dir = std.fs.cwd(), .path = "main.db" });

    // memory
    // low level operations
    {
        var db = try Database(.memory).init(allocator, .{ .capacity = 10000 });
        defer db.deinit();

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
        try expectEqual(42, reader.readInt(u64, .little));
    }
}

test "get/set tag" {
    const ptr_value = xitdb.Slot.init(42, .hash_map);
    try std.testing.expectEqual(.hash_map, try xitdb.Tag.init(ptr_value));
    const ptr_index = xitdb.Slot.init(42, .index);
    try std.testing.expectEqual(.index, try xitdb.Tag.init(ptr_index));
}
