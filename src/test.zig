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
    var hash = [_]u8{0} ** xitdb.HASH_INT_SIZE;
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(buffer);
    h.final(hash[0..xitdb.HASH_SIZE]);
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
            _ = try root_cursor.execute(Ctx, &[_]PathPart(Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = foo_key },
                .{ .ctx = Ctx{} },
            });
        }

        // read foo
        const bar_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = foo_key },
        })).?;
        defer allocator.free(bar_value);
        try std.testing.expectEqualStrings("bar", bar_value);

        // read foo from ctx
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(self: @This(), cursor: *Database(kind).Cursor) !void {
                    try std.testing.expect(cursor.pointer() != null);

                    const value = (try cursor.readBytesAlloc(self.allocator, MAX_READ_BYTES, void, &[_]PathPart(void){})).?;
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
            _ = try root_cursor.execute(Ctx, &[_]PathPart(Ctx){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .hash_map_get = foo_key },
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

                    const value = (try cursor.readBytesAlloc(self.allocator, MAX_READ_BYTES, void, &[_]PathPart(void){})).?;
                    defer self.allocator.free(value);
                    try std.testing.expectEqualStrings("baz", value);
                }
            };
            _ = try root_cursor.execute(Ctx, &[_]PathPart(Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = foo_key },
                .{ .ctx = Ctx{ .allocator = allocator } },
            });
        }

        // write bar -> foo with writeBytes
        const bar_key = hash_buffer("bar");
        const foo_slot = try root_cursor.writeBytes("foo", .once, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = bar_key },
        });
        try expectEqual(foo_slot, try root_cursor.writeBytes("foo", .once, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = bar_key },
        }));
        try std.testing.expect(!foo_slot.eql(try root_cursor.writeBytes("foo", .replace, void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = bar_key },
        })));

        // read bar
        const foo_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = bar_key },
        })).?;
        defer allocator.free(foo_value);
        try std.testing.expectEqualStrings("foo", foo_value);

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
            _ = root_cursor.execute(Ctx, &[_]PathPart(Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = hash_buffer("foo") },
                .{ .ctx = Ctx{ .allocator = allocator } },
            }) catch {};

            // read foo
            const value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .hash_map_get = foo_key },
            })).?;
            defer allocator.free(value);
            try std.testing.expectEqualStrings("baz", value);
        }

        // read foo into stack-allocated buffer
        var bar_buffer = [_]u8{0} ** 3;
        const bar_buffer_value = (try root_cursor.readBytes(&bar_buffer, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = foo_key },
        })).?;
        try std.testing.expectEqualStrings("baz", bar_buffer_value);

        // write bar and get pointer to it
        const bar_slot = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = hash_buffer("bar") },
            .{ .value = .{ .bytes = "bar" } },
        });

        // overwrite foo -> bar using the bar pointer
        _ = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = foo_key },
            .{ .value = .{ .slot = bar_slot } },
        });
        const baz_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = foo_key },
        })).?;
        defer allocator.free(baz_value);
        try std.testing.expectEqualStrings("bar", baz_value);

        // can still read the old value
        const baz_value2 = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 1, .reverse = true } } },
            .{ .hash_map_get = foo_key },
        })).?;
        defer allocator.free(baz_value2);
        try std.testing.expectEqualStrings("baz", baz_value2);

        // key not found
        const not_found_key = hash_buffer("this doesn't exist");
        try expectEqual(null, try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = not_found_key },
        }));

        // write key that conflicts with foo
        var conflict_key = hash_buffer("conflict");
        conflict_key = (conflict_key & ~xitdb.MASK) | (foo_key & xitdb.MASK);
        _ = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = conflict_key },
            .{ .value = .{ .bytes = "hello" } },
        });

        // read conflicting key
        const hello_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = conflict_key },
        })).?;
        defer allocator.free(hello_value);
        try std.testing.expectEqualStrings("hello", hello_value);

        // we can still read foo
        const bar_value2 = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = foo_key },
        })).?;
        defer allocator.free(bar_value2);
        try std.testing.expectEqualStrings("bar", bar_value2);

        // overwrite conflicting key
        _ = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = conflict_key },
            .{ .value = .{ .bytes = "goodbye" } },
        });
        const goodbye_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = conflict_key },
        })).?;
        defer allocator.free(goodbye_value);
        try std.testing.expectEqualStrings("goodbye", goodbye_value);

        // we can still read the old conflicting key
        const hello_value2 = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 1, .reverse = true } } },
            .{ .hash_map_get = conflict_key },
        })).?;
        defer allocator.free(hello_value2);
        try std.testing.expectEqualStrings("hello", hello_value2);

        // overwrite foo with an int
        _ = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = foo_key },
            .{ .value = .{ .uint = 42 } },
        });

        // read foo
        const int_value = try root_cursor.readInt(void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = foo_key },
        });
        try expectEqual(42, int_value);

        // remove foo
        _ = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_remove = foo_key },
        });

        // read foo
        try expectEqual(null, try root_cursor.readInt(void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = foo_key },
        }));

        // non-top-level list
        {
            // write apple
            _ = try root_cursor.execute(void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = hash_buffer("fruits") },
                .array_list_create,
                .{ .array_list_get = .append },
                .{ .value = .{ .bytes = "apple" } },
            });

            // read apple
            const apple_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .hash_map_get = hash_buffer("fruits") },
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            })).?;
            defer allocator.free(apple_value);
            try std.testing.expectEqualStrings("apple", apple_value);

            // write banana
            _ = try root_cursor.execute(void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = hash_buffer("fruits") },
                .array_list_create,
                .{ .array_list_get = .append },
                .{ .value = .{ .bytes = "banana" } },
            });

            // read banana
            const banana_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .hash_map_get = hash_buffer("fruits") },
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            })).?;
            defer allocator.free(banana_value);
            try std.testing.expectEqualStrings("banana", banana_value);

            // can't read banana in older array_list
            try expectEqual(null, try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 1, .reverse = true } } },
                .{ .hash_map_get = hash_buffer("fruits") },
                .{ .array_list_get = .{ .index = .{ .index = 1, .reverse = false } } },
            }));

            // write pear and grape
            _ = try root_cursor.execute(void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = hash_buffer("fruits") },
                .array_list_create,
                .{ .path = &[_]PathPart(void){
                    .{ .array_list_get = .append },
                    .{ .value = .{ .bytes = "pear" } },
                } },
                .{ .path = &[_]PathPart(void){
                    .{ .array_list_get = .append },
                    .{ .value = .{ .bytes = "grape" } },
                } },
            });

            // read pear
            const pear_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .hash_map_get = hash_buffer("fruits") },
                .{ .array_list_get = .{ .index = .{ .index = 1, .reverse = true } } },
            })).?;
            defer allocator.free(pear_value);
            try std.testing.expectEqualStrings("pear", pear_value);

            // read grape
            const grape_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .hash_map_get = hash_buffer("fruits") },
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            })).?;
            defer allocator.free(grape_value);
            try std.testing.expectEqualStrings("grape", grape_value);
        }

        // slice
        {
            // slice the fruits list
            const fruits_slot = try root_cursor.execute(void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .hash_map_get = hash_buffer("fruits") },
            });
            const fruits_slice_slot = try root_cursor.db.slice(fruits_slot, 1, 2);

            // save the newly-made slice
            _ = try root_cursor.execute(void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = hash_buffer("fruits-slice") },
                .{ .value = .{ .slot = fruits_slice_slot } },
            });

            {
                // read banana from fruits-slice
                const slice_banana_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .hash_map_get = hash_buffer("fruits-slice") },
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = false } } },
                })).?;
                defer allocator.free(slice_banana_value);
                try std.testing.expectEqualStrings("banana", slice_banana_value);

                // read pear from fruits-slice
                const slice_pear_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .hash_map_get = hash_buffer("fruits-slice") },
                    .{ .array_list_get = .{ .index = .{ .index = 1, .reverse = false } } },
                })).?;
                defer allocator.free(slice_pear_value);
                try std.testing.expectEqualStrings("pear", slice_pear_value);

                // grape is not in the slice
                try std.testing.expect(null == try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .hash_map_get = hash_buffer("fruits-slice") },
                    .{ .array_list_get = .{ .index = .{ .index = 2, .reverse = false } } },
                }));
            }

            // slice the fruits list again
            const fruits_slice_slot2 = try root_cursor.db.slice(fruits_slice_slot, 1, 1);

            // save the newly-made slice
            _ = try root_cursor.execute(void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = hash_buffer("fruits-slice") },
                .{ .value = .{ .slot = fruits_slice_slot2 } },
            });

            {
                // read pear from fruits-slice
                const slice_pear_value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .hash_map_get = hash_buffer("fruits-slice") },
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = false } } },
                })).?;
                defer allocator.free(slice_pear_value);
                try std.testing.expectEqualStrings("pear", slice_pear_value);

                // grape is not in the slice
                try std.testing.expect(null == try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .hash_map_get = hash_buffer("fruits-slice") },
                    .{ .array_list_get = .{ .index = .{ .index = 1, .reverse = false } } },
                }));
            }
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
            _ = try root_cursor.execute(void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = wat_key },
                .{ .value = .{ .bytes = value } },
            });
        }

        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const value2 = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = i, .reverse = false } } },
                .{ .hash_map_get = wat_key },
            })).?;
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
            _ = try root_cursor.execute(void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .array_list_create,
                .{ .array_list_get = .append },
                .{ .value = .{ .bytes = value } },
            });
        }

        for (0..xitdb.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const value2 = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .array_list_get = .{ .index = .{ .index = i, .reverse = false } } },
            })).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // overwrite last value with hello
        _ = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .array_list_create,
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .value = .{ .bytes = "hello" } },
        });

        // read last value
        const value = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(value);
        try std.testing.expectEqualStrings("hello", value);

        // overwrite last value with goodbye
        _ = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .array_list_create,
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .value = .{ .bytes = "goodbye" } },
        });

        // read last value
        const value2 = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(value2);
        try std.testing.expectEqualStrings("goodbye", value2);

        // previous last value is still hello
        const value3 = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 1, .reverse = true } } },
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(value3);
        try std.testing.expectEqualStrings("hello", value3);
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
            _ = try root_cursor.execute(void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .array_list_create,
                .{ .array_list_get = .append },
                .{ .value = .{ .bytes = value } },
            });

            const value2 = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            })).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // iterate over array_list
        var inner_cursor = (try root_cursor.readCursor(void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        var iter = try inner_cursor.iter(.array_list);
        defer iter.deinit();
        var i: u64 = 0;
        while (try iter.next()) |*next_cursor| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const value2 = (try next_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){})).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
            i += 1;
        }
        try expectEqual(10, i);
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
            _ = try root_cursor.execute(void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = wat_key },
                .{ .value = .{ .bytes = value } },
            });

            const value2 = (try root_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .hash_map_get = wat_key },
            })).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // add foo
        const foo_key = hash_buffer("foo");
        _ = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = foo_key },
            .{ .value = .{ .uint = 42 } },
        });

        // remove a wat
        _ = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_remove = hash_buffer("wat0") },
        });

        // iterate over hash_map
        var inner_cursor = (try root_cursor.readCursor(void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        var iter = try inner_cursor.iter(.hash_map);
        defer iter.deinit();
        var i: u64 = 0;
        while (try iter.next()) |*next_cursor| {
            const hash = (try next_cursor.readHash(void, &[_]PathPart(void){})).?;
            if (hash == foo_key) {
                const value = (try next_cursor.readInt(void, &[_]PathPart(void){})).?;
                try expectEqual(42, value);
            } else {
                const value = (try next_cursor.readBytesAlloc(allocator, MAX_READ_BYTES, void, &[_]PathPart(void){})).?;
                defer allocator.free(value);
                try expectEqual(hash, hash_buffer(value));
            }
            i += 1;
        }
        try expectEqual(10, i);
    }

    // slice
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

        // create list
        for (0..xitdb.SLOT_COUNT + 1) |i| {
            _ = try root_cursor.execute(void, &[_]PathPart(void){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .hash_map_get = hash_buffer("even") },
                .array_list_create,
                .{ .array_list_get = .append },
                .{ .value = .{ .uint = i * 2 } },
            });
        }

        // slice list
        const even_list_slot = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = hash_buffer("even") },
        });
        const even_list_slice_slot = try root_cursor.db.slice(even_list_slot, 0, 2);

        // save the newly-made slice
        _ = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = hash_buffer("even-slice") },
            .{ .value = .{ .slot = even_list_slice_slot } },
        });

        // append to the slice
        _ = try root_cursor.execute(void, &[_]PathPart(void){
            .{ .array_list_get = .append_copy },
            .hash_map_create,
            .{ .hash_map_get = hash_buffer("even-slice") },
            .array_list_create,
            .{ .path = &[_]PathPart(void){
                .{ .array_list_get = .append },
                .{ .value = .{ .uint = 42 } },
            } },
        });

        // read the new value from the slice
        try expectEqual(42, try root_cursor.readInt(void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = hash_buffer("even-slice") },
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        }));
        try expectEqual(42, try root_cursor.readInt(void, &[_]PathPart(void){
            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .hash_map_get = hash_buffer("even-slice") },
            .{ .array_list_get = .{ .index = .{ .index = 2, .reverse = false } } },
        }));
    }
}

test "read and write" {
    const allocator = std.testing.allocator;

    try testMain(allocator, .memory, .{ .capacity = 10000 });

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
