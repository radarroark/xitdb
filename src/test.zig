const std = @import("std");
const main = @import("./main.zig");
const Database = main.Database;
const DatabaseKind = main.DatabaseKind;
const PathPart = main.PathPart;

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
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
    // list of maps
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

        // write foo
        const foo_key = main.hash_buffer("foo");
        const bar_key = main.hash_buffer("bar");
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .map_create,
            .{ .map_get = foo_key },
            .{ .value = .{ .pointer = try db.writeAtHash(bar_key, "bar", .once) } },
        });

        // read foo
        const bar_value = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = foo_key },
        })).?;
        defer allocator.free(bar_value);
        try std.testing.expectEqualStrings("bar", bar_value);

        // read foo from ctx
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(self: @This(), cursor: *Database(kind).Cursor) !void {
                    const value = (try cursor.readBytesAlloc(self.allocator, void, &[_]PathPart(void){})).?;
                    defer self.allocator.free(value);
                    try std.testing.expectEqualStrings("bar", value);

                    var bar_reader = try cursor.reader();

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
                        try expectEqual('a', try bar_reader.readIntLittle(u8));

                        try bar_reader.seekFromEnd(-3);
                        try expectEqual('b', try bar_reader.readIntLittle(u8));
                    }

                    try expectEqual(false, cursor.is_new);
                }
            };
            try root_cursor.execute(Ctx, &[_]PathPart(Ctx){
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .map_get = main.hash_buffer("foo") },
                .{ .ctx = Ctx{ .allocator = allocator } },
            });
        }

        // write baz with writer
        {
            const Ctx = struct {
                pub fn run(_: @This(), writer: *Database(kind).Writer) !void {
                    try writer.writeAll("x");
                    try writer.writeAll("x");
                    try writer.writeAll("x");
                    try writer.seekBy(-3);
                    try writer.writeAll("b");
                    try writer.seekTo(2);
                    try writer.writeAll("z");
                    try writer.seekFromEnd(-2);
                    try writer.writeAll("a");
                }
            };
            _ = try db.writerAtHash(main.hash_buffer("baz"), Ctx, Ctx{}, .once);
        }

        // if error in ctx, db doesn't change
        {
            const Ctx = struct {
                allocator: std.mem.Allocator,

                pub fn run(_: @This(), cursor: *Database(kind).Cursor) !void {
                    const value = "this value won't be visible";
                    try cursor.execute(void, &[_]PathPart(void){
                        .{ .map_get = main.hash_buffer("foo") },
                        .{ .value = .{ .pointer = try cursor.db.writeAtHash(main.hash_buffer(value), value, .once) } },
                    });
                    return error.NotImplemented;
                }
            };
            root_cursor.execute(Ctx, &[_]PathPart(Ctx){
                .{ .list_get = .append_copy },
                .map_create,
                .{ .ctx = Ctx{ .allocator = allocator } },
            }) catch {};

            // read foo
            const value = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .map_get = foo_key },
            })).?;
            defer allocator.free(value);
            try std.testing.expectEqualStrings("bar", value);
        }

        // read foo into stack-allocated buffer
        var bar_buffer = [_]u8{0} ** 3;
        const bar_buffer_value = (try root_cursor.readBytes(&bar_buffer, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = foo_key },
        })).?;
        try std.testing.expectEqualStrings("bar", bar_buffer_value);

        // overwrite foo
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .map_create,
            .{ .map_get = foo_key },
            .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer("baz"), "baz", .once) } },
        });
        const baz_value = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = foo_key },
        })).?;
        defer allocator.free(baz_value);
        try std.testing.expectEqualStrings("baz", baz_value);

        // can still read the old value
        const bar_value2 = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } },
            .{ .map_get = foo_key },
        })).?;
        defer allocator.free(bar_value2);
        try std.testing.expectEqualStrings("bar", bar_value2);

        // key not found
        const not_found_key = main.hash_buffer("this doesn't exist");
        try expectEqual(null, try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = not_found_key },
        }));

        // write key that conflicts with foo
        var conflict_key = main.hash_buffer("conflict");
        conflict_key = (conflict_key & ~main.MASK) | (foo_key & main.MASK);
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .map_create,
            .{ .map_get = conflict_key },
            .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer("hello"), "hello", .once) } },
        });

        // read conflicting key
        const hello_value = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = conflict_key },
        })).?;
        defer allocator.free(hello_value);
        try std.testing.expectEqualStrings("hello", hello_value);

        // we can still read foo
        const baz_value2 = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = foo_key },
        })).?;
        defer allocator.free(baz_value2);
        try std.testing.expectEqualStrings("baz", baz_value2);

        // overwrite conflicting key
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .map_create,
            .{ .map_get = conflict_key },
            .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer("goodbye"), "goodbye", .once) } },
        });
        const goodbye_value = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = conflict_key },
        })).?;
        defer allocator.free(goodbye_value);
        try std.testing.expectEqualStrings("goodbye", goodbye_value);

        // we can still read the old conflicting key
        const hello_value2 = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } },
            .{ .map_get = conflict_key },
        })).?;
        defer allocator.free(hello_value2);
        try std.testing.expectEqualStrings("hello", hello_value2);

        // write apple
        const fruits_key = main.hash_buffer("fruits");
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .map_create,
            .{ .map_get = fruits_key },
            .list_create,
            .{ .list_get = .append },
            .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer("apple"), "apple", .once) } },
        });

        // read apple
        const apple_value = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = fruits_key },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(apple_value);
        try std.testing.expectEqualStrings("apple", apple_value);

        // write banana
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .map_create,
            .{ .map_get = fruits_key },
            .list_create,
            .{ .list_get = .append },
            .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer("banana"), "banana", .once) } },
        });

        // read banana
        const banana_value = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = fruits_key },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(banana_value);
        try std.testing.expectEqualStrings("banana", banana_value);

        // can't read banana in older list
        try expectEqual(null, try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } },
            .{ .map_get = fruits_key },
            .{ .list_get = .{ .index = .{ .index = 1, .reverse = false } } },
        }));

        // write pear and grape
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .map_create,
            .{ .map_get = fruits_key },
            .list_create,
            .{ .path = &[_]PathPart(void){
                .{ .list_get = .append },
                .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer("pear"), "pear", .once) } },
            } },
            .{ .path = &[_]PathPart(void){
                .{ .list_get = .append },
                .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer("grape"), "grape", .once) } },
            } },
        });

        // read pear
        const pear_value = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = fruits_key },
            .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } },
        })).?;
        defer allocator.free(pear_value);
        try std.testing.expectEqualStrings("pear", pear_value);

        // read grape
        const grape_value = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = fruits_key },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(grape_value);
        try std.testing.expectEqualStrings("grape", grape_value);

        // overwrite foo with an int
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .map_create,
            .{ .map_get = foo_key },
            .{ .value = .{ .uint = 42 } },
        });

        // read foo
        const int_value = try root_cursor.readInt(void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = foo_key },
        });
        try expectEqual(42, int_value);

        // remove foo
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .map_create,
            .{ .map_remove = foo_key },
        });

        // read foo
        try expectEqual(null, try root_cursor.readInt(void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = foo_key },
        }));
    }

    // append to top-level list many times, filling up the list until a root overflow occurs
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

        const wat_key = main.hash_buffer("wat");
        for (0..main.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            try root_cursor.execute(void, &[_]PathPart(void){
                .{ .list_get = .append_copy },
                .map_create,
                .{ .map_get = wat_key },
                .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer(value), value, .once) } },
            });

            const value2 = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .map_get = wat_key },
            })).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }
    }

    // append to inner list many times, filling up the list until a root overflow occurs
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

        for (0..main.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            try root_cursor.execute(void, &[_]PathPart(void){
                .{ .list_get = .append_copy },
                .list_create,
                .{ .list_get = .append },
                .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer(value), value, .once) } },
            });

            const value2 = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            })).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // overwrite last value with hello
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .list_create,
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer("hello"), "hello", .once) } },
        });

        // read last value
        const value = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(value);
        try std.testing.expectEqualStrings("hello", value);

        // overwrite last value with goodbye
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .list_create,
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer("goodbye"), "goodbye", .once) } },
        });

        // read last value
        const value2 = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(value2);
        try std.testing.expectEqualStrings("goodbye", value2);

        // previous last value is still hello
        const value3 = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(value3);
        try std.testing.expectEqualStrings("hello", value3);
    }

    // iterate over inner list
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
            try root_cursor.execute(void, &[_]PathPart(void){
                .{ .list_get = .append_copy },
                .list_create,
                .{ .list_get = .append },
                .{ .value = .{ .pointer = try db.writeAtHash(main.hash_buffer(value), value, .once) } },
            });

            const value2 = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            })).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // iterate over list
        var inner_cursor = (try root_cursor.readCursor(void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        var iter = try inner_cursor.iter(.list);
        defer iter.deinit();
        var i: u64 = 0;
        while (try iter.next()) |*next_cursor| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const value2 = (try next_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){})).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
            i += 1;
        }
        try expectEqual(10, i);
    }

    // iterate over inner map
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
            const wat_key = main.hash_buffer(value);
            try root_cursor.execute(void, &[_]PathPart(void){
                .{ .list_get = .append_copy },
                .map_create,
                .{ .map_get = wat_key },
                .{ .value = .{ .pointer = try db.writeAtHash(wat_key, value, .once) } },
            });

            const value2 = (try root_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .map_get = wat_key },
            })).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // add foo
        const foo_key = main.hash_buffer("foo");
        _ = try db.writeAtHash(foo_key, "foo", .once);
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .map_create,
            .{ .map_get = foo_key },
            .{ .value = .{ .uint = 42 } },
        });

        // remove a wat
        try root_cursor.execute(void, &[_]PathPart(void){
            .{ .list_get = .append_copy },
            .map_create,
            .{ .map_remove = main.hash_buffer("wat0") },
        });

        // iterate over map
        var inner_cursor = (try root_cursor.readCursor(void, &[_]PathPart(void){
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        var iter = try inner_cursor.iter(.map);
        defer iter.deinit();
        var i: u64 = 0;
        while (try iter.next()) |*next_cursor| {
            const value = (try next_cursor.readKeyBytesAlloc(allocator, void, &[_]PathPart(void){})).?;
            defer allocator.free(value);
            if (std.mem.eql(u8, "foo", value)) {
                const value2 = (try next_cursor.readInt(void, &[_]PathPart(void){})).?;
                try expectEqual(42, value2);
            } else {
                const value2 = (try next_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){})).?;
                defer allocator.free(value2);
                try std.testing.expectEqualStrings(value, value2);
            }
            i += 1;
        }
        try expectEqual(10, i);
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
        try writer.writeIntLittle(u64, 42);
        const hello = try std.fmt.allocPrint(allocator, "Hello{s}", .{std.mem.asBytes(&std.mem.nativeToLittle(u64, 42))});
        defer allocator.free(hello);
        try std.testing.expectEqualStrings(hello, db.core.buffer.items[0..13]);

        var reader = db.core.reader();
        try db.core.seekTo(0);
        var block = [_]u8{0} ** 5;
        try reader.readNoEof(&block);
        try std.testing.expectEqualStrings("Hello", &block);
        try expectEqual(42, reader.readIntLittle(u64));
    }
}
