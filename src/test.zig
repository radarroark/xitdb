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
        var cursor = db.rootCursor();

        // write foo
        const foo_key = main.hash_buffer("foo");
        try cursor.writePath(&[_]PathPart{
            .{ .list_get = .append_copy },
            .{ .map_get = foo_key },
            .{ .value = .{ .bytes = "bar" } },
        });

        // read foo
        const bar_value = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = foo_key },
        })).?;
        defer allocator.free(bar_value);
        try std.testing.expectEqualStrings("bar", bar_value);

        // overwrite foo
        try cursor.writePath(&[_]PathPart{
            .{ .list_get = .append_copy },
            .{ .map_get = foo_key },
            .{ .value = .{ .bytes = "baz" } },
        });
        const baz_value = (try cursor.readBytes(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .map_get = foo_key } })).?;
        defer allocator.free(baz_value);
        try std.testing.expectEqualStrings("baz", baz_value);

        // can still read the old value
        const bar_value2 = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } },
            .{ .map_get = foo_key },
        })).?;
        defer allocator.free(bar_value2);
        try std.testing.expectEqualStrings("bar", bar_value2);

        // key not found
        const not_found_key = main.hash_buffer("this doesn't exist");
        try expectEqual(null, try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = not_found_key },
        }));

        // write key that conflicts with foo
        var conflict_key = main.hash_buffer("conflict");
        conflict_key = (conflict_key & ~main.MASK) | (foo_key & main.MASK);
        try cursor.writePath(&[_]PathPart{
            .{ .list_get = .append_copy },
            .{ .map_get = conflict_key },
            .{ .value = .{ .bytes = "hello" } },
        });

        // read conflicting key
        const hello_value = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = conflict_key },
        })).?;
        defer allocator.free(hello_value);
        try std.testing.expectEqualStrings("hello", hello_value);

        // we can still read foo
        const baz_value2 = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = foo_key },
        })).?;
        defer allocator.free(baz_value2);
        try std.testing.expectEqualStrings("baz", baz_value2);

        // overwrite conflicting key
        try cursor.writePath(&[_]PathPart{
            .{ .list_get = .append_copy },
            .{ .map_get = conflict_key },
            .{ .value = .{ .bytes = "goodbye" } },
        });
        const goodbye_value = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = conflict_key },
        })).?;
        defer allocator.free(goodbye_value);
        try std.testing.expectEqualStrings("goodbye", goodbye_value);

        // we can still read the old conflicting key
        const hello_value2 = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } },
            .{ .map_get = conflict_key },
        })).?;
        defer allocator.free(hello_value2);
        try std.testing.expectEqualStrings("hello", hello_value2);

        // write apple
        const fruits_key = main.hash_buffer("fruits");
        try cursor.writePath(&[_]PathPart{
            .{ .list_get = .append_copy },
            .{ .map_get = fruits_key },
            .{ .list_get = .append },
            .{ .value = .{ .bytes = "apple" } },
        });

        // read apple
        const apple_value = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = fruits_key },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(apple_value);
        try std.testing.expectEqualStrings("apple", apple_value);

        // write banana
        try cursor.writePath(&[_]PathPart{
            .{ .list_get = .append_copy },
            .{ .map_get = fruits_key },
            .{ .list_get = .append },
            .{ .value = .{ .bytes = "banana" } },
        });

        // read banana
        const banana_value = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = fruits_key },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(banana_value);
        try std.testing.expectEqualStrings("banana", banana_value);

        // can't read banana in older list
        try expectEqual(null, try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } },
            .{ .map_get = fruits_key },
            .{ .list_get = .{ .index = .{ .index = 1, .reverse = false } } },
        }));

        // write pear and grape
        try cursor.writePath(&[_]PathPart{
            .{ .list_get = .append_copy },
            .{ .map_get = fruits_key },
            .{ .path = &[_]PathPart{ .{ .list_get = .append }, .{ .value = .{ .bytes = "pear" } } } },
            .{ .path = &[_]PathPart{ .{ .list_get = .append }, .{ .value = .{ .bytes = "grape" } } } },
        });

        // read pear
        const pear_value = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = fruits_key },
            .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } },
        })).?;
        defer allocator.free(pear_value);
        try std.testing.expectEqualStrings("pear", pear_value);

        // read grape
        const grape_value = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = fruits_key },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(grape_value);
        try std.testing.expectEqualStrings("grape", grape_value);

        // overwrite foo with an int
        try cursor.writePath(&[_]PathPart{
            .{ .list_get = .append_copy },
            .{ .map_get = foo_key },
            .{ .value = .{ .int = 42 } },
        });

        // read foo
        const int_value = try cursor.readInt(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .map_get = foo_key },
        });
        try expectEqual(42, int_value);

        // remove foo
        try cursor.writePath(&[_]PathPart{
            .{ .list_get = .append_copy },
            .{ .map_get = foo_key },
            .{ .value = .none },
        });

        // read foo
        try expectEqual(null, try cursor.readInt(&[_]PathPart{
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
        var cursor = db.rootCursor();

        const wat_key = main.hash_buffer("wat");
        for (0..main.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            try cursor.writePath(&[_]PathPart{
                .{ .list_get = .append_copy },
                .{ .map_get = wat_key },
                .{ .value = .{ .bytes = value } },
            });

            const value2 = (try cursor.readBytes(&[_]PathPart{
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
        var cursor = db.rootCursor();

        for (0..main.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            try cursor.writePath(&[_]PathPart{
                .{ .list_get = .append_copy },
                .{ .list_get = .append },
                .{ .value = .{ .bytes = value } },
            });

            const value2 = (try cursor.readBytes(&[_]PathPart{
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            })).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // overwrite last value with hello
        try cursor.writePath(&[_]PathPart{
            .{ .list_get = .append_copy },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .value = .{ .bytes = "hello" } },
        });

        // read last value
        const value = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(value);
        try std.testing.expectEqualStrings("hello", value);

        // overwrite last value with goodbye
        try cursor.writePath(&[_]PathPart{
            .{ .list_get = .append_copy },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .value = .{ .bytes = "goodbye" } },
        });

        // read last value
        const value2 = (try cursor.readBytes(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        defer allocator.free(value2);
        try std.testing.expectEqualStrings("goodbye", value2);

        // previous last value is still hello
        const value3 = (try cursor.readBytes(&[_]PathPart{
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
        var cursor = db.rootCursor();

        for (0..main.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            try cursor.writePath(&[_]PathPart{
                .{ .list_get = .append_copy },
                .{ .list_get = .append },
                .{ .value = .{ .bytes = value } },
            });

            const value2 = (try cursor.readBytes(&[_]PathPart{
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
            })).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        var inner_cursor = (try cursor.readCursor(&[_]PathPart{
            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
        })).?;
        var iter = try inner_cursor.iter(.list);
        var i: u64 = 0;
        while (try iter.next()) |*next_cursor| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            const value2 = (try next_cursor.readBytes(&[_]PathPart{})).?;
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);

            i += 1;
        }
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
