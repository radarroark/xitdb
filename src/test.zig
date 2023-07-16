const std = @import("std");
const main = @import("./main.zig");
const Database = main.Database;
const DatabaseKind = main.DatabaseKind;
const PathPart = main.PathPart;

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

fn testMain(allocator: std.mem.Allocator, comptime kind: DatabaseKind, opts: Database(kind).InitOpts) !void {
    // list of maps
    {
        var db = try Database(kind).init(allocator, opts);
        defer if (kind == .file) opts.dir.deleteFile(opts.path) catch {};
        defer db.deinit();

        // write foo
        const foo_key = main.hash_buffer("foo");
        try db.writePath(&[_]PathPart{ .{ .list_get = .append_copy }, .{ .map_get = foo_key } }, "bar");

        // read foo
        const bar_value = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .map_get = foo_key } });
        defer allocator.free(bar_value);
        try std.testing.expectEqualStrings("bar", bar_value);

        // overwrite foo
        try db.writePath(&[_]PathPart{ .{ .list_get = .append_copy }, .{ .map_get = foo_key } }, "baz");
        const baz_value = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .map_get = foo_key } });
        defer allocator.free(baz_value);
        try std.testing.expectEqualStrings("baz", baz_value);

        // can still read the old value
        const bar_value2 = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } }, .{ .map_get = foo_key } });
        defer allocator.free(bar_value2);
        try std.testing.expectEqualStrings("bar", bar_value2);

        // key not found
        const not_found_key = main.hash_buffer("this doesn't exist");
        try expectEqual(error.KeyNotFound, db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .map_get = not_found_key } }));

        // write key that conflicts with foo
        var conflict_key = main.hash_buffer("conflict");
        conflict_key = (conflict_key & ~main.MASK) | (foo_key & main.MASK);
        try db.writePath(&[_]PathPart{ .{ .list_get = .append_copy }, .{ .map_get = conflict_key } }, "hello");

        // read conflicting key
        const hello_value = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .map_get = conflict_key } });
        defer allocator.free(hello_value);
        try std.testing.expectEqualStrings("hello", hello_value);

        // we can still read foo
        const baz_value2 = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .map_get = foo_key } });
        defer allocator.free(baz_value2);
        try std.testing.expectEqualStrings("baz", baz_value2);

        // overwrite conflicting key
        try db.writePath(&[_]PathPart{ .{ .list_get = .append_copy }, .{ .map_get = conflict_key } }, "goodbye");
        const goodbye_value = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .map_get = conflict_key } });
        defer allocator.free(goodbye_value);
        try std.testing.expectEqualStrings("goodbye", goodbye_value);

        // we can still read the old conflicting key
        const hello_value2 = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } }, .{ .map_get = conflict_key } });
        defer allocator.free(hello_value2);
        try std.testing.expectEqualStrings("hello", hello_value2);

        // write apple
        const fruits_key = main.hash_buffer("fruits");
        try db.writePath(&[_]PathPart{ .{ .list_get = .append_copy }, .{ .map_get = fruits_key }, .{ .list_get = .append } }, "apple");

        // read apple
        const apple_value = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .map_get = fruits_key }, .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } } });
        defer allocator.free(apple_value);
        try std.testing.expectEqualStrings("apple", apple_value);

        // write banana
        try db.writePath(&[_]PathPart{ .{ .list_get = .append_copy }, .{ .map_get = fruits_key }, .{ .list_get = .append } }, "banana");

        // read banana
        const banana_value = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .map_get = fruits_key }, .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } } });
        defer allocator.free(banana_value);
        try std.testing.expectEqualStrings("banana", banana_value);

        // can't read banana in older list
        try expectEqual(error.KeyNotFound, db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } }, .{ .map_get = fruits_key }, .{ .list_get = .{ .index = .{ .index = 1, .reverse = false } } } }));
    }

    // append to top-level list many times, filling up the list until a root overflow occurs
    {
        var db = try Database(kind).init(allocator, opts);
        defer if (kind == .file) opts.dir.deleteFile(opts.path) catch {};
        defer db.deinit();

        const wat_key = main.hash_buffer("wat");
        for (0..main.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            try db.writePath(&[_]PathPart{ .{ .list_get = .append_copy }, .{ .map_get = wat_key } }, value);

            const value2 = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .map_get = wat_key } });
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }
    }

    // append to inner list many times, filling up the list until a root overflow occurs
    {
        var db = try Database(kind).init(allocator, opts);
        defer if (kind == .file) opts.dir.deleteFile(opts.path) catch {};
        defer db.deinit();

        for (0..main.SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            try db.writePath(&[_]PathPart{ .{ .list_get = .append_copy }, .{ .list_get = .append } }, value);

            const value2 = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } } });
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }

        // overwrite last value with hello
        try db.writePath(&[_]PathPart{ .{ .list_get = .append_copy }, .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } } }, "hello");

        // read last value
        const value = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } } });
        defer allocator.free(value);
        try std.testing.expectEqualStrings("hello", value);

        // overwrite last value with goodbye
        try db.writePath(&[_]PathPart{ .{ .list_get = .append_copy }, .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } } }, "goodbye");

        // read last value
        const value2 = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } }, .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } } });
        defer allocator.free(value2);
        try std.testing.expectEqualStrings("goodbye", value2);

        // previous last value is still hello
        const value3 = try db.readPath(&[_]PathPart{ .{ .list_get = .{ .index = .{ .index = 1, .reverse = true } } }, .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } } });
        defer allocator.free(value3);
        try std.testing.expectEqualStrings("hello", value3);
    }
}

test "read and write" {
    const allocator = std.testing.allocator;

    try testMain(allocator, .memory, Database(.memory).InitOpts{
        .capacity = 10000,
    });

    try testMain(allocator, .file, Database(.file).InitOpts{
        .dir = std.fs.cwd(),
        .path = "main.db",
    });

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
