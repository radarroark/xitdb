//! you're looking at radar's hopeless attempt to implement
//! his dream database. it will be embedded, immutable, and
//! reactive, and will be practical for both on-disk and
//! in-memory use. there is so much work to do, and so much
//! to learn. we're gonna leeroy jenkins our way through this.

const std = @import("std");

// using sha1 to hash the keys for now, but this will eventually be
// configurable. for many uses it will be overkill...
pub const HASH_SIZE = std.crypto.hash.Sha1.digest_length;
pub fn hash_buffer(buffer: []const u8, out: *[HASH_SIZE]u8) !void {
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(buffer);
    h.final(out);
}

const POINTER_SIZE: comptime_int = @sizeOf(u64);
const HEADER_BLOCK_SIZE: comptime_int = 2;
const INDEX_BLOCK_SIZE: comptime_int = POINTER_SIZE * 256;

const PointerType = enum(u64) {
    plain = (0b00 << 62),
    index = (0b01 << 62),
    start = (0b10 << 62),
    chain = (0b11 << 62),
};

const TYPE_MASK: u64 = (0b11 << 62);

pub fn setPointerType(ptr: u64, ptr_type: PointerType) u64 {
    return ptr | @enumToInt(ptr_type);
}

pub fn getPointerType(ptr: u64) PointerType {
    return @intToEnum(PointerType, ptr & TYPE_MASK);
}

pub fn getPointerValue(ptr: u64) u64 {
    return ptr & (~TYPE_MASK);
}

pub const DatabaseError = error{
    NotImplemented,
    KeyOffsetExceeded,
    KeyNotFound,
};

pub const Database = struct {
    allocator: std.mem.Allocator,
    db_file: std.fs.File,

    pub fn init(allocator: std.mem.Allocator, dir: std.fs.Dir, path: []const u8) !Database {
        // create or open file
        const file_or_err = dir.openFile(path, .{ .mode = .read_write });
        const file = try if (file_or_err == error.FileNotFound)
            dir.createFile(path, .{ .read = true })
        else
            file_or_err;
        errdefer file.close();

        const meta = try file.metadata();
        const size = meta.size();
        const reader = file.reader();
        const writer = file.writer();

        var header_block = [_]u8{0} ** HEADER_BLOCK_SIZE;
        var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;

        if (size == 0) {
            try writer.writeAll(&header_block);
            try writer.writeAll(&index_block);
        } else {
            try reader.readNoEof(&header_block);
            try reader.readNoEof(&index_block);
        }

        return Database{
            .allocator = allocator,
            .db_file = file,
        };
    }

    pub fn deinit(self: *Database) void {
        self.db_file.close();
    }

    pub fn write(self: *Database, key: [HASH_SIZE]u8, value: []const u8, key_offset: u32, index_pos: u64) !void {
        if (key_offset >= HASH_SIZE) {
            return error.KeyOffsetExceeded;
        }

        const reader = self.db_file.reader();
        const writer = self.db_file.writer();

        const digit = @as(u64, key[key_offset]);
        const slot_pos = index_pos + (POINTER_SIZE * digit);
        try self.db_file.seekTo(slot_pos);
        const slot = try reader.readIntNative(u64);

        if (slot == 0) {
            try self.db_file.seekFromEnd(0);
            const value_pos = try self.db_file.getPos();
            try writer.writeAll(&key);
            try writer.writeIntNative(u64, value.len);
            try writer.writeAll(value);
            try self.db_file.seekTo(slot_pos);
            try writer.writeIntNative(u64, setPointerType(value_pos, PointerType.plain));
            return;
        }

        const ptr_type = getPointerType(slot);
        const ptr = getPointerValue(slot);

        switch (ptr_type) {
            .plain => {
                try self.db_file.seekTo(ptr);
                var existing_key = [_]u8{0} ** HASH_SIZE;
                try reader.readNoEof(&existing_key);
                if (std.mem.eql(u8, &existing_key, &key)) {
                    return error.NotImplemented;
                }

                // append new index block
                if (key_offset + 1 >= HASH_SIZE) {
                    return error.KeyOffsetExceeded;
                }
                const next_digit = @as(u64, existing_key[key_offset + 1]);
                try self.db_file.seekFromEnd(0);
                const new_index_pos = try self.db_file.getPos();
                var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                try writer.writeAll(&index_block);
                try self.db_file.seekTo(new_index_pos + (POINTER_SIZE * next_digit));
                try writer.writeIntNative(u64, slot);
                try self.db_file.seekTo(slot_pos);
                try writer.writeIntNative(u64, setPointerType(new_index_pos, .index));
                try self.write(key, value, key_offset + 1, new_index_pos);

                return;
            },
            else => {
                return error.NotImplemented;
            },
        }
    }

    pub fn read(self: *Database, key: [HASH_SIZE]u8, key_offset: u32, index_pos: u64) ![]u8 {
        if (key_offset >= HASH_SIZE) {
            return error.KeyOffsetExceeded;
        }

        const reader = self.db_file.reader();

        const digit = @as(u64, key[key_offset]);
        const slot_pos = index_pos + (POINTER_SIZE * digit);
        try self.db_file.seekTo(slot_pos);
        const slot = try reader.readIntNative(u64);

        if (slot == 0) {
            return error.KeyNotFound;
        }

        const ptr_type = getPointerType(slot);
        const ptr = getPointerValue(slot);

        switch (ptr_type) {
            .plain => {
                try self.db_file.seekTo(ptr);
                var existing_key = [_]u8{0} ** HASH_SIZE;
                try reader.readNoEof(&existing_key);
                if (std.mem.eql(u8, &existing_key, &key)) {
                    const value_len = try reader.readIntNative(u64);
                    var value = try self.allocator.alloc(u8, value_len);
                    errdefer self.allocator.free(value);
                    try reader.readNoEof(value);
                    return value;
                } else {
                    return error.KeyNotFound;
                }
            },
            .index => {
                return self.read(key, key_offset + 1, ptr);
            },
            else => {
                return error.NotImplemented;
            },
        }
    }
};

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

test "get/set pointer type" {
    const ptr_plain = setPointerType(42, .plain);
    try expectEqual(PointerType.plain, getPointerType(ptr_plain));
    const ptr_index = setPointerType(42, .index);
    try expectEqual(PointerType.index, getPointerType(ptr_index));
    const ptr_start = setPointerType(42, .start);
    try expectEqual(PointerType.start, getPointerType(ptr_start));
    const ptr_chain = setPointerType(42, .chain);
    try expectEqual(PointerType.chain, getPointerType(ptr_chain));
}

test "read and write" {
    const allocator = std.testing.allocator;
    const cwd = std.fs.cwd();
    const db_path = "main.db";
    defer cwd.deleteFile(db_path) catch {};

    var db = try Database.init(allocator, cwd, db_path);
    defer db.deinit();

    // write foo
    var foo_key = [_]u8{0} ** HASH_SIZE;
    try hash_buffer("foo", &foo_key);
    try db.write(foo_key, "bar", 0, HEADER_BLOCK_SIZE);

    // read foo
    const bar_value = try db.read(foo_key, 0, HEADER_BLOCK_SIZE);
    defer allocator.free(bar_value);
    try std.testing.expectEqualStrings("bar", bar_value);

    // key not found
    var not_key = [_]u8{0} ** HASH_SIZE;
    try hash_buffer("this doesn't exist", &not_key);
    try expectEqual(error.KeyNotFound, db.read(not_key, 0, HEADER_BLOCK_SIZE));

    // write key that conflicts with foo at first byte
    var conflict_key = [_]u8{0} ** HASH_SIZE;
    try hash_buffer("conflict", &conflict_key);
    conflict_key[0] = foo_key[0]; // intentionally make it conflict
    try db.write(conflict_key, "hello", 0, HEADER_BLOCK_SIZE);

    // read conflicting key
    const hello_value = try db.read(conflict_key, 0, HEADER_BLOCK_SIZE);
    defer allocator.free(hello_value);
    try std.testing.expectEqualStrings("hello", hello_value);

    // we can still read foo
    const bar_value2 = try db.read(foo_key, 0, HEADER_BLOCK_SIZE);
    defer allocator.free(bar_value2);
    try std.testing.expectEqualStrings("bar", bar_value2);
}
