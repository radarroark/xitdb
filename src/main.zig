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

    pub fn write(self: *Database, key: [HASH_SIZE]u8, value: []const u8, key_offset: u32, index_position: u64) !void {
        if (key_offset >= HASH_SIZE) {
            return error.KeyOffsetExceeded;
        }

        const digit = key[key_offset];
        const ptr_pos = index_position + (POINTER_SIZE * digit);
        try self.db_file.seekTo(ptr_pos);

        const reader = self.db_file.reader();
        const ptr = try reader.readIntNative(u64);

        const writer = self.db_file.writer();

        if (ptr == 0) {
            try self.db_file.seekFromEnd(0);
            const value_pos = try self.db_file.getPos();
            try writer.writeAll(&key);
            try writer.writeIntNative(u64, value.len);
            try writer.writeAll(value);
            try self.db_file.seekTo(ptr_pos);
            try writer.writeIntNative(u64, setPointerType(value_pos, PointerType.plain));
            return;
        }

        return error.NotImplemented;
    }

    pub fn read(self: *Database, key: [HASH_SIZE]u8, key_offset: u32, index_position: u64) ![]u8 {
        const digit = @as(u64, key[key_offset]);
        const ptr_pos = index_position + (POINTER_SIZE * digit);
        try self.db_file.seekTo(ptr_pos);

        const reader = self.db_file.reader();
        const ptr_and_type = try reader.readIntNative(u64);

        if (ptr_and_type == 0) {
            return error.KeyNotFound;
        }

        const ptr_type = getPointerType(ptr_and_type);
        const ptr = getPointerValue(ptr_and_type);

        switch (ptr_type) {
            .plain => {
                try self.db_file.seekTo(ptr);
                var hash = [_]u8{0} ** HASH_SIZE;
                try reader.readNoEof(&hash);
                if (std.mem.eql(u8, &hash, &key)) {
                    const value_len = try reader.readIntNative(u64);
                    return try reader.readAllAlloc(self.allocator, value_len);
                } else {
                    return error.NotImplemented;
                }
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

test "add records to a database" {
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
    const value = try db.read(foo_key, 0, HEADER_BLOCK_SIZE);
    defer allocator.free(value);
    try std.testing.expectEqualStrings("bar", value);

    // key not found
    var not_key = [_]u8{0} ** HASH_SIZE;
    try hash_buffer("this doesn't exist", &not_key);
    try expectEqual(error.KeyNotFound, db.read(not_key, 0, HEADER_BLOCK_SIZE));

    // key conflicts with foo at first byte
    var conflict_key = [_]u8{0} ** HASH_SIZE;
    conflict_key[0] = foo_key[0];
    try expectEqual(error.NotImplemented, db.write(conflict_key, "bar", 0, HEADER_BLOCK_SIZE));
    try expectEqual(error.NotImplemented, db.read(conflict_key, 0, HEADER_BLOCK_SIZE));
}
