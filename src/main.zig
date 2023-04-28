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

const POINTER_SIZE = @sizeOf(u64);
const HEADER_BLOCK_SIZE = 2;
const SLOT_COUNT = 256;
const BIT_COUNT = 8;
const MASK = SLOT_COUNT - 1;
const INDEX_BLOCK_SIZE = POINTER_SIZE * SLOT_COUNT;
const KEY_INDEX_START = HEADER_BLOCK_SIZE;
const VALUE_INDEX_START = KEY_INDEX_START + INDEX_BLOCK_SIZE;
const LIST_INDEX_START = VALUE_INDEX_START + INDEX_BLOCK_SIZE;

const PointerType = enum(u64) {
    value = (0b00 << 62),
    index = (0b01 << 62),
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
        var key_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
        var value_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;

        // this is temporary, so we can test list stuff
        var list_size: u64 = 0;
        var list_ptr: u64 = 0;
        var list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;

        if (size == 0) {
            try writer.writeAll(&header_block);
            try writer.writeAll(&key_index_block);
            try writer.writeAll(&value_index_block);
            try writer.writeIntLittle(u64, list_size);
            list_ptr = try file.getPos() + POINTER_SIZE;
            try writer.writeIntLittle(u64, list_ptr);
            try writer.writeAll(&list_index_block);
        } else {
            try reader.readNoEof(&header_block);
            try reader.readNoEof(&key_index_block);
            try reader.readNoEof(&value_index_block);
            list_size = try reader.readIntLittle(u64);
            list_ptr = try reader.readIntLittle(u64);
            try file.seekTo(list_ptr);
            try reader.readNoEof(&list_index_block);
        }

        return Database{
            .allocator = allocator,
            .db_file = file,
        };
    }

    pub fn deinit(self: *Database) void {
        self.db_file.close();
    }

    pub fn write(self: *Database, key: []const u8, value: []const u8) !void {
        var key_hash = [_]u8{0} ** HASH_SIZE;
        try hash_buffer(key, &key_hash);
        try self.writeMap(key_hash, value);
    }

    pub fn read(self: *Database, key: []const u8) ![]u8 {
        var key_hash = [_]u8{0} ** HASH_SIZE;
        try hash_buffer(key, &key_hash);
        return self.readMap(key_hash);
    }

    // maps

    fn writeMap(self: *Database, key_hash: [HASH_SIZE]u8, value: []const u8) !void {
        var value_hash = [_]u8{0} ** HASH_SIZE;
        try hash_buffer(value, &value_hash);
        const value_pos = try self.writeMapInner(value_hash, value.len, value, VALUE_INDEX_START, 0);
        _ = try self.writeMapInner(key_hash, value_pos, null, KEY_INDEX_START, 0);
    }

    fn writeMapInner(self: *Database, key_hash: [HASH_SIZE]u8, value: u64, blob_maybe: ?[]const u8, index_pos: u64, key_offset: u32) !u64 {
        if (key_offset >= HASH_SIZE) {
            return error.KeyOffsetExceeded;
        }

        const reader = self.db_file.reader();
        const writer = self.db_file.writer();

        const digit = @as(u64, key_hash[key_offset]);
        const slot_pos = index_pos + (POINTER_SIZE * digit);
        try self.db_file.seekTo(slot_pos);
        const slot = try reader.readIntLittle(u64);

        if (slot == 0) {
            try self.db_file.seekFromEnd(0);
            const value_pos = try self.db_file.getPos();
            try writer.writeAll(&key_hash);
            try writer.writeIntLittle(u64, value);
            if (blob_maybe) |blob| {
                try writer.writeAll(blob);
            }
            try self.db_file.seekTo(slot_pos);
            try writer.writeIntLittle(u64, setPointerType(value_pos, .value));
            return value_pos;
        }

        const ptr_type = getPointerType(slot);
        const ptr = getPointerValue(slot);

        switch (ptr_type) {
            .value => {
                try self.db_file.seekTo(ptr);
                var existing_key_hash = [_]u8{0} ** HASH_SIZE;
                try reader.readNoEof(&existing_key_hash);
                if (std.mem.eql(u8, &existing_key_hash, &key_hash)) {
                    if (blob_maybe) |_| {
                        return ptr;
                    } else {
                        return error.NotImplemented;
                    }
                }

                // append new index block
                if (key_offset + 1 >= HASH_SIZE) {
                    return error.KeyOffsetExceeded;
                }
                const next_digit = @as(u64, existing_key_hash[key_offset + 1]);
                try self.db_file.seekFromEnd(0);
                const next_index_pos = try self.db_file.getPos();
                var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                try writer.writeAll(&index_block);
                try self.db_file.seekTo(next_index_pos + (POINTER_SIZE * next_digit));
                try writer.writeIntLittle(u64, slot);
                const next_pos = try self.writeMapInner(key_hash, value, blob_maybe, next_index_pos, key_offset + 1);
                try self.db_file.seekTo(slot_pos);
                try writer.writeIntLittle(u64, setPointerType(next_index_pos, .index));
                return next_pos;
            },
            .index => {
                return error.NotImplemented;
            },
        }
    }

    fn readMap(self: *Database, key_hash: [HASH_SIZE]u8) ![]u8 {
        const value_pos = try self.readMapInner(key_hash, KEY_INDEX_START, 0);
        try self.db_file.seekTo(value_pos + HASH_SIZE);

        const reader = self.db_file.reader();
        const value_size = try reader.readIntLittle(u64);

        var value = try self.allocator.alloc(u8, value_size);
        errdefer self.allocator.free(value);
        try reader.readNoEof(value);
        return value;
    }

    fn readMapInner(self: *Database, key_hash: [HASH_SIZE]u8, index_pos: u64, key_offset: u32) !u64 {
        if (key_offset >= HASH_SIZE) {
            return error.KeyOffsetExceeded;
        }

        const reader = self.db_file.reader();

        const digit = @as(u64, key_hash[key_offset]);
        const slot_pos = index_pos + (POINTER_SIZE * digit);
        try self.db_file.seekTo(slot_pos);
        const slot = try reader.readIntLittle(u64);

        if (slot == 0) {
            return error.KeyNotFound;
        }

        const ptr_type = getPointerType(slot);
        const ptr = getPointerValue(slot);

        switch (ptr_type) {
            .value => {
                try self.db_file.seekTo(ptr);
                var existing_key_hash = [_]u8{0} ** HASH_SIZE;
                try reader.readNoEof(&existing_key_hash);
                if (std.mem.eql(u8, &existing_key_hash, &key_hash)) {
                    return try reader.readIntLittle(u64);
                } else {
                    return error.KeyNotFound;
                }
            },
            .index => {
                return self.readMapInner(key_hash, ptr, key_offset + 1);
            },
        }
    }

    // lists

    fn writeList(self: *Database, value: u64, blob_maybe: ?[]const u8) !u64 {
        const reader = self.db_file.reader();
        const writer = self.db_file.writer();

        try self.db_file.seekTo(LIST_INDEX_START);
        const key = try reader.readIntLittle(u64);
        const index_pos = try reader.readIntLittle(u64);

        const prev_shift = @truncate(u6, if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key - 1));
        const next_shift = @truncate(u6, if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key));

        if (prev_shift != next_shift) {
            // root overflow
            try self.db_file.seekFromEnd(0);
            const next_index_pos = try self.db_file.getPos();
            var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
            try writer.writeAll(&index_block);
            try self.db_file.seekTo(next_index_pos);
            try writer.writeIntLittle(u64, index_pos);
            const next_pos = try self.writeListInner(value, blob_maybe, next_index_pos, key, next_shift);
            try self.db_file.seekTo(LIST_INDEX_START);
            try writer.writeIntLittle(u64, key + 1);
            try writer.writeIntLittle(u64, next_index_pos);
            return next_pos;
        } else {
            const next_pos = try self.writeListInner(value, blob_maybe, index_pos, key, next_shift);
            try self.db_file.seekTo(LIST_INDEX_START);
            try writer.writeIntLittle(u64, key + 1);
            return next_pos;
        }
    }

    fn writeListInner(self: *Database, value: u64, blob_maybe: ?[]const u8, index_pos: u64, key: u64, shift: u6) !u64 {
        const reader = self.db_file.reader();
        const writer = self.db_file.writer();

        const i = (key >> (shift * BIT_COUNT)) & MASK;
        const ptr_pos = index_pos + (POINTER_SIZE * i);
        try self.db_file.seekTo(ptr_pos);
        const ptr = try reader.readIntLittle(u64);

        if (shift == 0) {
            try self.db_file.seekFromEnd(0);
            const value_pos = try self.db_file.getPos();
            try writer.writeIntLittle(u64, value);
            if (blob_maybe) |blob| {
                try writer.writeAll(blob);
            }
            try self.db_file.seekTo(ptr_pos);
            try writer.writeIntLittle(u64, value_pos);
            return value_pos;
        } else {
            if (ptr == 0) {
                try self.db_file.seekFromEnd(0);
                const next_index_pos = try self.db_file.getPos();
                var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                try writer.writeAll(&index_block);
                try self.db_file.seekTo(ptr_pos);
                try writer.writeIntLittle(u64, next_index_pos);
                return try self.writeListInner(value, blob_maybe, next_index_pos, key, shift - 1);
            } else {
                return try self.writeListInner(value, blob_maybe, ptr, key, shift - 1);
            }
        }
    }

    fn readList(self: *Database, key: u64) ![]u8 {
        const reader = self.db_file.reader();

        try self.db_file.seekTo(LIST_INDEX_START);
        const size = try reader.readIntLittle(u64);

        if (key < 0 or key >= size) {
            return error.KeyNotFound;
        }

        const index_pos = try reader.readIntLittle(u64);

        const shift = @truncate(u6, if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key));
        const value_size = try self.readListInner(index_pos, key, shift);

        var value = try self.allocator.alloc(u8, value_size);
        errdefer self.allocator.free(value);

        try reader.readNoEof(value);
        return value;
    }

    fn readListInner(self: *Database, index_pos: u64, key: u64, shift: u6) !u64 {
        const reader = self.db_file.reader();

        const i = (key >> (shift * BIT_COUNT)) & MASK;
        const ptr_pos = index_pos + (POINTER_SIZE * i);
        try self.db_file.seekTo(ptr_pos);
        const ptr = try reader.readIntLittle(u64);

        if (ptr == 0) {
            return error.KeyNotFound;
        }

        if (shift == 0) {
            try self.db_file.seekTo(ptr);
            return try reader.readIntLittle(u64);
        } else {
            return self.readListInner(ptr, key, shift - 1);
        }
    }
};

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

test "get/set pointer type" {
    const ptr_value = setPointerType(42, .value);
    try expectEqual(PointerType.value, getPointerType(ptr_value));
    const ptr_index = setPointerType(42, .index);
    try expectEqual(PointerType.index, getPointerType(ptr_index));
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
    try db.writeMap(foo_key, "bar");

    // read foo
    const bar_value = try db.readMap(foo_key);
    defer allocator.free(bar_value);
    try std.testing.expectEqualStrings("bar", bar_value);

    // key not found
    try expectEqual(error.KeyNotFound, db.read("this doesn't exist"));

    // write key that conflicts with foo at first byte
    var conflict_key = [_]u8{0} ** HASH_SIZE;
    try hash_buffer("conflict", &conflict_key);
    conflict_key[0] = foo_key[0]; // intentionally make it conflict
    try db.writeMap(conflict_key, "hello");

    // read conflicting key
    const hello_value = try db.readMap(conflict_key);
    defer allocator.free(hello_value);
    try std.testing.expectEqualStrings("hello", hello_value);

    // we can still read foo
    const bar_value2 = try db.read("foo");
    defer allocator.free(bar_value2);
    try std.testing.expectEqualStrings("bar", bar_value2);

    for (0..257) |i| {
        const value = try std.fmt.allocPrint(allocator, "foo{}", .{i});
        defer allocator.free(value);
        _ = try db.writeList(value.len, value);
        const value2 = try db.readList(i);
        defer allocator.free(value2);
        try std.testing.expectEqualStrings(value, value2);
    }
}
