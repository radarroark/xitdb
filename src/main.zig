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

const PointerType = enum(u64) {
    index = 0 << 63,
    value = 1 << 63,
};

const POINTER_TYPE_MASK: u64 = 0b1 << 63;

const ValueType = enum(u64) {
    map = 0b00 << 61,
    list = 0b01 << 61,
    int64 = 0b10 << 61,
    bytes = 0b11 << 61,
};

const VALUE_TYPE_MASK: u64 = 0b11 << 61;

pub fn setType(ptr: u64, ptr_type: PointerType, value_type_maybe: ?ValueType) u64 {
    switch (ptr_type) {
        .index => return ptr | @enumToInt(ptr_type),
        .value => {
            if (value_type_maybe) |value_type| {
                return ptr | @enumToInt(ptr_type) | @enumToInt(value_type);
            } else {
                return ptr | @enumToInt(ptr_type);
            }
        },
    }
}

pub fn getPointerType(ptr: u64) PointerType {
    return @intToEnum(PointerType, ptr & POINTER_TYPE_MASK);
}

pub fn getValueType(ptr: u64) ValueType {
    return @intToEnum(ValueType, ptr & VALUE_TYPE_MASK);
}

pub fn getPointer(ptr: u64) u64 {
    return ptr & (~POINTER_TYPE_MASK) & (~VALUE_TYPE_MASK);
}

pub const DatabaseError = error{
    NotImplemented,
    KeyOffsetExceeded,
    KeyNotFound,
    UnexpectedPointerType,
    UnexpectedValueType,
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

        if (size == 0) {
            try writer.writeAll(&header_block);
            try writer.writeAll(&key_index_block);
            try writer.writeAll(&value_index_block);
        } else {
            try reader.readNoEof(&header_block);
            try reader.readNoEof(&key_index_block);
            try reader.readNoEof(&value_index_block);
        }

        return Database{
            .allocator = allocator,
            .db_file = file,
        };
    }

    pub fn deinit(self: *Database) void {
        self.db_file.close();
    }

    fn writeValue(self: *Database, value: []const u8) !u64 {
        var value_hash = [_]u8{0} ** HASH_SIZE;
        try hash_buffer(value, &value_hash);

        var slot: u64 = 0;
        const slot_pos = try self.readMapSlot(value_hash, VALUE_INDEX_START, 0, true, &slot);
        const ptr = getPointer(slot);

        if (ptr == 0) {
            // if slot was empty, insert the new value
            const writer = self.db_file.writer();
            try self.db_file.seekFromEnd(0);
            const value_pos = try self.db_file.getPos();
            try writer.writeAll(&value_hash);
            try writer.writeIntLittle(u64, value.len);
            try writer.writeAll(value);
            try self.db_file.seekTo(slot_pos);
            try writer.writeIntLittle(u64, setType(value_pos, .value, .bytes));
            return value_pos;
        } else {
            const ptr_type = getPointerType(slot);
            if (ptr_type != .value) {
                return error.UnexpectedPointerType;
            }
            const val_type = getValueType(slot);
            if (val_type != .bytes) {
                return error.UnexpectedValueType;
            }
            // get the existing value
            return ptr;
        }
    }

    // map of lists

    fn writeListMap(self: *Database, key_hash: [HASH_SIZE]u8, value: []const u8, index_start: u64, reverse_offset: usize) !void {
        var slot: u64 = 0;
        const slot_pos = try self.readMapSlot(key_hash, index_start, 0, true, &slot);
        const ptr = getPointer(slot);

        if (ptr == 0) {
            // if slot was empty, insert the new list
            const writer = self.db_file.writer();
            try self.db_file.seekFromEnd(0);
            const value_pos = try self.db_file.getPos();
            try writer.writeAll(&key_hash);
            const list_start = try self.db_file.getPos();
            const list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
            try writer.writeIntLittle(u64, 0); // list size
            const list_ptr = try self.db_file.getPos() + POINTER_SIZE;
            try writer.writeIntLittle(u64, list_ptr);
            try writer.writeAll(&list_index_block);
            // add value to list
            _ = try self.writeList(value, list_start, reverse_offset);
            // make slot point to list
            try self.db_file.seekTo(slot_pos);
            try writer.writeIntLittle(u64, setType(value_pos, .value, .list));
        } else {
            const ptr_type = getPointerType(slot);
            if (ptr_type != .value) {
                return error.UnexpectedPointerType;
            }
            const val_type = getValueType(slot);
            if (val_type != .list) {
                return error.UnexpectedValueType;
            }
            const list_start = ptr + HASH_SIZE;
            _ = try self.writeList(value, list_start, reverse_offset);
        }
    }

    fn readListMap(self: *Database, key_hash: [HASH_SIZE]u8, index_start: u64, reverse_offset: usize) ![]u8 {
        const reader = self.db_file.reader();

        var slot: u64 = 0;
        _ = try self.readMapSlot(key_hash, index_start, 0, false, &slot);
        const ptr = getPointer(slot);

        if (ptr == 0) {
            return error.KeyNotFound;
        }

        const ptr_type = getPointerType(slot);
        if (ptr_type != .value) {
            return error.UnexpectedPointerType;
        }
        const val_type = getValueType(slot);
        if (val_type != .list) {
            return error.UnexpectedValueType;
        }

        const list_start = ptr + HASH_SIZE;
        try self.db_file.seekTo(list_start);
        const list_size = try reader.readIntLittle(u64);
        if (list_size <= reverse_offset) {
            return error.KeyNotFound;
        }
        return try self.readList(list_size - reverse_offset - 1, list_start);
    }

    // maps

    fn writeMap(self: *Database, key_hash: [HASH_SIZE]u8, value: []const u8, index_start: u64) !void {
        const value_pos = try self.writeValue(value);
        const slot_pos = try self.readMapSlot(key_hash, index_start, 0, true, null);
        // always write the new key entry
        const writer = self.db_file.writer();
        try self.db_file.seekFromEnd(0);
        const pos = try self.db_file.getPos();
        try writer.writeAll(&key_hash);
        try writer.writeIntLittle(u64, value_pos);
        try self.db_file.seekTo(slot_pos);
        try writer.writeIntLittle(u64, setType(pos, .value, .bytes));
    }

    fn readMap(self: *Database, key_hash: [HASH_SIZE]u8, index_start: u64) ![]u8 {
        const reader = self.db_file.reader();

        var slot: u64 = 0;
        _ = try self.readMapSlot(key_hash, index_start, 0, false, &slot);
        const ptr = try reader.readIntLittle(u64);

        const ptr_type = getPointerType(slot);
        if (ptr_type != .value) {
            return error.UnexpectedPointerType;
        }
        const val_type = getValueType(slot);
        if (val_type != .bytes) {
            return error.UnexpectedValueType;
        }

        try self.db_file.seekTo(ptr + HASH_SIZE);
        const value_size = try reader.readIntLittle(u64);

        var value = try self.allocator.alloc(u8, value_size);
        errdefer self.allocator.free(value);
        try reader.readNoEof(value);
        return value;
    }

    fn readMapSlot(self: *Database, key_hash: [HASH_SIZE]u8, index_pos: u64, key_offset: u32, allow_write: bool, slot_val_maybe: ?*u64) !u64 {
        if (key_offset >= HASH_SIZE) {
            return error.KeyOffsetExceeded;
        }

        const reader = self.db_file.reader();

        const digit = @as(u64, key_hash[key_offset]);
        const slot_pos = index_pos + (POINTER_SIZE * digit);
        try self.db_file.seekTo(slot_pos);
        const slot = try reader.readIntLittle(u64);

        if (slot == 0) {
            if (allow_write) {
                return slot_pos;
            } else {
                return error.KeyNotFound;
            }
        }

        const ptr_type = getPointerType(slot);
        const ptr = getPointer(slot);

        switch (ptr_type) {
            .index => {
                return self.readMapSlot(key_hash, ptr, key_offset + 1, allow_write, slot_val_maybe);
            },
            .value => {
                try self.db_file.seekTo(ptr);
                var existing_key_hash = [_]u8{0} ** HASH_SIZE;
                try reader.readNoEof(&existing_key_hash);
                if (std.mem.eql(u8, &existing_key_hash, &key_hash)) {
                    if (slot_val_maybe) |slot_val| {
                        slot_val.* = slot;
                    }
                    return slot_pos;
                } else {
                    if (allow_write) {
                        // append new index block
                        const writer = self.db_file.writer();
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
                        const next_pos = try self.readMapSlot(key_hash, next_index_pos, key_offset + 1, allow_write, slot_val_maybe);
                        try self.db_file.seekTo(slot_pos);
                        try writer.writeIntLittle(u64, setType(next_index_pos, .index, null));
                        return next_pos;
                    } else {
                        return error.KeyNotFound;
                    }
                }
            },
        }
    }

    // lists

    fn writeList(self: *Database, value: []const u8, index_start: u64, reverse_offset: usize) !u64 {
        const reader = self.db_file.reader();
        const writer = self.db_file.writer();

        try self.db_file.seekTo(index_start);
        const list_size = try reader.readIntLittle(u64);
        if (list_size < reverse_offset) {
            return error.KeyNotFound;
        }
        const key = list_size - reverse_offset;
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
            const next_pos = try self.writeListValue(value, next_index_pos, key, next_shift);
            try self.db_file.seekTo(index_start);
            try writer.writeIntLittle(u64, key + 1);
            try writer.writeIntLittle(u64, next_index_pos);
            return next_pos;
        } else {
            const next_pos = try self.writeListValue(value, index_pos, key, next_shift);
            try self.db_file.seekTo(index_start);
            try writer.writeIntLittle(u64, key + 1);
            return next_pos;
        }
    }

    fn writeListValue(self: *Database, value: []const u8, index_pos: u64, key: u64, shift: u6) !u64 {
        const value_pos = try self.writeValue(value);
        const slot_pos = try self.readListSlot(index_pos, key, shift, true, null);
        const writer = self.db_file.writer();
        try self.db_file.seekTo(slot_pos);
        try writer.writeIntLittle(u64, setType(value_pos, .value, .bytes));
        return value_pos;
    }

    fn readList(self: *Database, key: u64, list_start: u64) ![]u8 {
        const reader = self.db_file.reader();

        try self.db_file.seekTo(list_start);
        const size = try reader.readIntLittle(u64);

        if (key < 0 or key >= size) {
            return error.KeyNotFound;
        }

        const index_pos = try reader.readIntLittle(u64);

        const shift = @truncate(u6, if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key));
        var slot: u64 = 0;
        _ = try self.readListSlot(index_pos, key, shift, false, &slot);
        const ptr = getPointer(slot);

        const ptr_type = getPointerType(slot);
        if (ptr_type != .value) {
            return error.UnexpectedPointerType;
        }
        const val_type = getValueType(slot);
        if (val_type != .bytes) {
            return error.UnexpectedValueType;
        }

        try self.db_file.seekTo(ptr + HASH_SIZE);
        const value_size = try reader.readIntLittle(u64);

        var value = try self.allocator.alloc(u8, value_size);
        errdefer self.allocator.free(value);

        try reader.readNoEof(value);
        return value;
    }

    fn readListSlot(self: *Database, index_pos: u64, key: u64, shift: u6, allow_write: bool, slot_val_maybe: ?*u64) !u64 {
        const reader = self.db_file.reader();

        const i = (key >> (shift * BIT_COUNT)) & MASK;
        const slot_pos = index_pos + (POINTER_SIZE * i);
        try self.db_file.seekTo(slot_pos);
        const slot = try reader.readIntLittle(u64);

        const ptr_type = getPointerType(slot);
        const ptr = getPointer(slot);

        if (ptr == 0) {
            if (allow_write) {
                if (shift == 0) {
                    return slot_pos;
                } else {
                    const writer = self.db_file.writer();
                    try self.db_file.seekFromEnd(0);
                    const next_index_pos = try self.db_file.getPos();
                    var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                    try writer.writeAll(&index_block);
                    try self.db_file.seekTo(slot_pos);
                    try writer.writeIntLittle(u64, setType(next_index_pos, .index, null));
                    return try self.readListSlot(next_index_pos, key, shift - 1, allow_write, slot_val_maybe);
                }
            } else {
                return error.KeyNotFound;
            }
        } else {
            if (slot_val_maybe) |slot_val| {
                slot_val.* = slot;
            }
            if (shift == 0) {
                return slot_pos;
            } else {
                if (ptr_type != .index) {
                    return error.UnexpectedPointerType;
                }
                return self.readListSlot(ptr, key, shift - 1, allow_write, slot_val_maybe);
            }
        }
    }
};

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

test "get/set pointer type" {
    const ptr_value = setType(42, .value, .map);
    try expectEqual(PointerType.value, getPointerType(ptr_value));
    try expectEqual(ValueType.map, getValueType(ptr_value));
    const ptr_index = setType(42, .index, null);
    try expectEqual(PointerType.index, getPointerType(ptr_index));
}

test "read and write" {
    const allocator = std.testing.allocator;
    const cwd = std.fs.cwd();
    const db_path = "main.db";
    defer cwd.deleteFile(db_path) catch {};

    // list maps
    // under each key is a list of all values that were set
    {
        var db = try Database.init(allocator, cwd, db_path);
        defer db.deinit();

        // write foo
        var foo_key = [_]u8{0} ** HASH_SIZE;
        try hash_buffer("foo", &foo_key);
        try db.writeListMap(foo_key, "bar", KEY_INDEX_START, 0);

        // read foo
        const bar_value = try db.readListMap(foo_key, KEY_INDEX_START, 0);
        defer allocator.free(bar_value);
        try std.testing.expectEqualStrings("bar", bar_value);

        // overwrite foo
        try db.writeListMap(foo_key, "baz", KEY_INDEX_START, 0);
        const baz_value = try db.readListMap(foo_key, KEY_INDEX_START, 0);
        defer allocator.free(baz_value);
        try std.testing.expectEqualStrings("baz", baz_value);

        // can still read the old value
        const bar_value2 = try db.readListMap(foo_key, KEY_INDEX_START, 1);
        defer allocator.free(bar_value2);
        try std.testing.expectEqualStrings("bar", bar_value);

        // key not found
        var not_found_key = [_]u8{0} ** HASH_SIZE;
        try hash_buffer("this doesn't exist", &not_found_key);
        try expectEqual(error.KeyNotFound, db.readListMap(not_found_key, KEY_INDEX_START, 0));

        // write key that conflicts with foo at first byte
        var conflict_key = [_]u8{0} ** HASH_SIZE;
        try hash_buffer("conflict", &conflict_key);
        conflict_key[0] = foo_key[0]; // intentionally make it conflict
        try db.writeListMap(conflict_key, "hello", KEY_INDEX_START, 0);

        // read conflicting key
        const hello_value = try db.readListMap(conflict_key, KEY_INDEX_START, 0);
        defer allocator.free(hello_value);
        try std.testing.expectEqualStrings("hello", hello_value);

        // we can still read foo
        const baz_value2 = try db.readListMap(foo_key, KEY_INDEX_START, 0);
        defer allocator.free(baz_value2);
        try std.testing.expectEqualStrings("baz", baz_value2);
    }

    // overwrite a value many times, filling up the list until a root overflow occurs
    {
        var db = try Database.init(allocator, cwd, db_path);
        defer db.deinit();

        var wat_key = [_]u8{0} ** HASH_SIZE;
        try hash_buffer("wat", &wat_key);
        for (0..257) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            try db.writeListMap(wat_key, value, KEY_INDEX_START, 0);

            const value2 = try db.readListMap(wat_key, KEY_INDEX_START, 0);
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }
    }

    // maps
    // under each key is a single value
    {
        var db = try Database.init(allocator, cwd, db_path);
        defer db.deinit();

        // write foo
        var foo_key = [_]u8{0} ** HASH_SIZE;
        try hash_buffer("foo", &foo_key);
        try db.writeMap(foo_key, "bar", KEY_INDEX_START);

        // read foo
        const bar_value = try db.readMap(foo_key, KEY_INDEX_START);
        defer allocator.free(bar_value);
        try std.testing.expectEqualStrings("bar", bar_value);

        // overwrite foo
        try db.writeMap(foo_key, "baz", KEY_INDEX_START);
        const baz_value = try db.readMap(foo_key, KEY_INDEX_START);
        defer allocator.free(baz_value);
        try std.testing.expectEqualStrings("baz", baz_value);

        // key not found
        var not_found_key = [_]u8{0} ** HASH_SIZE;
        try hash_buffer("this doesn't exist", &not_found_key);
        try expectEqual(error.KeyNotFound, db.readMap(not_found_key, KEY_INDEX_START));

        // write key that conflicts with foo at first byte
        var conflict_key = [_]u8{0} ** HASH_SIZE;
        try hash_buffer("conflict", &conflict_key);
        conflict_key[0] = foo_key[0]; // intentionally make it conflict
        try db.writeMap(conflict_key, "hello", KEY_INDEX_START);

        // read conflicting key
        const hello_value = try db.readMap(conflict_key, KEY_INDEX_START);
        defer allocator.free(hello_value);
        try std.testing.expectEqualStrings("hello", hello_value);

        // we can still read foo
        const baz_value2 = try db.readMap(foo_key, KEY_INDEX_START);
        defer allocator.free(baz_value2);
        try std.testing.expectEqualStrings("baz", baz_value2);
    }
}
