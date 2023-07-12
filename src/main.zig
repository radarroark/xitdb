//! you're looking at radar's hopeless attempt to implement
//! his dream database. it will be embedded, immutable, and
//! reactive, and will be practical for both on-disk and
//! in-memory use. there is so much work to do, and so much
//! to learn. we're gonna leeroy jenkins our way through this.

const std = @import("std");

// using sha1 to hash the keys for now, but this will eventually be
// configurable. for many uses it will be overkill...
pub const HASH_SIZE = std.crypto.hash.Sha1.digest_length;
pub const Hash = u160;
comptime {
    std.debug.assert(@bitSizeOf(Hash) == HASH_SIZE * 8);
}
pub const HASH_INT_SIZE = @sizeOf(Hash);
pub fn hash_buffer(buffer: []const u8) Hash {
    var hash = [_]u8{0} ** HASH_INT_SIZE;
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(buffer);
    h.final(hash[0..HASH_SIZE]);
    return std.mem.bytesToValue(Hash, &hash);
}

const POINTER_SIZE = @sizeOf(u64);
const HEADER_BLOCK_SIZE = 2;
const BIT_COUNT = 5;
const SLOT_COUNT = 1 << BIT_COUNT;
const MASK: u64 = SLOT_COUNT - 1;
const INDEX_BLOCK_SIZE = POINTER_SIZE * SLOT_COUNT;
const VALUE_INDEX_START = HEADER_BLOCK_SIZE;
const KEY_INDEX_START = VALUE_INDEX_START + INDEX_BLOCK_SIZE;

const PointerType = enum(u64) {
    index = 0 << 63,
    value = 1 << 63,
};

const POINTER_TYPE_MASK: u64 = 0b1 << 63;

const ValueType = enum(u64) {
    map = 0b00 << 61,
    list = 0b01 << 61,
    hash = 0b10 << 61,
    bytes = 0b11 << 61,
};

const VALUE_TYPE_MASK: u64 = 0b11 << 61;

const Index = struct {
    index: u64,
    reverse: bool,
};

const PathPart = union(enum) {
    map_get: Hash,
    list_get: union(enum) {
        index: Index,
        append,
        append_copy,
    },
};

pub fn setType(ptr: u64, ptr_type: PointerType, value_type_maybe: ?ValueType) u64 {
    switch (ptr_type) {
        .index => return ptr | @intFromEnum(ptr_type),
        .value => {
            if (value_type_maybe) |value_type| {
                return ptr | @intFromEnum(ptr_type) | @intFromEnum(value_type);
            } else {
                return ptr | @intFromEnum(ptr_type);
            }
        },
    }
}

pub fn getPointerType(ptr: u64) PointerType {
    return @enumFromInt(ptr & POINTER_TYPE_MASK);
}

pub fn getValueType(ptr: u64) ValueType {
    return @enumFromInt(ptr & VALUE_TYPE_MASK);
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

pub const DatabaseKind = enum {
    memory,
    file,
};

pub fn Database(comptime kind: DatabaseKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: Core,

        pub const Core = switch (kind) {
            .memory => struct {
                buffer: std.ArrayList(u8),
                size: u64,
                position: u64,

                const Reader = struct {
                    parent: *Core,

                    pub fn readNoEof(self: Reader, buf: []u8) !void {
                        const new_position = self.parent.position + buf.len;
                        if (new_position > self.parent.size) return error.EndOfStream;
                        @memcpy(buf, self.parent.buffer.items[self.parent.position..new_position]);
                        self.parent.position = new_position;
                    }

                    pub fn readIntLittle(self: Reader, comptime T: type) !T {
                        const new_position = self.parent.position + @sizeOf(T);
                        if (new_position > self.parent.size) return error.EndOfStream;
                        const bytes = self.parent.buffer.items[self.parent.position..new_position];
                        self.parent.position = new_position;
                        return std.mem.littleToNative(T, std.mem.bytesToValue(T, bytes[0..@sizeOf(T)]));
                    }
                };

                const Writer = struct {
                    parent: *Core,

                    pub fn writeAll(self: Writer, bytes: []const u8) !void {
                        const new_position = self.parent.position + bytes.len;
                        @memcpy(self.parent.buffer.items[self.parent.position..new_position], bytes);
                        self.parent.size = @max(self.parent.size, new_position);
                        self.parent.position = new_position;
                    }

                    pub fn writeIntLittle(self: Writer, comptime T: type, value: T) !void {
                        const new_position = self.parent.position + @sizeOf(T);
                        @memcpy(self.parent.buffer.items[self.parent.position..new_position], std.mem.asBytes(&std.mem.nativeToLittle(T, value)));
                        self.parent.size = @max(self.parent.size, new_position);
                        self.parent.position = new_position;
                    }
                };

                pub fn deinit(self: *Core) void {
                    self.buffer.deinit();
                }

                pub fn reader(self: *Core) Reader {
                    return Core.Reader{ .parent = self };
                }

                pub fn writer(self: *Core) Writer {
                    return Core.Writer{ .parent = self };
                }

                pub fn seekTo(self: *Core, offset: u64) !void {
                    self.position = offset;
                }

                pub fn seekFromEnd(self: *Core, offset: i64) !void {
                    if (offset > 0) {
                        self.position = self.size +| std.math.absCast(offset);
                    } else {
                        self.position = self.size -| std.math.absCast(offset);
                    }
                }

                pub fn getPos(self: Core) !u64 {
                    return self.position;
                }
            },
            .file => struct {
                file: std.fs.File,

                pub fn deinit(self: *Core) void {
                    self.file.close();
                }

                pub fn reader(self: Core) std.fs.File.Reader {
                    return self.file.reader();
                }

                pub fn writer(self: Core) std.fs.File.Writer {
                    return self.file.writer();
                }

                pub fn seekTo(self: Core, offset: u64) !void {
                    try self.file.seekTo(offset);
                }

                pub fn seekFromEnd(self: Core, offset: i64) !void {
                    try self.file.seekFromEnd(offset);
                }

                pub fn getPos(self: Core) !u64 {
                    return try self.file.getPos();
                }
            },
        };

        pub const InitOpts = switch (kind) {
            .memory => struct {
                capacity: usize,
            },
            .file => struct {
                dir: std.fs.Dir,
                path: []const u8,
            },
        };

        pub fn init(allocator: std.mem.Allocator, opts: InitOpts) !Database(kind) {
            switch (kind) {
                .memory => {
                    var buffer = try std.ArrayList(u8).initCapacity(allocator, opts.capacity);
                    buffer.expandToCapacity();

                    var self = Database(kind){
                        .allocator = allocator,
                        .core = .{
                            .buffer = buffer,
                            .size = 0,
                            .position = 0,
                        },
                    };

                    try self.writeHeader();

                    return self;
                },
                .file => {
                    // create or open file
                    const file_or_err = opts.dir.openFile(opts.path, .{ .mode = .read_write });
                    const file = try if (file_or_err == error.FileNotFound)
                        opts.dir.createFile(opts.path, .{ .read = true })
                    else
                        file_or_err;
                    errdefer file.close();

                    var self = Database(kind){
                        .allocator = allocator,
                        .core = .{ .file = file },
                    };

                    const meta = try file.metadata();
                    const size = meta.size();

                    if (size == 0) {
                        try self.writeHeader();
                    }

                    return self;
                },
            }
        }

        pub fn deinit(self: *Database(kind)) void {
            self.core.deinit();
        }

        fn writeHeader(self: *Database(kind)) !void {
            const writer = self.core.writer();

            var header_block = [_]u8{0} ** HEADER_BLOCK_SIZE;
            try writer.writeAll(&header_block);

            var value_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
            try writer.writeAll(&value_index_block);

            const list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
            try writer.writeIntLittle(u64, 0); // list size
            const list_ptr = try self.core.getPos() + POINTER_SIZE;
            try writer.writeIntLittle(u64, list_ptr);
            try writer.writeAll(&list_index_block);
        }

        fn writeValue(self: *Database(kind), value: []const u8) !u64 {
            var value_hash = hash_buffer(value);

            var slot: u64 = 0;
            const slot_pos = try self.readMapSlot(VALUE_INDEX_START, value_hash, 0, true, &slot);
            const ptr = getPointer(slot);

            if (ptr == 0) {
                // if slot was empty, insert the new value
                const writer = self.core.writer();
                try self.core.seekFromEnd(0);
                const value_pos = try self.core.getPos();
                try writer.writeIntLittle(u64, value.len);
                try writer.writeAll(value);
                try self.core.seekTo(slot_pos);
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

        fn readSlot(self: *Database(kind), path: []const PathPart, index_start: u64, allow_write: bool, slot_val_maybe: ?*u64) !u64 {
            var pos = index_start;
            var slot_maybe: ?u64 = null;
            for (path) |part| {
                var next_slot: u64 = 0;
                pos = switch (part) {
                    .map_get => blk: {
                        if (slot_maybe) |slot| {
                            if (slot == 0) {
                                if (allow_write) {
                                    // if slot was empty, insert the new map
                                    const writer = self.core.writer();
                                    try self.core.seekFromEnd(0);
                                    const map_start = try self.core.getPos();
                                    const map_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                                    try writer.writeAll(&map_index_block);
                                    // make slot point to map
                                    try self.core.seekTo(pos);
                                    try writer.writeIntLittle(u64, setType(map_start, .value, .map));
                                    pos = map_start;
                                } else {
                                    return error.KeyNotFound;
                                }
                            } else {
                                const ptr_type = getPointerType(slot);
                                if (ptr_type != .value) {
                                    return error.UnexpectedPointerType;
                                }
                                const val_type = getValueType(slot);
                                if (val_type != .map) {
                                    return error.UnexpectedValueType;
                                }
                                const next_pos = getPointer(slot);
                                if (allow_write) {
                                    // read existing block
                                    const reader = self.core.reader();
                                    try self.core.seekTo(next_pos);
                                    var map_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                                    try reader.readNoEof(&map_index_block);
                                    // copy it to the end
                                    const writer = self.core.writer();
                                    try self.core.seekFromEnd(0);
                                    const map_start = try self.core.getPos();
                                    try writer.writeAll(&map_index_block);
                                    // make slot point to map
                                    try self.core.seekTo(pos);
                                    try writer.writeIntLittle(u64, setType(map_start, .value, .map));
                                    pos = map_start;
                                } else {
                                    pos = next_pos;
                                }
                            }
                        }
                        break :blk try self.readMapSlot(pos, part.map_get, 0, allow_write, &next_slot);
                    },
                    .list_get => blk: {
                        if (slot_maybe) |slot| {
                            if (slot == 0) {
                                if (allow_write) {
                                    // if slot was empty, insert the new list
                                    const writer = self.core.writer();
                                    try self.core.seekFromEnd(0);
                                    const list_start = try self.core.getPos();
                                    const list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                                    try writer.writeIntLittle(u64, 0); // list size
                                    const list_ptr = try self.core.getPos() + POINTER_SIZE;
                                    try writer.writeIntLittle(u64, list_ptr);
                                    try writer.writeAll(&list_index_block);
                                    // make slot point to list
                                    try self.core.seekTo(pos);
                                    try writer.writeIntLittle(u64, setType(list_start, .value, .list));
                                    pos = list_start;
                                } else {
                                    return error.KeyNotFound;
                                }
                            } else {
                                const ptr_type = getPointerType(slot);
                                if (ptr_type != .value) {
                                    return error.UnexpectedPointerType;
                                }
                                const val_type = getValueType(slot);
                                if (val_type != .list) {
                                    return error.UnexpectedValueType;
                                }
                                pos = getPointer(slot);
                            }
                        }
                        switch (part.list_get) {
                            .index => {
                                const index = part.list_get.index;
                                try self.core.seekTo(pos);
                                const reader = self.core.reader();
                                const list_size = try reader.readIntLittle(u64);
                                var key: u64 = 0;
                                if (index.reverse) {
                                    if (index.index >= list_size) {
                                        return error.KeyNotFound;
                                    } else {
                                        key = list_size - index.index - 1;
                                    }
                                } else {
                                    if (index.index >= list_size) {
                                        return error.KeyNotFound;
                                    } else {
                                        key = index.index;
                                    }
                                }
                                const list_ptr = try reader.readIntLittle(u64);
                                const shift: u6 = @truncate(if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key));
                                break :blk try self.readListSlot(list_ptr, key, shift, allow_write, &next_slot);
                            },
                            .append => {
                                if (allow_write) {
                                    break :blk try self.readListSlotAppend(pos);
                                } else {
                                    return error.KeyNotFound;
                                }
                            },
                            .append_copy => {
                                if (allow_write) {
                                    try self.core.seekTo(pos);
                                    const reader = self.core.reader();
                                    const list_size = try reader.readIntLittle(u64);
                                    // read the last slot in the list
                                    var last_slot: u64 = 0;
                                    if (list_size > 0) {
                                        const key = list_size - 1;
                                        const list_ptr = try reader.readIntLittle(u64);
                                        const shift: u6 = @truncate(if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key));
                                        _ = try self.readListSlot(list_ptr, key, shift, false, &last_slot);
                                    }
                                    // make the next slot
                                    const next_pos = try self.readListSlotAppend(pos);
                                    // set its value to the last slot
                                    if (last_slot != 0) {
                                        const writer = self.core.writer();
                                        try self.core.seekTo(next_pos);
                                        try writer.writeIntLittle(u64, last_slot);
                                        next_slot = last_slot;
                                    }
                                    break :blk next_pos;
                                } else {
                                    return error.KeyNotFound;
                                }
                            },
                        }
                    },
                };
                slot_maybe = next_slot;
            }
            if (slot_val_maybe) |slot_val| {
                if (slot_maybe) |slot| {
                    slot_val.* = slot;
                }
            }
            return pos;
        }

        // list of maps

        fn writeListMap(self: *Database(kind), key_hash: Hash, value: []const u8, index_start: u64) !void {
            const slot_pos = try self.readSlot(&[_]PathPart{ .{ .list_get = .append_copy }, .{ .map_get = key_hash } }, index_start, true, null);
            const value_pos = try self.writeValue(value);
            const writer = self.core.writer();
            try self.core.seekTo(slot_pos);
            try writer.writeIntLittle(u64, setType(value_pos, .value, .bytes));
        }

        fn readListMap(self: *Database(kind), key_hash: Hash, index_start: u64, index: Index) ![]u8 {
            const reader = self.core.reader();

            var slot: u64 = 0;
            _ = try self.readSlot(&[_]PathPart{ .{ .list_get = .{ .index = index } }, .{ .map_get = key_hash } }, index_start, false, &slot);
            const ptr = getPointer(slot);

            const ptr_type = getPointerType(slot);
            if (ptr_type != .value) {
                return error.UnexpectedPointerType;
            }
            const val_type = getValueType(slot);
            if (val_type != .bytes) {
                return error.UnexpectedValueType;
            }

            try self.core.seekTo(ptr);
            const value_size = try reader.readIntLittle(u64);

            var value = try self.allocator.alloc(u8, value_size);
            errdefer self.allocator.free(value);

            try reader.readNoEof(value);
            return value;
        }

        // maps

        fn writeMap(self: *Database(kind), key_hash: Hash, value: []const u8, index_start: u64) !void {
            const value_pos = try self.writeValue(value);
            const slot_pos = try self.readMapSlot(index_start, key_hash, 0, true, null);
            // always write the new key entry
            const writer = self.core.writer();
            try self.core.seekTo(slot_pos);
            try writer.writeIntLittle(u64, setType(value_pos, .value, .bytes));
        }

        fn readMap(self: *Database(kind), key_hash: Hash, index_start: u64) ![]u8 {
            const reader = self.core.reader();

            var slot: u64 = 0;
            _ = try self.readMapSlot(index_start, key_hash, 0, false, &slot);
            const ptr = getPointer(slot);

            const ptr_type = getPointerType(slot);
            if (ptr_type != .value) {
                return error.UnexpectedPointerType;
            }
            const val_type = getValueType(slot);
            if (val_type != .bytes) {
                return error.UnexpectedValueType;
            }

            try self.core.seekTo(ptr);
            const value_size = try reader.readIntLittle(u64);

            var value = try self.allocator.alloc(u8, value_size);
            errdefer self.allocator.free(value);
            try reader.readNoEof(value);
            return value;
        }

        fn readMapSlot(self: *Database(kind), index_pos: u64, key_hash: Hash, key_offset: u8, allow_write: bool, slot_val_maybe: ?*u64) !u64 {
            if (key_offset >= (HASH_SIZE * 8) / BIT_COUNT) {
                return error.KeyOffsetExceeded;
            }

            const reader = self.core.reader();
            const writer = self.core.writer();

            const i = @as(u64, @truncate((key_hash >> key_offset * BIT_COUNT))) & MASK;
            const slot_pos = index_pos + (POINTER_SIZE * i);
            try self.core.seekTo(slot_pos);
            const slot = try reader.readIntLittle(u64);

            if (slot == 0) {
                if (allow_write) {
                    try self.core.seekFromEnd(0);
                    // write hash
                    const hash_pos = try self.core.getPos();
                    try writer.writeAll(std.mem.asBytes(&key_hash)[0..HASH_SIZE]);
                    // write empty value slot
                    const value_slot_pos = try self.core.getPos();
                    try writer.writeIntLittle(u64, 0);
                    // point slot to hash pos
                    try self.core.seekTo(slot_pos);
                    try writer.writeIntLittle(u64, setType(hash_pos, .value, .hash));
                    return value_slot_pos;
                } else {
                    return error.KeyNotFound;
                }
            }

            const ptr_type = getPointerType(slot);
            const ptr = getPointer(slot);

            switch (ptr_type) {
                .index => {
                    return self.readMapSlot(ptr, key_hash, key_offset + 1, allow_write, slot_val_maybe);
                },
                .value => {
                    const val_type = getValueType(slot);
                    if (val_type != .hash) {
                        return error.UnexpectedValueType;
                    }
                    try self.core.seekTo(ptr);
                    const existing_key_hash = blk: {
                        var hash = [_]u8{0} ** HASH_INT_SIZE;
                        try reader.readNoEof(hash[0..HASH_SIZE]);
                        break :blk std.mem.bytesToValue(Hash, &hash);
                    };
                    if (existing_key_hash == key_hash) {
                        const value_slot_pos = try self.core.getPos();
                        const value_slot = try reader.readIntLittle(u64);
                        if (slot_val_maybe) |slot_val| {
                            slot_val.* = value_slot;
                        }
                        if (allow_write) {
                            try self.core.seekFromEnd(0);
                            // write hash
                            const hash_pos = try self.core.getPos();
                            try writer.writeAll(std.mem.asBytes(&key_hash)[0..HASH_SIZE]);
                            // write value slot
                            const next_value_slot_pos = try self.core.getPos();
                            try writer.writeIntLittle(u64, value_slot);
                            // point slot to hash pos
                            try self.core.seekTo(slot_pos);
                            try writer.writeIntLittle(u64, setType(hash_pos, .value, .hash));
                            return next_value_slot_pos;
                        } else {
                            return value_slot_pos;
                        }
                    } else {
                        if (allow_write) {
                            // append new index block
                            if (key_offset + 1 >= (HASH_SIZE * 8) / BIT_COUNT) {
                                return error.KeyOffsetExceeded;
                            }
                            const next_i = @as(u64, @truncate((existing_key_hash >> (key_offset + 1) * BIT_COUNT))) & MASK;
                            try self.core.seekFromEnd(0);
                            const next_index_pos = try self.core.getPos();
                            var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                            try writer.writeAll(&index_block);
                            try self.core.seekTo(next_index_pos + (POINTER_SIZE * next_i));
                            try writer.writeIntLittle(u64, slot);
                            const next_pos = try self.readMapSlot(next_index_pos, key_hash, key_offset + 1, allow_write, slot_val_maybe);
                            try self.core.seekTo(slot_pos);
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

        fn readListSlotAppend(self: *Database(kind), index_start: u64) !u64 {
            const reader = self.core.reader();
            const writer = self.core.writer();

            try self.core.seekTo(index_start);
            const list_size = try reader.readIntLittle(u64);
            const key = list_size;
            var index_pos = try reader.readIntLittle(u64);

            const prev_shift: u6 = @truncate(if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key - 1));
            const next_shift: u6 = @truncate(if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key));

            var slot_pos: u64 = 0;

            if (prev_shift != next_shift) {
                // root overflow
                try self.core.seekFromEnd(0);
                const next_index_pos = try self.core.getPos();
                var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                try writer.writeAll(&index_block);
                try self.core.seekTo(next_index_pos);
                try writer.writeIntLittle(u64, index_pos);
                slot_pos = try self.readListSlot(next_index_pos, key, next_shift, true, null);
                index_pos = next_index_pos;
            } else {
                slot_pos = try self.readListSlot(index_pos, key, next_shift, true, null);
            }

            try self.core.seekTo(index_start);
            try writer.writeIntLittle(u64, key + 1);
            try writer.writeIntLittle(u64, index_pos);

            return slot_pos;
        }

        fn readListSlot(self: *Database(kind), index_pos: u64, key: u64, shift: u6, allow_write: bool, slot_val_maybe: ?*u64) !u64 {
            const reader = self.core.reader();

            const i = (key >> (shift * BIT_COUNT)) & MASK;
            const slot_pos = index_pos + (POINTER_SIZE * i);
            try self.core.seekTo(slot_pos);
            const slot = try reader.readIntLittle(u64);

            if (slot == 0) {
                if (allow_write) {
                    if (shift == 0) {
                        return slot_pos;
                    } else {
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const next_index_pos = try self.core.getPos();
                        var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try writer.writeAll(&index_block);
                        try self.core.seekTo(slot_pos);
                        try writer.writeIntLittle(u64, setType(next_index_pos, .index, null));
                        return try self.readListSlot(next_index_pos, key, shift - 1, allow_write, slot_val_maybe);
                    }
                } else {
                    return error.KeyNotFound;
                }
            } else {
                const ptr_type = getPointerType(slot);
                const ptr = getPointer(slot);
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
}

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

fn testMain(allocator: std.mem.Allocator, comptime kind: DatabaseKind, opts: Database(kind).InitOpts) !void {
    // list of maps
    {
        var db = try Database(kind).init(allocator, opts);
        defer db.deinit();

        // write foo
        var foo_key = hash_buffer("foo");
        try db.writeListMap(foo_key, "bar", KEY_INDEX_START);

        // read foo
        const bar_value = try db.readListMap(foo_key, KEY_INDEX_START, .{ .index = 0, .reverse = true });
        defer allocator.free(bar_value);
        try std.testing.expectEqualStrings("bar", bar_value);

        // overwrite foo
        try db.writeListMap(foo_key, "baz", KEY_INDEX_START);
        const baz_value = try db.readListMap(foo_key, KEY_INDEX_START, .{ .index = 0, .reverse = true });
        defer allocator.free(baz_value);
        try std.testing.expectEqualStrings("baz", baz_value);

        // can still read the old value
        const bar_value2 = try db.readListMap(foo_key, KEY_INDEX_START, .{ .index = 1, .reverse = true });
        defer allocator.free(bar_value2);
        try std.testing.expectEqualStrings("bar", bar_value2);

        // key not found
        var not_found_key = hash_buffer("this doesn't exist");
        try expectEqual(error.KeyNotFound, db.readListMap(not_found_key, KEY_INDEX_START, .{ .index = 0, .reverse = true }));

        // write key that conflicts with foo
        var conflict_key = hash_buffer("conflict");
        conflict_key = (conflict_key & ~MASK) | (foo_key & MASK);
        try db.writeListMap(conflict_key, "hello", KEY_INDEX_START);

        // read conflicting key
        const hello_value = try db.readListMap(conflict_key, KEY_INDEX_START, .{ .index = 0, .reverse = true });
        defer allocator.free(hello_value);
        try std.testing.expectEqualStrings("hello", hello_value);

        // we can still read foo
        const baz_value2 = try db.readListMap(foo_key, KEY_INDEX_START, .{ .index = 0, .reverse = true });
        defer allocator.free(baz_value2);
        try std.testing.expectEqualStrings("baz", baz_value2);
    }

    // overwrite a value many times, filling up the list until a root overflow occurs
    if (false) {
        var db = try Database(kind).init(allocator, opts);
        defer db.deinit();

        var wat_key = hash_buffer("wat");
        for (0..SLOT_COUNT + 1) |i| {
            const value = try std.fmt.allocPrint(allocator, "wat{}", .{i});
            defer allocator.free(value);
            try db.writeListMap(wat_key, value, KEY_INDEX_START);

            const value2 = try db.readListMap(wat_key, KEY_INDEX_START, .{ .index = 0, .reverse = true });
            defer allocator.free(value2);
            try std.testing.expectEqualStrings(value, value2);
        }
    }

    // maps
    if (false) {
        var db = try Database(kind).init(allocator, opts);
        defer db.deinit();

        // write foo
        var foo_key = hash_buffer("foo");
        try db.writeMap(foo_key, "bar", VALUE_INDEX_START);

        // read foo
        const bar_value = try db.readMap(foo_key, VALUE_INDEX_START);
        defer allocator.free(bar_value);
        try std.testing.expectEqualStrings("bar", bar_value);

        // overwrite foo
        try db.writeMap(foo_key, "baz", VALUE_INDEX_START);
        const baz_value = try db.readMap(foo_key, VALUE_INDEX_START);
        defer allocator.free(baz_value);
        try std.testing.expectEqualStrings("baz", baz_value);

        // key not found
        var not_found_key = hash_buffer("this doesn't exist");
        try expectEqual(error.KeyNotFound, db.readMap(not_found_key, VALUE_INDEX_START));

        // write key that conflicts with foo
        var conflict_key = hash_buffer("conflict");
        conflict_key = (conflict_key & ~MASK) | (foo_key & MASK);
        try db.writeMap(conflict_key, "hello", VALUE_INDEX_START);

        // read conflicting key
        const hello_value = try db.readMap(conflict_key, VALUE_INDEX_START);
        defer allocator.free(hello_value);
        try std.testing.expectEqualStrings("hello", hello_value);

        // we can still read foo
        const baz_value2 = try db.readMap(foo_key, VALUE_INDEX_START);
        defer allocator.free(baz_value2);
        try std.testing.expectEqualStrings("baz", baz_value2);
    }
}

test "read and write" {
    const allocator = std.testing.allocator;

    try testMain(allocator, .memory, Database(.memory).InitOpts{
        .capacity = 10000,
    });

    const cwd = std.fs.cwd();
    const db_path = "main.db";
    defer cwd.deleteFile(db_path) catch {};

    try testMain(allocator, .file, Database(.file).InitOpts{
        .dir = cwd,
        .path = db_path,
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
