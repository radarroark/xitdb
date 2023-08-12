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
const BIT_COUNT = 4;
pub const SLOT_COUNT = 1 << BIT_COUNT;
pub const MASK: u64 = SLOT_COUNT - 1;
const INDEX_BLOCK_SIZE = POINTER_SIZE * SLOT_COUNT;
const VALUE_INDEX_START = HEADER_BLOCK_SIZE;
const KEY_INDEX_START = VALUE_INDEX_START + INDEX_BLOCK_SIZE;

const PointerType = enum(u64) {
    index = 0b0000 << 60,
    map = 0b1000 << 60,
    list = 0b0100 << 60,
    hash = 0b0010 << 60,
    bytes = 0b0001 << 60,
    int = 0b1100 << 60,
};

const POINTER_TYPE_MASK: u64 = 0b1111 << 60;

const Index = struct {
    index: u64,
    reverse: bool,
};

pub const PathPart = union(enum) {
    map_get: Hash,
    list_get: union(enum) {
        index: Index,
        append,
        append_copy,
    },
    value: union(enum) {
        none,
        int: u60,
        bytes: []const u8,
    },
    path: []const PathPart,
};

const WriteMode = enum {
    read_only,
    write,
    write_immutable,
};

fn setType(ptr: u64, ptr_type: PointerType) u64 {
    return ptr | @intFromEnum(ptr_type);
}

fn getPointerType(ptr: u64) PointerType {
    return @enumFromInt(ptr & POINTER_TYPE_MASK);
}

fn getPointerValue(ptr: u64) u60 {
    return @intCast(ptr & (~POINTER_TYPE_MASK));
}

pub const DatabaseError = error{
    NotImplemented,
    KeyOffsetExceeded,
    KeyNotFound,
    UnexpectedPointerType,
    WriteNotAllowed,
    ValueMustBeAtEnd,
    EmptyPath,
};

pub const DatabaseKind = enum {
    memory,
    file,
};

pub const SlotPointer = struct {
    position: u64,
    slot: u64,
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
                file: std.fs.File,
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
                    var self = Database(kind){
                        .allocator = allocator,
                        .core = .{ .file = opts.file },
                    };

                    const meta = try self.core.file.metadata();
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

        pub const Cursor = struct {
            read_slot_cursor: ReadSlotCursor,
            db: *Database(kind),

            pub fn writePath(self: *Cursor, path: []const PathPart) !void {
                _ = try self.db.readSlot(path, true, self.read_slot_cursor);
            }

            pub fn readBytes(self: *Cursor, path: []const PathPart) !?[]u8 {
                const reader = self.db.core.reader();

                const slot_ptr = self.db.readSlot(path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                const slot = slot_ptr.slot;
                const ptr = getPointerValue(slot);

                const ptr_type = getPointerType(slot);
                if (ptr_type != .bytes) {
                    return error.UnexpectedPointerType;
                }

                try self.db.core.seekTo(ptr);
                const value_size = try reader.readIntLittle(u64);

                var value = try self.db.allocator.alloc(u8, value_size);
                errdefer self.db.allocator.free(value);

                try reader.readNoEof(value);
                return value;
            }

            pub fn readInt(self: *Cursor, path: []const PathPart) !?u60 {
                const slot_ptr = self.db.readSlot(path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                const slot = slot_ptr.slot;
                const value = getPointerValue(slot);

                const ptr_type = getPointerType(slot);
                if (ptr_type != .int) {
                    return error.UnexpectedPointerType;
                }
                return value;
            }

            pub const Iter = struct {
                cursor: *Cursor,
                core: IterCore,

                pub const IterKind = enum {
                    list,
                };
                pub const IterCore = union(IterKind) {
                    list: struct {
                        index_maybe: ?u64,
                        size: u64,
                    },
                };

                pub fn init(cursor: *Cursor, iter_kind: IterKind) !Iter {
                    const core: IterCore = switch (iter_kind) {
                        .list => blk: {
                            const reader = cursor.db.core.reader();
                            try cursor.db.core.seekTo(cursor.read_slot_cursor.index_start);
                            const list_size = try reader.readIntLittle(u64);
                            break :blk .{
                                .list = .{
                                    .index_maybe = null,
                                    .size = list_size,
                                },
                            };
                        },
                    };
                    return .{
                        .cursor = cursor,
                        .core = core,
                    };
                }

                pub fn next(self: *Iter) ?Cursor {
                    switch (self.core) {
                        .list => {
                            if (self.index_maybe) |*index| {
                                index += 1;
                            } else {
                                self.index_maybe = 0;
                            }
                            //const index = self.index_maybe.?;
                            return null;
                        },
                    }
                }
            };

            pub fn iter(self: *Cursor, iter_kind: Iter.IterKind) !Iter {
                return try Iter.init(self, iter_kind);
            }
        };

        pub fn rootCursor(self: *Database(kind)) Cursor {
            return Cursor{
                .read_slot_cursor = .{ .index_start = KEY_INDEX_START },
                .db = self,
            };
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

        const ReadSlotCursor = union(enum) {
            index_start: u64,
            slot_ptr: SlotPointer,
        };

        fn readSlot(self: *Database(kind), path: []const PathPart, allow_write: bool, cursor: ReadSlotCursor) !SlotPointer {
            const part = if (path.len > 0) path[0] else switch (cursor) {
                .index_start => return error.EmptyPath,
                .slot_ptr => {
                    if (!allow_write and cursor.slot_ptr.slot == 0) {
                        return error.KeyNotFound;
                    }
                    return cursor.slot_ptr;
                },
            };
            const write_mode: WriteMode = if (allow_write)
                switch (cursor) {
                    .index_start => .write,
                    .slot_ptr => .write_immutable,
                }
            else
                .read_only;
            switch (part) {
                .map_get => {
                    var next_map_start: u64 = undefined;
                    switch (cursor) {
                        .index_start => {
                            next_map_start = cursor.index_start;
                        },
                        .slot_ptr => {
                            if (cursor.slot_ptr.slot == 0) {
                                if (allow_write) {
                                    // if slot was empty, insert the new map
                                    const writer = self.core.writer();
                                    try self.core.seekFromEnd(0);
                                    const map_start = try self.core.getPos();
                                    const map_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                                    try writer.writeAll(&map_index_block);
                                    // make slot point to map
                                    try self.core.seekTo(cursor.slot_ptr.position);
                                    try writer.writeIntLittle(u64, setType(map_start, .map));
                                    next_map_start = map_start;
                                } else {
                                    return error.KeyNotFound;
                                }
                            } else {
                                const ptr_type = getPointerType(cursor.slot_ptr.slot);
                                if (ptr_type != .map) {
                                    return error.UnexpectedPointerType;
                                }
                                const next_pos = getPointerValue(cursor.slot_ptr.slot);
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
                                    try self.core.seekTo(cursor.slot_ptr.position);
                                    try writer.writeIntLittle(u64, setType(map_start, .map));
                                    next_map_start = map_start;
                                } else {
                                    next_map_start = next_pos;
                                }
                            }
                        },
                    }
                    const next_slot_ptr = try self.readMapSlot(next_map_start, part.map_get, 0, write_mode);
                    return self.readSlot(path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                },
                .list_get => {
                    var next_list_start: u64 = undefined;
                    var next_slot_ptr: SlotPointer = undefined;
                    switch (cursor) {
                        .index_start => {
                            next_list_start = cursor.index_start;
                        },
                        .slot_ptr => {
                            if (cursor.slot_ptr.slot == 0) {
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
                                    next_list_start = list_start;
                                    next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = setType(list_start, .list) };
                                    try self.core.seekTo(next_slot_ptr.position);
                                    try writer.writeIntLittle(u64, next_slot_ptr.slot);
                                } else {
                                    return error.KeyNotFound;
                                }
                            } else {
                                const ptr_type = getPointerType(cursor.slot_ptr.slot);
                                if (ptr_type != .list) {
                                    return error.UnexpectedPointerType;
                                }
                                const next_pos = getPointerValue(cursor.slot_ptr.slot);
                                if (allow_write) {
                                    // read existing block
                                    const reader = self.core.reader();
                                    try self.core.seekTo(next_pos);
                                    const list_size = try reader.readIntLittle(u64);
                                    const list_ptr = try reader.readIntLittle(u64);
                                    try self.core.seekTo(list_ptr);
                                    var list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                                    try reader.readNoEof(&list_index_block);
                                    // copy it to the end
                                    const writer = self.core.writer();
                                    try self.core.seekFromEnd(0);
                                    const list_start = try self.core.getPos();
                                    try writer.writeIntLittle(u64, list_size);
                                    const next_list_ptr = try self.core.getPos() + POINTER_SIZE;
                                    try writer.writeIntLittle(u64, next_list_ptr);
                                    try writer.writeAll(&list_index_block);
                                    // make slot point to map
                                    next_list_start = list_start;
                                    next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = setType(list_start, .list) };
                                    try self.core.seekTo(next_slot_ptr.position);
                                    try writer.writeIntLittle(u64, next_slot_ptr.slot);
                                } else {
                                    next_list_start = next_pos;
                                }
                            }
                        },
                    }
                    switch (part.list_get) {
                        .index => {
                            const index = part.list_get.index;
                            try self.core.seekTo(next_list_start);
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
                            const last_key = list_size - 1;
                            const list_ptr = try reader.readIntLittle(u64);
                            const shift: u6 = @truncate(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                            next_slot_ptr = try self.readListSlot(list_ptr, key, shift, write_mode);
                            return self.readSlot(path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                        },
                        .append => {
                            if (!allow_write) return error.WriteNotAllowed;

                            const append_result = try self.readListSlotAppend(next_list_start, write_mode);
                            _ = try self.readSlot(path[1..], allow_write, .{ .slot_ptr = append_result.slot_ptr });
                            // update list size and ptr
                            try self.core.seekTo(next_list_start);
                            const writer = self.core.writer();
                            try writer.writeIntLittle(u64, append_result.list_size);
                            try writer.writeIntLittle(u64, append_result.list_ptr);

                            return next_slot_ptr;
                        },
                        .append_copy => {
                            if (!allow_write) return error.WriteNotAllowed;

                            const reader = self.core.reader();
                            const writer = self.core.writer();

                            try self.core.seekTo(next_list_start);
                            const list_size = try reader.readIntLittle(u64);
                            // read the last slot in the list
                            var last_slot: u64 = 0;
                            if (list_size > 0) {
                                const key = list_size - 1;
                                const list_ptr = try reader.readIntLittle(u64);
                                const shift: u6 = @truncate(if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key));
                                const last_slot_ptr = try self.readListSlot(list_ptr, key, shift, .read_only);
                                last_slot = last_slot_ptr.slot;
                            }
                            // make the next slot
                            var append_result = try self.readListSlotAppend(next_list_start, write_mode);
                            // set its value to the last slot
                            if (last_slot != 0) {
                                try self.core.seekTo(append_result.slot_ptr.position);
                                try writer.writeIntLittle(u64, last_slot);
                                append_result.slot_ptr.slot = last_slot;
                            }
                            const final_slot_ptr = self.readSlot(path[1..], allow_write, .{ .slot_ptr = append_result.slot_ptr });
                            // update list size and ptr
                            try self.core.seekTo(next_list_start);
                            try writer.writeIntLittle(u64, append_result.list_size);
                            try writer.writeIntLittle(u64, append_result.list_ptr);

                            return final_slot_ptr;
                        },
                    }
                },
                .value => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (path.len > 1) return error.ValueMustBeAtEnd;

                    if (cursor != .slot_ptr) return error.NotImplemented;

                    const writer = self.core.writer();

                    var value_pos: u64 = undefined;

                    switch (part.value) {
                        .none => {
                            value_pos = 0;
                        },
                        .int => {
                            value_pos = part.value.int;
                        },
                        .bytes => {
                            const value_hash = hash_buffer(part.value.bytes);
                            const next_slot_ptr = try self.readMapSlot(VALUE_INDEX_START, value_hash, 0, .write);
                            const slot_pos = next_slot_ptr.position;
                            const slot = next_slot_ptr.slot;
                            const ptr = getPointerValue(slot);

                            if (ptr == 0) {
                                // if slot was empty, insert the new value
                                try self.core.seekFromEnd(0);
                                value_pos = try self.core.getPos();
                                try writer.writeIntLittle(u64, part.value.bytes.len);
                                try writer.writeAll(part.value.bytes);
                                try self.core.seekTo(slot_pos);
                                try writer.writeIntLittle(u64, setType(value_pos, .bytes));
                            } else {
                                const ptr_type = getPointerType(slot);
                                if (ptr_type != .bytes) {
                                    return error.UnexpectedPointerType;
                                }
                                // get the existing value
                                value_pos = ptr;
                            }
                        },
                    }

                    const ptr: u64 = switch (part.value) {
                        .none => value_pos,
                        .int => setType(value_pos, .int),
                        .bytes => setType(value_pos, .bytes),
                    };

                    try self.core.seekTo(cursor.slot_ptr.position);
                    try writer.writeIntLittle(u64, ptr);

                    return cursor.slot_ptr;
                },
                .path => {
                    if (!allow_write) return error.WriteNotAllowed;
                    const next_slot_ptr = try self.readSlot(part.path, allow_write, cursor);
                    return try self.readSlot(path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                },
            }
        }

        // maps

        fn readMapSlot(self: *Database(kind), index_pos: u64, key_hash: Hash, key_offset: u8, write_mode: WriteMode) !SlotPointer {
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
                if (write_mode == .write or write_mode == .write_immutable) {
                    try self.core.seekFromEnd(0);
                    // write hash
                    const hash_pos = try self.core.getPos();
                    try writer.writeAll(std.mem.asBytes(&key_hash)[0..HASH_SIZE]);
                    // write empty value slot
                    const value_slot_pos = try self.core.getPos();
                    try writer.writeIntLittle(u64, 0);
                    // point slot to hash pos
                    try self.core.seekTo(slot_pos);
                    try writer.writeIntLittle(u64, setType(hash_pos, .hash));
                    return SlotPointer{ .position = value_slot_pos, .slot = slot };
                } else {
                    return error.KeyNotFound;
                }
            }

            const ptr_type = getPointerType(slot);
            const ptr = getPointerValue(slot);

            switch (ptr_type) {
                .index => {
                    var next_ptr = ptr;
                    if (write_mode == .write_immutable) {
                        // read existing block
                        try self.core.seekTo(ptr);
                        var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try reader.readNoEof(&index_block);
                        // copy it to the end
                        try self.core.seekFromEnd(0);
                        next_ptr = @intCast(try self.core.getPos());
                        try writer.writeAll(&index_block);
                        // make slot point to block
                        try self.core.seekTo(slot_pos);
                        try writer.writeIntLittle(u64, setType(next_ptr, .index));
                    }
                    return self.readMapSlot(next_ptr, key_hash, key_offset + 1, write_mode);
                },
                else => {
                    if (ptr_type != .hash) {
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
                        if (write_mode == .write_immutable) {
                            try self.core.seekFromEnd(0);
                            // write hash
                            const hash_pos = try self.core.getPos();
                            try writer.writeAll(std.mem.asBytes(&key_hash)[0..HASH_SIZE]);
                            // write value slot
                            const next_value_slot_pos = try self.core.getPos();
                            try writer.writeIntLittle(u64, value_slot);
                            // point slot to hash pos
                            try self.core.seekTo(slot_pos);
                            try writer.writeIntLittle(u64, setType(hash_pos, .hash));
                            return SlotPointer{ .position = next_value_slot_pos, .slot = value_slot };
                        } else {
                            return SlotPointer{ .position = value_slot_pos, .slot = value_slot };
                        }
                    } else {
                        if (write_mode == .write or write_mode == .write_immutable) {
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
                            const next_slot_ptr = try self.readMapSlot(next_index_pos, key_hash, key_offset + 1, write_mode);
                            try self.core.seekTo(slot_pos);
                            try writer.writeIntLittle(u64, setType(next_index_pos, .index));
                            return next_slot_ptr;
                        } else {
                            return error.KeyNotFound;
                        }
                    }
                },
            }
        }

        // lists

        const AppendResult = struct {
            list_size: u64,
            list_ptr: u64,
            slot_ptr: SlotPointer,
        };

        fn readListSlotAppend(self: *Database(kind), index_start: u64, write_mode: WriteMode) !AppendResult {
            const reader = self.core.reader();
            const writer = self.core.writer();

            try self.core.seekTo(index_start);
            const key = try reader.readIntLittle(u64);
            var index_pos = try reader.readIntLittle(u64);

            const prev_shift: u6 = @truncate(if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key - 1));
            const next_shift: u6 = @truncate(if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key));

            var slot_ptr: SlotPointer = undefined;

            if (prev_shift != next_shift) {
                // root overflow
                try self.core.seekFromEnd(0);
                const next_index_pos = try self.core.getPos();
                var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                try writer.writeAll(&index_block);
                try self.core.seekTo(next_index_pos);
                try writer.writeIntLittle(u64, index_pos);
                slot_ptr = try self.readListSlot(next_index_pos, key, next_shift, write_mode);
                index_pos = next_index_pos;
            } else {
                slot_ptr = try self.readListSlot(index_pos, key, next_shift, write_mode);
            }

            return AppendResult{ .list_size = key + 1, .list_ptr = index_pos, .slot_ptr = slot_ptr };
        }

        fn readListSlot(self: *Database(kind), index_pos: u64, key: u64, shift: u6, write_mode: WriteMode) !SlotPointer {
            const reader = self.core.reader();

            const i = (key >> (shift * BIT_COUNT)) & MASK;
            const slot_pos = index_pos + (POINTER_SIZE * i);
            try self.core.seekTo(slot_pos);
            const slot = try reader.readIntLittle(u64);

            if (slot == 0) {
                if (write_mode == .write or write_mode == .write_immutable) {
                    if (shift == 0) {
                        return SlotPointer{ .position = slot_pos, .slot = slot };
                    } else {
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const next_index_pos = try self.core.getPos();
                        var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try writer.writeAll(&index_block);
                        try self.core.seekTo(slot_pos);
                        try writer.writeIntLittle(u64, setType(next_index_pos, .index));
                        return try self.readListSlot(next_index_pos, key, shift - 1, write_mode);
                    }
                } else {
                    return error.KeyNotFound;
                }
            } else {
                const ptr_type = getPointerType(slot);
                const ptr = getPointerValue(slot);
                if (shift == 0) {
                    return SlotPointer{ .position = slot_pos, .slot = slot };
                } else {
                    if (ptr_type != .index) {
                        return error.UnexpectedPointerType;
                    }
                    var next_ptr = ptr;
                    if (write_mode == .write_immutable) {
                        // read existing block
                        try self.core.seekTo(ptr);
                        var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try reader.readNoEof(&index_block);
                        // copy it to the end
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        next_ptr = @intCast(try self.core.getPos());
                        try writer.writeAll(&index_block);
                        // make slot point to block
                        try self.core.seekTo(slot_pos);
                        try writer.writeIntLittle(u64, setType(next_ptr, .index));
                    }
                    return self.readListSlot(next_ptr, key, shift - 1, write_mode);
                }
            }
        }
    };
}

test "get/set pointer type" {
    const ptr_value = setType(42, .map);
    try std.testing.expectEqual(PointerType.map, getPointerType(ptr_value));
    const ptr_index = setType(42, .index);
    try std.testing.expectEqual(PointerType.index, getPointerType(ptr_index));
}
