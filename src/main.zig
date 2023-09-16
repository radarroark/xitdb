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
    uint = 0b1100 << 60,
};

const POINTER_TYPE_MASK: u64 = 0b1111 << 60;

const Index = struct {
    index: u64,
    reverse: bool,
};

pub fn PathPart(comptime UpdateCtx: type) type {
    return union(enum) {
        map_create,
        list_create,
        map_get: union(enum) {
            hash: Hash,
            bytes: []const u8,
        },
        list_get: union(enum) {
            index: Index,
            append,
            append_copy,
        },
        map_remove: union(enum) {
            hash: Hash,
            bytes: []const u8,
        },
        value: union(enum) {
            uint: u60,
            bytes: []const u8,
        },
        update: UpdateCtx,
        path: []const PathPart(UpdateCtx),
    };
}

const WriteMode = enum {
    read_only,
    write,
    write_immutable,
};

fn setType(ptr: u64, ptr_type: PointerType) u64 {
    return ptr | @intFromEnum(ptr_type);
}

fn getPointerType(ptr: u64) !PointerType {
    return std.meta.intToEnum(PointerType, ptr & POINTER_TYPE_MASK);
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
};

pub const DatabaseKind = enum {
    memory,
    file,
};

pub const SlotPointer = struct {
    position: u64,
    slot: u64,
};

pub fn Database(comptime db_kind: DatabaseKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: Core,

        pub const Core = switch (db_kind) {
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

        pub const InitOpts = switch (db_kind) {
            .memory => struct {
                capacity: usize,
            },
            .file => struct {
                file: std.fs.File,
            },
        };

        pub fn init(allocator: std.mem.Allocator, opts: InitOpts) !Database(db_kind) {
            switch (db_kind) {
                .memory => {
                    var buffer = try std.ArrayList(u8).initCapacity(allocator, opts.capacity);
                    buffer.expandToCapacity();

                    var self = Database(db_kind){
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
                    var self = Database(db_kind){
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

        pub fn deinit(self: *Database(db_kind)) void {
            self.core.deinit();
        }

        pub const Cursor = struct {
            read_slot_cursor: ReadSlotCursor,
            db: *Database(db_kind),

            pub fn execute(self: Cursor, comptime UpdateCtx: type, path: []const PathPart(UpdateCtx)) !void {
                _ = try self.db.readSlot(UpdateCtx, path, true, self.read_slot_cursor);
            }

            pub fn readBytesAlloc(self: Cursor, allocator: std.mem.Allocator, comptime UpdateCtx: type, path: []const PathPart(UpdateCtx)) !?[]u8 {
                const reader = self.db.core.reader();

                const slot_ptr = self.db.readSlot(UpdateCtx, path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                const slot = slot_ptr.slot;
                const ptr = getPointerValue(slot);
                const ptr_type = try getPointerType(slot);

                const position = switch (ptr_type) {
                    .bytes => ptr,
                    .hash => blk: {
                        try self.db.core.seekTo(ptr + HASH_SIZE);
                        const value_slot = try reader.readIntLittle(u64);
                        const value_ptr_type = try getPointerType(value_slot);
                        if (value_ptr_type != .bytes) {
                            return error.UnexpectedPointerType;
                        }
                        break :blk getPointerValue(value_slot);
                    },
                    else => return error.UnexpectedPointerType,
                };

                try self.db.core.seekTo(position);
                const value_size = try reader.readIntLittle(u64);

                var value = try allocator.alloc(u8, value_size);
                errdefer allocator.free(value);

                try reader.readNoEof(value);
                return value;
            }

            pub fn readBytes(self: Cursor, buffer: []u8, comptime UpdateCtx: type, path: []const PathPart(UpdateCtx)) !?[]u8 {
                const reader = self.db.core.reader();

                const slot_ptr = self.db.readSlot(UpdateCtx, path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                const slot = slot_ptr.slot;
                const ptr = getPointerValue(slot);
                const ptr_type = try getPointerType(slot);

                const position = switch (ptr_type) {
                    .bytes => ptr,
                    .hash => blk: {
                        try self.db.core.seekTo(ptr + HASH_SIZE);
                        const value_slot = try reader.readIntLittle(u64);
                        const value_ptr_type = try getPointerType(value_slot);
                        if (value_ptr_type != .bytes) {
                            return error.UnexpectedPointerType;
                        }
                        break :blk getPointerValue(value_slot);
                    },
                    else => return error.UnexpectedPointerType,
                };

                try self.db.core.seekTo(position);
                const value_size = try reader.readIntLittle(u64);
                const size = @min(buffer.len, value_size);

                try reader.readNoEof(buffer[0..size]);
                return buffer[0..size];
            }

            pub fn readKeyBytesAlloc(self: Cursor, allocator: std.mem.Allocator, comptime UpdateCtx: type, path: []const PathPart(UpdateCtx)) !?[]u8 {
                const reader = self.db.core.reader();

                const slot_ptr = self.db.readSlot(UpdateCtx, path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                const slot = slot_ptr.slot;
                const ptr = getPointerValue(slot);
                const ptr_type = try getPointerType(slot);

                if (ptr_type != .hash) {
                    return error.UnexpectedPointerType;
                }

                try self.db.core.seekTo(ptr);
                var hash = [_]u8{0} ** HASH_INT_SIZE;
                try reader.readNoEof(hash[0..HASH_SIZE]);

                const value_cursor = Cursor{
                    .read_slot_cursor = ReadSlotCursor{
                        .index_start = VALUE_INDEX_START,
                    },
                    .db = self.db,
                };
                return value_cursor.readBytesAlloc(allocator, void, &[_]PathPart(void){.{ .map_get = .{ .hash = std.mem.bytesToValue(Hash, &hash) } }});
            }

            pub fn readInt(self: Cursor, comptime UpdateCtx: type, path: []const PathPart(UpdateCtx)) !?u60 {
                const slot_ptr = self.db.readSlot(UpdateCtx, path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                const slot = slot_ptr.slot;
                const ptr = getPointerValue(slot);
                const ptr_type = try getPointerType(slot);

                const value = switch (ptr_type) {
                    .uint => ptr,
                    .hash => blk: {
                        const reader = self.db.core.reader();
                        try self.db.core.seekTo(ptr + HASH_SIZE);
                        const value_slot = try reader.readIntLittle(u64);
                        const value_ptr_type = try getPointerType(value_slot);
                        if (value_ptr_type != .uint) {
                            return error.UnexpectedPointerType;
                        }
                        break :blk getPointerValue(value_slot);
                    },
                    else => return error.UnexpectedPointerType,
                };
                return value;
            }

            pub fn readCursor(self: Cursor, comptime UpdateCtx: type, path: []const PathPart(UpdateCtx)) !?Cursor {
                const slot_ptr = self.db.readSlot(UpdateCtx, path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                return Cursor{
                    .read_slot_cursor = ReadSlotCursor{
                        .slot_ptr = slot_ptr,
                    },
                    .db = self.db,
                };
            }

            pub const Iter = struct {
                cursor: Cursor,
                core: IterCore,

                pub const IterKind = enum {
                    list,
                    map,
                };
                pub const IterCore = union(IterKind) {
                    list: struct {
                        index: u64,
                    },
                    map: struct {
                        stack: std.ArrayList(MapLevel),
                    },

                    pub const MapLevel = struct {
                        position: u64,
                        block: [SLOT_COUNT]u64,
                        index: u16,
                    };
                };

                pub fn init(cursor: Cursor, iter_db_kind: IterKind) !Iter {
                    const core: IterCore = switch (iter_db_kind) {
                        .list => .{
                            .list = .{
                                .index = 0,
                            },
                        },
                        .map => .{
                            .map = .{
                                .stack = blk: {
                                    // find the block
                                    const position = switch (cursor.read_slot_cursor) {
                                        .index_start => cursor.read_slot_cursor.index_start,
                                        .slot_ptr => pos_blk: {
                                            const ptr = getPointerValue(cursor.read_slot_cursor.slot_ptr.slot);
                                            const ptr_type = try getPointerType(cursor.read_slot_cursor.slot_ptr.slot);
                                            if (ptr_type != .map) {
                                                return error.UnexpectedPointerType;
                                            }
                                            break :pos_blk ptr;
                                        },
                                    };
                                    try cursor.db.core.seekTo(position);
                                    // read the block
                                    const reader = cursor.db.core.reader();
                                    var map_index_block_bytes = [_]u8{0} ** INDEX_BLOCK_SIZE;
                                    try reader.readNoEof(&map_index_block_bytes);
                                    // convert the block into 64-bit little endian ints
                                    var map_index_block = [_]u64{0} ** SLOT_COUNT;
                                    {
                                        var stream = std.io.fixedBufferStream(&map_index_block_bytes);
                                        var block_reader = stream.reader();
                                        for (&map_index_block) |*block_slot| {
                                            block_slot.* = try block_reader.readIntLittle(u64);
                                        }
                                    }
                                    // init the stack
                                    var stack = std.ArrayList(IterCore.MapLevel).init(cursor.db.allocator);
                                    try stack.append(IterCore.MapLevel{
                                        .position = position,
                                        .block = map_index_block,
                                        .index = 0,
                                    });
                                    break :blk stack;
                                },
                            },
                        },
                    };
                    return .{
                        .cursor = cursor,
                        .core = core,
                    };
                }

                pub fn deinit(self: *Iter) void {
                    switch (self.core) {
                        .list => {},
                        .map => self.core.map.stack.deinit(),
                    }
                }

                pub fn next(self: *Iter) !?Cursor {
                    switch (self.core) {
                        .list => {
                            const index = self.core.list.index;
                            const path = &[_]PathPart(void){.{ .list_get = .{ .index = .{ .index = index, .reverse = false } } }};
                            const slot_ptr = self.cursor.db.readSlot(void, path, false, self.cursor.read_slot_cursor) catch |err| {
                                switch (err) {
                                    error.KeyNotFound => return null,
                                    else => return err,
                                }
                            };
                            self.core.list.index += 1;
                            return Cursor{
                                .read_slot_cursor = ReadSlotCursor{
                                    .slot_ptr = slot_ptr,
                                },
                                .db = self.cursor.db,
                            };
                        },
                        .map => {
                            while (self.core.map.stack.items.len > 0) {
                                const level = self.core.map.stack.items[self.core.map.stack.items.len - 1];
                                if (level.index == level.block.len) {
                                    _ = self.core.map.stack.pop();
                                    if (self.core.map.stack.items.len > 0) {
                                        self.core.map.stack.items[self.core.map.stack.items.len - 1].index += 1;
                                    }
                                    continue;
                                } else {
                                    const slot = level.block[level.index];
                                    if (slot == 0) {
                                        self.core.map.stack.items[self.core.map.stack.items.len - 1].index += 1;
                                        continue;
                                    } else {
                                        const ptr_type = try getPointerType(slot);
                                        if (ptr_type == .index) {
                                            // find the block
                                            const next_pos = getPointerValue(slot);
                                            try self.cursor.db.core.seekTo(next_pos);
                                            // read the block
                                            const reader = self.cursor.db.core.reader();
                                            var map_index_block_bytes = [_]u8{0} ** INDEX_BLOCK_SIZE;
                                            try reader.readNoEof(&map_index_block_bytes);
                                            // convert the block into 64-bit little endian ints
                                            var map_index_block = [_]u64{0} ** SLOT_COUNT;
                                            {
                                                var stream = std.io.fixedBufferStream(&map_index_block_bytes);
                                                var block_reader = stream.reader();
                                                for (&map_index_block) |*block_slot| {
                                                    block_slot.* = try block_reader.readIntLittle(u64);
                                                }
                                            }
                                            // append to the stack
                                            try self.core.map.stack.append(IterCore.MapLevel{
                                                .position = next_pos,
                                                .block = map_index_block,
                                                .index = 0,
                                            });
                                            continue;
                                        } else {
                                            self.core.map.stack.items[self.core.map.stack.items.len - 1].index += 1;
                                            const position = level.position + (level.index * POINTER_SIZE);
                                            return Cursor{
                                                .read_slot_cursor = ReadSlotCursor{
                                                    .slot_ptr = SlotPointer{ .position = position, .slot = slot },
                                                },
                                                .db = self.cursor.db,
                                            };
                                        }
                                    }
                                }
                            }
                            return null;
                        },
                    }
                }
            };

            pub fn iter(self: Cursor, iter_db_kind: Iter.IterKind) !Iter {
                return try Iter.init(self, iter_db_kind);
            }
        };

        pub fn rootCursor(self: *Database(db_kind)) Cursor {
            return Cursor{
                .read_slot_cursor = .{ .index_start = KEY_INDEX_START },
                .db = self,
            };
        }

        fn writeHeader(self: *Database(db_kind)) !void {
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

        fn readSlot(self: *Database(db_kind), comptime UpdateCtx: type, path: []const PathPart(UpdateCtx), allow_write: bool, cursor: ReadSlotCursor) !SlotPointer {
            const part = if (path.len > 0) path[0] else switch (cursor) {
                .index_start => return SlotPointer{ .position = 0, .slot = 0 },
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
                .map_create => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (cursor != .slot_ptr) return error.NotImplemented;

                    if (cursor.slot_ptr.slot == 0) {
                        // if slot was empty, insert the new map
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const map_start = try self.core.getPos();
                        const map_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try writer.writeAll(&map_index_block);
                        // make slot point to map
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = setType(map_start, .map) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeIntLittle(u64, next_slot_ptr.slot);
                        return self.readSlot(UpdateCtx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    } else {
                        const ptr_type = try getPointerType(cursor.slot_ptr.slot);
                        if (ptr_type != .map) {
                            return error.UnexpectedPointerType;
                        }
                        const next_pos = getPointerValue(cursor.slot_ptr.slot);
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
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = setType(map_start, .map) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeIntLittle(u64, next_slot_ptr.slot);
                        return self.readSlot(UpdateCtx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    }
                },
                .list_create => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (cursor != .slot_ptr) return error.NotImplemented;

                    if (cursor.slot_ptr.slot == 0) {
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
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = setType(list_start, .list) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeIntLittle(u64, next_slot_ptr.slot);
                        return self.readSlot(UpdateCtx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    } else {
                        const ptr_type = try getPointerType(cursor.slot_ptr.slot);
                        if (ptr_type != .list) {
                            return error.UnexpectedPointerType;
                        }
                        const next_pos = getPointerValue(cursor.slot_ptr.slot);
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
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = setType(list_start, .list) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeIntLittle(u64, next_slot_ptr.slot);
                        return self.readSlot(UpdateCtx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    }
                },
                .map_get => {
                    const next_map_start = switch (cursor) {
                        .index_start => cursor.index_start,
                        .slot_ptr => blk: {
                            if (cursor.slot_ptr.slot == 0) {
                                return error.KeyNotFound;
                            } else {
                                const ptr_type = try getPointerType(cursor.slot_ptr.slot);
                                if (ptr_type != .map) {
                                    return error.UnexpectedPointerType;
                                }
                                break :blk getPointerValue(cursor.slot_ptr.slot);
                            }
                        },
                    };
                    const hash = switch (part.map_get) {
                        .hash => part.map_get.hash,
                        .bytes => blk: {
                            const value_hash = hash_buffer(part.map_get.bytes);
                            // write key so we can retrieve it when iterating over map
                            if (allow_write) {
                                _ = try self.writeValue(value_hash, part.map_get.bytes);
                            }
                            break :blk value_hash;
                        },
                    };
                    const next_slot_ptr = try self.readMapSlot(next_map_start, hash, 0, write_mode, true);
                    return self.readSlot(UpdateCtx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                },
                .list_get => {
                    const next_list_start = switch (cursor) {
                        .index_start => cursor.index_start,
                        .slot_ptr => blk: {
                            if (cursor.slot_ptr.slot == 0) {
                                return error.KeyNotFound;
                            } else {
                                const ptr_type = try getPointerType(cursor.slot_ptr.slot);
                                if (ptr_type != .list) {
                                    return error.UnexpectedPointerType;
                                }
                                break :blk getPointerValue(cursor.slot_ptr.slot);
                            }
                        },
                    };
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
                            const final_slot_ptr = try self.readListSlot(list_ptr, key, shift, write_mode);
                            return try self.readSlot(UpdateCtx, path[1..], allow_write, .{ .slot_ptr = final_slot_ptr });
                        },
                        .append => {
                            if (!allow_write) return error.WriteNotAllowed;

                            const append_result = try self.readListSlotAppend(next_list_start, write_mode);
                            const final_slot_ptr = try self.readSlot(UpdateCtx, path[1..], allow_write, .{ .slot_ptr = append_result.slot_ptr });
                            // update list size and ptr
                            try self.core.seekTo(next_list_start);
                            const writer = self.core.writer();
                            try writer.writeIntLittle(u64, append_result.list_size);
                            try writer.writeIntLittle(u64, append_result.list_ptr);

                            return final_slot_ptr;
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
                            const final_slot_ptr = try self.readSlot(UpdateCtx, path[1..], allow_write, .{ .slot_ptr = append_result.slot_ptr });
                            // update list size and ptr
                            try self.core.seekTo(next_list_start);
                            try writer.writeIntLittle(u64, append_result.list_size);
                            try writer.writeIntLittle(u64, append_result.list_ptr);

                            return final_slot_ptr;
                        },
                    }
                },
                .map_remove => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (path.len > 1) return error.ValueMustBeAtEnd;

                    const next_map_start = switch (cursor) {
                        .index_start => cursor.index_start,
                        .slot_ptr => blk: {
                            if (cursor.slot_ptr.slot == 0) {
                                return error.KeyNotFound;
                            } else {
                                const ptr_type = try getPointerType(cursor.slot_ptr.slot);
                                if (ptr_type != .map) {
                                    return error.UnexpectedPointerType;
                                }
                                break :blk getPointerValue(cursor.slot_ptr.slot);
                            }
                        },
                    };
                    const hash = switch (part.map_remove) {
                        .hash => part.map_remove.hash,
                        .bytes => hash_buffer(part.map_remove.bytes),
                    };
                    const next_slot_ptr = try self.readMapSlot(next_map_start, hash, 0, .read_only, false);

                    const writer = self.core.writer();
                    try self.core.seekTo(next_slot_ptr.position);
                    try writer.writeIntLittle(u64, 0);

                    return next_slot_ptr;
                },
                .value => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (path.len > 1) return error.ValueMustBeAtEnd;

                    if (cursor != .slot_ptr) return error.NotImplemented;

                    const ptr: u64 = switch (part.value) {
                        .uint => setType(part.value.uint, .uint),
                        .bytes => setType(try self.writeValue(hash_buffer(part.value.bytes), part.value.bytes), .bytes),
                    };

                    const writer = self.core.writer();
                    try self.core.seekTo(cursor.slot_ptr.position);
                    try writer.writeIntLittle(u64, ptr);

                    return cursor.slot_ptr;
                },
                .update => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (path.len > 1) return error.ValueMustBeAtEnd;

                    if (cursor != .slot_ptr) return error.NotImplemented;

                    if (@TypeOf(part.update) == void) {
                        return error.NotImplmented;
                    } else {
                        const next_cursor = Cursor{
                            .read_slot_cursor = ReadSlotCursor{
                                .slot_ptr = cursor.slot_ptr,
                            },
                            .db = self,
                        };
                        try part.update.update(next_cursor, cursor.slot_ptr.slot == 0);
                        return cursor.slot_ptr;
                    }
                },
                .path => {
                    if (!allow_write) return error.WriteNotAllowed;
                    _ = try self.readSlot(UpdateCtx, part.path, allow_write, cursor);
                    return try self.readSlot(UpdateCtx, path[1..], allow_write, cursor);
                },
            }
        }

        fn writeValue(self: *Database(db_kind), value_hash: Hash, value: []const u8) !u64 {
            const next_slot_ptr = try self.readMapSlot(VALUE_INDEX_START, value_hash, 0, .write, true);
            const slot_pos = next_slot_ptr.position;
            const slot = next_slot_ptr.slot;
            const ptr = getPointerValue(slot);

            var value_pos: u64 = undefined;

            if (ptr == 0) {
                const writer = self.core.writer();
                // if slot was empty, insert the new value
                try self.core.seekFromEnd(0);
                value_pos = try self.core.getPos();
                try writer.writeIntLittle(u64, value.len);
                try writer.writeAll(value);
                try self.core.seekTo(slot_pos);
                try writer.writeIntLittle(u64, setType(value_pos, .bytes));
            } else {
                const ptr_type = try getPointerType(slot);
                if (ptr_type != .bytes) {
                    return error.UnexpectedPointerType;
                }
                // get the existing value
                value_pos = ptr;
            }

            return value_pos;
        }

        // maps

        fn readMapSlot(self: *Database(db_kind), index_pos: u64, key_hash: Hash, key_offset: u8, write_mode: WriteMode, return_value_slot: bool) !SlotPointer {
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

            const ptr_type = try getPointerType(slot);
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
                    return self.readMapSlot(next_ptr, key_hash, key_offset + 1, write_mode, return_value_slot);
                },
                .hash => {
                    try self.core.seekTo(ptr);
                    const existing_key_hash = blk: {
                        var hash = [_]u8{0} ** HASH_INT_SIZE;
                        try reader.readNoEof(hash[0..HASH_SIZE]);
                        break :blk std.mem.bytesToValue(Hash, &hash);
                    };
                    if (existing_key_hash == key_hash) {
                        if (write_mode == .write_immutable) {
                            const value_slot = try reader.readIntLittle(u64);
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
                            if (return_value_slot) {
                                const value_slot_pos = try self.core.getPos();
                                const value_slot = try reader.readIntLittle(u64);
                                return SlotPointer{ .position = value_slot_pos, .slot = value_slot };
                            } else {
                                return SlotPointer{ .position = slot_pos, .slot = slot };
                            }
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
                            const next_slot_ptr = try self.readMapSlot(next_index_pos, key_hash, key_offset + 1, write_mode, return_value_slot);
                            try self.core.seekTo(slot_pos);
                            try writer.writeIntLittle(u64, setType(next_index_pos, .index));
                            return next_slot_ptr;
                        } else {
                            return error.KeyNotFound;
                        }
                    }
                },
                else => {
                    return error.UnexpectedPointerType;
                },
            }
        }

        // lists

        const AppendResult = struct {
            list_size: u64,
            list_ptr: u64,
            slot_ptr: SlotPointer,
        };

        fn readListSlotAppend(self: *Database(db_kind), index_start: u64, write_mode: WriteMode) !AppendResult {
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

        fn readListSlot(self: *Database(db_kind), index_pos: u64, key: u64, shift: u6, write_mode: WriteMode) !SlotPointer {
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
                const ptr_type = try getPointerType(slot);
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
    try std.testing.expectEqual(PointerType.map, try getPointerType(ptr_value));
    const ptr_index = setType(42, .index);
    try std.testing.expectEqual(PointerType.index, try getPointerType(ptr_index));
}
