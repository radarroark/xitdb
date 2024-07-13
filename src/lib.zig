//! you're looking at radar's hopeless attempt to implement
//! his dream database. it will be embedded and immutable.
//! it will be practical for both on-disk and in-memory use.
//! there is so much work to do, and so much to learn. we're
//! gonna leeroy jenkins our way through this.

const std = @import("std");

// using sha1 to hash the keys for now, but this will eventually be
// configurable. for many uses it will be overkill...
pub const HASH_SIZE = std.crypto.hash.Sha1.digest_length;
pub const Hash = u160;
comptime {
    std.debug.assert(@bitSizeOf(Hash) == HASH_SIZE * 8);
}
pub const HASH_INT_SIZE = @sizeOf(Hash);

fn byteSizeOf(T: type) u64 {
    return @bitSizeOf(T) / 8;
}

const HEADER_BLOCK_SIZE = 2;
const BIT_COUNT = 4;
pub const SLOT_COUNT = 1 << BIT_COUNT;
pub const MASK: u64 = SLOT_COUNT - 1;
const INDEX_BLOCK_SIZE = byteSizeOf(Slot) * SLOT_COUNT;
const INDEX_START = HEADER_BLOCK_SIZE;
const LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE = byteSizeOf(LinkedArrayListSlot) * SLOT_COUNT;

const SlotInt = u72;
pub const Slot = packed struct {
    value: u64 = 0,
    tag: u8 = 0,

    pub fn init(ptr: u64, tag: Tag) Slot {
        return .{
            .value = ptr,
            .tag = @intFromEnum(tag),
        };
    }

    pub fn eql(self: Slot, other: Slot) bool {
        const self_int: SlotInt = @bitCast(self);
        const other_int: SlotInt = @bitCast(other);
        return self_int == other_int;
    }
};
pub const Tag = enum(u8) {
    index = 1,
    array_list = 2,
    linked_array_list = 3,
    hash_map = 4,
    hash = 5,
    bytes = 6,
    uint = 7,

    pub fn init(slot: Slot) !Tag {
        return std.meta.intToEnum(Tag, slot.tag);
    }
};

const ArrayListHeaderInt = u128;
const ArrayListHeader = packed struct {
    ptr: u64,
    size: u64,
};

const LinkedArrayListSlotInt = u136;
pub const LinkedArrayListSlot = packed struct {
    size: u64,
    slot: Slot,
};

pub const SlotPointer = struct {
    position: u64,
    slot: Slot,
};

pub const LinkedArrayListSlotPointer = struct {
    slot_ptr: SlotPointer,
    leaf_count: u64,
};

const LinkedArrayListBlockInfo = struct {
    block: [SLOT_COUNT]LinkedArrayListSlot,
    i: u4,
    ptr: u64,
    leaf_count: u64,
};

pub fn PathPart(comptime Ctx: type) type {
    return union(enum) {
        array_list_create,
        array_list_get: union(enum) {
            index: struct {
                index: u64,
                reverse: bool,
            },
            append,
            append_copy,
        },
        linked_array_list_create,
        linked_array_list_get: union(enum) {
            index: struct {
                index: u64,
                reverse: bool,
            },
            append,
        },
        hash_map_create,
        hash_map_get: Hash,
        hash_map_remove: Hash,
        value: union(enum) {
            slot: Slot,
            uint: u64,
            bytes: []const u8,
        },
        ctx: Ctx,
        path: []const PathPart(Ctx),
    };
}

const WriteMode = enum {
    read_only,
    write,
    write_immutable,
};

pub const DatabaseKind = enum {
    memory,
    file,
};

pub fn Database(comptime db_kind: DatabaseKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: Core,
        tx_start: ?u64,

        pub const Core = switch (db_kind) {
            .memory => struct {
                buffer: std.ArrayList(u8),
                size: u64,
                position: u64,

                const Reader = struct {
                    parent: *Core,

                    pub fn read(self: Core.Reader, buf: []u8) !u64 {
                        const new_position = self.parent.position + @min(@as(u64, @intCast(buf.len)), self.parent.size - self.parent.position);
                        if (new_position > self.parent.size) return error.EndOfStream;
                        @memcpy(buf, self.parent.buffer.items[self.parent.position..new_position]);
                        const size = new_position - self.parent.position;
                        self.parent.position = new_position;
                        return size;
                    }

                    pub fn readNoEof(self: Core.Reader, buf: []u8) !void {
                        const new_position = self.parent.position + @as(u64, @intCast(buf.len));
                        if (new_position > self.parent.size) return error.EndOfStream;
                        @memcpy(buf, self.parent.buffer.items[self.parent.position..new_position]);
                        self.parent.position = new_position;
                    }

                    pub fn readInt(self: Core.Reader, comptime T: type, endian: std.builtin.Endian) !T {
                        if (@bitSizeOf(T) % 8 != 0) {
                            return error.InvalidTypeSize;
                        }
                        const size = @bitSizeOf(T) / 8;
                        const new_position = self.parent.position + size;
                        if (new_position > self.parent.size) return error.EndOfStream;
                        const bytes = self.parent.buffer.items[self.parent.position..new_position];
                        self.parent.position = new_position;
                        return std.mem.toNative(T, std.mem.bytesToValue(T, bytes), endian);
                    }
                };

                const Writer = struct {
                    parent: *Core,

                    pub fn writeAll(self: Core.Writer, bytes: []const u8) !void {
                        const new_position = self.parent.position + @as(u64, @intCast(bytes.len));
                        @memcpy(self.parent.buffer.items[self.parent.position..new_position], bytes);
                        self.parent.size = @max(self.parent.size, new_position);
                        self.parent.position = new_position;
                    }

                    pub fn writeInt(self: Core.Writer, comptime T: type, value: T, endian: std.builtin.Endian) !void {
                        if (@bitSizeOf(T) % 8 != 0) {
                            return error.InvalidTypeSize;
                        }
                        const size = @bitSizeOf(T) / 8;
                        const new_position = self.parent.position + size;
                        const bytes = std.mem.asBytes(&std.mem.nativeTo(T, value, endian));
                        @memcpy(self.parent.buffer.items[self.parent.position..new_position], bytes[0..size]);
                        self.parent.size = @max(self.parent.size, new_position);
                        self.parent.position = new_position;
                    }
                };

                pub fn deinit(self: *Core) void {
                    self.buffer.deinit();
                }

                pub fn reader(self: *Core) Core.Reader {
                    return Core.Reader{ .parent = self };
                }

                pub fn writer(self: *Core) Core.Writer {
                    return Core.Writer{ .parent = self };
                }

                pub fn seekTo(self: *Core, offset: u64) !void {
                    self.position = offset;
                }

                pub fn seekBy(self: *Core, offset: i64) !void {
                    if (offset > 0) {
                        self.position +|= @intCast(@abs(offset));
                    } else {
                        self.position -|= @intCast(@abs(offset));
                    }
                }

                pub fn seekFromEnd(self: *Core, offset: i64) !void {
                    if (offset <= 0) {
                        self.position = self.size -| @as(u64, @intCast(@abs(offset)));
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

                pub fn seekBy(self: Core, offset: i64) !void {
                    try self.file.seekBy(offset);
                }

                pub fn seekFromEnd(self: Core, offset: i64) !void {
                    try self.file.seekFromEnd(offset);
                }

                pub fn getPos(self: Core) !u64 {
                    return @intCast(try self.file.getPos());
                }
            },
        };

        // init

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
                        .tx_start = null,
                    };

                    try self.writeHeader();

                    return self;
                },
                .file => {
                    var self = Database(db_kind){
                        .allocator = allocator,
                        .core = .{ .file = opts.file },
                        .tx_start = null,
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

        // cursor

        pub const Cursor = struct {
            read_slot_cursor: ReadSlotCursor,
            db: *Database(db_kind),

            pub const Reader = struct {
                parent: *Database(db_kind).Cursor,
                size: u64,
                start_position: u64,
                relative_position: u64,

                pub fn read(self: *Reader, buf: []u8) !u64 {
                    if (self.size < self.relative_position) return error.EndOfStream;
                    try self.parent.db.core.seekTo(self.start_position + self.relative_position);
                    const core_reader = self.parent.db.core.reader();
                    const size = try core_reader.read(buf[0..@min(buf.len, self.size - self.relative_position)]);
                    self.relative_position += @intCast(size);
                    return @intCast(size);
                }

                pub fn readNoEof(self: *Reader, buf: []u8) !void {
                    if (self.size < self.relative_position or self.size - self.relative_position < buf.len) return error.EndOfStream;
                    try self.parent.db.core.seekTo(self.start_position + self.relative_position);
                    const core_reader = self.parent.db.core.reader();
                    try core_reader.readNoEof(buf);
                    self.relative_position += @intCast(buf.len);
                }

                pub fn readInt(self: *Reader, comptime T: type, endian: std.builtin.Endian) !T {
                    if (self.size < self.relative_position or self.size - self.relative_position < byteSizeOf(T)) return error.EndOfStream;
                    try self.parent.db.core.seekTo(self.start_position + self.relative_position);
                    const core_reader = self.parent.db.core.reader();
                    const ret = try core_reader.readInt(T, endian);
                    self.relative_position += byteSizeOf(T);
                    return ret;
                }

                pub fn readUntilDelimiter(self: *Reader, buf: []u8, delimiter: u8) ![]u8 {
                    if (self.size < self.relative_position) return error.EndOfStream;
                    try self.parent.db.core.seekTo(self.start_position + self.relative_position);
                    const core_reader = self.parent.db.core.reader();
                    const buf_slice = core_reader.readUntilDelimiter(buf[0..@min(buf.len, self.size - self.relative_position)], delimiter) catch |err| switch (err) {
                        error.StreamTooLong => return error.EndOfStream,
                        else => return err,
                    };
                    self.relative_position += @intCast(buf_slice.len);
                    self.relative_position += 1; // for the delimiter
                    return buf_slice;
                }

                pub fn readUntilDelimiterAlloc(self: *Reader, allocator: std.mem.Allocator, delimiter: u8, max_size: usize) ![]u8 {
                    if (self.size < self.relative_position) return error.EndOfStream;
                    try self.parent.db.core.seekTo(self.start_position + self.relative_position);
                    const core_reader = self.parent.db.core.reader();
                    const buf_slice = core_reader.readUntilDelimiterAlloc(allocator, delimiter, @min(max_size, self.size - self.relative_position)) catch |err| switch (err) {
                        error.StreamTooLong => return error.EndOfStream,
                        else => return err,
                    };
                    self.relative_position += @intCast(buf_slice.len);
                    self.relative_position += 1; // for the delimiter
                    return buf_slice;
                }

                pub fn readAllAlloc(self: *Reader, allocator: std.mem.Allocator, max_size: usize) ![]u8 {
                    if (self.size < self.relative_position) return error.EndOfStream;
                    if (self.size - self.relative_position > max_size) return error.StreamTooLong;
                    const buffer = try allocator.alloc(u8, self.size - self.relative_position);
                    errdefer allocator.free(buffer);
                    try self.parent.db.core.seekTo(self.start_position + self.relative_position);
                    const core_reader = self.parent.db.core.reader();
                    const size = try core_reader.read(buffer);
                    if (size != buffer.len) {
                        return error.UnexpectedReadSize;
                    }
                    self.relative_position += @intCast(size);
                    return buffer;
                }

                pub fn seekTo(self: *Reader, offset: u64) !void {
                    if (offset > self.size) {
                        return error.InvalidOffset;
                    }
                    self.relative_position = offset;
                }

                pub fn seekBy(self: *Reader, offset: i64) !void {
                    if (offset > 0) {
                        self.relative_position = @min(self.size, self.relative_position +| @as(u64, @intCast(@abs(offset))));
                    } else {
                        self.relative_position -|= @intCast(@abs(offset));
                    }
                }

                pub fn seekFromEnd(self: *Reader, offset: i64) !void {
                    if (offset <= 0) {
                        self.relative_position = self.size -| @as(u64, @intCast(@abs(offset)));
                    }
                }
            };

            pub const Writer = struct {
                parent: *Database(db_kind).Cursor,
                slot_ptr: SlotPointer,
                size: u64,
                slot: Slot,
                start_position: u64,
                relative_position: u64,

                pub fn finish(self: Writer) !void {
                    const core_writer = self.parent.db.core.writer();

                    try self.parent.db.core.seekTo(self.slot.value);
                    try core_writer.writeInt(u64, self.size, .big);

                    try self.parent.db.core.seekTo(self.slot_ptr.position);
                    try core_writer.writeInt(SlotInt, @bitCast(self.slot), .big);

                    // if the cursor is directly pointing to the slot we are updating,
                    // make sure it is updated as well, so subsequent reads with the
                    // cursor will see the new value.
                    if (self.parent.read_slot_cursor == .slot_ptr and self.parent.read_slot_cursor.slot_ptr.position == self.slot_ptr.position) {
                        self.parent.read_slot_cursor.slot_ptr.slot = self.slot;
                    }
                }

                pub fn writeAll(self: *Writer, bytes: []const u8) !void {
                    if (self.size < self.relative_position) return error.EndOfStream;
                    try self.parent.db.core.seekTo(self.start_position + self.relative_position);
                    const core_writer = self.parent.db.core.writer();
                    try core_writer.writeAll(bytes);
                    self.relative_position += @intCast(bytes.len);
                    if (self.relative_position > self.size) {
                        self.size = self.relative_position;
                    }
                }

                pub fn writeInt(self: *Writer, comptime T: type, value: T, endian: std.builtin.Endian) !void {
                    if (self.size < self.relative_position) return error.EndOfStream;
                    try self.parent.db.core.seekTo(self.start_position + self.relative_position);
                    const core_writer = self.parent.db.core.writer();
                    try core_writer.writeInt(T, value, endian);
                    self.relative_position += byteSizeOf(T);
                    if (self.relative_position > self.size) {
                        self.size = self.relative_position;
                    }
                }

                pub fn seekTo(self: *Writer, offset: u64) !void {
                    if (offset <= self.size) {
                        self.relative_position = offset;
                    }
                }

                pub fn seekBy(self: *Writer, offset: i64) !void {
                    if (offset > 0) {
                        self.relative_position = @min(self.size, self.relative_position +| @as(u64, @intCast(@abs(offset))));
                    } else {
                        self.relative_position -|= @intCast(@abs(offset));
                    }
                }

                pub fn seekFromEnd(self: *Writer, offset: i64) !void {
                    if (offset <= 0) {
                        self.relative_position = self.size -| @as(u64, @intCast(@abs(offset)));
                    }
                }
            };

            pub fn execute(self: Cursor, comptime Ctx: type, path: []const PathPart(Ctx)) !Slot {
                return (try self.db.readSlot(Ctx, path, true, self.read_slot_cursor)).slot;
            }

            pub fn reader(self: *Cursor, comptime Ctx: type, path: []const PathPart(Ctx)) !?Reader {
                const core_reader = self.db.core.reader();

                const slot_ptr = self.db.readSlot(Ctx, path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                const slot = slot_ptr.slot;
                const ptr = slot.value;
                const tag = try Tag.init(slot);

                const position = switch (tag) {
                    .bytes => ptr,
                    .hash => blk: {
                        try self.db.core.seekTo(ptr + HASH_SIZE);
                        const value_slot: Slot = @bitCast(try core_reader.readInt(SlotInt, .big));
                        const value_tag = try Tag.init(value_slot);
                        if (value_tag != .bytes) {
                            return error.UnexpectedTag;
                        }
                        break :blk value_slot.value;
                    },
                    else => return error.UnexpectedTag,
                };

                try self.db.core.seekTo(position);
                const size: u64 = @intCast(try core_reader.readInt(u64, .big));
                const start_position = try self.db.core.getPos();

                return Reader{
                    .parent = self,
                    .size = size,
                    .start_position = start_position,
                    .relative_position = 0,
                };
            }

            pub fn writer(self: *Cursor, comptime Ctx: type, path: []const PathPart(Ctx)) !Writer {
                const slot_ptr = try self.db.readSlot(Ctx, path, true, self.read_slot_cursor);

                const core_writer = self.db.core.writer();
                try self.db.core.seekFromEnd(0);
                const ptr_pos = try self.db.core.getPos();
                try core_writer.writeInt(u64, 0, .big);
                const start_position = try self.db.core.getPos();

                return Writer{
                    .parent = self,
                    .slot_ptr = slot_ptr,
                    .size = 0,
                    .slot = Slot.init(ptr_pos, .bytes),
                    .start_position = start_position,
                    .relative_position = 0,
                };
            }

            pub fn readBytesAlloc(self: Cursor, allocator: std.mem.Allocator, max_size: usize, comptime Ctx: type, path: []const PathPart(Ctx)) !?[]u8 {
                const core_reader = self.db.core.reader();

                const slot_ptr = self.db.readSlot(Ctx, path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                const slot = slot_ptr.slot;
                const ptr = slot.value;
                const tag = try Tag.init(slot);

                const position = switch (tag) {
                    .bytes => ptr,
                    .hash => blk: {
                        try self.db.core.seekTo(ptr + HASH_SIZE);
                        const value_slot: Slot = @bitCast(try core_reader.readInt(SlotInt, .big));
                        const value_tag = try Tag.init(value_slot);
                        if (value_tag != .bytes) {
                            return error.UnexpectedTag;
                        }
                        break :blk value_slot.value;
                    },
                    else => return error.UnexpectedTag,
                };

                try self.db.core.seekTo(position);
                const value_size = try core_reader.readInt(u64, .big);

                if (value_size > max_size) {
                    return error.MaxSizeExceeded;
                }

                const value = try allocator.alloc(u8, value_size);
                errdefer allocator.free(value);

                try core_reader.readNoEof(value);
                return value;
            }

            pub fn readBytes(self: Cursor, buffer: []u8, comptime Ctx: type, path: []const PathPart(Ctx)) !?[]u8 {
                const core_reader = self.db.core.reader();

                const slot_ptr = self.db.readSlot(Ctx, path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                const slot = slot_ptr.slot;
                const ptr = slot.value;
                const tag = try Tag.init(slot);

                const position = switch (tag) {
                    .bytes => ptr,
                    .hash => blk: {
                        try self.db.core.seekTo(ptr + HASH_SIZE);
                        const value_slot: Slot = @bitCast(try core_reader.readInt(SlotInt, .big));
                        const value_tag = try Tag.init(value_slot);
                        if (value_tag != .bytes) {
                            return error.UnexpectedTag;
                        }
                        break :blk value_slot.value;
                    },
                    else => return error.UnexpectedTag,
                };

                try self.db.core.seekTo(position);
                const value_size = try core_reader.readInt(u64, .big);
                const size = @min(buffer.len, value_size);

                try core_reader.readNoEof(buffer[0..size]);
                return buffer[0..size];
            }

            pub fn readHash(self: Cursor, comptime Ctx: type, path: []const PathPart(Ctx)) !?Hash {
                const core_reader = self.db.core.reader();

                const slot_ptr = self.db.readSlot(Ctx, path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                const slot = slot_ptr.slot;
                const ptr = slot.value;
                const tag = try Tag.init(slot);

                if (tag != .hash) {
                    return error.UnexpectedTag;
                }

                try self.db.core.seekTo(ptr);
                var hash = [_]u8{0} ** HASH_INT_SIZE;
                try core_reader.readNoEof(hash[0..HASH_SIZE]);
                return std.mem.bytesToValue(Hash, &hash);
            }

            pub fn readInt(self: Cursor, comptime Ctx: type, path: []const PathPart(Ctx)) !?u64 {
                const slot_ptr = self.db.readSlot(Ctx, path, false, self.read_slot_cursor) catch |err| {
                    switch (err) {
                        error.KeyNotFound => return null,
                        else => return err,
                    }
                };
                const slot = slot_ptr.slot;
                const ptr = slot.value;
                const tag = try Tag.init(slot);

                const value = switch (tag) {
                    .uint => ptr,
                    .hash => blk: {
                        const core_reader = self.db.core.reader();
                        try self.db.core.seekTo(ptr + HASH_SIZE);
                        const value_slot: Slot = @bitCast(try core_reader.readInt(SlotInt, .big));
                        const value_tag = try Tag.init(value_slot);
                        if (value_tag != .uint) {
                            return error.UnexpectedTag;
                        }
                        break :blk value_slot.value;
                    },
                    else => return error.UnexpectedTag,
                };
                return value;
            }

            pub fn readCursor(self: Cursor, comptime Ctx: type, path: []const PathPart(Ctx)) !?Cursor {
                const slot_ptr = self.db.readSlot(Ctx, path, false, self.read_slot_cursor) catch |err| {
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

            pub fn writeBytes(self: *Cursor, buffer: []const u8, mode: enum { once, replace }, comptime Ctx: type, path: []const PathPart(Ctx)) !Slot {
                var cursor_writer = try self.writer(Ctx, path);
                if (mode == .replace or cursor_writer.slot_ptr.slot.tag == 0) {
                    try cursor_writer.writeAll(buffer);
                    try cursor_writer.finish();
                    return cursor_writer.slot;
                } else {
                    return cursor_writer.slot_ptr.slot;
                }
            }

            pub fn pointer(self: Cursor) ?Slot {
                return if (self.read_slot_cursor == .slot_ptr and self.read_slot_cursor.slot_ptr.slot.tag != 0) self.read_slot_cursor.slot_ptr.slot else null;
            }

            pub const Iter = struct {
                cursor: Cursor,
                core: IterCore,

                pub const IterKind = enum {
                    array_list,
                    linked_array_list,
                    hash_map,
                };
                pub const IterCore = union(IterKind) {
                    array_list: struct {
                        index: u64,
                    },
                    linked_array_list: struct {
                        index: u64,
                    },
                    hash_map: struct {
                        stack: std.ArrayList(MapLevel),
                    },

                    pub const MapLevel = struct {
                        position: u64,
                        block: [SLOT_COUNT]Slot,
                        index: u16,
                    };
                };

                pub fn init(cursor: Cursor, iter_db_kind: IterKind) !Iter {
                    const core: IterCore = switch (iter_db_kind) {
                        .array_list => .{
                            .array_list = .{
                                .index = 0,
                            },
                        },
                        .linked_array_list => .{
                            .linked_array_list = .{
                                .index = 0,
                            },
                        },
                        .hash_map => .{
                            .hash_map = .{
                                .stack = blk: {
                                    // find the block
                                    const position = switch (cursor.read_slot_cursor) {
                                        .db_start => cursor.read_slot_cursor.db_start,
                                        .slot_ptr => pos_blk: {
                                            const ptr = cursor.read_slot_cursor.slot_ptr.slot.value;
                                            const tag = try Tag.init(cursor.read_slot_cursor.slot_ptr.slot);
                                            if (tag != .hash_map) {
                                                return error.UnexpectedTag;
                                            }
                                            break :pos_blk ptr;
                                        },
                                    };
                                    try cursor.db.core.seekTo(position);
                                    // read the block
                                    const core_reader = cursor.db.core.reader();
                                    var map_index_block_bytes = [_]u8{0} ** INDEX_BLOCK_SIZE;
                                    try core_reader.readNoEof(&map_index_block_bytes);
                                    // convert the block into 72-bit slots
                                    var map_index_block = [_]Slot{.{}} ** SLOT_COUNT;
                                    {
                                        var stream = std.io.fixedBufferStream(&map_index_block_bytes);
                                        var block_reader = stream.reader();
                                        for (&map_index_block) |*block_slot| {
                                            block_slot.* = @bitCast(try block_reader.readInt(SlotInt, .big));
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
                        .array_list => {},
                        .linked_array_list => {},
                        .hash_map => self.core.hash_map.stack.deinit(),
                    }
                }

                pub fn next(self: *Iter) !?Cursor {
                    switch (self.core) {
                        .array_list => {
                            const index = self.core.array_list.index;
                            const path = &[_]PathPart(void){.{ .array_list_get = .{ .index = .{ .index = index, .reverse = false } } }};
                            const slot_ptr = self.cursor.db.readSlot(void, path, false, self.cursor.read_slot_cursor) catch |err| {
                                switch (err) {
                                    error.KeyNotFound => return null,
                                    else => return err,
                                }
                            };
                            self.core.array_list.index += 1;
                            return Cursor{
                                .read_slot_cursor = ReadSlotCursor{
                                    .slot_ptr = slot_ptr,
                                },
                                .db = self.cursor.db,
                            };
                        },
                        .linked_array_list => {
                            const index = self.core.array_list.index;
                            const path = &[_]PathPart(void){.{ .linked_array_list_get = .{ .index = .{ .index = index, .reverse = false } } }};
                            const slot_ptr = self.cursor.db.readSlot(void, path, false, self.cursor.read_slot_cursor) catch |err| {
                                switch (err) {
                                    error.KeyNotFound => return null,
                                    else => return err,
                                }
                            };
                            self.core.linked_array_list.index += 1;
                            return Cursor{
                                .read_slot_cursor = ReadSlotCursor{
                                    .slot_ptr = slot_ptr,
                                },
                                .db = self.cursor.db,
                            };
                        },
                        .hash_map => {
                            while (self.core.hash_map.stack.items.len > 0) {
                                const level = self.core.hash_map.stack.items[self.core.hash_map.stack.items.len - 1];
                                if (level.index == level.block.len) {
                                    _ = self.core.hash_map.stack.pop();
                                    if (self.core.hash_map.stack.items.len > 0) {
                                        self.core.hash_map.stack.items[self.core.hash_map.stack.items.len - 1].index += 1;
                                    }
                                    continue;
                                } else {
                                    const slot = level.block[level.index];
                                    if (slot.tag == 0) {
                                        self.core.hash_map.stack.items[self.core.hash_map.stack.items.len - 1].index += 1;
                                        continue;
                                    } else {
                                        const tag = try Tag.init(slot);
                                        if (tag == .index) {
                                            // find the block
                                            const next_pos = slot.value;
                                            try self.cursor.db.core.seekTo(next_pos);
                                            // read the block
                                            const core_reader = self.cursor.db.core.reader();
                                            var map_index_block_bytes = [_]u8{0} ** INDEX_BLOCK_SIZE;
                                            try core_reader.readNoEof(&map_index_block_bytes);
                                            // convert the block into 72-bit slots
                                            var map_index_block = [_]Slot{.{}} ** SLOT_COUNT;
                                            {
                                                var stream = std.io.fixedBufferStream(&map_index_block_bytes);
                                                var block_reader = stream.reader();
                                                for (&map_index_block) |*block_slot| {
                                                    block_slot.* = @bitCast(try block_reader.readInt(SlotInt, .big));
                                                }
                                            }
                                            // append to the stack
                                            try self.core.hash_map.stack.append(IterCore.MapLevel{
                                                .position = next_pos,
                                                .block = map_index_block,
                                                .index = 0,
                                            });
                                            continue;
                                        } else {
                                            self.core.hash_map.stack.items[self.core.hash_map.stack.items.len - 1].index += 1;
                                            const position = level.position + (level.index * byteSizeOf(Slot));
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
                .read_slot_cursor = .{ .db_start = INDEX_START },
                .db = self,
            };
        }

        pub fn slice(self: *Database(db_kind), list: Slot, offset: u64, size: u64) !Slot {
            const tag = try Tag.init(list);
            if (tag != .linked_array_list) {
                return error.UnexpectedTag;
            }

            const reader = self.core.reader();
            const writer = self.core.writer();

            const array_list_start = list.value;
            try self.core.seekTo(array_list_start);
            const header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));

            if (offset + size > header.size) {
                return error.LinkedArrayListSliceOutOfBounds;
            } else if (size == header.size) {
                return list;
            }

            // read the list's left blocks
            var left_blocks = std.ArrayList(LinkedArrayListBlockInfo).init(self.allocator);
            defer left_blocks.deinit();
            {
                const last_key = if (header.size == 0) 0 else header.size - 1;
                const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                try self.readLinkedArrayListBlocks(header.ptr, offset, shift, &left_blocks);
            }

            // read the list's right blocks
            var right_blocks = std.ArrayList(LinkedArrayListBlockInfo).init(self.allocator);
            defer right_blocks.deinit();
            {
                const key = if (offset + size == 0) 0 else offset + size - 1;
                const last_key = if (header.size == 0) 0 else header.size - 1;
                const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                try self.readLinkedArrayListBlocks(header.ptr, key, shift, &right_blocks);
            }

            // create the new blocks
            const block_count = left_blocks.items.len;
            var next_slots = [_]?LinkedArrayListSlot{null} ** 2;
            for (0..block_count) |i| {
                const is_leaf_node = next_slots[0] == null;

                const left_block = left_blocks.items[block_count - i - 1];
                const right_block = right_blocks.items[block_count - i - 1];
                const orig_block_infos = [_]LinkedArrayListBlockInfo{
                    left_block,
                    right_block,
                };
                var next_blocks: [2]?[SLOT_COUNT]LinkedArrayListSlot = .{ null, null };

                if (left_block.ptr == right_block.ptr) {
                    var slot_i: usize = 0;
                    var new_root_block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;
                    // left slot
                    if (next_slots[0]) |slot| {
                        new_root_block[slot_i] = slot;
                    } else {
                        new_root_block[slot_i] = left_block.block[left_block.i];
                    }
                    slot_i += 1;
                    // middle slots
                    if (left_block.i != right_block.i) {
                        for (left_block.block[left_block.i + 1 .. right_block.i]) |slot| {
                            new_root_block[slot_i] = slot;
                            slot_i += 1;
                        }
                    }
                    // right slot
                    if (next_slots[1]) |slot| {
                        new_root_block[slot_i] = slot;
                    } else {
                        new_root_block[slot_i] = left_block.block[right_block.i];
                    }
                    next_blocks[0] = new_root_block;
                } else {
                    var slot_i: usize = 0;
                    var new_left_block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;

                    // first slot
                    if (next_slots[0]) |slot| {
                        new_left_block[slot_i] = slot;
                    } else {
                        new_left_block[slot_i] = left_block.block[left_block.i];
                    }
                    slot_i += 1;
                    // rest of slots
                    for (left_block.block[left_block.i + 1 ..]) |slot| {
                        new_left_block[slot_i] = slot;
                        slot_i += 1;
                    }
                    next_blocks[0] = new_left_block;

                    slot_i = 0;
                    var new_right_block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;
                    // first slots
                    for (right_block.block[0..right_block.i]) |slot| {
                        new_right_block[slot_i] = slot;
                        slot_i += 1;
                    }
                    // last slot
                    if (next_slots[1]) |slot| {
                        new_right_block[slot_i] = slot;
                    } else {
                        new_right_block[slot_i] = right_block.block[right_block.i];
                    }
                    next_blocks[1] = new_right_block;
                }

                // clear the next slots
                next_slots = .{ null, null };

                // write the block(s)
                try self.core.seekFromEnd(0);
                for (&next_slots, next_blocks, orig_block_infos) |*next_slot, block_maybe, orig_block_info| {
                    if (block_maybe) |block| {
                        // determine if the block changed compared to the original block
                        var eql = true;
                        for (block, orig_block_info.block) |slot, orig_slot| {
                            if (!slot.slot.eql(orig_slot.slot)) {
                                eql = false;
                                break;
                            }
                        }
                        // if there is no change, just use the original block
                        if (eql) {
                            next_slot.* = LinkedArrayListSlot{ .slot = Slot.init(orig_block_info.ptr, .index), .size = orig_block_info.leaf_count };
                        }
                        // otherwise make a new block
                        else {
                            const next_ptr = try self.core.getPos();
                            var leaf_count: u64 = 0;
                            for (block) |slot| {
                                try writer.writeInt(LinkedArrayListSlotInt, @bitCast(slot), .big);
                                if (is_leaf_node) {
                                    if (slot.slot.tag != 0) {
                                        leaf_count += 1;
                                    }
                                } else {
                                    leaf_count += slot.size;
                                }
                            }
                            next_slot.* = LinkedArrayListSlot{ .slot = Slot.init(next_ptr, .index), .size = leaf_count };
                        }
                    }
                }

                // we found the root node so we can exit
                if (next_slots[0] != null and next_slots[1] == null) {
                    break;
                }
            }

            const root_slot = next_slots[0] orelse return error.ExpectedRootNode;

            // write new list header
            try self.core.seekFromEnd(0);
            const new_array_list_start = try self.core.getPos();
            try writer.writeInt(ArrayListHeaderInt, @bitCast(ArrayListHeader{
                .ptr = root_slot.slot.value,
                .size = size,
            }), .big);

            return Slot.init(new_array_list_start, .linked_array_list);
        }

        pub fn concat(self: *Database(db_kind), list_a: Slot, list_b: Slot) !Slot {
            if (try Tag.init(list_a) != .linked_array_list) {
                return error.UnexpectedTag;
            }
            if (try Tag.init(list_b) != .linked_array_list) {
                return error.UnexpectedTag;
            }

            const reader = self.core.reader();
            const writer = self.core.writer();

            // read the first list's blocks
            try self.core.seekTo(list_a.value);
            const header_a: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
            var blocks_a = std.ArrayList(LinkedArrayListBlockInfo).init(self.allocator);
            defer blocks_a.deinit();
            {
                const last_key = if (header_a.size == 0) 0 else header_a.size - 1;
                const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                try self.readLinkedArrayListBlocks(header_a.ptr, last_key, shift, &blocks_a);
            }

            // read the second list's blocks
            try self.core.seekTo(list_b.value);
            const header_b: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
            var blocks_b = std.ArrayList(LinkedArrayListBlockInfo).init(self.allocator);
            defer blocks_b.deinit();
            {
                const last_key = if (header_b.size == 0) 0 else header_b.size - 1;
                const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                try self.readLinkedArrayListBlocks(header_b.ptr, 0, shift, &blocks_b);
            }

            // stitch the blocks together
            var next_slots = [_]?LinkedArrayListSlot{null} ** 2;
            for (0..@max(blocks_a.items.len, blocks_b.items.len)) |i| {
                const block_infos: [2]?LinkedArrayListBlockInfo = .{
                    if (i < blocks_a.items.len) blocks_a.items[blocks_a.items.len - 1 - i] else null,
                    if (i < blocks_b.items.len) blocks_b.items[blocks_b.items.len - 1 - i] else null,
                };
                var next_blocks: [2]?[SLOT_COUNT]LinkedArrayListSlot = .{ null, null };
                const is_leaf_node = next_slots[0] == null;

                for (block_infos, &next_blocks) |block_info_maybe, *next_block_maybe| {
                    if (block_info_maybe) |block_info| {
                        var block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;
                        var target_i: usize = 0;
                        for (block_info.block, 0..) |slot, source_i| {
                            // skip i'th block if necessary
                            if (!is_leaf_node and block_info.i == source_i) {
                                continue;
                            }
                            // break on first empty slot
                            else if (slot.slot.tag == 0) {
                                break;
                            }
                            block[target_i] = slot;
                            target_i += 1;
                        }

                        // there are no slots in this block so don't bother writing it
                        if (target_i == 0) {
                            continue;
                        }

                        next_block_maybe.* = block;
                    }
                }

                var slots_to_write = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** (SLOT_COUNT * 2);
                var slot_i: usize = 0;

                // add the left block
                if (next_blocks[0]) |block| {
                    for (block) |slot| {
                        if (slot.slot.tag == 0) {
                            break;
                        }
                        slots_to_write[slot_i] = slot;
                        slot_i += 1;
                    }
                }

                // add the center block
                for (next_slots) |slot_maybe| {
                    if (slot_maybe) |slot| {
                        slots_to_write[slot_i] = slot;
                        slot_i += 1;
                    }
                }

                // add the right block
                if (next_blocks[1]) |block| {
                    for (block) |slot| {
                        if (slot.slot.tag == 0) {
                            break;
                        }
                        slots_to_write[slot_i] = slot;
                        slot_i += 1;
                    }
                }

                // clear the next slots
                next_slots = .{ null, null };

                // write the block(s)
                try self.core.seekFromEnd(0);
                for (&next_slots, 0..) |*next_slot, block_i| {
                    const start = block_i * SLOT_COUNT;
                    const block = slots_to_write[start .. start + SLOT_COUNT];

                    // this block is empty so don't bother writing it
                    if (block[0].slot.tag == 0) {
                        break;
                    }

                    // write the block
                    const next_ptr = try self.core.getPos();
                    var leaf_count: u64 = 0;
                    for (block) |slot| {
                        try writer.writeInt(LinkedArrayListSlotInt, @bitCast(slot), .big);
                        if (is_leaf_node) {
                            if (slot.slot.tag != 0) {
                                leaf_count += 1;
                            }
                        } else {
                            leaf_count += slot.size;
                        }
                    }

                    next_slot.* = LinkedArrayListSlot{ .slot = Slot.init(next_ptr, .index), .size = leaf_count };
                }
            }

            const root_ptr = blk: {
                if (next_slots[0]) |first_slot| {
                    // if there is more than one slot, make a root node
                    if (next_slots[1]) |second_slot| {
                        var block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;
                        block[0] = first_slot;
                        block[1] = second_slot;

                        // write the root node
                        const new_ptr = try self.core.getPos();
                        for (block) |slot| {
                            try writer.writeInt(LinkedArrayListSlotInt, @bitCast(slot), .big);
                        }
                        break :blk new_ptr;
                    }
                    // otherwise the first slot is the root node
                    else {
                        break :blk first_slot.slot.value;
                    }
                }
                // lists were empty so just re-use existing empty block
                else {
                    break :blk header_a.ptr;
                }
            };

            // write the header
            const list_start = try self.core.getPos();
            try writer.writeInt(ArrayListHeaderInt, @bitCast(ArrayListHeader{
                .ptr = root_ptr,
                .size = header_a.size + header_b.size,
            }), .big);

            return Slot.init(list_start, .linked_array_list);
        }

        // private

        fn writeHeader(self: *Database(db_kind)) !void {
            const writer = self.core.writer();

            var header_block = [_]u8{0} ** HEADER_BLOCK_SIZE;
            try writer.writeAll(&header_block);

            const index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
            const array_list_ptr = try self.core.getPos() + byteSizeOf(ArrayListHeader);
            try writer.writeInt(ArrayListHeaderInt, @bitCast(ArrayListHeader{
                .ptr = array_list_ptr,
                .size = 0,
            }), .big);
            try writer.writeAll(&index_block);
        }

        const ReadSlotCursor = union(enum) {
            db_start: u64,
            slot_ptr: SlotPointer,
        };

        fn readSlot(self: *Database(db_kind), comptime Ctx: type, path: []const PathPart(Ctx), allow_write: bool, cursor: ReadSlotCursor) anyerror!SlotPointer {
            const part = if (path.len > 0) path[0] else switch (cursor) {
                .db_start => return SlotPointer{ .position = 0, .slot = .{} },
                .slot_ptr => {
                    if (!allow_write and cursor.slot_ptr.slot.tag == 0) {
                        return error.KeyNotFound;
                    }
                    return cursor.slot_ptr;
                },
            };

            const write_mode: WriteMode = if (allow_write)
                switch (cursor) {
                    .db_start => .write,
                    .slot_ptr => .write_immutable,
                }
            else
                .read_only;

            const is_tx_start = write_mode == .write and self.tx_start == null;
            if (is_tx_start) {
                try self.core.seekFromEnd(0);
                self.tx_start = try self.core.getPos();
            }
            defer {
                if (is_tx_start) {
                    self.tx_start = null;
                }
            }

            switch (part) {
                .array_list_create => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (cursor != .slot_ptr) return error.NotImplemented;

                    if (cursor.slot_ptr.slot.tag == 0) {
                        // if slot was empty, insert the new list
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const array_list_start = try self.core.getPos();
                        const array_list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        const array_list_ptr = try self.core.getPos() + byteSizeOf(ArrayListHeader);
                        try writer.writeInt(ArrayListHeaderInt, @bitCast(ArrayListHeader{
                            .ptr = array_list_ptr,
                            .size = 0,
                        }), .big);
                        try writer.writeAll(&array_list_index_block);
                        // make slot point to list
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = Slot.init(array_list_start, .array_list) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    } else {
                        const tag = try Tag.init(cursor.slot_ptr.slot);
                        if (tag != .array_list) {
                            return error.UnexpectedTag;
                        }
                        const reader = self.core.reader();
                        const writer = self.core.writer();

                        // read existing block
                        var array_list_start = cursor.slot_ptr.slot.value;
                        try self.core.seekTo(array_list_start);
                        var header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
                        try self.core.seekTo(header.ptr);
                        var array_list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try reader.readNoEof(&array_list_index_block);

                        // copy it to the end unless it was made in this transaction
                        const tx_start = self.tx_start orelse return error.ExpectedTxStart;
                        if (array_list_start < tx_start) {
                            try self.core.seekFromEnd(0);
                            array_list_start = try self.core.getPos();
                            const next_array_list_ptr = array_list_start + byteSizeOf(ArrayListHeader);
                            header.ptr = next_array_list_ptr;
                            try writer.writeInt(ArrayListHeaderInt, @bitCast(header), .big);
                            try writer.writeAll(&array_list_index_block);
                        }

                        // make slot point to list
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = Slot.init(array_list_start, .array_list) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    }
                },
                .array_list_get => {
                    const next_array_list_start = switch (cursor) {
                        .db_start => cursor.db_start,
                        .slot_ptr => blk: {
                            if (cursor.slot_ptr.slot.tag == 0) {
                                return error.KeyNotFound;
                            } else {
                                const tag = try Tag.init(cursor.slot_ptr.slot);
                                if (tag != .array_list) {
                                    return error.UnexpectedTag;
                                }
                                break :blk cursor.slot_ptr.slot.value;
                            }
                        },
                    };
                    switch (part.array_list_get) {
                        .index => {
                            const index = part.array_list_get.index;
                            try self.core.seekTo(next_array_list_start);
                            const reader = self.core.reader();
                            const header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
                            if (index.index >= header.size) {
                                return error.KeyNotFound;
                            }
                            const key = if (index.reverse)
                                header.size - index.index - 1
                            else
                                index.index;
                            const last_key = header.size - 1;
                            const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                            const final_slot_ptr = try self.readArrayListSlot(header.ptr, key, shift, write_mode);
                            return try self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = final_slot_ptr });
                        },
                        .append => {
                            if (!allow_write) return error.WriteNotAllowed;

                            const append_result = try self.readArrayListSlotAppend(next_array_list_start, write_mode);
                            const final_slot_ptr = try self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = append_result.slot_ptr });

                            // update header
                            const writer = self.core.writer();
                            try self.core.seekTo(next_array_list_start);
                            try writer.writeInt(ArrayListHeaderInt, @bitCast(append_result.header), .big);

                            return final_slot_ptr;
                        },
                        .append_copy => {
                            if (!allow_write) return error.WriteNotAllowed;

                            const reader = self.core.reader();
                            const writer = self.core.writer();

                            try self.core.seekTo(next_array_list_start);
                            const header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
                            // read the last slot in the list
                            var last_slot: Slot = .{};
                            if (header.size > 0) {
                                const last_key = header.size - 1;
                                const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                                const last_slot_ptr = try self.readArrayListSlot(header.ptr, last_key, shift, .read_only);
                                last_slot = last_slot_ptr.slot;
                            }

                            // make the next slot
                            var append_result = try self.readArrayListSlotAppend(next_array_list_start, write_mode);
                            // set its value to the last slot
                            if (last_slot.tag != 0) {
                                try self.core.seekTo(append_result.slot_ptr.position);
                                try writer.writeInt(SlotInt, @bitCast(last_slot), .big);
                                append_result.slot_ptr.slot = last_slot;
                            }
                            const final_slot_ptr = try self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = append_result.slot_ptr });
                            // update header
                            try self.core.seekTo(next_array_list_start);
                            try writer.writeInt(ArrayListHeaderInt, @bitCast(append_result.header), .big);

                            return final_slot_ptr;
                        },
                    }
                },
                .linked_array_list_create => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (cursor != .slot_ptr) return error.NotImplemented;

                    if (cursor.slot_ptr.slot.tag == 0) {
                        // if slot was empty, insert the new list
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const array_list_start = try self.core.getPos();
                        const array_list_index_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
                        const array_list_ptr = try self.core.getPos() + byteSizeOf(ArrayListHeader);
                        try writer.writeInt(ArrayListHeaderInt, @bitCast(ArrayListHeader{
                            .ptr = array_list_ptr,
                            .size = 0,
                        }), .big);
                        try writer.writeAll(&array_list_index_block);
                        // make slot point to new list
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = Slot.init(array_list_start, .linked_array_list) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeInt(LinkedArrayListSlotInt, @bitCast(LinkedArrayListSlot{ .slot = next_slot_ptr.slot, .size = 0 }), .big);
                        return self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    } else {
                        const tag = try Tag.init(cursor.slot_ptr.slot);
                        if (tag != .linked_array_list) {
                            return error.UnexpectedTag;
                        }
                        const reader = self.core.reader();
                        const writer = self.core.writer();

                        var array_list_start = cursor.slot_ptr.slot.value;
                        // read existing block
                        try self.core.seekTo(array_list_start);
                        var header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
                        try self.core.seekTo(header.ptr);
                        var array_list_index_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
                        try reader.readNoEof(&array_list_index_block);

                        // copy it to the end unless it was made in this transaction
                        const tx_start = self.tx_start orelse return error.ExpectedTxStart;
                        if (array_list_start < tx_start) {
                            try self.core.seekFromEnd(0);
                            array_list_start = try self.core.getPos();
                            const next_array_list_ptr = array_list_start + byteSizeOf(ArrayListHeader);
                            header.ptr = next_array_list_ptr;
                            try writer.writeInt(ArrayListHeaderInt, @bitCast(header), .big);
                            try writer.writeAll(&array_list_index_block);
                        }

                        // make slot point to list
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = Slot.init(array_list_start, .linked_array_list) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    }
                },
                .linked_array_list_get => {
                    const next_array_list_start = switch (cursor) {
                        .db_start => cursor.db_start,
                        .slot_ptr => blk: {
                            if (cursor.slot_ptr.slot.tag == 0) {
                                return error.KeyNotFound;
                            } else {
                                const tag = try Tag.init(cursor.slot_ptr.slot);
                                if (tag != .linked_array_list) {
                                    return error.UnexpectedTag;
                                }
                                break :blk cursor.slot_ptr.slot.value;
                            }
                        },
                    };
                    switch (part.linked_array_list_get) {
                        .index => {
                            const index = part.linked_array_list_get.index;
                            try self.core.seekTo(next_array_list_start);
                            const reader = self.core.reader();
                            const header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
                            if (index.index >= header.size) {
                                return error.KeyNotFound;
                            }
                            const key = if (index.reverse)
                                header.size - index.index - 1
                            else
                                index.index;
                            const last_key = header.size - 1;
                            const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                            const final_slot_ptr = try self.readLinkedArrayListSlot(header.ptr, key, shift, write_mode);
                            return try self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = final_slot_ptr.slot_ptr });
                        },
                        .append => {
                            if (!allow_write) return error.WriteNotAllowed;

                            const append_result = try self.readLinkedArrayListSlotAppend(next_array_list_start, write_mode);
                            const final_slot_ptr = try self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = append_result.slot_ptr.slot_ptr });

                            // update header
                            const writer = self.core.writer();
                            try self.core.seekTo(next_array_list_start);
                            try writer.writeInt(ArrayListHeaderInt, @bitCast(append_result.header), .big);

                            return final_slot_ptr;
                        },
                    }
                },
                .hash_map_create => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (cursor != .slot_ptr) return error.NotImplemented;

                    if (cursor.slot_ptr.slot.tag == 0) {
                        // if slot was empty, insert the new map
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const map_start = try self.core.getPos();
                        const map_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try writer.writeAll(&map_index_block);
                        // make slot point to map
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = Slot.init(map_start, .hash_map) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    } else {
                        const tag = try Tag.init(cursor.slot_ptr.slot);
                        if (tag != .hash_map) {
                            return error.UnexpectedTag;
                        }
                        const reader = self.core.reader();
                        const writer = self.core.writer();

                        var map_start = cursor.slot_ptr.slot.value;
                        // read existing block
                        try self.core.seekTo(map_start);
                        var map_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try reader.readNoEof(&map_index_block);

                        // copy it to the end unless it was made in this transaction
                        const tx_start = self.tx_start orelse return error.ExpectedTxStart;
                        if (map_start < tx_start) {
                            // copy it to the end
                            try self.core.seekFromEnd(0);
                            map_start = try self.core.getPos();
                            try writer.writeAll(&map_index_block);
                        }

                        // make slot point to map
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = Slot.init(map_start, .hash_map) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    }
                },
                .hash_map_get => {
                    if (cursor != .slot_ptr) return error.NotImplemented;

                    if (cursor.slot_ptr.slot.tag == 0) {
                        return error.KeyNotFound;
                    }
                    const tag = try Tag.init(cursor.slot_ptr.slot);
                    if (tag != .hash_map) {
                        return error.UnexpectedTag;
                    }
                    const next_map_start = cursor.slot_ptr.slot.value;

                    const next_slot_ptr = try self.readMapSlot(next_map_start, part.hash_map_get, 0, write_mode, true);
                    return self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                },
                .hash_map_remove => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (path.len > 1) return error.ValueMustBeAtEnd;

                    if (cursor != .slot_ptr) return error.NotImplemented;

                    if (cursor.slot_ptr.slot.tag == 0) {
                        return error.KeyNotFound;
                    }
                    const tag = try Tag.init(cursor.slot_ptr.slot);
                    if (tag != .hash_map) {
                        return error.UnexpectedTag;
                    }
                    const next_map_start = cursor.slot_ptr.slot.value;

                    const next_slot_ptr = try self.readMapSlot(next_map_start, part.hash_map_remove, 0, .read_only, false);

                    const writer = self.core.writer();
                    try self.core.seekTo(next_slot_ptr.position);
                    try writer.writeInt(SlotInt, 0, .big);

                    return next_slot_ptr;
                },
                .value => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (path.len > 1) return error.ValueMustBeAtEnd;

                    if (cursor != .slot_ptr) return error.NotImplemented;

                    const core_writer = self.core.writer();

                    const slot: Slot = switch (part.value) {
                        .slot => blk: {
                            _ = try Tag.init(part.value.slot); // make sure tag is valid
                            break :blk part.value.slot;
                        },
                        .uint => Slot.init(part.value.uint, .uint),
                        .bytes => blk: {
                            var next_cursor = Cursor{
                                .read_slot_cursor = ReadSlotCursor{
                                    .slot_ptr = cursor.slot_ptr,
                                },
                                .db = self,
                            };
                            var writer = try next_cursor.writer(void, &[_]PathPart(void){});
                            try writer.writeAll(part.value.bytes);
                            try writer.finish();
                            break :blk writer.slot;
                        },
                    };

                    try self.core.seekTo(cursor.slot_ptr.position);
                    try core_writer.writeInt(SlotInt, @bitCast(slot), .big);

                    return .{ .position = cursor.slot_ptr.position, .slot = slot };
                },
                .ctx => {
                    if (!allow_write) return error.WriteNotAllowed;

                    if (path.len > 1) return error.ValueMustBeAtEnd;

                    if (cursor != .slot_ptr) return error.NotImplemented;

                    if (@TypeOf(part.ctx) == void) {
                        return error.NotImplmented;
                    } else {
                        var next_cursor = Cursor{
                            .read_slot_cursor = ReadSlotCursor{
                                .slot_ptr = cursor.slot_ptr,
                            },
                            .db = self,
                        };
                        try part.ctx.run(&next_cursor);
                        return next_cursor.read_slot_cursor.slot_ptr;
                    }
                },
                .path => {
                    if (!allow_write) return error.WriteNotAllowed;
                    _ = try self.readSlot(Ctx, part.path, allow_write, cursor);
                    return try self.readSlot(Ctx, path[1..], allow_write, cursor);
                },
            }
        }

        // hash_map

        fn readMapSlot(self: *Database(db_kind), index_pos: u64, key_hash: Hash, key_offset: u8, write_mode: WriteMode, return_value_slot: bool) !SlotPointer {
            if (key_offset >= (HASH_SIZE * 8) / BIT_COUNT) {
                return error.KeyOffsetExceeded;
            }

            const reader = self.core.reader();
            const writer = self.core.writer();

            const i: u4 = @intCast((key_hash >> key_offset * BIT_COUNT) & MASK);
            const slot_pos = index_pos + (byteSizeOf(Slot) * i);
            try self.core.seekTo(slot_pos);
            const slot: Slot = @bitCast(try reader.readInt(SlotInt, .big));

            if (slot.tag == 0) {
                if (write_mode == .write or write_mode == .write_immutable) {
                    try self.core.seekFromEnd(0);
                    // write hash
                    const hash_pos = try self.core.getPos();
                    try writer.writeAll(std.mem.asBytes(&key_hash)[0..HASH_SIZE]);
                    // write empty value slot
                    const value_slot_pos = try self.core.getPos();
                    try writer.writeInt(SlotInt, 0, .big);
                    // point slot to hash pos
                    try self.core.seekTo(slot_pos);
                    try writer.writeInt(SlotInt, @bitCast(Slot.init(hash_pos, .hash)), .big);
                    return SlotPointer{ .position = value_slot_pos, .slot = slot };
                } else {
                    return error.KeyNotFound;
                }
            }

            const tag = try Tag.init(slot);
            const ptr = slot.value;

            switch (tag) {
                .index => {
                    var next_ptr = ptr;
                    if (write_mode == .write_immutable) {
                        const tx_start = self.tx_start orelse return error.ExpectedTxStart;
                        if (next_ptr < tx_start) {
                            // read existing block
                            try self.core.seekTo(ptr);
                            var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                            try reader.readNoEof(&index_block);
                            // copy it to the end
                            try self.core.seekFromEnd(0);
                            next_ptr = try self.core.getPos();
                            try writer.writeAll(&index_block);
                            // make slot point to block
                            try self.core.seekTo(slot_pos);
                            try writer.writeInt(SlotInt, @bitCast(Slot.init(next_ptr, .index)), .big);
                        }
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
                            const value_slot: Slot = @bitCast(try reader.readInt(SlotInt, .big));
                            try self.core.seekFromEnd(0);
                            // write hash
                            const hash_pos = try self.core.getPos();
                            try writer.writeAll(std.mem.asBytes(&key_hash)[0..HASH_SIZE]);
                            // write value slot
                            const next_value_slot_pos = try self.core.getPos();
                            try writer.writeInt(SlotInt, @bitCast(value_slot), .big);
                            // point slot to hash pos
                            try self.core.seekTo(slot_pos);
                            try writer.writeInt(SlotInt, @bitCast(Slot.init(hash_pos, .hash)), .big);
                            return SlotPointer{ .position = next_value_slot_pos, .slot = value_slot };
                        } else {
                            if (return_value_slot) {
                                const value_slot_pos = try self.core.getPos();
                                const value_slot: Slot = @bitCast(try reader.readInt(SlotInt, .big));
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
                            const next_i: u4 = @intCast((existing_key_hash >> (key_offset + 1) * BIT_COUNT) & MASK);
                            try self.core.seekFromEnd(0);
                            const next_index_pos = try self.core.getPos();
                            var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                            try writer.writeAll(&index_block);
                            try self.core.seekTo(next_index_pos + (byteSizeOf(Slot) * next_i));
                            try writer.writeInt(SlotInt, @bitCast(slot), .big);
                            const next_slot_ptr = try self.readMapSlot(next_index_pos, key_hash, key_offset + 1, write_mode, return_value_slot);
                            try self.core.seekTo(slot_pos);
                            try writer.writeInt(SlotInt, @bitCast(Slot.init(next_index_pos, .index)), .big);
                            return next_slot_ptr;
                        } else {
                            return error.KeyNotFound;
                        }
                    }
                },
                else => {
                    return error.UnexpectedTag;
                },
            }
        }

        // array_list

        const ArrayListAppendResult = struct {
            header: ArrayListHeader,
            slot_ptr: SlotPointer,
        };

        fn readArrayListSlotAppend(self: *Database(db_kind), index_start: u64, write_mode: WriteMode) !ArrayListAppendResult {
            const reader = self.core.reader();
            const writer = self.core.writer();

            try self.core.seekTo(index_start);
            const header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
            var index_pos = header.ptr;
            var slot_ptr: SlotPointer = undefined;

            const key = header.size;

            const prev_shift: u6 = @intCast(if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key - 1));
            const next_shift: u6 = @intCast(if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key));

            if (prev_shift != next_shift) {
                // root overflow
                try self.core.seekFromEnd(0);
                const next_index_pos = try self.core.getPos();
                var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                try writer.writeAll(&index_block);
                try self.core.seekTo(next_index_pos);
                try writer.writeInt(SlotInt, @bitCast(Slot.init(index_pos, .index)), .big);
                index_pos = next_index_pos;
            }

            slot_ptr = try self.readArrayListSlot(index_pos, key, next_shift, write_mode);

            return .{
                .header = .{
                    .ptr = index_pos,
                    .size = header.size + 1,
                },
                .slot_ptr = slot_ptr,
            };
        }

        fn readArrayListSlot(self: *Database(db_kind), index_pos: u64, key: u64, shift: u6, write_mode: WriteMode) !SlotPointer {
            const reader = self.core.reader();

            const i: u4 = @intCast(key >> (shift * BIT_COUNT) & MASK);
            const slot_pos = index_pos + (byteSizeOf(Slot) * i);
            try self.core.seekTo(slot_pos);
            const slot: Slot = @bitCast(try reader.readInt(SlotInt, .big));

            if (slot.tag == 0) {
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
                        try writer.writeInt(SlotInt, @bitCast(Slot.init(next_index_pos, .index)), .big);
                        return try self.readArrayListSlot(next_index_pos, key, shift - 1, write_mode);
                    }
                } else {
                    return error.KeyNotFound;
                }
            } else {
                const ptr = slot.value;
                const tag = try Tag.init(slot);
                if (shift == 0) {
                    return SlotPointer{ .position = slot_pos, .slot = slot };
                } else {
                    if (tag != .index) {
                        return error.UnexpectedTag;
                    }
                    var next_ptr = ptr;
                    if (write_mode == .write_immutable) {
                        const tx_start = self.tx_start orelse return error.ExpectedTxStart;
                        if (next_ptr < tx_start) {
                            // read existing block
                            try self.core.seekTo(ptr);
                            var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                            try reader.readNoEof(&index_block);
                            // copy it to the end
                            const writer = self.core.writer();
                            try self.core.seekFromEnd(0);
                            next_ptr = try self.core.getPos();
                            try writer.writeAll(&index_block);
                            // make slot point to block
                            try self.core.seekTo(slot_pos);
                            try writer.writeInt(SlotInt, @bitCast(Slot.init(next_ptr, .index)), .big);
                        }
                    }
                    return self.readArrayListSlot(next_ptr, key, shift - 1, write_mode);
                }
            }
        }

        // linked_array_list

        const LinkedArrayListAppendResult = struct {
            header: ArrayListHeader,
            slot_ptr: LinkedArrayListSlotPointer,
        };

        fn readLinkedArrayListSlotAppend(self: *Database(db_kind), index_start: u64, write_mode: WriteMode) !LinkedArrayListAppendResult {
            const reader = self.core.reader();
            const writer = self.core.writer();

            try self.core.seekTo(index_start);
            const header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
            var index_pos = header.ptr;
            var slot_ptr: LinkedArrayListSlotPointer = undefined;

            const key = header.size;

            const prev_shift: u6 = @intCast(if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key - 1));
            const next_shift: u6 = @intCast(if (key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, key));

            if (prev_shift != next_shift) {
                // root overflow
                try self.core.seekFromEnd(0);
                const next_index_pos = try self.core.getPos();
                var index_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
                try writer.writeAll(&index_block);
                try self.core.seekTo(next_index_pos);
                try writer.writeInt(LinkedArrayListSlotInt, @bitCast(LinkedArrayListSlot{
                    .slot = Slot.init(index_pos, .index),
                    .size = header.size,
                }), .big);
                index_pos = next_index_pos;
            }

            slot_ptr = try self.readLinkedArrayListSlot(index_pos, key, next_shift, write_mode);

            return .{
                .header = .{
                    .ptr = index_pos,
                    .size = header.size + 1,
                },
                .slot_ptr = slot_ptr,
            };
        }

        fn countLinkedArrayListLeafCount(block: []LinkedArrayListSlot, shift: u6, i: u4) u64 {
            var count: u64 = 0;
            // for leaf nodes, count all non-empty slots along with the slot being accessed
            if (shift == 0) {
                for (block, 0..) |block_slot, block_i| {
                    if (block_slot.slot.tag != 0 or block_i == i) {
                        count += 1;
                    }
                }
            }
            // for non-leaf nodes, add up their sizes
            else {
                for (block) |block_slot| {
                    count += block_slot.size;
                }
            }
            return count;
        }

        fn keyAndIndexForLinkedArrayList(slot_block: []LinkedArrayListSlot, key: u64, shift: u6) !struct { key: u64, index: u4 } {
            var next_key = key;
            var i: u4 = 0;
            const max_leaf_count = if (shift == 0) 1 else shift * SLOT_COUNT;
            while (true) {
                const slot_leaf_count: u64 = if (shift == 0) (if (slot_block[i].slot.tag == 0) 0 else 1) else slot_block[i].size;
                if (next_key == slot_leaf_count) {
                    // if the slot's leaf count is at its maximum,
                    // we have to skip to the next slot
                    if (slot_leaf_count == max_leaf_count) {
                        if (i + 1 < SLOT_COUNT) {
                            next_key -= slot_leaf_count;
                            i += 1;
                        } else {
                            return error.SkipLeafCountError;
                        }
                    }
                    // if the next slot has anything in it, consider this a gap
                    // and skip to the next block
                    else if (i + 1 < SLOT_COUNT and slot_block[i + 1].size > 0) {
                        next_key -= slot_leaf_count;
                        i += 1;
                    }
                    break;
                } else if (next_key < slot_leaf_count) {
                    break;
                } else if (i + 1 < SLOT_COUNT) {
                    next_key -= slot_leaf_count;
                    i += 1;
                } else {
                    return error.SkipLeafCountError;
                }
            }
            return .{ .key = next_key, .index = i };
        }

        fn readLinkedArrayListSlot(self: *Database(db_kind), index_pos: u64, key: u64, shift: u6, write_mode: WriteMode) !LinkedArrayListSlotPointer {
            const reader = self.core.reader();
            const writer = self.core.writer();

            var slot_block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;
            {
                try self.core.seekTo(index_pos);
                var index_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
                try reader.readNoEof(&index_block);

                var stream = std.io.fixedBufferStream(&index_block);
                var block_reader = stream.reader();
                for (&slot_block) |*block_slot| {
                    block_slot.* = @bitCast(try block_reader.readInt(LinkedArrayListSlotInt, .big));
                }
            }

            const key_and_index = try keyAndIndexForLinkedArrayList(&slot_block, key, shift);
            const next_key = key_and_index.key;
            const i = key_and_index.index;
            const slot = slot_block[i];
            const slot_pos = index_pos + (byteSizeOf(LinkedArrayListSlot) * i);

            if (slot.slot.tag == 0) {
                if (write_mode == .write or write_mode == .write_immutable) {
                    if (shift == 0) {
                        const leaf_count = countLinkedArrayListLeafCount(&slot_block, shift, i);
                        return .{ .slot_ptr = .{ .position = slot_pos, .slot = slot.slot }, .leaf_count = leaf_count };
                    } else {
                        try self.core.seekFromEnd(0);
                        const next_index_pos = try self.core.getPos();
                        var index_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
                        try writer.writeAll(&index_block);

                        const next_slot_ptr = try self.readLinkedArrayListSlot(next_index_pos, next_key, shift - 1, write_mode);

                        slot_block[i].size = next_slot_ptr.leaf_count;
                        const leaf_count = countLinkedArrayListLeafCount(&slot_block, shift, i);

                        try self.core.seekTo(slot_pos);
                        try writer.writeInt(LinkedArrayListSlotInt, @bitCast(LinkedArrayListSlot{ .slot = Slot.init(next_index_pos, .index), .size = next_slot_ptr.leaf_count }), .big);
                        return .{ .slot_ptr = next_slot_ptr.slot_ptr, .leaf_count = leaf_count };
                    }
                } else {
                    return error.KeyNotFound;
                }
            } else {
                const ptr = slot.slot.value;
                const tag = try Tag.init(slot.slot);
                if (shift == 0) {
                    const leaf_count = countLinkedArrayListLeafCount(&slot_block, shift, i);
                    return .{ .slot_ptr = .{ .position = slot_pos, .slot = slot.slot }, .leaf_count = leaf_count };
                } else {
                    if (tag != .index) {
                        return error.UnexpectedTag;
                    }

                    var next_ptr = ptr;
                    if (write_mode == .write_immutable) {
                        const tx_start = self.tx_start orelse return error.ExpectedTxStart;
                        if (next_ptr < tx_start) {
                            // read existing block
                            try self.core.seekTo(ptr);
                            var index_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
                            try reader.readNoEof(&index_block);
                            // copy it to the end
                            try self.core.seekFromEnd(0);
                            next_ptr = try self.core.getPos();
                            try writer.writeAll(&index_block);
                        }
                    }

                    const next_slot_ptr = try self.readLinkedArrayListSlot(next_ptr, next_key, shift - 1, write_mode);

                    slot_block[i].size = next_slot_ptr.leaf_count;
                    const leaf_count = countLinkedArrayListLeafCount(&slot_block, shift, i);

                    if (write_mode == .write_immutable) {
                        // make slot point to block
                        try self.core.seekTo(slot_pos);
                        try writer.writeInt(LinkedArrayListSlotInt, @bitCast(LinkedArrayListSlot{ .slot = Slot.init(next_ptr, .index), .size = next_slot_ptr.leaf_count }), .big);
                    }

                    return .{ .slot_ptr = next_slot_ptr.slot_ptr, .leaf_count = leaf_count };
                }
            }
        }

        fn readLinkedArrayListBlocks(self: *Database(db_kind), index_pos: u64, key: u64, shift: u6, blocks: *std.ArrayList(LinkedArrayListBlockInfo)) !void {
            const reader = self.core.reader();
            try self.core.seekTo(index_pos);
            var bytes_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
            try reader.readNoEof(&bytes_block);

            var slot_block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;
            var stream = std.io.fixedBufferStream(&bytes_block);
            var block_reader = stream.reader();
            for (&slot_block) |*block_slot| {
                block_slot.* = @bitCast(try block_reader.readInt(LinkedArrayListSlotInt, .big));
            }

            const key_and_index = try keyAndIndexForLinkedArrayList(&slot_block, key, shift);
            const next_key = key_and_index.key;
            const i = key_and_index.index;
            const leaf_count = countLinkedArrayListLeafCount(&slot_block, shift, i);

            try blocks.append(.{ .block = slot_block, .i = i, .ptr = index_pos, .leaf_count = leaf_count });

            if (shift == 0) {
                return;
            }

            const slot = slot_block[i];
            if (slot.slot.tag == 0) {
                return error.EmptySlot;
            } else {
                const ptr = slot.slot.value;
                const tag = try Tag.init(slot.slot);
                if (tag != .index) {
                    return error.UnexpectedTag;
                }
                try self.readLinkedArrayListBlocks(ptr, next_key, shift - 1, blocks);
            }
        }
    };
}
