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

const SLOT_SIZE: u64 = byteSizeOf(Slot);
const HEADER_BLOCK_SIZE = 2;
const BIT_COUNT = 4;
pub const SLOT_COUNT = 1 << BIT_COUNT;
pub const MASK: u64 = SLOT_COUNT - 1;
const INDEX_BLOCK_SIZE = SLOT_SIZE * SLOT_COUNT;
const INDEX_START = HEADER_BLOCK_SIZE;

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

const LinkedArrayListHeaderInt = u256;
const LinkedArrayListHeader = packed struct {
    ptr: u64,
    begin_padding: u64,
    size: u64,
    end_padding: u64,
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

pub const SlotPointer = struct {
    position: u64,
    slot: Slot,
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
                                        .index_start => cursor.read_slot_cursor.index_start,
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
                                            const position = level.position + (level.index * SLOT_SIZE);
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
                .read_slot_cursor = .{ .index_start = INDEX_START },
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
            const header: LinkedArrayListHeader = @bitCast(try reader.readInt(LinkedArrayListHeaderInt, .big));

            if (offset + size > header.size) {
                return error.LinkedArrayListSliceOutOfBounds;
            }

            // write new list header
            try self.core.seekFromEnd(0);
            const new_array_list_start = try self.core.getPos();
            try writer.writeInt(LinkedArrayListHeaderInt, @bitCast(LinkedArrayListHeader{
                .ptr = header.ptr,
                .begin_padding = header.begin_padding + offset,
                .size = size,
                .end_padding = header.end_padding + header.size - (offset + size),
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

            // read the first list's blocks

            try self.core.seekTo(list_a.value);
            const header_a: LinkedArrayListHeader = @bitCast(try reader.readInt(LinkedArrayListHeaderInt, .big));

            var blocks_a = std.ArrayList([SLOT_COUNT]Slot).init(self.allocator);
            defer blocks_a.deinit();
            {
                const last_key = if (header_a.size == 0) 0 else header_a.begin_padding + header_a.size + header_a.end_padding - 1;
                const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                try self.readLinkedArrayListBlocks(header_a.ptr, header_a.begin_padding + header_a.size - 1, shift, &blocks_a);
            }

            // read the second list's blocks

            try self.core.seekTo(list_b.value);
            const header_b: LinkedArrayListHeader = @bitCast(try reader.readInt(LinkedArrayListHeaderInt, .big));

            var blocks_b = std.ArrayList([SLOT_COUNT]Slot).init(self.allocator);
            defer blocks_b.deinit();
            {
                const last_key = if (header_b.size == 0) 0 else header_b.begin_padding + header_b.size + header_b.end_padding - 1;
                const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                try self.readLinkedArrayListBlocks(header_b.ptr, header_b.begin_padding, shift, &blocks_b);
            }

            return list_a;
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
            index_start: u64,
            slot_ptr: SlotPointer,
        };

        fn readSlot(self: *Database(db_kind), comptime Ctx: type, path: []const PathPart(Ctx), allow_write: bool, cursor: ReadSlotCursor) anyerror!SlotPointer {
            const part = if (path.len > 0) path[0] else switch (cursor) {
                .index_start => return SlotPointer{ .position = 0, .slot = .{} },
                .slot_ptr => {
                    if (!allow_write and cursor.slot_ptr.slot.tag == 0) {
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
                        const next_pos = cursor.slot_ptr.slot.value;
                        // read existing block
                        const reader = self.core.reader();
                        try self.core.seekTo(next_pos);
                        var header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
                        try self.core.seekTo(header.ptr);
                        var array_list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try reader.readNoEof(&array_list_index_block);
                        // copy it to the end
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const array_list_start = try self.core.getPos();
                        const next_array_list_ptr = array_list_start + byteSizeOf(ArrayListHeader);
                        header.ptr = next_array_list_ptr;
                        try writer.writeInt(ArrayListHeaderInt, @bitCast(header), .big);
                        try writer.writeAll(&array_list_index_block);
                        // make slot point to map
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = Slot.init(array_list_start, .array_list) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    }
                },
                .array_list_get => {
                    const next_array_list_start = switch (cursor) {
                        .index_start => cursor.index_start,
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
                            var key: u64 = 0;
                            if (index.reverse) {
                                if (index.index >= header.size) {
                                    return error.KeyNotFound;
                                } else {
                                    key = header.size - index.index - 1;
                                }
                            } else {
                                if (index.index >= header.size) {
                                    return error.KeyNotFound;
                                } else {
                                    key = index.index;
                                }
                            }
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
                        const array_list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        const array_list_ptr = try self.core.getPos() + byteSizeOf(LinkedArrayListHeader);
                        try writer.writeInt(LinkedArrayListHeaderInt, @bitCast(LinkedArrayListHeader{
                            .ptr = array_list_ptr,
                            .begin_padding = 0,
                            .size = 0,
                            .end_padding = 0,
                        }), .big);
                        try writer.writeAll(&array_list_index_block);
                        // make slot point to new list
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = Slot.init(array_list_start, .linked_array_list) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    } else {
                        const tag = try Tag.init(cursor.slot_ptr.slot);
                        if (tag != .linked_array_list) {
                            return error.UnexpectedTag;
                        }
                        const next_pos = cursor.slot_ptr.slot.value;
                        // read existing block
                        const reader = self.core.reader();
                        try self.core.seekTo(next_pos);
                        var header: LinkedArrayListHeader = @bitCast(try reader.readInt(LinkedArrayListHeaderInt, .big));
                        try self.core.seekTo(header.ptr);
                        var array_list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try reader.readNoEof(&array_list_index_block);
                        // copy it to the end
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const array_list_start = try self.core.getPos();
                        const next_array_list_ptr = array_list_start + byteSizeOf(LinkedArrayListHeader);
                        header.ptr = next_array_list_ptr;
                        try writer.writeInt(LinkedArrayListHeaderInt, @bitCast(header), .big);
                        try writer.writeAll(&array_list_index_block);
                        // make slot point to map
                        const next_slot_ptr = SlotPointer{ .position = cursor.slot_ptr.position, .slot = Slot.init(array_list_start, .linked_array_list) };
                        try self.core.seekTo(next_slot_ptr.position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = next_slot_ptr });
                    }
                },
                .linked_array_list_get => {
                    const next_array_list_start = switch (cursor) {
                        .index_start => cursor.index_start,
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
                            const header: LinkedArrayListHeader = @bitCast(try reader.readInt(LinkedArrayListHeaderInt, .big));
                            var key: u64 = header.begin_padding;
                            if (index.reverse) {
                                if (index.index >= header.size) {
                                    return error.KeyNotFound;
                                } else {
                                    key += header.size - index.index - 1;
                                }
                            } else {
                                if (index.index >= header.size) {
                                    return error.KeyNotFound;
                                } else {
                                    key += index.index;
                                }
                            }
                            const last_key = header.begin_padding + header.size + header.end_padding - 1;
                            const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                            const final_slot_ptr = try self.readLinkedArrayListSlot(header.ptr, key, shift, write_mode);
                            return try self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = final_slot_ptr });
                        },
                        .append => {
                            if (!allow_write) return error.WriteNotAllowed;

                            const append_result = try self.readLinkedArrayListSlotAppend(next_array_list_start, write_mode);
                            const final_slot_ptr = try self.readSlot(Ctx, path[1..], allow_write, .{ .slot_ptr = append_result.slot_ptr });

                            // update header
                            const writer = self.core.writer();
                            try self.core.seekTo(next_array_list_start);
                            try writer.writeInt(LinkedArrayListHeaderInt, @bitCast(append_result.header), .big);

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
                        const next_pos = cursor.slot_ptr.slot.value;
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

            const i = @as(u64, @truncate((key_hash >> key_offset * BIT_COUNT))) & MASK;
            const slot_pos = index_pos + (SLOT_SIZE * i);
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
                            const next_i = @as(u64, @truncate((existing_key_hash >> (key_offset + 1) * BIT_COUNT))) & MASK;
                            try self.core.seekFromEnd(0);
                            const next_index_pos = try self.core.getPos();
                            var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                            try writer.writeAll(&index_block);
                            try self.core.seekTo(next_index_pos + (SLOT_SIZE * next_i));
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

            const i = @as(u64, @truncate(key >> (shift * BIT_COUNT))) & MASK;
            const slot_pos = index_pos + (SLOT_SIZE * i);
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
                    return self.readArrayListSlot(next_ptr, key, shift - 1, write_mode);
                }
            }
        }

        // linked_array_list

        const LinkedArrayListAppendResult = struct {
            header: LinkedArrayListHeader,
            slot_ptr: SlotPointer,
        };

        fn readLinkedArrayListSlotAppend(self: *Database(db_kind), index_start: u64, write_mode: WriteMode) !LinkedArrayListAppendResult {
            const reader = self.core.reader();
            const writer = self.core.writer();

            try self.core.seekTo(index_start);
            const header: LinkedArrayListHeader = @bitCast(try reader.readInt(LinkedArrayListHeaderInt, .big));
            var index_pos = header.ptr;
            var slot_ptr: SlotPointer = undefined;

            if (header.end_padding == 0) {
                const key = header.begin_padding + header.size;

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

                slot_ptr = try self.readLinkedArrayListSlot(index_pos, key, next_shift, write_mode);
            } else {
                const last_key = if (header.size == 0) 0 else header.begin_padding + header.size + header.end_padding - 1;
                const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                const key = header.begin_padding + header.size;
                slot_ptr = try self.readLinkedArrayListSlot(index_pos, key, shift, write_mode);
            }

            return .{
                .header = .{
                    .ptr = index_pos,
                    .begin_padding = header.begin_padding,
                    .size = header.size + 1,
                    .end_padding = if (header.end_padding == 0) 0 else header.end_padding - 1,
                },
                .slot_ptr = slot_ptr,
            };
        }

        fn readLinkedArrayListSlot(self: *Database(db_kind), index_pos: u64, key: u64, shift: u6, write_mode: WriteMode) !SlotPointer {
            const reader = self.core.reader();

            const i = @as(u64, @truncate(key >> (shift * BIT_COUNT))) & MASK;
            const slot_pos = index_pos + (SLOT_SIZE * i);
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
                        return try self.readLinkedArrayListSlot(next_index_pos, key, shift - 1, write_mode);
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
                    return self.readLinkedArrayListSlot(next_ptr, key, shift - 1, write_mode);
                }
            }
        }

        fn readLinkedArrayListBlocks(self: *Database(db_kind), index_pos: u64, key: u64, shift: u6, blocks: *std.ArrayList([SLOT_COUNT]Slot)) !void {
            const reader = self.core.reader();
            try self.core.seekTo(index_pos);
            var bytes_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
            try reader.readNoEof(&bytes_block);

            var slot_block = [_]Slot{.{}} ** SLOT_COUNT;
            var stream = std.io.fixedBufferStream(&bytes_block);
            var block_reader = stream.reader();
            for (&slot_block) |*block_slot| {
                block_slot.* = @bitCast(try block_reader.readInt(SlotInt, .big));
            }
            try blocks.append(slot_block);

            if (shift == 0) {
                return;
            }

            const i = @as(u64, @truncate(key >> (shift * BIT_COUNT))) & MASK;
            const slot = slot_block[i];
            if (slot.tag == 0) {
                return error.EmptySlot;
            } else {
                const ptr = slot.value;
                const tag = try Tag.init(slot);
                if (tag != .index) {
                    return error.UnexpectedTag;
                }
                try self.readLinkedArrayListBlocks(ptr, key, shift - 1, blocks);
            }
        }
    };
}
