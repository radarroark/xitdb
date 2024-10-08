//! you're looking at radar's hopeless attempt to implement
//! his dream database. it will be embedded and immutable.
//! it will be practical for both on-disk and in-memory use.
//! there is so much work to do, and so much to learn. we're
//! gonna leeroy jenkins our way through this.

const std = @import("std");

fn byteSizeOf(T: type) u16 {
    return @bitSizeOf(T) / 8;
}

const BIT_COUNT = 4;
pub const SLOT_COUNT = 1 << BIT_COUNT;
pub const MASK: u64 = SLOT_COUNT - 1;

const SlotInt = u72;
pub const Slot = packed struct {
    value: u64 = 0,
    tag: Tag = .none,
    full: bool = false,

    pub fn eql(self: Slot, other: Slot) bool {
        const self_int: SlotInt = @bitCast(self);
        const other_int: SlotInt = @bitCast(other);
        return self_int == other_int;
    }
};

const SlotPointer = struct {
    position: ?u64,
    slot: Slot,
};

// reordering is a breaking change
pub const Tag = enum(u7) {
    none,
    index,
    array_list,
    linked_array_list,
    hash_map,
    kv_pair,
    bytes,
    uint,
    int,
    float,

    pub fn validate(self: Tag) !void {
        _ = try std.meta.intToEnum(Tag, @intFromEnum(self));
    }
};

const DATABASE_START = byteSizeOf(DatabaseHeader);
const MAGIC_NUMBER: u24 = std.mem.nativeTo(u24, std.mem.bytesToValue(u24, "xit"), .big);
pub const VERSION: u16 = 0;
const DatabaseHeaderInt = u64;
const DatabaseHeader = packed struct {
    // the size in bytes of all hashes used by the database.
    hash_size: u16,
    // increment this number when the file format changes,
    // such as when a new Tag member is added.
    version: u16 = VERSION,
    // currently the flag is just an extra bit for the version number.
    // it might be repurposed in the future.
    flag: u1 = 0,
    // the root tag, representing the type of the top-level data.
    tag: Tag = .none,
    // a value that allows for a quick sanity check when determining
    // if the file is a valid database. it also provides a quick
    // visual indicator that this is a xitdb file to anyone looking
    // directly at the bytes.
    magic_number: u24 = MAGIC_NUMBER,

    pub fn read(reader: anytype) !DatabaseHeader {
        return @bitCast(try reader.readInt(DatabaseHeaderInt, .big));
    }

    pub fn validate(self: DatabaseHeader) !void {
        if (self.magic_number != MAGIC_NUMBER) {
            return error.InvalidDatabase;
        }
        try self.tag.validate();
        if (self.flag != 0 or self.version > VERSION) {
            return error.InvalidVersion;
        }
    }
};

const WriteMode = enum {
    read_only,
    read_write,
};

const InternalWriteMode = enum {
    read_only,
    read_write,
    read_write_immutable,
};

pub const DatabaseKind = enum {
    memory,
    file,
};

pub fn Database(comptime db_kind: DatabaseKind, comptime Hash: type) type {
    return struct {
        allocator: std.mem.Allocator,
        core: Core,
        header: DatabaseHeader,
        tx_start: ?u64,

        pub const Core = switch (db_kind) {
            .memory => struct {
                buffer: *std.ArrayList(u8),
                max_size: ?u64,
                position: u64,

                pub const Reader = struct {
                    parent: *Core,

                    pub const Error = error{ EndOfStream, InvalidTypeSize };

                    pub fn read(self: Core.Reader, buf: []u8) !u64 {
                        const size = @min(buf.len, self.parent.buffer.items.len - self.parent.position);
                        if (size == 0) {
                            return 0;
                        }
                        const new_position = self.parent.position + size;
                        @memcpy(buf, self.parent.buffer.items[self.parent.position..new_position]);
                        self.parent.position = new_position;
                        return size;
                    }

                    pub fn readNoEof(self: Core.Reader, buf: []u8) !void {
                        const new_position = self.parent.position + buf.len;
                        if (new_position > self.parent.buffer.items.len) return error.EndOfStream;
                        @memcpy(buf, self.parent.buffer.items[self.parent.position..new_position]);
                        self.parent.position = new_position;
                    }

                    pub fn readInt(self: Core.Reader, comptime T: type, endian: std.builtin.Endian) !T {
                        if (@bitSizeOf(T) % 8 != 0) {
                            return error.InvalidTypeSize;
                        }
                        const size = @bitSizeOf(T) / 8;
                        const new_position = self.parent.position + size;
                        if (new_position > self.parent.buffer.items.len) return error.EndOfStream;
                        const bytes = self.parent.buffer.items[self.parent.position..new_position];
                        self.parent.position = new_position;
                        return std.mem.toNative(T, std.mem.bytesToValue(T, bytes), endian);
                    }
                };

                const Writer = struct {
                    parent: *Core,

                    fn resizeBuffer(self: Core.Writer, new_size: u64) !void {
                        if (new_size > self.parent.buffer.items.len) {
                            if (self.parent.max_size) |max_size| {
                                if (new_size > max_size) {
                                    return error.MaxSizeExceeded;
                                }
                            }
                            try self.parent.buffer.ensureTotalCapacityPrecise(new_size);
                            self.parent.buffer.expandToCapacity();
                        }
                    }

                    pub fn writeAll(self: Core.Writer, bytes: []const u8) !void {
                        const new_position = self.parent.position + @as(u64, @intCast(bytes.len));
                        try self.resizeBuffer(new_position);
                        @memcpy(self.parent.buffer.items[self.parent.position..new_position], bytes);
                        self.parent.position = new_position;
                    }

                    pub fn writeInt(self: Core.Writer, comptime T: type, value: T, endian: std.builtin.Endian) !void {
                        if (@bitSizeOf(T) % 8 != 0) {
                            return error.InvalidTypeSize;
                        }
                        const size = @bitSizeOf(T) / 8;
                        const new_position = self.parent.position + size;
                        try self.resizeBuffer(new_position);
                        const bytes = std.mem.asBytes(&std.mem.nativeTo(T, value, endian));
                        @memcpy(self.parent.buffer.items[self.parent.position..new_position], bytes[0..size]);
                        self.parent.position = new_position;
                    }
                };

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
                        self.position = self.buffer.items.len -| @as(u64, @intCast(@abs(offset)));
                    }
                }

                pub fn getPos(self: Core) !u64 {
                    return self.position;
                }
            },
            .file => struct {
                file: std.fs.File,

                pub const Reader = std.fs.File.Reader;

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

        // internal constants

        const HASH_SIZE = byteSizeOf(Hash);
        const INDEX_BLOCK_SIZE = byteSizeOf(Slot) * SLOT_COUNT;
        const LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE = byteSizeOf(LinkedArrayListSlot) * SLOT_COUNT;

        const ArrayListHeaderInt = u128;
        const ArrayListHeader = packed struct {
            ptr: u64,
            size: u64,
        };

        const LinkedArrayListHeaderInt = u136;
        const LinkedArrayListHeader = packed struct {
            shift: u6,
            padding: u2 = 0,
            ptr: u64,
            size: u64,
        };

        const KeyValuePairInt = u304;
        const KeyValuePair = packed struct {
            value_slot: Slot,
            key_slot: Slot,
            hash: Hash,
        };

        const LinkedArrayListSlotInt = u136;
        const LinkedArrayListSlot = packed struct {
            size: u64,
            slot: Slot,
        };

        const LinkedArrayListSlotPointer = struct {
            slot_ptr: SlotPointer,
            leaf_count: u64,
        };

        const LinkedArrayListBlockInfo = struct {
            block: [SLOT_COUNT]LinkedArrayListSlot,
            i: u4,
            parent_slot: LinkedArrayListSlot,
        };

        const HashMapSlotKind = enum {
            kv_pair,
            key,
            value,
        };

        pub const WriteableData = union(enum) {
            slot: ?Slot,
            uint: u64,
            int: i64,
            float: f64,
            bytes: []const u8,
        };

        pub fn PathPart(comptime Ctx: type) type {
            return union(enum) {
                array_list_init,
                array_list_get: union(enum) {
                    index: i65,
                    append,
                },
                linked_array_list_init,
                linked_array_list_get: union(enum) {
                    index: i65,
                    append,
                },
                hash_map_init,
                hash_map_get: union(HashMapSlotKind) {
                    kv_pair: Hash,
                    key: Hash,
                    value: Hash,
                },
                hash_map_remove: Hash,
                write: WriteableData,
                ctx: Ctx,
            };
        }

        // init

        pub const InitOpts = switch (db_kind) {
            .memory => struct {
                buffer: *std.ArrayList(u8),
                max_size: ?u64 = null,
            },
            .file => struct {
                file: std.fs.File,
            },
        };

        pub fn init(allocator: std.mem.Allocator, opts: InitOpts) !Database(db_kind, Hash) {
            switch (db_kind) {
                .memory => {
                    var self = Database(db_kind, Hash){
                        .allocator = allocator,
                        .core = .{
                            .buffer = opts.buffer,
                            .max_size = opts.max_size,
                            .position = 0,
                        },
                        .header = undefined,
                        .tx_start = null,
                    };

                    try self.core.seekTo(0);
                    if (self.core.buffer.items.len == 0) {
                        self.header = try self.writeHeader();
                    } else {
                        const reader = self.core.reader();
                        self.header = try DatabaseHeader.read(reader);
                        try self.header.validate();
                        if (self.header.hash_size != byteSizeOf(Hash)) {
                            return error.InvalidHashSize;
                        }
                    }

                    return self;
                },
                .file => {
                    var self = Database(db_kind, Hash){
                        .allocator = allocator,
                        .core = .{ .file = opts.file },
                        .header = undefined,
                        .tx_start = null,
                    };

                    const meta = try self.core.file.metadata();
                    const size = meta.size();

                    try self.core.seekTo(0);
                    if (size == 0) {
                        self.header = try self.writeHeader();
                    } else {
                        const reader = self.core.reader();
                        self.header = try DatabaseHeader.read(reader);
                        try self.header.validate();
                        if (self.header.hash_size != byteSizeOf(Hash)) {
                            return error.InvalidHashSize;
                        }
                    }

                    return self;
                },
            }
        }

        pub fn rootCursor(self: *Database(db_kind, Hash)) Cursor(.read_write) {
            return .{
                .slot_ptr = .{ .position = null, .slot = .{ .value = DATABASE_START, .tag = self.header.tag } },
                .db = self,
            };
        }

        // private

        fn writeHeader(self: *Database(db_kind, Hash)) !DatabaseHeader {
            const writer = self.core.writer();
            const header = DatabaseHeader{
                .hash_size = byteSizeOf(Hash),
            };
            try writer.writeInt(DatabaseHeaderInt, @bitCast(header), .big);
            return header;
        }

        fn readSlotPointer(self: *Database(db_kind, Hash), comptime write_mode: WriteMode, comptime Ctx: type, path: []const PathPart(Ctx), slot_ptr: SlotPointer) anyerror!SlotPointer {
            const internal_write_mode: InternalWriteMode = switch (write_mode) {
                .read_write => if (slot_ptr.slot.value == DATABASE_START) .read_write else .read_write_immutable,
                .read_only => .read_only,
            };

            const part = if (path.len > 0) path[0] else {
                if (internal_write_mode == .read_only and slot_ptr.slot.tag == .none) {
                    return error.KeyNotFound;
                }
                return slot_ptr;
            };

            const is_tx_start = internal_write_mode == .read_write and self.tx_start == null;
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
                .array_list_init => {
                    if (write_mode == .read_only) return error.WriteNotAllowed;

                    if (slot_ptr.slot.value == DATABASE_START) {
                        const writer = self.core.writer();

                        // update header if necessary
                        if (self.header.tag == .none) {
                            try self.core.seekTo(0);
                            self.header.tag = .array_list;
                            try writer.writeInt(DatabaseHeaderInt, @bitCast(self.header), .big);
                        }

                        // if db has nothing after header, initialize the array list
                        try self.core.seekFromEnd(0);
                        if (try self.core.getPos() == DATABASE_START) {
                            const index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                            const array_list_ptr = try self.core.getPos() + byteSizeOf(ArrayListHeader);
                            try writer.writeInt(ArrayListHeaderInt, @bitCast(ArrayListHeader{
                                .ptr = array_list_ptr,
                                .size = 0,
                            }), .big);
                            try writer.writeAll(&index_block);
                        }

                        var next_slot_ptr = slot_ptr;
                        next_slot_ptr.slot.tag = .array_list;
                        return self.readSlotPointer(write_mode, Ctx, path[1..], next_slot_ptr);
                    }

                    const position = slot_ptr.position orelse return error.CursorNotWriteable;

                    if (slot_ptr.slot.tag == .none) {
                        // if slot was empty, insert the new list
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const array_list_start = try self.core.getPos();
                        const array_list_ptr = try self.core.getPos() + byteSizeOf(ArrayListHeader);
                        try writer.writeInt(ArrayListHeaderInt, @bitCast(ArrayListHeader{
                            .ptr = array_list_ptr,
                            .size = 0,
                        }), .big);
                        const array_list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try writer.writeAll(&array_list_index_block);
                        // make slot point to list
                        const next_slot_ptr = SlotPointer{ .position = position, .slot = .{ .value = array_list_start, .tag = .array_list } };
                        try self.core.seekTo(position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlotPointer(write_mode, Ctx, path[1..], next_slot_ptr);
                    } else {
                        if (slot_ptr.slot.tag != .array_list) {
                            return error.UnexpectedTag;
                        }
                        const reader = self.core.reader();
                        const writer = self.core.writer();

                        var array_list_start = slot_ptr.slot.value;

                        // copy it to the end unless it was made in this transaction
                        const tx_start = self.tx_start orelse return error.ExpectedTxStart;
                        if (array_list_start < tx_start) {
                            // read existing block
                            try self.core.seekTo(array_list_start);
                            var header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
                            try self.core.seekTo(header.ptr);
                            var array_list_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                            try reader.readNoEof(&array_list_index_block);
                            // copy to the end
                            try self.core.seekFromEnd(0);
                            array_list_start = try self.core.getPos();
                            const next_array_list_ptr = array_list_start + byteSizeOf(ArrayListHeader);
                            header.ptr = next_array_list_ptr;
                            try writer.writeInt(ArrayListHeaderInt, @bitCast(header), .big);
                            try writer.writeAll(&array_list_index_block);
                        }

                        // make slot point to list
                        const next_slot_ptr = SlotPointer{ .position = position, .slot = .{ .value = array_list_start, .tag = .array_list } };
                        try self.core.seekTo(position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlotPointer(write_mode, Ctx, path[1..], next_slot_ptr);
                    }
                },
                .array_list_get => {
                    const tag = if (slot_ptr.slot.value == DATABASE_START) self.header.tag else slot_ptr.slot.tag;
                    if (tag == .none) {
                        return error.KeyNotFound;
                    } else if (tag != .array_list) {
                        return error.UnexpectedTag;
                    }
                    const next_array_list_start = slot_ptr.slot.value;
                    switch (part.array_list_get) {
                        .index => {
                            const index = part.array_list_get.index;
                            try self.core.seekTo(next_array_list_start);
                            const reader = self.core.reader();
                            const header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
                            if (index >= header.size or index < -@as(i65, header.size)) {
                                return error.KeyNotFound;
                            }
                            const key: u64 = if (index < 0)
                                @intCast(header.size - @abs(index))
                            else
                                @intCast(index);
                            const last_key = header.size - 1;
                            const shift: u6 = @intCast(if (last_key < SLOT_COUNT) 0 else std.math.log(u64, SLOT_COUNT, last_key));
                            const final_slot_ptr = try self.readArrayListSlot(header.ptr, key, shift, internal_write_mode);
                            return try self.readSlotPointer(write_mode, Ctx, path[1..], final_slot_ptr);
                        },
                        .append => {
                            if (write_mode == .read_only) return error.WriteNotAllowed;

                            const append_result = try self.readArrayListSlotAppend(next_array_list_start, internal_write_mode);
                            const final_slot_ptr = try self.readSlotPointer(write_mode, Ctx, path[1..], append_result.slot_ptr);

                            // update header
                            const writer = self.core.writer();
                            try self.core.seekTo(next_array_list_start);
                            try writer.writeInt(ArrayListHeaderInt, @bitCast(append_result.header), .big);

                            return final_slot_ptr;
                        },
                    }
                },
                .linked_array_list_init => {
                    if (write_mode == .read_only) return error.WriteNotAllowed;

                    if (slot_ptr.slot.value == DATABASE_START) return error.RootTypeMustBeArrayList;

                    const position = slot_ptr.position orelse return error.CursorNotWriteable;

                    if (slot_ptr.slot.tag == .none) {
                        // if slot was empty, insert the new list
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const array_list_start = try self.core.getPos();
                        const array_list_ptr = try self.core.getPos() + byteSizeOf(LinkedArrayListHeader);
                        try writer.writeInt(LinkedArrayListHeaderInt, @bitCast(LinkedArrayListHeader{
                            .shift = 0,
                            .ptr = array_list_ptr,
                            .size = 0,
                        }), .big);
                        const array_list_index_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
                        try writer.writeAll(&array_list_index_block);
                        // make slot point to new list
                        const next_slot_ptr = SlotPointer{ .position = position, .slot = .{ .value = array_list_start, .tag = .linked_array_list } };
                        try self.core.seekTo(position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlotPointer(write_mode, Ctx, path[1..], next_slot_ptr);
                    } else {
                        if (slot_ptr.slot.tag != .linked_array_list) {
                            return error.UnexpectedTag;
                        }
                        const reader = self.core.reader();
                        const writer = self.core.writer();

                        var array_list_start = slot_ptr.slot.value;

                        // copy it to the end unless it was made in this transaction
                        const tx_start = self.tx_start orelse return error.ExpectedTxStart;
                        if (array_list_start < tx_start) {
                            // read existing block
                            try self.core.seekTo(array_list_start);
                            var header: LinkedArrayListHeader = @bitCast(try reader.readInt(LinkedArrayListHeaderInt, .big));
                            try self.core.seekTo(header.ptr);
                            var array_list_index_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
                            try reader.readNoEof(&array_list_index_block);
                            // copy to the end
                            try self.core.seekFromEnd(0);
                            array_list_start = try self.core.getPos();
                            const next_array_list_ptr = array_list_start + byteSizeOf(LinkedArrayListHeader);
                            header.ptr = next_array_list_ptr;
                            try writer.writeInt(LinkedArrayListHeaderInt, @bitCast(header), .big);
                            try writer.writeAll(&array_list_index_block);
                        }

                        // make slot point to list
                        const next_slot_ptr = SlotPointer{ .position = position, .slot = .{ .value = array_list_start, .tag = .linked_array_list } };
                        try self.core.seekTo(position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlotPointer(write_mode, Ctx, path[1..], next_slot_ptr);
                    }
                },
                .linked_array_list_get => {
                    if (slot_ptr.slot.tag == .none) {
                        return error.KeyNotFound;
                    } else if (slot_ptr.slot.tag != .linked_array_list) {
                        return error.UnexpectedTag;
                    }
                    const next_array_list_start = slot_ptr.slot.value;

                    switch (part.linked_array_list_get) {
                        .index => {
                            const index = part.linked_array_list_get.index;
                            try self.core.seekTo(next_array_list_start);
                            const reader = self.core.reader();
                            const header: LinkedArrayListHeader = @bitCast(try reader.readInt(LinkedArrayListHeaderInt, .big));
                            if (index >= header.size or index < -@as(i65, header.size)) {
                                return error.KeyNotFound;
                            }
                            const key: u64 = if (index < 0)
                                @intCast(header.size - @abs(index))
                            else
                                @intCast(index);
                            const final_slot_ptr = try self.readLinkedArrayListSlot(header.ptr, key, header.shift, internal_write_mode);
                            return try self.readSlotPointer(write_mode, Ctx, path[1..], final_slot_ptr.slot_ptr);
                        },
                        .append => {
                            if (write_mode == .read_only) return error.WriteNotAllowed;

                            const append_result = try self.readLinkedArrayListSlotAppend(next_array_list_start, internal_write_mode);
                            const final_slot_ptr = try self.readSlotPointer(write_mode, Ctx, path[1..], append_result.slot_ptr.slot_ptr);

                            // update header
                            const writer = self.core.writer();
                            try self.core.seekTo(next_array_list_start);
                            try writer.writeInt(LinkedArrayListHeaderInt, @bitCast(append_result.header), .big);

                            return final_slot_ptr;
                        },
                    }
                },
                .hash_map_init => {
                    if (write_mode == .read_only) return error.WriteNotAllowed;

                    if (slot_ptr.slot.value == DATABASE_START) return error.RootTypeMustBeArrayList;

                    const position = slot_ptr.position orelse return error.CursorNotWriteable;

                    if (slot_ptr.slot.tag == .none) {
                        // if slot was empty, insert the new map
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const map_start = try self.core.getPos();
                        const map_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try writer.writeAll(&map_index_block);
                        // make slot point to map
                        const next_slot_ptr = SlotPointer{ .position = position, .slot = .{ .value = map_start, .tag = .hash_map } };
                        try self.core.seekTo(position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlotPointer(write_mode, Ctx, path[1..], next_slot_ptr);
                    } else {
                        if (slot_ptr.slot.tag != .hash_map) {
                            return error.UnexpectedTag;
                        }
                        const reader = self.core.reader();
                        const writer = self.core.writer();

                        var map_start = slot_ptr.slot.value;

                        // copy it to the end unless it was made in this transaction
                        const tx_start = self.tx_start orelse return error.ExpectedTxStart;
                        if (map_start < tx_start) {
                            // read existing block
                            try self.core.seekTo(map_start);
                            var map_index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                            try reader.readNoEof(&map_index_block);
                            // copy to the end
                            try self.core.seekFromEnd(0);
                            map_start = try self.core.getPos();
                            try writer.writeAll(&map_index_block);
                        }

                        // make slot point to map
                        const next_slot_ptr = SlotPointer{ .position = position, .slot = .{ .value = map_start, .tag = .hash_map } };
                        try self.core.seekTo(position);
                        try writer.writeInt(SlotInt, @bitCast(next_slot_ptr.slot), .big);
                        return self.readSlotPointer(write_mode, Ctx, path[1..], next_slot_ptr);
                    }
                },
                .hash_map_get => {
                    if (slot_ptr.slot.tag == .none) {
                        return error.KeyNotFound;
                    } else if (slot_ptr.slot.tag != .hash_map) {
                        return error.UnexpectedTag;
                    }
                    const next_map_start = slot_ptr.slot.value;

                    const next_slot_ptr = switch (part.hash_map_get) {
                        .kv_pair => try self.readMapSlot(next_map_start, part.hash_map_get.kv_pair, 0, internal_write_mode, .kv_pair),
                        .key => try self.readMapSlot(next_map_start, part.hash_map_get.key, 0, internal_write_mode, .key),
                        .value => try self.readMapSlot(next_map_start, part.hash_map_get.value, 0, internal_write_mode, .value),
                    };
                    return self.readSlotPointer(write_mode, Ctx, path[1..], next_slot_ptr);
                },
                .hash_map_remove => {
                    if (write_mode == .read_only) return error.WriteNotAllowed;

                    if (path.len > 1) return error.PathPartMustBeAtEnd;

                    if (slot_ptr.slot.tag == .none) {
                        return error.KeyNotFound;
                    } else if (slot_ptr.slot.tag != .hash_map) {
                        return error.UnexpectedTag;
                    }
                    const next_map_start = slot_ptr.slot.value;

                    const next_slot_ptr = self.readMapSlot(next_map_start, part.hash_map_remove, 0, .read_only, .kv_pair) catch |err| switch (err) {
                        error.KeyNotFound => {
                            // if there was nothing to remove, return an empty
                            // slot pointer so caller can see nothing was removed
                            return .{ .position = null, .slot = .{} };
                        },
                        else => return err,
                    };

                    const writer = self.core.writer();
                    const position = next_slot_ptr.position orelse return error.CursorNotWriteable;
                    try self.core.seekTo(position);
                    try writer.writeInt(SlotInt, 0, .big);
                    return next_slot_ptr;
                },
                .write => {
                    if (write_mode == .read_only) return error.WriteNotAllowed;

                    const position = slot_ptr.position orelse return error.CursorNotWriteable;

                    const core_writer = self.core.writer();

                    var slot: Slot = switch (part.write) {
                        .slot => part.write.slot orelse .{ .tag = .none },
                        .uint => .{ .value = part.write.uint, .tag = .uint },
                        .int => .{ .value = @bitCast(part.write.int), .tag = .int },
                        .float => .{ .value = @bitCast(part.write.float), .tag = .float },
                        .bytes => blk: {
                            var next_cursor = Cursor(.read_write){
                                .slot_ptr = slot_ptr,
                                .db = self,
                            };
                            var writer = try next_cursor.writer();
                            try writer.writeAll(part.write.bytes);
                            try writer.finish();
                            break :blk writer.slot;
                        },
                    };

                    // this bit allows us to distinguish between a slot explicitly set to .none
                    // and a slot that hasn't been set yet. it also is particularly important
                    // for linked array lists, which rely on it when doing index lookups.
                    slot.full = true;

                    try self.core.seekTo(position);
                    try core_writer.writeInt(SlotInt, @bitCast(slot), .big);

                    const next_slot_ptr = SlotPointer{ .position = slot_ptr.position, .slot = slot };
                    return self.readSlotPointer(write_mode, Ctx, path[1..], next_slot_ptr);
                },
                .ctx => {
                    if (write_mode == .read_only) return error.WriteNotAllowed;

                    if (path.len > 1) return error.PathPartMustBeAtEnd;

                    if (@TypeOf(part.ctx) == void) {
                        return error.NotImplmented;
                    } else {
                        var next_cursor = Cursor(.read_write){
                            .slot_ptr = slot_ptr,
                            .db = self,
                        };
                        try part.ctx.run(&next_cursor);
                        return next_cursor.slot_ptr;
                    }
                },
            }
        }

        // hash_map

        fn readMapSlot(self: *Database(db_kind, Hash), index_pos: u64, key_hash: Hash, key_offset: u8, internal_write_mode: InternalWriteMode, hash_map_return: HashMapSlotKind) !SlotPointer {
            if (key_offset >= (HASH_SIZE * 8) / BIT_COUNT) {
                return error.KeyOffsetExceeded;
            }

            const reader = self.core.reader();
            const writer = self.core.writer();

            const i: u4 = @intCast((key_hash >> key_offset * BIT_COUNT) & MASK);
            const slot_pos = index_pos + (byteSizeOf(Slot) * i);
            try self.core.seekTo(slot_pos);
            const slot: Slot = @bitCast(try reader.readInt(SlotInt, .big));
            try slot.tag.validate();

            const ptr = slot.value;

            switch (slot.tag) {
                .none => {
                    if (internal_write_mode != .read_only) {
                        try self.core.seekFromEnd(0);

                        // write hash and key/val slots
                        const hash_pos = try self.core.getPos();
                        const key_slot_pos = hash_pos + byteSizeOf(Hash);
                        const value_slot_pos = key_slot_pos + byteSizeOf(Slot);
                        const kv_pair = KeyValuePair{
                            .value_slot = @bitCast(@as(SlotInt, 0)),
                            .key_slot = @bitCast(@as(SlotInt, 0)),
                            .hash = key_hash,
                        };
                        try writer.writeInt(KeyValuePairInt, @bitCast(kv_pair), .big);

                        // point slot to hash pos
                        const next_slot = Slot{ .value = hash_pos, .tag = .kv_pair };
                        try self.core.seekTo(slot_pos);
                        try writer.writeInt(SlotInt, @bitCast(next_slot), .big);

                        return switch (hash_map_return) {
                            .kv_pair => SlotPointer{ .position = slot_pos, .slot = next_slot },
                            .key => SlotPointer{ .position = key_slot_pos, .slot = kv_pair.key_slot },
                            .value => SlotPointer{ .position = value_slot_pos, .slot = kv_pair.value_slot },
                        };
                    } else {
                        return error.KeyNotFound;
                    }
                },
                .index => {
                    var next_ptr = ptr;
                    if (internal_write_mode == .read_write_immutable) {
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
                            try writer.writeInt(SlotInt, @bitCast(Slot{ .value = next_ptr, .tag = .index }), .big);
                        }
                    }
                    return self.readMapSlot(next_ptr, key_hash, key_offset + 1, internal_write_mode, hash_map_return);
                },
                .kv_pair => {
                    try self.core.seekTo(ptr);
                    const kv_pair: KeyValuePair = @bitCast(try reader.readInt(KeyValuePairInt, .big));

                    if (kv_pair.hash == key_hash) {
                        if (internal_write_mode == .read_write_immutable) {
                            const tx_start = self.tx_start orelse return error.ExpectedTxStart;
                            if (ptr < tx_start) {
                                try self.core.seekFromEnd(0);

                                // write hash and key/val slots
                                const hash_pos = try self.core.getPos();
                                const key_slot_pos = hash_pos + byteSizeOf(Hash);
                                const value_slot_pos = key_slot_pos + byteSizeOf(Slot);
                                try writer.writeInt(KeyValuePairInt, @bitCast(kv_pair), .big);

                                // point slot to hash pos
                                const next_slot = Slot{ .value = hash_pos, .tag = .kv_pair };
                                try self.core.seekTo(slot_pos);
                                try writer.writeInt(SlotInt, @bitCast(next_slot), .big);

                                return switch (hash_map_return) {
                                    .kv_pair => SlotPointer{ .position = slot_pos, .slot = next_slot },
                                    .key => SlotPointer{ .position = key_slot_pos, .slot = kv_pair.key_slot },
                                    .value => SlotPointer{ .position = value_slot_pos, .slot = kv_pair.value_slot },
                                };
                            }
                        }

                        const key_slot_pos = ptr + byteSizeOf(Hash);
                        const value_slot_pos = key_slot_pos + byteSizeOf(Slot);
                        return switch (hash_map_return) {
                            .kv_pair => SlotPointer{ .position = slot_pos, .slot = slot },
                            .key => SlotPointer{ .position = key_slot_pos, .slot = kv_pair.key_slot },
                            .value => SlotPointer{ .position = value_slot_pos, .slot = kv_pair.value_slot },
                        };
                    } else {
                        if (internal_write_mode != .read_only) {
                            // append new index block
                            if (key_offset + 1 >= (HASH_SIZE * 8) / BIT_COUNT) {
                                return error.KeyOffsetExceeded;
                            }
                            const next_i: u4 = @intCast((kv_pair.hash >> (key_offset + 1) * BIT_COUNT) & MASK);
                            try self.core.seekFromEnd(0);
                            const next_index_pos = try self.core.getPos();
                            var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                            try writer.writeAll(&index_block);
                            try self.core.seekTo(next_index_pos + (byteSizeOf(Slot) * next_i));
                            try writer.writeInt(SlotInt, @bitCast(slot), .big);
                            const next_slot_ptr = try self.readMapSlot(next_index_pos, key_hash, key_offset + 1, internal_write_mode, hash_map_return);
                            try self.core.seekTo(slot_pos);
                            try writer.writeInt(SlotInt, @bitCast(Slot{ .value = next_index_pos, .tag = .index }), .big);
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

        fn readArrayListSlotAppend(self: *Database(db_kind, Hash), index_start: u64, internal_write_mode: InternalWriteMode) !ArrayListAppendResult {
            const reader = self.core.reader();
            const writer = self.core.writer();

            try self.core.seekTo(index_start);
            const header: ArrayListHeader = @bitCast(try reader.readInt(ArrayListHeaderInt, .big));
            var index_pos = header.ptr;

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
                try writer.writeInt(SlotInt, @bitCast(Slot{ .value = index_pos, .tag = .index }), .big);
                index_pos = next_index_pos;
            }

            const slot_ptr = try self.readArrayListSlot(index_pos, key, next_shift, internal_write_mode);

            return .{
                .header = .{
                    .ptr = index_pos,
                    .size = header.size + 1,
                },
                .slot_ptr = slot_ptr,
            };
        }

        fn readArrayListSlot(self: *Database(db_kind, Hash), index_pos: u64, key: u64, shift: u6, internal_write_mode: InternalWriteMode) !SlotPointer {
            const reader = self.core.reader();

            const i: u4 = @intCast(key >> (shift * BIT_COUNT) & MASK);
            const slot_pos = index_pos + (byteSizeOf(Slot) * i);
            try self.core.seekTo(slot_pos);
            const slot: Slot = @bitCast(try reader.readInt(SlotInt, .big));
            try slot.tag.validate();

            if (shift == 0) {
                return SlotPointer{ .position = slot_pos, .slot = slot };
            }

            const ptr = slot.value;

            switch (slot.tag) {
                .none => {
                    if (internal_write_mode != .read_only) {
                        const writer = self.core.writer();
                        try self.core.seekFromEnd(0);
                        const next_index_pos = try self.core.getPos();
                        var index_block = [_]u8{0} ** INDEX_BLOCK_SIZE;
                        try writer.writeAll(&index_block);
                        try self.core.seekTo(slot_pos);
                        try writer.writeInt(SlotInt, @bitCast(Slot{ .value = next_index_pos, .tag = .index }), .big);
                        return try self.readArrayListSlot(next_index_pos, key, shift - 1, internal_write_mode);
                    } else {
                        return error.KeyNotFound;
                    }
                },
                .index => {
                    var next_ptr = ptr;
                    if (internal_write_mode == .read_write_immutable) {
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
                            try writer.writeInt(SlotInt, @bitCast(Slot{ .value = next_ptr, .tag = .index }), .big);
                        }
                    }
                    return self.readArrayListSlot(next_ptr, key, shift - 1, internal_write_mode);
                },
                else => return error.UnexpectedTag,
            }
        }

        // linked_array_list

        const LinkedArrayListAppendResult = struct {
            header: LinkedArrayListHeader,
            slot_ptr: LinkedArrayListSlotPointer,
        };

        fn readLinkedArrayListSlotAppend(self: *Database(db_kind, Hash), index_start: u64, internal_write_mode: InternalWriteMode) !LinkedArrayListAppendResult {
            const reader = self.core.reader();
            const writer = self.core.writer();

            try self.core.seekTo(index_start);
            const header: LinkedArrayListHeader = @bitCast(try reader.readInt(LinkedArrayListHeaderInt, .big));
            var ptr = header.ptr;
            const key = header.size;
            var shift = header.shift;

            var slot_ptr = self.readLinkedArrayListSlot(ptr, key, shift, internal_write_mode) catch |err| switch (err) {
                error.NoAvailableSlots => blk: {
                    // root overflow
                    try self.core.seekFromEnd(0);
                    const next_ptr = try self.core.getPos();
                    var index_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
                    try writer.writeAll(&index_block);
                    try self.core.seekTo(next_ptr);
                    try writer.writeInt(LinkedArrayListSlotInt, @bitCast(LinkedArrayListSlot{
                        .slot = .{ .value = ptr, .tag = .index, .full = true },
                        .size = header.size,
                    }), .big);
                    ptr = next_ptr;
                    shift += 1;
                    break :blk try self.readLinkedArrayListSlot(ptr, key, shift, internal_write_mode);
                },
                else => return err,
            };

            // newly-appended slots must have full set to true
            // or else the indexing will be screwed up
            const new_slot = Slot{ .value = 0, .tag = .none, .full = true };
            slot_ptr.slot_ptr.slot = new_slot;
            const position = slot_ptr.slot_ptr.position orelse return error.CursorNotWriteable;
            try self.core.seekTo(position);
            try writer.writeInt(LinkedArrayListSlotInt, @bitCast(LinkedArrayListSlot{ .slot = new_slot, .size = 0 }), .big);
            if (header.size < SLOT_COUNT and shift > 0) {
                return error.MustSetNewSlotsToFull;
            }

            return .{
                .header = .{
                    .shift = shift,
                    .ptr = ptr,
                    .size = header.size + 1,
                },
                .slot_ptr = slot_ptr,
            };
        }

        fn blockLeafCount(block: []LinkedArrayListSlot, shift: u6, i: u4) u64 {
            var n: u64 = 0;
            // for leaf nodes, count all non-empty slots along with the slot being accessed
            if (shift == 0) {
                for (block, 0..) |block_slot, block_i| {
                    if (block_slot.slot.tag != .none or block_slot.slot.full or block_i == i) {
                        n += 1;
                    }
                }
            }
            // for non-leaf nodes, add up their sizes
            else {
                for (block) |block_slot| {
                    n += block_slot.size;
                }
            }
            return n;
        }

        fn slotLeafCount(slot: LinkedArrayListSlot, shift: u6) u64 {
            if (shift == 0) {
                if (slot.slot.tag == .none and !slot.slot.full) {
                    return 0;
                } else {
                    return 1;
                }
            } else {
                return slot.size;
            }
        }

        fn keyAndIndexForLinkedArrayList(slot_block: []LinkedArrayListSlot, key: u64, shift: u6) ?struct { key: u64, index: u4 } {
            var next_key = key;
            var i: u4 = 0;
            const max_leaf_count: u64 = if (shift == 0) 1 else std.math.pow(u64, SLOT_COUNT, shift);
            while (true) {
                const slot_leaf_count = slotLeafCount(slot_block[i], shift);
                if (next_key == slot_leaf_count) {
                    // if the slot's leaf count is at its maximum
                    // or it is full, we have to skip to the next slot
                    if (slot_leaf_count == max_leaf_count or slot_block[i].slot.full) {
                        if (i < SLOT_COUNT - 1) {
                            next_key -= slot_leaf_count;
                            i += 1;
                        } else {
                            return null;
                        }
                    }
                    break;
                } else if (next_key < slot_leaf_count) {
                    break;
                } else if (i < SLOT_COUNT - 1) {
                    next_key -= slot_leaf_count;
                    i += 1;
                } else {
                    return null;
                }
            }
            return .{ .key = next_key, .index = i };
        }

        fn readLinkedArrayListSlot(self: *Database(db_kind, Hash), index_pos: u64, key: u64, shift: u6, internal_write_mode: InternalWriteMode) !LinkedArrayListSlotPointer {
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
                    try block_slot.slot.tag.validate();
                }
            }

            const key_and_index = keyAndIndexForLinkedArrayList(&slot_block, key, shift) orelse return error.NoAvailableSlots;
            const next_key = key_and_index.key;
            const i = key_and_index.index;
            const slot = slot_block[i];
            const slot_pos = index_pos + (byteSizeOf(LinkedArrayListSlot) * i);

            if (shift == 0) {
                const leaf_count = blockLeafCount(&slot_block, shift, i);
                return .{ .slot_ptr = .{ .position = slot_pos, .slot = slot.slot }, .leaf_count = leaf_count };
            }

            const ptr = slot.slot.value;

            switch (slot.slot.tag) {
                .none => {
                    if (internal_write_mode != .read_only) {
                        try self.core.seekFromEnd(0);
                        const next_index_pos = try self.core.getPos();
                        var index_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
                        try writer.writeAll(&index_block);

                        const next_slot_ptr = try self.readLinkedArrayListSlot(next_index_pos, next_key, shift - 1, internal_write_mode);

                        slot_block[i].size = next_slot_ptr.leaf_count;
                        const leaf_count = blockLeafCount(&slot_block, shift, i);

                        try self.core.seekTo(slot_pos);
                        try writer.writeInt(LinkedArrayListSlotInt, @bitCast(LinkedArrayListSlot{ .slot = .{ .value = next_index_pos, .tag = .index }, .size = next_slot_ptr.leaf_count }), .big);
                        return .{ .slot_ptr = next_slot_ptr.slot_ptr, .leaf_count = leaf_count };
                    } else {
                        return error.KeyNotFound;
                    }
                },
                .index => {
                    var next_ptr = ptr;
                    if (internal_write_mode == .read_write_immutable) {
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

                    const next_slot_ptr = try self.readLinkedArrayListSlot(next_ptr, next_key, shift - 1, internal_write_mode);

                    slot_block[i].size = next_slot_ptr.leaf_count;
                    const leaf_count = blockLeafCount(&slot_block, shift, i);

                    if (internal_write_mode == .read_write_immutable) {
                        // make slot point to block
                        try self.core.seekTo(slot_pos);
                        try writer.writeInt(LinkedArrayListSlotInt, @bitCast(LinkedArrayListSlot{ .slot = .{ .value = next_ptr, .tag = .index }, .size = next_slot_ptr.leaf_count }), .big);
                    }

                    return .{ .slot_ptr = next_slot_ptr.slot_ptr, .leaf_count = leaf_count };
                },
                else => return error.UnexpectedTag,
            }
        }

        fn readLinkedArrayListBlocks(self: *Database(db_kind, Hash), index_pos: u64, key: u64, shift: u6, blocks: *std.ArrayList(LinkedArrayListBlockInfo)) !void {
            const reader = self.core.reader();

            var slot_block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;
            {
                try self.core.seekTo(index_pos);
                var index_block = [_]u8{0} ** LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE;
                try reader.readNoEof(&index_block);

                var stream = std.io.fixedBufferStream(&index_block);
                var block_reader = stream.reader();
                for (&slot_block) |*block_slot| {
                    block_slot.* = @bitCast(try block_reader.readInt(LinkedArrayListSlotInt, .big));
                    try block_slot.slot.tag.validate();
                }
            }

            const key_and_index = keyAndIndexForLinkedArrayList(&slot_block, key, shift) orelse return error.NoAvailableSlots;
            const next_key = key_and_index.key;
            const i = key_and_index.index;
            const leaf_count = blockLeafCount(&slot_block, shift, i);

            try blocks.append(.{ .block = slot_block, .i = i, .parent_slot = .{ .slot = .{ .value = index_pos, .tag = .index }, .size = leaf_count } });

            if (shift == 0) {
                return;
            }

            const slot = slot_block[i];
            switch (slot.slot.tag) {
                .none => return error.EmptySlot,
                .index => {
                    try self.readLinkedArrayListBlocks(slot.slot.value, next_key, shift - 1, blocks);
                },
                else => return error.UnexpectedTag,
            }
        }

        // Cursor

        pub fn Cursor(comptime write_mode: WriteMode) type {
            return struct {
                slot_ptr: SlotPointer,
                db: *Database(db_kind, Hash),

                pub const Reader = struct {
                    parent: *Cursor(write_mode),
                    size: u64,
                    start_position: u64,
                    relative_position: u64,

                    pub const Error = Database(db_kind, Hash).Core.Reader.Error || error{ EndOfStream, Unseekable };

                    pub fn read(self: *Reader, buf: []u8) !u64 {
                        if (self.size < self.relative_position) return error.EndOfStream;
                        try self.parent.db.core.seekTo(self.start_position + self.relative_position);
                        const core_reader = self.parent.db.core.reader();
                        const size = try core_reader.read(buf[0..@min(buf.len, self.size - self.relative_position)]);
                        self.relative_position += size;
                        return size;
                    }

                    pub fn readNoEof(self: *Reader, buf: []u8) !void {
                        if (self.size < self.relative_position or self.size - self.relative_position < buf.len) return error.EndOfStream;
                        try self.parent.db.core.seekTo(self.start_position + self.relative_position);
                        const core_reader = self.parent.db.core.reader();
                        try core_reader.readNoEof(buf);
                        self.relative_position += buf.len;
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
                        self.relative_position += buf_slice.len;
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
                        self.relative_position += buf_slice.len;
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
                        self.relative_position += size;
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
                    parent: *Cursor(.read_write),
                    size: u64,
                    slot: Slot,
                    start_position: u64,
                    relative_position: u64,

                    pub fn finish(self: Writer) !void {
                        const core_writer = self.parent.db.core.writer();

                        try self.parent.db.core.seekTo(self.slot.value);
                        try core_writer.writeInt(u64, self.size, .big);

                        const position = self.parent.slot_ptr.position orelse return error.CursorNotWriteable;
                        try self.parent.db.core.seekTo(position);
                        try core_writer.writeInt(SlotInt, @bitCast(self.slot), .big);

                        self.parent.slot_ptr.slot = self.slot;
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

                pub fn readOnly(self: Cursor(.read_write)) Cursor(.read_only) {
                    return .{
                        .slot_ptr = self.slot_ptr,
                        .db = self.db,
                    };
                }

                pub fn readPath(self: Cursor(write_mode), comptime Ctx: type, path: []const PathPart(Ctx)) !?Cursor(.read_only) {
                    const slot_ptr = self.db.readSlotPointer(.read_only, Ctx, path, self.slot_ptr) catch |err| {
                        switch (err) {
                            error.KeyNotFound => return null,
                            else => return err,
                        }
                    };
                    return .{
                        .slot_ptr = slot_ptr,
                        .db = self.db,
                    };
                }

                pub fn readPathSlot(self: Cursor(write_mode), comptime Ctx: type, path: []const PathPart(Ctx)) !?Slot {
                    const slot_ptr = self.db.readSlotPointer(.read_only, Ctx, path, self.slot_ptr) catch |err| {
                        switch (err) {
                            error.KeyNotFound => return null,
                            else => return err,
                        }
                    };
                    if (slot_ptr.slot.tag == .none) {
                        return null;
                    } else {
                        return slot_ptr.slot;
                    }
                }

                pub fn writePath(self: Cursor(.read_write), comptime Ctx: type, path: []const PathPart(Ctx)) !Cursor(.read_write) {
                    const slot_ptr = try self.db.readSlotPointer(.read_write, Ctx, path, self.slot_ptr);
                    return .{
                        .slot_ptr = slot_ptr,
                        .db = self.db,
                    };
                }

                pub fn readUint(self: Cursor(write_mode)) !u64 {
                    if (self.slot_ptr.slot.tag != .uint) {
                        return error.UnexpectedTag;
                    }
                    return self.slot_ptr.slot.value;
                }

                pub fn readInt(self: Cursor(write_mode)) !i64 {
                    if (self.slot_ptr.slot.tag != .int) {
                        return error.UnexpectedTag;
                    }
                    return @bitCast(self.slot_ptr.slot.value);
                }

                pub fn readFloat(self: Cursor(write_mode)) !f64 {
                    if (self.slot_ptr.slot.tag != .float) {
                        return error.UnexpectedTag;
                    }
                    return @bitCast(self.slot_ptr.slot.value);
                }

                pub fn readBytesAlloc(self: Cursor(write_mode), allocator: std.mem.Allocator, max_size: usize) ![]u8 {
                    const core_reader = self.db.core.reader();

                    if (self.slot_ptr.slot.tag != .bytes) {
                        return error.UnexpectedTag;
                    }

                    try self.db.core.seekTo(self.slot_ptr.slot.value);
                    const value_size = try core_reader.readInt(u64, .big);

                    if (value_size > max_size) {
                        return error.MaxSizeExceeded;
                    }

                    const value = try allocator.alloc(u8, value_size);
                    errdefer allocator.free(value);

                    try core_reader.readNoEof(value);
                    return value;
                }

                pub fn readBytes(self: Cursor(write_mode), buffer: []u8) ![]u8 {
                    const core_reader = self.db.core.reader();

                    if (self.slot_ptr.slot.tag != .bytes) {
                        return error.UnexpectedTag;
                    }

                    try self.db.core.seekTo(self.slot_ptr.slot.value);
                    const value_size = try core_reader.readInt(u64, .big);
                    const size = @min(buffer.len, value_size);

                    try core_reader.readNoEof(buffer[0..size]);
                    return buffer[0..size];
                }

                pub const KeyValuePairCursor = struct {
                    value_cursor: Cursor(write_mode),
                    key_cursor: Cursor(write_mode),
                    hash: Hash,
                };

                pub fn readKeyValuePair(self: Cursor(write_mode)) !KeyValuePairCursor {
                    const core_reader = self.db.core.reader();

                    if (self.slot_ptr.slot.tag != .kv_pair) {
                        return error.UnexpectedTag;
                    }

                    try self.db.core.seekTo(self.slot_ptr.slot.value);
                    const kv_pair: KeyValuePair = @bitCast(try core_reader.readInt(KeyValuePairInt, .big));

                    try kv_pair.key_slot.tag.validate();
                    try kv_pair.value_slot.tag.validate();

                    const hash_pos = self.slot_ptr.slot.value;
                    const key_slot_pos = hash_pos + byteSizeOf(Hash);
                    const value_slot_pos = key_slot_pos + byteSizeOf(Slot);

                    return .{
                        .value_cursor = .{ .slot_ptr = .{ .position = value_slot_pos, .slot = kv_pair.value_slot }, .db = self.db },
                        .key_cursor = .{ .slot_ptr = .{ .position = key_slot_pos, .slot = kv_pair.key_slot }, .db = self.db },
                        .hash = kv_pair.hash,
                    };
                }

                pub fn writeBytes(self: *Cursor(.read_write), buffer: []const u8, mode: enum { once, replace }) !void {
                    if (mode == .replace or self.slot_ptr.slot.tag == .none) {
                        var cursor_writer = try self.writer();
                        try cursor_writer.writeAll(buffer);
                        try cursor_writer.finish();
                    }
                }

                pub fn reader(self: *Cursor(write_mode)) !Reader {
                    const core_reader = self.db.core.reader();
                    const cursor_slot = self.slot_ptr.slot;

                    if (cursor_slot.tag != .bytes) {
                        return error.UnexpectedTag;
                    }

                    try self.db.core.seekTo(cursor_slot.value);
                    const size: u64 = @intCast(try core_reader.readInt(u64, .big));
                    const start_position = try self.db.core.getPos();

                    return Reader{
                        .parent = self,
                        .size = size,
                        .start_position = start_position,
                        .relative_position = 0,
                    };
                }

                pub fn writer(self: *Cursor(.read_write)) !Writer {
                    if (self.slot_ptr.slot.tag != .none and self.slot_ptr.slot.tag != .bytes) {
                        return error.UnexpectedTag;
                    }

                    const core_writer = self.db.core.writer();
                    try self.db.core.seekFromEnd(0);
                    const ptr_pos = try self.db.core.getPos();
                    try core_writer.writeInt(u64, 0, .big);
                    const start_position = try self.db.core.getPos();

                    return Writer{
                        .parent = self,
                        .size = 0,
                        .slot = .{ .value = ptr_pos, .tag = .bytes },
                        .start_position = start_position,
                        .relative_position = 0,
                    };
                }

                pub fn slot(self: Cursor(write_mode)) ?Slot {
                    return if (self.slot_ptr.slot.tag == .none) null else self.slot_ptr.slot;
                }

                pub fn slice(self: Cursor(write_mode), offset: u64, size: u64) !Cursor(.read_only) {
                    if (self.slot_ptr.slot.tag != .linked_array_list) {
                        return error.UnexpectedTag;
                    }

                    const core_reader = self.db.core.reader();
                    const core_writer = self.db.core.writer();

                    const array_list_start = self.slot_ptr.slot.value;
                    try self.db.core.seekTo(array_list_start);
                    const header: LinkedArrayListHeader = @bitCast(try core_reader.readInt(LinkedArrayListHeaderInt, .big));

                    if (offset + size > header.size) {
                        return error.LinkedArrayListSliceOutOfBounds;
                    } else if (size == header.size) {
                        return switch (write_mode) {
                            .read_only => self,
                            .read_write => self.readOnly(),
                        };
                    }

                    // read the list's left blocks
                    var left_blocks = std.ArrayList(LinkedArrayListBlockInfo).init(self.db.allocator);
                    defer left_blocks.deinit();
                    try self.db.readLinkedArrayListBlocks(header.ptr, offset, header.shift, &left_blocks);

                    // read the list's right blocks
                    var right_blocks = std.ArrayList(LinkedArrayListBlockInfo).init(self.db.allocator);
                    defer right_blocks.deinit();
                    const right_key = if (offset + size == 0) 0 else offset + size - 1;
                    try self.db.readLinkedArrayListBlocks(header.ptr, right_key, header.shift, &right_blocks);

                    // create the new blocks
                    const block_count = left_blocks.items.len;
                    var next_slots = [_]?LinkedArrayListSlot{null} ** 2;
                    var next_shift: u6 = 0;
                    for (0..block_count) |i| {
                        const is_leaf_node = next_slots[0] == null;

                        const left_block = left_blocks.items[block_count - i - 1];
                        const right_block = right_blocks.items[block_count - i - 1];
                        const orig_block_infos = [_]LinkedArrayListBlockInfo{
                            left_block,
                            right_block,
                        };
                        var next_blocks: [2]?[SLOT_COUNT]LinkedArrayListSlot = .{ null, null };

                        if (left_block.parent_slot.slot.value == right_block.parent_slot.slot.value) {
                            var slot_i: usize = 0;
                            var new_root_block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;
                            // left slot
                            if (next_slots[0]) |left_slot| {
                                new_root_block[slot_i] = left_slot;
                            } else {
                                new_root_block[slot_i] = left_block.block[left_block.i];
                            }
                            slot_i += 1;
                            // middle slots
                            if (left_block.i != right_block.i) {
                                for (left_block.block[left_block.i + 1 .. right_block.i]) |middle_slot| {
                                    new_root_block[slot_i] = middle_slot;
                                    slot_i += 1;
                                }
                            }
                            // right slot
                            if (next_slots[1]) |right_slot| {
                                new_root_block[slot_i] = right_slot;
                            } else {
                                new_root_block[slot_i] = left_block.block[right_block.i];
                            }
                            next_blocks[0] = new_root_block;
                        } else {
                            var slot_i: usize = 0;
                            var new_left_block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;

                            // first slot
                            if (next_slots[0]) |first_slot| {
                                new_left_block[slot_i] = first_slot;
                            } else {
                                new_left_block[slot_i] = left_block.block[left_block.i];
                            }
                            slot_i += 1;
                            // rest of slots
                            for (left_block.block[left_block.i + 1 ..]) |next_slot| {
                                new_left_block[slot_i] = next_slot;
                                slot_i += 1;
                            }
                            next_blocks[0] = new_left_block;

                            slot_i = 0;
                            var new_right_block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;
                            // first slots
                            for (right_block.block[0..right_block.i]) |first_slot| {
                                new_right_block[slot_i] = first_slot;
                                slot_i += 1;
                            }
                            // last slot
                            if (next_slots[1]) |last_slot| {
                                new_right_block[slot_i] = last_slot;
                            } else {
                                new_right_block[slot_i] = right_block.block[right_block.i];
                            }
                            next_blocks[1] = new_right_block;

                            next_shift += 1;
                        }

                        // clear the next slots
                        next_slots = .{ null, null };

                        const Side = enum { left, right };
                        const sides = [_]Side{ .left, .right };

                        // write the block(s)
                        try self.db.core.seekFromEnd(0);
                        for (&next_slots, next_blocks, orig_block_infos, sides) |*next_slot, block_maybe, orig_block_info, side| {
                            if (block_maybe) |block| {
                                // determine if the block changed compared to the original block
                                var eql = true;
                                for (block, orig_block_info.block) |block_slot, orig_slot| {
                                    if (!block_slot.slot.eql(orig_slot.slot)) {
                                        eql = false;
                                        break;
                                    }
                                }
                                // if there is no change, just use the original block
                                if (eql) {
                                    next_slot.* = orig_block_info.parent_slot;
                                }
                                // otherwise make a new block
                                else {
                                    const next_ptr = try self.db.core.getPos();
                                    var leaf_count: u64 = 0;
                                    for (block) |block_slot| {
                                        try core_writer.writeInt(LinkedArrayListSlotInt, @bitCast(block_slot), .big);
                                        if (is_leaf_node) {
                                            if (block_slot.slot.tag != .none) {
                                                leaf_count += 1;
                                            }
                                        } else {
                                            leaf_count += block_slot.size;
                                        }
                                    }
                                    next_slot.* = LinkedArrayListSlot{
                                        .slot = switch (side) {
                                            // only the left side needs to be set to full,
                                            // because it can have a gap that affects indexing
                                            .left => .{ .value = next_ptr, .tag = .index, .full = true },
                                            .right => .{ .value = next_ptr, .tag = .index },
                                        },
                                        .size = leaf_count,
                                    };
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
                    try self.db.core.seekFromEnd(0);
                    const new_array_list_start = try self.db.core.getPos();
                    try core_writer.writeInt(LinkedArrayListHeaderInt, @bitCast(LinkedArrayListHeader{
                        .shift = next_shift,
                        .ptr = root_slot.slot.value,
                        .size = size,
                    }), .big);

                    return .{
                        .slot_ptr = .{
                            .position = null,
                            .slot = .{ .value = new_array_list_start, .tag = .linked_array_list },
                        },
                        .db = self.db,
                    };
                }

                pub fn concat(self: Cursor(write_mode), other: Cursor(.read_only)) !Cursor(.read_only) {
                    if (self.slot_ptr.slot.tag != .linked_array_list) {
                        return error.UnexpectedTag;
                    }
                    if (other.slot_ptr.slot.tag != .linked_array_list) {
                        return error.UnexpectedTag;
                    }

                    const core_reader = self.db.core.reader();
                    const core_writer = self.db.core.writer();

                    // read the first list's blocks
                    try self.db.core.seekTo(self.slot_ptr.slot.value);
                    const header_a: LinkedArrayListHeader = @bitCast(try core_reader.readInt(LinkedArrayListHeaderInt, .big));
                    var blocks_a = std.ArrayList(LinkedArrayListBlockInfo).init(self.db.allocator);
                    defer blocks_a.deinit();
                    const key_a = if (header_a.size == 0) 0 else header_a.size - 1;
                    try self.db.readLinkedArrayListBlocks(header_a.ptr, key_a, header_a.shift, &blocks_a);

                    // read the second list's blocks
                    try self.db.core.seekTo(other.slot_ptr.slot.value);
                    const header_b: LinkedArrayListHeader = @bitCast(try core_reader.readInt(LinkedArrayListHeaderInt, .big));
                    var blocks_b = std.ArrayList(LinkedArrayListBlockInfo).init(self.db.allocator);
                    defer blocks_b.deinit();
                    try self.db.readLinkedArrayListBlocks(header_b.ptr, 0, header_b.shift, &blocks_b);

                    // stitch the blocks together
                    var next_slots = [_]?LinkedArrayListSlot{null} ** 2;
                    var next_shift: u6 = 0;
                    for (0..@max(blocks_a.items.len, blocks_b.items.len)) |i| {
                        const block_infos: [2]?LinkedArrayListBlockInfo = .{
                            if (i < blocks_a.items.len) blocks_a.items[blocks_a.items.len - 1 - i] else null,
                            if (i < blocks_b.items.len) blocks_b.items[blocks_b.items.len - 1 - i] else null,
                        };
                        var next_blocks: [2]?[SLOT_COUNT]LinkedArrayListSlot = .{ null, null };
                        const is_leaf_node = next_slots[0] == null;

                        if (!is_leaf_node) {
                            next_shift += 1;
                        }

                        for (block_infos, &next_blocks) |block_info_maybe, *next_block_maybe| {
                            if (block_info_maybe) |block_info| {
                                var block = [_]LinkedArrayListSlot{.{ .slot = .{}, .size = 0 }} ** SLOT_COUNT;
                                var target_i: usize = 0;
                                for (block_info.block, 0..) |block_slot, source_i| {
                                    // skip i'th block if necessary
                                    if (!is_leaf_node and block_info.i == source_i) {
                                        continue;
                                    }
                                    // break on first empty slot
                                    else if (block_slot.slot.tag == .none) {
                                        break;
                                    }
                                    block[target_i] = block_slot;
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
                            for (block) |block_slot| {
                                if (block_slot.slot.tag == .none) {
                                    break;
                                }
                                slots_to_write[slot_i] = block_slot;
                                slot_i += 1;
                            }
                        }

                        // add the center block
                        for (next_slots) |slot_maybe| {
                            if (slot_maybe) |block_slot| {
                                slots_to_write[slot_i] = block_slot;
                                slot_i += 1;
                            }
                        }

                        // add the right block
                        if (next_blocks[1]) |block| {
                            for (block) |block_slot| {
                                if (block_slot.slot.tag == .none) {
                                    break;
                                }
                                slots_to_write[slot_i] = block_slot;
                                slot_i += 1;
                            }
                        }

                        // clear the next slots
                        next_slots = .{ null, null };

                        // write the block(s)
                        try self.db.core.seekFromEnd(0);
                        for (&next_slots, 0..) |*next_slot, block_i| {
                            const start = block_i * SLOT_COUNT;
                            const block = slots_to_write[start .. start + SLOT_COUNT];

                            // this block is empty so don't bother writing it
                            if (block[0].slot.tag == .none) {
                                break;
                            }

                            // write the block
                            const next_ptr = try self.db.core.getPos();
                            var leaf_count: u64 = 0;
                            for (block) |block_slot| {
                                try core_writer.writeInt(LinkedArrayListSlotInt, @bitCast(block_slot), .big);
                                if (is_leaf_node) {
                                    if (block_slot.slot.tag != .none) {
                                        leaf_count += 1;
                                    }
                                } else {
                                    leaf_count += block_slot.size;
                                }
                            }

                            next_slot.* = LinkedArrayListSlot{ .slot = .{ .value = next_ptr, .tag = .index, .full = true }, .size = leaf_count };
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
                                const new_ptr = try self.db.core.getPos();
                                for (block) |block_slot| {
                                    try core_writer.writeInt(LinkedArrayListSlotInt, @bitCast(block_slot), .big);
                                }

                                next_shift += 1;

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
                    const list_start = try self.db.core.getPos();
                    try core_writer.writeInt(LinkedArrayListHeaderInt, @bitCast(LinkedArrayListHeader{
                        .shift = next_shift,
                        .ptr = root_ptr,
                        .size = header_a.size + header_b.size,
                    }), .big);

                    return .{
                        .slot_ptr = .{
                            .position = null,
                            .slot = .{ .value = list_start, .tag = .linked_array_list },
                        },
                        .db = self.db,
                    };
                }

                pub fn count(self: Cursor(write_mode)) !u64 {
                    const core_reader = self.db.core.reader();
                    switch (self.slot_ptr.slot.tag) {
                        .array_list => {
                            try self.db.core.seekTo(self.slot_ptr.slot.value);
                            const header: ArrayListHeader = @bitCast(try core_reader.readInt(ArrayListHeaderInt, .big));
                            return header.size;
                        },
                        .linked_array_list => {
                            try self.db.core.seekTo(self.slot_ptr.slot.value);
                            const header: LinkedArrayListHeader = @bitCast(try core_reader.readInt(LinkedArrayListHeaderInt, .big));
                            return header.size;
                        },
                        .bytes => {
                            try self.db.core.seekTo(self.slot_ptr.slot.value);
                            return try core_reader.readInt(u64, .big);
                        },
                        else => return error.UnexpectedTag,
                    }
                }

                pub const Iter = struct {
                    cursor: Cursor(write_mode),
                    core: struct {
                        size: u64,
                        index: u64,
                        stack: std.ArrayList(Level),
                    },

                    pub const Level = struct {
                        position: u64,
                        block: [SLOT_COUNT]Slot,
                        index: u8,
                    };

                    pub fn init(cursor: Cursor(write_mode)) !Iter {
                        return .{
                            .cursor = cursor,
                            .core = switch (cursor.slot_ptr.slot.tag) {
                                .array_list => blk: {
                                    const position = cursor.slot_ptr.slot.value;
                                    try cursor.db.core.seekTo(position);
                                    const core_reader = cursor.db.core.reader();
                                    const header: ArrayListHeader = @bitCast(try core_reader.readInt(ArrayListHeaderInt, .big));
                                    break :blk .{
                                        .size = try cursor.count(),
                                        .index = 0,
                                        .stack = try initStack(cursor, header.ptr, INDEX_BLOCK_SIZE),
                                    };
                                },
                                .linked_array_list => blk: {
                                    const position = cursor.slot_ptr.slot.value;
                                    try cursor.db.core.seekTo(position);
                                    const core_reader = cursor.db.core.reader();
                                    const header: LinkedArrayListHeader = @bitCast(try core_reader.readInt(LinkedArrayListHeaderInt, .big));
                                    break :blk .{
                                        .size = try cursor.count(),
                                        .index = 0,
                                        .stack = try initStack(cursor, header.ptr, LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE),
                                    };
                                },
                                .hash_map => .{
                                    .size = 0,
                                    .index = 0,
                                    .stack = try initStack(cursor, cursor.slot_ptr.slot.value, INDEX_BLOCK_SIZE),
                                },
                                else => return error.UnexpectedTag,
                            },
                        };
                    }

                    pub fn deinit(self: *Iter) void {
                        self.core.stack.deinit();
                    }

                    pub fn next(self: *Iter) !?Cursor(.read_only) {
                        switch (self.cursor.slot_ptr.slot.tag) {
                            .array_list => {
                                if (self.core.index == self.core.size) return null;
                                self.core.index += 1;
                                return try self.nextInternal(INDEX_BLOCK_SIZE);
                            },
                            .linked_array_list => {
                                if (self.core.index == self.core.size) return null;
                                self.core.index += 1;
                                return try self.nextInternal(LINKED_ARRAY_LIST_INDEX_BLOCK_SIZE);
                            },
                            .hash_map => return try self.nextInternal(INDEX_BLOCK_SIZE),
                            else => return error.UnexpectedTag,
                        }
                    }

                    fn initStack(cursor: Cursor(write_mode), position: u64, comptime block_size: u64) !std.ArrayList(Level) {
                        // find the block
                        try cursor.db.core.seekTo(position);
                        // read the block
                        const core_reader = cursor.db.core.reader();
                        var index_block_bytes = [_]u8{0} ** block_size;
                        try core_reader.readNoEof(&index_block_bytes);
                        // convert the block into slots
                        var index_block = [_]Slot{undefined} ** SLOT_COUNT;
                        {
                            var stream = std.io.fixedBufferStream(&index_block_bytes);
                            var block_reader = stream.reader();
                            for (&index_block) |*block_slot| {
                                block_slot.* = @bitCast(try block_reader.readInt(SlotInt, .big));
                                try block_slot.tag.validate();
                                // linked array list has larger slots so we need to skip over the rest
                                try block_reader.skipBytes((block_size / SLOT_COUNT) - byteSizeOf(Slot), .{});
                            }
                        }
                        // init the stack
                        var stack = std.ArrayList(Level).init(cursor.db.allocator);
                        try stack.append(.{
                            .position = position,
                            .block = index_block,
                            .index = 0,
                        });
                        return stack;
                    }

                    fn nextInternal(self: *Iter, comptime block_size: u64) !?Cursor(.read_only) {
                        while (self.core.stack.items.len > 0) {
                            const level = self.core.stack.items[self.core.stack.items.len - 1];
                            if (level.index == level.block.len) {
                                _ = self.core.stack.pop();
                                if (self.core.stack.items.len > 0) {
                                    self.core.stack.items[self.core.stack.items.len - 1].index += 1;
                                }
                                continue;
                            } else {
                                const next_slot = level.block[level.index];
                                if (next_slot.tag == .index) {
                                    // find the block
                                    const next_pos = next_slot.value;
                                    try self.cursor.db.core.seekTo(next_pos);
                                    // read the block
                                    const core_reader = self.cursor.db.core.reader();
                                    var index_block_bytes = [_]u8{0} ** block_size;
                                    try core_reader.readNoEof(&index_block_bytes);
                                    // convert the block into slots
                                    var index_block = [_]Slot{undefined} ** SLOT_COUNT;
                                    {
                                        var stream = std.io.fixedBufferStream(&index_block_bytes);
                                        var block_reader = stream.reader();
                                        for (&index_block) |*block_slot| {
                                            block_slot.* = @bitCast(try block_reader.readInt(SlotInt, .big));
                                            try block_slot.tag.validate();
                                            // linked array list has larger slots so we need to skip over the rest
                                            try block_reader.skipBytes((block_size / SLOT_COUNT) - byteSizeOf(Slot), .{});
                                        }
                                    }
                                    // append to the stack
                                    try self.core.stack.append(.{
                                        .position = next_pos,
                                        .block = index_block,
                                        .index = 0,
                                    });
                                    continue;
                                } else {
                                    self.core.stack.items[self.core.stack.items.len - 1].index += 1;
                                    // normally a slot that is .none should be skipped because it doesn't
                                    // have a value, but if it's set to full, then it is actually a valid
                                    // item that should be returned.
                                    if (next_slot.tag != .none or next_slot.full) {
                                        const position = level.position + (level.index * byteSizeOf(Slot));
                                        return .{
                                            .slot_ptr = .{ .position = position, .slot = next_slot },
                                            .db = self.cursor.db,
                                        };
                                    } else {
                                        continue;
                                    }
                                }
                            }
                        }
                        return null;
                    }
                };

                pub fn iterator(self: Cursor(write_mode)) !Iter {
                    return try Iter.init(self);
                }
            };
        }

        // high level API

        pub fn HashMap(comptime write_mode: WriteMode) type {
            return struct {
                cursor: Database(db_kind, Hash).Cursor(write_mode),

                pub fn init(cursor: Database(db_kind, Hash).Cursor(write_mode)) !HashMap(write_mode) {
                    return switch (write_mode) {
                        .read_only => .{
                            .cursor = .{
                                .slot_ptr = cursor.slot_ptr,
                                .db = cursor.db,
                            },
                        },
                        .read_write => .{
                            .cursor = try cursor.writePath(void, &.{.hash_map_init}),
                        },
                    };
                }

                pub fn get(self: HashMap(write_mode), hash: Hash) !?Cursor(.read_only) {
                    return try self.cursor.readPath(void, &.{
                        .{ .hash_map_get = .{ .value = hash } },
                    });
                }

                pub fn getSlot(self: HashMap(write_mode), hash: Hash) !?Slot {
                    return try self.cursor.readPathSlot(void, &.{
                        .{ .hash_map_get = .{ .value = hash } },
                    });
                }

                pub fn getKey(self: HashMap(write_mode), hash: Hash) !?Cursor(.read_only) {
                    return try self.cursor.readPath(void, &.{
                        .{ .hash_map_get = .{ .key = hash } },
                    });
                }

                pub fn put(self: HashMap(.read_write), hash: Hash) !Cursor(.read_write) {
                    return try self.cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hash } },
                    });
                }

                pub fn putData(self: HashMap(.read_write), hash: Hash, data: WriteableData) !void {
                    _ = try self.cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hash } },
                        .{ .write = data },
                    });
                }

                pub fn putKey(self: HashMap(.read_write), hash: Hash) !Cursor(.read_write) {
                    return try self.cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .key = hash } },
                    });
                }

                pub fn putKeyData(self: HashMap(.read_write), hash: Hash, data: WriteableData) !void {
                    _ = try self.cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .key = hash } },
                        .{ .write = data },
                    });
                }

                pub fn remove(self: HashMap(.read_write), hash: Hash) !void {
                    _ = try self.cursor.writePath(void, &.{
                        .{ .hash_map_remove = hash },
                    });
                }

                pub fn iterator(self: HashMap(write_mode)) !Cursor(write_mode).Iter {
                    return try self.cursor.iterator();
                }
            };
        }

        pub fn ArrayList(comptime write_mode: WriteMode) type {
            return struct {
                cursor: Database(db_kind, Hash).Cursor(write_mode),

                pub fn init(cursor: Database(db_kind, Hash).Cursor(write_mode)) !ArrayList(write_mode) {
                    return switch (write_mode) {
                        .read_only => .{
                            .cursor = .{
                                .slot_ptr = cursor.slot_ptr,
                                .db = cursor.db,
                            },
                        },
                        .read_write => .{
                            .cursor = try cursor.writePath(void, &.{.array_list_init}),
                        },
                    };
                }

                pub fn count(self: ArrayList(write_mode)) !u64 {
                    return try self.cursor.count();
                }

                pub fn get(self: ArrayList(write_mode), index: i65) !?Cursor(.read_only) {
                    return try self.cursor.readPath(void, &.{
                        .{ .array_list_get = .{ .index = index } },
                    });
                }

                pub fn getSlot(self: ArrayList(write_mode), index: i65) !?Slot {
                    return try self.cursor.readPathSlot(void, &.{
                        .{ .array_list_get = .{ .index = index } },
                    });
                }

                pub fn put(self: ArrayList(.read_write), index: i65) !Cursor(.read_write) {
                    return try self.cursor.writePath(void, &.{
                        .{ .array_list_get = .{ .index = index } },
                    });
                }

                pub fn putData(self: ArrayList(.read_write), index: i65, data: WriteableData) !void {
                    _ = try self.cursor.writePath(void, &.{
                        .{ .array_list_get = .{ .index = index } },
                        .{ .write = data },
                    });
                }

                pub fn append(self: ArrayList(.read_write)) !Cursor(.read_write) {
                    return try self.cursor.writePath(void, &.{
                        .{ .array_list_get = .append },
                    });
                }

                pub fn appendData(self: ArrayList(.read_write), data: WriteableData) !void {
                    _ = try self.cursor.writePath(void, &.{
                        .{ .array_list_get = .append },
                        .{ .write = data },
                    });
                }

                pub fn appendDataContext(self: ArrayList(.read_write), data: WriteableData, ctx: anytype) !void {
                    const Ctx = @TypeOf(ctx);
                    _ = try self.cursor.writePath(Ctx, &.{
                        .{ .array_list_get = .append },
                        .{ .write = data },
                        .{ .ctx = ctx },
                    });
                }

                pub fn iterator(self: ArrayList(write_mode)) !Cursor(write_mode).Iter {
                    return try self.cursor.iterator();
                }
            };
        }

        pub fn LinkedArrayList(comptime write_mode: WriteMode) type {
            return struct {
                cursor: Database(db_kind, Hash).Cursor(write_mode),

                pub fn init(cursor: Database(db_kind, Hash).Cursor(write_mode)) !LinkedArrayList(write_mode) {
                    return switch (write_mode) {
                        .read_only => .{
                            .cursor = .{
                                .slot_ptr = cursor.slot_ptr,
                                .db = cursor.db,
                            },
                        },
                        .read_write => .{
                            .cursor = try cursor.writePath(void, &.{.linked_array_list_init}),
                        },
                    };
                }

                pub fn count(self: LinkedArrayList(write_mode)) !u64 {
                    return try self.cursor.count();
                }

                pub fn get(self: LinkedArrayList(write_mode), index: i65) !?Cursor(.read_only) {
                    return try self.cursor.readPath(void, &.{
                        .{ .linked_array_list_get = .{ .index = index } },
                    });
                }

                pub fn getSlot(self: LinkedArrayList(write_mode), index: i65) !?Slot {
                    return try self.cursor.readPathSlot(void, &.{
                        .{ .linked_array_list_get = .{ .index = index } },
                    });
                }

                pub fn put(self: LinkedArrayList(.read_write), index: i65) !Cursor(.read_write) {
                    return try self.cursor.writePath(void, &.{
                        .{ .linked_array_list_get = .{ .index = index } },
                    });
                }

                pub fn putData(self: LinkedArrayList(.read_write), index: i65, data: WriteableData) !void {
                    _ = try self.cursor.writePath(void, &.{
                        .{ .linked_array_list_get = .{ .index = index } },
                        .{ .write = data },
                    });
                }

                pub fn append(self: LinkedArrayList(.read_write)) !Cursor(.read_write) {
                    return try self.cursor.writePath(void, &.{
                        .{ .linked_array_list_get = .append },
                    });
                }

                pub fn appendData(self: LinkedArrayList(.read_write), data: WriteableData) !void {
                    _ = try self.cursor.writePath(void, &.{
                        .{ .linked_array_list_get = .append },
                        .{ .write = data },
                    });
                }

                pub fn iterator(self: LinkedArrayList(write_mode)) !Cursor(write_mode).Iter {
                    return try self.cursor.iterator();
                }

                pub fn slice(self: LinkedArrayList(write_mode), offset: u64, size: u64) !Cursor(.read_only) {
                    return try self.cursor.slice(offset, size);
                }

                pub fn concat(self: LinkedArrayList(.read_write), other: Cursor(.read_only)) !Cursor(.read_only) {
                    return try self.cursor.concat(other);
                }
            };
        }
    };
}
