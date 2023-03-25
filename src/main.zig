//! you're looking at radar's hopeless attempt to implement
//! his dream database. it will be embedded, immutable, and
//! reactive, and will be practical for both on-disk and
//! in-memory use. there is so much work to do, and so much
//! to learn. we're gonna leeroy jenkins our way through this.

const std = @import("std");

pub const Header = struct {
    checksum: u32,
    timestamp: u32,
    expiry: u32,
    key_size: u32,
    val_size: u32,
};

pub const Record = struct {
    const Self = @This();

    header: Header,
    key: []u8,
    val: []u8,

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, header: Header) !Record {
        const key = try allocator.alloc(u8, header.key_size);
        errdefer allocator.free(key);

        const val = try allocator.alloc(u8, header.val_size);
        errdefer allocator.free(val);

        return Record{
            .header = header,
            .key = key,
            .val = val,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.key);
        self.allocator.free(self.val);
    }
};

pub const DeserializeError = error{
    InvalidKey,
    InvalidVal,
};

/// serializes the data in big endian format. why big endian?
/// mostly because it's common for on-disk and over-the-wire
/// formats. i might change my mind later though.
fn serializeRecord(record: Record, buffer: *std.ArrayList(u8)) !void {
    try buffer.writer().print("{s}{s}{s}{s}{s}{s}{s}", .{
        std.mem.asBytes(&std.mem.nativeToBig(u32, record.header.checksum)),
        std.mem.asBytes(&std.mem.nativeToBig(u32, record.header.timestamp)),
        std.mem.asBytes(&std.mem.nativeToBig(u32, record.header.expiry)),
        std.mem.asBytes(&std.mem.nativeToBig(u32, record.header.key_size)),
        std.mem.asBytes(&std.mem.nativeToBig(u32, record.header.val_size)),
        record.key,
        record.val,
    });
}

/// deserializes the data. if the key or val isn't the encoded size,
/// an error will be returned.
fn deserializeRecord(allocator: std.mem.Allocator, buffer: std.ArrayList(u8)) !Record {
    var fis = std.io.fixedBufferStream(buffer.items);
    const reader = fis.reader();

    const header = Header{
        .checksum = try reader.readIntBig(u32),
        .timestamp = try reader.readIntBig(u32),
        .expiry = try reader.readIntBig(u32),
        .key_size = try reader.readIntBig(u32),
        .val_size = try reader.readIntBig(u32),
    };

    var record = try Record.init(allocator, header);
    errdefer record.deinit();

    const key_size = try reader.readAll(record.key);
    if (header.key_size != @intCast(u32, key_size)) {
        return error.InvalidKey;
    }

    const val_size = try reader.readAll(record.val);
    if (header.val_size != @intCast(u32, val_size)) {
        return error.InvalidVal;
    }

    return record;
}

test "serialize and deserialize record" {
    const allocator = std.testing.allocator;

    // create the record
    const key = "foo";
    const val = "bar";
    const header = Header{
        .checksum = 0,
        .timestamp = 0,
        .expiry = 0,
        .key_size = key.len,
        .val_size = val.len,
    };
    var record = try Record.init(allocator, header);
    std.mem.copy(u8, record.key, key);
    std.mem.copy(u8, record.val, val);
    defer record.deinit();

    // serialize the record
    var entry_buffer = std.ArrayList(u8).init(allocator);
    defer entry_buffer.deinit();
    try serializeRecord(record, &entry_buffer);

    // deserialize the record
    var record2 = try deserializeRecord(allocator, entry_buffer);
    defer record2.deinit();

    // check that the records are equal
    try std.testing.expectEqual(record.header, record2.header);
    try std.testing.expectEqualStrings(key, record2.key);
    try std.testing.expectEqualStrings(val, record2.val);
}

pub const Meta = struct {
    timestamp: u32,
    record_size: u32,
    record_pos: u32,
};

pub const Database = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    key_pairs: std.StringHashMap(Meta),
    db_file: std.fs.File,

    pub fn init(allocator: std.mem.Allocator, dir: std.fs.Dir, path: []const u8) !Database {
        const file_or_err = dir.openFile(path, .{ .mode = .read_write });
        const file = try if (file_or_err == error.FileNotFound)
            dir.createFile(path, .{})
        else
            file_or_err;
        errdefer file.close();

        return Database{
            .allocator = allocator,
            .key_pairs = std.StringHashMap(Meta).init(allocator),
            .db_file = file,
        };
    }

    pub fn deinit(self: *Self) void {
        self.key_pairs.deinit();
        self.db_file.close();
    }

    pub fn appendRecord(self: *Self, record: Record) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        try serializeRecord(record, &buffer);
        try self.db_file.seekFromEnd(0);
        try self.db_file.writeAll(buffer.items);
    }
};

test "write record to disk and read record from disk" {
    const allocator = std.testing.allocator;
    const cwd = std.fs.cwd();
    const db_path = "main.db";
    defer cwd.deleteFile(db_path) catch {};

    // write record to file
    {
        const key = "foo";
        const val = "bar";
        const header = Header{
            .checksum = 0,
            .timestamp = 0,
            .expiry = 0,
            .key_size = key.len,
            .val_size = val.len,
        };
        var record = try Record.init(allocator, header);
        std.mem.copy(u8, record.key, key);
        std.mem.copy(u8, record.val, val);
        defer record.deinit();

        var db = try Database.init(allocator, cwd, db_path);
        defer db.deinit();
        try db.appendRecord(record);
    }

    // write record to file
    {
        const key = "foo";
        const val = "baz";
        const header = Header{
            .checksum = 0,
            .timestamp = 0,
            .expiry = 0,
            .key_size = key.len,
            .val_size = val.len,
        };
        var record = try Record.init(allocator, header);
        std.mem.copy(u8, record.key, key);
        std.mem.copy(u8, record.val, val);
        defer record.deinit();

        var db = try Database.init(allocator, cwd, db_path);
        defer db.deinit();
        try db.appendRecord(record);
    }
}
