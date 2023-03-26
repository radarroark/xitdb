//! you're looking at radar's hopeless attempt to implement
//! his dream database. it will be embedded, immutable, and
//! reactive, and will be practical for both on-disk and
//! in-memory use. there is so much work to do, and so much
//! to learn. we're gonna leeroy jenkins our way through this.

const std = @import("std");

pub const Header = struct {
    padding: u64,
    key_size: u64,
    val_size: u64,
};

pub const Record = struct {
    const Self = @This();

    position: u64,
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
            .position = 0,
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
    try buffer.writer().print("{s}{s}{s}{s}{s}", .{
        std.mem.asBytes(&std.mem.nativeToBig(u64, record.header.padding)),
        std.mem.asBytes(&std.mem.nativeToBig(u64, record.header.key_size)),
        std.mem.asBytes(&std.mem.nativeToBig(u64, record.header.val_size)),
        record.key,
        record.val,
    });
}

/// deserializes the data. if the key or val isn't the encoded size,
/// an error will be returned.
fn deserializeRecord(allocator: std.mem.Allocator, reader: anytype) !Record {
    const header = Header{
        .padding = try reader.readIntBig(u64),
        .key_size = try reader.readIntBig(u64),
        .val_size = try reader.readIntBig(u64),
    };

    var record = try Record.init(allocator, header);
    errdefer record.deinit();

    const key_size = try reader.readAll(record.key);
    if (header.key_size != key_size) {
        return error.InvalidKey;
    }

    const val_size = try reader.readAll(record.val);
    if (header.val_size != val_size) {
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
        .padding = 0,
        .key_size = key.len,
        .val_size = val.len,
    };
    var record = try Record.init(allocator, header);
    std.mem.copy(u8, record.key, key);
    std.mem.copy(u8, record.val, val);
    defer record.deinit();

    // serialize the record
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try serializeRecord(record, &buffer);

    // deserialize the record
    var fis = std.io.fixedBufferStream(buffer.items);
    var record2 = try deserializeRecord(allocator, fis.reader());
    defer record2.deinit();

    // check that the records are equal
    try std.testing.expectEqual(record.header, record2.header);
    try std.testing.expectEqualStrings(key, record2.key);
    try std.testing.expectEqualStrings(val, record2.val);
}

pub const Database = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    key_pairs: std.StringHashMap(Record),
    db_file: std.fs.File,

    pub fn init(allocator: std.mem.Allocator, dir: std.fs.Dir, path: []const u8) !Database {
        // create or open file
        const file_or_err = dir.openFile(path, .{ .mode = .read_write });
        const file = try if (file_or_err == error.FileNotFound)
            dir.createFile(path, .{})
        else
            file_or_err;
        errdefer file.close();

        var db = Database{
            .allocator = allocator,
            .key_pairs = std.StringHashMap(Record).init(allocator),
            .db_file = file,
        };

        // read kv pairs
        const meta = try file.metadata();
        const size = meta.size();
        const reader = file.reader();
        while (true) {
            const pos = try reader.context.getPos();
            if (pos >= size) {
                break;
            }
            var record = try deserializeRecord(allocator, reader);
            record.position = pos;
            errdefer record.deinit();
            if (record.header.padding > 0) {
                try reader.skipBytes(record.header.padding, .{});
            }
            try db.put(record);
        }

        return db;
    }

    pub fn deinit(self: *Self) void {
        var iter = self.key_pairs.valueIterator();
        while (iter.next()) |value| {
            value.deinit();
        }
        self.key_pairs.deinit();
        self.db_file.close();
    }

    fn put(self: *Self, record: Record) !void {
        // if key exists, remove it
        var key_pair_maybe = self.key_pairs.fetchRemove(record.key);
        if (key_pair_maybe) |*key_pair| {
            key_pair.value.deinit();
        }
        try self.key_pairs.put(record.key, record);

        // if it's a tombstone record, immediately remove it
        if (record.header.val_size == 0) {
            var pair_maybe = self.key_pairs.fetchRemove(record.key);
            if (pair_maybe) |*key_pair| {
                key_pair.value.deinit();
            }
        }
    }

    pub fn add(self: *Self, record: Record) !void {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();
        try serializeRecord(record, &buffer);
        try self.db_file.seekFromEnd(0);
        try self.db_file.writeAll(buffer.items);
        try self.put(record);
    }

    pub fn remove(self: *Self, key: []const u8) !void {
        const header = Header{
            .padding = 0,
            .key_size = key.len,
            .val_size = 0,
        };
        var record = try Record.init(self.allocator, header);
        std.mem.copy(u8, record.key, key);
        try self.add(record);
    }
};

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

test "add records to a database" {
    const allocator = std.testing.allocator;
    const cwd = std.fs.cwd();
    const db_path = "main.db";
    defer cwd.deleteFile(db_path) catch {};

    // add a record
    {
        var record: Record = undefined;
        var db: Database = undefined;
        {
            const key = "foo";
            const val = "bar";
            const header = Header{
                .padding = 0,
                .key_size = key.len,
                .val_size = val.len,
            };
            record = try Record.init(allocator, header);
            std.mem.copy(u8, record.key, key);
            std.mem.copy(u8, record.val, val);
            errdefer record.deinit();
            db = try Database.init(allocator, cwd, db_path);
        }
        defer db.deinit();
        try db.add(record);
        try expectEqual(1, db.key_pairs.count());
    }

    // add another record
    {
        var record: Record = undefined;
        var db: Database = undefined;
        {
            const key = "hello";
            const val = "world";
            const header = Header{
                .padding = 0,
                .key_size = key.len,
                .val_size = val.len,
            };
            record = try Record.init(allocator, header);
            std.mem.copy(u8, record.key, key);
            std.mem.copy(u8, record.val, val);
            errdefer record.deinit();
            db = try Database.init(allocator, cwd, db_path);
        }
        defer db.deinit();
        try db.add(record);
        try expectEqual(2, db.key_pairs.count());
    }

    // replace a record
    {
        var record: Record = undefined;
        var db: Database = undefined;
        {
            const key = "foo";
            const val = "baz";
            const header = Header{
                .padding = 0,
                .key_size = key.len,
                .val_size = val.len,
            };
            record = try Record.init(allocator, header);
            std.mem.copy(u8, record.key, key);
            std.mem.copy(u8, record.val, val);
            errdefer record.deinit();
            db = try Database.init(allocator, cwd, db_path);
        }
        defer db.deinit();
        try db.add(record);
        try expectEqual(2, db.key_pairs.count());
    }

    // remove a record
    {
        var db = try Database.init(allocator, cwd, db_path);
        defer db.deinit();
        try db.remove("foo");
        try expectEqual(1, db.key_pairs.count());
    }

    // the record is still removed after init
    {
        var db = try Database.init(allocator, cwd, db_path);
        defer db.deinit();
        try expectEqual(1, db.key_pairs.count());
    }
}
