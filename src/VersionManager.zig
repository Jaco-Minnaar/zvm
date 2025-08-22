const std = @import("std");

const ZigVersion = struct {
    version: ?[]const u8 = null,
    date: ?[]const u8 = null,
    notes: ?[]const u8 = null,
    docs: ?[]const u8 = null,
    stdDocs: ?[]const u8 = null,
    platforms: std.StringHashMap(*const ZigSource),

    fn deinit(self: *ZigVersion, allocator: std.mem.Allocator) void {
        var iter = self.platforms.valueIterator();
        while (iter.next()) |value| {
            allocator.destroy(value.*);
        }
        self.platforms.deinit();
    }
};

const ZigSource = struct {
    tarball: []const u8,
    shasum: []const u8,
    size: []const u8,
};

const Self = @This();

versions: ?std.StringHashMap(*const ZigVersion) = null,
parsed: ?std.json.Parsed(std.json.ArrayHashMap(std.json.Value)) = null,
client: *std.http.Client,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, client: *std.http.Client) Self {
    return .{
        .client = client,
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    self.deinit_versions();
}

fn deinit_versions(self: *Self) void {
    if (self.versions) |*versions| {
        var iter = versions.iterator();
        while (iter.next()) |*entry| {
            @constCast(entry.value_ptr.*).deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        versions.deinit();
    }
    if (self.parsed) |*parsed| {
        parsed.deinit();
    }
}

pub fn getVersion(self: *Self, version: []const u8) !*const ZigVersion {
    if (self.versions == null) {
        try self.refreshVersions();
    }

    const versions = if (self.versions) |versions| &versions else unreachable;

    const found_version = versions.get(version) orelse return error.NotFound;

    return found_version;
}

pub fn printVersions(self: *Self) !void {
    if (self.versions == null) {
        try self.refreshVersions();
    }

    const versions = if (self.versions) |versions| &versions else unreachable;

    var iter = versions.iterator();
    while (iter.next()) |entry| {
        std.debug.print("{s}\n", .{entry.key_ptr.*});
    }
}

fn refreshVersions(self: *Self) !void {
    self.deinit_versions();

    var req = try self.client.request(.GET, try .parse("https://ziglang.org/download/index.json"), .{});
    defer req.deinit();

    try req.sendBodiless();
    var response = try req.receiveHead(&.{});

    if (response.head.status != .ok) {
        std.log.err("Request failed with code {}", .{response.head.status});
        return error.RequestFailed;
    }

    var reader_buffer: [1024]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    var decompress_buffer: [std.compress.flate.max_window_len]u8 = undefined;
    const body_reader = response.readerDecompressing(
        &reader_buffer,
        &decompress,
        &decompress_buffer,
    );

    var response_buf = std.ArrayList(u8).empty;
    defer response_buf.deinit(self.allocator);

    var current_read: [1024]u8 = undefined;
    var bytes_read = try body_reader.readSliceShort(&current_read);
    while (bytes_read == current_read.len) : (bytes_read = try body_reader.readSliceShort(&current_read)) {
        try response_buf.appendSlice(self.allocator, current_read[0..bytes_read]);
    }
    try response_buf.appendSlice(self.allocator, current_read[0..bytes_read]);

    const parsed = try std.json.parseFromSlice(
        std.json.ArrayHashMap(std.json.Value),
        self.allocator,
        response_buf.items,
        .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        },
    );

    var versions = std.StringHashMap(*const ZigVersion).init(self.allocator);
    var iter = parsed.value.map.iterator();
    while (iter.next()) |entry| {
        const version = try self.parseVersion(entry.value_ptr);
        try versions.put(entry.key_ptr.*, version);
    }

    self.versions = versions;
    self.parsed = parsed;
}

fn parseVersion(self: *Self, value: *std.json.Value) !*const ZigVersion {
    if (value.* != .object) return error.UnexpectedJsonValue;

    var zig_version = try self.allocator.create(ZigVersion);
    zig_version.date = null;
    zig_version.docs = null;
    zig_version.notes = null;
    zig_version.stdDocs = null;
    zig_version.version = null;
    zig_version.platforms = std.StringHashMap(*const ZigSource).init(self.allocator);

    var iter = value.object.iterator();
    while (iter.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, "date")) {
            if (entry.value_ptr.* != .string) return error.UnexpectedJsonValue;
            zig_version.date = entry.value_ptr.string;
        } else if (std.mem.eql(u8, entry.key_ptr.*, "docs")) {
            if (entry.value_ptr.* != .string) return error.UnexpectedJsonValue;
            zig_version.docs = entry.value_ptr.string;
        } else if (std.mem.eql(u8, entry.key_ptr.*, "notes")) {
            if (entry.value_ptr.* != .string) return error.UnexpectedJsonValue;
            zig_version.notes = entry.value_ptr.string;
        } else if (std.mem.eql(u8, entry.key_ptr.*, "stdDocs")) {
            if (entry.value_ptr.* != .string) return error.UnexpectedJsonValue;
            zig_version.stdDocs = entry.value_ptr.string;
        } else if (std.mem.eql(u8, entry.key_ptr.*, "version")) {
            if (entry.value_ptr.* != .string) return error.UnexpectedJsonValue;
            zig_version.version = entry.value_ptr.string;
        } else {
            const source = try self.parseSource(entry.value_ptr) orelse continue;
            try zig_version.platforms.put(entry.key_ptr.*, source);
        }
    }

    return zig_version;
}

fn parseSource(self: *Self, value: *std.json.Value) !?*const ZigSource {
    if (value.* != .object) return null;

    var zig_source = try self.allocator.create(ZigSource);

    var iter = value.object.iterator();
    while (iter.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, "tarball")) {
            if (entry.value_ptr.* != .string) return error.UnexpectedJsonValue;
            zig_source.tarball = entry.value_ptr.string;
        } else if (std.mem.eql(u8, entry.key_ptr.*, "shasum")) {
            if (entry.value_ptr.* != .string) return error.UnexpectedJsonValue;
            zig_source.shasum = entry.value_ptr.string;
        } else if (std.mem.eql(u8, entry.key_ptr.*, "size")) {
            if (entry.value_ptr.* != .string) return error.UnexpectedJsonValue;
            zig_source.size = entry.value_ptr.string;
        } else {
            continue;
        }
    }

    return zig_source;
}
