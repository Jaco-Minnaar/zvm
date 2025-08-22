const std = @import("std");
const flags = @import("flags");
const minisign = @import("minisign.zig");
const folders = @import("known_folders");
const json = std.json;
const log = std.log;

pub const std_options = std.Options{ .logFn = zvmLog };

var log_buf: [1024]u8 = undefined;
var stderr_writer = std.fs.File.stderr().writer(&log_buf);
const stderr = &stderr_writer.interface;

fn zvmLog(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = level;
    _ = scope;

    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();

    stderr.print(format ++ "\n", args) catch return;
    stderr.flush() catch return;
}

const VersionManager = @import("VersionManager.zig");

pub const known_folders_config = folders.KnownFolderConfig{};

const ZIG_PUBLIC_KEY = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U";

const Cli = struct {
    pub const description = "A Zig Version Manager";

    command: union(enum) {
        init: struct {},
        ls: struct {},
        install: struct {
            positional: struct {
                version: []const u8,
            },
        },
        use: struct {
            positional: struct {
                version: []const u8,
            },
        },
    },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);

    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const cli = flags.parse(args, "zvm", Cli, .{});

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var version_manager = VersionManager.init(allocator, &client);
    defer version_manager.deinit();

    switch (cli.command) {
        .init => {
            var env = try init_zvm_env(allocator);
            defer env.deinit();
        },
        .ls => try list_versions(allocator),
        .install => |i| try install(
            &version_manager,
            i.positional.version,
            &client,
            allocator,
        ),
        .use => |cmd| try use_version(
            &version_manager,
            cmd.positional.version,
            &client,
            allocator,
        ),
    }
}

fn use_version(
    version_manager: *VersionManager,
    version: []const u8,
    client: *std.http.Client,
    allocator: std.mem.Allocator,
) !void {
    var zvm_env = try init_zvm_env(allocator);
    defer zvm_env.deinit();

    var version_dir = zvm_env.versions.openDir(version, .{}) catch |err| err_sw: switch (err) {
        error.FileNotFound => {
            try install(version_manager, version, client, allocator);
            break :err_sw try zvm_env.versions.openDir(version, .{});
        },
        else => return err,
    };
    defer version_dir.close();

    log.info("Creating symlink...", .{});

    const symlink_target = try std.fmt.allocPrint(allocator, "../versions/{s}/zig", .{version});
    defer allocator.free(symlink_target);

    zvm_env.bin.symLink(symlink_target, "zig", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {
            try zvm_env.bin.deleteFile("zig");
            try zvm_env.bin.symLink(symlink_target, "zig", .{});
        },
        else => return err,
    };

    log.info("{s} is now the active Zig", .{version});
}

fn list_versions(allocator: std.mem.Allocator) !void {
    var zvm_env = try init_zvm_env(allocator);
    defer zvm_env.deinit();

    var version_count: u32 = 0;
    var iter = zvm_env.versions.iterate();
    while (try iter.next()) |entry| {
        log.info("    - {s}", .{entry.name});
        version_count += 1;
    }

    if (version_count == 0) {
        log.info("No versions currently installed.", .{});
    }
}

fn install(
    version_manager: *VersionManager,
    version: []const u8,
    client: *std.http.Client,
    allocator: std.mem.Allocator,
) !void {
    var zvm_env = try init_zvm_env(allocator);
    defer zvm_env.deinit();

    if (!std.mem.eql(u8, version, "master") and zvm_env.versions.access(version, .{}) != error.FileNotFound) {
        log.info("Version {s} already installed", .{version});
        return;
    }

    const zig_version = version_manager.getVersion(version) catch |err| switch (err) {
        error.NotFound => {
            log.info("Could not find version {s}.", .{version});
            return;
        },
        else => return err,
    };

    log.info("Found information for Zig version {s}", .{version});

    const platform = zig_version.platforms.get("x86_64-linux") orelse return error.PlatformNotFound;

    var slash_iter = std.mem.splitBackwardsScalar(u8, platform.tarball, '/');
    const file_name = slash_iter.next() orelse return error.CouldNotParseAddress;
    var dot_iter = std.mem.splitSequence(u8, file_name, ".tar");
    const dir_name = dot_iter.next() orelse return error.CouldNotParseAddress;

    log.info("Downloading {s}", .{dir_name});

    const size = try std.fmt.parseInt(usize, platform.size, 10);
    log.debug("expected size: {d}", .{size});

    const minisig = try download_minisig(platform.tarball, client, allocator);
    defer allocator.free(minisig);

    const progress = std.Progress.start(.{});
    const tarball = try download_tarball(platform.tarball, size, client, allocator, progress);
    defer allocator.free(tarball);

    if (size != tarball.len) {
        log.err("ERROR: Expected size: {d}, Actual size: {d}", .{ size, tarball.len });
        return error.CouldNotVerify;
    }

    try verify(tarball, minisig, allocator);

    var fixed_buf = std.io.fixedBufferStream(tarball);
    var decompress_stream = try std.compress.xz.decompress(allocator, fixed_buf.reader());
    defer decompress_stream.deinit();

    var decompress_buf: [4096]u8 = undefined;
    var adapter = decompress_stream.reader().adaptToNewApi(&decompress_buf);
    try std.tar.pipeToFileSystem(zvm_env.versions, &adapter.new_interface, .{});

    try zvm_env.versions.rename(dir_name, version);

    log.info("Version {s} installed", .{version});
}

const ZvmEnv = struct {
    zvm: std.fs.Dir,
    bin: std.fs.Dir,
    versions: std.fs.Dir,

    pub fn deinit(self: *ZvmEnv) void {
        self.zvm.close();
        self.bin.close();
        self.versions.close();
    }
};

fn init_zvm_env(allocator: std.mem.Allocator) !ZvmEnv {
    const home = if (try folders.open(allocator, .home, .{})) |dir| dir else return error.NoHome;
    const zvm = try open_make_dir(home, ".zvm", .{});
    const bin = try open_make_dir(zvm, "bin", .{});
    const versions = try open_make_dir(zvm, "versions", .{ .iterate = true });

    return .{
        .zvm = zvm,
        .bin = bin,
        .versions = versions,
    };
}

fn open_make_dir(dir: std.fs.Dir, sub_path: []const u8, options: std.fs.Dir.OpenOptions) !std.fs.Dir {
    return dir.openDir(sub_path, options) catch |err| switch (err) {
        error.FileNotFound => {
            try dir.makeDir(sub_path);
            return try dir.openDir(sub_path, options);
        },
        else => return err,
    };
}

fn verify(tarball: []const u8, minisig: []const u8, allocator: std.mem.Allocator) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const pk = try minisign.PublicKey.decodeFromBase64(ZIG_PUBLIC_KEY);
    const sig = try minisign.Signature.decode(arena.allocator(), minisig);

    try minisign.verify(arena.allocator(), &.{pk}, tarball, sig, null);
}

fn download_tarball(url: []const u8, init_size: usize, client: *std.http.Client, allocator: std.mem.Allocator, progress: std.Progress.Node) ![]const u8 {
    var response_buf = try std.ArrayList(u8).initCapacity(allocator, init_size);
    errdefer response_buf.deinit(allocator);

    log.info("Downloading tarball from {s}", .{url});

    var req = try client.request(.GET, try .parse(url), .{});
    defer req.deinit();

    try req.sendBodiless();
    var response = try req.receiveHead(&.{});

    if (response.head.status != .ok) {
        log.err("ERROR: Tarball request returned status {}", .{response.head.status});
        return error.DownloadError;
    }

    var reader_buffer: [4096]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    var decompress_buffer: [std.compress.flate.max_window_len]u8 = undefined;
    const body_reader = response.readerDecompressing(
        &reader_buffer,
        &decompress,
        &decompress_buffer,
    );

    const progress_node = progress.start("tarball download", init_size);

    var current_read: [1024]u8 = undefined;
    var bytes_read = try body_reader.readSliceShort(&current_read);
    while (bytes_read == current_read.len) : (bytes_read = try body_reader.readSliceShort(&current_read)) {
        try response_buf.appendSlice(allocator, current_read[0..bytes_read]);

        for (0..bytes_read) |_| progress_node.completeOne();
    }
    try response_buf.appendSlice(allocator, current_read[0..bytes_read]);
    for (0..bytes_read) |_| progress_node.completeOne();

    progress_node.end();

    return try response_buf.toOwnedSlice(allocator);
}

fn download_minisig(tarball_url: []const u8, client: *std.http.Client, allocator: std.mem.Allocator) ![]const u8 {
    const url = try std.fmt.allocPrint(allocator, "{s}.minisig", .{tarball_url});
    defer allocator.free(url);

    log.info("Downloading minisig from {s}", .{url});

    var req = try client.request(.GET, try .parse(url), .{});
    defer req.deinit();

    try req.sendBodiless();
    var response = try req.receiveHead(&.{});

    if (response.head.status != .ok) {
        log.err("ERROR: Minisig request returned status {}", .{response.head.status});
        return error.DownloadError;
    }

    const len = if (response.head.content_length) |l| l else return error.NoContentLength;

    var reader_buffer: [4096]u8 = undefined;
    const body_reader = response.reader(&reader_buffer);

    const response_buf = try body_reader.readAlloc(allocator, len);

    return response_buf;
}
