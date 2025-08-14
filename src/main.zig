const std = @import("std");
const flags = @import("flags");
const minisign = @import("minisign.zig");
const folders = @import("known_folders");
const json = std.json;

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

    std.debug.print("Creating symlink...\n", .{});

    const symlink_target = try std.fmt.allocPrint(allocator, "../versions/{s}/zig", .{version});
    defer allocator.free(symlink_target);

    zvm_env.bin.symLink(symlink_target, "zig", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {
            try zvm_env.bin.deleteFile("zig");
            try zvm_env.bin.symLink(symlink_target, "zig", .{});
        },
        else => return err,
    };
}

fn list_versions(allocator: std.mem.Allocator) !void {
    var zvm_env = try init_zvm_env(allocator);
    defer zvm_env.deinit();

    var version_count: u32 = 0;
    var iter = zvm_env.versions.iterate();
    while (try iter.next()) |entry| {
        std.debug.print("    - {s}\n", .{entry.name});
        version_count += 1;
    }

    if (version_count == 0) {
        std.debug.print("No versions currently installed.", .{});
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

    if (zvm_env.versions.access(version, .{}) != error.FileNotFound) {
        std.debug.print("Version {s} already installed\n", .{version});
        return;
    }

    const zig_version = version_manager.getVersion(version) catch |err| switch (err) {
        error.NotFound => {
            std.debug.print("Could not find version {s}.\n", .{version});
            return;
        },
        else => return err,
    };

    std.debug.print("Installing zig version {s}\n", .{version});

    const platform = zig_version.platforms.get("x86_64-linux") orelse return error.PlatformNotFound;

    var slash_iter = std.mem.splitBackwardsScalar(u8, platform.tarball, '/');
    const file_name = slash_iter.next() orelse return error.CouldNotParseAddress;
    var dot_iter = std.mem.splitSequence(u8, file_name, ".tar");
    const dir_name = dot_iter.next() orelse return error.CouldNotParseAddress;

    std.debug.print("Downloading {s}\n", .{dir_name});

    const size = try std.fmt.parseInt(usize, platform.size, 10);

    const tarball = try download_tarball(platform.tarball, size, client, allocator);
    defer allocator.free(tarball);

    const minisig = try download_minisig(platform.tarball, client, allocator);
    defer allocator.free(minisig);

    if (size != tarball.len) {
        std.debug.print("ERROR: Expected size: {d}, Actual size: {d}", .{ size, tarball.len });
        return error.CouldNotVerify;
    }

    try verify(tarball, minisig, allocator);

    var fixed_buf = std.io.fixedBufferStream(tarball);
    var decompress_stream = try std.compress.xz.decompress(allocator, fixed_buf.reader());
    defer decompress_stream.deinit();

    try std.tar.pipeToFileSystem(zvm_env.versions, decompress_stream.reader(), .{});

    try zvm_env.versions.rename(dir_name, version);

    std.debug.print("Version {s} installed\n", .{version});
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

fn download_tarball(url: []const u8, init_size: usize, client: *std.http.Client, allocator: std.mem.Allocator) ![]const u8 {
    var response_buf = try std.ArrayList(u8).initCapacity(allocator, init_size);
    errdefer response_buf.deinit();

    std.debug.print("Downloading tarball...\n", .{});
    const response = try client.fetch(.{
        .method = .GET,
        .location = .{ .url = url },
        .response_storage = .{ .dynamic = &response_buf },
        .max_append_size = 1024 * 1024 * 1024,
    });

    if (response.status != .ok) {
        std.debug.print("Tarball request return status {}", .{response.status});
        return error.DownloadError;
    }

    return try response_buf.toOwnedSlice();
}

fn download_minisig(tarball_url: []const u8, client: *std.http.Client, allocator: std.mem.Allocator) ![]const u8 {
    const url = try std.fmt.allocPrint(allocator, "{s}.minisig", .{tarball_url});
    defer allocator.free(url);

    var response_buf = std.ArrayList(u8).init(allocator);
    errdefer response_buf.deinit();

    std.debug.print("Downloading minisig...\n", .{});
    const response = try client.fetch(.{
        .method = .GET,
        .location = .{ .url = url },
        .response_storage = .{ .dynamic = &response_buf },
    });

    if (response.status != .ok) {
        std.debug.print("Minisig request return status {}", .{response.status});
        return error.DownloadError;
    }

    return try response_buf.toOwnedSlice();
}
