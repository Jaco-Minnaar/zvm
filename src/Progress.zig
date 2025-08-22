const std = @import("std");
const posix = std.posix;
const assert = std.debug.assert;

const Progress = @This();

terminal: std.fs.File,

terminal_mode: TerminalMode,

update_thread: ?std.Thread,
redraw_event: std.Thread.ResetEvent,

done: bool,
need_clear: bool,
status: Status,

refresh_rate_ns: u64,
initial_delay_ns: u64,

rows: u16,
cols: u16,

/// Accessed only by the update thread.
draw_buffer: []u8,

node_parents: []Node.Parent,
node_storage: []Node.Storage,
node_freelist_next: []Node.OptionalIndex,
node_freelist: Freelist,
node_end_index: usize,

pub const Status = enum {
    /// Indicates the application is progressing towards completion of a task.
    /// Unless the application is interactive, this is the only status the
    /// program will ever have!
    working,
    /// The application has completed an operation, and is now waiting for user
    /// input rather than calling exit(0).
    success,
    /// The application encountered an error, and is now waiting for user input
    /// rather than calling exit(1).
    failure,
    /// The application encountered at least one error, but is still working on
    /// more tasks.
    failure_working,
};

pub const TerminalMode = union(enum) {
    off,
    ansi_escape_codes,
};

const Freelist = packed struct(u32) {
    head: Node.OptionalIndex,
    /// Whenever `node_freelist` is added to, this generation is incremented
    /// to avoid ABA bugs when acquiring nodes. Wrapping arithmetic is used.
    generation: u24,
};

pub const Options = struct {
    /// User-provided buffer with static lifetime.
    ///
    /// Used to store the entire write buffer sent to the terminal. Progress output will be truncated if it
    /// cannot fit into this buffer which will look bad but not cause any malfunctions.
    ///
    /// Must be at least 200 bytes.
    draw_buffer: []u8 = &default_draw_buffer,
    /// How many nanoseconds between writing updates to the terminal.
    refresh_rate_ns: u64 = 80 * std.time.ns_per_ms,
    /// How many nanoseconds to keep the output hidden
    initial_delay_ns: u64 = 200 * std.time.ns_per_ms,
    /// If provided, causes the progress item to have a denominator.
    /// 0 means unknown.
    estimated_total_items: usize = 0,
    root_name: []const u8 = "",
    disable_printing: bool = false,
};

pub const Node = struct {
    index: OptionalIndex,
    pub const none: Node = .{ .index = .none };

    pub const max_name_len = 40;

    const Storage = struct {
        completed_count: usize,
        estimated_total_count: usize,
        name: [max_name_len]u8 align(@alignOf(usize)),
    };

    const Parent = enum(u8) {
        unused = std.math.maxInt(u8) - 1,
        none = std.math.maxInt(u8),
        _,

        fn unwrap(i: @This()) ?Index {
            return switch (i) {
                .unused, .none => return null,
                else => @enumFromInt(@intFromEnum(i)),
            };
        }
    };

    pub const OptionalIndex = enum(u8) {
        none = std.math.maxInt(u8),
        _,

        pub fn unwrap(i: @This()) ?Index {
            if (i == .none) return null;

            return @enumFromInt(@intFromEnum(i));
        }

        fn toParent(i: @This()) Parent {
            assert(@intFromEnum(i) != @intFromEnum(Parent.unused));

            return @enumFromInt(@intFromEnum(i));
        }
    };

    pub const Index = enum(u8) {
        _,

        fn toParent(i: @This()) Parent {
            assert(@intFromEnum(i) != @intFromEnum(Parent.unused));
            assert(@intFromEnum(i) != @intFromEnum(Parent.none));

            return @enumFromInt(@intFromEnum(i));
        }

        fn toOptional(i: @This()) OptionalIndex {
            return @enumFromInt(@intFromEnum(i));
        }
    };

    pub fn start(node: Node, name: []const u8, estimated_total_items: usize) Node {
        const node_index = node.index.unwrap() orelse return Node.none;

        const parent = node_index.toParent();
        const freelist = &global_progress.node_freelist;
        var old_freelist = @atomicLoad(Freelist, freelist, .acquire);
        while (old_freelist.head.unwrap()) |free_index| {
            const next_ptr = freelistNextByIndex(free_index);
            const new_freelist: Freelist = .{
                .head = @atomicLoad(Node.OptionalIndex, next_ptr, .monotonic),
                .generation = old_freelist.generation,
            };
            old_freelist = @cmpxchgStrong(
                Freelist,
                freelist,
                old_freelist,
                new_freelist,
                .acquire,
                .acquire,
            ) orelse {
                return init(free_index, parent, name, estimated_total_items);
            };
        }

        const free_index = @atomicRmw(usize, &global_progress.node_end_index, .Add, 1, .monotonic);
        if (free_index >= global_progress.node_storage.len) {
            _ = @atomicRmw(usize, &global_progress.node_end_index, .Sub, 1, .monotonic);
        }

        return init(@enumFromInt(free_index), parent, name, estimated_total_items);
    }

    pub fn completeOne(n: Node) void {
        const index = n.index.unwrap() orelse return;
        const storage = storageByIndex(index);
        _ = @atomicRmw(usize, &storage.completed_count, .Add, 1, .monotonic);
    }

    pub fn completeMany(n: Node, count: usize) void {
        const index = n.index.unwrap() orelse return;
        const storage = storageByIndex(index);
        _ = @atomicRmw(usize, &storage.completed_count, .Add, count, .monotonic);
    }

    pub fn end(n: Node) void {
        const index = n.index.unwrap() orelse return;
        const parent_ptr = parentByIndex(index);
        if (@atomicLoad(Node.Parent, parent_ptr, .monotonic).unwrap()) |parent_index| {
            _ = @atomicRmw(usize, &storageByIndex(parent_index).completed_count, .Add, 1, .monotonic);
            @atomicStore(Node.Parent, parent_ptr, .unused, .monotonic);

            const freelist = &global_progress.node_freelist;
            var old_freelist = @atomicLoad(Freelist, freelist, .monotonic);
            while (true) {
                @atomicStore(Node.OptionalIndex, freelistNextByIndex(index), old_freelist.head, .monotonic);
                old_freelist = @cmpxchgWeak(
                    Freelist,
                    freelist,
                    old_freelist,
                    .{ .head = index.toOptional(), .generation = old_freelist.generation +% 1 },
                    .release, // ensure a matching `start` sees the freelist link written above
                    .monotonic, // our write above is irrelevant if we need to retry
                ) orelse {
                    // We won the race.
                    return;
                };
            }
        } else {
            @atomicStore(bool, &global_progress.done, true, .monotonic);
            global_progress.redraw_event.set();
            if (global_progress.update_thread) |thread| thread.join();
        }
    }

    fn storageByIndex(index: Node.Index) *Node.Storage {
        return &global_progress.node_storage[@intFromEnum(index)];
    }

    fn parentByIndex(index: Node.Index) *Node.Parent {
        return &global_progress.node_parents[@intFromEnum(index)];
    }

    fn freelistNextByIndex(index: Node.Index) *Node.OptionalIndex {
        return &global_progress.node_freelist_next[@intFromEnum(index)];
    }

    fn init(free_index: Index, parent: Parent, name: []const u8, estimated_total_items: usize) Node {
        assert(parent == .none or @intFromEnum(parent) < node_storage_buffer_len);

        const storage = storageByIndex(free_index);
        @atomicStore(usize, &storage.completed_count, 0, .monotonic);
        @atomicStore(usize, &storage.estimated_total_count, estimated_total_items, .monotonic);
        const name_len = @min(max_name_len, name.len);
        copyAtomicStore(storage.name[0..name_len], name[0..name_len]);
        if (name_len < storage.name.len) {
            @atomicStore(u8, &storage.name[name_len], 0, .monotonic);
        }
        const parent_ptr = parentByIndex(free_index);
        if (std.debug.runtime_safety) {
            assert(@atomicLoad(Node.Parent, parent_ptr, .monotonic) == .unused);
        }

        @atomicStore(Node.Parent, parent_ptr, parent, .monotonic);

        return .{ .index = free_index.toOptional() };
    }
};

var global_progress: Progress = .{
    .node_parents = &node_parents_buffer,
    .node_storage = &node_storage_buffer,
    .node_freelist_next = &node_freelist_next_buffer,
    .node_freelist = .{ .head = .none, .generation = 0 },
    .node_end_index = 0,

    .terminal = undefined,
    .terminal_mode = .off,
    .need_clear = false,
    .status = .working,
    .rows = 0,
    .cols = 0,
    .draw_buffer = undefined,
    .done = false,
    .refresh_rate_ns = undefined,
    .initial_delay_ns = undefined,
    .update_thread = null,
    .redraw_event = .{},
};

const node_storage_buffer_len = 83;
var node_parents_buffer: [node_storage_buffer_len]Node.Parent = undefined;
var node_storage_buffer: [node_storage_buffer_len]Node.Storage = undefined;
var node_freelist_next_buffer: [node_storage_buffer_len]Node.OptionalIndex = undefined;

var default_draw_buffer: [4096]u8 = undefined;

var debug_start_trace = std.debug.Trace.init;

pub fn start(options: Options) Node {
    if (global_progress.node_end_index != 0) {
        debug_start_trace.dump();
        unreachable;
    }
    debug_start_trace.add("first initialized here");

    @memset(global_progress.node_parents, .unused);
    const root_node = Node.init(
        @enumFromInt(0),
        .none,
        options.root_name,
        options.estimated_total_items,
    );
    global_progress.done = false;
    global_progress.node_end_index = 1;

    assert(options.draw_buffer.len >= 200);
    global_progress.draw_buffer = options.draw_buffer;
    global_progress.refresh_rate_ns = options.refresh_rate_ns;
    global_progress.initial_delay_ns = options.initial_delay_ns;

    const stderr: std.fs.File = .stderr();
    global_progress.terminal = stderr;
    if (stderr.getOrEnableAnsiEscapeSupport()) {
        global_progress.terminal_mode = .ansi_escape_codes;
    }

    if (global_progress.terminal_mode == .off) {
        return Node.none;
    }

    const act: posix.Sigaction = .{
        .handler = .{ .sigaction = handleSigWinch },
        .mask = posix.sigemptyset(),
        .flags = (posix.SA.SIGINFO | posix.SA.RESTART),
    };

    posix.sigaction(posix.SIG.WINCH, &act, null);

    if (std.Thread.spawn(.{}, updateThreadRun, .{})) |thread| {
        global_progress.update_thread = thread;
    } else |err| {
        std.log.warn("Failed to start progress update thread: {s}", .{@errorName(err)});
        return Node.none;
    }

    return root_node;
}

fn wait(timeout_ns: u64) bool {
    const resize_flag = if (global_progress.redraw_event.timedWait(timeout_ns)) |_|
        true
    else |err| switch (err) {
        error.Timeout => false,
    };
    global_progress.redraw_event.reset();

    return resize_flag or (global_progress.cols == 0);
}

fn updateThreadRun() void {
    var serialized_buffer: Serialized.Buffer = undefined;

    {
        const resize_flag = wait(global_progress.initial_delay_ns);
        if (@atomicLoad(bool, &global_progress.done, .monotonic)) return;
        maybeUpdateSize(resize_flag);
        const buffer, _ = computeRedraw(&serialized_buffer);
        if (stderr_mutex.tryLock()) {
            defer stderr_mutex.unlock();
            write(buffer) catch return;
            global_progress.need_clear = true;
        }
    }

    while (true) {
        const resize_flag = wait(global_progress.refresh_rate_ns);

        if (@atomicLoad(bool, &global_progress.done, .monotonic)) {
            stderr_mutex.lock();
            defer stderr_mutex.unlock();
            return clearWrittenWithEscapeCodes() catch {};
        }

        maybeUpdateSize(resize_flag);

        const buffer, _ = computeRedraw(&serialized_buffer);
        if (stderr_mutex.tryLock()) {
            defer stderr_mutex.unlock();
            write(buffer) catch return;
            global_progress.need_clear = true;
        }
    }
}

fn handleSigWinch(sig: i32, info: *const posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) void {
    _ = info;
    _ = ctx_ptr;
    assert(sig == posix.SIG.WINCH);
    global_progress.redraw_event.set();
}

fn maybeUpdateSize(resize_flag: bool) void {
    if (!resize_flag) return;

    const fd = global_progress.terminal.handle;

    var winsize: posix.winsize = .{
        .row = 0,
        .col = 0,
        .xpixel = 0,
        .ypixel = 0,
    };

    const err = posix.system.ioctl(fd, posix.T.IOCGWINSZ, @intFromPtr(&winsize));
    if (posix.errno(err) == .SUCCESS) {
        global_progress.rows = winsize.row;
        global_progress.cols = winsize.col;
    } else {
        std.log.debug("failed to determine terminal size; using conservative guess 80x25", .{});
        global_progress.rows = 25;
        global_progress.cols = 80;
    }
}

fn computeRedraw(serialized_buffer: *Serialized.Buffer) struct { []u8, usize } {
    const serialized = serialize(serialized_buffer);

    // Now we can analyze our copy of the graph without atomics, reconstructing
    // children lists which do not exist in the canonical data. These are
    // needed for tree traversal below.

    var children_buffer: [node_storage_buffer_len]Children = undefined;
    const children = children_buffer[0..serialized.parents.len];

    @memset(children, .{ .child = .none, .sibling = .none });

    for (serialized.parents, 0..) |parent, child_index_usize| {
        const child_index: Node.Index = @enumFromInt(child_index_usize);
        assert(parent != .unused);
        const parent_index = parent.unwrap() orelse continue;
        const children_node = &children[@intFromEnum(parent_index)];
        if (children_node.child.unwrap()) |existing_child_index| {
            const existing_child = &children[@intFromEnum(existing_child_index)];
            children[@intFromEnum(child_index)].sibling = existing_child.sibling;
            existing_child.sibling = child_index.toOptional();
        } else {
            children_node.child = child_index.toOptional();
        }
    }

    // The strategy is, with every redraw:
    // erase to end of screen, write, move cursor to beginning of line, move cursor up N lines
    // This keeps the cursor at the beginning so that unlocked stderr writes
    // don't get eaten by the clear.

    var i: usize = 0;
    const buf = global_progress.draw_buffer;

    if (global_progress.terminal_mode == .ansi_escape_codes) {
        buf[i..][0..start_sync.len].* = start_sync.*;
        i += start_sync.len;
    }

    switch (global_progress.terminal_mode) {
        .off => unreachable,
        .ansi_escape_codes => {
            buf[i..][0..clear.len].* = clear.*;
            i += clear.len;
        },
    }

    const root_node_index: Node.Index = @enumFromInt(0);
    i, const nl_n = computeNode(buf, i, 0, serialized, children, root_node_index);

    if (global_progress.terminal_mode == .ansi_escape_codes) {
        {
            // Set progress state https://conemu.github.io/en/AnsiEscapeCodes.html#ConEmu_specific_OSC
            const root_storage = &serialized.storage[0];
            const storage = if (root_storage.name[0] != 0 or children[0].child == .none) root_storage else &serialized.storage[@intFromEnum(children[0].child)];
            const estimated_total = storage.estimated_total_count;
            const completed_items = storage.completed_count;
            const status = @atomicLoad(Status, &global_progress.status, .monotonic);
            switch (status) {
                .working => {
                    if (estimated_total == 0) {
                        buf[i..][0..progress_pulsing.len].* = progress_pulsing.*;
                        i += progress_pulsing.len;
                    } else {
                        const percent = completed_items * 100 / estimated_total;
                        i += (std.fmt.bufPrint(buf[i..], @"progress_normal {d}", .{percent}) catch &.{}).len;
                    }
                },
                .success => {
                    buf[i..][0..progress_remove.len].* = progress_remove.*;
                    i += progress_remove.len;
                },
                .failure => {
                    buf[i..][0..progress_error_100.len].* = progress_error_100.*;
                    i += progress_error_100.len;
                },
                .failure_working => {
                    if (estimated_total == 0) {
                        buf[i..][0..progress_pulsing_error.len].* = progress_pulsing_error.*;
                        i += progress_pulsing_error.len;
                    } else {
                        const percent = completed_items * 100 / estimated_total;
                        i += (std.fmt.bufPrint(buf[i..], @"progress_error {d}", .{percent}) catch &.{}).len;
                    }
                },
            }
        }

        if (nl_n > 0) {
            buf[i] = '\r';
            i += 1;
            for (0..nl_n) |_| {
                buf[i..][0..up_one_line.len].* = up_one_line.*;
                i += up_one_line.len;
            }
        }

        buf[i..][0..finish_sync.len].* = finish_sync.*;
        i += finish_sync.len;
    }

    return .{ buf[0..i], nl_n };
}

fn computePrefix(
    buf: []u8,
    start_i: usize,
    nl_n: usize,
    serialized: Serialized,
    children: []const Children,
    node_index: Node.Index,
) usize {
    var i = start_i;
    const parent_index = serialized.parents[@intFromEnum(node_index)].unwrap() orelse return i;
    if (serialized.parents[@intFromEnum(parent_index)] == .none) return i;
    if (@intFromEnum(serialized.parents[@intFromEnum(parent_index)]) == 0 and
        serialized.storage[0].name[0] == 0)
    {
        return i;
    }
    i = computePrefix(buf, i, nl_n, serialized, children, parent_index);
    if (children[@intFromEnum(parent_index)].sibling == .none) {
        const prefix = "   ";
        const upper_bound_len = prefix.len + lineUpperBoundLen(nl_n);
        if (i + upper_bound_len > buf.len) return buf.len;
        buf[i..][0..prefix.len].* = prefix.*;
        i += prefix.len;
    } else {
        const upper_bound_len = TreeSymbol.line.maxByteLen() + lineUpperBoundLen(nl_n);
        if (i + upper_bound_len > buf.len) return buf.len;
        i = appendTreeSymbol(.line, buf, i);
    }
    return i;
}

fn lineUpperBoundLen(nl_n: usize) usize {
    // \r\n on Windows, \n otherwise.
    const nl_len = 1;
    return @max(TreeSymbol.tee.maxByteLen(), TreeSymbol.langle.maxByteLen()) +
        "[4294967296/4294967296] ".len + Node.max_name_len + nl_len +
        (1 + (nl_n + 1) * up_one_line.len) +
        finish_sync.len;
}

fn computeNode(
    buf: []u8,
    start_i: usize,
    start_nl_n: usize,
    serialized: Serialized,
    children: []const Children,
    node_index: Node.Index,
) struct { usize, usize } {
    var i = start_i;
    var nl_n = start_nl_n;

    i = computePrefix(buf, i, nl_n, serialized, children, node_index);

    if (i + lineUpperBoundLen(nl_n) > buf.len)
        return .{ start_i, start_nl_n };

    const storage = &serialized.storage[@intFromEnum(node_index)];
    const estimated_total = storage.estimated_total_count;
    const completed_items = storage.completed_count;
    const name = if (std.mem.indexOfScalar(u8, &storage.name, 0)) |end| storage.name[0..end] else &storage.name;
    const parent = serialized.parents[@intFromEnum(node_index)];

    if (parent != .none) p: {
        if (@intFromEnum(parent) == 0 and serialized.storage[0].name[0] == 0) {
            break :p;
        }
        if (children[@intFromEnum(node_index)].sibling == .none) {
            i = appendTreeSymbol(.langle, buf, i);
        } else {
            i = appendTreeSymbol(.tee, buf, i);
        }
    }

    const is_empty_root = @intFromEnum(node_index) == 0 and serialized.storage[0].name[0] == 0;
    if (!is_empty_root) {
        if (name.len != 0 or estimated_total > 0) {
            if (name.len != 0) {
                i += (std.fmt.bufPrint(buf[i..], "{s}: ", .{name}) catch &.{}).len;
            }

            if (estimated_total > 0) {
                const fraction = @as(f32, @floatFromInt(completed_items)) / @as(f32, @floatFromInt(estimated_total));

                const percentage = fraction * 100.0;

                const size, const unit = if (completed_items < 1024 * 1024)
                    .{ @as(f32, @floatFromInt(completed_items)) / 1024, "KB" }
                else
                    .{ @as(f32, @floatFromInt(completed_items)) / (1024 * 1024), "MB" };

                i += (std.fmt.bufPrint(buf[i..], "{d:.2}% ({d:.2}{s}) [", .{ percentage, size, unit }) catch &.{}).len;

                const width = global_progress.cols / 3;
                const width_fraction: u16 = @intFromFloat(@as(f32, @floatFromInt(width)) * fraction);
                for (0..width) |pos| {
                    buf[i] = if (pos < width_fraction) '=' else ' ';
                    i += 1;
                }
                buf[i] = ']';
                i += 1;
            } else if (completed_items != 0) {
                i += (std.fmt.bufPrint(buf[i..], "[{d}] ", .{completed_items}) catch &.{}).len;
            }
        }

        i = @min(global_progress.cols + start_i, i);
        buf[i] = '\n';
        i += 1;
        nl_n += 1;
    }

    if (global_progress.withinRowLimit(nl_n)) {
        if (children[@intFromEnum(node_index)].child.unwrap()) |child| {
            i, nl_n = computeNode(buf, i, nl_n, serialized, children, child);
        }
    }

    if (global_progress.withinRowLimit(nl_n)) {
        if (children[@intFromEnum(node_index)].sibling.unwrap()) |sibling| {
            i, nl_n = computeNode(buf, i, nl_n, serialized, children, sibling);
        }
    }

    return .{ i, nl_n };
}

fn withinRowLimit(p: *Progress, nl_n: usize) bool {
    // The +2 here is so that the PS1 is not scrolled off the top of the terminal.
    // one because we keep the cursor on the next line
    // one more to account for the PS1
    return nl_n + 2 < p.rows;
}

fn clearWrittenWithEscapeCodes() anyerror!void {
    if (!global_progress.need_clear) return;

    global_progress.need_clear = false;
    try write(clear ++ progress_remove);
}

fn write(buf: []const u8) anyerror!void {
    try global_progress.terminal.writeAll(buf);
}

var remaining_write_trash_bytes: usize = 0;

const start_sync = "\x1b[?2026h";
const up_one_line = "\x1bM";
const clear = "\x1b[J";
const save = "\x1b7";
const restore = "\x1b8";
const finish_sync = "\x1b[?2026l";

const progress_remove = "\x1b]9;4;0\x07";
const @"progress_normal {d}" = "\x1b]9;4;1;{d}\x07";
const @"progress_error {d}" = "\x1b]9;4;2;{d}\x07";
const progress_pulsing = "\x1b]9;4;3\x07";
const progress_pulsing_error = "\x1b]9;4;2\x07";
const progress_normal_100 = "\x1b]9;4;1;100\x07";
const progress_error_100 = "\x1b]9;4;2;100\x07";

const TreeSymbol = enum {
    /// ├─
    tee,
    /// │
    line,
    /// └─
    langle,

    const Encoding = enum {
        ansi_escapes,
        code_page_437,
        utf8,
        ascii,
    };

    /// The escape sequence representation as a string literal
    fn escapeSeq(symbol: TreeSymbol) *const [9:0]u8 {
        return switch (symbol) {
            .tee => "\x1B\x28\x30\x74\x71\x1B\x28\x42 ",
            .line => "\x1B\x28\x30\x78\x1B\x28\x42  ",
            .langle => "\x1B\x28\x30\x6d\x71\x1B\x28\x42 ",
        };
    }

    fn bytes(symbol: TreeSymbol, encoding: Encoding) []const u8 {
        return switch (encoding) {
            .ansi_escapes => escapeSeq(symbol),
            .code_page_437 => switch (symbol) {
                .tee => "\xC3\xC4 ",
                .line => "\xB3  ",
                .langle => "\xC0\xC4 ",
            },
            .utf8 => switch (symbol) {
                .tee => "├─ ",
                .line => "│  ",
                .langle => "└─ ",
            },
            .ascii => switch (symbol) {
                .tee => "|- ",
                .line => "|  ",
                .langle => "+- ",
            },
        };
    }

    fn maxByteLen(symbol: TreeSymbol) usize {
        var max: usize = 0;
        inline for (@typeInfo(Encoding).@"enum".fields) |field| {
            const len = symbol.bytes(@field(Encoding, field.name)).len;
            max = @max(max, len);
        }
        return max;
    }
};

fn appendTreeSymbol(symbol: TreeSymbol, buf: []u8, start_i: usize) usize {
    switch (global_progress.terminal_mode) {
        .off => unreachable,
        .ansi_escape_codes => {
            const bytes = symbol.escapeSeq();
            buf[start_i..][0..bytes.len].* = bytes.*;
            return start_i + bytes.len;
        },
    }
}

const Children = struct {
    child: Node.OptionalIndex,
    sibling: Node.OptionalIndex,
};

const Serialized = struct {
    parents: []Node.Parent,
    storage: []Node.Storage,

    const Buffer = struct {
        parents: [node_storage_buffer_len]Node.Parent,
        storage: [node_storage_buffer_len]Node.Storage,
        map: [node_storage_buffer_len]Node.OptionalIndex,

        parents_copy: [node_storage_buffer_len]Node.Parent,
        storage_copy: [node_storage_buffer_len]Node.Storage,
    };
};

fn serialize(serialized_buffer: *Serialized.Buffer) Serialized {
    var serialized_len: usize = 0;

    // Iterate all of the nodes and construct a serializable copy of the state that can be examined
    // without atomics. The `@min` call is here because `node_end_index` might briefly exceed the
    // node count sometimes.
    const end_index = @min(@atomicLoad(usize, &global_progress.node_end_index, .monotonic), global_progress.node_storage.len);
    for (
        global_progress.node_parents[0..end_index],
        global_progress.node_storage[0..end_index],
        serialized_buffer.map[0..end_index],
    ) |*parent_ptr, *storage_ptr, *map| {
        const parent = @atomicLoad(Node.Parent, parent_ptr, .monotonic);
        if (parent == .unused) {
            // We might read "mixed" node data in this loop, due to weird atomic things
            // or just a node actually being freed while this loop runs. That could cause
            // there to be a parent reference to a nonexistent node. Without this assignment,
            // this would lead to the map entry containing stale data. By assigning none, the
            // child node with the bad parent pointer will be harmlessly omitted from the tree.
            //
            // Note that there's no concern of potentially creating "looping" data if we read
            // "mixed" node data like this, because if a node is (directly or indirectly) its own
            // parent, it will just not be printed at all. The general idea here is that performance
            // is more important than 100% correct output every frame, given that this API is likely
            // to be used in hot paths!
            map.* = .none;
            continue;
        }
        const dest_storage = &serialized_buffer.storage[serialized_len];
        copyAtomicLoad(&dest_storage.name, &storage_ptr.name);
        dest_storage.estimated_total_count = @atomicLoad(usize, &storage_ptr.estimated_total_count, .acquire); // sychronizes with release in `setIpcFd`
        dest_storage.completed_count = @atomicLoad(usize, &storage_ptr.completed_count, .monotonic);

        serialized_buffer.parents[serialized_len] = parent;
        map.* = @enumFromInt(serialized_len);
        serialized_len += 1;
    }

    // Remap parents to point inside serialized arrays.
    for (serialized_buffer.parents[0..serialized_len]) |*parent| {
        parent.* = switch (parent.*) {
            .unused => unreachable,
            .none => .none,
            _ => |p| serialized_buffer.map[@intFromEnum(p)].toParent(),
        };
    }

    return .{
        .parents = serialized_buffer.parents[0..serialized_len],
        .storage = serialized_buffer.storage[0..serialized_len],
    };
}

/// The primary motivation for recursive mutex here is so that a panic while
/// stderr mutex is held still dumps the stack trace and other debug
/// information.
var stderr_mutex = std.Thread.Mutex.Recursive.init;

fn copyAtomicStore(dest: []align(@alignOf(usize)) u8, src: []const u8) void {
    assert(dest.len == src.len);
    const chunked_len = dest.len / @sizeOf(usize);
    const dest_chunked: []usize = @as([*]usize, @ptrCast(dest))[0..chunked_len];
    const src_chunked: []align(1) const usize = @as([*]align(1) const usize, @ptrCast(src))[0..chunked_len];
    for (dest_chunked, src_chunked) |*d, s| {
        @atomicStore(usize, d, s, .monotonic);
    }
    const remainder_start = chunked_len * @sizeOf(usize);
    for (dest[remainder_start..], src[remainder_start..]) |*d, s| {
        @atomicStore(u8, d, s, .monotonic);
    }
}

fn copyAtomicLoad(
    dest: *align(@alignOf(usize)) [Node.max_name_len]u8,
    src: *align(@alignOf(usize)) const [Node.max_name_len]u8,
) void {
    const chunked_len = @divExact(dest.len, @sizeOf(usize));
    const dest_chunked: *[chunked_len]usize = @ptrCast(dest);
    const src_chunked: *const [chunked_len]usize = @ptrCast(src);
    for (dest_chunked, src_chunked) |*d, *s| {
        d.* = @atomicLoad(usize, s, .monotonic);
    }
}
