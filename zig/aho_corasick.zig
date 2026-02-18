// Aho-Corasick multi-pattern automaton for service probe pre-filtering.
//
// Builds an automaton from literal byte prefixes at init time, then scans a
// response buffer ONCE to find all matching pattern IDs — eliminating the
// per-pattern sequential scan done by probe_filter.zig.
//
// C ABI exports:
//   ac_create()      — allocate an empty automaton
//   ac_add_pattern() — add a byte pattern with an application-level ID
//   ac_build()       — finalize failure links (BFS)
//   ac_search()      — scan text, fill results array with matched IDs
//   ac_destroy()     — free all resources

const std = @import("std");

// ── Types ────────────────────────────────────────────────────────────────────

/// One output record hanging off a state.  Multiple patterns can end at the
/// same state (exact duplicates or one pattern being a suffix of another).
const Output = struct {
    pattern_id: u32,
    next: ?*Output, // singly-linked list
};

/// A single automaton state.
const State = struct {
    /// Goto function: indexed by byte value.
    /// INVALID_STATE means "no transition set yet" for non-root states.
    /// After build(), every entry is a valid state index (the table is complete).
    goto: [256]u32,
    /// Failure (fall-back) link — used during search.
    failure: u32,
    /// Linked list of pattern IDs whose pattern ends at this state.
    output: ?*Output,
};

const INVALID_STATE: u32 = std.math.maxInt(u32);
const ROOT: u32 = 0;

/// The automaton handle exposed to C callers as `void *`.
/// Uses std.array_list.Managed so the allocator is stored inside the list.
const Automaton = struct {
    allocator: std.mem.Allocator,
    // Zig 0.15: std.ArrayList(T) is the unmanaged variant; the allocator-
    // storing variant lives at std.array_list.Managed(T).
    states: std.array_list.Managed(State),
    built: bool,

    fn init(allocator: std.mem.Allocator) !*Automaton {
        const self = try allocator.create(Automaton);
        self.* = .{
            .allocator = allocator,
            .states = std.array_list.Managed(State).init(allocator),
            .built = false,
        };
        // Add root state (state 0).
        try self.states.append(makeRootState());
        return self;
    }

    fn deinit(self: *Automaton) void {
        // Free all Output nodes.
        for (self.states.items) |*s| {
            var out = s.output;
            while (out) |node| {
                const nxt = node.next;
                self.allocator.destroy(node);
                out = nxt;
            }
        }
        self.states.deinit();
        self.allocator.destroy(self);
    }

    /// Allocate a new non-root state and return its index.
    fn newState(self: *Automaton) !u32 {
        const idx: u32 = @intCast(self.states.items.len);
        try self.states.append(.{
            .goto = [_]u32{INVALID_STATE} ** 256,
            .failure = ROOT,
            .output = null,
        });
        return idx;
    }

    /// Insert one pattern into the trie (goto graph).
    fn addPattern(self: *Automaton, pattern: []const u8, pattern_id: u32) !void {
        var cur: u32 = ROOT;
        for (pattern) |byte| {
            const g = self.states.items[cur].goto[byte];
            if (g == INVALID_STATE) {
                const next = try self.newState();
                self.states.items[cur].goto[byte] = next;
                cur = next;
            } else {
                cur = g;
            }
        }
        // Append an Output node at the terminal state.
        const node = try self.allocator.create(Output);
        node.* = .{ .pattern_id = pattern_id, .next = self.states.items[cur].output };
        self.states.items[cur].output = node;
    }

    /// Build failure links and merge output lists via BFS (Aho-Corasick
    /// construction, textbook algorithm).
    fn build(self: *Automaton) !void {
        // Complete root's goto: every unset byte loops back to root.
        for (&self.states.items[ROOT].goto) |*g| {
            if (g.* == INVALID_STATE) g.* = ROOT;
        }

        // BFS queue — indices of states to process.
        var queue = std.array_list.Managed(u32).init(self.allocator);
        defer queue.deinit();

        // Enqueue direct children of root.
        for (0..256) |c| {
            const child = self.states.items[ROOT].goto[c];
            if (child != ROOT) {
                self.states.items[child].failure = ROOT;
                try queue.append(child);
            }
        }

        var head: usize = 0;
        while (head < queue.items.len) {
            const r = queue.items[head];
            head += 1;

            for (0..256) |c| {
                const s_ptr = self.states.items[r].goto[c];
                if (s_ptr == INVALID_STATE) {
                    // Redirect to what the failure ancestor does on this byte.
                    const fail = self.states.items[r].failure;
                    self.states.items[r].goto[c] = self.states.items[fail].goto[c];
                    continue;
                }
                // Real child — compute and store its failure link.
                try queue.append(s_ptr);

                var fail = self.states.items[r].failure;
                // Walk failure chain to find an ancestor with a goto on c.
                // Root is always safe: root.goto[c] was completed above.
                while (self.states.items[fail].goto[c] == INVALID_STATE) {
                    fail = self.states.items[fail].failure;
                }
                const fl = self.states.items[fail].goto[c];
                self.states.items[s_ptr].failure = if (fl == s_ptr) ROOT else fl;

                // Merge output from failure link into this state.
                var src_out = self.states.items[self.states.items[s_ptr].failure].output;
                while (src_out) |node| {
                    const merged = try self.allocator.create(Output);
                    merged.* = .{
                        .pattern_id = node.pattern_id,
                        .next = self.states.items[s_ptr].output,
                    };
                    self.states.items[s_ptr].output = merged;
                    src_out = node.next;
                }
            }
        }

        self.built = true;
    }

    /// Scan `text`, collect matching pattern IDs into `results[0..max]`.
    /// Returns the number of IDs written (capped at max_results).
    fn search(self: *const Automaton, text: []const u8, results: [*]u32, max_results: u32) u32 {
        var count: u32 = 0;
        var cur: u32 = ROOT;

        for (text) |byte| {
            cur = self.states.items[cur].goto[byte];
            var out = self.states.items[cur].output;
            while (out) |node| {
                if (count < max_results) {
                    results[count] = node.pattern_id;
                    count += 1;
                }
                out = node.next;
            }
        }
        return count;
    }
};

fn makeRootState() State {
    return .{
        .goto = [_]u32{INVALID_STATE} ** 256,
        .failure = ROOT,
        .output = null,
    };
}

// ── C ABI Exports ────────────────────────────────────────────────────────────

/// Create an empty automaton.  Returns NULL on allocation failure.
export fn ac_create() callconv(.c) ?*anyopaque {
    const allocator = std.heap.c_allocator;
    const ac = Automaton.init(allocator) catch return null;
    return @ptrCast(ac);
}

/// Add a pattern (raw bytes) with an application-supplied `pattern_id`.
/// Must be called before ac_build().
/// Returns 0 on success, -1 on error.
export fn ac_add_pattern(
    handle: ?*anyopaque,
    pattern_ptr: [*]const u8,
    pattern_len: usize,
    pattern_id: u32,
) callconv(.c) c_int {
    const ac: *Automaton = @ptrCast(@alignCast(handle orelse return -1));
    if (ac.built) return -1; // cannot add after build
    const pattern = pattern_ptr[0..pattern_len];
    ac.addPattern(pattern, pattern_id) catch return -1;
    return 0;
}

/// Finalize the automaton: build failure links and complete goto table.
/// Returns 0 on success, -1 on error.
export fn ac_build(handle: ?*anyopaque) callconv(.c) c_int {
    const ac: *Automaton = @ptrCast(@alignCast(handle orelse return -1));
    if (ac.built) return 0; // idempotent
    ac.build() catch return -1;
    return 0;
}

/// Scan `text_ptr[0..text_len]` for all added patterns.
/// Matching pattern IDs are written into `results_ptr[0..max_results]`.
/// Returns the number of IDs written.
/// Returns 0 if the automaton has not been built yet.
export fn ac_search(
    handle: ?*anyopaque,
    text_ptr: [*]const u8,
    text_len: usize,
    results_ptr: [*]u32,
    max_results: u32,
) callconv(.c) u32 {
    const ac: *Automaton = @ptrCast(@alignCast(handle orelse return 0));
    if (!ac.built) return 0;
    const text = text_ptr[0..text_len];
    return ac.search(text, results_ptr, max_results);
}

/// Free the automaton and all associated memory.
export fn ac_destroy(handle: ?*anyopaque) callconv(.c) void {
    const ac: *Automaton = @ptrCast(@alignCast(handle orelse return));
    ac.deinit();
}
