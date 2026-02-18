// Aho-Corasick multi-pattern automaton for service probe pre-filtering.
//
// Builds an automaton from literal byte prefixes at init time, then scans a
// response buffer ONCE to find all matching pattern IDs — eliminating the
// per-pattern sequential scan done by probe_filter.zig.
//
// Memory optimization: uses a hybrid dense/sparse goto representation.
// Root state uses a dense [256]u32 table for O(1) lookup on every input byte.
// Interior states use sorted (byte, state) pairs with binary search, since
// most transitions fall back to root. States with >128 non-root transitions
// keep the dense representation.
//
// C ABI exports:
//   ac_create()      — allocate an empty automaton
//   ac_add_pattern() — add a byte pattern with an application-level ID
//   ac_build()       — finalize failure links (BFS) and sparsify goto tables
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

/// A (byte, state) pair for sparse goto tables.
const Pair = packed struct {
    byte: u8,
    state: u32,
};

/// Threshold: if a state has more than this many non-root transitions after
/// build(), keep it dense rather than converting to sparse.
const SPARSE_THRESHOLD: u16 = 128;

/// Tagged union for goto tables: dense [256]u32 or sparse sorted pairs.
const GotoTable = union(enum) {
    dense: *[256]u32,
    sparse: SparseGoto,
};

/// Sparse goto: sorted pairs of (byte -> state) for transitions that don't
/// go to root. During search, if a byte is not found, the implicit default
/// destination is ROOT (state 0).
const SparseGoto = struct {
    pairs: [*]Pair,
    count: u16,
};

/// A single automaton state. During construction, uses a temporary dense
/// goto table. After build(), the goto table is replaced with the optimal
/// representation (dense for root/high-fanout states, sparse otherwise).
const FinalState = struct {
    goto_table: GotoTable,
    failure: u32,
    output: ?*Output,
};

/// Temporary state used during construction (before build/sparsify).
/// Uses the dense [256]u32 table for easy manipulation.
const BuildState = struct {
    goto: [256]u32,
    failure: u32,
    output: ?*Output,
};

const INVALID_STATE: u32 = std.math.maxInt(u32);
const ROOT: u32 = 0;

/// The automaton handle exposed to C callers as `void *`.
const Automaton = struct {
    allocator: std.mem.Allocator,
    /// Build-phase states (dense goto). Freed after sparsify.
    build_states: ?std.array_list.Managed(BuildState),
    /// Final states (hybrid dense/sparse goto). Populated by sparsify.
    final_states: ?[]FinalState,
    built: bool,

    fn init(allocator: std.mem.Allocator) !*Automaton {
        const self = try allocator.create(Automaton);
        self.* = .{
            .allocator = allocator,
            .build_states = std.array_list.Managed(BuildState).init(allocator),
            .final_states = null,
            .built = false,
        };
        // Add root state (state 0).
        try self.build_states.?.append(makeRootBuildState());
        return self;
    }

    fn deinit(self: *Automaton) void {
        // Free all Output nodes and goto tables from final states.
        if (self.final_states) |fs| {
            for (fs) |*s| {
                // Free output chain.
                var out = s.output;
                while (out) |node| {
                    const nxt = node.next;
                    self.allocator.destroy(node);
                    out = nxt;
                }
                // Free goto table storage.
                switch (s.goto_table) {
                    .dense => |dense| self.allocator.destroy(dense),
                    .sparse => |sparse| {
                        if (sparse.count > 0) {
                            self.allocator.free(sparse.pairs[0..sparse.count]);
                        }
                    },
                }
            }
            self.allocator.free(fs);
        }
        // Free build states if still present (not yet sparsified).
        if (self.build_states) |*bs| {
            for (bs.items) |*s| {
                var out = s.output;
                while (out) |node| {
                    const nxt = node.next;
                    self.allocator.destroy(node);
                    out = nxt;
                }
            }
            bs.deinit();
        }
        self.allocator.destroy(self);
    }

    /// Allocate a new non-root build state and return its index.
    fn newState(self: *Automaton) !u32 {
        const bs = &self.build_states.?;
        const idx: u32 = @intCast(bs.items.len);
        try bs.append(.{
            .goto = [_]u32{INVALID_STATE} ** 256,
            .failure = ROOT,
            .output = null,
        });
        return idx;
    }

    /// Insert one pattern into the trie (goto graph).
    fn addPattern(self: *Automaton, pattern: []const u8, pattern_id: u32) !void {
        var bs = &self.build_states.?;
        var cur: u32 = ROOT;
        for (pattern) |byte| {
            const g = bs.items[cur].goto[byte];
            if (g == INVALID_STATE) {
                const next = try self.newState();
                // Re-fetch pointer since newState may have reallocated.
                bs = &self.build_states.?;
                bs.items[cur].goto[byte] = next;
                cur = next;
            } else {
                cur = g;
            }
        }
        // Append an Output node at the terminal state.
        const node = try self.allocator.create(Output);
        node.* = .{ .pattern_id = pattern_id, .next = bs.items[cur].output };
        bs.items[cur].output = node;
    }

    /// Build failure links and merge output lists via BFS (Aho-Corasick
    /// construction, textbook algorithm), then sparsify goto tables.
    fn build(self: *Automaton) !void {
        var bs = &self.build_states.?;

        // Complete root's goto: every unset byte loops back to root.
        for (&bs.items[ROOT].goto) |*g| {
            if (g.* == INVALID_STATE) g.* = ROOT;
        }

        // BFS queue — indices of states to process.
        var queue = std.array_list.Managed(u32).init(self.allocator);
        defer queue.deinit();

        // Enqueue direct children of root.
        for (0..256) |c| {
            const child = bs.items[ROOT].goto[c];
            if (child != ROOT) {
                bs.items[child].failure = ROOT;
                try queue.append(child);
            }
        }

        var head: usize = 0;
        while (head < queue.items.len) {
            const r = queue.items[head];
            head += 1;

            for (0..256) |c| {
                const s_ptr = bs.items[r].goto[c];
                if (s_ptr == INVALID_STATE) {
                    // Redirect to what the failure ancestor does on this byte.
                    const fail = bs.items[r].failure;
                    bs.items[r].goto[c] = bs.items[fail].goto[c];
                    continue;
                }
                // Real child — compute and store its failure link.
                try queue.append(s_ptr);

                var fail = bs.items[r].failure;
                // Walk failure chain to find an ancestor with a goto on c.
                // Root is always safe: root.goto[c] was completed above.
                while (bs.items[fail].goto[c] == INVALID_STATE) {
                    fail = bs.items[fail].failure;
                }
                const fl = bs.items[fail].goto[c];
                bs.items[s_ptr].failure = if (fl == s_ptr) ROOT else fl;

                // Merge output from failure link into this state.
                var src_out = bs.items[bs.items[s_ptr].failure].output;
                while (src_out) |node| {
                    const merged = try self.allocator.create(Output);
                    merged.* = .{
                        .pattern_id = node.pattern_id,
                        .next = bs.items[s_ptr].output,
                    };
                    bs.items[s_ptr].output = merged;
                    src_out = node.next;
                }
            }
        }

        // Sparsify goto tables.
        try self.sparsify();
        self.built = true;
    }

    /// Convert build states to final states with hybrid dense/sparse goto.
    fn sparsify(self: *Automaton) !void {
        const bs = &self.build_states.?;
        const n = bs.items.len;

        const final = try self.allocator.alloc(FinalState, n);
        errdefer self.allocator.free(final);

        for (0..n) |i| {
            const src = &bs.items[i];
            final[i].failure = src.failure;
            final[i].output = src.output;
            // Clear output from build state so deinit doesn't double-free.
            src.output = null;

            if (i == ROOT) {
                // Root always gets a dense table.
                const dense = try self.allocator.create([256]u32);
                dense.* = src.goto;
                final[i].goto_table = .{ .dense = dense };
                continue;
            }

            // Count non-root transitions.
            var non_root_count: u16 = 0;
            for (src.goto) |dest| {
                if (dest != ROOT) non_root_count += 1;
            }

            if (non_root_count > SPARSE_THRESHOLD) {
                // High-fanout state: keep dense.
                const dense = try self.allocator.create([256]u32);
                dense.* = src.goto;
                final[i].goto_table = .{ .dense = dense };
            } else {
                // Sparse: allocate only non-root pairs, sorted by byte.
                if (non_root_count == 0) {
                    final[i].goto_table = .{ .sparse = .{
                        .pairs = undefined,
                        .count = 0,
                    } };
                } else {
                    const pairs = try self.allocator.alloc(Pair, non_root_count);
                    var idx: u16 = 0;
                    for (0..256) |c| {
                        const dest = src.goto[c];
                        if (dest != ROOT) {
                            pairs[idx] = .{ .byte = @intCast(c), .state = dest };
                            idx += 1;
                        }
                    }
                    // pairs are already sorted by byte since we iterate 0..255.
                    final[i].goto_table = .{ .sparse = .{
                        .pairs = pairs.ptr,
                        .count = non_root_count,
                    } };
                }
            }
        }

        self.final_states = final;
        // Free build states (output nodes already moved).
        bs.deinit();
        self.build_states = null;
    }

    /// Look up a byte in a goto table. Returns the destination state.
    inline fn gotoLookup(table: GotoTable, byte: u8) u32 {
        return switch (table) {
            .dense => |dense| dense[byte],
            .sparse => |sparse| blk: {
                // Binary search in sorted pairs.
                if (sparse.count == 0) break :blk ROOT;
                const pairs = sparse.pairs[0..sparse.count];
                var lo: u16 = 0;
                var hi: u16 = sparse.count;
                while (lo < hi) {
                    const mid = lo + (hi - lo) / 2;
                    if (pairs[mid].byte < byte) {
                        lo = mid + 1;
                    } else if (pairs[mid].byte > byte) {
                        hi = mid;
                    } else {
                        break :blk pairs[mid].state;
                    }
                }
                break :blk ROOT;
            },
        };
    }

    /// Scan `text`, collect matching pattern IDs into `results[0..max]`.
    /// Returns the number of IDs written (capped at max_results).
    fn search(self: *const Automaton, text: []const u8, results: [*]u32, max_results: u32) u32 {
        const fs = self.final_states orelse return 0;
        var count: u32 = 0;
        var cur: u32 = ROOT;

        for (text) |byte| {
            cur = gotoLookup(fs[cur].goto_table, byte);
            var out = fs[cur].output;
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

fn makeRootBuildState() BuildState {
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

// ── Tests ────────────────────────────────────────────────────────────────────

test "basic single pattern" {
    const allocator = std.testing.allocator;
    const ac = try Automaton.init(allocator);
    defer ac.deinit();

    try ac.addPattern("hello", 42);
    try ac.build();

    var results: [16]u32 = undefined;
    const n = ac.search("say hello world", &results, 16);
    try std.testing.expectEqual(@as(u32, 1), n);
    try std.testing.expectEqual(@as(u32, 42), results[0]);
}

test "multiple patterns" {
    const allocator = std.testing.allocator;
    const ac = try Automaton.init(allocator);
    defer ac.deinit();

    try ac.addPattern("he", 1);
    try ac.addPattern("she", 2);
    try ac.addPattern("his", 3);
    try ac.addPattern("hers", 4);

    try ac.build();

    var results: [16]u32 = undefined;
    const n = ac.search("shers", &results, 16);

    // "shers" should match: "she" at pos 0-2, "he" at pos 1-2, "hers" at pos 1-4
    try std.testing.expectEqual(@as(u32, 3), n);

    // Collect matched IDs into a set for order-independent checking.
    var found = [_]bool{false} ** 5;
    for (results[0..n]) |id| {
        found[id] = true;
    }
    try std.testing.expect(found[1]); // "he"
    try std.testing.expect(found[2]); // "she"
    try std.testing.expect(found[4]); // "hers"
}

test "no match returns zero" {
    const allocator = std.testing.allocator;
    const ac = try Automaton.init(allocator);
    defer ac.deinit();

    try ac.addPattern("xyz", 99);
    try ac.build();

    var results: [16]u32 = undefined;
    const n = ac.search("hello world", &results, 16);
    try std.testing.expectEqual(@as(u32, 0), n);
}

test "overlapping patterns" {
    const allocator = std.testing.allocator;
    const ac = try Automaton.init(allocator);
    defer ac.deinit();

    try ac.addPattern("a", 1);
    try ac.addPattern("ab", 2);
    try ac.addPattern("abc", 3);

    try ac.build();

    var results: [16]u32 = undefined;
    const n = ac.search("abc", &results, 16);
    try std.testing.expectEqual(@as(u32, 3), n);
}

test "C ABI round-trip" {
    const handle = ac_create();
    try std.testing.expect(handle != null);

    const pat = "test";
    try std.testing.expectEqual(@as(c_int, 0), ac_add_pattern(handle, pat.ptr, pat.len, 7));
    try std.testing.expectEqual(@as(c_int, 0), ac_build(handle));

    var results: [4]u32 = undefined;
    const text = "this is a test string";
    const n = ac_search(handle, text.ptr, text.len, &results, 4);
    try std.testing.expectEqual(@as(u32, 1), n);
    try std.testing.expectEqual(@as(u32, 7), results[0]);

    ac_destroy(handle);
}

test "empty automaton search" {
    const allocator = std.testing.allocator;
    const ac = try Automaton.init(allocator);
    defer ac.deinit();

    try ac.build();

    var results: [16]u32 = undefined;
    const n = ac.search("anything", &results, 16);
    try std.testing.expectEqual(@as(u32, 0), n);
}

test "sparse goto memory savings" {
    // Verify that interior states use sparse representation.
    const allocator = std.testing.allocator;
    const ac = try Automaton.init(allocator);
    defer ac.deinit();

    try ac.addPattern("hello", 1);
    try ac.addPattern("help", 2);
    try ac.build();

    const fs = ac.final_states.?;
    // Root (state 0) should be dense.
    try std.testing.expect(fs[0].goto_table == .dense);
    // Interior states (e.g., state for 'h' -> 'e' -> 'l') should be sparse.
    // State 1 is 'h', state 2 is 'e', state 3 is 'l'.
    // These have very few non-root transitions so should be sparse.
    if (fs.len > 1) {
        // At least one non-root state should be sparse.
        var has_sparse = false;
        for (fs[1..]) |s| {
            if (s.goto_table == .sparse) {
                has_sparse = true;
                break;
            }
        }
        try std.testing.expect(has_sparse);
    }
}
