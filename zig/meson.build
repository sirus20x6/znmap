zig = find_program('zig')

checksum_obj = custom_target('zig_checksum',
  input: 'checksum.zig',
  output: 'checksum.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'checksum', '-femit-bin=@OUTPUT@'],
)

probe_filter_obj = custom_target('zig_probe_filter',
  input: 'probe_filter.zig',
  output: 'probe_filter.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'probe_filter', '-femit-bin=@OUTPUT@'],
)

arena_obj = custom_target('zig_arena',
  input: 'arena.zig',
  output: 'arena.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'arena', '-femit-bin=@OUTPUT@'],
)

portstate_obj = custom_target('zig_portstate',
  input: 'portstate.zig',
  output: 'portstate.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'portstate', '-femit-bin=@OUTPUT@'],
)

aho_corasick_obj = custom_target('zig_aho_corasick',
  input: 'aho_corasick.zig',
  output: 'aho_corasick.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'aho_corasick', '-femit-bin=@OUTPUT@'],
)

dns_pool_obj = custom_target('zig_dns_pool',
  input: 'dns_pool.zig',
  output: 'dns_pool.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'dns_pool', '-femit-bin=@OUTPUT@'],
)

fp_match_obj = custom_target('zig_fp_match',
  input: 'fp_match.zig',
  output: 'fp_match.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'fp_match', '-femit-bin=@OUTPUT@'],
)

pkt_builder_obj = custom_target('zig_pkt_builder',
  input: 'pkt_builder.zig',
  output: 'pkt_builder.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'pkt_builder', '-femit-bin=@OUTPUT@'],
)

pkt_parse_obj = custom_target('zig_pkt_parse',
  input: 'pkt_parse.zig',
  output: 'pkt_parse.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'pkt_parse', '-femit-bin=@OUTPUT@'],
)

ip_range_obj = custom_target('zig_ip_range',
  input: 'ip_range.zig',
  output: 'ip_range.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'ip_range', '-femit-bin=@OUTPUT@'],
)

banner_match_obj = custom_target('zig_banner_match',
  input: 'banner_match.zig',
  output: 'banner_match.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'banner_match', '-femit-bin=@OUTPUT@'],
)

pkt_mmap_obj = custom_target('zig_pkt_mmap',
  input: 'pkt_mmap.zig',
  output: 'pkt_mmap.o',
  command: [zig, 'build-obj', '-OReleaseFast', '-lc', '@INPUT@', '--name', 'pkt_mmap', '-femit-bin=@OUTPUT@'],
)

zig_objects = [
  checksum_obj,
  probe_filter_obj,
  arena_obj,
  portstate_obj,
  aho_corasick_obj,
  dns_pool_obj,
  fp_match_obj,
  pkt_builder_obj,
  pkt_parse_obj,
  ip_range_obj,
  banner_match_obj,
  pkt_mmap_obj,
]
