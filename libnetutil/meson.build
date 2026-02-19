libnetutil_src = files(
  'ARPHeader.cc',
  'DestOptsHeader.cc',
  'EthernetHeader.cc',
  'FragmentHeader.cc',
  'HopByHopHeader.cc',
  'ICMPv4Header.cc',
  'ICMPv6Header.cc',
  'ICMPv6Option.cc',
  'ICMPv6RRBody.cc',
  'IPv4Header.cc',
  'IPv6Header.cc',
  'netutil.cc',
  'NetworkLayerElement.cc',
  'PacketElement.cc',
  'PacketParser.cc',
  'RawData.cc',
  'RoutingHeader.cc',
  'TCPHeader.cc',
  'TransportLayerElement.cc',
  'UDPHeader.cc',
)

libnetutil_lib = static_library('netutil',
  libnetutil_src,
  cpp_args: ['-DHAVE_CONFIG_H'],
  include_directories: [include_directories('.', '..', '../nbase', '../libdnet-stripped/include'), config_inc],
)

libnetutil_dep = declare_dependency(
  link_with: libnetutil_lib,
  include_directories: include_directories('.'),
)
