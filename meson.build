project('znmap', ['c', 'cpp'],
  version: '7.98',
  default_options: [
    'c_std=gnu11',
    'cpp_std=gnu++23',
    'warning_level=2',
    'b_ndebug=if-release',
    'b_lto=true',
  ],
)

cc = meson.get_compiler('c')
cxx = meson.get_compiler('cpp')

# --- Configuration header ---

cdata = configuration_data()

# Headers
foreach h : [
  'unistd.h', 'string.h', 'strings.h', 'pwd.h', 'stdint.h',
  'linux/rtnetlink.h', 'sys/stat.h', 'net/if.h', 'fcntl.h',
  'termios.h', 'sys/time.h',
]
  varname = 'HAVE_' + h.underscorify().to_upper()
  if cc.has_header(h)
    cdata.set(varname, 1)
  endif
endforeach

# Functions
if cc.has_function('strerror')
  cdata.set('HAVE_STRERROR', 1)
endif
if cc.has_function('signal')
  cdata.set('HAVE_SIGNAL', 1)
endif

# Struct members
if cc.has_member('struct ip', 'ip_hl', prefix: '#include <netinet/ip.h>')
  cdata.set('HAVE_STRUCT_IP', 1)
endif
if cc.has_member('struct icmp', 'icmp_type', prefix: '#include <netinet/ip_icmp.h>')
  cdata.set('HAVE_STRUCT_ICMP', 1)
endif
if cc.has_member('struct ip', 'ip_sum', prefix: '#include <netinet/ip.h>')
  cdata.set('HAVE_IP_IP_SUM', 1)
endif

# Platform symbols
if cc.has_header_symbol('netinet/in.h', 'IPPROTO_RAW',
    prefix: '#include <sys/types.h>\n#include <sys/socket.h>\n#include <netinet/in.h>')
  cdata.set('HAVE_IPV6_IPPROTO_RAW', 1)
endif

# Platform constants
cdata.set('STDC_HEADERS', 1)
if host_machine.system() == 'linux'
  cdata.set('LINUX', 1)
endif
cdata.set('DNET_INCLUDED', 1)

# --- System dependencies ---

pcap_dep = dependency('libpcap')
openssl_dep = dependency('openssl', required: false)
libssh2_dep = dependency('libssh2', required: false)
zlib_dep = dependency('zlib', required: false)
pcre2_dep = dependency('libpcre2-8')
libpq_dep = dependency('libpq')
uring_dep = dependency('liburing', required: false)

if openssl_dep.found()
  cdata.set('HAVE_OPENSSL', 1)
endif
if libssh2_dep.found()
  cdata.set('HAVE_LIBSSH2', 1)
endif
if zlib_dep.found()
  cdata.set('HAVE_LIBZ', 1)
endif
if uring_dep.found()
  cdata.set('HAVE_IO_URING', 1)
endif

# pcap_set_immediate_mode
if cc.has_function('pcap_set_immediate_mode',
    prefix: '#include <pcap.h>',
    dependencies: pcap_dep)
  cdata.set('HAVE_PCAP_SET_IMMEDIATE_MODE', 1)
endif

# Lua — system package
lua_dep = dependency('lua5.4', required: false)
if not lua_dep.found()
  lua_dep = dependency('lua-5.4', required: false)
endif
if not lua_dep.found()
  lua_dep = dependency('lua54', required: false)
endif
if not lua_dep.found()
  lua_dep = dependency('lua', version: '>=5.4')
endif
if cc.has_header('lua.h', dependencies: lua_dep)
  cdata.set('HAVE_LUA_H', 1)
endif

configure_file(
  input: 'meson_config.h.in',
  output: 'nmap_config.h',
  configuration: cdata,
)
config_inc = include_directories('.')  # for generated nmap_config.h in builddir

# --- Bundled libraries ---

# libdnet-stripped (bundled, Linux platform sources)
libdnet_src = files(
  'libdnet-stripped/src/addr-util.c',
  'libdnet-stripped/src/addr.c',
  'libdnet-stripped/src/blob.c',
  'libdnet-stripped/src/ip-util.c',
  'libdnet-stripped/src/ip6.c',
  'libdnet-stripped/src/rand.c',
  # Linux-specific LIBOBJS
  'libdnet-stripped/src/arp-ioctl.c',
  'libdnet-stripped/src/eth-linux.c',
  'libdnet-stripped/src/fw-none.c',
  'libdnet-stripped/src/intf.c',
  'libdnet-stripped/src/ip.c',
  'libdnet-stripped/src/route-linux.c',
  'libdnet-stripped/src/ndisc-linux.c',
  'libdnet-stripped/src/tun-linux.c',
)
libdnet_lib = static_library('dnet',
  libdnet_src,
  c_args: ['-DHAVE_CONFIG_H'],
  include_directories: [
    include_directories('libdnet-stripped/include'),
    include_directories('libdnet-stripped/src'),
    config_inc,
  ],
)
libdnet_dep = declare_dependency(
  link_with: libdnet_lib,
  include_directories: include_directories('libdnet-stripped/include'),
)

# liblinear (bundled, with bundled BLAS)
liblinear_lib = static_library('linear',
  files(
    'liblinear/linear.cpp',
    'liblinear/newton.cpp',
    'liblinear/blas/daxpy.c',
    'liblinear/blas/ddot.c',
    'liblinear/blas/dnrm2.c',
    'liblinear/blas/dscal.c',
  ),
  cpp_args: ['-DHAVE_CONFIG_H'],
  include_directories: [include_directories('liblinear'), config_inc],
)
liblinear_dep = declare_dependency(
  link_with: liblinear_lib,
  include_directories: include_directories('liblinear'),
)

# --- Subdirectory libraries ---

subdir('nbase')
subdir('nsock/src')
subdir('libnetutil')
subdir('zig')

# --- Nmap core sources ---

nmap_src = files(
  'charpool.cc',
  'FingerPrintResults.cc',
  'FPEngine.cc',
  'FPModel.cc',
  'idle_scan.cc',
  'MACLookup.cc',
  'main.cc',
  'multicast_discovery.cc',
  'nmap.cc',
  'nmap_dns.cc',
  'nmap_error.cc',
  'nmap_ftp.cc',
  'NmapOps.cc',
  'NmapOutputTable.cc',
  'nmap_tty.cc',
  'osscan2.cc',
  'osscan.cc',
  'output.cc',
  'payload.cc',
  'pg_output.cc',
  'portlist.cc',
  'portreasons.cc',
  'protocols.cc',
  'scan_engine.cc',
  'scan_engine_connect.cc',
  'scan_engine_raw.cc',
  'scan_lists.cc',
  'service_scan.cc',
  'services.cc',
  'string_pool.cc',
  'Target.cc',
  'NewTargets.cc',
  'TargetGroup.cc',
  'targets.cc',
  'tcpip.cc',
  'timing.cc',
  'traceroute.cc',
  'utils.cc',
  'xml.cc',
)

# NSE (Lua scripting engine) sources
nse_src = files(
  'nse_main.cc',
  'nse_utility.cc',
  'nse_nsock.cc',
  'nse_db.cc',
  'nse_dnet.cc',
  'nse_fs.cc',
  'nse_nmaplib.cc',
  'nse_debug.cc',
  'nse_lpeg.cc',
)

if openssl_dep.found()
  nse_src += files('nse_openssl.cc', 'nse_ssl_cert.cc')
endif
if libssh2_dep.found()
  nse_src += files('nse_libssh2.cc')
endif
if zlib_dep.found()
  nse_src += files('nse_zlib.cc')
endif

# --- Build nmap executable ---

nmap_inc = include_directories(
  '.',
  'nbase',
  'nsock/include',
  'libnetutil',
  'libdnet-stripped/include',
  'liblinear',
)

nmap_deps = [
  nbase_dep,
  nsock_dep,
  libnetutil_dep,
  libdnet_dep,
  liblinear_dep,
  lua_dep,
  pcap_dep,
  pcre2_dep,
  libpq_dep,
]

if openssl_dep.found()
  nmap_deps += openssl_dep
endif
if libssh2_dep.found()
  nmap_deps += libssh2_dep
endif
if zlib_dep.found()
  nmap_deps += zlib_dep
endif

executable('znmap',
  nmap_src + nse_src,
  objects: zig_objects,
  cpp_args: ['-DHAVE_CONFIG_H', '-D_FORTIFY_SOURCE=2',
             '-DNMAP_PLATFORM="@0@"'.format(host_machine.system()),
             '-DNMAPDATADIR="/usr/local/share/nmap"'],
  include_directories: [nmap_inc, config_inc],
  dependencies: nmap_deps,
  link_args: ['-Wl,--allow-multiple-definition', '-ldl', '-lm', '-lpthread'],
  install: true,
)
