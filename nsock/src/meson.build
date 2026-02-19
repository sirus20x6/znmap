nsock_src = files(
  'engine_epoll.c',
  'engine_iocp.c',
  'engine_kqueue.c',
  'engine_poll.c',
  'engine_select.c',
  'error.c',
  'filespace.c',
  'gh_heap.c',
  'netutils.c',
  'nsock_connect.c',
  'nsock_core.c',
  'nsock_engines.c',
  'nsock_event.c',
  'nsock_iod.c',
  'nsock_log.c',
  'nsock_pcap.c',
  'nsock_pool.c',
  'nsock_proxy.c',
  'nsock_read.c',
  'nsock_ssl.c',
  'nsock_timers.c',
  'nsock_write.c',
  'proxy_http.c',
  'proxy_socks4.c',
)

if uring_dep.found()
  nsock_src += files('engine_io_uring.c')
endif

nsock_deps = [pcap_dep, openssl_dep]
if uring_dep.found()
  nsock_deps += uring_dep
endif

nsock_lib = static_library('nsock',
  nsock_src,
  c_args: ['-DHAVE_CONFIG_H'],
  include_directories: [include_directories('.', '../include', '../../nbase', '../..'), config_inc],
  dependencies: nsock_deps,
)

nsock_dep = declare_dependency(
  link_with: nsock_lib,
  include_directories: include_directories('../include'),
)
