nbase_src = files(
  'nbase_addrset.c',
  'nbase_memalloc.c',
  'nbase_misc.c',
  'nbase_rnd.c',
  'nbase_str.c',
  'nbase_time.c',
  'snprintf.c',
  'strcasecmp.c',
)

# Compat shims only needed when system lacks them
if not cc.has_function('getaddrinfo')
  nbase_src += files('getaddrinfo.c')
endif
if not cc.has_function('getnameinfo')
  nbase_src += files('getnameinfo.c')
endif
if not cc.has_function('inet_ntop')
  nbase_src += files('inet_ntop.c')
endif
if not cc.has_function('inet_pton')
  nbase_src += files('inet_pton.c')
endif

nbase_lib = static_library('nbase',
  nbase_src,
  c_args: ['-DHAVE_CONFIG_H'],
  include_directories: [include_directories('.', '..'), config_inc],
)

nbase_dep = declare_dependency(
  link_with: nbase_lib,
  include_directories: include_directories('.'),
)
