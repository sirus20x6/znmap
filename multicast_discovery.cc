/***************************************************************************
 * multicast_discovery.cc -- IPv6 all-nodes multicast host discovery via   *
 * ICMPv6 Echo Request to ff02::1.                                         *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2026 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 ***************************************************************************/

#include "multicast_discovery.h"
#include "nmap.h"
#include "NmapOps.h"
#include "nmap_error.h"
#include "output.h"

#include <nbase.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <set>
#include <string>

extern NmapOps o;

/* Get the link-local IPv6 address for a given interface by iterating
   getifaddrs results. Returns true on success. */
static bool get_link_local_addr(const char *device, struct in6_addr *addr) {
  struct ifaddrs *ifap, *ifa;

  if (getifaddrs(&ifap) != 0)
    return false;

  bool found = false;
  for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;
    if (ifa->ifa_addr->sa_family != AF_INET6)
      continue;
    if (strcmp(ifa->ifa_name, device) != 0)
      continue;

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
    /* Check if this is a link-local address (fe80::/10) */
    if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
      memcpy(addr, &sin6->sin6_addr, sizeof(*addr));
      found = true;
      break;
    }
  }

  freeifaddrs(ifap);
  return found;
}

std::vector<struct sockaddr_storage> do_multicast_discovery(const char *device) {
  std::vector<struct sockaddr_storage> results;
  std::set<std::string> seen_addrs;
  char addr_str[INET6_ADDRSTRLEN];
  int sd;

  if (device == NULL || device[0] == '\0') {
    error("ERROR: --multicast-discovery requires an interface (use -e <device>)");
    return results;
  }

  log_write(LOG_STDOUT, "Starting IPv6 multicast discovery on interface %s...\n", device);

  /* Resolve link-local source address for this interface */
  struct in6_addr src_addr;
  if (!get_link_local_addr(device, &src_addr)) {
    error("ERROR: Could not find a link-local IPv6 address on interface %s", device);
    return results;
  }

  inet_ntop(AF_INET6, &src_addr, addr_str, sizeof(addr_str));
  if (o.verbose)
    log_write(LOG_STDOUT, "Using source address %s on %s\n", addr_str, device);

  /* Record our own address so we can skip it in responses */
  std::string own_addr_str(addr_str);

  /* Create raw ICMPv6 socket */
  sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (sd < 0) {
    error("ERROR: Could not create raw ICMPv6 socket: %s (are you root?)", strerror(errno));
    return results;
  }

  /* Bind to the specified interface */
#ifdef SO_BINDTODEVICE
  if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1) < 0) {
    error("ERROR: Could not bind to device %s: %s", device, strerror(errno));
    close(sd);
    return results;
  }
#endif

  /* Set multicast hop limit to 1 (link-local only) */
  int hoplimit = 1;
  if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hoplimit, sizeof(hoplimit)) < 0) {
    error("WARNING: Could not set multicast hop limit: %s", strerror(errno));
  }

  /* Set the outgoing multicast interface */
  unsigned int ifindex = if_nametoindex(device);
  if (ifindex == 0) {
    error("ERROR: Could not resolve interface index for %s: %s", device, strerror(errno));
    close(sd);
    return results;
  }
  if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
    error("WARNING: Could not set multicast interface: %s", strerror(errno));
  }

  /* Build ICMPv6 Echo Request destined to ff02::1 */
  struct sockaddr_in6 dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin6_family = AF_INET6;
  dest.sin6_scope_id = ifindex;
  inet_pton(AF_INET6, "ff02::1", &dest.sin6_addr);

  /* Construct the ICMPv6 Echo Request packet.
     The kernel handles the IPv6 header and ICMPv6 checksum for SOCK_RAW
     with IPPROTO_ICMPV6. */
  struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
  } echo_req;

  memset(&echo_req, 0, sizeof(echo_req));
  echo_req.type = ICMP6_ECHO_REQUEST;  /* 128 */
  echo_req.code = 0;
  echo_req.checksum = 0;  /* Kernel computes this for ICMPv6 raw sockets */
  echo_req.id = htons((uint16_t)(get_random_uint() & 0xFFFF));
  echo_req.seq = htons(1);

  /* Set an ICMPv6 filter to only receive Echo Reply messages */
  struct icmp6_filter filt;
  ICMP6_FILTER_SETBLOCKALL(&filt);
  ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);
  if (setsockopt(sd, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt)) < 0) {
    if (o.verbose)
      log_write(LOG_STDOUT, "WARNING: Could not set ICMPv6 filter: %s\n", strerror(errno));
  }

  /* Send the Echo Request to ff02::1 */
  ssize_t sent = sendto(sd, &echo_req, sizeof(echo_req), 0,
                         (struct sockaddr *)&dest, sizeof(dest));
  if (sent < 0) {
    error("ERROR: Failed to send ICMPv6 Echo Request to ff02::1: %s", strerror(errno));
    close(sd);
    return results;
  }

  if (o.verbose)
    log_write(LOG_STDOUT, "Sent ICMPv6 Echo Request to ff02::1 (%zd bytes)\n", sent);

  /* Listen for replies with a 3-second timeout */
  struct timeval timeout;
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;

  fd_set readfds;
  u8 recv_buf[1500];

  while (1) {
    FD_ZERO(&readfds);
    FD_SET(sd, &readfds);

    int sel = select(sd + 1, &readfds, NULL, NULL, &timeout);
    if (sel < 0) {
      if (errno == EINTR)
        continue;
      error("ERROR: select() failed: %s", strerror(errno));
      break;
    }
    if (sel == 0) {
      /* Timeout reached */
      break;
    }

    struct sockaddr_in6 from;
    socklen_t fromlen = sizeof(from);
    ssize_t recvlen = recvfrom(sd, recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr *)&from, &fromlen);
    if (recvlen < 0) {
      if (errno == EINTR)
        continue;
      if (o.verbose)
        log_write(LOG_STDOUT, "WARNING: recvfrom() error: %s\n", strerror(errno));
      continue;
    }

    /* Verify this is an Echo Reply (the ICMPv6 filter should ensure this,
       but double-check) */
    if (recvlen < 4)
      continue;
    if (recv_buf[0] != ICMP6_ECHO_REPLY)
      continue;

    /* Format the source address */
    inet_ntop(AF_INET6, &from.sin6_addr, addr_str, sizeof(addr_str));
    std::string addr_key(addr_str);

    /* Skip our own address */
    if (addr_key == own_addr_str)
      continue;

    /* De-duplicate */
    if (seen_addrs.find(addr_key) != seen_addrs.end())
      continue;
    seen_addrs.insert(addr_key);

    /* Store the result */
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    memcpy(&ss, &from, sizeof(from));
    results.push_back(ss);

    log_write(LOG_STDOUT, "Discovered %s via multicast\n", addr_str);
  }

  close(sd);

  log_write(LOG_STDOUT, "Multicast discovery done: %lu host(s) found on %s\n",
            (unsigned long)results.size(), device);

  return results;
}
