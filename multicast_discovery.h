/***************************************************************************
 * multicast_discovery.h -- IPv6 all-nodes multicast host discovery via    *
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

#ifndef MULTICAST_DISCOVERY_H
#define MULTICAST_DISCOVERY_H

#include <vector>
#include <sys/socket.h>

/* Sends an ICMPv6 Echo Request to ff02::1 (all-nodes multicast) on the
   specified interface and collects responding IPv6 addresses.
   Returns a list of discovered host addresses as sockaddr_storage. */
std::vector<struct sockaddr_storage> do_multicast_discovery(const char *device);

#endif /* MULTICAST_DISCOVERY_H */
