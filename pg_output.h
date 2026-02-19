#ifndef PG_OUTPUT_H
#define PG_OUTPUT_H

#include "Target.h"
#include <vector>

/* Initialize PG connection (called once at scan start).
   Returns true if connection succeeded, false otherwise. */
bool pg_output_init(const char *dsn, const char *command_line, const char *scanner_version);

/* Log a batch of completed hosts (called per host group in output loop). */
void pg_output_hosts(const std::vector<Target *> &hosts);

/* Finalize: set run end_time, close connection (called at scan end). */
void pg_output_finish(void);

/* Check if PG output is active. */
bool pg_output_enabled(void);

/* Query PG for hosts where all requested ports were scanned within
   skip_seconds. Returns the number of IPs added to exclude_group.
   Must be called after pg_output_init(). */
struct addrset;
int pg_output_skip_recent(struct addrset *exclude_group, int af,
                          const unsigned short *tcp_ports, int tcp_count,
                          const unsigned short *udp_ports, int udp_count,
                          const unsigned short *sctp_ports, int sctp_count,
                          long skip_seconds);

#endif
