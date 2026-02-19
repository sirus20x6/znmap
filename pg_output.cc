
/***************************************************************************
 * pg_output.cc -- PostgreSQL live scan logging module. Activated by       *
 * --pg-dsn <connstr> or the $NMAP_PG_DSN environment variable. Inserts   *
 * scan results into nmap_live.{runs,hosts,ports} using libpq.             *
 *                                                                         *
 * Writes are performed on a background thread to avoid blocking the scan  *
 * engine on PG round-trips. pg_output_hosts() serializes host/port data   *
 * into a job struct and enqueues it; the writer thread drains the queue.  *
 ***************************************************************************/

#include "pg_output.h"
#include "NmapOps.h"
#include "portlist.h"
#include "osscan.h"
#include "FingerPrintResults.h"
#include "nmap_error.h"
#include "nmap.h"

#include <libpq-fe.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <csignal>

extern NmapOps o;

/* Main-thread PG connection (used only for pre-scan skip_recent query) */
static PGconn *pg_conn = NULL;
static int64_t pg_run_id = 0;
static bool pg_active = false;
static int pg_hosts_done = 0;
static std::string pg_dsn_copy;

/* ---- Background writer thread state ---- */

struct PortData {
  std::string port;
  std::string protocol;
  std::string state;
  std::string service_name;
  std::string product;
  std::string version;
  std::string extra_info;
  std::string scripts;
};

struct HostData {
  std::string ip;
  std::string hostname;
  std::string status;
  std::string os_guess;
  std::vector<PortData> ports;
};

struct PgWriteJob {
  std::vector<HostData> hosts;
  int hosts_done_after;  /* cumulative hosts_done after this batch */
  bool shutdown;         /* sentinel: writer should exit after draining */
};

static std::thread pg_writer_thread;
static std::mutex pg_queue_mutex;
static std::condition_variable pg_queue_cv;
static std::queue<PgWriteJob> pg_queue;

/* Escape a C string for inclusion in a JSON string value.
   Caller must free the returned buffer. */
static char *json_escape(const char *s) {
  if (!s || !*s) {
    char *empty = (char *)malloc(1);
    empty[0] = '\0';
    return empty;
  }
  /* Worst case: every char becomes \uXXXX (6 chars) */
  size_t len = strlen(s);
  char *out = (char *)malloc(len * 6 + 1);
  char *p = out;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    switch (c) {
      case '"':  *p++ = '\\'; *p++ = '"'; break;
      case '\\': *p++ = '\\'; *p++ = '\\'; break;
      case '\b': *p++ = '\\'; *p++ = 'b'; break;
      case '\f': *p++ = '\\'; *p++ = 'f'; break;
      case '\n': *p++ = '\\'; *p++ = 'n'; break;
      case '\r': *p++ = '\\'; *p++ = 'r'; break;
      case '\t': *p++ = '\\'; *p++ = 't'; break;
      default:
        if (c < 0x20) {
          p += sprintf(p, "\\u%04x", c);
        } else {
          *p++ = c;
        }
        break;
    }
  }
  *p = '\0';
  return out;
}

static void pg_check_result_conn(PGconn *conn, PGresult *res, const char *context) {
  if (!res || (PQresultStatus(res) != PGRES_COMMAND_OK &&
               PQresultStatus(res) != PGRES_TUPLES_OK)) {
    error("WARNING: pg_output %s failed: %s", context, PQerrorMessage(conn));
    if (res)
      PQclear(res);
  }
}


/* ---- Writer thread entry point ---- */
static void pg_writer_func() {
  PGconn *wconn = PQconnectdb(pg_dsn_copy.c_str());
  if (PQstatus(wconn) != CONNECTION_OK) {
    error("WARNING: pg_output writer: could not connect to PostgreSQL: %s", PQerrorMessage(wconn));
    PQfinish(wconn);
    return;
  }

  /* Prepare statements on writer connection */
  PGresult *res;

  res = PQprepare(wconn, "insert_host",
    "INSERT INTO nmap_live.hosts(run_id, ip, hostname, status, os_guess) "
    "VALUES ($1, $2::inet, $3, $4, $5) RETURNING id",
    5, NULL);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    error("WARNING: pg_output writer: prepare insert_host failed: %s", PQerrorMessage(wconn));
    PQclear(res);
    PQfinish(wconn);
    return;
  }
  PQclear(res);

  res = PQprepare(wconn, "update_progress",
    "UPDATE nmap_live.runs SET hosts_done = $2 WHERE id = $1",
    2, NULL);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    error("WARNING: pg_output writer: prepare update_progress failed: %s", PQerrorMessage(wconn));
    PQclear(res);
    PQfinish(wconn);
    return;
  }
  PQclear(res);

  res = PQprepare(wconn, "check_recent_port",
    "SELECT p.state, p.service_name, p.product, p.version "
    "FROM nmap_live.ports p "
    "JOIN nmap_live.hosts h ON h.id = p.host_id "
    "JOIN nmap_live.runs r ON r.id = h.run_id "
    "WHERE h.ip = $1::inet AND p.port = $2::int AND p.protocol = $3 "
    "AND r.end_time IS NOT NULL "
    "AND r.end_time > now() - make_interval(secs => $4::int) "
    "ORDER BY r.end_time DESC LIMIT 1",
    4, NULL);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    error("WARNING: pg_output writer: prepare check_recent_port failed: %s", PQerrorMessage(wconn));
    PQclear(res);
    PQfinish(wconn);
    return;
  }
  PQclear(res);

  char run_id_str[32];
  snprintf(run_id_str, sizeof(run_id_str), "%lld", (long long)pg_run_id);

  long skip_recent = o.pg_skip_recent;
  char skip_secs_str[32];
  snprintf(skip_secs_str, sizeof(skip_secs_str), "%ld", skip_recent);

  for (;;) {
    PgWriteJob job;
    {
      std::unique_lock<std::mutex> lk(pg_queue_mutex);
      pg_queue_cv.wait(lk, [] { return !pg_queue.empty(); });
      job = std::move(pg_queue.front());
      pg_queue.pop();
    }

    if (job.shutdown && job.hosts.empty())
      break;

    res = PQexec(wconn, "BEGIN");
    pg_check_result_conn(wconn, res, "writer BEGIN");
    if (res) PQclear(res);

    for (size_t i = 0; i < job.hosts.size(); i++) {
      const HostData &hd = job.hosts[i];

      const char *host_params[5];
      host_params[0] = run_id_str;
      host_params[1] = hd.ip.c_str();
      host_params[2] = hd.hostname.c_str();
      host_params[3] = hd.status.c_str();
      host_params[4] = hd.os_guess.c_str();

      res = PQexecPrepared(wconn, "insert_host", 5, host_params, NULL, NULL, 0);
      if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        error("WARNING: pg_output writer: insert host failed: %s", PQerrorMessage(wconn));
        if (res) PQclear(res);
        continue;
      }
      int64_t host_id = strtoll(PQgetvalue(res, 0, 0), NULL, 10);
      PQclear(res);

      char host_id_str[32];
      snprintf(host_id_str, sizeof(host_id_str), "%lld", (long long)host_id);

      /* Port-level dedup + batch insert */
      std::vector<const PortData *> insert_ports;
      int ports_skipped = 0;

      for (size_t p = 0; p < hd.ports.size(); p++) {
        const PortData &pd = hd.ports[p];

        if (skip_recent > 0) {
          const char *check_params[4];
          check_params[0] = hd.ip.c_str();
          check_params[1] = pd.port.c_str();
          check_params[2] = pd.protocol.c_str();
          check_params[3] = skip_secs_str;

          PGresult *chk = PQexecPrepared(wconn, "check_recent_port", 4, check_params, NULL, NULL, 0);
          if (PQresultStatus(chk) == PGRES_TUPLES_OK && PQntuples(chk) > 0) {
            const char *prev_state = PQgetvalue(chk, 0, 0);
            const char *prev_svc   = PQgetvalue(chk, 0, 1);
            const char *prev_prod  = PQgetvalue(chk, 0, 2);
            const char *prev_ver   = PQgetvalue(chk, 0, 3);

            if (pd.state == prev_state &&
                pd.service_name == prev_svc &&
                pd.product == prev_prod &&
                pd.version == prev_ver) {
              ports_skipped++;
              PQclear(chk);
              continue;
            }
          }
          if (chk) PQclear(chk);
        }

        insert_ports.push_back(&pd);
      }

      if (!insert_ports.empty()) {
        std::string query =
          "INSERT INTO nmap_live.ports(host_id, port, protocol, state, service_name, product, version, extra_info, scripts) VALUES ";
        std::vector<std::string> param_storage;
        param_storage.reserve(insert_ports.size() * 9);

        for (size_t j = 0; j < insert_ports.size(); j++) {
          int base = (int)j * 9;
          if (j > 0) query += ", ";
          query += "($" + std::to_string(base + 1) +
            ", $" + std::to_string(base + 2) + "::integer" +
            ", $" + std::to_string(base + 3) +
            ", $" + std::to_string(base + 4) +
            ", $" + std::to_string(base + 5) +
            ", $" + std::to_string(base + 6) +
            ", $" + std::to_string(base + 7) +
            ", $" + std::to_string(base + 8) +
            ", $" + std::to_string(base + 9) + "::jsonb)";

          param_storage.push_back(host_id_str);
          param_storage.push_back(insert_ports[j]->port);
          param_storage.push_back(insert_ports[j]->protocol);
          param_storage.push_back(insert_ports[j]->state);
          param_storage.push_back(insert_ports[j]->service_name);
          param_storage.push_back(insert_ports[j]->product);
          param_storage.push_back(insert_ports[j]->version);
          param_storage.push_back(insert_ports[j]->extra_info);
          param_storage.push_back(insert_ports[j]->scripts);
        }

        std::vector<const char *> param_values(param_storage.size());
        for (size_t k = 0; k < param_storage.size(); k++)
          param_values[k] = param_storage[k].c_str();

        res = PQexecParams(wconn, query.c_str(), (int)param_values.size(), NULL,
                           param_values.data(), NULL, NULL, 0);
        pg_check_result_conn(wconn, res, "insert ports batch");
        if (res) PQclear(res);
      }

      if (o.verbose && ports_skipped > 0)
        log_write(LOG_STDOUT, "pg_output: host %s - %d ports skipped (unchanged), %d inserted\n",
                  hd.ip.c_str(), ports_skipped, (int)insert_ports.size());
    }

    /* Update progress */
    char hosts_done_str[32];
    snprintf(hosts_done_str, sizeof(hosts_done_str), "%d", job.hosts_done_after);
    {
      const char *prog_params[2] = { run_id_str, hosts_done_str };
      res = PQexecPrepared(wconn, "update_progress", 2, prog_params, NULL, NULL, 0);
      pg_check_result_conn(wconn, res, "update progress");
      if (res) PQclear(res);
    }

    res = PQexec(wconn, "COMMIT");
    pg_check_result_conn(wconn, res, "writer COMMIT");
    if (res) PQclear(res);

    if (job.shutdown)
      break;
  }

  /* Finalize: set end_time and hosts_total */
  char hosts_done_str[32];
  snprintf(hosts_done_str, sizeof(hosts_done_str), "%d", pg_hosts_done);

  const char *fin_params[2] = { run_id_str, hosts_done_str };
  res = PQexecParams(wconn,
    "UPDATE nmap_live.runs SET end_time = now(), hosts_total = $2::int, hosts_done = $2::int WHERE id = $1",
    2, NULL, fin_params, NULL, NULL, 0);
  pg_check_result_conn(wconn, res, "writer finalize run");
  if (res) PQclear(res);

  PQfinish(wconn);
}

/* ---- Public API ---- */

bool pg_output_init(const char *dsn, const char *command_line, const char *scanner_version) {
  pg_conn = PQconnectdb(dsn);
  if (PQstatus(pg_conn) != CONNECTION_OK) {
    error("WARNING: pg_output: could not connect to PostgreSQL: %s", PQerrorMessage(pg_conn));
    PQfinish(pg_conn);
    pg_conn = NULL;
    return false;
  }

  pg_dsn_copy = dsn;

  /* Prepare statements on main connection (for skip_recent query and run insert) */
  PGresult *res;

  res = PQprepare(pg_conn, "insert_run",
    "INSERT INTO nmap_live.runs(command, scanner_ver, args) "
    "VALUES ($1, $2, $3::jsonb) RETURNING id",
    3, NULL);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    error("WARNING: pg_output: prepare insert_run failed: %s", PQerrorMessage(pg_conn));
    PQclear(res);
    PQfinish(pg_conn);
    pg_conn = NULL;
    return false;
  }
  PQclear(res);

  /* Build args JSON array from command_line */
  std::string args_json = "[\"";
  char *esc = json_escape(command_line);
  args_json += esc;
  free(esc);
  args_json += "\"]";

  /* Insert the run row */
  const char *params[3];
  params[0] = command_line;
  params[1] = scanner_version;
  params[2] = args_json.c_str();

  res = PQexecPrepared(pg_conn, "insert_run", 3, params, NULL, NULL, 0);
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    error("WARNING: pg_output: insert run failed: %s", PQerrorMessage(pg_conn));
    PQclear(res);
    PQfinish(pg_conn);
    pg_conn = NULL;
    return false;
  }

  pg_run_id = strtoll(PQgetvalue(res, 0, 0), NULL, 10);
  PQclear(res);

  pg_active = true;
  pg_hosts_done = 0;

  /* Start writer thread */
  pg_writer_thread = std::thread(pg_writer_func);

  /* Ensure the run gets finalized on SIGINT/SIGTERM */
  struct sigaction sa, old_sa;
  sa.sa_handler = [](int signo) {
    pg_output_finish();
    signal(signo, SIG_DFL);
    raise(signo);
  };
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, &old_sa);
  sigaction(SIGTERM, &sa, NULL);

  if (o.verbose)
    log_write(LOG_STDOUT, "pg_output: connected, run_id=%lld (async writer started)\n", (long long)pg_run_id);

  return true;
}

void pg_output_hosts(const std::vector<Target *> &hosts) {
  if (!pg_active)
    return;

  PgWriteJob job;
  job.shutdown = false;

  for (size_t i = 0; i < hosts.size(); i++) {
    Target *target = hosts[i];

    HostData hd;
    hd.ip = target->targetipstr();
    hd.hostname = target->HostName();

    if (target->flags & HOST_UP)
      hd.status = "up";
    else if (target->flags & HOST_DOWN)
      hd.status = "down";
    else
      hd.status = "unknown";

    if (target->FPR && target->FPR->overall_results == OSSCAN_SUCCESS &&
        target->FPR->num_matches > 0 && target->FPR->matches[0]) {
      hd.os_guess = target->FPR->matches[0]->OS_name ? target->FPR->matches[0]->OS_name : "";
    }

    /* Serialize all port data */
    Port port;
    Port *current = NULL;
    while ((current = target->ports.nextPort(current, &port, TCPANDUDPANDSCTP, 0)) != NULL) {
      struct serviceDeductions sd;
      target->ports.getServiceDeductions(current->portno, current->proto, &sd);

      PortData pd;
      char portno_str[16];
      snprintf(portno_str, sizeof(portno_str), "%d", current->portno);
      pd.port = portno_str;
      pd.protocol = proto2ascii_lowercase(current->proto);
      pd.state = statenum2str(current->state);
      pd.service_name = sd.name ? sd.name : "";
      pd.product = sd.product ? sd.product : "";
      pd.version = sd.version ? sd.version : "";
      pd.extra_info = sd.extrainfo ? sd.extrainfo : "";

      /* Build NSE scripts JSON */
      pd.scripts = "{}";
#ifndef NOLUA
      if (!current->scriptResults.empty()) {
        pd.scripts = "{";
        bool first = true;
        for (ScriptResults::const_iterator it = current->scriptResults.begin();
             it != current->scriptResults.end(); ++it) {
          if (!first) pd.scripts += ",";
          first = false;

          char *esc_id = json_escape((*it)->get_id());
          std::string output_str = (*it)->get_output_str();
          char *esc_out = json_escape(output_str.c_str());

          pd.scripts += "\"";
          pd.scripts += esc_id;
          pd.scripts += "\":\"";
          pd.scripts += esc_out;
          pd.scripts += "\"";

          free(esc_id);
          free(esc_out);
        }
        pd.scripts += "}";
      }
#endif

      hd.ports.push_back(std::move(pd));
    }

    job.hosts.push_back(std::move(hd));
  }

  pg_hosts_done += (int)hosts.size();
  job.hosts_done_after = pg_hosts_done;

  {
    std::lock_guard<std::mutex> lk(pg_queue_mutex);
    pg_queue.push(std::move(job));
  }
  pg_queue_cv.notify_one();
}

void pg_output_finish(void) {
  if (!pg_active)
    return;

  pg_active = false;

  /* Send shutdown sentinel to writer thread */
  {
    std::lock_guard<std::mutex> lk(pg_queue_mutex);
    PgWriteJob sentinel;
    sentinel.shutdown = true;
    sentinel.hosts_done_after = pg_hosts_done;
    pg_queue.push(std::move(sentinel));
  }
  pg_queue_cv.notify_one();

  if (pg_writer_thread.joinable())
    pg_writer_thread.join();

  /* Close main connection */
  if (pg_conn) {
    PQfinish(pg_conn);
    pg_conn = NULL;
  }

  if (o.verbose)
    log_write(LOG_STDOUT, "pg_output: scan complete, run_id=%lld finalized\n", (long long)pg_run_id);
}

bool pg_output_enabled(void) {
  return pg_active;
}

int pg_output_skip_recent(struct addrset *exclude_group, int af,
                          const unsigned short *tcp_ports, int tcp_count,
                          const unsigned short *udp_ports, int udp_count,
                          const unsigned short *sctp_ports, int sctp_count,
                          long skip_seconds) {
  if (!pg_active || !pg_conn)
    return 0;

  /* Build a VALUES list of all requested port+protocol pairs. */
  std::string values_list;
  bool first = true;
  char buf[48];
  for (int i = 0; i < tcp_count; i++) {
    if (!first) values_list += ",";
    first = false;
    snprintf(buf, sizeof(buf), "(%d,'tcp')", tcp_ports[i]);
    values_list += buf;
  }
  for (int i = 0; i < udp_count; i++) {
    if (!first) values_list += ",";
    first = false;
    snprintf(buf, sizeof(buf), "(%d,'udp')", udp_ports[i]);
    values_list += buf;
  }
  for (int i = 0; i < sctp_count; i++) {
    if (!first) values_list += ",";
    first = false;
    snprintf(buf, sizeof(buf), "(%d,'sctp')", sctp_ports[i]);
    values_list += buf;
  }

  int total_requested = tcp_count + udp_count + sctp_count;
  if (total_requested == 0)
    return 0;

  char interval_str[32];
  snprintf(interval_str, sizeof(interval_str), "%ld seconds", skip_seconds);

  std::string query =
    "SELECT DISTINCT h.ip::text FROM nmap_live.hosts h "
    "JOIN nmap_live.runs r ON r.id = h.run_id "
    "WHERE r.end_time IS NOT NULL "
    "AND r.end_time > now() - interval '" + std::string(interval_str) + "' "
    "AND (SELECT count(DISTINCT (p.port, p.protocol)) "
    "     FROM nmap_live.ports p WHERE p.host_id = h.id "
    "     AND (p.port, p.protocol::text) IN (VALUES " + values_list + ")) "
    "= " + std::to_string(total_requested);

  PGresult *res = PQexec(pg_conn, query.c_str());
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    error("WARNING: pg_output: skip-recent query failed: %s", PQerrorMessage(pg_conn));
    if (res) PQclear(res);
    return 0;
  }

  int nrows = PQntuples(res);
  int added = 0;
  for (int i = 0; i < nrows; i++) {
    const char *ip = PQgetvalue(res, i, 0);
    if (addrset_add_spec(exclude_group, ip, af, 0))
      added++;
  }
  PQclear(res);

  if (added > 0)
    log_write(LOG_STDOUT, "pg_output: skipping %d hosts scanned within last %ld seconds\n",
              added, skip_seconds);

  return added;
}
