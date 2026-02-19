/***************************************************************************
 * engine_io_uring.c -- io_uring based IO engine.                          *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *
 * The nsock parallel socket event library is (C) 1999-2026 Nmap Software LLC
 * This library is free software; you may redistribute and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; Version 2. This guarantees your right to use, modify, and
 * redistribute this software under certain conditions. If this license is
 * unacceptable to you, Nmap Software LLC may be willing to sell alternative
 * licenses (contact sales@nmap.com ).
 *
 * As a special exception to the GPL terms, Nmap Software LLC grants permission
 * to link the code of this program with any version of the OpenSSL library
 * which is distributed under a license identical to that listed in the included
 * docs/licenses/OpenSSL.txt file, and distribute linked combinations including
 * the two. You must obey the GNU GPL in all respects for all of the code used
 * other than OpenSSL. If you modify this file, you may extend this exception to
 * your version of the file, but you are not obligated to do so.
 *
 * If you received these files with a written license agreement stating terms
 * other than the (GPL) terms above, then that alternative license agreement
 * takes precedence over this comment.
 *
 * Source is provided to this software because we believe users have a right to
 * know exactly what a program is going to do before they run it. This also
 * allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to send your changes to the
 * dev@nmap.org mailing list for possible incorporation into the main
 * distribution. By sending these changes to Fyodor or one of the Insecure.Org
 * development mailing lists, or checking them into the Nmap source code
 * repository, it is understood (unless you specify otherwise) that you are
 * offering the Nmap Project (Nmap Software LLC) the unlimited, non-exclusive
 * right to reuse, modify, and relicense the code. Nmap will always be available
 * Open Source, but this is important because the inability to relicense code
 * has caused devastating problems for other Free Software projects (such as KDE
 * and NASM). We also occasionally relicense the code to third parties as
 * discussed above. If you wish to specify special license conditions of your
 * contributions, just say so when you send them.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License v2.0 for more
 * details (http://www.gnu.org/licenses/gpl-2.0.html).
 *
 ***************************************************************************/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "nsock_config.h"
#endif

#if HAVE_IO_URING

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <liburing.h>

#include "nsock_internal.h"
#include "nsock_log.h"

#if HAVE_PCAP
#include "nsock_pcap.h"
#endif

#define IO_URING_ENTRIES 256

#define IORING_R_FLAGS (POLLIN | POLLPRI)
#define IORING_W_FLAGS POLLOUT
#ifndef POLLRDHUP
#define POLLRDHUP 0
#endif
#define IORING_X_FLAGS (POLLERR | POLLHUP | POLLNVAL | POLLRDHUP)

#define IOD_IORING_POLL_ACTIVE 0x01

#define IORING_TAG_CANCEL 0x1ULL
#define IORING_TAG_MASK   0x1ULL

#define IORING_ENCODE_DATA(iod, tag) (((uint64_t)(uintptr_t)(iod)) | (uint64_t)(tag))
#define IORING_DECODE_IOD(data) ((struct niod *)(uintptr_t)((data) & ~IORING_TAG_MASK))
#define IORING_IS_CANCEL(data) (((data) & IORING_TAG_MASK) == IORING_TAG_CANCEL)

/* --- ENGINE INTERFACE PROTOTYPES --- */
static int io_uring_init(struct npool *nsp);
static void io_uring_destroy(struct npool *nsp);
static int io_uring_iod_register(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev);
static int io_uring_iod_unregister(struct npool *nsp, struct niod *iod);
static int io_uring_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr);
static int io_uring_loop(struct npool *nsp, int msec_timeout);

extern struct io_operations posix_io_operations;

/* ---- ENGINE DEFINITION ---- */
struct io_engine engine_io_uring = {
  "io_uring",
  io_uring_init,
  io_uring_destroy,
  io_uring_iod_register,
  io_uring_iod_unregister,
  io_uring_iod_modify,
  io_uring_loop,
  &posix_io_operations
};

struct io_uring_engine_info {
  struct io_uring ring;
  int num_pcap_nonselect;
};

static int io_uring_submit_poll_add(struct npool *nsp, struct niod *iod);
static int io_uring_submit_poll_remove(struct npool *nsp, struct niod *iod);
static int io_uring_poll_mask(int ev);
static int io_uring_revents_to_evmask(int revents);
static void io_uring_process_cqe(struct npool *nsp, struct io_uring_cqe *cqe);

int io_uring_init(struct npool *nsp) {
  struct io_uring_engine_info *uinfo;
  int rc;

  uinfo = (struct io_uring_engine_info *)safe_malloc(sizeof(struct io_uring_engine_info));
  memset(uinfo, 0, sizeof(*uinfo));

  rc = io_uring_queue_init(IO_URING_ENTRIES, &uinfo->ring, 0);
  if (rc < 0)
    fatal("Unable to initialize io_uring queue: %s", strerror(-rc));

  uinfo->num_pcap_nonselect = 0;
  nsp->engine_data = (void *)uinfo;

  return 1;
}

void io_uring_destroy(struct npool *nsp) {
  struct io_uring_engine_info *uinfo = (struct io_uring_engine_info *)nsp->engine_data;

  assert(uinfo != NULL);
  io_uring_queue_exit(&uinfo->ring);
  free(uinfo);
}

int io_uring_iod_register(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev) {
  int sd;
  struct io_uring_engine_info *uinfo = (struct io_uring_engine_info *)nsp->engine_data;

  assert(!IOD_PROPGET(iod, IOD_REGISTERED));

  iod->watched_events = ev;
  iod->engine_info = 0;

  sd = nsock_iod_get_sd(iod);
  if (sd == -1) {
    if (iod->pcap)
      uinfo->num_pcap_nonselect++;
    else
      fatal("Unable to get descriptor for IOD #%lu", iod->id);
  }
  else if (ev != EV_NONE) {
    io_uring_submit_poll_add(nsp, iod);
  }

  IOD_PROPSET(iod, IOD_REGISTERED);
  return 1;
}

int io_uring_iod_unregister(struct npool *nsp, struct niod *iod) {
  struct io_uring_engine_info *uinfo = (struct io_uring_engine_info *)nsp->engine_data;
  int sd;

  iod->watched_events = EV_NONE;

  if (IOD_PROPGET(iod, IOD_REGISTERED)) {
    sd = nsock_iod_get_sd(iod);

    if (sd == -1) {
      assert(iod->pcap);
      uinfo->num_pcap_nonselect--;
    }
    else if (iod->engine_info & IOD_IORING_POLL_ACTIVE) {
      io_uring_submit_poll_remove(nsp, iod);
    }

    IOD_PROPCLR(iod, IOD_REGISTERED);
    iod->engine_info = 0;
  }

  return 1;
}

int io_uring_iod_modify(struct npool *nsp, struct niod *iod, struct nevent *nse, int ev_set, int ev_clr) {
  int new_events;

  assert((ev_set & ev_clr) == 0);
  assert(IOD_PROPGET(iod, IOD_REGISTERED));

  new_events = iod->watched_events;
  new_events |= ev_set;
  new_events &= ~ev_clr;

  if (new_events == iod->watched_events)
    return 1;

  iod->watched_events = new_events;

  if (nsock_iod_get_sd(iod) != -1) {
    if (iod->engine_info & IOD_IORING_POLL_ACTIVE)
      io_uring_submit_poll_remove(nsp, iod);

    if (iod->watched_events != EV_NONE)
      io_uring_submit_poll_add(nsp, iod);
  }

  return 1;
}

int io_uring_loop(struct npool *nsp, int msec_timeout) {
  int results_left = 0;
  int event_msecs;
  int combined_msecs;
  int sock_err = 0;
  unsigned int iod_count;
  struct io_uring_cqe *cqe;
  struct io_uring_engine_info *uinfo = (struct io_uring_engine_info *)nsp->engine_data;

  assert(msec_timeout >= -1);

  if (nsp->events_pending == 0)
    return 0;

  iod_count = gh_list_count(&nsp->active_iods) - uinfo->num_pcap_nonselect;

  do {
    struct nevent *nse;

    nsock_log_debug_all("wait for events");
    results_left = 0;

    nse = next_expirable_event(nsp);
    if (!nse)
      event_msecs = -1;
    else {
      event_msecs = TIMEVAL_MSEC_SUBTRACT(nse->timeout, nsock_tod);
      event_msecs = MAX(0, event_msecs);
    }

#if HAVE_PCAP
    if (uinfo->num_pcap_nonselect > 0 && gh_list_count(&nsp->pcap_read_events) > 0) {
      if (pcap_read_on_nonselect(nsp)) {
        gettimeofday(&nsock_tod, NULL);
        iterate_through_pcap_events(nsp);
        event_msecs = 0;
      }
      else if (event_msecs > PCAP_POLL_INTERVAL) {
        event_msecs = PCAP_POLL_INTERVAL;
      }
    }
#endif

    combined_msecs = MIN((unsigned)event_msecs, (unsigned)msec_timeout);

    if (iod_count > 0) {
      int rc;
      struct __kernel_timespec ts;
      struct __kernel_timespec *ts_p;

      memset(&ts, 0, sizeof(ts));
      if (combined_msecs >= 0) {
        ts.tv_sec = combined_msecs / 1000;
        ts.tv_nsec = (combined_msecs % 1000) * 1000000L;
        ts_p = &ts;
      } else {
        ts_p = NULL;
      }

      rc = io_uring_wait_cqe_timeout(&uinfo->ring, &cqe, ts_p);
      if (rc == 0) {
        results_left = 1;
        io_uring_process_cqe(nsp, cqe);
        io_uring_cqe_seen(&uinfo->ring, cqe);

        while (io_uring_peek_cqe(&uinfo->ring, &cqe) == 0) {
          results_left++;
          io_uring_process_cqe(nsp, cqe);
          io_uring_cqe_seen(&uinfo->ring, cqe);
        }
      }
      else if (rc == -ETIME) {
        results_left = 0;
      }
      else {
        results_left = -1;
        sock_err = -rc;
      }
    }
    else if (combined_msecs > 0) {
      usleep(combined_msecs * 1000);
    }

    gettimeofday(&nsock_tod, NULL);
  } while (results_left == -1 && sock_err == EINTR);

  if (results_left == -1 && sock_err != EINTR) {
    nsock_log_error("nsock_loop error %d: %s", sock_err, socket_strerror(sock_err));
    nsp->errnum = sock_err;
    return -1;
  }

  process_expired_events(nsp);

  return 1;
}

static int io_uring_submit_poll_add(struct npool *nsp, struct niod *iod) {
  int mask;
  int sd;
  int rc;
  struct io_uring_engine_info *uinfo = (struct io_uring_engine_info *)nsp->engine_data;
  struct io_uring_sqe *sqe;

  sd = nsock_iod_get_sd(iod);
  if (sd == -1)
    return 1;

  mask = io_uring_poll_mask(iod->watched_events);
  if (mask == 0)
    return 1;

  sqe = io_uring_get_sqe(&uinfo->ring);
  if (!sqe) {
    rc = io_uring_submit(&uinfo->ring);
    if (rc < 0)
      fatal("Unable to submit io_uring SQEs: %s", strerror(-rc));
    sqe = io_uring_get_sqe(&uinfo->ring);
  }
  if (!sqe)
    fatal("Unable to allocate io_uring SQE for IOD #%lu", iod->id);

  io_uring_prep_poll_add(sqe, sd, mask);
  io_uring_sqe_set_data64(sqe, IORING_ENCODE_DATA(iod, 0));

  rc = io_uring_submit(&uinfo->ring);
  if (rc < 0)
    fatal("Unable to register IOD #%lu in io_uring: %s", iod->id, strerror(-rc));

  iod->engine_info |= IOD_IORING_POLL_ACTIVE;
  return 1;
}

static int io_uring_submit_poll_remove(struct npool *nsp, struct niod *iod) {
  int rc;
  struct io_uring_engine_info *uinfo = (struct io_uring_engine_info *)nsp->engine_data;
  struct io_uring_sqe *sqe;

  if ((iod->engine_info & IOD_IORING_POLL_ACTIVE) == 0)
    return 1;

  sqe = io_uring_get_sqe(&uinfo->ring);
  if (!sqe) {
    rc = io_uring_submit(&uinfo->ring);
    if (rc < 0)
      fatal("Unable to submit io_uring SQEs: %s", strerror(-rc));
    sqe = io_uring_get_sqe(&uinfo->ring);
  }
  if (!sqe)
    fatal("Unable to allocate io_uring SQE for poll removal on IOD #%lu", iod->id);

  io_uring_prep_poll_remove(sqe, IORING_ENCODE_DATA(iod, 0));
  io_uring_sqe_set_data64(sqe, IORING_ENCODE_DATA(iod, IORING_TAG_CANCEL));

  rc = io_uring_submit(&uinfo->ring);
  if (rc < 0)
    fatal("Unable to unregister IOD #%lu from io_uring: %s", iod->id, strerror(-rc));

  iod->engine_info &= ~IOD_IORING_POLL_ACTIVE;
  return 1;
}

static int io_uring_poll_mask(int ev) {
  int mask = 0;

  if (ev & EV_READ)
    mask |= IORING_R_FLAGS;
  if (ev & EV_WRITE)
    mask |= IORING_W_FLAGS;

  return mask;
}

static int io_uring_revents_to_evmask(int revents) {
  int evmask = EV_NONE;

  if (revents & IORING_R_FLAGS)
    evmask |= EV_READ;
  if (revents & IORING_W_FLAGS)
    evmask |= EV_WRITE;
  if (revents & IORING_X_FLAGS)
    evmask |= EV_EXCEPT;

  return evmask;
}

static void io_uring_process_cqe(struct npool *nsp, struct io_uring_cqe *cqe) {
  uint64_t data;
  struct niod *iod;
  int evmask;

  data = cqe->user_data;
  if (IORING_IS_CANCEL(data))
    return;

  iod = IORING_DECODE_IOD(data);
  if (!iod)
    return;

  iod->engine_info &= ~IOD_IORING_POLL_ACTIVE;

  if (cqe->res < 0) {
    if (cqe->res == -ECANCELED || cqe->res == -ENOENT)
      return;
    evmask = EV_EXCEPT;
  }
  else {
    evmask = io_uring_revents_to_evmask(cqe->res);
  }

  if (evmask != EV_NONE)
    process_iod_events(nsp, iod, evmask);

  if (iod->state == NSIOD_STATE_DELETED) {
    gh_list_remove(&nsp->active_iods, &iod->nodeq);
    gh_list_prepend(&nsp->free_iods, &iod->nodeq);
    return;
  }

  if (IOD_PROPGET(iod, IOD_REGISTERED) && iod->watched_events != EV_NONE)
    io_uring_submit_poll_add(nsp, iod);
}

#endif /* HAVE_IO_URING */
