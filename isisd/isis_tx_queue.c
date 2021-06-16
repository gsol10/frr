/*
 * IS-IS Rout(e)ing protocol - LSP TX Queuing logic
 *
 * Copyright (C) 2018 Christian Franke
 *
 * This file is part of FRRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "hash.h"
#include "jhash.h"

#include "isisd/isisd.h"
#include "isisd/isis_memory.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_tx_queue.h"

DEFINE_MTYPE_STATIC(ISISD, TX_QUEUE, "ISIS TX Queue")
DEFINE_MTYPE_STATIC(ISISD, TX_QUEUE_ENTRY, "ISIS TX Queue Entry")

PREDECL_LIST(queue_entry_fifo)
struct qef_item {
	struct queue_entry_fifo_item qef_item;
	struct isis_tx_queue_entry *e; // Back pointer
};

DECLARE_LIST(queue_entry_fifo, struct qef_item, qef_item)

struct isis_tx_queue {
	struct isis_circuit *circuit;
	void (*send_event)(struct isis_circuit *circuit,
			   struct isis_lsp *, enum isis_tx_type);
	struct hash *hash;
	struct thread *delayed; // Used to store any delayed send thread
	struct queue_entry_fifo_head delayed_lsp;
	struct queue_entry_fifo_head lsp_to_retransmit;
	uint32_t unacked_lsps;
	uint32_t cwin;
	uint32_t cwin_frac;
	int slow_start;

	struct thread *update;
	double rtt;
	uint delivered;
	double bw;
	double prev_bw;
	int repeat_stall;
};

void tx_schedule_send(struct isis_tx_queue_entry *e);

struct isis_tx_queue_entry {
	struct isis_lsp *lsp;
	enum isis_tx_type type;
	bool is_inflight;
	int nb_trans;
	struct thread *retry;
	struct isis_tx_queue *queue;
	struct queue_entry_fifo_head *current_fifo;
	struct qef_item fifo_entry;
	struct timeval sendtime;
	uint delivered; //Number of LSP acked at sending time
};

static unsigned tx_queue_hash_key(const void *p)
{
	const struct isis_tx_queue_entry *e = p;

	uint32_t id_key = jhash(e->lsp->hdr.lsp_id,
				ISIS_SYS_ID_LEN + 2, 0x55aa5a5a);

	return jhash_1word(e->lsp->level, id_key);
}

static bool tx_queue_hash_cmp(const void *a, const void *b)
{
	const struct isis_tx_queue_entry *ea = a, *eb = b;

	if (ea->lsp->level != eb->lsp->level)
		return false;

	if (memcmp(ea->lsp->hdr.lsp_id, eb->lsp->hdr.lsp_id,
		   ISIS_SYS_ID_LEN + 2))
		return false;

	return true;
}

struct isis_tx_queue *isis_tx_queue_new(
		struct isis_circuit *circuit,
		void(*send_event)(struct isis_circuit *circuit,
				  struct isis_lsp *,
				  enum isis_tx_type))
{
	struct isis_tx_queue *rv = XCALLOC(MTYPE_TX_QUEUE, sizeof(*rv));

	rv->circuit = circuit;
	rv->send_event = send_event;

	rv->hash = hash_create(tx_queue_hash_key, tx_queue_hash_cmp, NULL);
	queue_entry_fifo_init(&rv->delayed_lsp);
	queue_entry_fifo_init(&rv->lsp_to_retransmit);
	rv->unacked_lsps = 0;
	rv->cwin = 1;
	rv->cwin_frac = 0;
	rv->slow_start = 1;

	rv->rtt = -1;
	rv->delivered = 0;
	rv->bw = 0;
	rv->prev_bw = 0;
	rv->repeat_stall = 0;
	return rv;
}

static void tx_queue_element_free(void *element)
{
	struct isis_tx_queue_entry *e = element;

	thread_cancel(&(e->retry));

	XFREE(MTYPE_TX_QUEUE_ENTRY, e);
}

void isis_tx_queue_free(struct isis_tx_queue *queue)
{
	// Empty both queues before freeing them
	struct qef_item *item;
	while ((item = queue_entry_fifo_pop(&queue->delayed_lsp)))
		;
	while ((item = queue_entry_fifo_pop(&queue->lsp_to_retransmit)))
		;

	queue_entry_fifo_fini(&queue->delayed_lsp);
	queue_entry_fifo_fini(&queue->lsp_to_retransmit);

	hash_clean(queue->hash, tx_queue_element_free);
	hash_free(queue->hash);
	XFREE(MTYPE_TX_QUEUE, queue);
}

static struct isis_tx_queue_entry *tx_queue_find(struct isis_tx_queue *queue,
						 struct isis_lsp *lsp)
{
	struct isis_tx_queue_entry e = {
		.lsp = lsp
	};

	return hash_lookup(queue->hash, &e);
}

static int tx_resend(struct thread *thread)
{
	struct isis_tx_queue_entry *e = THREAD_ARG(thread);
	e->is_inflight = false;
	e->queue->unacked_lsps--;
	tx_schedule_send(e);
	return 0;
}

static int tx_queue_send_event(struct thread *thread)
{
	struct isis_tx_queue *queue = THREAD_ARG(thread);

	int32_t to_send = queue->cwin - queue->unacked_lsps;
	to_send = to_send > 0 ? to_send : 1; // Always send at least one packet.
	to_send = MIN(queue_entry_fifo_count(&queue->delayed_lsp), to_send);

	// Here send to fill the receive windows,...
	for (int i = 0; i < to_send; i++) {
		struct qef_item *qef =
			queue_entry_fifo_pop(&queue->delayed_lsp);
		struct isis_tx_queue_entry *e = qef->e;

		if (e->nb_trans >= 1) {
			queue->circuit->area->lsp_rxmt_count++;
		} else {
			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			TIMESPEC_TO_TIMEVAL(&e->sendtime, &ts);
			e->delivered = e->queue->delivered;
		}

		if (!e->is_inflight) {
			queue->unacked_lsps++;
			e->is_inflight = true;
		}
		// Every sent packet goes from L1 to L2
		e->current_fifo = &queue->lsp_to_retransmit;
		queue_entry_fifo_add_tail(&queue->lsp_to_retransmit,
					  &e->fifo_entry);
		e->retry = NULL;
		thread_add_timer_tv(
			master, tx_resend, e,
			&queue->circuit->remote_fp_min_lsp_trans_int,
			&e->retry);
		e->nb_trans++;

		queue->send_event(
			queue->circuit, e->lsp,
			e->type); /* Don't access e here anymore, send_event
				     might have destroyed it */
	}
	// ...then schedule next send event with delay
	queue->delayed = NULL;
	if (queue->unacked_lsps >= queue->cwin) {
		thread_add_timer_tv(
			master, tx_queue_send_event, queue,
			&queue->circuit->remote_fp_min_int_lsp_trans_int,
			&queue->delayed);
	}

	return 0;
}

void _isis_tx_queue_add(struct isis_tx_queue *queue,
			struct isis_lsp *lsp,
			enum isis_tx_type type,
			const char *func, const char *file,
			int line)
{
	if (!queue)
		return;

	if (IS_DEBUG_TX_QUEUE) {
		zlog_debug("Add LSP %s to %s queue as %s LSP. (From %s %s:%d)",
			   rawlspid_print(lsp->hdr.lsp_id),
			   queue->circuit->interface->name,
			   (type == TX_LSP_CIRCUIT_SCOPED) ?
			   "circuit scoped" : "regular",
			   func, file, line);
	}

	struct isis_tx_queue_entry *e = tx_queue_find(queue, lsp);
	if (!e) {
		e = XCALLOC(MTYPE_TX_QUEUE_ENTRY, sizeof(*e));
		e->lsp = lsp;
		e->queue = queue;

		struct isis_tx_queue_entry *inserted;
		inserted = hash_get(queue->hash, e, hash_alloc_intern);
		assert(inserted == e);
		e->is_inflight = false;
		e->nb_trans = 0;
	}
	e->fifo_entry.e = e;
	e->type = type;

	tx_schedule_send(e);
}

void tx_schedule_send(struct isis_tx_queue_entry *e)
{
	// add to delayed_lsp (check if it was not send before)
	// It it was in lsp_to_retransmit, put it back to delayed_lsp
	if (e->current_fifo != &e->queue->delayed_lsp) {
		if (e->current_fifo == &e->queue->lsp_to_retransmit) {
			queue_entry_fifo_del(&e->queue->lsp_to_retransmit,
					     &e->fifo_entry);
			thread_cancel(&e->retry);
		}
		queue_entry_fifo_add_tail(&e->queue->delayed_lsp,
					  &e->fifo_entry);
		e->current_fifo = &e->queue->delayed_lsp;
	}
	// Then schedule sending thread
	if (e->queue->delayed == NULL)
		thread_add_timer(master, tx_queue_send_event, e->queue, 0,
				 &e->queue->delayed);
}

void _isis_tx_queue_del(struct isis_tx_queue *queue, struct isis_lsp *lsp,
			const char *func, const char *file, int line)
{
	if (!queue)
		return;
	//TODO: check if lsp seqno is not null here
	struct isis_tx_queue_entry *e = tx_queue_find(queue, lsp);
	if (!e)
		return;

	if (IS_DEBUG_TX_QUEUE) {
		zlog_debug("Remove LSP %s from %s queue. (From %s %s:%d)",
			   rawlspid_print(lsp->hdr.lsp_id),
			   queue->circuit->interface->name,
			   func, file, line);
	}

	if (e->is_inflight) {
		queue->unacked_lsps--;
		e->is_inflight = false;
		if (queue->unacked_lsps < queue->cwin) {
			thread_cancel(&queue->delayed);
			thread_add_timer(master, tx_queue_send_event, queue, 0,
					 &queue->delayed);
		}
	}

	thread_cancel(&(e->retry));
	queue_entry_fifo_del(e->current_fifo, &e->fifo_entry);

	hash_release(queue->hash, e);
	XFREE(MTYPE_TX_QUEUE_ENTRY, e);
}

static inline double tv_to_sec(struct timeval *tv) {
	return (double) tv->tv_sec + (double) tv->tv_usec / 1000000;
}

static int isis_tx_update(struct thread *thread)
{
	struct isis_tx_queue *queue = THREAD_ARG(thread);

	if (queue->bw < 1.25 * queue->prev_bw) { // We are in the startup phase, so it
					  // should grow, if not, it means we found a bottleneck
		queue->repeat_stall++;
//		return 0; // Don't reschedule update
	} else {
		//We increase, so we are still in growing phase
		queue->repeat_stall = 0;
	}
	if (queue->repeat_stall > 2) {
		zlog_debug(
			"End of startup phase, cwin is %d, RTT is %e, bw is %e",
			queue->cwin, queue->rtt, queue->bw);
		queue->slow_start = false;
		return 0; //Don't reschedule update
	}
	queue->prev_bw = queue->bw;

	struct timeval tv_rtt;
	microseconds_to_timeval((uint32_t) (queue->rtt * 1000000LL), &tv_rtt);
	thread_add_timer_tv(master, isis_tx_update, queue, &tv_rtt, &queue->update);
	return 0;
}

void isis_tx_measures(struct isis_lsp **measurements, uint32_t count,
		      struct isis_tx_queue *queue)
{
	if (!queue)
		return;
	struct timespec ts;
	struct timeval tv;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	TIMESPEC_TO_TIMEVAL(&tv, &ts);
	double min_rtt = -1;
	double max_bw = 0; // LSP/s for now
	
	for (uint32_t i = 0; i < count; i++) {
		struct timeval rtt;
		struct isis_lsp *lsp = measurements[i];

		// We store every sending info in the queue entry
		struct isis_tx_queue_entry *e = tx_queue_find(queue, lsp);
		if (!e || e->nb_trans != 1)
			continue;

		queue->delivered++;

		timersub(&tv, &e->sendtime, &rtt);

		//BW estimate
		double bw = (double) (queue->delivered - e->delivered) / tv_to_sec(&rtt);

		max_bw = MAX(max_bw, bw);

		if (min_rtt < 0) {
			min_rtt = tv_to_sec(&rtt);
		} else {
			min_rtt = MIN(min_rtt, tv_to_sec(&rtt));
		}

		if (queue->slow_start) {
			queue->cwin++;
			queue->cwin =
				MIN(queue->circuit->remote_fp_rcv, queue->cwin);
		} else {
			queue->cwin_frac++;
			if (queue->cwin_frac >= queue->cwin) {
				queue->cwin_frac = 0;
				queue->cwin++;
				queue->cwin = MIN(queue->circuit->remote_fp_rcv,
						  queue->cwin);
			}
		}
	}
	if (min_rtt > 0) {
		if (queue->rtt < 0) {
			thread_add_timer(master, isis_tx_update, queue, 0,
					 &queue->update);
			queue->rtt = min_rtt;
		} else {
			queue->rtt = MIN(queue->rtt, min_rtt);
		}
	}
	queue->bw = MAX(queue->bw, max_bw);
}

unsigned long isis_tx_queue_len(struct isis_tx_queue *queue)
{
	if (!queue)
		return 0;

	return hashcount(queue->hash);
}

void isis_tx_queue_clean(struct isis_tx_queue *queue)
{
	// First empty sending lists
	struct qef_item *item;
	while ((item = queue_entry_fifo_pop(&queue->delayed_lsp)))
		;
	while ((item = queue_entry_fifo_pop(&queue->lsp_to_retransmit)))
		;

	queue->unacked_lsps = 0;

	hash_clean(queue->hash, tx_queue_element_free);
}
