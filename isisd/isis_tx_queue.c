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
};

void tx_schedule_send(struct isis_tx_queue_entry *e);

struct isis_tx_queue_entry {
	struct isis_lsp *lsp;
	enum isis_tx_type type;
	bool is_retry;
	struct thread *retry;
	struct isis_tx_queue *queue;
	struct queue_entry_fifo_head *current_fifo;
	struct qef_item fifo_entry;
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
	tx_schedule_send(e);
	return 0;
}

static int tx_queue_send_event(struct thread *thread)
{
	struct isis_tx_queue *queue = THREAD_ARG(thread);

	int32_t to_send = queue->circuit->remote_fp_rcv - queue->unacked_lsps;
	to_send = to_send > 0 ? to_send : 1; // Always send at least one packet.
	to_send = MIN(queue_entry_fifo_count(&queue->delayed_lsp), to_send);

	// Here send to fill the receive windows,...
	for (int i = 0; i < to_send; i++) {
		struct qef_item *qef =
			queue_entry_fifo_pop(&queue->delayed_lsp);
		struct isis_tx_queue_entry *e = qef->e;

		if (e->is_retry) {
			queue->circuit->area->lsp_rxmt_count++;
		} else {
			queue->unacked_lsps++;
			e->is_retry = true;
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

		queue->send_event(
			queue->circuit, e->lsp,
			e->type); /* Don't access e here anymore, send_event
				     might have destroyed it */
	}
	// ...then schedule next send event with delay
	queue->delayed = NULL;
	if (queue_entry_fifo_count(&queue->delayed_lsp) != 0) {
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
	}
	e->fifo_entry.e = e;
	e->type = type;

	tx_schedule_send(e);

	e->is_retry = false;
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

	struct isis_tx_queue_entry *e = tx_queue_find(queue, lsp);
	if (!e)
		return;

	if (IS_DEBUG_TX_QUEUE) {
		zlog_debug("Remove LSP %s from %s queue. (From %s %s:%d)",
			   rawlspid_print(lsp->hdr.lsp_id),
			   queue->circuit->interface->name,
			   func, file, line);
	}

	if (e->is_retry) {
		queue->unacked_lsps--;
		if (queue->unacked_lsps < queue->circuit->remote_fp_rcv) {
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
