/*
 * IS-IS Rout(e)ing protocol - isis_csm.c
 *                             IS-IS circuit state machine
 * Copyright (C) 2001,2002    Sampo Saaristo
 *                            Tampere University of Technology
 *                            Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <pcap.h>
#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "if.h"
#include "linklist.h"
#include "command.h"
#include "thread.h"
#include "hash.h"
#include "prefix.h"
#include "stream.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_network.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_dr.h"
#include "isisd/isisd.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_events.h"
#include "isisd/isis_errors.h"

static const char *const csm_statestr[] = {"C_STATE_NA", "C_STATE_INIT",
				     "C_STATE_CONF", "C_STATE_UP"};

#define STATE2STR(S) csm_statestr[S]

static const char *const csm_eventstr[] = {
	"NO_STATE",     "ISIS_ENABLE",    "IF_UP_FROM_Z",
	"ISIS_DISABLE", "IF_DOWN_FROM_Z",
};

#define EVENT2STR(E) csm_eventstr[E]

static void add_lsp(struct isis_circuit *circuit) {
	char cwd[500];
	getcwd(cwd, sizeof(cwd));
	zlog_debug("Curdir is %s", cwd);
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline("trace_lsp.pcap", error_buffer);
	if (handle == NULL) {
		zlog_debug("Can't open pcap");
	}
	struct pcap_pkthdr h;
	const uint8_t *data = NULL;
	data = pcap_next(handle, &h);

	while (data != NULL) {
		stream_reset(circuit->rcv_stream);
		stream_write(circuit->rcv_stream, data + 14 + 3,
			     h.len - 14 - 3);
		char dst[8];
		stream_get(dst, circuit->rcv_stream, 8); // Remove ISIS header

		struct isis_lsp_hdr hdr = {}; // Get PDU Header

		hdr.pdu_len = stream_getw(circuit->rcv_stream);
		hdr.rem_lifetime = stream_getw(circuit->rcv_stream);
		stream_get(hdr.lsp_id, circuit->rcv_stream, sizeof(hdr.lsp_id));
		hdr.seqno = stream_getl(circuit->rcv_stream);
		hdr.checksum = stream_getw(circuit->rcv_stream);
		hdr.lsp_bits = stream_getc(circuit->rcv_stream);

		struct isis_tlvs *tlvs = NULL;
		const char *error_log;
		if (isis_unpack_tlvs(STREAM_READABLE(circuit->rcv_stream),
				     circuit->rcv_stream, &tlvs, &error_log)) {
			zlog_debug("Error unpacking TLVs %s", error_log);
		}

		struct isis_lsp *lsp0 = NULL;
		if (LSP_FRAGMENT(hdr.lsp_id) != 0) {
			uint8_t lspid[ISIS_SYS_ID_LEN + 2];
			memcpy(lspid, hdr.lsp_id, ISIS_SYS_ID_LEN + 1);
			lsp0 = lsp_search(&circuit->area->lspdb[2 - 1], lspid);
			if (lsp0 == NULL) {
				data = pcap_next(handle, &h);
				continue;
			}
		}

		struct isis_lsp *lsp =
			lsp_new_from_recv(&hdr, tlvs, circuit->rcv_stream, lsp0,
					  circuit->area, 2);
		tlvs = NULL;
		lsp_insert(&circuit->area->lspdb[2 - 1], lsp);
		data = pcap_next(handle, &h);
	}
}

struct isis_circuit *
isis_csm_state_change(int event, struct isis_circuit *circuit, void *arg)
{
	int old_state;
	struct isis *isis = NULL;
	struct isis_area *area = NULL;

	old_state = circuit ? circuit->state : C_STATE_NA;
	if (IS_DEBUG_EVENTS)
		zlog_debug("CSM_EVENT: %s", EVENT2STR(event));

	switch (old_state) {
	case C_STATE_NA:
		if (circuit)
			zlog_warn("Non-null circuit while state C_STATE_NA");
		assert(circuit == NULL);
		switch (event) {
		case ISIS_ENABLE:
			area = arg;

			circuit = isis_circuit_new(area->isis);
			isis_circuit_configure(circuit, area);
			circuit->state = C_STATE_CONF;
			break;
		case IF_UP_FROM_Z:
			isis = isis_lookup_by_vrfid(((struct interface *)arg)->vrf_id);
			if (isis == NULL) {
				zlog_warn(
					" %s : ISIS routing instance not found",
					__func__);
				break;
			}
			circuit = isis_circuit_new(isis);
			isis_circuit_if_add(circuit, (struct interface *)arg);
			listnode_add(isis->init_circ_list, circuit);
			circuit->state = C_STATE_INIT;
			break;
		case ISIS_DISABLE:
			zlog_warn("circuit already disabled");
			break;
		case IF_DOWN_FROM_Z:
			zlog_warn("circuit already disconnected");
			break;
		}
		break;
	case C_STATE_INIT:
		assert(circuit);
		switch (event) {
		case ISIS_ENABLE:
			isis_circuit_configure(circuit,
					       (struct isis_area *)arg);
			if (isis_circuit_up(circuit) != ISIS_OK) {
				isis_circuit_deconfigure(
					circuit, (struct isis_area *)arg);
				break;
			}
			circuit->state = C_STATE_UP;
			isis_event_circuit_state_change(circuit, circuit->area,
							1);
			listnode_delete(circuit->isis->init_circ_list,
					circuit);
			break;
		case IF_UP_FROM_Z:
			assert(circuit);
			zlog_warn("circuit already connected");
			break;
		case ISIS_DISABLE:
			zlog_warn("circuit already disabled");
			break;
		case IF_DOWN_FROM_Z:
			isis_circuit_if_del(circuit, (struct interface *)arg);
			listnode_delete(circuit->isis->init_circ_list,
					circuit);
			isis_circuit_del(circuit);
			circuit = NULL;
			break;
		}
		break;
	case C_STATE_CONF:
		assert(circuit);
		switch (event) {
		case ISIS_ENABLE:
			zlog_warn("circuit already enabled");
			break;
		case IF_UP_FROM_Z:
			isis_circuit_if_add(circuit, (struct interface *)arg);
			if (isis_circuit_up(circuit) != ISIS_OK) {
				isis_circuit_if_del(circuit, (struct interface *)arg);
				flog_err(
					EC_ISIS_CONFIG,
					"Could not bring up %s because of invalid config.",
					circuit->interface->name);
				break;
			}
			if (!strcmp(( (struct interface *)arg)->name, "lo")) {
				zlog_debug("Interface lo -- adding LSPs");
				add_lsp(circuit);
			}

			circuit->state = C_STATE_UP;
			isis_event_circuit_state_change(circuit, circuit->area,
							1);
			break;
		case ISIS_DISABLE:
			isis_circuit_deconfigure(circuit,
						 (struct isis_area *)arg);
			isis_circuit_del(circuit);
			circuit = NULL;
			break;
		case IF_DOWN_FROM_Z:
			zlog_warn("circuit already disconnected");
			break;
		}
		break;
	case C_STATE_UP:
		assert(circuit);
		switch (event) {
		case ISIS_ENABLE:
			zlog_warn("circuit already configured");
			break;
		case IF_UP_FROM_Z:
			zlog_warn("circuit already connected");
			break;
		case ISIS_DISABLE:
			isis = circuit->isis;
			isis_circuit_down(circuit);
			isis_circuit_deconfigure(circuit,
						 (struct isis_area *)arg);
			circuit->state = C_STATE_INIT;
			isis_event_circuit_state_change(
				circuit, (struct isis_area *)arg, 0);
			listnode_add(isis->init_circ_list, circuit);
			break;
		case IF_DOWN_FROM_Z:
			isis_circuit_down(circuit);
			isis_circuit_if_del(circuit, (struct interface *)arg);
			circuit->state = C_STATE_CONF;
			isis_event_circuit_state_change(circuit, circuit->area,
							0);
			break;
		}
		break;

	default:
		zlog_warn("Invalid circuit state %d", old_state);
	}

	if (IS_DEBUG_EVENTS)
		zlog_debug("CSM_STATE_CHANGE: %s -> %s ", STATE2STR(old_state),
			   circuit ? STATE2STR(circuit->state)
				   : STATE2STR(C_STATE_NA));

	return circuit;
}
