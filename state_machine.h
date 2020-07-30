#ifndef STATE_MACHINE_H
#define STATE_MACHINE_H

#include "int32_state.h"
#include "message_trace_buffer.h"
#include "generic_message_state.h"
#include "special_message_state.h"
#include "fe_state.h"
#include "be_state.h"
#include "connection_state.h"


typedef struct {
    connection_state_t connections[0xffff];
} pgtrace_state_t;

pgtrace_state_t global_state;

static connection_state_t *get_first_connection_state() {
    return global_state.connections;
}

static connection_state_t *get_end_connection_state() {
    return global_state.connections + (sizeof(global_state.connections)/sizeof(global_state.connections[0]));
}

static connection_state_t *get_connection_state(uint16_t fe_port) {
    return &global_state.connections[fe_port];
}

static void state_machine_init() {
    memset(global_state.connections, 0, sizeof(global_state.connections));
    connection_state_t *cs_p = get_first_connection_state();
    connection_state_t *cs_end = get_end_connection_state();
    for (; cs_p < cs_end; ++cs_p) {
        connection_state_init(cs_p);
    }
}


static inline void state_machine_fe_next(uint16_t sender_port,
                                         uint16_t receiver_port,
                                         uint8_t byte,
                                         size_t packet_payload_size,
                                         FILE *trace_fp) {
    connection_state_on_fe_byte(sender_port, get_connection_state(sender_port), byte, trace_fp);
}

static inline void state_machine_be_next(uint16_t sender_port,
                                         uint16_t receiver_port,
                                         uint8_t byte,
                                         size_t packet_payload_size,
                                         FILE *trace_fp) {
    connection_state_on_be_byte(receiver_port, get_connection_state(receiver_port), byte, packet_payload_size, trace_fp);    
}

#endif
