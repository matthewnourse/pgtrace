#ifndef CONNECTION_STATE_H
#define CONNECTION_STATE_H

typedef struct {
    fe_state_t fe;    
    be_state_t be;
} connection_state_t;

static void connection_state_init(connection_state_t *connection) {
    ASSERT(connection);
    fe_state_init(&connection->fe);
    be_state_init(&connection->be);
}

static inline void connection_state_on_fe_byte(uint16_t fe_port,
                                               connection_state_t *state,
                                               uint8_t byte,                                        
                                               FILE *trace_fp) {
    ASSERT(state);
    fe_state_on_byte(fe_port, &state->fe, byte, trace_fp);
}

static inline void connection_state_on_be_byte(uint16_t fe_port,
                                               connection_state_t *state,
                                               uint8_t byte,
                                               size_t packet_payload_size,
                                               FILE *trace_fp) {
    ASSERT(state);
    be_state_on_byte(fe_port, &state->be, byte, packet_payload_size, trace_fp);
}


#endif
