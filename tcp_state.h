#ifndef TCP_STATE_H
#define TCP_STATE_H

typedef struct {
    u_int min_seq;
    u_int max_seq;
} tcp_state_channel_t;

typedef struct {
    /* FE -> BE TCP states */
    tcp_state_channel_t fe[0xffff];
    
    /* BE -> FE TCP states */
    tcp_state_channel_t be[0xffff];    
} tcp_state_t;


static void tcp_state_init(tcp_state_t *state) {
    ASSERT(state);
    memset(state, 0, sizeof(*state));
}

static bool tcp_state_is_packet_in_sequence(tcp_state_channel_t *channels,
                                            const char *sender_name,
                                            uint16_t fe_port,
                                            u_int seq,
                                            size_t payload_size) {
    ASSERT(channels);
    tcp_state_channel_t *channel = &channels[fe_port];
    if ((0 == channel->min_seq) || ((seq >= channel->min_seq) && (seq <= channel->max_seq))) {  
        channel->min_seq = seq + payload_size;
        if (channel->max_seq < channel->min_seq) {
            channel->max_seq = channel->min_seq;
        }
        
        return true;
    }
    
    if (seq < channel->min_seq) {
        LOG("Duplicate %s packet (seq=%u min_seq=%u) detected on port=%u", sender_name, seq, channel->min_seq, fe_port);
        return false;
    }
    
    if (seq > channel->max_seq) {
        LOG("Out-of-order %s packet (seq=%u max_seq=%u) detected on port=%u", sender_name, seq, channel->max_seq, fe_port);
        return false;
    }
    
    ASSERT(false);
    return false;
}

static void tcp_state_set_seq_range(tcp_state_channel_t *channels, uint16_t fe_port, u_int ack, u_short window) {
    ASSERT(channels);
    tcp_state_channel_t *channel = &channels[fe_port];
    channel->min_seq = ack;
    channel->max_seq = ack + window;
}

static bool tcp_state_is_fe_packet_in_sequence(tcp_state_t *state,
                                               uint16_t fe_port,
                                               u_int seq,
                                               size_t payload_size) {
    ASSERT(state);
    return tcp_state_is_packet_in_sequence(state->fe, "fe", fe_port, seq, payload_size);
}

static bool tcp_state_is_be_packet_in_sequence(tcp_state_t *state,
                                               uint16_t fe_port,
                                               u_int seq,
                                               size_t payload_size) {
    ASSERT(state);
    return tcp_state_is_packet_in_sequence(state->be, "be", fe_port, seq, payload_size);
}

static void tcp_state_set_fe_seq_range(tcp_state_t *state, uint16_t fe_port, u_int ack, u_short window) {
    ASSERT(state);
    tcp_state_set_seq_range(state->fe, fe_port, ack, window);
}

static void tcp_state_set_be_seq_range(tcp_state_t *state, uint16_t fe_port, u_int ack, u_short window) {
    ASSERT(state);
    tcp_state_set_seq_range(state->be, fe_port, ack, window);
}


#endif
