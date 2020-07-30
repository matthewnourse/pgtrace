#ifndef GENERIC_MESSAGE_STATE_H
#define GENERIC_MESSAGE_STATE_H

/* The maximum length that a message is likely to be.  If this is exceeded then we're likely out of sync
   due to a dropped packet or bug. */
#define GENERIC_MESSAGE_STATE_MAX_LENGTH (1024*1024)

typedef enum {
    GENERIC_MESSAGE_STATE_TYPE_BEFORE_MESSAGE,
    GENERIC_MESSAGE_STATE_TYPE_IN_LENGTH,
    GENERIC_MESSAGE_STATE_TYPE_IN_PAYLOAD,
} generic_message_state_type_t;

typedef struct {
    generic_message_state_type_t state_type;
    int32_state_t length_state;
    int32_t message_bytes_read;
    message_trace_buffer_t buf;
} generic_message_state_t;

static void generic_message_state_init(generic_message_state_t *state) {
    ASSERT(state);
    state->state_type = GENERIC_MESSAGE_STATE_TYPE_BEFORE_MESSAGE;
    int32_state_init(&state->length_state);
    state->message_bytes_read = 0;
    message_trace_buffer_init(&state->buf);
}

static void generic_message_state_on_new_message(generic_message_state_t *state,
                                                 uint16_t fe_port,
                                                 sender_type_t sender_type,
                                                 const char *message_name) {
    ASSERT(state);
    generic_message_state_init(state);
    state->state_type = GENERIC_MESSAGE_STATE_TYPE_IN_LENGTH;
    message_trace_buffer_write_start(&state->buf, fe_port, sender_type, message_name);
}

static bool generic_message_state_on_length_complete(generic_message_state_t *state, uint16_t fe_port, FILE *trace_fp) {
    ASSERT(state);
    ASSERT(trace_fp);

    int32_t length = int32_state_value_get(&state->length_state);
    if (length > GENERIC_MESSAGE_STATE_MAX_LENGTH) {
        LOG("Max length exceeded.  fe_port=%u  length=%d  max_length=%d", fe_port, length,
            GENERIC_MESSAGE_STATE_MAX_LENGTH);
        return true;
    }
    
    message_trace_buffer_write_length_field(&state->buf, length);
    state->state_type = GENERIC_MESSAGE_STATE_TYPE_IN_PAYLOAD;
    
    /* If there is no payload then bow out now. */
    if (state->message_bytes_read >= length) {
        return true;
    }
    
    message_trace_buffer_write_space(&state->buf);
    return false;
}

static inline bool generic_message_state_on_byte(generic_message_state_t *state, uint16_t fe_port, uint8_t byte, FILE *trace_fp) {
    ASSERT(state);
    ASSERT(trace_fp);
    
    switch (state->state_type) {
        case GENERIC_MESSAGE_STATE_TYPE_BEFORE_MESSAGE:
            ASSERT(false);
            return false;
        
        case GENERIC_MESSAGE_STATE_TYPE_IN_LENGTH:
            state->message_bytes_read++;
            if (int32_state_on_byte(&state->length_state, byte)) {
                return generic_message_state_on_length_complete(state, fe_port, trace_fp);
            }
            
            if (int32_state_is_high_byte_set(&state->length_state)) {
                LOG("generic_message length high byte is set.  fe_port=%u  byte=0x%02x", fe_port, byte);
                return true;
            }
                        
            return false;
        
        case GENERIC_MESSAGE_STATE_TYPE_IN_PAYLOAD:
            message_trace_buffer_write_byte_as_safe_char(&state->buf, byte);
            state->message_bytes_read++;
            if (state->message_bytes_read >= int32_state_value_get(&state->length_state)) {
                message_trace_buffer_print(&state->buf, trace_fp);
                return true;
            }
            
            return false;
    }
    
    ASSERT(false);
    return false;
}



#endif
