#ifndef SPECIAL_MESSAGE_STATE_H
#define SPECIAL_MESSAGE_STATE_H

typedef enum {
    SPECIAL_MESSAGE_TYPE_UNKNOWN,
    SPECIAL_MESSAGE_TYPE_CANCEL_REQUEST,
    SPECIAL_MESSAGE_TYPE_SSL_REQUEST,
    SPECIAL_MESSAGE_TYPE_STARTUP_MESSAGE,
} special_message_type_t;


typedef struct {    
    special_message_type_t message_type;
    generic_message_state_t generic_message_state;
} special_message_state_t;

static bool special_message_state_on_byte(special_message_state_t *state, uint16_t fe_port, uint8_t byte, FILE *trace_fp) {
    return generic_message_state_on_byte(&state->generic_message_state, fe_port, byte, trace_fp);
}

static void special_message_state_on_new_message(special_message_state_t *state,
                                                 uint16_t fe_port,
                                                 sender_type_t sender_type,
                                                 const char *message_name) {
    ASSERT(state);
    state->message_type = SPECIAL_MESSAGE_TYPE_UNKNOWN;
    generic_message_state_on_new_message(&state->generic_message_state, fe_port, sender_type, message_name);
    
    /* Special messages have no type byte, the first byte is part of the length, and it's always 0. */
    special_message_state_on_byte(state, fe_port, 0, stderr);
}


#endif
