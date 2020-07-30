#ifndef FE_STATE_H
#define FE_STATE_H

/* Message types that are sent by the front-end */
typedef enum {
    FE_MESSAGE_TYPE_UNKNOWN = '_',
    /* There is no message type for "special" messages, they just start with a length int32, the first (high) byte of which is 0. */
    FE_MESSAGE_TYPE_SPECIAL = 0,
    FE_MESSAGE_TYPE_BIND = 'B',    
    FE_MESSAGE_TYPE_CLOSE = 'C',
    FE_MESSAGE_TYPE_COPY_DATA = 'd',
    FE_MESSAGE_TYPE_COPY_DONE = 'c',
    FE_MESSAGE_TYPE_COPY_FAIL = 'f',
    FE_MESSAGE_TYPE_DESCRIBE = 'D',
    FE_MESSAGE_TYPE_EXECUTE = 'E',
    FE_MESSAGE_TYPE_FLUSH = 'H',
    FE_MESSAGE_TYPE_FUNCTION_CALL = 'F',
    FE_MESSAGE_TYPE_PARSE = 'P',
    FE_MESSAGE_TYPE_PASSWORD_MESSAGE = 'p',
    FE_MESSAGE_TYPE_QUERY = 'Q',
    FE_MESSAGE_TYPE_SYNC = 'S',
    FE_MESSAGE_TYPE_TERMINATE = 'X',
} fe_message_type_t;


typedef struct {
    fe_message_type_t message_type;
    union {
        generic_message_state_t generic;
        special_message_state_t special;
    } message_state;
} fe_state_t;

static void fe_state_init(fe_state_t *state) {
    ASSERT(state);
    state->message_type = FE_MESSAGE_TYPE_UNKNOWN;
    generic_message_state_init(&state->message_state.generic);
}

static void fe_state_on_new_message(uint16_t fe_port, fe_state_t *state, uint8_t byte) {
    ASSERT(state);
    switch ((fe_message_type_t)byte) {
        case FE_MESSAGE_TYPE_UNKNOWN:
            LOG("Unexpected unknown-message byte sent by frontend on fe_port %u", fe_port);
            break;
        
        case FE_MESSAGE_TYPE_SPECIAL:
            special_message_state_on_new_message(&state->message_state.special, fe_port, SENDER_TYPE_FE, "[special]");
            break;

        case FE_MESSAGE_TYPE_BIND:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "Bind");
            break;
        
        case FE_MESSAGE_TYPE_CLOSE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "Close");
            break;

        case FE_MESSAGE_TYPE_COPY_DATA:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "CopyData");
            break;

        case FE_MESSAGE_TYPE_COPY_DONE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "CopyDone");
            break;

        case FE_MESSAGE_TYPE_COPY_FAIL:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "CopyFail");
            break;

        case FE_MESSAGE_TYPE_DESCRIBE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "Describe");
            break;

        case FE_MESSAGE_TYPE_EXECUTE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "Execute");
            break;

        case FE_MESSAGE_TYPE_FLUSH:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "Flush");
            break;

        case FE_MESSAGE_TYPE_FUNCTION_CALL:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "Call");
            break;

        case FE_MESSAGE_TYPE_PARSE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "Parse");
            break;

        case FE_MESSAGE_TYPE_PASSWORD_MESSAGE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "PasswordMessage");
            break;

        case FE_MESSAGE_TYPE_QUERY:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "Query");
            break;
        
        case FE_MESSAGE_TYPE_SYNC:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "Sync");
            break;

        case FE_MESSAGE_TYPE_TERMINATE:            
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_FE, "Terminate");
            break;
            
        default:
            LOG("Unexpected new-message byte 0x%02x sent by frontend on fe_port %u", (unsigned int)byte, fe_port);
            return;
    }
    
    state->message_type = (fe_message_type_t)byte;
}

static inline void fe_state_on_byte(uint16_t fe_port, fe_state_t *state, uint8_t byte, FILE *trace_fp) {
    ASSERT(state);
    ASSERT(trace_fp);
    
    switch (state->message_type) {
        case FE_MESSAGE_TYPE_UNKNOWN:
            fe_state_on_new_message(fe_port, state, byte);
            break;
    
        case FE_MESSAGE_TYPE_SPECIAL:
            if (special_message_state_on_byte(&state->message_state.special, fe_port, byte, trace_fp)) {
                state->message_type = FE_MESSAGE_TYPE_UNKNOWN;
            }
            break;
        
        case FE_MESSAGE_TYPE_BIND:
        case FE_MESSAGE_TYPE_CLOSE:
        case FE_MESSAGE_TYPE_COPY_DATA:
        case FE_MESSAGE_TYPE_COPY_DONE:
        case FE_MESSAGE_TYPE_COPY_FAIL:
        case FE_MESSAGE_TYPE_DESCRIBE:
        case FE_MESSAGE_TYPE_EXECUTE:
        case FE_MESSAGE_TYPE_FLUSH:
        case FE_MESSAGE_TYPE_FUNCTION_CALL:
        case FE_MESSAGE_TYPE_PARSE:
        case FE_MESSAGE_TYPE_PASSWORD_MESSAGE:
        case FE_MESSAGE_TYPE_QUERY:
        case FE_MESSAGE_TYPE_SYNC:
        case FE_MESSAGE_TYPE_TERMINATE:
            if (generic_message_state_on_byte(&state->message_state.generic, fe_port, byte, trace_fp)) {
                state->message_type = FE_MESSAGE_TYPE_UNKNOWN;                
            }
            break;
    }
}




#endif
