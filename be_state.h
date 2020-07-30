#ifndef BE_STATE_H
#define BE_STATE_H

/* Message types that are sent by the back-end */
typedef enum {
    BE_MESSAGE_TYPE_UNKNOWN = '_',
    BE_MESSAGE_TYPE_AUTHENTICATION = 'R',
    BE_MESSAGE_TYPE_KEY_DATA = 'K',
    BE_MESSAGE_TYPE_BIND_COMPLETE = '2',
    BE_MESSAGE_TYPE_CLOSE_COMPLETE = '3',
    BE_MESSAGE_TYPE_COMMAND_COMPLETE = 'C',
    BE_MESSAGE_TYPE_COPY_DATA = 'd',
    BE_MESSAGE_TYPE_COPY_DONE = 'c',
    BE_MESSAGE_TYPE_COPY_FAIL = 'f',
    BE_MESSAGE_TYPE_COPY_IN_RESPONSE = 'G',
    BE_MESSAGE_TYPE_COPY_OUT_RESPONSE = 'H',
    BE_MESSAGE_TYPE_COPY_BOTH_RESPONSE = 'W',
    BE_MESSAGE_TYPE_DATA_ROW = 'D',
    BE_MESSAGE_TYPE_EMPTY_QUERY_RESPONSE = 'I',
    BE_MESSAGE_TYPE_ERROR_RESPONSE = 'E',
    BE_MESSAGE_TYPE_FUNCTION_CALL_RESPONSE = 'V',
    BE_MESSAGE_TYPE_NEGOTIATE_PROTOCOL_VERSION = 'v',
    BE_MESSAGE_TYPE_NO_DATA = 'n',
    BE_MESSAGE_TYPE_NOTICE_RESPONSE = 'N',
    BE_MESSAGE_TYPE_NOTIFICATION_RESPONSE = 'A',
    BE_MESSAGE_TYPE_PARAMETER_DESCRIPTION = 't',
    BE_MESSAGE_TYPE_PARAMETER_STATUS = 'S',
    BE_MESSAGE_TYPE_PARSE_COMPLETE = '1',
    BE_MESSAGE_TYPE_PORTAL_SUSPENDED = 's',
    BE_MESSAGE_TYPE_READY_FOR_QUERY = 'Z',
    BE_MESSAGE_TYPE_ROW_DESCRIPTION = 'T',
} be_message_type_t;


typedef struct {
    be_message_type_t message_type;
    union {
        generic_message_state_t generic;
    } message_state;
} be_state_t;

static void be_state_init(be_state_t *state) {
    ASSERT(state);
    state->message_type = BE_MESSAGE_TYPE_UNKNOWN;
    generic_message_state_init(&state->message_state.generic);
}

static void be_state_on_new_message(uint16_t fe_port,
                                    be_state_t *state,
                                    uint8_t byte,
                                    size_t packet_payload_size,
                                    FILE *trace_fp) {
    ASSERT(state);
    ASSERT(trace_fp);
    
    /* The SSLRequest response is either N or S in a single packet.  Incredibly, these letters are used by other message types
       so we need to give them special handling here. */
    if (1 == packet_payload_size) {
        message_trace_buffer_t buf;
        message_trace_buffer_init(&buf);
        if ('N' == byte) {
            message_trace_buffer_write_start(&buf, fe_port, SENDER_TYPE_BE, "SSLResponseNo");
            message_trace_buffer_print(&buf, trace_fp);
            return;
        }
        
        if ('S' == byte) {
            message_trace_buffer_write_start(&buf, fe_port, SENDER_TYPE_BE, "SSLResponseYes");
            message_trace_buffer_print(&buf, trace_fp);
            ASSERT(false);
            return;
        }
    }
    
    switch ((be_message_type_t)byte) {
        case BE_MESSAGE_TYPE_UNKNOWN:
            LOG("Unexpected unknown-message byte sent by backend to fe_port %u", fe_port);
            break;
        
        case BE_MESSAGE_TYPE_AUTHENTICATION:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "Authentication");
            break;
            
        case BE_MESSAGE_TYPE_KEY_DATA:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "BackendKeyData");
            break;

        case BE_MESSAGE_TYPE_BIND_COMPLETE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "BindComplete");
            break;

        case BE_MESSAGE_TYPE_CLOSE_COMPLETE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "CloseComplete");
            break;

        case BE_MESSAGE_TYPE_COMMAND_COMPLETE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "CommandComplete");
            break;

        case BE_MESSAGE_TYPE_COPY_DATA:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "CopyData");
            break;

        case BE_MESSAGE_TYPE_COPY_DONE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "CopyDone");
            break;

        case BE_MESSAGE_TYPE_COPY_FAIL:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "CopyFail");
            break;

        case BE_MESSAGE_TYPE_COPY_IN_RESPONSE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "CopyIn");
            break;

        case BE_MESSAGE_TYPE_COPY_OUT_RESPONSE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "CopyOut");
            break;

        case BE_MESSAGE_TYPE_COPY_BOTH_RESPONSE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "CopyBoth");
            break;

        case BE_MESSAGE_TYPE_DATA_ROW:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "DataRow");
            break;

        case BE_MESSAGE_TYPE_EMPTY_QUERY_RESPONSE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "QueryResponse");
            break;

        case BE_MESSAGE_TYPE_ERROR_RESPONSE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "ErrorResponse");
            break;

        case BE_MESSAGE_TYPE_FUNCTION_CALL_RESPONSE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "CallResponse");
            break;

        case BE_MESSAGE_TYPE_NEGOTIATE_PROTOCOL_VERSION:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "NegotiateProtocolVersion");
            break;

        case BE_MESSAGE_TYPE_NO_DATA:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "NoData");
            break;

        case BE_MESSAGE_TYPE_NOTICE_RESPONSE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "NoticeResponse");
            break;

        case BE_MESSAGE_TYPE_NOTIFICATION_RESPONSE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "NotificationResponse");
            break;

        case BE_MESSAGE_TYPE_PARAMETER_DESCRIPTION:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "ParameterDescription");
            break;

        case BE_MESSAGE_TYPE_PARAMETER_STATUS:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "ParameterStatus");
            break;

        case BE_MESSAGE_TYPE_PARSE_COMPLETE:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "ParseComplete");
            break;

        case BE_MESSAGE_TYPE_PORTAL_SUSPENDED:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "PortalSuspended");
            break;

        case BE_MESSAGE_TYPE_READY_FOR_QUERY:
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "ReadyForQuery");
            break;

        case BE_MESSAGE_TYPE_ROW_DESCRIPTION:                    
            generic_message_state_on_new_message(&state->message_state.generic, fe_port, SENDER_TYPE_BE, "RowDescription");
            break;

        default:
            LOG("Unexpected new-message byte 0x%02x sent by backend to fe_port %u", (unsigned int)byte, fe_port);
            return;
    }
    
    state->message_type = (be_message_type_t)byte;
}

static inline void be_state_on_byte(uint16_t fe_port, be_state_t *state, uint8_t byte, size_t packet_payload_size, FILE *trace_fp) {
    ASSERT(state);
    ASSERT(trace_fp);
    
    switch (state->message_type) {
        case BE_MESSAGE_TYPE_UNKNOWN:
            be_state_on_new_message(fe_port, state, byte, packet_payload_size, trace_fp);
            break;
    
        case BE_MESSAGE_TYPE_AUTHENTICATION:
        case BE_MESSAGE_TYPE_KEY_DATA:
        case BE_MESSAGE_TYPE_BIND_COMPLETE:
        case BE_MESSAGE_TYPE_CLOSE_COMPLETE:
        case BE_MESSAGE_TYPE_COMMAND_COMPLETE:
        case BE_MESSAGE_TYPE_COPY_DATA:
        case BE_MESSAGE_TYPE_COPY_DONE:
        case BE_MESSAGE_TYPE_COPY_FAIL:
        case BE_MESSAGE_TYPE_COPY_IN_RESPONSE:
        case BE_MESSAGE_TYPE_COPY_OUT_RESPONSE:
        case BE_MESSAGE_TYPE_COPY_BOTH_RESPONSE:
        case BE_MESSAGE_TYPE_DATA_ROW:
        case BE_MESSAGE_TYPE_EMPTY_QUERY_RESPONSE:
        case BE_MESSAGE_TYPE_ERROR_RESPONSE:
        case BE_MESSAGE_TYPE_FUNCTION_CALL_RESPONSE:
        case BE_MESSAGE_TYPE_NEGOTIATE_PROTOCOL_VERSION:
        case BE_MESSAGE_TYPE_NO_DATA:
        case BE_MESSAGE_TYPE_NOTICE_RESPONSE:
        case BE_MESSAGE_TYPE_NOTIFICATION_RESPONSE:
        case BE_MESSAGE_TYPE_PARAMETER_DESCRIPTION:
        case BE_MESSAGE_TYPE_PARAMETER_STATUS:
        case BE_MESSAGE_TYPE_PARSE_COMPLETE:
        case BE_MESSAGE_TYPE_PORTAL_SUSPENDED:
        case BE_MESSAGE_TYPE_READY_FOR_QUERY:
        case BE_MESSAGE_TYPE_ROW_DESCRIPTION:        
            if (generic_message_state_on_byte(&state->message_state.generic, fe_port, byte, trace_fp)) {
                state->message_type = BE_MESSAGE_TYPE_UNKNOWN;
            }
            break;
    }
}


#endif
