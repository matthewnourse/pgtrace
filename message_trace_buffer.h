#ifndef MESSAGE_TRACE_BUFFER_H
#define MESSAGE_TRACE_BUFFER_H


typedef struct {
    /*TODO: dynamically allocate this, or find another way to hold all of each message. */
    /* This must be long enough to hold all possible message prefixes including all known message names and message lengths. */
    char data[4096];
    char *p;
} message_trace_buffer_t;


static void message_trace_buffer_init(message_trace_buffer_t *buffer) {
    ASSERT(buffer);
    buffer->data[0] = '\0';
    buffer->p = buffer->data;
}

static inline const char *message_trace_buffer_data_end(message_trace_buffer_t *buffer) {
    return buffer->data + sizeof(buffer->data) - 4;  /* -4 for elipsis then NUL */
}

static inline void message_trace_buffer_write_byte_as_safe_char(message_trace_buffer_t *buffer, uint8_t byte) {
    ASSERT(buffer);
    char c = (((byte <= 32) || (byte >= 127)) && (byte != ' ')) ? '.' : byte;
    if (buffer->p < message_trace_buffer_data_end(buffer)) {
        *buffer->p++ = c;
        *buffer->p = '\0';        
    } else {
        strcpy(buffer->p, "...");
    }
}

static inline void message_trace_buffer_write_space(message_trace_buffer_t *buffer) {
    message_trace_buffer_write_byte_as_safe_char(buffer, ' ');
}

static inline void message_trace_buffer_write_start(message_trace_buffer_t *buffer,
                                                    uint16_t fe_port,
                                                    sender_type_t sender_type,
                                                    const char *message_name) {
    ASSERT(buffer);
    ASSERT(message_name);
    
    message_trace_buffer_init(buffer);
    
    buffer->p = uint64_to_dec_str(buffer->p, now_epoch_usec());
    *buffer->p++ = ' ';
    buffer->p = uint64_to_dec_str(buffer->p, fe_port);
    *buffer->p++ = ' ';
    if (SENDER_TYPE_FE == sender_type) {
        *buffer->p++ = 'f';
    } else {
        *buffer->p++ = 'b';
    }
    
    *buffer->p++ = 'e';
    *buffer->p++ = ' ';
    
    size_t name_len = strlen(message_name);
    memcpy(buffer->p, message_name, name_len + 1);
    buffer->p += name_len;
}
 
static inline void message_trace_buffer_write_length_field(message_trace_buffer_t *buffer, int32_t length) {
    ASSERT(buffer);
    
    *buffer->p++ = ' ';    
    buffer->p = uint64_to_dec_str(buffer->p, length);
}


static inline void message_trace_buffer_print(message_trace_buffer_t *buffer, FILE *fp) {
    ASSERT(buffer);
    fwrite(buffer->data, strlen(buffer->data), 1, fp);
    putc('\n', fp);
}

#endif
