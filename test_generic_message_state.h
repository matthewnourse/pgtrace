#include <stdio.h>
#include "generic_message_state.h"

static void test_generic_message_state_helper(const char *message,
                                              size_t message_length,
                                              const char *expected_trace_message_suffix) {
    const uint16_t fe_port = 0xff;
    generic_message_state_t state;
    generic_message_state_init(&state);
    generic_message_state_on_new_message(&state, fe_port, SENDER_TYPE_FE, "test");
    
    char buf[1024];
    buf[0] = '\0';
    FILE *trace_fp = fmemopen(buf, sizeof(buf), "w");
    /* +1 because we skip over the message-type character in the message, it's handled by
       generic_message_state_on_new_message. */
    const char *message_p = message + 1;
    const char *message_end = message + message_length;
    for (; message_p < message_end; ++message_p) {
        generic_message_state_on_byte(&state, fe_port, *message_p, trace_fp);
    }
    
    fclose(trace_fp);
    
    size_t actual_trace_message_len = strlen(buf);
    size_t expected_trace_message_suffix_len = strlen(expected_trace_message_suffix);
    
/*    fprintf(stderr, 
            "actual_trace_message_len: %zu  expected_trace_message_suffix_len: %zu  Actual: %s", 
            actual_trace_message_len, 
            expected_trace_message_suffix_len, 
            buf); */

    ASSERT(actual_trace_message_len > expected_trace_message_suffix_len);
    const char *actual_suffix = &buf[actual_trace_message_len - expected_trace_message_suffix_len];
//    fprintf(stderr, "Actual suffix: %sExpected suffix: %s\n", actual_suffix, expected_trace_message_suffix);
    ASSERT(strcmp(actual_suffix, expected_trace_message_suffix) == 0);
}

static void test_generic_message_state() {
    /* AuthenticationMD5Password */
    test_generic_message_state_helper("R\x00\x00\x00\x0C\x00\x00\x00\x05\x01\x02\x03\x04", 13, " 255 fe test 12 ........\n");
    
    /* ErrorResponse */
    test_generic_message_state_helper("E\x00\x00\x00\x0ASERROR", 11, " 255 fe test 10 SERROR\n");
    
    /* Over-size ErrorResponse */
    /*TODO: this is no longer over-sized */
    test_generic_message_state_helper("E\x00\x00\x01\x36SERROR012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                      311,
                                      " 255 fe test 310 SERROR012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\n");
}
