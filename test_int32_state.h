#ifndef TEST_INT32_STATE_H
#define TEST_INT32_STATE_H

#include "common.h"
#include "int32_state.h"


static void test_int32_state_helper(const char *input, int32_t expected_result) {
    int32_state_t state;
    int32_state_init(&state);
    ASSERT(!int32_state_on_byte(&state, input[0]));
    ASSERT(!int32_state_on_byte(&state, input[1]));
    ASSERT(!int32_state_on_byte(&state, input[2]));
    ASSERT(int32_state_on_byte(&state, input[3]));
//    fprintf(stderr, "actual=0x%x expected=0x%x\n", int32_state_value_get(&state), expected_result);
    ASSERT(int32_state_value_get(&state) == expected_result);
}

static void test_int32_state() {
    test_int32_state_helper("\x00\x00\x00\x00", 0);
    test_int32_state_helper("\x00\x00\x00\x01", 1);
    test_int32_state_helper("\x00\x00\x00\x08", 8);
    test_int32_state_helper("\x00\x00\x00\xff", 0xff);
    test_int32_state_helper("\x00\x00\x01\xff", 0x1ff);
    test_int32_state_helper("\x00\x00\x09\xff", 2559);
    test_int32_state_helper("\x00\x00\xff\xff", 65535);
    test_int32_state_helper("\x00\xff\xff\xff", 0xffffff);
    test_int32_state_helper("\x01\xff\xff\xff", 0x1ffffff);
    test_int32_state_helper("\xff\xff\xff\xff", 0xffffffff);
}


#endif

