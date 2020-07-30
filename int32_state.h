#ifndef INT32_STATE_H
#define INT32_STATE_H

typedef struct {
    uint8_t offset;
    int32_t value;
} int32_state_t;

static void int32_state_init(int32_state_t *state) {
    ASSERT(state);
    state->offset = 0;
    state->value = 0;
}

static uint32_t int32_state_calc_shift(uint8_t offset) {
    uint32_t shift_bytes = 3 - offset;
    uint32_t shift_bits = shift_bytes * 8;
    return shift_bits;
}

static bool int32_state_on_byte(int32_state_t *state, uint8_t byte) {
    ASSERT(state);
    ASSERT(state->offset < 4);
    
    state->value = state->value | (((uint32_t)byte) << int32_state_calc_shift(state->offset));
    state->offset++;
    return (state->offset >= 4);
}

static int32_t int32_state_value_get(int32_state_t *state) {
    ASSERT(state);
    return state->value;
}

static bool int32_state_is_high_byte_set(int32_state_t *state) {
    ASSERT(state);
    return ((state->value & 0xff000000) != 0);
}

#endif
