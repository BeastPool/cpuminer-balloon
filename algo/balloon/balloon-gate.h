#ifndef __BALLOON_GATE_H__
#define __BALLOON_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

bool register_balloon_algo( algo_gate_t* gate );

int scanhash_balloon( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );


#endif