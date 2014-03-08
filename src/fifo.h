/*
  This file is taken from :
  B-Queue -- An efficient and practical queueing for fast core-to-core communication.
  Copyright (C) 2011 Junchang Wang <junchang.wang@gmail.com>
  
  -- Modified in February 2014 by shashibici.
*/

#ifndef _FIFO_B_QUQUQ_H_
#define _FIFO_B_QUQUQ_H_

#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <inttypes.h>
#include <string.h>
#include <stdint.h>

#include "nids.h"


//#define ELEMENT_TYPE uint64_t

#define QUEUE_SIZE (256) 
#define BATCH_SIZE (QUEUE_SIZE/16)
#define CONS_BATCH_SIZE BATCH_SIZE
#define PROD_BATCH_SIZE BATCH_SIZE
#define BATCH_INCREAMENT (BATCH_SIZE/2)

#define CONGESTION_PENALTY (1000) /* cycles */
typedef struct fifo_node ELEMENT_TYPE;
typedef struct fifo_node* ELEMENT_TYPE_P;



// Note that this struct is aligned by 64B.
// and some of its members are aligned by 64B as well.
// so that members with high affinity are located(mostly in Intel i386) in the same cache line.
// If run on different machines, '64B' should be modified accrodingly.
struct queue_t{
	/* Mostly accessed by producer. */
	volatile	uint32_t	head;
	volatile	uint32_t	batch_head;

	/* Mostly accessed by consumer. */
	volatile	uint32_t	tail __attribute__ ((aligned(64)));
	volatile	uint32_t	batch_tail;
	unsigned long	batch_history;

	/* readonly data */
	uint64_t	start_c __attribute__ ((aligned(64)));
	uint64_t	stop_c;

	/* accessed by both producer and comsumer */
	ELEMENT_TYPE	data[QUEUE_SIZE] __attribute__ ((aligned(64)));
	
	
} __attribute__ ((aligned(64)));



#define SUCCESS 0
#define BUFFER_FULL -1
#define BUFFER_EMPTY -2

// externs
void queue_init(struct queue_t *q);
int enqueue(struct queue_t *q, char* data_buf, int data_len);
int dequeue(struct queue_t *q, ELEMENT_TYPE_P value);

/* some inline utilities */
inline uint64_t read_tsc();
inline void wait_ticks(uint64_t);
inline void setelezero(ELEMENT_TYPE_P ele);
inline _Bool iselezero(ELEMENT_TYPE ele);

#endif


