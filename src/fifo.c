/*
  This file is taken from :
  B-Queue -- An efficient and practical queueing for fast core-to-core communication.
  Copyright (C) 2011 Junchang Wang <junchang.wang@gmail.com>
  
  -- Modified in February 2014 by shashibici.
  
*/
#include <string.h>
#include "fifo.h"
#include <sched.h>

#if defined(FIFO_DEBUG)
#include <assert.h>
#endif

/* get current time  */
inline uint64_t read_tsc()
{
        uint64_t        time;
        uint32_t        msw   , lsw;
        __asm__         __volatile__("rdtsc\n\t"
                        "movl %%edx, %0\n\t"
                        "movl %%eax, %1\n\t"
                        :         "=r"         (msw), "=r"(lsw)
                        :   
                        :         "%edx"      , "%eax");
        time = ((uint64_t) msw << 32) | lsw;
        return time;
}


inline void wait_ticks(uint64_t ticks)
{
        uint64_t        current_time;
        uint64_t        time = read_tsc();
        time += ticks;
        do {
                current_time = read_tsc();
        } while (current_time < time);
}

// uint64_t 
//static ELEMENT_TYPE ELEMENT_ZERO = 0x0UL;

/*************************************************/
/********** Queue Functions **********************/
/*************************************************/

void queue_init(struct queue_t *q)
{

	///////////////////////////
	printf("\n queue_init 001 \n");


	memset(q, 0, sizeof(struct queue_t));

	///////////////////////////
	printf("\n queue_init 002 \n");

	q->batch_history = CONS_BATCH_SIZE;
}

/* compare tow points wheather they equal to each other*/
# if 0
inline int leqthan(volatile ELEMENT_TYPE point, volatile ELEMENT_TYPE batch_point)
{
	return (point == batch_point);
}
# endif


inline void setelezero(ELEMENT_TYPE_P ele)
{
	ele->skblen = -1;
}

inline _Bool iselezero(ELEMENT_TYPE ele)
{
	return (ele.skblen == -1);
}



int enqueue(struct queue_t * q, char* data_buf, int data_len)
{
	uint32_t tmp_head;
	/* if there is no space for producer*/
	if ( q->head == q->batch_head ) 
	{
		// move head forward
		tmp_head = q->head + PROD_BATCH_SIZE;
		// if overhead set to 0
		if ( tmp_head >= QUEUE_SIZE )
		{
			tmp_head = 0;
		}
		// if the destination is full wait.
		if ( !iselezero(q->data[tmp_head]) ) 
		{
			printf("skblen = %x", (q->data[tmp_head]).skblen);
			wait_ticks(CONGESTION_PENALTY);
			return BUFFER_FULL;
		}
		// else change bathch_head to the next step
		q->batch_head = tmp_head;
	}
	
	// else enqueue
	memcpy((q->data[q->head]).data, data_buf, data_len);
	(q->data[q->head]).skblen = data_len;
	q->head ++;
	// adjust head
	if ( q->head >= QUEUE_SIZE ) 
	{
		q->head = 0;
	}

	return SUCCESS;
}


static inline int backtracking(struct queue_t * q)
{
	uint32_t tmp_tail;
	// get next batch_tail
	tmp_tail = q->tail + CONS_BATCH_SIZE;
	// if next batch_tail is lager than queue_size then adjust.
	if ( tmp_tail >= QUEUE_SIZE ) 
	{
		tmp_tail = 0;

		// if history is smaller then adjust history
		if (q->batch_history < CONS_BATCH_SIZE) 
		{
			q->batch_history = 
				// if history+increment > batch_size than history is batch_size else is history+increment
				// to make sure history no more than batch_size
				(CONS_BATCH_SIZE < (q->batch_history + BATCH_INCREAMENT))? 
				CONS_BATCH_SIZE : (q->batch_history + BATCH_INCREAMENT);
		}

	}



	// uodate current batch_size to history
	unsigned long batch_size = q->batch_history;
	// if tmp_tail is empty then loop
	while ( iselezero(q->data[tmp_tail]) ) 
	{
		// wait a moment
		wait_ticks(CONGESTION_PENALTY);
		// half the batch_size
		batch_size = batch_size >> 1;
		// if batch_size >= 0 then modify the tmp_tail
		if( batch_size >= 0 ) 
		{
			tmp_tail = q->tail + batch_size;
			if (tmp_tail >= QUEUE_SIZE)
				tmp_tail = 0;		
		// then go to the next loop until it is not empty
		// so that the comsumer can read from the queue
		}
		else
		{
			return -1;
		}
	}

	q->batch_history = batch_size;



	
	// it indecats that no space is available to read if tmp_tail == tail
	// because each time tmp_tail will forwarad at most batch_size
	if ( tmp_tail == q->tail ) 
	{
		tmp_tail = (tmp_tail + 1) >= QUEUE_SIZE ?
			0 : tmp_tail + 1;
	}
	// update batch_tail
	q->batch_tail = tmp_tail;

	return 0;
}

int dequeue(struct queue_t * q, ELEMENT_TYPE_P value)
{
	// if tail go to the end of this batch
	if( q->tail == q->batch_tail ) 
	{
		// get a backracing to update batch_tail
		if ( backtracking(q) != 0 )
			return BUFFER_EMPTY;
	}
	
	// else dqueue
	*value = q->data[q->tail];
	setelezero(&(q->data[q->tail]));
	q->tail ++;
	if ( q->tail >= QUEUE_SIZE )
		q->tail = 0;

	return SUCCESS;
}




