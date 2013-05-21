/* Copyright (c) 2002-2010 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

/* 
   sFlow Agent Library
   ===================
   sflow_api.h		- API for sflow agent library.
   sflow.h			- structure definitions for sFlow.
   sflow_api.c		- Agent, Sampler, Poller and Receiver

   Neil McKee
   InMon Corp.
   http://www.inmon.com
   email: neil.mckee@inmon.com
*/

#ifndef SFLOW_API_H
#define SFLOW_API_H 1

#include <apr.h>
#include <apr_time.h>
#include "sflow.h"

/*
  uncomment this preprocessor flag  (or compile with -DSFL_USE_32BIT_INDEX)
  if your ds_index numbers can ever be >= 2^30-1 (i.e. >= 0x3FFFFFFF)
*/
/* #define SFL_USE_32BIT_INDEX */


/* Used to combine ds_class, ds_index and instance into
   a single 64-bit number like this:
   __________________________________
   | cls|  index     |   instance     |
   ----------------------------------
 
   but now is opened up to a 12-byte struct to ensure
   that ds_index has a full 32-bit field, and to make
   accessing the components simpler. The macros have
   the same behavior as before, so this change should
   be transparent.  The only difference is that these
   objects are now passed around by reference instead
   of by value, and the comparison is done using a fn.
*/

typedef struct _SFLDataSource_instance {
  apr_uint32_t ds_class;
  apr_uint32_t ds_index;
  apr_uint32_t ds_instance;
} SFLDataSource_instance;

#ifdef SFL_USE_32BIT_INDEX
#define SFL_FLOW_SAMPLE_TYPE SFLFlow_sample_expanded
#define SFL_COUNTERS_SAMPLE_TYPE SFLCounters_sample_expanded
#else
#define SFL_FLOW_SAMPLE_TYPE SFLFlow_sample
#define SFL_COUNTERS_SAMPLE_TYPE SFLCounters_sample
/* if index numbers are not going to use all 32 bits, then we can use
   the more compact encoding, with the dataSource class and index merged */
#define SFL_DS_DATASOURCE(dsi) (((dsi).ds_class << 24) + (dsi).ds_index)
#endif

#define SFL_DS_INSTANCE(dsi) (dsi).ds_instance
#define SFL_DS_CLASS(dsi) (dsi).ds_class
#define SFL_DS_INDEX(dsi) (dsi).ds_index
#define SFL_DS_SET(dsi,clss,indx,inst)		\
  do {						\
    (dsi).ds_class = (clss);			\
    (dsi).ds_index = (indx);			\
    (dsi).ds_instance = (inst);			\
  } while(0)

#define SFL_SAMPLECOLLECTOR_DATA_QUADS (SFL_MAX_DATAGRAM_SIZE + SFL_DATA_PAD) / sizeof(apr_uint32_t)

typedef struct _SFLSampleCollector {
  apr_uint32_t data[SFL_SAMPLECOLLECTOR_DATA_QUADS];
  apr_uint32_t *datap; /* packet fill pointer */
  apr_uint32_t pktlen; /* accumulated size */
  apr_uint32_t packetSeqNo;
  apr_uint32_t numSamples;
} SFLSampleCollector;

struct _SFLAgent;  /* forward decl */

typedef struct _SFLReceiver {
  struct _SFLReceiver *nxt;
  /* MIB fields */
  char *sFlowRcvrOwner;
  apr_time_t sFlowRcvrTimeout;
  apr_uint32_t sFlowRcvrMaximumDatagramSize;
  SFLAddress sFlowRcvrAddress;
  apr_uint32_t sFlowRcvrPort;
  apr_uint32_t sFlowRcvrDatagramVersion;
  /* public fields */
  struct _SFLAgent *agent;    /* pointer to my agent */
  /* private fields */
  SFLSampleCollector sampleCollector;
} SFLReceiver;

typedef struct _SFLSampler {
  /* for linked list */
  struct _SFLSampler *nxt;
  /* for hash lookup table */
  struct _SFLSampler *hash_nxt;
  /* MIB fields */
  SFLDataSource_instance dsi;
  apr_uint32_t sFlowFsReceiver;
  apr_uint32_t sFlowFsPacketSamplingRate;
  apr_uint32_t sFlowFsMaximumHeaderSize;
  /* public fields */
  struct _SFLAgent *agent; /* pointer to my agent */
  void *userData;          /* can be useful to hang something else here */
  /* private fields */
  SFLReceiver *myReceiver;
  apr_uint32_t skip;
  apr_uint32_t samplePool;
  apr_uint32_t dropEvents;
  apr_uint32_t flowSampleSeqNo;
  /* rate checking */
  apr_uint32_t samplesThisTick;
  apr_uint32_t samplesLastTick;
  apr_uint32_t backoffThreshold;
} SFLSampler;

/* declare */
struct _SFLPoller;

typedef void (*getCountersFn_t)(void *magic,                   /* callback to get counters */
				struct _SFLPoller *sampler,    /* called with self */
				SFL_COUNTERS_SAMPLE_TYPE *cs); /* struct to fill in */

typedef struct _SFLPoller {
  /* for linked list */
  struct _SFLPoller *nxt;
  /* MIB fields */
  SFLDataSource_instance dsi;
  apr_uint32_t sFlowCpReceiver;
  apr_time_t sFlowCpInterval;
  /* public fields */
  struct _SFLAgent *agent; /* pointer to my agent */
  void *magic;             /* ptr to pass back in getCountersFn() */
  void *userData;          /* can be useful to hang something else here */
  getCountersFn_t getCountersFn;
  /* private fields */
  SFLReceiver *myReceiver;
  apr_time_t countersCountdown;
  apr_uint32_t countersSampleSeqNo;
} SFLPoller;

typedef void *(*allocFn_t)(void *magic,               /* callback to allocate space on heap */
			   struct _SFLAgent *agent,   /* called with self */
			   size_t bytes);             /* bytes requested */

typedef int (*freeFn_t)(void *magic,                  /* callback to free space on heap */
			struct _SFLAgent *agent,      /* called with self */
			void *obj);                   /* obj to free */

typedef void (*errorFn_t)(void *magic,                /* callback to log error message */
			  struct _SFLAgent *agent,    /* called with self */
			  char *msg);                 /* error message */

typedef void (*sendFn_t)(void *magic,                 /* optional override fn to send packet */
			 struct _SFLAgent *agent,
			 SFLReceiver *receiver,
			 apr_byte_t *pkt,
			 apr_uint32_t pktLen);


/* prime numbers are good for hash tables */
#define SFL_HASHTABLE_SIZ 199

typedef struct _SFLAgent {
  SFLSampler *jumpTable[SFL_HASHTABLE_SIZ]; /* fast lookup table for samplers (by ifIndex) */
  SFLSampler *samplers;   /* the list of samplers */
  SFLPoller  *pollers;    /* the list of samplers */
  SFLReceiver *receivers; /* the array of receivers */
  apr_time_t bootTime;        /* time when we booted or started */
  apr_time_t now;             /* time now */
  SFLAddress myIP;        /* IP address of this node */
  apr_uint32_t subId;        /* sub_agent_id */
  void *magic;            /* ptr to pass back in logging and alloc fns */
  allocFn_t allocFn;
  freeFn_t freeFn;
  errorFn_t errorFn;
  sendFn_t sendFn;
} SFLAgent;

/* call this at the start with a newly created agent */
void sfl_agent_init(SFLAgent *agent,
		    SFLAddress *myIP, /* IP address of this agent */
		    apr_uint32_t subId,  /* agent_sub_id */
		    apr_time_t bootTime,  /* agent boot time */
		    apr_time_t now,       /* time now */
		    void *magic,      /* ptr to pass back in logging and alloc fns */
		    allocFn_t allocFn,
		    freeFn_t freeFn,
		    errorFn_t errorFn,
		    sendFn_t sendFn);

/* call this to create samplers */
SFLSampler *sfl_agent_addSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* call this to create pollers */
SFLPoller *sfl_agent_addPoller(SFLAgent *agent,
			       SFLDataSource_instance *pdsi,
			       void *magic, /* ptr to pass back in getCountersFn() */
			       getCountersFn_t getCountersFn);

/* call this to create receivers */
SFLReceiver *sfl_agent_addReceiver(SFLAgent *agent);

/* call this to remove samplers */
int sfl_agent_removeSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* call this to remove pollers */
int sfl_agent_removePoller(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* note: receivers should not be removed. Typically the receivers
   list will be created at init time and never changed */

/* call these fns to retrieve sampler, poller or receiver (e.g. for SNMP GET or GETNEXT operation) */
SFLSampler  *sfl_agent_getSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLSampler  *sfl_agent_getNextSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLPoller   *sfl_agent_getPoller(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLPoller   *sfl_agent_getNextPoller(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLReceiver *sfl_agent_getReceiver(SFLAgent *agent, apr_uint32_t receiverIndex);
SFLReceiver *sfl_agent_getNextReceiver(SFLAgent *agent, apr_uint32_t receiverIndex);

/* jump table access - for performance */
SFLSampler *sfl_agent_getSamplerByIfIndex(SFLAgent *agent, apr_uint32_t ifIndex);

/* random number generator - used by sampler and poller */
apr_uint32_t sfl_random(apr_uint32_t mean);
void sfl_random_init(apr_uint32_t seed);

/* call these functions to GET and SET MIB values */

/* receiver */
char *      sfl_receiver_get_sFlowRcvrOwner(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrOwner(SFLReceiver *receiver, char *sFlowRcvrOwner);
apr_time_t      sfl_receiver_get_sFlowRcvrTimeout(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrTimeout(SFLReceiver *receiver, apr_time_t sFlowRcvrTimeout);
apr_uint32_t   sfl_receiver_get_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver, apr_uint32_t sFlowRcvrMaximumDatagramSize);
SFLAddress *sfl_receiver_get_sFlowRcvrAddress(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrAddress(SFLReceiver *receiver, SFLAddress *sFlowRcvrAddress);
apr_uint32_t   sfl_receiver_get_sFlowRcvrPort(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrPort(SFLReceiver *receiver, apr_uint32_t sFlowRcvrPort);
/* sampler */
apr_uint32_t sfl_sampler_get_sFlowFsReceiver(SFLSampler *sampler);
void      sfl_sampler_set_sFlowFsReceiver(SFLSampler *sampler, apr_uint32_t sFlowFsReceiver);
apr_uint32_t sfl_sampler_get_sFlowFsPacketSamplingRate(SFLSampler *sampler);
apr_uint32_t sfl_sampler_set_sFlowFsPacketSamplingRate(SFLSampler *sampler, apr_uint32_t sFlowFsPacketSamplingRate);
apr_uint32_t sfl_sampler_get_sFlowFsMaximumHeaderSize(SFLSampler *sampler);
void      sfl_sampler_set_sFlowFsMaximumHeaderSize(SFLSampler *sampler, apr_uint32_t sFlowFsMaximumHeaderSize);
/* poller */
apr_uint32_t sfl_poller_get_sFlowCpReceiver(SFLPoller *poller);
void      sfl_poller_set_sFlowCpReceiver(SFLPoller *poller, apr_uint32_t sFlowCpReceiver);
apr_uint32_t sfl_poller_get_sFlowCpInterval(SFLPoller *poller);
void      sfl_poller_set_sFlowCpInterval(SFLPoller *poller, apr_uint32_t sFlowCpInterval);

/* call this to indicate a discontinuity with a counter like samplePool so that the
   sflow collector will ignore the next delta */
void sfl_sampler_resetFlowSeqNo(SFLSampler *sampler);

/* call this to indicate a discontinuity with one or more of the counters so that the
   sflow collector will ignore the next delta */
void sfl_poller_resetCountersSeqNo(SFLPoller *poller);
  
/* software sampling: call this with every packet - returns non-zero if the packet
   should be sampled (in which case you then call sfl_sampler_writeFlowSample()) */
apr_uint32_t sfl_sampler_next_skip(SFLSampler *sampler);
int sfl_sampler_takeSample(SFLSampler *sampler);

/* call this to set a maximum samples-per-second threshold. If the sampler reaches this
   threshold it will automatically back off the sampling rate. A value of 0 disables the
   mechanism */
void sfl_sampler_set_backoffThreshold(SFLSampler *sampler, apr_uint32_t samplesPerSecond);
apr_uint32_t sfl_sampler_get_backoffThreshold(SFLSampler *sampler);
apr_uint32_t sfl_sampler_get_samplesLastTick(SFLSampler *sampler);


/* call this once per second (N.B. not on interrupt stack i.e. not hard real-time) */
void sfl_agent_tick(SFLAgent *agent, apr_time_t now);

/* call this with each flow sample */
void sfl_sampler_writeFlowSample(SFLSampler *sampler, SFL_FLOW_SAMPLE_TYPE *fs);
void sfl_sampler_writeEncodedFlowSample(SFLSampler *sampler, char *xdrBytes, apr_uint32_t len);

/* call this to push counters samples (usually done in the getCountersFn callback) */
void sfl_poller_writeCountersSample(SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs);

/* call this to deallocate resources */
void sfl_agent_release(SFLAgent *agent);


/* internal fns */

void sfl_receiver_init(SFLReceiver *receiver, SFLAgent *agent);
void sfl_sampler_init(SFLSampler *sampler, SFLAgent *agent, SFLDataSource_instance *pdsi);
void sfl_poller_init(SFLPoller *poller, SFLAgent *agent, SFLDataSource_instance *pdsi, void *magic, getCountersFn_t getCountersFn);


void sfl_receiver_tick(SFLReceiver *receiver, apr_time_t now);
void sfl_poller_tick(SFLPoller *poller, apr_time_t now);
void sfl_sampler_tick(SFLSampler *sampler, apr_time_t now);

int sfl_receiver_writeFlowSample(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs);
int sfl_receiver_writeEncodedFlowSample(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs, char *xdrBytes, apr_uint32_t packedSize);
int sfl_receiver_writeCountersSample(SFLReceiver *receiver, SFL_COUNTERS_SAMPLE_TYPE *cs);

void sfl_agent_resetReceiver(SFLAgent *agent, SFLReceiver *receiver);

void sfl_agent_error(SFLAgent *agent, char *modName, char *msg);

apr_uint32_t sfl_receiver_samplePacketsSent(SFLReceiver *receiver);


/* If supported, give compiler hints for branch prediction. */
#if !defined(__GNUC__) || (__GNUC__ == 2 && __GNUC_MINOR__ < 96)
#define __builtin_expect(x, expected_value) (x)
#endif

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

/* selective exposure of some internal hooks,  just for this project */
void sfl_receiver_put32(SFLReceiver *receiver, apr_uint32_t val);
void sfl_receiver_putOpaque(SFLReceiver *receiver, char *val, int len);
void sfl_receiver_resetSampleCollector(SFLReceiver *receiver);

#endif /* SFLOW_API_H */
