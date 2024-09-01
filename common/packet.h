#ifndef PACKET
#define PACKET

/**
 * @brief packet that is sent to server. 3 timestamps and some data. No need for
 * time when client is reached as this is handled implicitly.
 *
 * the naming of the `leave_server_timestamp` means to represent the time after
 * the queuing delay, but BEFORE the synthetic workload has been run on the
 * target CPU of a packet.
 */
struct __attribute__((packed)) packet {
	unsigned long leave_client_timestamp;
	unsigned long reach_server_timestamp;
	unsigned long leave_server_timestamp;
	unsigned char data; // in the eBPF looping logic, this will be interpreted
		// loop time = data * 10 [us]
};

#endif
