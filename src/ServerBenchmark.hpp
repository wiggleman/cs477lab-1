#include <bpf/bpf.h>
#include <getopt.h>
#include <net/if.h>
#include <unistd.h>

#include <string>
#include <vector>

#ifndef SERVER_BENCHMARK
#define SERVER_BENCHMARK

/**
 * BPF scheduling policy that redirects packtets to a cpu in `cpus` in round-robin
 * fashion. Loads program onto `ifname` and expects traffic at `port`
 * Lasts for `duration` seconds because terminating
 */
int redirectProgRoundRobin(std::vector<int>& cpus, std::string& ifname, __u16 port, int duration);

/**
 * BPF scheduling policy that redirects packtets to a cpu in `cpus` in round-robin
 * fashion with core-separation between long and short requests. Loads program
 * onto `ifname` and expects traffic at `port`. Lasts for `duration` seconds because terminating
 */
int redirectProgRoundRobinCoreSeparated(std::vector<int>& cpusShort, std::vector<int>& cpusLong, std::string& ifname,
                                        __u16 port, int duration);

/**
 * BPF scheduling policy that redirects packtets to a cpu in `cpus` in round-robin
 * fashion, starting at one CPU and allocating more to the core group after surpassing
 * 20us avg queuing delay.
 * Loads program onto `ifname` and expects traffic at `port`. Lasts for `duration` seconds before terminating
 */
int redirectProgDynamicCoreAllocation(std::vector<int>& cpus, std::string& ifname, __u16 port, int duration);

/**
 * BPF scheduling policy that redirects packtets to a cpu in `cpus` in round-robin
 * fashion, starting at one CPU and allocating more to the core group after surpassing
 * 50% avg cpu utilization
 * Loads program onto `ifname` and expects traffic at `port`. Lasts for `duration` seconds before terminating
 */
int redirectProgDynamicCoreAllocationUtilization(std::vector<int>& availCpus, std::string& ifname, __u16 port,
                                                 int duration);
#endif
