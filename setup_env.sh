#!/bin/bash

# Exit on any error
set -e

# Function to check if a command is available
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
for cmd in ip nsenter; do
    if ! command_exists $cmd; then
        echo "Error: $cmd is not installed. Please install it and try again."
        exit 1
    fi
done

# Create a new network namespace
NETNS_NAME="mynetns"
sudo ip netns add $NETNS_NAME

# Create a veth pair
VETH_NAME="veth0"
VETH_PEER_NAME="veth1"
sudo ip link add $VETH_NAME type veth peer name $VETH_PEER_NAME

# Move one end of the veth pair to the network namespace
sudo ip link set $VETH_PEER_NAME netns $NETNS_NAME

# Set up the host side of the veth pair
sudo ip addr add 172.16.0.1/24 dev $VETH_NAME
sudo ip link set $VETH_NAME up

# Set up the namespace side of the veth pair
sudo ip netns exec $NETNS_NAME ip addr add 172.16.0.2/24 dev $VETH_PEER_NAME
sudo ip netns exec $NETNS_NAME ip link set $VETH_PEER_NAME up
sudo ip netns exec $NETNS_NAME ip link set lo up

# Print the IP address of the virtual ethernet interface
echo "Virtual Ethernet Interface IP: 172.16.0.2"

echo "Network environment setup complete."
echo "You can now attach your eBPF program to $VETH_PEER_NAME in the $NETNS_NAME namespace."
