#!/bin/bash

# Exit on any error
set -e

# Function to check if a command is available
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
for cmd in ip; do
    if ! command_exists $cmd; then
        echo "Error: $cmd is not installed. Please install it and try again."
        exit 1
    fi
done

# Variables (should match those in the setup script)
NETNS_NAME="mynetns"
VETH_NAME="veth0"

# Function to safely delete a network namespace
delete_netns() {
    if ip netns list | grep -q "$1"; then
        echo "Deleting network namespace: $1"
        sudo ip netns delete "$1"
    else
        echo "Network namespace $1 does not exist. Skipping."
    fi
}

# Function to safely delete a network interface
delete_interface() {
    if ip link show "$1" &> /dev/null; then
        echo "Deleting network interface: $1"
        sudo ip link delete "$1"
    else
        echo "Network interface $1 does not exist. Skipping."
    fi
}

# Delete the veth pair (deleting one end automatically deletes the other)
delete_interface $VETH_NAME

# Delete the network namespace
delete_netns $NETNS_NAME

echo "Network environment teardown complete."
