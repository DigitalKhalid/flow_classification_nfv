#!/bin/bash

# activate virtual network
echo "Virtual Environment Activated"
echo
source fc/bin/activate

# Prompt the user for their password
echo -n "Enter your password: "
read -s password
echo

# Clean previous running mininet instance
echo "Running cleaning up for previous virtual network instance....." &
echo
echo "$password" | sudo -S mn -c &
sleep 3
echo

# Start the Ryu API
echo "Starting Ryu Rest API....."
echo
gnome-terminal -- bash -c 'ryu-manager ryu.app.rest_topology ryu.app.ofctl_rest' &
sleep 3
echo

# Start your Ryu application
echo "Starting Ryu controller....."
echo
gnome-terminal -- bash -c 'ryu-manager my_controller_13.py --verbose' &
# sleep 3
echo

# Start Mininet
echo "Creating virtual network....."
echo
# sleep 3
echo "$password" | sudo -S python3 virtual_network.py
