#!/bin/sh

error=0
if [ -z "${CLIENT_SUBNET_IPV6}"  ]; then
  echo "ERROR: CLIENT_SUBNET_IPV6 is not set."
  error=1
fi

if [ -z "${STRONGSWAN_CONTAINER_IPV6}"  ]; then
  echo "ERROR: STRONGSWAN_CONTAINER_IPV6 is not set."
  error=1
fi

# abort, if an error occurred
if [ $error -ne 0  ]; then
  exit 1
fi

# handle TERM signal
trap 'quit=1' TERM
quit=0

# add route for VPN client subnet to the strongswan container
echo "Adding route to VPN client subnet ${CLIENT_SUBNET_IPV6} via ${STRONGSWAN_CONTAINER_IPV6}..."
ip -6 route add ${CLIENT_SUBNET_IPV6} via ${STRONGSWAN_CONTAINER_IPV6}

# wait for the TERM signal
while [ "$quit" -ne 1 ]; do
    sleep 1
done

# remove route for VPN client subnet
echo "Removing route to VPN client subnet ${CLIENT_SUBNET_IPV6}..."
ip -6 route del ${CLIENT_SUBNET_IPV6} via ${STRONGSWAN_CONTAINER_IPV6}
