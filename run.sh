#!/bin/bash

# This script starts a new instance of the cloudycube/strongswan container and opens a shell in it.
# It is useful in cases where some debugging is needed...

docker run -it \
  --name strongswan-vpn \
  --ip6=2001:xxxx:xxxx:xxxx::2 \
  --network internet \
  --publish 500:500/udp \
  --publish 4500:4500/udp \
  --volume /lib/modules:/lib/modules:ro \
  --volume strongswan-data:/data \
  --cap-add NET_ADMIN \
  --cap-add SYS_MODULE \
  --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  --env STARTUP_VERBOSITY=4 \
  --env VPN_HOSTNAMES="vpn.my-company.com" \
  cloudycube/strongswan \
  run-and-enter

