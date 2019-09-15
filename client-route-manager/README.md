# Configuration Helper Image for Routing an IPv6 Client Subnet

[![Build Status](https://dev.azure.com/griffinplus/Docker%20Images/_apis/build/status/8?branchName=master)](https://dev.azure.com/griffinplus/Docker%20Images/_build/latest?definitionId=8&branchName=master)
[![Docker Pulls](https://img.shields.io/docker/pulls/griffinplus/strongswan-client-route-manager.svg)](https://hub.docker.com/r/griffinplus/strongswan-client-route-manager)

This image helps to set up a route to the IPv6 client subnet assigned to VPN clients. This is necessary, if you've
chosen to give your VPN clients public IPv6 addresses, so they can directly communicate with other hosts on the
internet. 

To accomplish that, the container needs the `NET_ADMIN` capability and access to the host network namespace.
You can run the container as follows:

```
docker run \
  --rm \
  --net host \
  --cap-drop ALL \
  --cap-add NET_ADMIN \
  -e CLIENT_SUBNET_IPV6=<ipv6-subnet-assigned-to-your-clients> \
  -e STRONGSWAN_CONTAINER_IPV6=<public-ipv6-address-of-your-strongswan-container> \
  griffinplus/strongswan-client-route-manager
```

As soon as the container comes up, it adds the route to the host's routing table, then it sleeps until the container
is stopped. At this point the route is removed. You can start the container along with the strongswan container to
make necessary adjustments to the host networking, so strongswan can operate without manual intervention.
